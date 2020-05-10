// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_CONNMAN_H
#define ECCOIN_CONNMAN_H

#include "addrman.h"
#include "chain/chainparams.h"
#include "net/netconstants.h"
#include "node.h"
#include "tagstore.h"
#include "threadgroup.h"

struct AddedNodeInfo
{
    std::string strAddedNode;
    CService resolvedAddress;
    bool fConnected;
    bool fInbound;
};

class CConnman
{
private:
    struct ListenSocket
    {
        SOCKET socket;
        bool whitelisted;

        ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
    };

    // Network usage totals
    CCriticalSection cs_totalBytesRecv;
    CCriticalSection cs_totalBytesSent;
    uint64_t nTotalBytesRecv;
    uint64_t nTotalBytesSent;

    // outbound limit & stats
    uint64_t nMaxOutboundTotalBytesSentInCycle;
    uint64_t nMaxOutboundCycleStartTime;
    uint64_t nMaxOutboundLimit;
    uint64_t nMaxOutboundTimeframe;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<CSubNet> vWhitelistedRange;
    CCriticalSection cs_vWhitelistedRange;

    unsigned int nSendBufferMaxSize;
    unsigned int nReceiveFloodSize;

    std::vector<ListenSocket> vhListenSocket;
    bool fAddressesInitialized;
    CAddrMan addrman;
    std::deque<std::string> vOneShots;
    CCriticalSection cs_vOneShots;
    std::vector<std::string> vAddedNodes;
    CCriticalSection cs_vAddedNodes;
    std::vector<CNode *> vNodes;
    std::list<CNode *> vNodesDisconnected;
    mutable CCriticalSection cs_vNodes;
    std::atomic<NodeId> nLastNodeId;

    /** Services this instance offers */
    ServiceFlags nLocalServices;

    /** Services this instance cares about */
    ServiceFlags nRelevantServices;

    std::unique_ptr<CSemaphore> semOutbound;
    std::unique_ptr<CSemaphore> semAddnode;
    int nMaxConnections;
    int nMaxOutbound;
    int nMaxAddnode;
    int nMaxFeeler;
    std::atomic<int> nBestHeight;

    /** SipHasher seeds for deterministic randomness */
    const uint64_t nSeed0, nSeed1;

    std::atomic<bool> interruptNet;
    thread_group netThreads;

public:
    CNetTagStore *tagstore;
    CPubKey pub_routing_id;

    enum NumConnections
    {
        CONNECTIONS_NONE = 0,
        CONNECTIONS_IN = (1U << 0),
        CONNECTIONS_OUT = (1U << 1),
        CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
    };

    CConnman(uint64_t seed0, uint64_t seed1);
    ~CConnman();
    bool Start(std::string &strNodeError);
    void Stop();
    void Interrupt();
    bool BindListenPort(const CService &bindAddr, std::string &strError, bool fWhitelisted = false);
    bool OpenNetworkConnection(const CAddress &addrConnect,
        bool fCountFailure,
        CSemaphoreGrant *grantOutbound = nullptr,
        const char *strDest = nullptr,
        bool fOneShot = false,
        bool fFeeler = false,
        bool fAddnode = false);

    bool ForNode(NodeId id, std::function<bool(CNode *pnode)> func);

    template <typename... Args>
    void PushMessage(CNode *pnode, std::string sCommand, Args &&... args)
    {
        std::vector<uint8_t> data;
        CVectorWriter{SER_NETWORK, pnode->GetSendVersion(), data, 0, std::forward<Args>(args)...};
        size_t nMessageSize = data.size();
        size_t nTotalSize = nMessageSize + CMessageHeader::HEADER_SIZE;
        LogPrint("net", "sending %s (%d bytes) peer=%d\n", SanitizeString(sCommand.c_str()), nMessageSize, pnode->id);

        std::vector<uint8_t> serializedHeader;
        serializedHeader.reserve(CMessageHeader::HEADER_SIZE);
        uint256 hash = Hash(data.data(), data.data() + nMessageSize);
        CMessageHeader hdr(Params().MessageStart(), sCommand.c_str(), nMessageSize);
        memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

        CVectorWriter{SER_NETWORK, MIN_PROTO_VERSION, serializedHeader, 0, hdr};

        size_t nBytesSent = 0;
        {
            LOCK(pnode->cs_vSend);
            bool optimisticSend(pnode->vSendMsg.empty());

            // log total amount of bytes per command
            pnode->mapSendBytesPerMsgCmd[sCommand] += nTotalSize;
            pnode->nSendSize += nTotalSize;

            if (pnode->nSendSize > nSendBufferMaxSize)
            {
                pnode->fPauseSend = true;
            }
            pnode->vSendMsg.push_back(std::move(serializedHeader));
            if (nMessageSize)
            {
                pnode->vSendMsg.push_back(std::move(data));
            }
            const char *strCommand = sCommand.c_str();
            if (strcmp(strCommand, NetMsgType::PING) != 0 && strcmp(strCommand, NetMsgType::PONG) != 0 &&
                strcmp(strCommand, NetMsgType::ADDR) != 0 && strcmp(strCommand, NetMsgType::VERSION) != 0 &&
                strcmp(strCommand, NetMsgType::VERACK) != 0 && strcmp(strCommand, NetMsgType::INV) != 0)
            {
                pnode->nActivityBytes += nMessageSize;
            }

            // If write queue empty, attempt "optimistic write"
            if (optimisticSend == true)
            {
                nBytesSent = SocketSendData(pnode);
            }
        }
        if (nBytesSent)
        {
            RecordBytesSent(nBytesSent);
        }
    }

    template <typename... Args>
    void PushMessageToId(const NodeId &dest, const std::string sCommand, Args &&... args)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node) && node->GetId() == dest)
            {
                PushMessage(node, sCommand, std::forward<Args>(args)...);
                break;
            }
        }
    }

    template <typename... Args>
    void PushMessageAll(const std::string sCommand, Args &&... args)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
            {
                PushMessage(node, sCommand, std::forward<Args>(args)...);
            }
        }
    }

    template <typename... Args>
    void PushMessageAll(const CPubKey &source, const std::string sCommand, Args &&... args)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node) && node->routing_id != source)
            {
                PushMessage(node, sCommand, std::forward<Args>(args)...);
            }
        }
    }

    template <typename Callable>
    void ForEachNode(Callable &&func)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                func(node);
        }
    };

    template <typename Callable>
    void ForEachNode(Callable &&func) const
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                func(node);
        }
    };

    template <typename Callable, typename CallableAfter>
    void ForEachNodeThen(Callable &&pre, CallableAfter &&post)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                pre(node);
        }
        post();
    };

    template <typename Callable, typename CallableAfter>
    void ForEachNodeThen(Callable &&pre, CallableAfter &&post) const
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                pre(node);
        }
        post();
    };

    // Addrman functions
    size_t GetAddressCount() const;
    void SetServices(const CService &addr, ServiceFlags nServices);
    void MarkAddressGood(const CAddress &addr);
    void AddNewAddress(const CAddress &addr, const CAddress &addrFrom, int64_t nTimePenalty = 0);
    void AddNewAddresses(const std::vector<CAddress> &vAddr, const CAddress &addrFrom, int64_t nTimePenalty = 0);
    std::vector<CAddress> GetAddresses();

    void AddOneShot(const std::string &strDest);

    bool AddNode(const std::string &node);
    bool RemoveAddedNode(const std::string &node);
    std::vector<AddedNodeInfo> GetAddedNodeInfo();

    size_t GetNodeCount(NumConnections num);
    void GetNodeStats(std::vector<CNodeStats> &vstats);
    bool DisconnectNode(const std::string &node);
    bool DisconnectNode(NodeId id);
    bool DisconnectNode(const CSubNet &subnet);

    unsigned int GetSendBufferSize() const;

    void AddWhitelistedRange(const CSubNet &subnet);

    ServiceFlags GetLocalServices() const;

    //! set the max outbound target in bytes.
    void SetMaxOutboundTarget(uint64_t limit);
    uint64_t GetMaxOutboundTarget();

    //! set the timeframe for the max outbound target.
    void SetMaxOutboundTimeframe(uint64_t timeframe);
    uint64_t GetMaxOutboundTimeframe();

    //! check if the outbound target is reached.
    // If param historicalBlockServingLimit is set true, the function will
    // response true if the limit for serving historical blocks has been
    // reached.
    bool OutboundTargetReached(bool historicalBlockServingLimit);

    //! response the bytes left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetOutboundTargetBytesLeft();

    //! response the time in second left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetMaxOutboundTimeLeftInCycle();

    uint64_t GetTotalBytesRecv();
    uint64_t GetTotalBytesSent();

    /** Get a unique deterministic randomizer. */
    CSipHasher GetDeterministicRandomizer(uint64_t id) const;

    unsigned int GetReceiveFloodSize() const;

    CPubKey GetPublicTagPubKey() const;

    void PushNodeVersion(CNode *pnode, int64_t nTime);

private:
    void ThreadOpenAddedConnections();
    void ProcessOneShot();
    void ThreadOpenConnections();
    void ThreadMessageHandler();
    void AcceptConnection(const ListenSocket &hListenSocket);
    void ThreadSocketHandler();
    void ThreadDNSAddressSeed();

    uint64_t CalculateKeyedNetGroup(const CAddress &ad) const;

    CNode *FindNode(const CNetAddr &ip);
    CNode *FindNode(const CSubNet &subNet);
    CNode *FindNode(const std::string &addrName);
    CNode *FindNode(const CService &addr);

    bool AttemptToEvictConnection();
    CNode *ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure);
    bool IsWhitelistedRange(const CNetAddr &addr);

    void DeleteNode(CNode *pnode);

    NodeId GetNewNodeId();

    size_t SocketSendData(CNode *pnode) const;
    //! clean unused entries (if bantime has expired)
    void DumpAddresses();
    void _DumpData();
    void DumpData(int64_t seconds_between_runs);

    // Network stats
    void RecordBytesRecv(uint64_t bytes);
    void RecordBytesSent(uint64_t bytes);

    // Whether the node should be passed out in ForEach* callbacks
    static bool NodeFullyConnected(const CNode *pnode);

    void InitializeNode(CNode *pnode);
};

extern std::unique_ptr<CConnman> g_connman;


#endif
