// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NODE_H
#define ECCOIN_NODE_H

#include "bloom.h"
#include "limitedmap.h"
#include "netmessage.h"
#include "pubkey.h"
#include "random.h"
#include "sync.h"

#include <atomic>
#include <deque>

typedef int64_t NodeId;
// Command, total bytes
typedef std::map<std::string, uint64_t> mapMsgCmdSize;

class CNodeStats
{
public:
    NodeId nodeid;
    ServiceFlags nServices;
    bool fRelayTxes;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    bool fAddnode;
    int nStartingHeight;
    uint64_t nSendBytes;
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    uint64_t nRecvBytes;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;
    bool fWhitelisted;
    double dPingTime;
    double dPingWait;
    double dMinPing;
    std::string addrLocal;
    CAddress addr;
};

/** Information about a peer */
class CNode
{
    friend class CConnman;

public:
    // socket
    std::atomic<ServiceFlags> nServices;
    // Services expected from a peer, otherwise it will be disconnected
    ServiceFlags nServicesExpected;
    SOCKET hSocket;
    // Total size of all vSendMsg entries.
    size_t nSendSize;
    // Offset inside the first vSendMsg already sent.
    size_t nSendOffset;
    uint64_t nSendBytes;
    // Total bytes sent and received
    uint64_t nActivityBytes;
    std::deque<std::vector<uint8_t> > vSendMsg;
    CCriticalSection cs_vSend;
    CCriticalSection cs_hSocket;
    CCriticalSection cs_vRecv;

    CCriticalSection cs_vProcessMsg;
    std::list<CNetMessage> vProcessMsg;
    size_t nProcessQueueSize;

    CCriticalSection cs_sendProcessing;

    CCriticalSection csRecvGetData;
    std::deque<CInv> vRecvGetData;
    uint64_t nRecvBytes;
    std::atomic<int> nRecvVersion;

    std::atomic<int64_t> nLastSend;
    std::atomic<int64_t> nLastRecv;
    const int64_t nTimeConnected;
    std::atomic<int64_t> nTimeOffset;
    const CAddress addr;
    std::atomic<int> nVersion;
    // strSubVer is whatever byte array we read from the wire. However, this
    // field is intended to be printed out, displayed to humans in various forms
    // and so on. So we sanitize it and store the sanitized version in
    // cleanSubVer. The original should be used when dealing with the network or
    // wire types and the cleaned string used when displayed or logged.
    std::string strSubVer, cleanSubVer;
    // Used for both cleanSubVer and strSubVer.
    CCriticalSection cs_SubVer;
    // This peer can bypass DoS banning.
    bool fWhitelisted;
    // If true this node is being used as a short lived feeler.
    bool fFeeler;
    bool fOneShot;
    bool fAddnode;
    bool fClient;
    const bool fInbound;
    std::atomic_bool fSuccessfullyConnected;
    std::atomic_bool fDisconnect;
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version
    // message.
    // b) the peer may tell us in its version message that we should not relay
    // tx invs unless it loads a bloom filter.

    // protected by cs_filter
    bool fRelayTxes;
    bool fSentAddr;
    CSemaphoreGrant grantOutbound;
    CCriticalSection cs_filter;
    CBloomFilter *pfilter;
    std::atomic<int> nRefCount;
    const NodeId id;

    const uint64_t nKeyedNetGroup;
    std::atomic_bool fPauseRecv;
    std::atomic_bool fPauseSend;
    CPubKey routing_id;

    std::atomic<uint8_t> nMisbehavior;

protected:
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;

public:
    std::atomic<int> nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    CRollingBloomFilter addrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;
    int64_t nNextAddrSend;
    int64_t nNextLocalAddrSend;

    // Inventory based relay.
    CRollingBloomFilter filterInventoryKnown;
    // Set of transaction ids we still have to announce. They are sorted by the
    // mempool before relay, so the order is not important.
    std::vector<CInv> vInventoryToSend;
    // List of block ids we still have announce. There is no final sorting
    // before sending, as they are always sent immediately and in the order
    // requested.
    CCriticalSection cs_inventory;
    CCriticalSection cs_askfor;
    std::set<uint256> setAskFor;
    std::multimap<int64_t, CInv> mapAskFor;
    // Used for headers announcements - unfiltered blocks to relay. Also
    // protected by cs_inventory.
    std::vector<uint256> vBlockHashesToAnnounce;
    // Used for BIP35 mempool sending, also protected by cs_inventory.
    bool fSendMempool;

    // Last time a "MEMPOOL" request was serviced.
    std::atomic<int64_t> timeLastMempoolReq;

    // Block and TXN accept times
    std::atomic<int64_t> nLastBlockTime;
    std::atomic<int64_t> nLastTXTime;

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    std::atomic<uint64_t> nPingNonceSent;
    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    std::atomic<int64_t> nPingUsecStart;
    // Last measured round-trip time.
    std::atomic<int64_t> nPingUsecTime;
    // Best measured round-trip time.
    std::atomic<int64_t> nMinPingUsecTime;
    // Whether a ping is requested.
    std::atomic<bool> fPingQueued;

    std::atomic<uint64_t> nNetworkServiceVersion;

    CNode(NodeId id,
        ServiceFlags nLocalServicesIn,
        SOCKET hSocketIn,
        const CAddress &addrIn,
        uint64_t nKeyedNetGroupIn,
        uint64_t nLocalHostNonceIn,
        const std::string &addrNameIn = "",
        bool fInboundIn = false);
    ~CNode();

private:
    CNode(const CNode &);
    void operator=(const CNode &);

    // Services offered to this peer
    const ServiceFlags nLocalServices;
    int nSendVersion;
    // Used only by SocketHandler thread.
    std::list<CNetMessage> vRecvMsg;

    mutable CCriticalSection cs_addrName;
    std::string addrName;

    CService addrLocal;
    mutable CCriticalSection cs_addrLocal;

public:
    NodeId GetId() const { return id; }
    int GetRefCount()
    {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    bool ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool &complete);

    void SetRecvVersion(int nVersionIn) { nRecvVersion = nVersionIn; }
    int GetRecvVersion() { return nRecvVersion; }
    void SetSendVersion(int nVersionIn);
    int GetSendVersion() const;

    CService GetAddrLocal() const;
    //! May not be called more than once
    void SetAddrLocal(const CService &addrLocalIn);

    CNode *AddRef()
    {
        nRefCount++;
        return this;
    }

    void Release() { nRefCount--; }
    void AddAddressKnown(const CAddress &_addr) { addrKnown.insert(_addr.GetKey()); }
    void PushAddress(const CAddress &_addr, FastRandomContext &insecure_rand)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (_addr.IsValid() && !addrKnown.contains(_addr.GetKey()))
        {
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND)
            {
                vAddrToSend[insecure_rand.randrange(vAddrToSend.size())] = _addr;
            }
            else
            {
                vAddrToSend.push_back(_addr);
            }
        }
    }

    void AddInventoryKnown(const CInv &inv)
    {
        LOCK(cs_inventory);
        filterInventoryKnown.insert(inv.hash);
    }

    void PushInventory(const CInv &inv)
    {
        LOCK(cs_inventory);
        if (inv.type == MSG_TX && filterInventoryKnown.contains(inv.hash))
        {
            return;
        }
        vInventoryToSend.push_back(inv);
    }

    void PushBlockHash(const uint256 &hash)
    {
        LOCK(cs_inventory);
        vBlockHashesToAnnounce.push_back(hash);
    }

    void AskFor(const CInv &inv);

    void CloseSocketDisconnect();

    void copyStats(CNodeStats &stats);

    ServiceFlags GetLocalServices() const { return nLocalServices; }
    std::string GetAddrName() const;
    //! Sets the addrName only if it was not previously set
    void MaybeSetAddrName(const std::string &addrNameIn);

    //! returns the name of this node for logging.  Respects the user's choice to not log the node's IP
    std::string GetLogName()
    {
        return std::to_string(id);
    }
};

#endif
