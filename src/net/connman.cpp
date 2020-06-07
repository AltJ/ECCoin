// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "connman.h"

#include "args.h"
#include "beta.h"
#include "chain/chainman.h"
#include "consensus/consensus.h"
#include "dosman.h"
#include "messages.h"
#include "requestmanager.h"

// We add a random period time (0 to 1 seconds) to feeler connections to prevent
// synchronization.
#define FEELER_SLEEP_WINDOW 1

// Dump addresses to peers.dat and banlist.dat every 15 minutes (900s)
#define DUMP_ADDRESSES_INTERVAL 900

ServiceFlags DEFAULT_RELEVANT_SERVICES = NODE_NETWORK;
ServiceFlags DEFAULT_LOCAL_SERVICES = NODE_NETWORK;

extern int initMaxConnections;

// Connection Slot mitigation - used to determine how many connection attempts over time
extern CCriticalSection cs_mapInboundConnectionTracker;
extern std::map<CNetAddr, ConnectionHistory> mapInboundConnectionTracker;

extern uint64_t nLocalHostNonce;

void EraseOrphansFor(NodeId peer);

CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In) : nSeed0(nSeed0In), nSeed1(nSeed1In), netThreads(&interruptNet)
{
    fAddressesInitialized = false;
    nLastNodeId = 0;
    nSendBufferMaxSize = 0;
    nReceiveFloodSize = 0;
    semOutbound = nullptr;
    semAddnode = nullptr;
    nMaxConnections = 0;
    nMaxOutbound = 0;
    nMaxAddnode = 0;
    nBestHeight = 0;
    interruptNet.store(false);
    tagstore = new CNetTagStore(strRoutingFile);
}
CConnman::~CConnman()
{
    Interrupt();
    Stop();
}

bool CConnman::Start(std::string &strNodeError)
{
    nTotalBytesRecv = 0;
    nTotalBytesSent = 0;
    nMaxOutboundTotalBytesSentInCycle = 0;
    nMaxOutboundCycleStartTime = 0;

    nRelevantServices = DEFAULT_RELEVANT_SERVICES;
    nLocalServices = DEFAULT_LOCAL_SERVICES;
    if (gArgs.GetBoolArg("-peerbloomfilters", true))
    {
        nLocalServices = ServiceFlags(nLocalServices | NODE_BLOOM);
    }

    nMaxConnections = initMaxConnections;
    nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, nMaxConnections);
    nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
    nMaxFeeler = 1;

    nSendBufferMaxSize = 1000 * gArgs.GetArg("-maxsendbuffer", DEFAULT_MAXSENDBUFFER);
    nReceiveFloodSize = 1000 * gArgs.GetArg("-maxreceivebuffer", DEFAULT_MAXRECEIVEBUFFER);

    nMaxOutboundLimit = 0;

    if (gArgs.IsArgSet("-maxuploadtarget"))
    {
        nMaxOutboundLimit = gArgs.GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET) * 1024 * 1024;
    }
    nMaxOutboundTimeframe = MAX_UPLOAD_TIMEFRAME;

    LogPrintf("Generating random routing id...\n");

    if (IsBetaEnabled())
    {
        tagstore->Load();
        pub_routing_id = tagstore->GetCurrentPublicTagPubKey();
    }

    LogPrintf("Loading addresses...\n");
    // Load addresses from peers.dat
    int64_t nStart = GetTimeMillis();
    {
        CAddrDB adb;
        if (adb.Read(addrman))
        {
            LogPrintf("Loaded %i addresses from peers.dat  %dms\n", addrman.size(), GetTimeMillis() - nStart);
        }
        else
        {
            // Addrman can be in an inconsistent state after failure, reset it
            addrman.Clear();
            LogPrintf("Invalid or missing peers.dat; recreating\n");
            DumpAddresses();
        }
    }
    LogPrintf("Loading banlist...\n");
    // Load addresses from banlist.dat
    nStart = GetTimeMillis();
    CBanDB bandb;
    banmap_t banmap;
    if (bandb.Read(banmap))
    {
        // thread save setter
        g_dosman->SetBanned(banmap);
        // no need to write down, just read data
        g_dosman->SetBannedSetDirty(false);
        // sweep out unused entries
        g_dosman->SweepBanned();

        LogPrintf(
            "Loaded %d banned node ips/subnets from banlist.dat  %dms\n", banmap.size(), GetTimeMillis() - nStart);
    }
    else
    {
        LogPrintf("Invalid or missing banlist.dat; recreating\n");
        // force write
        g_dosman->SetBannedSetDirty(true);
        g_dosman->DumpBanlist();
    }

    LogPrintf("Starting network threads...\n");

    fAddressesInitialized = true;

    if (semOutbound == nullptr)
    {
        // initialize semaphore
        semOutbound = MakeUnique<CSemaphore>(std::min((nMaxOutbound + nMaxFeeler), nMaxConnections));
    }

    if (semAddnode == nullptr)
    {
        // initialize semaphore
        semAddnode = MakeUnique<CSemaphore>(nMaxAddnode);
    }

    //
    // Start threads
    //
    InterruptSocks5(false);
    interruptNet.store(false);

    // Send and receive from sockets, accept connections
    netThreads.create_thread(&CConnman::ThreadSocketHandler, this);

    if (!gArgs.GetBoolArg("-dnsseed", true))
    {
        LogPrintf("DNS seeding disabled\n");
    }
    else
    {
        netThreads.create_thread(&CConnman::ThreadDNSAddressSeed, this);
    }

    // Initiate outbound connections from -addnode
    netThreads.create_thread(&CConnman::ThreadOpenAddedConnections, this);

    // Initiate outbound connections unless connect=0
    if (!gArgs.IsArgSet("-connect") || gArgs.GetArgs("-connect").size() != 1 || gArgs.GetArgs("-connect")[0] != "0")
    {
        netThreads.create_thread(&CConnman::ThreadOpenConnections, this);
    }

    // Process messages
    netThreads.create_thread(&CConnman::ThreadMessageHandler, this);

    // Dump network addresses
    netThreads.create_thread(&CConnman::DumpData, this, DUMP_ADDRESSES_INTERVAL);

    return true;
}

void CConnman::Stop()
{
    netThreads.interrupt_all();
    netThreads.join_all();

    if (fAddressesInitialized)
    {
        _DumpData();
        fAddressesInitialized = false;
    }

    // Close sockets
    for (CNode *pnode : vNodes)
    {
        pnode->CloseSocketDisconnect();
    }
    for (ListenSocket &hListenSocket : vhListenSocket)
    {
        if (hListenSocket.socket != INVALID_SOCKET)
        {
            if (!CloseSocket(hListenSocket.socket))
            {
                LogPrintf("CloseSocket(hListenSocket) failed with error %s\n", NetworkErrorString(WSAGetLastError()));
            }
        }
    }

    // clean up some globals (to help leak detection)
    for (CNode *pnode : vNodes)
    {
        DeleteNode(pnode);
    }
    for (CNode *pnode : vNodesDisconnected)
    {
        DeleteNode(pnode);
    }
    vNodes.clear();
    vNodesDisconnected.clear();
    vhListenSocket.clear();
    semOutbound.reset();
    semAddnode.reset();
}

void CConnman::Interrupt()
{
    interruptNet.store(true);
    InterruptSocks5(true);

    if (semOutbound)
    {
        for (int i = 0; i < (nMaxOutbound + nMaxFeeler); i++)
        {
            semOutbound->post();
        }
    }

    if (semAddnode)
    {
        for (int i = 0; i < nMaxAddnode; i++)
        {
            semAddnode->post();
        }
    }
}

bool CConnman::BindListenPort(const CService &addrBind, std::string &strError, bool fWhitelisted)
{
    strError = "";
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr *)&sockaddr, &len))
    {
        strError = strprintf("Error: Bind address family for %s not supported", addrBind.ToString());
        LogPrintf("%s\n", strError);
        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr *)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming "
                             "connections (socket returned error %s)",
            NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError);
        return false;
    }
    if (!IsSelectableSocket(hListenSocket))
    {
        strError = "Error: Couldn't create a listenable socket for incoming "
                   "connections";
        LogPrintf("%s\n", strError);
        return false;
    }

#ifndef WIN32
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&nOne, sizeof(int));
#endif
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void *)&nOne, sizeof(int));
    // Disable Nagle's algorithm
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&nOne, sizeof(int));
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char *)&nOne, sizeof(int));
#endif

    // Set to non-blocking, incoming connections will also inherit this
    if (!SetSocketNonBlocking(hListenSocket, true))
    {
        strError = strprintf("BindListenPort: Setting listening socket to "
                             "non-blocking failed, error %s\n",
            NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError);
        return false;
    }

    // Some systems don't have IPV6_V6ONLY but are always v6only; others do have
    // the option and enable it by default or not. Try to enable it, if
    // possible.
    if (addrBind.IsIPv6())
    {
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char *)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr *)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
        {
            strError = strprintf("Unable to bind to %s on this computer. %s "
                                 "is probably already running.",
                addrBind.ToString(), "Eccoind");
        }
        else
        {
            strError = strprintf("Unable to bind to %s on this computer "
                                 "(bind returned error %s)",
                addrBind.ToString(), NetworkErrorString(nErr));
        }
        LogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }
    LogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections "
                             "failed (listen returned error %s)",
            NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError);
        CloseSocket(hListenSocket);
        return false;
    }

    vhListenSocket.push_back(ListenSocket(hListenSocket, fWhitelisted));

    if (addrBind.IsRoutable() && fDiscover && !fWhitelisted)
    {
        AddLocal(addrBind, LOCAL_BIND);
    }

    return true;
}

// If successful, this moves the passed grant to the constructed node.
bool CConnman::OpenNetworkConnection(const CAddress &addrConnect,
    bool fCountFailure,
    CSemaphoreGrant *grantOutbound,
    const char *pszDest,
    bool fOneShot,
    bool fFeeler,
    bool fAddnode)
{
    //
    // Initiate outbound network connection
    //
    if (interruptNet.load() == true)
    {
        return false;
    }
    if (!pszDest)
    {
        if (IsLocal(addrConnect) || FindNode((CNetAddr)addrConnect) || g_dosman->IsBanned(addrConnect) ||
            FindNode(addrConnect.ToStringIPPort()))
        {
            return false;
        }
    }
    else if (FindNode(std::string(pszDest)))
    {
        return false;
    }

    CNode *pnode = ConnectNode(addrConnect, pszDest, fCountFailure);

    if (!pnode)
    {
        return false;
    }
    if (grantOutbound)
    {
        grantOutbound->MoveTo(pnode->grantOutbound);
    }
    if (fOneShot)
    {
        pnode->fOneShot = true;
    }
    if (fFeeler)
    {
        pnode->fFeeler = true;
    }
    if (fAddnode)
    {
        pnode->fAddnode = true;
    }

    InitializeNode(pnode);
    {
        LOCK(cs_vNodes);
        vNodes.push_back(pnode);
    }

    return true;
}

bool CConnman::ForNode(NodeId id, std::function<bool(CNode *pnode)> func)
{
    CNode *found = nullptr;
    LOCK(cs_vNodes);
    for (auto &&pnode : vNodes)
    {
        if (pnode->id == id)
        {
            found = pnode;
            break;
        }
    }
    return found != nullptr && NodeFullyConnected(found) && func(found);
}

size_t CConnman::GetAddressCount() const { return addrman.size(); }
void CConnman::SetServices(const CService &addr, ServiceFlags nServices) { addrman.SetServices(addr, nServices); }
void CConnman::MarkAddressGood(const CAddress &addr) { addrman.Good(addr); }
void CConnman::AddNewAddress(const CAddress &addr, const CAddress &addrFrom, int64_t nTimePenalty)
{
    addrman.Add(addr, addrFrom, nTimePenalty);
}

void CConnman::AddNewAddresses(const std::vector<CAddress> &vAddr, const CAddress &addrFrom, int64_t nTimePenalty)
{
    addrman.Add(vAddr, addrFrom, nTimePenalty);
}

std::vector<CAddress> CConnman::GetAddresses() { return addrman.GetAddr(); }

void CConnman::AddOneShot(const std::string &strDest)
{
    LOCK(cs_vOneShots);
    vOneShots.push_back(strDest);
}

bool CConnman::AddNode(const std::string &strNode)
{
    LOCK(cs_vAddedNodes);
    for (std::vector<std::string>::const_iterator it = vAddedNodes.begin(); it != vAddedNodes.end(); ++it)
    {
        if (strNode == *it)
        {
            return false;
        }
    }

    vAddedNodes.push_back(strNode);
    return true;
}

bool CConnman::RemoveAddedNode(const std::string &strNode)
{
    LOCK(cs_vAddedNodes);
    for (std::vector<std::string>::iterator it = vAddedNodes.begin(); it != vAddedNodes.end(); ++it)
    {
        if (strNode == *it)
        {
            vAddedNodes.erase(it);
            return true;
        }
    }
    return false;
}

std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo()
{
    std::vector<AddedNodeInfo> ret;

    std::list<std::string> lAddresses(0);
    {
        LOCK(cs_vAddedNodes);
        ret.reserve(vAddedNodes.size());
        for (const std::string &strAddNode : vAddedNodes)
        {
            lAddresses.push_back(strAddNode);
        }
    }

    // Build a map of all already connected addresses (by IP:port and by name)
    // to inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService> > mapConnectedByName;
    {
        LOCK(cs_vNodes);
        for (const CNode *pnode : vNodes)
        {
            if (pnode->addr.IsValid())
            {
                mapConnected[pnode->addr] = pnode->fInbound;
            }
            std::string addrName = pnode->GetAddrName();
            if (!addrName.empty())
            {
                mapConnectedByName[std::move(addrName)] =
                    std::make_pair(pnode->fInbound, static_cast<const CService &>(pnode->addr));
            }
        }
    }

    for (const std::string &strAddNode : lAddresses)
    {
        CService service(LookupNumeric(strAddNode.c_str(), Params().GetDefaultPort()));
        if (service.IsValid())
        {
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);
            if (it != mapConnected.end())
            {
                ret.push_back(AddedNodeInfo{strAddNode, service, true, it->second});
            }
            else
            {
                ret.push_back(AddedNodeInfo{strAddNode, CService(), false, false});
            }
        }
        else
        {
            // strAddNode is a name
            auto it = mapConnectedByName.find(strAddNode);
            if (it != mapConnectedByName.end())
            {
                ret.push_back(AddedNodeInfo{strAddNode, it->second.second, true, it->second.first});
            }
            else
            {
                ret.push_back(AddedNodeInfo{strAddNode, CService(), false, false});
            }
        }
    }

    return ret;
}

size_t CConnman::GetNodeCount(NumConnections flags)
{
    LOCK(cs_vNodes);
    // Shortcut if we want total
    if (flags == CConnman::CONNECTIONS_ALL)
    {
        return vNodes.size();
    }

    int nNum = 0;
    for (std::vector<CNode *>::const_iterator it = vNodes.begin(); it != vNodes.end(); ++it)
    {
        if (flags & ((*it)->fInbound ? CONNECTIONS_IN : CONNECTIONS_OUT))
        {
            nNum++;
        }
    }

    return nNum;
}

void CConnman::GetNodeStats(std::vector<CNodeStats> &vstats)
{
    vstats.clear();
    LOCK(cs_vNodes);
    vstats.reserve(vNodes.size());
    for (CNode *pnode : vNodes)
    {
        vstats.emplace_back();
        pnode->copyStats(vstats.back());
    }
}

bool CConnman::DisconnectNode(const std::string &strNode)
{
    LOCK(cs_vNodes);
    if (CNode *pnode = FindNode(strNode))
    {
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}
bool CConnman::DisconnectNode(NodeId id)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if (id == pnode->id)
        {
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

bool CConnman::DisconnectNode(const CSubNet &subNet)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if (subNet.Match((CNetAddr)pnode->addr))
        {
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

unsigned int CConnman::GetSendBufferSize() const { return nSendBufferMaxSize; }

void CConnman::AddWhitelistedRange(const CSubNet &subnet)
{
    LOCK(cs_vWhitelistedRange);
    vWhitelistedRange.push_back(subnet);
}

ServiceFlags CConnman::GetLocalServices() const { return nLocalServices; }

void CConnman::SetMaxOutboundTarget(uint64_t limit)
{
    LOCK(cs_totalBytesSent);
    nMaxOutboundLimit = limit;
}

uint64_t CConnman::GetMaxOutboundTarget()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundLimit;
}

uint64_t CConnman::GetMaxOutboundTimeframe()
{
    LOCK(cs_totalBytesSent);
    return nMaxOutboundTimeframe;
}

void CConnman::SetMaxOutboundTimeframe(uint64_t timeframe)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundTimeframe != timeframe)
    {
        // reset measure-cycle in case of changing the timeframe.
        nMaxOutboundCycleStartTime = GetTime();
    }
    nMaxOutboundTimeframe = timeframe;
}

bool CConnman::OutboundTargetReached(bool historicalBlockServingLimit)
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
    {
        return false;
    }

    if (historicalBlockServingLimit)
    {
        // keep a large enough buffer to at least relay each block once.
        uint64_t timeLeftInCycle = GetMaxOutboundTimeLeftInCycle();
        uint64_t buffer = timeLeftInCycle / 600 * MAX_BLOCK_SIZE;
        if (buffer >= nMaxOutboundLimit || nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer)
        {
            return true;
        }
    }
    else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
    {
        return true;
    }

    return false;
}

uint64_t CConnman::GetMaxOutboundTimeLeftInCycle()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
    {
        return 0;
    }

    if (nMaxOutboundCycleStartTime == 0)
    {
        return nMaxOutboundTimeframe;
    }

    uint64_t cycleEndTime = nMaxOutboundCycleStartTime + nMaxOutboundTimeframe;
    uint64_t now = GetTime();
    return (cycleEndTime < now) ? 0 : cycleEndTime - GetTime();
}

uint64_t CConnman::GetOutboundTargetBytesLeft()
{
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0)
    {
        return 0;
    }

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) ? 0 : nMaxOutboundLimit -
                                                                              nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CConnman::GetTotalBytesRecv()
{
    LOCK(cs_totalBytesRecv);
    return nTotalBytesRecv;
}

uint64_t CConnman::GetTotalBytesSent()
{
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}

CSipHasher CConnman::GetDeterministicRandomizer(uint64_t id) const { return CSipHasher(nSeed0, nSeed1).Write(id); }

unsigned int CConnman::GetReceiveFloodSize() const { return nReceiveFloodSize; }

CPubKey CConnman::GetPublicTagPubKey() const { return pub_routing_id; }

//////// private functions ////

void CConnman::ThreadOpenAddedConnections()
{
    {
        LOCK(cs_vAddedNodes);
        if (gArgs.IsArgSet("-addnode"))
        {
            vAddedNodes = gArgs.GetArgs("-addnode");
        }
    }

    while (true)
    {
        CSemaphoreGrant grant(*semAddnode);

        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo();
        bool tried = false;
        for (const AddedNodeInfo &info : vInfo)
        {
            if (!info.fConnected)
            {
                if (!grant.TryAcquire())
                {
                    // If we've used up our semaphore and need a new one, lets
                    // not wait here since while we are waiting the
                    // addednodeinfo state might change.
                    break;
                }
                // If strAddedNode is an IP/port, decode it immediately, so
                // OpenNetworkConnection can detect existing connections to that
                // IP/port.
                tried = true;
                CService service(
                    LookupNumeric(info.strAddedNode.c_str(), Params().GetDefaultPort()));
                OpenNetworkConnection(
                    CAddress(service, NODE_NONE), false, &grant, info.strAddedNode.c_str(), false, false, true);
                MilliSleep(500);
                if (interruptNet.load() == true)
                {
                    return;
                }
                break;
            }
        }
        // Retry every 60 seconds if a connection was attempted, otherwise two
        // seconds.
        MilliSleep((tried ? 60 : 2) * 1000);
        if (interruptNet.load() == true)
        {
            return;
        }
    }
}

void CConnman::ProcessOneShot()
{
    std::string strDest;
    {
        LOCK(cs_vOneShots);
        if (vOneShots.empty())
        {
            return;
        }
        strDest = vOneShots.front();
        vOneShots.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant)
    {
        if (!OpenNetworkConnection(addr, false, &grant, strDest.c_str(), true))
        {
            AddOneShot(strDest);
        }
    }
}

void CConnman::ThreadOpenConnections()
{
    // Connect to specific addresses
    if (gArgs.IsArgSet("-connect") && gArgs.GetArgs("-connect").size() > 0)
    {
        for (int64_t nLoop = 0;; nLoop++)
        {
            ProcessOneShot();
            for (const std::string &strAddr : gArgs.GetArgs("-connect"))
            {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, nullptr, strAddr.c_str());
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    MilliSleep(500);
                    if (interruptNet.load() == true)
                    {
                        return;
                    }
                }
            }
            MilliSleep(500);
            if (interruptNet.load() == true)
            {
                return;
            }
        }
    }

    // Initiate network connections
    int64_t nStart = GetTime();

    // Minimum time before next feeler connection (in microseconds).
    int64_t nNextFeeler = PoissonNextSend(nStart * 1000 * 1000, FEELER_INTERVAL);
    while (interruptNet.load() == false)
    {
        ProcessOneShot();

        MilliSleep(500);
        if (interruptNet.load() == true)
        {
            return;
        }

        CSemaphoreGrant grant(*semOutbound);
        if (interruptNet.load() == true)
        {
            return;
        }

        // Add seed nodes if DNS seeds are all down (an infrastructure attack?).
        if (addrman.size() == 0 && (GetTime() - nStart > 60))
        {
            static bool done = false;
            if (!done)
            {
                LogPrintf("Adding fixed seed nodes as DNS doesn't seem to be "
                          "available.\n");
                CNetAddr local;
                LookupHost("127.0.0.1", local, false);
                done = true;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4). Do
        // this here so we don't have to critsect vNodes inside mapAddresses
        // critsect.
        int nOutbound = 0;
        std::set<std::vector<uint8_t> > setConnected;
        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodes)
            {
                if (!pnode->fInbound && !pnode->fAddnode)
                {
                    // Netgroups for inbound and addnode peers are not excluded
                    // because our goal here is to not use multiple of our
                    // limited outbound slots on a single netgroup but inbound
                    // and addnode peers do not use our outbound slots. Inbound
                    // peers also have the added issue that they're attacker
                    // controlled and could be used to prevent us from
                    // connecting to particular hosts if we used them here.
                    setConnected.insert(pnode->addr.GetGroup());
                    nOutbound++;
                }
            }
        }

        // Feeler Connections
        //
        // Design goals:
        //  * Increase the number of connectable addresses in the tried table.
        //
        // Method:
        //  * Choose a random address from new and attempt to connect to it if
        //  we can connect successfully it is added to tried.
        //  * Start attempting feeler connections only after node finishes
        //  making outbound connections.
        //  * Only make a feeler connection once every few minutes.
        //
        bool fFeeler = false;
        if (nOutbound >= nMaxOutbound)
        {
            // The current time right now (in microseconds).
            int64_t nTime = GetTimeMicros();
            if (nTime > nNextFeeler)
            {
                nNextFeeler = PoissonNextSend(nTime, FEELER_INTERVAL);
                fFeeler = true;
            }
            else
            {
                continue;
            }
        }

        int64_t nANow = GetAdjustedTime();
        int nTries = 0;
        while (interruptNet.load() == false)
        {
            CAddrInfo addr = addrman.Select(fFeeler);

            // if we selected an invalid address, restart
            if (!addr.IsValid() || setConnected.count(addr.GetGroup()) || IsLocal(addr))
            {
                break;
            }

            // If we didn't find an appropriate destination after trying 100
            // addresses fetched from addrman, stop this loop, and let the outer
            // loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman
            // addresses.
            nTries++;
            if (nTries > 100)
            {
                break;
            }

            if (IsLimited(addr))
            {
                continue;
            }

            // only connect to full nodes
            if ((addr.nServices & REQUIRED_SERVICES) != REQUIRED_SERVICES)
            {
                continue;
            }

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 30)
            {
                continue;
            }

            // only consider nodes missing relevant services after 40 failed
            // attempts and only if less than half the outbound are up.
            if ((addr.nServices & nRelevantServices) != nRelevantServices &&
                (nTries < 40 || nOutbound >= (nMaxOutbound >> 1)))
            {
                continue;
            }

            // do not allow non-default ports, unless after 50 invalid addresses
            // selected already.
            if (addr.GetPort() != Params().GetDefaultPort() && nTries < 50)
            {
                continue;
            }

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid())
        {
            if (fFeeler)
            {
                // Add small amount of random noise before connection to avoid
                // synchronization.
                int randsleep = GetRandInt(FEELER_SLEEP_WINDOW * 1000);
                MilliSleep(randsleep);
                {
                    if (interruptNet.load() == true)
                    {
                        return;
                    }
                }
                LogPrintf("Making feeler connection to %s\n", addrConnect.ToString());
            }

            OpenNetworkConnection(addrConnect, (int)setConnected.size() >= std::min(nMaxConnections - 1, 2), &grant,
                nullptr, false, fFeeler);
        }
    }
}

void CConnman::ThreadMessageHandler()
{
    while (interruptNet.load() == false)
    {
        std::vector<CNode *> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            for (CNode *pnode : vNodesCopy)
            {
                pnode->AddRef();
            }
        }

        bool fMoreWork = false;

        for (CNode *pnode : vNodesCopy)
        {
            if (pnode->fDisconnect)
            {
                continue;
            }

            // Receive messages
            bool fMoreNodeWork = GetNodeSignals().ProcessMessages(pnode, *this);
            fMoreWork |= (fMoreNodeWork && !pnode->fPauseSend);

            // TODO : check if should be banned/disconnected here

            // Send messages
            {
                LOCK(pnode->cs_sendProcessing);
                GetNodeSignals().SendMessages(pnode, *this);
            }
        }

        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodesCopy)
            {
                pnode->Release();
            }
        }

        if (!fMoreWork)
        {
            MilliSleep(100);
        }
    }
}

void CConnman::AcceptConnection(const ListenSocket &hListenSocket)
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET hSocket = accept(hListenSocket.socket, (struct sockaddr *)&sockaddr, &len);
    CAddress addr;
    int nInbound = 0;
    int nMaxInbound = nMaxConnections - (nMaxOutbound + nMaxFeeler);

    if (hSocket != INVALID_SOCKET)
    {
        if (!addr.SetSockAddr((const struct sockaddr *)&sockaddr))
        {
            LogPrintf("Warning: Unknown socket family\n");
        }
    }

    bool whitelisted = hListenSocket.whitelisted || IsWhitelistedRange(addr);
    {
        LOCK(cs_vNodes);
        for (CNode *pnode : vNodes)
        {
            if (pnode->fInbound)
            {
                nInbound++;
            }
        }
    }

    if (hSocket == INVALID_SOCKET)
    {
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK)
        {
            LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        }
        return;
    }

    if (!IsSelectableSocket(hSocket))
    {
        LogPrintf("connection from %s dropped: non-selectable socket\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted
    // sockets on all platforms.  Set it again here just to be sure.
    int set = 1;
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char *)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&set, sizeof(int));
#endif

    if (g_dosman->IsBanned(addr) && !whitelisted)
    {
        LogPrintf("connection from %s dropped (banned)\n", addr.ToString());
        CloseSocket(hSocket);
        return;
    }

    if (nInbound >= nMaxInbound)
    {
        if (!AttemptToEvictConnection())
        {
            // No connection to evict, disconnect the new connection
            LogPrintf("failed to find an eviction candidate - "
                      "connection dropped (full)\n");
            CloseSocket(hSocket);
            return;
        }
    }

    // If connection attempts exceeded within allowable timeframe then ban peer
    {
        double nConnections = 0;
        LOCK(cs_mapInboundConnectionTracker);
        int64_t now = GetTime();
        CNetAddr ipAddress = (CNetAddr)addr;
        if (mapInboundConnectionTracker.count(ipAddress))
        {
            // Decay the current number of connections (over 60 seconds) depending on the last connection attempt
            int64_t nTimeElapsed = now - mapInboundConnectionTracker[ipAddress].nLastConnectionTime;
            if (nTimeElapsed < 0)
                nTimeElapsed = 0;
            double nRatioElapsed = (double)nTimeElapsed / 60;
            nConnections = mapInboundConnectionTracker[ipAddress].nConnections -
                           (nRatioElapsed * mapInboundConnectionTracker[ipAddress].nConnections);
            if (nConnections < 0)
                nConnections = 0;
        }
        else
        {
            ConnectionHistory ch;
            ch.nConnections = 0.0;
            ch.nLastConnectionTime = now;
            ch.nEvictions = 0.0;
            ch.nLastEvictionTime = now;
            mapInboundConnectionTracker[ipAddress] = ch;
        }

        nConnections += 1;
        mapInboundConnectionTracker[ipAddress].nConnections = nConnections;
        mapInboundConnectionTracker[ipAddress].nLastConnectionTime = GetTime();

        LogPrint("EVICT", "Number of connection attempts is %f for %s\n", nConnections, addr.ToString());
        if (nConnections > 4 && !whitelisted && !addr.IsLocal()) // local connections are auto-whitelisted
        {
            int nHoursToBan = 4;
            g_dosman->Ban((CNetAddr)addr, BanReasonNodeMisbehaving, nHoursToBan * 60 * 60);
            LogPrintf("Banning %s for %d hours: Too many connection attempts - connection dropped\n", addr.ToString(),
                nHoursToBan);
            CloseSocket(hSocket);
            return;
        }
    }

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();

    CNode *pnode = new CNode(id, nLocalServices, hSocket, addr, CalculateKeyedNetGroup(addr), nonce, "", true);
    pnode->AddRef();
    pnode->fWhitelisted = whitelisted;

    InitializeNode(pnode);

    LogPrintf("connection from %s accepted\n", addr.ToString());

    {
        LOCK(cs_vNodes);
        vNodes.push_back(pnode);
    }
}

void CConnman::ThreadSocketHandler()
{
    unsigned int nPrevNodeCount = 0;
    while (interruptNet.load() == false)
    {
        //
        // Disconnect nodes
        //
        {
            LOCK(cs_vNodes);
            // Disconnect unused nodes
            std::vector<CNode *> vNodesCopy = vNodes;
            for (CNode *pnode : vNodesCopy)
            {
                if (pnode->fDisconnect)
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();

                    // hold in disconnected pool until all refs are released
                    pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }
        }
        {
            // Delete disconnected nodes
            std::list<CNode *> vNodesDisconnectedCopy = vNodesDisconnected;
            for (CNode *pnode : vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_inventory, lockInv);
                        if (lockInv)
                        {
                            TRY_LOCK(pnode->cs_vSend, lockSend);
                            if (lockSend)
                            {
                                fDelete = true;
                            }
                        }
                    }
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        DeleteNode(pnode);
                    }
                }
            }
        }
        size_t vNodesSize;
        {
            LOCK(cs_vNodes);
            vNodesSize = vNodes.size();
        }
        if (vNodesSize != nPrevNodeCount)
        {
            nPrevNodeCount = vNodesSize;
        }

        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec = 0;
        // Frequency to poll pnode->vSend
        timeout.tv_usec = 50000;

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        bool have_fds = false;

        for (const ListenSocket &hListenSocket : vhListenSocket)
        {
            FD_SET(hListenSocket.socket, &fdsetRecv);
            hSocketMax = std::max(hSocketMax, hListenSocket.socket);
            have_fds = true;
        }

        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodes)
            {
                // Implement the following logic:
                // * If there is data to send, select() for sending data. As
                // this only happens when optimistic write failed, we choose to
                // first drain the write buffer in this case before receiving
                // more. This avoids needlessly queueing received data, if the
                // remote peer is not themselves receiving data. This means
                // properly utilizing TCP flow control signalling.
                // * Otherwise, if there is space left in the receive buffer,
                // select() for receiving data.
                // * Hand off all complete messages to the processor, to be
                // handled without blocking here.

                bool select_recv = !pnode->fPauseRecv;
                bool select_send = false;
                LOCK(pnode->cs_vSend);
                select_send = !pnode->vSendMsg.empty();


                LOCK(pnode->cs_hSocket);
                if (pnode->hSocket == INVALID_SOCKET)
                {
                    continue;
                }

                FD_SET(pnode->hSocket, &fdsetError);
                hSocketMax = std::max(hSocketMax, pnode->hSocket);
                have_fds = true;

                if (select_send)
                {
                    FD_SET(pnode->hSocket, &fdsetSend);
                    continue;
                }
                if (select_recv)
                {
                    FD_SET(pnode->hSocket, &fdsetRecv);
                }
            }
        }

        int nSelect = select(have_fds ? hSocketMax + 1 : 0, &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        if (interruptNet.load() == true)
        {
            return;
        }

        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();
                LogPrintf("socket select error %s\n", NetworkErrorString(nErr));
                for (unsigned int i = 0; i <= hSocketMax; i++)
                {
                    FD_SET(i, &fdsetRecv);
                }
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            MilliSleep(timeout.tv_usec / 1000);
            if (interruptNet.load() == true)
            {
                return;
            }
        }

        //
        // Accept new connections
        //
        for (const ListenSocket &hListenSocket : vhListenSocket)
        {
            if (hListenSocket.socket != INVALID_SOCKET && FD_ISSET(hListenSocket.socket, &fdsetRecv))
            {
                AcceptConnection(hListenSocket);
            }
        }

        //
        // Service each socket
        //
        std::vector<CNode *> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            for (CNode *pnode : vNodesCopy)
            {
                pnode->AddRef();
            }
        }
        for (CNode *pnode : vNodesCopy)
        {
            if (interruptNet.load() == true)
            {
                return;
            }

            //
            // Receive
            //
            bool recvSet = false;
            bool sendSet = false;
            bool errorSet = false;
            {
                LOCK(pnode->cs_hSocket);
                if (pnode->hSocket == INVALID_SOCKET)
                {
                    continue;
                }
                recvSet = FD_ISSET(pnode->hSocket, &fdsetRecv);
                sendSet = FD_ISSET(pnode->hSocket, &fdsetSend);
                errorSet = FD_ISSET(pnode->hSocket, &fdsetError);
            }
            if (recvSet || errorSet)
            {
                // typical socket buffer is 8K-64K
                char pchBuf[0x10000];
                int nBytes = 0;
                {
                    LOCK(pnode->cs_hSocket);
                    if (pnode->hSocket == INVALID_SOCKET)
                    {
                        continue;
                    }
                    nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                }
                if (nBytes > 0)
                {
                    bool notify = false;
                    if (!pnode->ReceiveMsgBytes(pchBuf, nBytes, notify))
                    {
                        pnode->CloseSocketDisconnect();
                    }
                    RecordBytesRecv(nBytes);
                    if (notify)
                    {
                        size_t nSizeAdded = 0;
                        auto it(pnode->vRecvMsg.begin());
                        for (; it != pnode->vRecvMsg.end(); ++it)
                        {
                            if (!it->complete())
                            {
                                break;
                            }
                            nSizeAdded += it->vRecv.size() + CMessageHeader::HEADER_SIZE;
                        }
                        {
                            LOCK(pnode->cs_vProcessMsg);
                            pnode->vProcessMsg.splice(
                                pnode->vProcessMsg.end(), pnode->vRecvMsg, pnode->vRecvMsg.begin(), it);
                            pnode->nProcessQueueSize += nSizeAdded;
                            pnode->fPauseRecv = pnode->nProcessQueueSize > nReceiveFloodSize;
                        }
                    }
                }
                else if (nBytes == 0)
                {
                    // socket closed gracefully
                    if (!pnode->fDisconnect)
                    {
                        LogPrintf("socket closed\n");
                    }
                    pnode->CloseSocketDisconnect();
                }
                else if (nBytes < 0)
                {
                    // error
                    int nErr = WSAGetLastError();
                    if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                    {
                        if (!pnode->fDisconnect)
                        {
                            LogPrintf("socket recv error %s\n", NetworkErrorString(nErr));
                        }
                        pnode->CloseSocketDisconnect();
                    }
                }
            }

            //
            // Send
            //
            if (sendSet)
            {
                LOCK(pnode->cs_vSend);
                size_t nBytes = SocketSendData(pnode);
                if (nBytes)
                {
                    RecordBytesSent(nBytes);
                }
            }

            //
            // Inactivity checking
            //
            int64_t nTime = GetSystemTimeInSeconds();
            if (nTime - pnode->nTimeConnected > 60)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    LogPrintf("socket no message in first 60 "
                              "seconds, %d %d from %d\n",
                        pnode->nLastRecv != 0, pnode->nLastSend != 0, pnode->id);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastSend > TIMEOUT_INTERVAL)
                {
                    LogPrintf("socket sending timeout: %is\n", nTime - pnode->nLastSend);
                    pnode->fDisconnect = true;
                }
                else if (nTime - pnode->nLastRecv > TIMEOUT_INTERVAL)
                {
                    LogPrintf("socket receive timeout: %is\n", nTime - pnode->nLastRecv);
                    pnode->fDisconnect = true;
                }
                else if (pnode->nPingNonceSent && pnode->nPingUsecStart + TIMEOUT_INTERVAL * 1000000 < GetTimeMicros())
                {
                    LogPrintf("ping timeout: %fs\n", 0.000001 * (GetTimeMicros() - pnode->nPingUsecStart));
                    pnode->fDisconnect = true;
                }
                else if (!pnode->fSuccessfullyConnected)
                {
                    LogPrintf("version handshake timeout from %d\n", pnode->id);
                    pnode->fDisconnect = true;
                }
            }
        }
        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodesCopy)
            {
                pnode->Release();
            }
        }
    }
}

static std::string GetDNSHost(const CDNSSeedData &data, ServiceFlags *requiredServiceBits)
{
    // use default host for non-filter-capable seeds or if we use the default
    // service bits (NODE_NETWORK)
    if (!data.supportsServiceBitsFiltering || *requiredServiceBits == NODE_NETWORK)
    {
        *requiredServiceBits = NODE_NETWORK;
        return data.host;
    }

    // See chainparams.cpp, most dnsseeds only support one or two possible
    // servicebits hostnames
    return strprintf("x%x.%s", *requiredServiceBits, data.host);
}

void CConnman::ThreadDNSAddressSeed()
{
    // goal: only query DNS seeds if address need is acute.
    // Avoiding DNS seeds when we don't need them improves user privacy by
    // creating fewer identifying DNS requests, reduces trust by giving seeds
    // less influence on the network topology, and reduces traffic to the seeds.
    if ((addrman.size() > 0) && (!gArgs.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED)))
    {
        MilliSleep(5000);
        if (interruptNet.load() == true)
        {
            return;
        }

        LOCK(cs_vNodes);
        int nRelevant = 0;
        for (auto pnode : vNodes)
        {
            nRelevant += pnode->fSuccessfullyConnected && ((pnode->nServices & nRelevantServices) == nRelevantServices);
        }
        if (nRelevant >= 2)
        {
            LogPrintf("P2P peers available. Skipped DNS seeding.\n");
            return;
        }
    }

    const std::vector<CDNSSeedData> &vSeeds = Params().DNSSeeds();
    int found = 0;

    LogPrintf("Loading addresses from DNS seeds (could take a while)\n");

    for (const CDNSSeedData &seed : vSeeds)
    {
        if (HaveNameProxy())
        {
            AddOneShot(seed.host);
        }
        else
        {
            std::vector<CNetAddr> vIPs;
            std::vector<CAddress> vAdd;
            ServiceFlags requiredServiceBits = nRelevantServices;
            if (LookupHost(GetDNSHost(seed, &requiredServiceBits).c_str(), vIPs, 0, true))
            {
                for (const CNetAddr &ip : vIPs)
                {
                    int nOneDay = 24 * 3600;
                    CAddress addr = CAddress(
                        CService(ip, Params().GetDefaultPort()), requiredServiceBits);
                    // Use a random age between 3 and 7 days old.
                    addr.nTime = GetTime() - 3 * nOneDay - GetRand(4 * nOneDay);
                    vAdd.push_back(addr);
                    found++;
                }
            }
            // TODO: The seed name resolve may fail, yielding an IP of [::],
            // which results in addrman assigning the same source to results
            // from different seeds. This should switch to a hard-coded stable
            // dummy IP for each seed name, so that the resolve is not required
            // at all.
            if (!vIPs.empty())
            {
                CService seedSource;
                Lookup(seed.name.c_str(), seedSource, 0, true);
                addrman.Add(vAdd, seedSource);
            }
        }
    }

    LogPrintf("%d addresses found from DNS seeds\n", found);
}

uint64_t CConnman::CalculateKeyedNetGroup(const CAddress &ad) const
{
    std::vector<uint8_t> vchNetGroup(ad.GetGroup());

    return GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(&vchNetGroup[0], vchNetGroup.size()).Finalize();
}

CNode *CConnman::FindNode(const CNetAddr &ip)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if ((CNetAddr)pnode->addr == ip)
        {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const CSubNet &subNet)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if (subNet.Match((CNetAddr)pnode->addr))
        {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const std::string &addrName)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if (pnode->GetAddrName() == addrName)
        {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const CService &addr)
{
    LOCK(cs_vNodes);
    for (CNode *pnode : vNodes)
    {
        if ((CService)pnode->addr == addr)
        {
            return pnode;
        }
    }
    return nullptr;
}

static bool CompareNodeActivityBytes(const CNodeRef &a, const CNodeRef &b)
{
    return a->nActivityBytes < b->nActivityBytes;
}

bool CConnman::AttemptToEvictConnection()
{
    std::vector<CNodeRef> vEvictionCandidates;
    std::vector<CNodeRef> vEvictionCandidatesByActivity;
    {
        LOCK(cs_vNodes);
        static int64_t nLastTime = GetTime();
        for (CNode *node : vNodes)
        {
            int64_t nNow = GetTime();
            node->nActivityBytes *= pow(1.0 - 1.0 / 7200, (double)(nNow - nLastTime)); // exponential 2 hour decay

            if (node->fWhitelisted || !node->fInbound || node->fDisconnect)
            {
                continue;
            }
            vEvictionCandidates.push_back(CNodeRef(node));
        }
        nLastTime = GetTime();
    }
    vEvictionCandidatesByActivity = vEvictionCandidates;

    if (vEvictionCandidates.empty())
    {
        return false;
    }

    // If we get here then we prioritize connections based on activity.  The least active incoming peer is
    // de-prioritized based on bytes in and bytes out.  A whitelisted peer will always get a connection and there is
    // no need here to check whether the peer is whitelisted or not.
    std::sort(vEvictionCandidatesByActivity.begin(), vEvictionCandidatesByActivity.end(), CompareNodeActivityBytes);
    vEvictionCandidatesByActivity[0]->fDisconnect = true;

    // BU - update the connection tracker
    {
        double nEvictions = 0;
        LOCK(cs_mapInboundConnectionTracker);
        CNetAddr ipAddress = (CNetAddr)vEvictionCandidatesByActivity[0]->addr;
        if (mapInboundConnectionTracker.count(ipAddress))
        {
            // Decay the current number of evictions (over 1800 seconds) depending on the last eviction
            int64_t nTimeElapsed = GetTime() - mapInboundConnectionTracker[ipAddress].nLastEvictionTime;
            double nRatioElapsed = (double)nTimeElapsed / 1800;
            nEvictions = mapInboundConnectionTracker[ipAddress].nEvictions -
                         (nRatioElapsed * mapInboundConnectionTracker[ipAddress].nEvictions);
            if (nEvictions < 0)
                nEvictions = 0;
        }

        nEvictions += 1;
        mapInboundConnectionTracker[ipAddress].nEvictions = nEvictions;
        mapInboundConnectionTracker[ipAddress].nLastEvictionTime = GetTime();

        LogPrint("EVICT", "Number of Evictions is %f for %s\n", nEvictions,
            vEvictionCandidatesByActivity[0]->addr.ToString());
        if (nEvictions > 15)
        {
            int nHoursToBan = 4;
            g_dosman->Ban(ipAddress, BanReasonNodeMisbehaving, nHoursToBan * 60 * 60);
            LogPrintf("Banning %s for %d hours: Too many evictions - connection dropped\n",
                vEvictionCandidatesByActivity[0]->addr.ToString(), nHoursToBan);
        }
    }

    LogPrint("EVICT", "Node disconnected because too inactive:%d bytes of activity for peer %s\n",
        vEvictionCandidatesByActivity[0]->nActivityBytes, vEvictionCandidatesByActivity[0]->addrName);
    for (unsigned int i = 0; i < vEvictionCandidatesByActivity.size(); i++)
    {
        LogPrint("EVICT", "Node %s bytes %d candidate %d\n", vEvictionCandidatesByActivity[i]->addrName,
            vEvictionCandidatesByActivity[i]->nActivityBytes, i);
    }

    return true;
}

CNode *CConnman::ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure)
{
    if (pszDest == nullptr)
    {
        if (IsLocal(addrConnect))
        {
            return nullptr;
        }

        // Look for an existing connection
        CNode *pnode = FindNode((CService)addrConnect);
        if (pnode)
        {
            LogPrintf("Failed to open new connection, already connected\n");
            return nullptr;
        }
    }

    /// debug print
    LogPrintf("trying connection %s lastseen=%.1fhrs\n", pszDest ? pszDest : addrConnect.ToString(),
        pszDest ? 0.0 : (double)(GetAdjustedTime() - addrConnect.nTime) / 3600.0);

    // Connect
    SOCKET hSocket;
    bool proxyConnectionFailed = false;
    if (pszDest ? ConnectSocketByName(addrConnect, hSocket, pszDest,
                      Params().GetDefaultPort(), nConnectTimeout, &proxyConnectionFailed) :
                  ConnectSocket(addrConnect, hSocket, nConnectTimeout, &proxyConnectionFailed))
    {
        if (!IsSelectableSocket(hSocket))
        {
            LogPrintf("Cannot create connection: non-selectable socket created "
                      "(fd >= FD_SETSIZE ?)\n");
            CloseSocket(hSocket);
            return nullptr;
        }

        if (pszDest && addrConnect.IsValid())
        {
            // It is possible that we already have a connection to the IP/port
            // pszDest resolved to. In that case, drop the connection that was
            // just created, and return the existing CNode instead. Also store
            // the name we used to connect in that CNode, so that future
            // FindNode() calls to that name catch this early.
            LOCK(cs_vNodes);
            CNode *pnode = FindNode((CService)addrConnect);
            if (pnode)
            {
                pnode->MaybeSetAddrName(std::string(pszDest));
                CloseSocket(hSocket);
                LogPrintf("Failed to open new connection, already connected\n");
                return nullptr;
            }
        }

        addrman.Attempt(addrConnect, fCountFailure);

        // Add node
        NodeId id = GetNewNodeId();
        uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();
        CNode *pnode = new CNode(id, nLocalServices, hSocket, addrConnect, CalculateKeyedNetGroup(addrConnect), nonce,
            pszDest ? pszDest : "", false);
        pnode->nServicesExpected = ServiceFlags(addrConnect.nServices & nRelevantServices);
        pnode->AddRef();

        return pnode;
    }
    else if (!proxyConnectionFailed)
    {
        // If connecting to the node failed, and failure is not caused by a
        // problem connecting to the proxy, mark this as an attempt.
        addrman.Attempt(addrConnect, fCountFailure);
    }

    return nullptr;
}

bool CConnman::IsWhitelistedRange(const CNetAddr &addr)
{
    LOCK(cs_vWhitelistedRange);
    for (const CSubNet &subnet : vWhitelistedRange)
    {
        if (subnet.Match(addr))
        {
            return true;
        }
    }
    return false;
}

void CConnman::DeleteNode(CNode *pnode)
{
    assert(pnode);
    bool fUpdateConnectionTime = false;
    g_requestman->RemoveNodeState(pnode->GetId());
    if (fUpdateConnectionTime)
    {
        addrman.Connected(pnode->addr);
    }
    delete pnode;
}

NodeId CConnman::GetNewNodeId() { return nLastNodeId.fetch_add(1, std::memory_order_relaxed); }

// requires LOCK(cs_vSend)
size_t CConnman::SocketSendData(CNode *pnode) const
{
    AssertLockHeld(pnode->cs_vSend);
    size_t nSentSize = 0;
    size_t nMsgCount = 0;

    for (const auto &data : pnode->vSendMsg)
    {
        assert(data.size() > pnode->nSendOffset);
        int nBytes = 0;

        {
            LOCK(pnode->cs_hSocket);
            if (pnode->hSocket == INVALID_SOCKET)
            {
                break;
            }

            nBytes = send(pnode->hSocket, reinterpret_cast<const char *>(data.data()) + pnode->nSendOffset,
                data.size() - pnode->nSendOffset, MSG_NOSIGNAL | MSG_DONTWAIT);
        }

        if (nBytes == 0)
        {
            // couldn't send anything at all
            break;
        }

        if (nBytes < 0)
        {
            // error
            int nErr = WSAGetLastError();
            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
            {
                LogPrintf("socket send error %s\n", NetworkErrorString(nErr));
                pnode->CloseSocketDisconnect();
            }

            break;
        }

        assert(nBytes > 0);
        pnode->nLastSend = GetSystemTimeInSeconds();
        pnode->nSendBytes += nBytes;
        pnode->nSendOffset += nBytes;
        nSentSize += nBytes;
        if (pnode->nSendOffset != data.size())
        {
            // could not send full message; stop sending more
            break;
        }

        pnode->nSendOffset = 0;
        pnode->nSendSize -= data.size();
        pnode->fPauseSend = pnode->nSendSize > nSendBufferMaxSize;
        nMsgCount++;
    }

    pnode->vSendMsg.erase(pnode->vSendMsg.begin(), pnode->vSendMsg.begin() + nMsgCount);

    if (pnode->vSendMsg.empty())
    {
        assert(pnode->nSendOffset == 0);
        assert(pnode->nSendSize == 0);
    }

    return nSentSize;
}

void CConnman::DumpAddresses()
{
    int64_t nStart = GetTimeMillis();

    CAddrDB adb;
    adb.Write(addrman);

    LogPrintf("Flushed %d addresses to peers.dat  %dms\n", addrman.size(), GetTimeMillis() - nStart);
}

void CConnman::_DumpData()
{
    DumpAddresses();
    g_dosman->DumpBanlist();
}

void CConnman::DumpData(int64_t seconds_between_runs)
{
    while (interruptNet.load() == false)
    {
        // this has the potential to be a long sleep. so do it in chunks incase of node shutdown
        int64_t nStart = GetTime();
        int64_t nEnd = nStart + seconds_between_runs;
        while (nStart < nEnd)
        {
            if (interruptNet.load() == true)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        _DumpData();
    }
}

void CConnman::RecordBytesRecv(uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);
    nTotalBytesRecv += bytes;
}

void CConnman::RecordBytesSent(uint64_t bytes)
{
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;

    uint64_t now = GetTime();
    if (nMaxOutboundCycleStartTime + nMaxOutboundTimeframe < now)
    {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    // TODO, exclude whitebind peers
    nMaxOutboundTotalBytesSentInCycle += bytes;
}

bool CConnman::NodeFullyConnected(const CNode *pnode)
{
    return pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect;
}

void CConnman::InitializeNode(CNode *pnode)
{
    g_requestman->InitializeNodeState(pnode);

    if (!pnode->fInbound)
    {
        PushNodeVersion(pnode, GetTime());
    }
}

void CConnman::PushNodeVersion(CNode *pnode, int64_t nTime)
{
    ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
    int nNodeStartingHeight = g_chainman.chainActive.Height();
    NodeId nodeid = pnode->GetId();
    CAddress addr = pnode->addr;

    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    GetRandBytes((unsigned char *)&nLocalHostNonce, sizeof(nLocalHostNonce));

    PushMessage(pnode, NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou,
        addrMe, nLocalHostNonce, strSubVersion, nNodeStartingHeight, ::fRelayTxes);

    if (g_logger->fLogIPs)
    {
        LogPrintf("send version message: version %d, blocks=%d, "
                  "us=%s, them=%s, peer=%d\n",
            PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), addrYou.ToString(), nodeid);
    }
    else
    {
        LogPrintf("send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION,
            nNodeStartingHeight, addrMe.ToString(), nodeid);
    }
}
