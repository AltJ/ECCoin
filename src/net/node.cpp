// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "node.h"

CNode::CNode(NodeId idIn,
    ServiceFlags nLocalServicesIn,
    SOCKET hSocketIn,
    const CAddress &addrIn,
    uint64_t nKeyedNetGroupIn,
    uint64_t nLocalHostNonceIn,
    const std::string &addrNameIn,
    bool fInboundIn)
    : nTimeConnected(GetSystemTimeInSeconds()), addr(addrIn), fInbound(fInboundIn), id(idIn),
      nKeyedNetGroup(nKeyedNetGroupIn), addrKnown(5000, 0.001), filterInventoryKnown(50000, 0.000001),
      nLocalServices(nLocalServicesIn), nSendVersion(0)
{
    nServices = NODE_NONE;
    nServicesExpected = NODE_NONE;
    hSocket = hSocketIn;
    nRecvVersion = MIN_PROTO_VERSION;
    nLastSend = 0;
    nLastRecv = 0;
    nSendBytes = 0;
    nRecvBytes = 0;
    nActivityBytes = 0;
    nTimeOffset = 0;
    addrName = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
    nVersion = 0;
    strSubVer = "";
    fWhitelisted = false;
    fOneShot = false;
    fAddnode = false;
    // set by version message
    fClient = false;
    fFeeler = false;
    fSuccessfullyConnected = false;
    fDisconnect = false;
    nRefCount = 0;
    nSendSize = 0;
    nSendOffset = 0;
    nStartingHeight = -1;
    filterInventoryKnown.reset();
    fSendMempool = false;
    fGetAddr = false;
    nNextLocalAddrSend = 0;
    nNextAddrSend = 0;
    fRelayTxes = false;
    fSentAddr = false;
    pfilter = new CBloomFilter();
    timeLastMempoolReq = 0;
    nLastBlockTime = 0;
    nLastTXTime = 0;
    nPingNonceSent = 0;
    nPingUsecStart = 0;
    nPingUsecTime = 0;
    fPingQueued = false;
    nMinPingUsecTime = std::numeric_limits<int64_t>::max();
    fPauseRecv = false;
    fPauseSend = false;
    nProcessQueueSize = 0;
    nNetworkServiceVersion = 0;

    for (const std::string &msg : getAllNetMessageTypes())
    {
        mapRecvBytesPerMsgCmd[msg] = 0;
    }
    mapRecvBytesPerMsgCmd[NET_MESSAGE_COMMAND_OTHER] = 0;

    if (g_logger->fLogIPs)
    {
        LogPrint("net", "Added connection to %s peer=%d\n", addrName, id);
    }
    else
    {
        LogPrint("net", "Added connection peer=%d\n", id);
    }
}

CNode::~CNode()
{
    CloseSocket(hSocket);

    if (pfilter)
    {
        delete pfilter;
    }
}

void CNode::AskFor(const CInv &inv)
{
    // TODO : mmake it clear this function is only for transactions
    // this function is only for transactions
    if (inv.type != MSG_TX)
    {
        return;
    }
    LOCK(cs_askfor);
    LOCK(cs_alreadyaskfor);
    if (mapAskFor.size() > MAPASKFOR_MAX_SZ || setAskFor.size() > SETASKFOR_MAX_SZ)
    {
        return;
    }

    // a peer may not have multiple non-responded queue positions for a single
    // inv item.
    if (!setAskFor.insert(inv.hash).second)
    {
        return;
    }

    // We're using mapAskFor as a priority queue, the key is the earliest time
    // the request can be sent.
    int64_t nRequestTime;
    std::map<uint256, int64_t>::iterator it = mapAlreadyAskedFor.find(inv.hash);
    if (it != mapAlreadyAskedFor.end())
    {
        nRequestTime = it->second;
    }
    else
    {
        nRequestTime = 0;
    }
    LogPrintf("askfor %s  %d (%s) peer=%d\n", inv.ToString(), nRequestTime,
        DateTimeStrFormat("%H:%M:%S", nRequestTime / 1000000), id);

    // Make sure not to reuse time indexes to keep things in the same order
    int64_t nNow = GetTimeMicros() - 1000000;
    static int64_t nLastTime;
    ++nLastTime;
    nNow = std::max(nNow, nLastTime);
    nLastTime = nNow;

    // Each retry is 2 minutes after the last
    nRequestTime = std::max(nRequestTime + 2 * 60 * 1000000, nNow);
    if (it != mapAlreadyAskedFor.end())
    {
        it->second = nRequestTime;
    }
    else
    {
        mapAlreadyAskedFor.insert(std::make_pair(inv.hash, nRequestTime));
    }
    mapAskFor.insert(std::make_pair(nRequestTime, inv));
}

void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    LOCK(cs_hSocket);
    if (hSocket != INVALID_SOCKET)
    {
        LogPrintf("disconnecting peer=%d\n", id);
        CloseSocket(hSocket);
    }
}

std::string CNode::GetAddrName() const
{
    LOCK(cs_addrName);
    return addrName;
}

void CNode::MaybeSetAddrName(const std::string &addrNameIn)
{
    LOCK(cs_addrName);
    if (addrName.empty())
    {
        addrName = addrNameIn;
    }
}

CService CNode::GetAddrLocal() const
{
    LOCK(cs_addrLocal);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService &addrLocalIn)
{
    LOCK(cs_addrLocal);
    if (addrLocal.IsValid())
    {
        error("Addr local already set for node: %i. Refusing to change from %s "
              "to %s",
            id, addrLocal.ToString(), addrLocalIn.ToString());
    }
    else
    {
        addrLocal = addrLocalIn;
    }
}

#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats)
{
    stats.nodeid = this->GetId();
    X(nServices);
    X(addr);
    {
        LOCK(cs_filter);
        X(fRelayTxes);
    }
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(nTimeOffset);
    stats.addrName = GetAddrName();
    X(nVersion);
    {
        LOCK(cs_SubVer);
        X(cleanSubVer);
    }
    X(fInbound);
    X(fAddnode);
    X(nStartingHeight);
    {
        LOCK(cs_vSend);
        X(mapSendBytesPerMsgCmd);
        X(nSendBytes);
    }
    {
        LOCK(cs_vRecv);
        X(mapRecvBytesPerMsgCmd);
        X(nRecvBytes);
    }
    X(fWhitelisted);

    // It is common for nodes with good ping times to suddenly become lagged,
    // due to a new block arriving or other large transfer. Merely reporting
    // pingtime might fool the caller into thinking the node was still
    // responsive, since pingtime does not update until the ping is complete,
    // which might take a while. So, if a ping is taking an unusually long time
    // in flight, the caller can immediately detect that this is happening.
    int64_t nPingUsecWait = 0;
    if ((0 != nPingNonceSent) && (0 != nPingUsecStart))
    {
        nPingUsecWait = GetTimeMicros() - nPingUsecStart;
    }

    // Raw ping time is in microseconds, but show it to user as whole seconds
    // (Bitcoin users should be well used to small numbers with many decimal
    // places by now :)
    stats.dPingTime = ((double(nPingUsecTime)) / 1e6);
    stats.dMinPing = ((double(nMinPingUsecTime)) / 1e6);
    stats.dPingWait = ((double(nPingUsecWait)) / 1e6);

    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnlocked = GetAddrLocal();
    stats.addrLocal = addrLocalUnlocked.IsValid() ? addrLocalUnlocked.ToString() : "";
}
#undef X

bool CNode::ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool &complete)
{
    complete = false;
    int64_t nTimeMicros = GetTimeMicros();
    LOCK(cs_vRecv);
    nLastRecv = nTimeMicros / 1000000;
    nRecvBytes += nBytes;
    while (nBytes > 0)
    {
        // Get current incomplete message, or create a new one.
        if (vRecvMsg.empty() || vRecvMsg.back().complete())
        {
            vRecvMsg.push_back(
                CNetMessage(Params().MessageStart(), SER_NETWORK, MIN_PROTO_VERSION));
        }

        CNetMessage &msg = vRecvMsg.back();

        // Absorb network data.
        int handled;
        if (!msg.in_data)
        {
            handled = msg.readHeader(pch, nBytes);
        }
        else
        {
            handled = msg.readData(pch, nBytes);
        }

        if (handled < 0)
        {
            return false;
        }

        if (msg.in_data && msg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH)
        {
            LogPrintf("Oversized message from peer=%i, disconnecting\n", GetId());
            return false;
        }

        pch += handled;
        nBytes -= handled;

        if (msg.complete())
        {
            // Store received bytes per message command to prevent a memory DOS,
            // only allow valid commands.
            mapMsgCmdSize::iterator i = mapRecvBytesPerMsgCmd.find(msg.hdr.pchCommand);
            if (i == mapRecvBytesPerMsgCmd.end())
            {
                i = mapRecvBytesPerMsgCmd.find(NET_MESSAGE_COMMAND_OTHER);
            }
            nActivityBytes += msg.hdr.nMessageSize;

            assert(i != mapRecvBytesPerMsgCmd.end());
            i->second += msg.hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

            msg.nTime = nTimeMicros;
            complete = true;
        }
    }

    return true;
}

void CNode::SetSendVersion(int nVersionIn) { nSendVersion = nVersionIn; }
int CNode::GetSendVersion() const
{
    // The send version should always be explicitly set to INIT_PROTO_VERSION
    // rather than using this value until SetSendVersion has been called.
    if (nSendVersion == 0)
    {
        LogPrint("net", "Requesting unset send version for node: %i. Using %i", id, MIN_PROTO_VERSION);
        return MIN_PROTO_VERSION;
    }
    return nSendVersion;
}
