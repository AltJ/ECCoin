// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "net/net.h"

#include "args.h"
#include "beta.h"
#include "chain/tx.h"
#include "clientversion.h"
#include "consensus/consensus.h"
#include "crypto/common.h"
#include "crypto/hash.h"
#include "init.h"
#include "net/addrman.h"
#include "chain/chainparams.h"

#include "util/utilstrencodings.h"

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#include <boost/filesystem.hpp>

#include <memory>

#include <cmath>

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

// Fix for ancient MinGW versions, that don't have defined these in ws2tcpip.h.
// Todo: Can be removed when our pull-tester is upgraded to a modern MinGW
// version.
#ifdef WIN32
#ifndef PROTECTION_LEVEL_UNRESTRICTED
#define PROTECTION_LEVEL_UNRESTRICTED 10
#endif
#ifndef IPV6_PROTECTION_LEVEL
#define IPV6_PROTECTION_LEVEL 23
#endif
#endif

//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
bool fRelayTxes = true;
extern CCriticalSection cs_mapLocalHost;
extern std::map<CNetAddr, LocalServiceInfo> mapLocalHost;
static bool vfLimited[NET_MAX] = {};

// TODO : replace this map with something else in the request manager
// tracking what was asked for and who to ask for txs is currently very poorly managed
CCriticalSection cs_alreadyaskfor;
std::map<uint256, int64_t> mapAlreadyAskedFor;

std::string strSubVersion;

// Signals for message handling
static CNodeSignals g_signals;
CNodeSignals &GetNodeSignals() { return g_signals; }

unsigned short GetListenPort()
{
    return (unsigned short)(gArgs.GetArg("-port", Params().GetDefaultPort()));
}

// find 'best' local address for a particular peer
bool GetLocal(CService &addr, const CNetAddr *paddrPeer)
{
    if (!fListen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(cs_mapLocalHost);
        for (std::map<CNetAddr, LocalServiceInfo>::iterator it = mapLocalHost.begin(); it != mapLocalHost.end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

// Get best local address for a particular peer as a CAddress. Otherwise, return
// the unroutable 0.0.0.0 but filled in with the normal parameters, since the IP
// may be changed to a useful one by discovery.
CAddress GetLocalAddress(const CNetAddr *paddrPeer, ServiceFlags nLocalServices)
{
    CAddress ret(CService(CNetAddr(), GetListenPort()), NODE_NONE);
    CService addr;
    if (GetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr, nLocalServices);
    }
    ret.nTime = GetAdjustedTime();
    return ret;
}

int GetnScore(const CService &addr)
{
    LOCK(cs_mapLocalHost);
    if (mapLocalHost.count(addr) == LOCAL_NONE)
    {
        return 0;
    }
    return mapLocalHost[addr].nScore;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode)
{
    CService addrLocal = pnode->GetAddrLocal();
    return fDiscover && pnode->addr.IsRoutable() && addrLocal.IsRoutable() && !IsLimited(addrLocal.GetNetwork());
}

// Pushes our own address to a peer.
void AdvertiseLocal(CNode *pnode)
{
    if (fListen && pnode->fSuccessfullyConnected)
    {
        CAddress addrLocal = GetLocalAddress(&pnode->addr, pnode->GetLocalServices());
        // If discovery is enabled, sometimes give our peer the address it tells
        // us that it sees us as in case it has a better idea of our address
        // than we do.
        if (IsPeerAddrLocalGood(pnode) &&
            (!addrLocal.IsRoutable() || GetRand((GetnScore(addrLocal) > LOCAL_MANUAL) ? 8 : 2) == 0))
        {
            addrLocal.SetIP(pnode->GetAddrLocal());
        }
        if (addrLocal.IsRoutable())
        {
            LogPrintf("AdvertiseLocal: advertising address %s\n", addrLocal.ToString());
            FastRandomContext insecure_rand;
            pnode->PushAddress(addrLocal, insecure_rand);
        }
    }
}

// Learn a new local address.
bool AddLocal(const CService &addr, int nScore)
{
    if (!addr.IsRoutable())
    {
        return false;
    }

    if (!fDiscover && nScore < LOCAL_MANUAL)
    {
        return false;
    }

    if (IsLimited(addr))
    {
        return false;
    }

    LogPrintf("AddLocal(%s,%i)\n", addr.ToString(), nScore);

    {
        LOCK(cs_mapLocalHost);
        bool fAlready = mapLocalHost.count(addr) > 0;
        LocalServiceInfo &info = mapLocalHost[addr];
        if (!fAlready || nScore >= info.nScore)
        {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore) { return AddLocal(CService(addr, GetListenPort()), nScore); }
bool RemoveLocal(const CService &addr)
{
    LOCK(cs_mapLocalHost);
    LogPrintf("RemoveLocal(%s)\n", addr.ToString());
    mapLocalHost.erase(addr);
    return true;
}

/** Make a particular network entirely off-limits (no automatic connects to it)
 */
void SetLimited(enum Network net, bool fLimited)
{
    if (net == NET_UNROUTABLE)
    {
        return;
    }
    LOCK(cs_mapLocalHost);
    vfLimited[net] = fLimited;
}

bool IsLimited(enum Network net)
{
    LOCK(cs_mapLocalHost);
    return vfLimited[net];
}

bool IsLimited(const CNetAddr &addr) { return IsLimited(addr.GetNetwork()); }
/** vote for a local address */
bool SeenLocal(const CService &addr)
{
    LOCK(cs_mapLocalHost);
    if (mapLocalHost.count(addr) == 0)
    {
        return false;
    }
    mapLocalHost[addr].nScore++;
    return true;
}

/** check whether a given address is potentially local */
bool IsLocal(const CService &addr)
{
    LOCK(cs_mapLocalHost);
    return mapLocalHost.count(addr) > 0;
}

/** check whether a given network is one we can probably connect to */
bool IsReachable(enum Network net)
{
    LOCK(cs_mapLocalHost);
    return !vfLimited[net];
}

/** check whether a given address is in a network we can probably connect to */
bool IsReachable(const CNetAddr &addr)
{
    enum Network net = addr.GetNetwork();
    return IsReachable(net);
}

std::atomic<bool> upnp_thread_shutdown(false);

#ifdef USE_UPNP
void ThreadMapPort()
{
    std::string port = strprintf("%u", GetListenPort());
    const char *multicastif = 0;
    const char *minissdpdpath = 0;
    struct UPNPDev *devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#elif MINIUPNPC_API_VERSION < 14
    /* miniupnpc 1.6 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#else
    /* miniupnpc 1.9.20150730 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, 2, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
        if (fDiscover)
        {
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if (r != UPNPCOMMAND_SUCCESS)
            {
                LogPrintf("UPnP: GetExternalIPAddress() returned %d\n", r);
            }
            else
            {
                if (externalIPAddress[0])
                {
                    CNetAddr resolved;
                    if (LookupHost(externalIPAddress, resolved, false))
                    {
                        LogPrintf("UPnP: ExternalIPAddress = %s\n", resolved.ToString().c_str());
                        AddLocal(resolved, LOCAL_UPNP);
                    }
                }
                else
                {
                    LogPrintf("UPnP: GetExternalIPAddress failed.\n");
                }
            }
        }

        std::string strDesc = "Bitcoin " + FormatFullVersion();

        try
        {
            while (true)
            {
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port.c_str(), port.c_str(), lanaddr,
                    strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port.c_str(), port.c_str(), lanaddr,
                    strDesc.c_str(), "TCP", 0, "0");
#endif

                if (r != UPNPCOMMAND_SUCCESS)
                {
                    LogPrintf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n", port, port, lanaddr, r,
                        strupnperror(r));
                }
                else
                {
                    LogPrintf("UPnP Port Mapping successful.\n");
                }
                if (upnp_thread_shutdown.load())
                {
                    return;
                }
                int64_t nStart = GetTime();
                int64_t nFinish = nStart + (20 * 60 * 1000);
                // Refresh every 20 minutes
                while (nStart <= nFinish && upnp_thread_shutdown.load() == false)
                {
                    MilliSleep(10000);
                    // this is more performant than calling GetTime() multipe times
                    nStart += 10000;
                }
                if (upnp_thread_shutdown.load())
                {
                    return;
                }
            }
        }
        catch (const boost::thread_interrupted &)
        {
            r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);
            LogPrintf("UPNP_DeletePortMapping() returned: %d\n", r);
            freeUPNPDevlist(devlist);
            devlist = 0;
            FreeUPNPUrls(&urls);
            throw;
        }
    }
    else
    {
        LogPrintf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist);
        devlist = 0;
        if (r != 0)
        {
            FreeUPNPUrls(&urls);
        }
    }
}

void MapPort(bool fUseUPnP)
{
    static std::thread *upnp_thread = nullptr;

    if (fUseUPnP)
    {
        if (upnp_thread)
        {
            upnp_thread_shutdown.store(true);
            upnp_thread->join();
            delete upnp_thread;
            upnp_thread = nullptr;
        }
        upnp_thread = new std::thread(&ThreadMapPort);
    }
    else if (upnp_thread)
    {
        upnp_thread_shutdown.store(true);
        upnp_thread->join();
        delete upnp_thread;
        upnp_thread = nullptr;
    }
}

#else
void MapPort(bool)
{
    // Intentionally left blank.
}
#endif

void Discover(thread_group &threadGroup)
{
    if (!fDiscover)
    {
        return;
    }

#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        std::vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr, 0, true))
        {
            for (const CNetAddr &addr : vaddr)
            {
                if (AddLocal(addr, LOCAL_IF))
                {
                    LogPrintf("%s: %s - %s\n", __func__, pszHostName, addr.ToString());
                }
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs *myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs *ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr || (ifa->ifa_flags & IFF_UP) == 0 || strcmp(ifa->ifa_name, "lo") == 0 ||
                strcmp(ifa->ifa_name, "lo0") == 0)
            {
                continue;
            }
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in *s4 = (struct sockaddr_in *)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (AddLocal(addr, LOCAL_IF))
                {
                    LogPrintf("%s: IPv4 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
                }
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (AddLocal(addr, LOCAL_IF))
                {
                    LogPrintf("%s: IPv6 %s: %s\n", __func__, ifa->ifa_name, addr.ToString());
                }
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

class CNetCleanup
{
public:
    CNetCleanup() {}
    ~CNetCleanup()
    {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
} instance_of_cnetcleanup;

int64_t PoissonNextSend(int64_t nNow, int average_interval_seconds)
{
    return nNow + int64_t(log1p(GetRand(1ULL << 48) * -0.0000000000000035527136788 /* -1/2^48 */) *
                              average_interval_seconds * -1000000.0 +
                          0.5);
}
