// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NET_DOSMAN_H
#define ECCOIN_NET_DOSMAN_H

#include "addrdb.h"
#include "connman.h"
#include "netaddress.h"
#include "node.h"
#include "sync.h"

#include <vector>

class CDoSManager
{
protected:
    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<CSubNet> vWhitelistedRange;
    mutable CCriticalSection cs_vWhitelistedRange;

    // Denial-of-service detection/prevention
    // Key is IP address, value is banned-until-time
    banmap_t setBanned;
    mutable CCriticalSection cs_setBanned;
    bool setBannedIsDirty;

    // If a node's misbehaving count reaches this value, it is flagged for banning.
    int nBanThreshold;

public:
    CDoSManager();

    void Misbehaving(CNode *node, int howmuch, const std::string &reason);

    // Denial-of-service detection/prevention. The idea is to detect peers that
    // are behaving badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network way.
    // IMPORTANT: There should be nothing I can give a node that it will forward
    // on that will make that node's peers drop it. If there is, an attacker can
    // isolate a node and/or try to split the network. Dropping a node for
    // sending stuff that is invalid now but might be valid in a later version
    // is also dangerous, because it can cause a network split between nodes
    // running old code and nodes running new code.
    void Ban(const CNetAddr &netAddr, const BanReason &reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    void Ban(const CSubNet &subNet, const BanReason &reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    // Needed for unit testing.
    void ClearBanned();
    bool IsBanned(CNetAddr ip);
    bool IsBanned(CSubNet subnet);
    bool Unban(const CNetAddr &ip);
    bool Unban(const CSubNet &ip);
    void GetBanned(banmap_t &banmap);
    void SetBanned(const banmap_t &banmap);
    void DumpBanlist();
    void SweepBanned();
    //! check is the banlist has unwritten changes
    bool BannedSetIsDirty();
    //! set the "dirty" flag for the banlist
    void SetBannedSetDirty(bool dirty = true);

    void AddWhitelistedRange(const CSubNet &subnet);

    bool IsWhitelistedRange(const CNetAddr &addr);

};

// actual definition should be in globals.cpp for ordered construction/destruction
extern std::unique_ptr<CDoSManager> g_dosman;

#endif
