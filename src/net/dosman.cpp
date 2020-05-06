// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "args.h"
#include "dosman.h"

CDoSManager::CDoSManager() : setBannedIsDirty(false), nBanThreshold(DEFAULT_BANSCORE_THRESHOLD) {}

void CDoSManager::Misbehaving(CNode *node, int howmuch, const std::string &reason)
{
    if (howmuch == 0 || !node)
    {
        return;
    }

    // Add the new misbehavior and check whether to ban
    uint8_t prior = node->nMisbehavior.load();
    while (true)
    {
        if (node->nMisbehavior.compare_exchange_weak(prior, prior + howmuch))
            break;
        prior = node->nMisbehavior.load();
    }
    if (node->nMisbehavior.load() >= nBanThreshold && prior < nBanThreshold)
    {
        LogPrintf("%s: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", __func__, node->GetLogName(), prior, prior + howmuch);
        g_connman->DisconnectNode(node->GetId());
    }
    else
    {
        LogPrintf("%s: %s (%d -> %d)\n", __func__, node->GetLogName(), prior, prior + howmuch);
    }
}

void CDoSManager::Ban(const CNetAddr &addr, const BanReason &banReason, int64_t bantimeoffset, bool sinceUnixEpoch)
{
    CSubNet subNet(addr);
    Ban(subNet, banReason, bantimeoffset, sinceUnixEpoch);
}

void CDoSManager::Ban(const CSubNet &subNet, const BanReason &banReason, int64_t bantimeoffset, bool sinceUnixEpoch)
{
    CBanEntry banEntry(GetTime());
    banEntry.banReason = banReason;
    if (bantimeoffset <= 0)
    {
        bantimeoffset = gArgs.GetArg("-bantime", DEFAULT_MISBEHAVING_BANTIME);
        sinceUnixEpoch = false;
    }
    banEntry.nBanUntil = (sinceUnixEpoch ? 0 : GetTime()) + bantimeoffset;

    {
        LOCK(cs_setBanned);
        if (setBanned[subNet].nBanUntil < banEntry.nBanUntil)
        {
            setBanned[subNet] = banEntry;
            setBannedIsDirty = true;
        }
        else
        {
            return;
        }
    }
    g_connman->DisconnectNode(subNet);

    if (banReason == BanReasonManuallyAdded)
    {
        // Store banlist to disk immediately if user requested ban.
        DumpBanlist();
    }
}

void CDoSManager::ClearBanned()
{
    {
        LOCK(cs_setBanned);
        setBanned.clear();
        setBannedIsDirty = true;
    }
    // Store banlist to disk.
    DumpBanlist();
}

bool CDoSManager::IsBanned(CNetAddr ip)
{
    LOCK(cs_setBanned);

    bool fResult = false;
    for (banmap_t::iterator it = setBanned.begin(); it != setBanned.end(); it++)
    {
        CSubNet subNet = (*it).first;
        CBanEntry banEntry = (*it).second;

        if (subNet.Match(ip) && GetTime() < banEntry.nBanUntil)
        {
            fResult = true;
        }
    }

    return fResult;
}

bool CDoSManager::IsBanned(CSubNet subnet)
{
    LOCK(cs_setBanned);

    bool fResult = false;
    banmap_t::iterator i = setBanned.find(subnet);
    if (i != setBanned.end())
    {
        CBanEntry banEntry = (*i).second;
        if (GetTime() < banEntry.nBanUntil)
        {
            fResult = true;
        }
    }

    return fResult;
}


bool CDoSManager::Unban(const CNetAddr &addr)
{
    CSubNet subNet(addr);
    return Unban(subNet);
}

bool CDoSManager::Unban(const CSubNet &subNet)
{
    {
        LOCK(cs_setBanned);
        if (!setBanned.erase(subNet))
        {
            return false;
        }
        setBannedIsDirty = true;
    }
    // Store banlist to disk immediately.
    DumpBanlist();
    return true;
}

void CDoSManager::GetBanned(banmap_t &banMap)
{
    LOCK(cs_setBanned);
    // Sweep the banlist so expired bans are not returned
    SweepBanned();
    // Create a thread safe copy.
    banMap = setBanned;
}

void CDoSManager::SetBanned(const banmap_t &banMap)
{
    LOCK(cs_setBanned);
    setBanned = banMap;
    setBannedIsDirty = true;
}

void CDoSManager::DumpBanlist()
{
    // Clean unused entries (if bantime has expired)
    SweepBanned();

    if (!BannedSetIsDirty())
    {
        return;
    }

    int64_t nStart = GetTimeMillis();

    CBanDB bandb;
    banmap_t banmap;
    GetBanned(banmap);
    if (bandb.Write(banmap))
    {
        SetBannedSetDirty(false);
    }

    LogPrintf("Flushed %d banned node ips/subnets to banlist.dat  %dms\n", banmap.size(), GetTimeMillis() - nStart);
}


void CDoSManager::SweepBanned()
{
    int64_t now = GetTime();

    LOCK(cs_setBanned);
    banmap_t::iterator it = setBanned.begin();
    while (it != setBanned.end())
    {
        CSubNet subNet = (*it).first;
        CBanEntry banEntry = (*it).second;
        if (now > banEntry.nBanUntil)
        {
            setBanned.erase(it++);
            setBannedIsDirty = true;
            LogPrintf("%s: Removed banned node ip/subnet from banlist.dat: %s\n", __func__, subNet.ToString());
        }
        else
        {
            ++it;
        }
    }
}

bool CDoSManager::BannedSetIsDirty()
{
    LOCK(cs_setBanned);
    return setBannedIsDirty;
}

void CDoSManager::SetBannedSetDirty(bool dirty)
{
    // Reuse setBanned lock for the isDirty flag.
    LOCK(cs_setBanned);
    setBannedIsDirty = dirty;
}
