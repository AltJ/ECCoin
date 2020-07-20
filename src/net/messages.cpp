// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "net/messages.h"

#include "aodv.h"
#include "args.h"
#include "beta.h"
#include "blockstorage/blockstorage.h"
#include "chain/chain.h"
#include "chain/tx.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "init.h"
#include "main.h"
#include "merkleblock.h"
#include "net/addrman.h"
#include "net/dosman.h"
#include "net/nodestate.h"
#include "net/packetmanager.h"
#include "net/protocol.h"
#include "net/requestmanager.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "processblock.h"
#include "processheader.h"
#include "serialize.h"
#include "sync.h"
#include "txmempool.h"
#include "util/util.h"
#include "util/utilstrencodings.h"
#include "validationinterface.h"
#include "version.h"

#include <algorithm>
#include <map>
#include <vector>

#include <boost/range/adaptor/reversed.hpp>

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

/**
 * Filter for transactions that were recently rejected by
 * AcceptToMemoryPool. These are not rerequested until the chain tip
 * changes, at which point the entire filter is reset. Protected by
 * cs_main.
 *
 * Without this filter we'd be re-requesting txs from each of our peers,
 * increasing bandwidth consumption considerably. For instance, with 100
 * peers, half of which relay a tx we don't accept, that might be a 50x
 * bandwidth increase. A flooding attacker attempting to roll-over the
 * filter using minimum-sized, 60byte, transactions might manage to send
 * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
 * two minute window to send invs to us.
 *
 * Decreasing the false positive rate is fairly cheap, so we pick one in a
 * million to make it highly unlikely for users to have issues with this
 * filter.
 *
 * Memory used: 1.3 MB
 */
std::unique_ptr<CRollingBloomFilter> recentRejects;

uint256 hashRecentRejectsChainTip;

// TODO : nLocalNonde should be a part of the connection manager
uint64_t nLocalHostNonce = 0;
extern CCriticalSection cs_mapInboundConnectionTracker;
extern std::map<CNetAddr, ConnectionHistory> mapInboundConnectionTracker;
extern std::map<uint256, std::pair<CBlockHeader, int64_t> > mapUnConnectedHeaders;

extern std::atomic<CBlockIndex *> pindexBestInvalid;

void RelayTransaction(const CTransaction &tx, CConnman &connman)
{
    CInv inv(MSG_TX, tx.GetId());
    g_requestman->TrackTxRelay(tx);
    connman.ForEachNode([&inv](CNode *pnode) { pnode->PushInventory(inv); });
}

static void RelayAddress(const CAddress &addr, bool fReachable, CConnman &connman)
{
    // Limited relaying of addresses outside our network(s)
    unsigned int nRelayNodes = fReachable ? 2 : 1;

    // Relay to a limited number of other nodes.
    // Use deterministic randomness to send to the same nodes for 24 hours at a
    // time so the addrKnowns of the chosen nodes prevent repeats.
    uint64_t hashAddr = addr.GetHash();
    const CSipHasher hasher = connman.GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY)
                                  .Write(hashAddr << 32)
                                  .Write((GetTime() + hashAddr) / (24 * 60 * 60));
    FastRandomContext insecure_rand;

    std::array<std::pair<uint64_t, CNode *>, 2> best{{{0, nullptr}, {0, nullptr}}};
    assert(nRelayNodes <= best.size());

    auto sortfunc = [&best, &hasher, nRelayNodes](CNode *pnode) {
        uint64_t hashKey = CSipHasher(hasher).Write(pnode->id).Finalize();
        for (unsigned int i = 0; i < nRelayNodes; i++)
        {
            if (hashKey > best[i].first)
            {
                std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
                best[i] = std::make_pair(hashKey, pnode);
                break;
            }
        }
    };

    auto pushfunc = [&addr, &best, nRelayNodes, &insecure_rand] {
        for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; i++)
        {
            best[i].second->PushAddress(addr, insecure_rand);
        }
    };

    connman.ForEachNodeThen(std::move(sortfunc), std::move(pushfunc));
}

bool AddOrphanTx(const CTransaction &tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_orphans)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    unsigned int sz = GetSerializeSize(tx, SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz > 5000)
    {
        LogPrint("mempool", "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    mapOrphanTransactions[hash].tx = tx;
    mapOrphanTransactions[hash].fromPeer = peer;
    for (const CTxIn &txin : tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    LogPrint("mempool", "stored orphan tx %s (mapsz %u prevsz %u)\n", hash.ToString(), mapOrphanTransactions.size(),
        mapOrphanTransactionsByPrev.size());
    return true;
}


void static EraseOrphanTx(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(cs_orphans)
{
    std::map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
    if (it == mapOrphanTransactions.end())
        return;
    for (const CTxIn &txin : it->second.tx.vin)
    {
        std::map<uint256, std::set<uint256> >::iterator itPrev = mapOrphanTransactionsByPrev.find(txin.prevout.hash);
        if (itPrev == mapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(hash);
        if (itPrev->second.empty())
            mapOrphanTransactionsByPrev.erase(itPrev);
    }
    mapOrphanTransactions.erase(it);
}

void EraseOrphansFor(NodeId peer)
{
    LOCK(cs_orphans);
    int nErased = 0;
    std::map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
    while (iter != mapOrphanTransactions.end())
    {
        std::map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            EraseOrphanTx(maybeErase->second.tx.GetHash());
            ++nErased;
        }
    }
    if (nErased > 0)
        LogPrint("mempool", "Erased %d orphan tx from peer %d\n", nErased, peer);
}


unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) EXCLUSIVE_LOCKS_REQUIRED(cs_orphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        std::map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

//////////////////////////////////////////////////////////////////////////////
//
// blockchain -> download logic notification
//

PeerLogicValidation::PeerLogicValidation(CConnman *connmanIn) : connman(connmanIn)
{
    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));
}

void PeerLogicValidation::NewPoWValidBlock(CBlockIndex *pindex, const CBlock *pblock)
{
    uint256 hashBlock(pblock->GetHash());
    RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
    connman->ForEachNode([this, pindex, &hashBlock](CNode *pnode) {
        // TODO: Avoid the repeated-serialization here
        if (pnode->fDisconnect)
        {
            return;
        }
        g_requestman->ProcessBlockAvailability(pnode->GetId());
        // If the peer has, or we announced to them the previous block already,
        // but we don't think they have this one, go ahead and announce it.

        // TODO : peer occasionally does not relay block headers because it incorrectly
        // thinks the peer has the header already, re-enable this at some point with better checks

        // if (!g_requestman->PeerHasHeader(pnode->GetId(), pindex))
        {
            LogPrint("net", "%s sending header-and-ids %s to peer=%d\n", "PeerLogicValidation::NewPoWValidBlock",
                hashBlock.ToString(), pnode->id);
            std::vector<CBlock> vHeaders;
            vHeaders.push_back(pindex->GetBlockHeader());
            connman->PushMessage(pnode, NetMsgType::HEADERS, vHeaders);
            g_requestman->SetBestHeaderSent(pnode->GetId(), pindex);
        }
    });
}

bool AlreadyHaveBlock(const CInv &inv)
{
    if (inv.type == MSG_BLOCK)
    {
        RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
        if (g_chainman.mapBlockIndex.count(inv.hash))
        {
            return (g_chainman.mapBlockIndex[inv.hash]->nStatus & BLOCK_HAVE_DATA);
        }
    }
    return false;
}

bool AlreadyHaveTx(const CInv &inv)
{
    if (inv.type == MSG_TX)
    {
        assert(recentRejects);
        if (g_chainman.chainActive.Tip()->GetBlockHash() != hashRecentRejectsChainTip)
        {
            // If the chain tip has changed previously rejected transactions
            // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
            // or a double-spend. Reset the rejects filter and give those
            // txs a second chance.
            hashRecentRejectsChainTip = g_chainman.chainActive.Tip()->GetBlockHash();
            recentRejects->reset();
        }
        LOCK(cs_orphans);
        return recentRejects->contains(inv.hash) || mempool.exists(inv.hash) || mapOrphanTransactions.count(inv.hash) ||
               // Best effort: only try output 0 and 1
               pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 0)) || pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 1));
    }
    return false;
}

void static ProcessGetData(CNode *pfrom,
    CConnman &connman,
    const Consensus::Params &consensusParams,
    std::deque<CInv> &vInv)
{
    std::vector<CInv> vNotFound;

    while (!vInv.empty())
    {
        // Don't bother if send buffer is too full to respond anyway.
        if (pfrom->fPauseSend)
        {
            break;
        }

        const CInv &inv = vInv.front();
        vInv.pop_front();
        if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
        {
            bool send = false;
            CBlockIndex *pindex = g_chainman.LookupBlockIndex(inv.hash);
            if (pindex)
            {
                RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
                if (g_chainman.chainActive.Contains(pindex))
                {
                    send = true;
                }
                else
                {
                    static const int nOneMonth = 30 * 24 * 60 * 60;
                    // To prevent fingerprinting attacks, only send blocks
                    // outside of the active chain if they are valid, and no
                    // more than a month older (both in time, and in best
                    // equivalent proof of work) than the best header chain
                    // we know about.
                    send = pindex->IsValid(BLOCK_VALID_SCRIPTS) && (g_chainman.pindexBestHeader != nullptr) &&
                           (g_chainman.pindexBestHeader.load()->GetBlockTime() - pindex->GetBlockTime() < nOneMonth) &&
                           (GetBlockProofEquivalentTime(*g_chainman.pindexBestHeader, *pindex,
                                *g_chainman.pindexBestHeader, consensusParams) < nOneMonth);
                    if (!send)
                    {
                        LogPrintf("%s: ignoring request from peer=%i for old block that isn't in the main chain\n",
                            __func__, pfrom->GetId());
                    }
                }
            }
            // Disconnect node in case we have reached the outbound limit
            // for serving historical blocks never disconnect whitelisted
            // nodes.
            // assume > 1 week = historical
            static const int nOneWeek = 7 * 24 * 60 * 60;
            if (send && connman.OutboundTargetReached(true) &&
                (((g_chainman.pindexBestHeader != nullptr) &&
                     (g_chainman.pindexBestHeader.load()->GetBlockTime() - pindex->GetBlockTime() > nOneWeek)) ||
                    inv.type == MSG_FILTERED_BLOCK) &&
                !pfrom->fWhitelisted)
            {
                LogPrintf("historical block serving limit reached, disconnect peer=%d\n", pfrom->GetId());

                // disconnect node
                pfrom->fDisconnect = true;
                send = false;
            }
            // Pruned nodes may have deleted the block, so check whether
            // it's available before trying to send.
            if (send && (pindex->nStatus & BLOCK_HAVE_DATA))
            {
                // Send block from disk
                CBlock block;
                if (!ReadBlockFromDisk(block, pindex, consensusParams))
                {
                    LogPrint("net", "cannot load block from disk, no response");
                }
                else
                {
                    if (inv.type == MSG_BLOCK)
                    {
                        connman.PushMessage(pfrom, NetMsgType::BLOCK, block);
                    }
                    else if (inv.type == MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            connman.PushMessage(pfrom, NetMsgType::MERKLEBLOCK, merkleBlock);
                            // CMerkleBlock just contains hashes, so also push
                            // any transactions in the block the client did not
                            // see. This avoids hurting performance by
                            // pointlessly requiring a round-trip. Note that
                            // there is currently no way for a node to request
                            // any single transactions we didn't send here -
                            // they must either disconnect and retry or request
                            // the full block. Thus, the protocol spec specified
                            // allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the
                            // remote peer needs.
                            typedef std::pair<unsigned int, uint256> PairType;
                            for (PairType &pair : merkleBlock.vMatchedTxn)
                            {
                                connman.PushMessage(pfrom, NetMsgType::TX, block.vtx[pair.first]);
                            }
                        }
                        // else
                        // no response
                    }
                    // Trigger the peer node to send a getblocks request for the
                    // next batch of inventory.
                    if (inv.hash == uint256())
                    {
                        // Bypass PushInventory, this must send even if
                        // redundant, and we want it right after the last block
                        // so they don't wait for other stuff first.
                        std::vector<CInv> vOneInv;
                        vInv.push_back(CInv(MSG_BLOCK, g_chainman.chainActive.Tip()->GetBlockHash()));
                        connman.PushMessage(pfrom, NetMsgType::INV, vOneInv);
                    }
                }
            }
        }
        else if (inv.type == MSG_TX)
        {
            if (g_requestman->FindAndPushTx(pfrom, inv.hash) == false)
            {
                vNotFound.push_back(inv);
            }
        }
        // Track requests for our stuff.
        GetMainSignals().Inventory(inv.hash);
    }
    if (!vNotFound.empty())
    {
        // Let the peer know that we didn't find what it asked for, so it
        // doesn't have to wait around forever. Currently only SPV clients
        // actually care about this message: it's needed when they are
        // recursively walking the dependencies of relevant unconfirmed
        // transactions. SPV clients want to do that because they want to know
        // about (and store and rebroadcast and risk analyze) the dependencies
        // of transactions relevant to them, without having to download the
        // entire memory pool.
        connman.PushMessage(pfrom, NetMsgType::NOTFOUND, vNotFound);
    }
}

void RegisterNodeSignals(CNodeSignals &nodeSignals)
{
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
}

void UnregisterNodeSignals(CNodeSignals &nodeSignals)
{
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
}


bool static ProcessMessage(CNode *pfrom,
    std::string strCommand,
    CDataStream &vRecv,
    int64_t nTimeReceived,
    CConnman &connman)
{
    const CChainParams &chainparams = Params();
    LogPrint("net", "received: %s (%u bytes) peer=%d\n", SanitizeString(strCommand), vRecv.size(), pfrom->id);
    if (gArgs.IsArgSet("-dropmessagestest") && GetRand(atoi(gArgs.GetArg("-dropmessagestest", "0"))) == 0)
    {
        LogPrint("net", "dropmessagestest DROPPING RECV MESSAGE \n");
        return true;
    }


    if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
        (strCommand == NetMsgType::FILTERLOAD || strCommand == NetMsgType::FILTERADD ||
            strCommand == NetMsgType::FILTERCLEAR))
    {
        if (pfrom->nVersion >= NO_BLOOM_VERSION)
        {
            g_dosman->Misbehaving(pfrom, 100, "no-bloom-version");
            return false;
        }
        else
        {
            pfrom->fDisconnect = true;
            return false;
        }
    }


    if (strCommand == NetMsgType::VERSION)
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            connman.PushMessage(
                pfrom, NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, std::string("Duplicate version message"));
            g_dosman->Misbehaving(pfrom, 1, "multiple-version");
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        ServiceFlags nServices;
        int nVersion;
        int nSendVersion;
        std::string strSubVer;
        std::string cleanSubVer;
        int nStartingHeight = -1;
        bool fRelay = true;

        vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
        nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
        nServices = ServiceFlags(nServiceInt);
        if (!pfrom->fInbound)
        {
            connman.SetServices(pfrom->addr, nServices);
        }
        if (pfrom->nServicesExpected & ~nServices)
        {
            LogPrintf("peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n",
                pfrom->id, nServices, pfrom->nServicesExpected);
            connman.PushMessage(pfrom, NetMsgType::REJECT, strCommand, REJECT_NONSTANDARD,
                strprintf("Expected to offer services %08x", pfrom->nServicesExpected));
            pfrom->fDisconnect = true;
            return false;
        }

        if (nVersion < MIN_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            LogPrintf("peer=%d using obsolete version %i; disconnecting\n", pfrom->id, nVersion);
            connman.PushMessage(pfrom, NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                strprintf("Version must be %d or greater", MIN_PROTO_VERSION));
            pfrom->fDisconnect = true;
            return false;
        }

        if (!vRecv.empty())
        {
            vRecv >> addrFrom >> nNonce;
        }
        if (!vRecv.empty())
        {
            vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
            cleanSubVer = SanitizeString(strSubVer);
        }
        if (!vRecv.empty())
        {
            vRecv >> nStartingHeight;
        }
        if (!vRecv.empty())
        {
            vRecv >> fRelay;
        }
        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
        {
            connman.PushNodeVersion(pfrom, GetAdjustedTime());
        }

        connman.PushMessage(pfrom, NetMsgType::VERACK);

        pfrom->nServices = nServices;
        pfrom->SetAddrLocal(addrMe);
        {
            LOCK(pfrom->cs_SubVer);
            pfrom->strSubVer = strSubVer;
            pfrom->cleanSubVer = cleanSubVer;
        }
        pfrom->nStartingHeight = nStartingHeight;
        pfrom->fClient = !(nServices & NODE_NETWORK);
        {
            LOCK(pfrom->cs_filter);
            // set to true after we get the first filter* message
            pfrom->fRelayTxes = fRelay;
        }

        // Change version
        pfrom->SetSendVersion(nSendVersion);
        pfrom->nVersion = nVersion;

        // Potentially mark this peer as a preferred download peer.
        g_requestman->UpdatePreferredDownload(pfrom);

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (fListen && !g_chainman.IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr, pfrom->GetLocalServices());
                FastRandomContext insecure_rand;
                if (addr.IsRoutable())
                {
                    LogPrint("net", "ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                }
                else if (IsPeerAddrLocalGood(pfrom))
                {
                    addr.SetIP(addrMe);
                    LogPrint("net", "ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || connman.GetAddressCount() < 1000)
            {
                connman.PushMessage(pfrom, NetMsgType::GETADDR);
                pfrom->fGetAddr = true;
            }
            connman.MarkAddressGood(pfrom->addr);
        }

        std::string remoteAddr;
        if (g_logger->fLogIPs)
        {
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();
        }

        LogPrint("net", "receive version message: [%s] %s: version %d, blocks=%d, "
                        "us=%s, peer=%d%s\n",
            pfrom->addr.ToString().c_str(), cleanSubVer, pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString(),
            pfrom->id, remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;
        AddTimeData(pfrom->addr, nTimeOffset);

        // Feeler connections exist only to verify if address is online.
        if (pfrom->fFeeler)
        {
            assert(pfrom->fInbound == false);
            pfrom->fDisconnect = true;
        }
        return true;
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        g_dosman->Misbehaving(pfrom, 1, "missing-version");
        return false;
    }


    if (strCommand == NetMsgType::VERACK)
    {
        pfrom->SetRecvVersion(std::min(pfrom->nVersion.load(), PROTOCOL_VERSION));

        // Tell our peer we prefer to receive headers rather than inv's
        // We send this to non-NODE NETWORK peers as well, because even
        // non-NODE NETWORK peers can announce blocks (such as pruning
        // nodes)
        connman.PushMessage(pfrom, NetMsgType::SENDHEADERS);

        if (pfrom->nVersion >= NETWORK_SERVICE_PROTOCOL_VERSION && IsBetaEnabled())
        {
            connman.PushMessage(pfrom, NetMsgType::NSVERSION, NETWORK_SERVICE_VERSION);
        }

        pfrom->fSuccessfullyConnected = true;
    }

    else if (!pfrom->fSuccessfullyConnected)
    {
        {
            // Must have a verack message before anything else
            g_dosman->Misbehaving(pfrom, 1, "missing-verack");
        }
        {
            // update connection tracker which is used by the connection slot algorithm.
            LOCK(cs_mapInboundConnectionTracker);
            CNetAddr ipAddress = (CNetAddr)pfrom->addr;
            mapInboundConnectionTracker[ipAddress].nEvictions += 1;
            mapInboundConnectionTracker[ipAddress].nLastEvictionTime = GetTime();
        }
        return false;
    }
    else if (strCommand == NetMsgType::NSVERSION)
    {
        if (IsBetaEnabled())
        {
            uint64_t netservice = 0;
            vRecv >> netservice;
            pfrom->nNetworkServiceVersion = netservice;
            if (netservice >= MIN_AODV_VERSION)
            {
                connman.PushMessage(pfrom, NetMsgType::NSVERACK, g_connman->GetPublicTagPubKey());
            }
        }
    }

    else if (strCommand == NetMsgType::NSVERACK)
    {
        if (IsBetaEnabled())
        {
            CPubKey peerPubKey;
            vRecv >> peerPubKey;
            pfrom->routing_id = peerPubKey;
            g_aodvtable.AddRoute(peerPubKey, pfrom->GetId());
        }
    }

    else if (strCommand == NetMsgType::ADDR)
    {
        std::vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (connman.GetAddressCount() > 1000)
        {
            return true;
        }
        if (vAddr.size() > 1000)
        {
            g_dosman->Misbehaving(pfrom, 20, "oversized-addr");
            return error("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        for (CAddress &addr : vAddr)
        {
            if ((addr.nServices & REQUIRED_SERVICES) != REQUIRED_SERVICES)
            {
                continue;
            }

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
            {
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            }
            pfrom->AddAddressKnown(addr);
            // Do not process banned addresses beyond remembering we received them
            if (g_dosman->IsBanned(addr))
            {
                continue;
            }
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                RelayAddress(addr, fReachable, connman);
            }
            // Do not store addresses outside our network
            if (fReachable)
            {
                vAddrOk.push_back(addr);
            }
        }
        connman.AddNewAddresses(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
        {
            pfrom->fGetAddr = false;
        }
        if (pfrom->fOneShot)
        {
            pfrom->fDisconnect = true;
        }
    }

    else if (strCommand == NetMsgType::SENDHEADERS)
    {
        g_requestman->SetPreferHeaders(pfrom);
    }

    else if (strCommand == NetMsgType::INV)
    {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            g_dosman->Misbehaving(pfrom, 20, "oversized-inv");
            return error("message inv size() = %u", vInv.size());
        }

        bool fBlocksOnly = !fRelayTxes;

        // Allow whitelisted peers to send data other than blocks in blocks only
        // mode if whitelistrelay is true
        if (pfrom->fWhitelisted && gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY))
        {
            fBlocksOnly = false;
        }
        for (size_t nInv = 0; nInv < vInv.size(); nInv++)
        {
            CInv &inv = vInv[nInv];

            // TODO : do a validity check (correct types and valid hashes) for the invs requested

            if (inv.type == MSG_BLOCK)
            {
                bool fAlreadyHave = AlreadyHaveBlock(inv);
                LogPrint("net", "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->id);
                g_requestman->UpdateBlockAvailability(pfrom->GetId(), inv.hash);
                if ((!fAlreadyHave && !g_requestman->IsBlockInFlight(inv.hash)) ||
                    (!fAlreadyHave && Params().NetworkIDString() == "regtest"))
                {
                    // We used to request the full block here, but since
                    // headers-announcements are now the primary method of
                    // announcement on the network, and since, in the case that
                    // a node fell back to inv we probably have a reorg which we
                    // should get the headers for first, we now only provide a
                    // getheaders response here. When we receive the headers, we
                    // will then ask for the blocks we need.
                    connman.PushMessage(pfrom, NetMsgType::GETHEADERS,
                        g_chainman.chainActive.GetLocator(g_chainman.pindexBestHeader), inv.hash);
                    LogPrint("net", "getheaders (%d) %s to peer=%d\n", g_chainman.pindexBestHeader.load()->nHeight,
                        inv.hash.ToString(), pfrom->id);
                }
                // TODO : putting a skip message here or something might help with debugging later
            }
            else
            {
                bool fAlreadyHave = AlreadyHaveTx(inv);
                LogPrint("net", "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->id);
                pfrom->AddInventoryKnown(inv);
                if (fBlocksOnly)
                {
                    LogPrintf(
                        "transaction (%s) inv sent in violation of protocol peer=%d\n", inv.hash.ToString(), pfrom->id);
                }
                else if (!fAlreadyHave && !fImporting && !fReindex && !g_chainman.IsInitialBlockDownload())
                {
                    pfrom->AskFor(inv);
                }
            }

            // Track requests for our stuff
            GetMainSignals().Inventory(inv.hash);
        }
    }

    else if (strCommand == NetMsgType::GETDATA)
    {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            g_dosman->Misbehaving(pfrom, 20, "too-many-inv");
            return error("message getdata size() = %u", vInv.size());
        }

        // Validate that INVs are a valid type
        std::deque<CInv> invDeque;
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];
            if (!((inv.type == MSG_TX) || (inv.type == MSG_BLOCK) || (inv.type == MSG_FILTERED_BLOCK)))
            {
                g_dosman->Misbehaving(pfrom, 20, "invalid inventory");
                return error("message inv invalid type = %u", inv.type);
            }
            invDeque.push_back(inv);
        }

        LogPrint("net", "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->id);

        if (vInv.size() > 0)
        {
            LogPrint("net", "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->id);
        }
        ProcessGetData(pfrom, connman, chainparams.GetConsensus(), invDeque);
        if (vInv.empty() == false)
        {
            LOCK(pfrom->csRecvGetData);
            pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), invDeque.begin(), invDeque.end());
        }
    }

    else if (strCommand == NetMsgType::GETHEADERS)
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        if (g_chainman.IsInitialBlockDownload() && !pfrom->fWhitelisted)
        {
            LogPrint(
                "net", "Ignoring getheaders from peer=%d because our node is in initial block download\n", pfrom->id);
            return true;
        }

        CBlockIndex *pindex = nullptr;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            pindex = g_chainman.LookupBlockIndex(hashStop);
            if (!pindex)
            {
                return true;
            }
        }

        std::vector<CBlock> vHeaders;
        {
            LOCK(cs_main);
            // Find the last block the caller has in the main chain
            pindex = g_chainman.FindForkInGlobalIndex(g_chainman.chainActive, locator);
            if (pindex)
            {
                pindex = g_chainman.chainActive.Next(pindex);
            }
            // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx
            // count at the end
            int nLimit = MAX_HEADERS_RESULTS;
            LogPrint("net", "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1),
                hashStop.IsNull() ? "end" : hashStop.ToString(), pfrom->id);
            // TODO : evaluate if this cs_main lock is needed
            LOCK(cs_main);
            for (; pindex; pindex = g_chainman.chainActive.Next(pindex))
            {
                vHeaders.push_back(pindex->GetBlockHeader());
                if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                {
                    break;
                }
            }
        }
        // pindex can be nullptr either if we sent chainActive.Tip() OR
        // if our peer has chainActive.Tip() (and thus we are sending an empty
        // headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        //
        // It is important that we simply reset the BestHeaderSent value here,
        // and not max(BestHeaderSent, newHeaderSent). We might have announced
        // the currently-being-connected tip using a compact block, which
        // resulted in the peer sending a headers request, which we respond to
        // without the new block. By resetting the BestHeaderSent, we ensure we
        // will re-announce the new block via headers (or compact blocks again)
        // in the SendMessages logic.
        g_requestman->SetBestHeaderSent(pfrom->GetId(), pindex ? pindex : g_chainman.chainActive.Tip());
        connman.PushMessage(pfrom, NetMsgType::HEADERS, vHeaders);
    }

    else if (strCommand == NetMsgType::TX)
    {
        // Stop processing the transaction early if
        // We are in blocks only mode and peer is either not whitelisted or
        // whitelistrelay is off
        if (!fRelayTxes && (!pfrom->fWhitelisted || !gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)))
        {
            LogPrintf("transaction sent in violation of protocol peer=%d\n", pfrom->id);
            return true;
        }

        std::deque<COutPoint> vWorkQueue;
        std::vector<uint256> vEraseQueue;
        CTransaction tx;
        vRecv >> tx;
        const CTransactionRef ptx = std::make_shared<CTransaction>(tx);

        CInv inv(MSG_TX, tx.GetId());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        CValidationState state;

        if (!AlreadyHaveTx(inv) && AcceptToMemoryPool(mempool, state, ptx, true, &fMissingInputs))
        {
            mempool.check(pcoinsTip.get());
            RelayTransaction(tx, connman);
            for (size_t i = 0; i < tx.vout.size(); i++)
            {
                vWorkQueue.emplace_back(inv.hash, i);
            }

            pfrom->nLastTXTime = GetTime();

            LogPrint("mempool", "AcceptToMemoryPool: peer=%d: accepted %s "
                                "(poolsz %u txn, %u kB)\n",
                pfrom->id, tx.GetId().ToString(), mempool.size(), mempool.DynamicMemoryUsage() / 1000);

            // Recursively process any orphan transactions that depended on this
            // one
            std::set<NodeId> setMisbehaving;
            while (!vWorkQueue.empty())
            {
                LOCK(cs_orphans);
                auto itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue[0].hash);
                vWorkQueue.pop_front();
                if (itByPrev == mapOrphanTransactionsByPrev.end())
                {
                    continue;
                }
                for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi)
                {
                    const uint256 &orphanHash = *mi;
                    const CTransaction orphanTx = mapOrphanTransactions[orphanHash].tx;
                    const CTransactionRef &porphanTx = std::make_shared<CTransaction>(orphanTx);
                    const uint256 &orphanId = orphanTx.GetId();
                    NodeId fromPeer = mapOrphanTransactions[orphanHash].fromPeer;

                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes
                    // to counter-DoS based on orphan resolution (that is,
                    // feeding people an invalid transaction based on LegitTxX
                    // in order to get anyone relaying LegitTxX banned)
                    CValidationState stateDummy;

                    if (setMisbehaving.count(fromPeer))
                    {
                        continue;
                    }
                    if (AcceptToMemoryPool(mempool, stateDummy, porphanTx, true, &fMissingInputs2))
                    {
                        LogPrintf("   accepted orphan tx %s\n", orphanId.ToString());
                        RelayTransaction(orphanTx, connman);
                        for (size_t i = 0; i < orphanTx.vout.size(); i++)
                        {
                            vWorkQueue.emplace_back(orphanId, i);
                        }
                        vEraseQueue.push_back(orphanId);
                    }
                    else if (!fMissingInputs2)
                    {
                        int nDos = 0;
                        if (stateDummy.IsInvalid(nDos) && nDos > 0)
                        {
                            // Punish peer that gave us an invalid orphan tx

                            // TODO : re-evaluate this punishment

                            // g_dosman->Misbehaving(fromPeer, nDos, "invalid-orphan-tx")
                            setMisbehaving.insert(fromPeer);
                            LogPrintf("   invalid orphan tx %s\n", orphanId.ToString());
                        }
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        LogPrintf("   removed orphan tx %s\n", orphanId.ToString());
                        vEraseQueue.push_back(orphanId);
                        if (!stateDummy.CorruptionPossible())
                        {
                            // Do not use rejection cache for witness
                            // transactions or witness-stripped transactions, as
                            // they can have been malleated. See
                            // https://github.com/bitcoin/bitcoin/issues/8279
                            // for details.
                            assert(recentRejects);
                            recentRejects->insert(orphanId);
                        }
                    }
                    mempool.check(pcoinsTip.get());
                }
            }

            for (uint256 hash : vEraseQueue)
            {
                EraseOrphanTx(hash);
            }
        }
        else if (fMissingInputs)
        {
            // It may be the case that the orphans parents have all been
            // rejected.
            bool fRejectedParents = false;
            for (const CTxIn &txin : tx.vin)
            {
                if (recentRejects->contains(txin.prevout.hash))
                {
                    fRejectedParents = true;
                    break;
                }
            }
            if (!fRejectedParents)
            {
                for (const CTxIn &txin : tx.vin)
                {
                    CInv _inv(MSG_TX, txin.prevout.hash);
                    if (!AlreadyHaveTx(_inv))
                    {
                        pfrom->AskFor(_inv);
                    }
                }
                AddOrphanTx(tx, pfrom->GetId());

                // DoS prevention: do not allow mapOrphanTransactions to grow
                // unbounded
                unsigned int nMaxOrphanTx =
                    (unsigned int)std::max(int64_t(0), gArgs.GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
                LOCK(cs_orphans);
                unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);
                if (nEvicted > 0)
                {
                    LogPrintf("mapOrphan overflow, removed %u tx\n", nEvicted);
                }
            }
            else
            {
                LogPrintf("not keeping orphan with rejected parents %s\n", tx.GetId().ToString());
                // We will continue to reject this tx since it has rejected
                // parents so avoid re-requesting it from other peers.
                recentRejects->insert(tx.GetId());
            }
        }
        else
        {
            if (!state.CorruptionPossible())
            {
                // Do not use rejection cache for witness transactions or
                // witness-stripped transactions, as they can have been
                // malleated. See https://github.com/bitcoin/bitcoin/issues/8279
                // for details.
                assert(recentRejects);
                recentRejects->insert(tx.GetId());
            }

            if (pfrom->fWhitelisted && gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY))
            {
                // Always relay transactions received from whitelisted peers,
                // even if they were already in the mempool or rejected from it
                // due to policy, allowing the node to function as a gateway for
                // nodes hidden behind it.
                //
                // Never relay transactions that we would assign a non-zero DoS
                // score for, as we expect peers to do the same with us in that
                // case.
                int nDoS = 0;
                if (!state.IsInvalid(nDoS) || nDoS == 0)
                {
                    LogPrint(
                        "net", "Force relaying tx %s from whitelisted peer=%d\n", tx.GetId().ToString(), pfrom->id);
                    RelayTransaction(tx, connman);
                }
                else
                {
                    LogPrint("net", "Not relaying invalid transaction %s from "
                                    "whitelisted peer=%d (%s)\n",
                        tx.GetId().ToString(), pfrom->id, FormatStateMessage(state));
                }
            }
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            LogPrintf("%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(), pfrom->id,
                FormatStateMessage(state));
            // Never send AcceptToMemoryPool's internal codes over P2P.
            if (state.GetRejectCode() > 0 && state.GetRejectCode() < REJECT_INTERNAL)
            {
                connman.PushMessage(pfrom, NetMsgType::REJECT, strCommand, uint8_t(state.GetRejectCode()),
                    state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash);
            }
            if (nDoS > 0)
            {
                g_dosman->Misbehaving(pfrom, nDoS, state.GetRejectReason());
            }
        }
    }

    // Ignore headers received while importing
    else if (strCommand == NetMsgType::HEADERS && !fImporting && !fReindex)
    {
        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS)
        {
            g_dosman->Misbehaving(pfrom, 20, "too-many-headers");
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++)
        {
            vRecv >> headers[n];
            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
            ReadCompactSize(vRecv); // ignore empty vchBlockSig
        }
        if (nCount == 0)
        {
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }
        // check if these are sequential before trying to accept them
        bool fNewUnconnectedHeaders = false;
        uint256 hashLastBlock;
        hashLastBlock.SetNull();
        for (const CBlockHeader &header : headers)
        {
            // check that the first header has a previous block in the blockindex.
            if (hashLastBlock.IsNull())
            {
                if (g_chainman.LookupBlockIndex(header.hashPrevBlock))
                {
                    hashLastBlock = header.hashPrevBlock;
                }
            }
            // Add this header to the map if it doesn't connect to a previous header
            if (header.hashPrevBlock != hashLastBlock)
            {
                // If we still haven't finished downloading the initial headers during node sync and we get
                // an out of order header then we must disconnect the node so that we can finish downloading
                // initial headers from a diffeent peer. An out of order header at this point is likely an attack
                // to prevent the node from syncing.
                if (header.GetBlockTime() < GetAdjustedTime() - 24 * 60 * 60)
                {
                    pfrom->fDisconnect = true;
                    return error(
                        "non-continuous-headers sequence during node sync - disconnecting peer=%d", pfrom->GetId());
                }
                fNewUnconnectedHeaders = true;
            }

            // if we have an unconnected header then add every following header to the unconnected headers cache.
            if (fNewUnconnectedHeaders)
            {
                uint256 hash = header.GetHash();
                if (mapUnConnectedHeaders.size() < MAX_UNCONNECTED_HEADERS)
                {
                    mapUnConnectedHeaders[hash] = std::make_pair(header, GetTime());
                }
                // update hashLastUnknownBlock so that we'll be able to download the block from this peer even
                // if we receive the headers, which will connect this one, from a different peer.
                g_requestman->UpdateBlockAvailability(pfrom->GetId(), hash);
            }
            hashLastBlock = header.GetHash();
        }
        // return without error if we have an unconnected header.  This way we can try to connect it when the next
        // header arrives.
        if (fNewUnconnectedHeaders)
        {
            // TODO : there is probably a better way to fix this issue where sometimes the missing headers
            // never come in and we need to request them but dont, probably on the sending side, we should
            // make sure we are announcing all headers to the peer since the last one we sent
            connman.PushMessage(pfrom, NetMsgType::GETHEADERS,
                g_chainman.chainActive.GetLocator(g_chainman.pindexBestHeader), uint256());
            return true;
        }
        // If possible add any previously unconnected headers to the headers vector and remove any expired entries.
        std::map<uint256, std::pair<CBlockHeader, int64_t> >::iterator mi = mapUnConnectedHeaders.begin();
        while (mi != mapUnConnectedHeaders.end())
        {
            std::map<uint256, std::pair<CBlockHeader, int64_t> >::iterator toErase = mi;

            // Add the header if it connects to the previous header
            if (headers.back().GetHash() == (*mi).second.first.hashPrevBlock)
            {
                headers.push_back((*mi).second.first);
                mapUnConnectedHeaders.erase(toErase);

                // if you found one to connect then search from the beginning again in case there is another
                // that will connect to this new header that was added.
                mi = mapUnConnectedHeaders.begin();
                continue;
            }

            // Remove any entries that have been in the cache too long.  Unconnected headers should only exist
            // for a very short while, typically just a second or two.
            int64_t nTimeHeaderArrived = (*mi).second.second;
            uint256 headerHash = (*mi).first;
            mi++;
            if (GetTime() - nTimeHeaderArrived >= UNCONNECTED_HEADERS_TIMEOUT)
            {
                mapUnConnectedHeaders.erase(toErase);
            }
            // At this point we know the headers in the list received are known to be in order, therefore,
            // check if the header is equal to some other header in the list. If so then remove it from the cache.
            else
            {
                for (const CBlockHeader &header : headers)
                {
                    if (header.GetHash() == headerHash)
                    {
                        mapUnConnectedHeaders.erase(toErase);
                        break;
                    }
                }
            }
        }
        // Check and accept each header in dependency order (oldest block to most recent)
        CBlockIndex *pindexLast = nullptr;
        int i = 0;
        {
            LOCK(cs_main);
            for (const CBlockHeader &header : headers)
            {
                CValidationState state;
                if (!AcceptBlockHeader(header, state, chainparams, &pindexLast))
                {
                    int nDos;
                    if (state.IsInvalid(nDos))
                    {
                        if (nDos > 0)
                        {
                            g_dosman->Misbehaving(pfrom, nDos, state.GetRejectReason());
                        }
                    }
                    // all headers from this one forward reference a fork that we don't follow, so erase them
                    headers.erase(headers.begin() + i, headers.end());
                    nCount = headers.size();
                    break;
                }
                i++;
            }
        }

        if (pindexLast)
        {
            g_requestman->UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());
        }

        if (nCount == MAX_HEADERS_RESULTS && pindexLast)
        {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            LogPrint("net", "more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight,
                pfrom->GetId(), pfrom->nStartingHeight);
            connman.PushMessage(
                pfrom, NetMsgType::GETHEADERS, g_chainman.chainActive.GetLocator(pindexLast), uint256());

            g_requestman->SetPeerSyncStartTime(pfrom);

            // During the process of IBD we need to update block availability for every connected peer. To do that we
            // request, from each NODE_NETWORK peer, a header that matches the last blockhash found in this recent set
            // of headers. Once the requested header is received then the block availability for this peer will get
            // updated.
            if (g_chainman.IsInitialBlockDownload())
            {
                // TODO : there is a better way to do this
                std::vector<NodeId> nodes = g_requestman->UpdateBestKnowBlockAll(pindexLast);
                for (auto &node : nodes)
                {
                    // We only want one single header so we pass a null for CBlockLocator.
                    connman.PushMessageToId(node, NetMsgType::GETHEADERS, CBlockLocator(), pindexLast->GetBlockHash());
                    LogPrint("net", "Requesting header for blockavailability, peer=%d block=%s height=%d\n", node,
                        pindexLast->GetBlockHash().ToString().c_str(), g_chainman.pindexBestHeader.load()->nHeight);
                }
            }
        }

        g_requestman->SetPeerFirstHeaderReceived(pfrom, pindexLast);

        // If this set of headers is valid and ends in a block with at least as
        // much work as our tip, download as much as possible.
        if (pindexLast && pindexLast->IsValid(BLOCK_VALID_TREE) &&
            g_chainman.chainActive.Tip()->nChainWork <= pindexLast->nChainWork)
        {
            std::vector<CBlockIndex *> vToFetch;
            CBlockIndex *pindexWalk = pindexLast;
            // Calculate all the blocks we'd need to switch to pindexLast.
            while (pindexWalk && !g_chainman.chainActive.Contains(pindexWalk))
            {
                vToFetch.push_back(pindexWalk);
                pindexWalk = pindexWalk->pprev;
            }

            // Download as much as possible, from earliest to latest.
            int nAskFor = 0;
            for (auto pindex_iter = vToFetch.rbegin(); pindex_iter != vToFetch.rend(); pindex_iter++)
            {
                CBlockIndex *pindex = *pindex_iter;
                // pindex must be nonnull because we populated vToFetch a few lines above
                CInv inv(MSG_BLOCK, pindex->GetBlockHash());
                if (!AlreadyHaveBlock(inv))
                {
                    pfrom->AskFor(inv);
                    LogPrint("net", "AskFor block via headers direct fetch %s (%d) peer=%d\n",
                        pindex->GetBlockHash().ToString(), pindex->nHeight, pfrom->GetId());
                    nAskFor++;
                }
                // We don't care about how many blocks are in flight.  We just need to make sure we don't
                // ask for more than the maximum allowed per peer because the request manager will take care
                // of any duplicate requests.

                if (nAskFor >= MAX_BLOCKS_IN_TRANSIT_PER_PEER)
                {
                    LogPrint("net", "Large reorg, could only fetch %d blocks\n", nAskFor);
                    break;
                }
            }
            if (nAskFor > 1)
            {
                LogPrint("net", "Downloading blocks toward %s (%d) via headers direct fetch\n",
                    pindexLast->GetBlockHash().ToString(), pindexLast->nHeight);
            }
        }
        CheckBlockIndex(chainparams.GetConsensus());
    }

    else if (strCommand == NetMsgType::BLOCK && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;

        const uint256 hash(block.GetHash());
        LogPrint("net", "received block %s peer=%d\n", hash.ToString(), pfrom->id);

        // Process all blocks from whitelisted peers, even if not requested,
        // unless we're still syncing with the network. Such an unrequested
        // block may still be processed, subject to the conditions in
        // AcceptBlock().
        bool forceProcessing = pfrom->fWhitelisted && !g_chainman.IsInitialBlockDownload();
        {
            // Also always process if we requested the block explicitly, as we
            // may need it even though it is not a candidate for a new best tip.
            forceProcessing |= g_requestman->MarkBlockAsReceived(hash);
        }
        CValidationState state;
        ProcessNewBlock(state, chainparams, pfrom, &block, forceProcessing, NULL);
        int nDoS;
        if (state.IsInvalid(nDoS))
        {
            assert(state.GetRejectCode() < REJECT_INTERNAL); // Blocks are never rejected with internal reject codes
            connman.PushMessage(pfrom, NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), hash);
            if (nDoS > 0)
            {
                g_dosman->Misbehaving(pfrom, nDoS, "invalid-blk");
            }
        }
    }

    // This asymmetric behavior for inbound and outbound connections was introduced
    // to prevent a fingerprinting attack: an attacker can send specific fake addresses
    // to users' AddrMan and later request them by sending getaddr messages.
    // Making nodes which are behind NAT and can only make outgoing connections ignore
    // the getaddr message mitigates the attack.
    else if ((strCommand == NetMsgType::GETADDR) && (pfrom->fInbound))
    {
        // This asymmetric behavior for inbound and outbound connections was
        // introduced to prevent a fingerprinting attack: an attacker can send
        // specific fake addresses to users' AddrMan and later request them by
        // sending getaddr messages. Making nodes which are behind NAT and can
        // only make outgoing connections ignore the getaddr message mitigates
        // the attack.
        if (!pfrom->fInbound)
        {
            LogPrintf("Ignoring \"getaddr\" from outbound connection. peer=%d\n", pfrom->GetId());
            return true;
        }

        // Only send one GetAddr response per connection to reduce resource
        // waste and discourage addr stamping of INV announcements.
        if (pfrom->fSentAddr)
        {
            LogPrintf("Ignoring repeated \"getaddr\". peer=%d\n", pfrom->GetId());
            return true;
        }
        pfrom->fSentAddr = true;

        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr = connman.GetAddresses();
        FastRandomContext insecure_rand;
        for (const CAddress &addr : vAddr)
        {
            // dont relay banned addresses
            if (!g_dosman->IsBanned(addr))
            {
                pfrom->PushAddress(addr, insecure_rand);
            }
        }
    }

    else if (strCommand == NetMsgType::PING)
    {
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            connman.PushMessage(pfrom, NetMsgType::PONG, nonce);
        }
    }

    else if (strCommand == NetMsgType::PONG)
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce))
        {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0)
            {
                if (nonce == pfrom->nPingNonceSent)
                {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0)
                    {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime.load(), pingUsecTime);
                    }
                    else
                    {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                }
                else
                {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0)
                    {
                        // This is most likely a bug in another implementation somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            }
            else
            {
                sProblem = "Unsolicited pong without ping";
            }
        }
        else
        {
            // This is most likely a bug in another implementation somewhere; cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty()))
        {
            LogPrint("net", "pong peer=%d: %s, %x expected, %x received, %u bytes\n", pfrom->id, sProblem,
                pfrom->nPingNonceSent, nonce, nAvail);
        }
        if (bPingFinished)
        {
            pfrom->nPingNonceSent = 0;
        }
    }

    else if (strCommand == NetMsgType::FILTERLOAD)
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            // There is no excuse for sending a too-large filter
            g_dosman->Misbehaving(pfrom, 100, "oversized-bloom-filter");
        }
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }

    else if (strCommand == NetMsgType::FILTERADD)
    {
        std::vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            g_dosman->Misbehaving(pfrom, 100, "invalid-filteradd");
        }
        else
        {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
            {
                pfrom->pfilter->insert(vData);
            }
            else
            {
                g_dosman->Misbehaving(pfrom, 100, "invalid-filteradd");
            }
        }
    }

    else if (strCommand == NetMsgType::FILTERCLEAR)
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }

    else if (strCommand == NetMsgType::REJECT)
    {
        if (g_logger->fDebug)
        {
            try
            {
                std::string strMsg;
                unsigned char ccode;
                std::string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >>
                    LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                std::ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX)
                {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint("net", "Reject %s\n", SanitizeString(ss.str()));
            }
            catch (const std::ios_base::failure &)
            {
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                LogPrint("net", "Unparseable reject message received\n");
            }
        }
    }

    else if (strCommand == NetMsgType::RREQ)
    {
        if (!IsBetaEnabled())
        {
            return true;
        }
        /**
         * A peer has requested a route to a specific id. we need to:
         * keep track of who sent the request, make sure it was unique,
         * check our routing table to see if we know of it, if we do respond with a RREP,
         * otherwise forward this request to our peers except the one that sent it.
         *
         * if we have the node we will respond with our preffered privacy settings.
         */
        uint64_t nonce = 0;
        CPubKey searchKey;
        vRecv >> nonce;
        vRecv >> searchKey;
        bool peerKnown = g_aodvtable.HaveRoute(searchKey) || connman.GetPublicTagPubKey() == searchKey;
        if (peerKnown)
        {
            connman.PushMessage(pfrom, NetMsgType::RREP, nonce, searchKey, peerKnown);
        }
        else
        {
            RequestRouteToPeer(connman, pfrom->routing_id, nonce, searchKey);
            RecordRequestOrigin(nonce, pfrom->routing_id);
        }
    }

    else if (strCommand == NetMsgType::RREP)
    {
        if (!IsBetaEnabled())
        {
            return true;
        }
        uint64_t nonce = 0;
        CPubKey searchKey;
        bool found;
        vRecv >> nonce;
        vRecv >> searchKey;
        vRecv >> found;
        /**
         * we got a response from someone who knows of or has what we are looking for.
         * if they allow direct connections try to form one with them to reduce network load.
         * if they dont, try to establish a more or less direct route to the general area of peers
         * to proceed with an application specific conversation
         */
        if (found)
        {
            RecordRouteToPeer(searchKey, pfrom->GetId());
            CPubKey source;
            if (GetRequestOrigin(nonce, source))
            {
                AddResponseToQueue(source, nonce, searchKey);
            }
        }
    }

    else if (strCommand == NetMsgType::RERR)
    {
        // intentionally left blank
        // to be used for error reporting later
    }

    else if (strCommand == NetMsgType::SPH)
    {
        uint64_t nonce = 0;
        CPubKey searchKey;
        CPacketHeader newHeader;
        vRecv >> nonce;
        vRecv >> searchKey;
        vRecv >> newHeader;
        bool ours = connman.GetPublicTagPubKey() == searchKey;
        if (ours)
        {
            if (!g_packetman.ProcessPacketHeader(nonce, newHeader))
            {
                // TODO : send an error back to the sender if possible
            }
        }
        else
        {
            NodeId peerNode;
            if (g_aodvtable.GetKeyNode(searchKey, peerNode))
            {
                connman.PushMessageToId(peerNode, NetMsgType::SPH, nonce, searchKey, newHeader);
            }
        }
    }

    else if (strCommand == NetMsgType::SPD)
    {
        uint64_t nonce = 0;
        CPubKey searchKey;
        CPacketDataSegment newSegment;
        vRecv >> nonce;
        vRecv >> searchKey;
        vRecv >> newSegment;
        bool ours = connman.GetPublicTagPubKey() == searchKey;
        if (ours)
        {
            if (!g_packetman.ProcessDataSegment(nonce, newSegment))
            {
                // TODO : send an error back to the sender if possible
            }
        }
        else
        {
            NodeId peerNode;
            if (g_aodvtable.GetKeyNode(searchKey, peerNode))
            {
                connman.PushMessageToId(peerNode, NetMsgType::SPD, nonce, searchKey, newSegment);
            }
        }
    }

    else
    {
        // Ignore unknown commands for extensibility
        LogPrint("net", "Unknown command \"%s\" from peer=%d\n", SanitizeString(strCommand), pfrom->id);
    }


    return true;
}

bool ProcessMessages(CNode *pfrom, CConnman &connman)
{
    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fMoreWork = false;

    {
        TRY_LOCK(pfrom->csRecvGetData, locked);
        if (locked && !pfrom->vRecvGetData.empty())
        {
            ProcessGetData(pfrom, connman, Params().GetConsensus(), pfrom->vRecvGetData);
        }
    }

    if (pfrom->fDisconnect)
    {
        return false;
    }

    // Don't bother if send buffer is too full to respond anyway
    if (pfrom->fPauseSend)
    {
        return false;
    }

    std::list<CNetMessage> msgs;
    {
        LOCK(pfrom->cs_vProcessMsg);
        if (pfrom->vProcessMsg.empty())
        {
            return false;
        }
        // Just take one message
        msgs.splice(msgs.begin(), pfrom->vProcessMsg, pfrom->vProcessMsg.begin());
        pfrom->nProcessQueueSize -= msgs.front().vRecv.size() + CMessageHeader::HEADER_SIZE;
        pfrom->fPauseRecv = pfrom->nProcessQueueSize > connman.GetReceiveFloodSize();
        fMoreWork = !pfrom->vProcessMsg.empty();
    }
    CNetMessage &msg(msgs.front());

    msg.SetVersion(pfrom->GetRecvVersion());

    // Scan for message start
    if (memcmp(std::begin(msg.hdr.pchMessageStart), std::begin(Params().MessageStart()),
            CMessageHeader::MESSAGE_START_SIZE) != 0)
    {
        LogPrintf("PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n", SanitizeString(msg.hdr.GetCommand()), pfrom->id);
        pfrom->fDisconnect = true;
        return false;
    }

    // Read header
    CMessageHeader &hdr = msg.hdr;
    if (!hdr.IsValid(Params().MessageStart()))
    {
        LogPrintf("PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n", SanitizeString(hdr.GetCommand()), pfrom->id);
        return fMoreWork;
    }
    std::string strCommand = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;

    // Checksum
    CDataStream &vRecv = msg.vRecv;

#if 0
    const uint256 &hash = msg.GetMessageHash();
    // Do not waste my CPU calculating a checksum provided by an untrusted node
    // TCP already has one that is sufficient for network errors.  The checksum does not increase security since
    // an attacker can always provide a bad message with a good checksum.
    // This code is removed by comment so it is clear that it is a deliberate omission.
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0)
    {
        LogPrintf("%s(%s, %u bytes): CHECKSUM ERROR expected %s was %s\n", __func__, SanitizeString(strCommand),
            nMessageSize, HexStr(hash.begin(), hash.begin() + CMessageHeader::CHECKSUM_SIZE),
            HexStr(hdr.pchChecksum, hdr.pchChecksum + CMessageHeader::CHECKSUM_SIZE));
        return fMoreWork;
    }
#endif

    // Process message
    bool fRet = false;
    try
    {
        fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime, connman);
        LOCK(pfrom->csRecvGetData);
        if (!pfrom->vRecvGetData.empty())
        {
            fMoreWork = true;
        }
    }
    catch (const std::ios_base::failure &e)
    {
        connman.PushMessage(
            pfrom, NetMsgType::REJECT, strCommand, REJECT_MALFORMED, std::string("error parsing message"));
        if (strstr(e.what(), "end of data"))
        {
            // Allow exceptions from under-length message on vRecv
            LogPrintf("%s(%s, %u bytes): Exception '%s' caught, normally caused by a "
                      "message being shorter than its stated length\n",
                __func__, SanitizeString(strCommand), nMessageSize, e.what());
        }
        else if (strstr(e.what(), "size too large"))
        {
            // Allow exceptions from over-long size
            LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize,
                e.what());
        }
        else if (strstr(e.what(), "non-canonical ReadCompactSize()"))
        {
            // Allow exceptions from non-canonical encoding
            LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize,
                e.what());
        }
        else
        {
            PrintExceptionContinue(&e, "ProcessMessages()");
        }
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "ProcessMessages()");
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "ProcessMessages()");
    }

    if (!fRet)
    {
        LogPrintf("%s(%s, %u bytes) FAILED peer=%d\n", __func__, SanitizeString(strCommand), nMessageSize, pfrom->id);
    }

    return fMoreWork;
}

bool SendMessages(CNode *pto, CConnman &connman)
{
    // Don't send anything until the version handshake is complete
    if (!pto->fSuccessfullyConnected || pto->fDisconnect)
    {
        return true;
    }

    //
    // Message: ping
    //
    bool pingSend = false;
    if (pto->fPingQueued)
    {
        // RPC ping request by user
        pingSend = true;
    }
    if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros())
    {
        // Ping automatically sent as a latency probe & keepalive.
        pingSend = true;
    }
    if (pingSend)
    {
        uint64_t nonce = 0;
        while (nonce == 0)
        {
            GetStrongRandBytes((uint8_t *)&nonce, sizeof(nonce));
        }
        pto->fPingQueued = false;
        pto->nPingUsecStart = GetTimeMicros();
        pto->nPingNonceSent = nonce;
        connman.PushMessage(pto, NetMsgType::PING, nonce);
    }

    // Address refresh broadcast
    int64_t nNow = GetTimeMicros();
    if (!g_chainman.IsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow)
    {
        AdvertiseLocal(pto);
        pto->nNextLocalAddrSend = PoissonNextSend(nNow, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
    }

    //
    // Message: addr
    //
    if (pto->nNextAddrSend < nNow)
    {
        pto->nNextAddrSend = PoissonNextSend(nNow, AVG_ADDRESS_BROADCAST_INTERVAL);
        std::vector<CAddress> vAddr;
        vAddr.reserve(pto->vAddrToSend.size());
        for (const CAddress &addr : pto->vAddrToSend)
        {
            if (!pto->addrKnown.contains(addr.GetKey()))
            {
                pto->addrKnown.insert(addr.GetKey());
                vAddr.push_back(addr);
                // receiver rejects addr messages larger than 1000
                if (vAddr.size() >= 1000)
                {
                    connman.PushMessage(pto, NetMsgType::ADDR, vAddr);
                    vAddr.clear();
                }
            }
        }
        pto->vAddrToSend.clear();
        if (!vAddr.empty())
        {
            connman.PushMessage(pto, NetMsgType::ADDR, vAddr);
        }

        // we only send the big addr message once
        if (pto->vAddrToSend.capacity() > 40)
        {
            pto->vAddrToSend.shrink_to_fit();
        }
    }

    // Start block sync
    if (g_chainman.pindexBestHeader == nullptr)
    {
        g_chainman.pindexBestHeader = g_chainman.chainActive.Tip();
    }

    g_requestman->StartDownload(pto);

    // Resend wallet transactions that haven't gotten in a block yet
    // Except during reindex, importing and IBD, when old wallet transactions
    // become unconfirmed and spams other nodes.
    if (!fReindex && !fImporting && !g_chainman.IsInitialBlockDownload())
    {
        GetMainSignals().Broadcast(nTimeBestReceived.load(), &connman);
    }

    //
    // Try sending block announcements via headers
    //
    {
        // If we have less than MAX_BLOCKS_TO_ANNOUNCE in our list of block
        // hashes we're relaying, and our peer wants headers announcements, then
        // find the first header not yet known to our peer but would connect,
        // and send. If no header would connect, or if we have too many blocks,
        // or if the peer doesn't want headers, just add all to the inv queue.
        RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
        LOCK(pto->cs_inventory);
        std::vector<CBlock> vHeaders;
        bool fRevertToInv = ((g_requestman->GetPreferHeaders(pto) && (pto->vBlockHashesToAnnounce.size() > 1)) ||
                             pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
        // last header queued for delivery
        CBlockIndex *pBestIndex = nullptr;
        // ensure pindexBestKnownBlock is up-to-date
        g_requestman->ProcessBlockAvailability(pto->id);

        if (!fRevertToInv)
        {
            bool fFoundStartingHeader = false;
            // Try to find first header that our peer doesn't have, and then
            // send all headers past that one. If we come across an headers that
            // aren't on chainActive, give up.
            for (const uint256 &hash : pto->vBlockHashesToAnnounce)
            {
                CBlockIndex *pindex = g_chainman.LookupBlockIndex(hash);
                if (!pindex)
                {
                    continue;
                }
                if (g_chainman.chainActive[pindex->nHeight] != pindex)
                {
                    // Bail out if we reorged away from this block
                    fRevertToInv = true;
                    break;
                }
                if (pBestIndex != nullptr && pindex->pprev != pBestIndex)
                {
                    // This means that the list of blocks to announce don't
                    // connect to each other. This shouldn't really be possible
                    // to hit during regular operation (because reorgs should
                    // take us to a chain that has some block not on the prior
                    // chain, which should be caught by the prior check), but
                    // one way this could happen is by using invalidateblock /
                    // reconsiderblock repeatedly on the tip, causing it to be
                    // added multiple times to vBlockHashesToAnnounce. Robustly
                    // deal with this rare situation by reverting to an inv.
                    fRevertToInv = true;
                    break;
                }
                pBestIndex = pindex;
                if (fFoundStartingHeader)
                {
                    // add this to the headers message
                    vHeaders.push_back(pindex->GetBlockHeader());
                }
                else if (g_requestman->PeerHasHeader(pto->GetId(), pindex))
                {
                    // Keep looking for the first new block.
                    continue;
                }
                else if (pindex->pprev == nullptr || g_requestman->PeerHasHeader(pto->GetId(), pindex->pprev))
                {
                    // Peer doesn't have this header but they do have the prior
                    // one.
                    // Start sending headers.
                    fFoundStartingHeader = true;
                    vHeaders.push_back(pindex->GetBlockHeader());
                }
                else
                {
                    // Peer doesn't have this header or the prior one --
                    // nothing will connect, so bail out.
                    fRevertToInv = true;
                    break;
                }
            }
        }
        if (fRevertToInv)
        {
            // If falling back to using an inv, just try to inv the tip. The
            // last entry in vBlockHashesToAnnounce was our tip at some point in
            // the past.
            if (!pto->vBlockHashesToAnnounce.empty())
            {
                for (const uint256 &hashToAnnounce : pto->vBlockHashesToAnnounce)
                {
                    CBlockIndex *pindex = nullptr;
                    pindex = g_chainman.LookupBlockIndex(hashToAnnounce);
                    if (!pindex)
                    {
                        continue;
                    }

                    // Warn if we're announcing a block that is not on the main
                    // chain. This should be very rare and could be optimized out.
                    // Just log for now.
                    if (g_chainman.chainActive[pindex->nHeight] != pindex)
                    {
                        LogPrint("net", "Announcing block %s not on main chain (tip=%s)\n", hashToAnnounce.ToString(),
                            g_chainman.chainActive.Tip()->GetBlockHash().ToString());
                    }

                    // If the peer's chain has this block, don't inv it back.
                    if (!g_requestman->PeerHasHeader(pto->GetId(), pindex))
                    {
                        pto->PushInventory(CInv(MSG_BLOCK, hashToAnnounce));
                        LogPrint(
                            "net", "%s: sending inv peer=%d hash=%s\n", __func__, pto->id, hashToAnnounce.ToString());
                    }
                }
            }
        }
        else if (!vHeaders.empty())
        {
            if (vHeaders.size() > 1)
            {
                LogPrint("net", "%s: %u headers, range (%s, %s), to peer=%d\n", __func__, vHeaders.size(),
                    vHeaders.front().GetHash().ToString(), vHeaders.back().GetHash().ToString(), pto->id);
            }
            else
            {
                LogPrint("net", "%s: sending header %s to peer=%d\n", __func__, vHeaders.front().GetHash().ToString(),
                    pto->id);
            }
            connman.PushMessage(pto, NetMsgType::HEADERS, vHeaders);
            g_requestman->SetBestHeaderSent(pto->GetId(), pBestIndex);
        }
        pto->vBlockHashesToAnnounce.clear();
    }

    //
    // Message: inventory
    //
    std::vector<CInv> vInv;
    std::vector<CInv> vInvToSend;
    {
        LOCK(pto->cs_inventory);
        if (pto->vInventoryToSend.empty() == false)
        {
            std::swap(vInvToSend, pto->vInventoryToSend);
        }
    }
    {
        // No reason to drain out at many times the network's capacity,
        // especially since we have many peers and some will draw much
        // shorter delays.
        unsigned int nRelayedTransactions = 0;
        LOCK(pto->cs_inventory);
        for (auto &entry : vInvToSend)
        {
            if (nRelayedTransactions < INVENTORY_BROADCAST_MAX)
            {
                // Check if not in the filter already
                if (pto->filterInventoryKnown.contains(entry.hash))
                {
                    continue;
                }
                // Send
                vInv.push_back(entry);
                nRelayedTransactions++;
                if (vInv.size() == MAX_INV_SZ)
                {
                    connman.PushMessage(pto, NetMsgType::INV, vInv);
                    vInv.clear();
                }
                pto->filterInventoryKnown.insert(entry.hash);
            }
        }
    }
    if (!vInv.empty())
    {
        connman.PushMessage(pto, NetMsgType::INV, vInv);
        vInv.clear();
    }

    // ask for things we need
    std::vector<CInv> requests;
    {
        LOCK(pto->cs_askfor);
        for (auto &element : pto->mapAskFor)
        {
            if (element.second.type == MSG_TX)
            {
                requests.push_back(element.second);
            }
        }
        pto->mapAskFor.clear();
    }
    {
        LOCK(pto->cs_askfor);
        LOCK(cs_alreadyaskfor);
        for (auto &entry : requests)
        {
            pto->setAskFor.erase(entry.hash);
            mapAlreadyAskedFor.erase(entry.hash);
        }
    }
    if (requests.empty() == false)
    {
        connman.PushMessage(pto, NetMsgType::GETDATA, requests);
    }

    // use temp variables because they are atomic
    // TODO : add some chain not in sync conditional as well
    // CBlockIndex *pTip = g_chainman.chainActive.Tip();
    // CBlockIndex *pBestInvalid = pindexBestInvalid.load();
    // if (pBestInvalid && pTip && pBestInvalid->nChainWork > pTip->nChainWork)
    {
        g_requestman->RequestNextBlocksToDownload(pto);
    }

    if (IsBetaEnabled())
    {
        std::set<RREQRESPONSE> responseQueue_copy;
        {
            RECURSIVEREADLOCK(g_aodvtable.cs_aodv);
            for (const auto &response : g_aodvtable.responseQueue)
            {
                if (response.source == pto->routing_id)
                {
                    connman.PushMessage(pto, NetMsgType::RREP, response.nonce, response.pubkey, response.found);
                }
                else
                {
                    responseQueue_copy.emplace(response);
                }
            }
        }
        {
            RECURSIVEWRITELOCK(g_aodvtable.cs_aodv);
            g_aodvtable.responseQueue = responseQueue_copy;
        }
    }

    return true;
}
