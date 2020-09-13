// This file is part of the Eccoin project
// Copyright (c) 2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "requestmanager.h"

#include "chain/chainman.h"
#include "connman.h"
#include "messages.h"

extern std::atomic<int> nPreferredDownload;

extern std::atomic<bool> fImporting;
extern std::atomic<bool> fReindex;

extern bool AlreadyHave(const CInv &inv);

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
CBlockIndex *LastCommonAncestor(CBlockIndex *pa, CBlockIndex *pb)
{
    if (pa->nHeight > pb->nHeight)
    {
        pa = pa->GetAncestor(pb->nHeight);
    }
    else if (pb->nHeight > pa->nHeight)
    {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb)
    {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

CNodeState *CRequestManager::_GetNodeState(const NodeId id)
{
    std::map<NodeId, CNodeState>::iterator it = mapNodeState.find(id);
    if (it == mapNodeState.end())
    {
        return nullptr;
    }
    return &it->second;
}

void CRequestManager::InitializeNodeState(const CNode *pnode)
{
    WRITELOCK(cs_requestmanager);
    mapNodeState.emplace_hint(mapNodeState.end(), std::piecewise_construct, std::forward_as_tuple(pnode->GetId()),
        std::forward_as_tuple(pnode->addr, pnode->GetAddrName()));
    mapNumBlocksInFlight.emplace(pnode->GetId(), 0);
}

void CRequestManager::RemoveNodeState(const NodeId id)
{
    WRITELOCK(cs_requestmanager);
    mapNodeState.erase(id);
    mapNumBlocksInFlight.erase(id);
    for (auto iter = mapBlocksInFlight.begin(); iter != mapBlocksInFlight.end();)
    {
        if (iter->second.first == id)
        {
            iter = mapBlocksInFlight.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

/** Check whether the last unknown block a peer advertized is not yet known. */
void CRequestManager::_ProcessBlockAvailability(NodeId nodeid)
{
    RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
    AssertWriteLockHeld(cs_requestmanager);

    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;

    if (!state->hashLastUnknownBlock.IsNull())
    {
        CBlockIndex *pindex = g_chainman.LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->nChainWork > 0)
        {
            if (state->pindexBestKnownBlock == NULL || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork)
            {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

/** Check whether the last unknown block a peer advertized is not yet known. */
void CRequestManager::ProcessBlockAvailability(NodeId nodeid)
{
    RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
    WRITELOCK(cs_requestmanager);

    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;

    if (!state->hashLastUnknownBlock.IsNull())
    {
        CBlockIndex *pindex = g_chainman.LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->nChainWork > 0)
        {
            if (state->pindexBestKnownBlock == NULL || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork)
            {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

// TODO : currently needs cs_mapBlockIndex before locking this, should fix that
void CRequestManager::UpdateBlockAvailability(NodeId nodeid, const uint256 &hash)
{
    CBlockIndex *pindex = g_chainman.LookupBlockIndex(hash);
    ProcessBlockAvailability(nodeid);
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;
    if (pindex && pindex->nChainWork > 0)
    {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == NULL || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork)
        {
            LogPrint("net", "updated peer %d best known block \n", nodeid);
            state->pindexBestKnownBlock = pindex;
        }
    }
    else
    {
        LogPrint("net", "updated peer %d hash last unknown block \n", nodeid);
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

bool CRequestManager::PeerHasHeader(const NodeId nodeid, const CBlockIndex *pindex)
{
    READLOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return false;
    }
    CNodeState* state = &iter->second;
    if (state->pindexBestKnownBlock && pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight))
    {
        return true;
    }
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
    {
        return true;
    }
    return false;
}

void CRequestManager::MarkBlockAsInFlight(NodeId nodeid, const uint256 &hash, const CBlockIndex *pindex)
{
    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);
    QueuedBlock newentry = {hash, GetTime(), pindex, pindex != nullptr};
    WRITELOCK(cs_requestmanager);
    mapBlocksInFlight[hash] = std::make_pair(nodeid, newentry);
    if (mapNumBlocksInFlight.count(nodeid) != 0)
    {
        mapNumBlocksInFlight[nodeid] += 1;
    }
}

void CRequestManager::UpdatePreferredDownload(CNode *node)
{
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;

    nPreferredDownload.fetch_sub(state->fPreferredDownload);

    // Whether this node should be marked as a preferred download node.
    // we allow downloads from inbound nodes; this may have been limited in the past to stop attackers from connecting
    // and offering a bad chain. However, we are connecting to multiple nodes and so can choose the most work
    // chain on that basis.
    state->fPreferredDownload = !node->fOneShot && !node->fClient;

    nPreferredDownload.fetch_add(state->fPreferredDownload);
}

// Returns a bool indicating whether we requested this block.
bool CRequestManager::MarkBlockAsReceived(const uint256 &hash)
{
    WRITELOCK(cs_requestmanager);
    std::map<uint256, std::pair<NodeId, QueuedBlock> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end())
    {
        if (mapNumBlocksInFlight.count(itInFlight->second.first) != 0)
        {
            mapNumBlocksInFlight[itInFlight->second.first] -= 1;
        }
        mapBlocksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

void CRequestManager::SetBestHeaderSent(NodeId nodeid, CBlockIndex* pindex)
{
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return;
    }
    iter->second.pindexBestHeaderSent = pindex;
}

bool CRequestManager::GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats)
{
    READLOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(nodeid);
    if(iter == mapNodeState.end())
    {
        return false;
    }
    CNodeState* state = &iter->second;

    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    for (const auto &queue : mapBlocksInFlight)
    {
        if (queue.second.first == nodeid)
        {
            if (queue.second.second.pindex)
            {
                stats.vHeightInFlight.push_back(queue.second.second.pindex->nHeight);
            }
        }
    }
    return true;
}

bool CRequestManager::GetPreferHeaders(CNode *node)
{
    READLOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return false;
    }
    return iter->second.fPreferHeaders;
}

void CRequestManager::SetPreferHeaders(CNode *node)
{
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    iter->second.fPreferHeaders = true;
}

int CRequestManager::GetBlocksInFlight(NodeId nodeid)
{
    READLOCK(cs_requestmanager);
    std::map<NodeId, int16_t>::iterator iter = mapNumBlocksInFlight.find(nodeid);
    if(iter == mapNumBlocksInFlight.end())
    {
        return 0;
    }
    return iter->second;
}

void CRequestManager::StartDownload(CNode* node)
{
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;

    // Download if this is a nice peer, or we have no nice peers and this one
    // might do.
    bool fFetch = state->fPreferredDownload || (nPreferredDownload.load() == 0 && !node->fOneShot);

    if (!state->fSyncStarted && !node->fClient && !fImporting && !fReindex)
    {
        if (fFetch ||
            g_chainman.pindexBestHeader.load()->GetBlockTime() > GetAdjustedTime() - 24 * 60 * 60)
        {
            state->fSyncStarted = true;
            const CBlockIndex *pindexStart = g_chainman.pindexBestHeader;
            /**
             * If possible, start at the block preceding the currently best
             * known header. This ensures that we always get a non-empty list of
             * headers back as long as the peer is up-to-date. With a non-empty
             * response, we can initialise the peer's known best block. This
             * wouldn't be possible if we requested starting at pindexBestHeader
             * and got back an empty response.
             */
            if (pindexStart->pprev)
            {
                pindexStart = pindexStart->pprev;
            }

            LogPrint("net", "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, node->id,
                node->nStartingHeight);
            g_connman->PushMessage(
                node, NetMsgType::GETHEADERS, g_chainman.chainActive.GetLocator(pindexStart), uint256());
        }
    }
}

bool CRequestManager::IsBlockInFlight(const uint256 &hash)
{
    return mapBlocksInFlight.count(hash);
}

void CRequestManager::TrackTxRelay(const CTransaction &tx)
{
    CInv inv(MSG_TX, tx.GetId());
    LOCK(cs_mapRelay);
    // Expire old relay messages
    while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
    {
        mapRelay.erase(vRelayExpiration.front().second);
        vRelayExpiration.pop_front();
    }
    // Save original serialized message so newer versions are preserved
    auto ret = mapRelay.emplace(inv.hash, tx);
    if (ret.second)
    {
        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, ret.first));
    }
}

bool CRequestManager::FindAndPushTx(CNode* node, const uint256 &hash)
{
    LOCK(cs_mapRelay);
    // Send stream from relay memory
    auto mi = mapRelay.find(hash);
    if (mi != mapRelay.end())
    {
        g_connman->PushMessage(node, NetMsgType::TX, mi->second);
        return true;
    }
    return false;
}

void CRequestManager::SetPeerFirstHeaderReceived(CNode* node, CBlockIndex* pindexLast)
{
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;
    // During the initial peer handshake we must receive the initial headers which should be greater
    // than or equal to our block height at the time of requesting GETHEADERS. This is because the peer has
    // advertised a height >= to our own. Furthermore, because the headers max returned is as much as 2000 this
    // could not be a mainnet re-org.
    if (!state->fFirstHeadersReceived)
    {
        // We want to make sure that the peer doesn't just send us any old valid header. The block height of the
        // last header they send us should be equal to our block height at the time we made the GETHEADERS
        // request.
        if (pindexLast && state->nFirstHeadersExpectedHeight <= pindexLast->nHeight)
        {
            state->fFirstHeadersReceived = true;
            LogPrint("net", "Initial headers received for peer=%d\n", node->GetId());
        }
    }
}

void CRequestManager::SetPeerSyncStartTime(CNode* node)
{
    int64_t now = GetTime();
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;
    state->nSyncStartTime = now; // reset the time because more headers needed
}

std::vector<NodeId> CRequestManager::UpdateBestKnowBlockAll(CBlockIndex* pindexLast)
{
    std::vector<NodeId> nodes;
    READLOCK(cs_requestmanager);
    for (auto &state : mapNodeState)
    {
        if (state.second.pindexBestKnownBlock == nullptr || pindexLast->nChainWork > state.second.pindexBestKnownBlock->nChainWork)
        {
            nodes.push_back(state.first);
        }
    }
    return nodes;
}

void CRequestManager::RequestNextBlocksToDownload(CNode* node)
{

    int16_t nBlocksInFlight = 0;
    {
        READLOCK(cs_requestmanager);
        std::map<NodeId, int16_t>::iterator iter = mapNumBlocksInFlight.find(node->GetId());
        if(iter == mapNumBlocksInFlight.end())
        {
            return;
        }
        nBlocksInFlight = iter->second;
    }
    if (!node->fDisconnect && !node->fClient && nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER)
    {
        std::vector<CBlockIndex *> vToDownload;
        FindNextBlocksToDownload(node, MAX_BLOCKS_IN_TRANSIT_PER_PEER - nBlocksInFlight, vToDownload);
        std::vector<CInv> vGetBlocks;
        for (CBlockIndex *pindex : vToDownload)
        {
            CInv inv(MSG_BLOCK, pindex->GetBlockHash());
            if (!AlreadyHaveBlock(inv))
            {
                vGetBlocks.emplace_back(inv);
            }
        }
        if (!vGetBlocks.empty())
        {
            std::vector<CInv> vToFetchNew;
            {
                READLOCK(cs_requestmanager);
                for (CInv &inv : vGetBlocks)
                {
                    // If this block is already in flight then don't ask for it again during the IBD process.
                    //
                    // If it's an additional source for a new peer then it would have been added already in
                    // FindNextBlocksToDownload().
                    std::map<uint256, std::pair<NodeId, QueuedBlock> >::iterator itInFlight = mapBlocksInFlight.find(inv.hash);
                    if (itInFlight != mapBlocksInFlight.end())
                    {
                        // timeout incoming block requests after 20 seconds and rerequest
                        if (itInFlight->second.second.nDownloadStartTime >= GetTime() - 20)
                        {
                            // block already incoming, move on
                            LogPrint("net", "block %s already in flight, continue \n", inv.hash.ToString().c_str());
                            continue;
                        }
                    }
                    vToFetchNew.push_back(inv);
                }
            }
            if (vToFetchNew.empty() == false)
            {
                vGetBlocks.swap(vToFetchNew);
                g_connman->PushMessage(node, NetMsgType::GETDATA, vGetBlocks);
                for (auto &block : vGetBlocks)
                {
                    MarkBlockAsInFlight(node->GetId(), block.hash, g_chainman.LookupBlockIndex(block.hash));
                }
            }
        }
    }
}

// Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
// at most count entries.
void CRequestManager::FindNextBlocksToDownload(CNode *node, unsigned int count, std::vector<CBlockIndex *> &vBlocks)
{
    if (count == 0)
        return;

    NodeId nodeid = node->GetId();
    vBlocks.reserve(vBlocks.size() + count);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
    WRITELOCK(cs_requestmanager);
    std::map<NodeId, CNodeState>::iterator iter = mapNodeState.find(node->GetId());
    if(iter == mapNodeState.end())
    {
        return;
    }
    CNodeState* state = &iter->second;

    if (state->pindexBestKnownBlock == nullptr ||
        state->pindexBestKnownBlock->nChainWork < g_chainman.chainActive.Tip()->nChainWork)
    {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == nullptr)
    {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock =
            g_chainman.chainActive[std::min(state->pindexBestKnownBlock->nHeight, g_chainman.chainActive.Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
    {
        return;
    }

    std::vector<CBlockIndex *> vToFetch;
    CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the current chain tip + the block download window.  We need to ensure
    // the if running in pruning mode we don't download too many blocks ahead and as a result use to
    // much disk space to store unconnected blocks.
    int nWindowEnd = g_chainman.chainActive.Height() + BLOCK_DOWNLOAD_WINDOW;

    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    while (pindexWalk->nHeight < nMaxHeight)
    {
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--)
        {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded, or if it's
        // already part of our chain (and therefore don't need it even if pruned).
        for (CBlockIndex *pindex : vToFetch)
        {
            uint256 blockHash = pindex->GetBlockHash();
            std::map<uint256, std::pair<NodeId, QueuedBlock> >::iterator itInFlight = mapBlocksInFlight.find(blockHash);
            if (itInFlight != mapBlocksInFlight.end())
            {
                // timeout incoming block requests after 20 seconds and rerequest
                if (itInFlight->second.second.nDownloadStartTime >= GetTime() - 20)
                {
                    // we already requested this block.
                    // TODO : consider also requesting this block from a second peer that has it
                    continue;
                }
            }
            if (!pindex->IsValid(BLOCK_VALID_TREE))
            {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA || g_chainman.chainActive.Contains(pindex))
            {
                if (pindex->nChainTx)
                {
                    state->pindexLastCommonBlock = pindex;
                }
            }
            else
            {
                // Return if we've reached the end of the download window.
                if (pindex->nHeight > nWindowEnd)
                {
                    return;
                }

                // Return if we've reached the end of the number of blocks we can download for this peer.
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count)
                {
                    return;
                }
            }
        }
    }
}
