// This file is part of the Eccoin project
// Copyright (c) 2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_REQUESTMANAGER_H
#define ECCOIN_REQUESTMANAGER_H

#include "net.h"
#include "nodestate.h"

#include <vector>

struct CNodeStateStats
{
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};

// Blocks that are in flight, and that are in the queue to be downloaded
// only used by request manager
struct QueuedBlock
{
    uint256 hash;
    const CBlockIndex *pindex; //!< Optional.
    bool fValidatedHeaders; //!< Whether this block has validated headers at the time of request.
};

class CRequestManager
{
protected:
    CSharedCriticalSection cs_requestmanager;
    CCriticalSection cs_mapRelay;

    std::map<uint256, std::pair<NodeId, QueuedBlock> > mapBlocksInFlight;
    std::map<NodeId, int16_t> mapNumBlocksInFlight;
    std::map<NodeId, CNodeState> mapNodeState;
    std::map<uint256, CTransaction> mapRelay;
    std::deque<std::pair<int64_t, std::map<uint256, CTransaction>::iterator> > vRelayExpiration;
    friend class CNodeStateAccessor;

protected:
    void _ProcessBlockAvailability(NodeId nodeid);

public:
    bool AlreadyAskedForBlock(const uint256 &hash);

    CNodeState *_GetNodeState(const NodeId id);

    /** Add a nodestate from the map */
    void InitializeNodeState(const CNode *pnode);

    /** Delete a nodestate from the map */
    void RemoveNodeState(const NodeId id);

    /** Clear the entire nodestate map */
    void Clear()
    {
        WRITELOCK(cs_requestmanager);
        mapNodeState.clear();
    }

    /** Is mapNodestate empty */
    bool Empty()
    {
        WRITELOCK(cs_requestmanager);
        return mapNodeState.empty();
    }

    void ProcessBlockAvailability(NodeId nodeid);

    /** Update tracking information about which blocks a peer is assumed to have. */
    void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash);

    bool PeerHasHeader(const NodeId nodeid, const CBlockIndex *pindex);

    void MarkBlockAsInFlight(NodeId nodeid, const uint256 &hash, const CBlockIndex *pindex = nullptr);

    void UpdatePreferredDownload(CNode *node);

    /** Returns a bool indicating whether we requested this block. If we did request it, marks it as receieved and removes
     * block from in flight list*/
    bool MarkBlockAsReceived(const uint256 &hash);

    void SetBestHeaderSent(NodeId nodeid, CBlockIndex* pindex);

    /** Get statistics from node state */
    bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);

    bool GetPreferHeaders(CNode *node);

    void SetPreferHeaders(CNode *node);

    int GetBlocksInFlight(NodeId nodeid);

    void StartDownload(CNode* node);

    bool IsBlockInFlight(const uint256 &hash);

    void TrackTxRelay(const CTransaction &tx);

    bool FindAndPushTx(CNode* node, const uint256 &hash);

    void SetPeerFirstHeaderReceived(CNode* node, CBlockIndex* pindexLast);

    void SetPeerSyncStartTime(CNode* node);

    // TODO : there is a better way to do this function
    std::vector<NodeId> UpdateBestKnowBlockAll(CBlockIndex* pindexLast);

    void RequestNextBlocksToDownload(CNode* node);

    void FindNextBlocksToDownload(CNode *node, unsigned int count, std::vector<CBlockIndex *> &vBlocks);
};

extern std::unique_ptr<CRequestManager> g_requestman;

#endif
