// This file is part of the Eccoin project
// Copyright (c) 2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NET_REQUESTMANAGER_H
#define ECCOIN_NET_REQUESTMANAGER_H

#include "net.h"
#include <vector>

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState
{
    //! The peer's address
    CService address;
    //! String name of this peer (debugging/logging purposes).
    std::string name;
    //! The best known block we know this peer has announced.
    CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    //! The last full block we both have.
    CBlockIndex *pindexLastCommonBlock;
    //! The best header we have sent our peer.
    CBlockIndex *pindexBestHeaderSent;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! The start time of the sync
    int64_t nSyncStartTime;
    //! Were the first headers requested in a sync received
    bool fFirstHeadersReceived;
    //! Our current block height at the time we requested GETHEADERS
    int nFirstHeadersExpectedHeight;
    //! During IBD we need to update the block availabiity for each peer. We do this by requesting a header
    //  when a peer connects and also when we ask for the initial set of all headers.
    bool fRequestedInitialBlockAvailability;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for block
    //! announcements.
    bool fPreferHeaders;

    CNodeState(CAddress addrIn, std::string addrNameIn) : address(addrIn), name(addrNameIn)
    {
        pindexBestKnownBlock = nullptr;
        hashLastUnknownBlock.SetNull();
        pindexLastCommonBlock = nullptr;
        pindexBestHeaderSent = nullptr;
        fSyncStarted = false;
        nSyncStartTime = -1;
        fFirstHeadersReceived = false;
        nFirstHeadersExpectedHeight = -1;
        fRequestedInitialBlockAvailability = false;
        fPreferredDownload = false;
        fPreferHeaders = false;
    }
};

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
    int64_t nDownloadStartTime; // the time we requested the block at
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

    CNodeState *_GetNodeState(const NodeId id);

public:
    /** Add a nodestate from the map */
    void InitializeNodeState(const CNode *pnode);

    /** Delete a nodestate from the map */
    void RemoveNodeState(const NodeId id);

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
