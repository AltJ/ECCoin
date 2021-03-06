// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "chain.h"
#include "init.h"
#include "main.h"
#include "networks/networktemplate.h"
#include "uint256.h"

#include <boost/foreach.hpp>
#include <stdint.h>

namespace Checkpoints
{
int GetTotalBlocksEstimate(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    if (checkpoints.empty())
        return 0;

    return checkpoints.rbegin()->first;
}

CBlockIndex *GetLastCheckpoint(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    BOOST_REVERSE_FOREACH (const MapCheckpoints::value_type &i, checkpoints)
    {
        const uint256 &hash = i.second;
        CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hash);
        if (pindex)
        {
            return pindex;
        }
    }
    return nullptr;
}

} // namespace Checkpoints
