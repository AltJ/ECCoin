// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MESSAGES_H
#define MESSAGES_H

#include "chain/blockindex.h"
#include "net/net.h"
#include "validationinterface.h"


extern std::unique_ptr<CRollingBloomFilter> recentRejects;

class PeerLogicValidation : public CValidationInterface
{
private:
    CConnman *connman;

public:
    PeerLogicValidation(CConnman *connmanIn);
    void NewPoWValidBlock(CBlockIndex *pindex, const CBlock *pblock) override;
};

bool AlreadyHaveBlock(const CInv &inv);
bool AlreadyHaveTx(const CInv &inv);

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode *pfrom, CConnman &connman);

/**Send queued protocol messages to be sent to a give node. */
bool SendMessages(CNode *pto, CConnman &connman);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals &nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals &nodeSignals);


#endif // MESSAGES_H
