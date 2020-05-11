// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "args.h"
#include "beta.h"
#include "chain/chainparams.h"

std::atomic<bool> fBeta{DEFAULT_BETA_ENABLED};

void SetBeta()
{
    // set the default to whatever the params for the network specify
    fBeta.store(gArgs.GetBoolArg("-beta", Params().GetBetaDefault()));
}

bool IsBetaEnabled()
{
    return fBeta.load();
}
