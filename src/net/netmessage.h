// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NET_NETMESSAGE_H
#define ECCOIN_NET_NETMESSAGE_H

#include "crypto/hash.h"
#include "protocol.h"
#include "streams.h"

class CNetMessage
{
private:
    mutable CHash256 hasher;
    mutable uint256 data_hash;

public:
    // Parsing header (false) or data (true)
    bool in_data;

    // Partially received header.
    CDataStream hdrbuf;
    // Complete header.
    CMessageHeader hdr;
    unsigned int nHdrPos;

    // Received message data.
    CDataStream vRecv;
    unsigned int nDataPos;

    // Time (in microseconds) of message receipt.
    int64_t nTime;

    CNetMessage(const CMessageHeader::MessageMagic &pchMessageStartIn, int nTypeIn, int nVersionIn)
        : hdrbuf(nTypeIn, nVersionIn), hdr(pchMessageStartIn), vRecv(nTypeIn, nVersionIn)
    {
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const
    {
        if (!in_data)
        {
            return false;
        }

        return (hdr.nMessageSize == nDataPos);
    }

    const uint256 &GetMessageHash() const;

    void SetVersion(int nVersionIn)
    {
        hdrbuf.SetVersion(nVersionIn);
        vRecv.SetVersion(nVersionIn);
    }

    int readHeader(const char *pch, unsigned int nBytes);
    int readData(const char *pch, unsigned int nBytes);
};

#endif
