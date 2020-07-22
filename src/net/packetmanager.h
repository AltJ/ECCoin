// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NET_PACKETMANAGER_H
#define ECCOIN_NET_PACKETMANAGER_H

#include <map>
#include <utility>
#include <vector>

#include "aodv.h"
#include "datapacket.h"
#include "net.h"
#include "pubkey.h"
#include "util/utiltime.h"
#include "validationinterface.h"

static const int64_t DEFAULT_PACKET_TIMEOUT = 30; // 30 seconds

class PacketBuffer
{
public:
    // vRecievedPackets should be partially stored on disk at some point
    std::vector<CPacket> vRecievedPackets;
    // the protocol id using this buffer
    uint16_t nProtocolId;
    // the token needed for authentication to read vRecievedPackets
    // TODO : use a different token method because this one is very expensive to use often
    CKey boundKey;
    CPubKey boundPubkey;
    // used in the request buffer method for authentication
    uint64_t requestCount;

public:
    PacketBuffer()
    {
        FreeBuffer();
    }

    bool IsUsed()
    {
        return (boundKey.IsValid() == true && boundPubkey.IsValid() == true);
    }

    void FreeBuffer()
    {
        vRecievedPackets.clear();
        nProtocolId = 0;
        boundKey = CKey();
        boundPubkey = CPubKey("");
        requestCount = 0;
    }
};


// TODO : implement a mutex to prevent data races
class CPacketManager
{
    // Data members
private:
    // protocolId : Buffer
    std::vector<PacketBuffer> vBuffers;
    // partial packets waiting for all required data segments to reconstruct
    // map stores nonce, time and when packet is complete it is removed from this
    // map and stored in our messages vector
    std::map<uint64_t, int64_t> mapPacketLastUpdated;

    // a map holding incomplete packets sorted by nonce
    std::map<uint64_t, CPacket> mapPartialPackets;

public:


    // Methods
private:
    // disallow copies
    CPacketManager(const CPacketManager &pman){}
    void FinalizePacket(const uint64_t &nonce, std::map<uint64_t, CPacket>::iterator iter);
    bool BindBuffer(uint16_t protocolId, CKey &_key, CPubKey &_pubkey);

public:
    CPacketManager()
    {
        vBuffers.clear();
        // not memory efficient, but instant access is instant
        vBuffers = std::vector<PacketBuffer>(std::numeric_limits<uint16_t>::max(), PacketBuffer());
        mapPacketLastUpdated.clear();
        mapPartialPackets.clear();
    }

    bool ProcessPacketHeader(const uint64_t &nonce, CPacketHeader &newHeader);

    bool ProcessDataSegment(const uint64_t &nonce, CPacketDataSegment newSegment);

    void CheckForTimeouts();

    bool SendPacket(const std::vector<unsigned char> &vPubKey, const uint8_t &nProtocolId, const uint8_t &nProtocolVersion, const std::vector<uint8_t> vData);

    bool RegisterBuffer(uint8_t &protocolId, std::string &pubkey);

    bool GetBuffer(uint8_t &protocolId, std::vector<CPacket> &bufferData, const std::string &sig);

    bool GetBufferKey(const CPubKey &pubkey, CKey &key);
};

extern CPacketManager g_packetman;

#endif
