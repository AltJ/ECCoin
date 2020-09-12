// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ROAM_DATAPACKET_H
#define ROAM_DATAPACKET_H

#include "serialize.h"
#include "uint256.h"
#include "util/utiltime.h"

#include <inttypes.h>
#include <random>
#include <vector>

const uint64_t PACKET_HEADER_SIZE = 45; // 45 bytes
const uint64_t MEGABYTE = 1000000;
const uint64_t MAX_DATA_SEGMENT_SIZE = 10 * MEGABYTE;
const uint8_t PACKET_VERSION = 1;

class CPacketHeader
{
public:
    uint8_t nPacketVersion; // versioning of the CPacketHeader and related classes
    uint16_t nProtocolId; // protocolId, should match the protocolid in mapBuffers
    uint64_t nTotalLength; // header + data in bytes (does not include extra vector serialization bytes)
    uint16_t nIdenfitication; // randomly generated
    uint256 nDataChecksum; // sha256 checksum

    CPacketHeader() { SetNull(); }
    CPacketHeader(uint16_t nProtocolIdIn)
    {
        nProtocolId = nProtocolIdIn;
        GenerateNewIdentifier();
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nPacketVersion);
        READWRITE(nProtocolId);
        READWRITE(nTotalLength);
        READWRITE(nIdenfitication);
        READWRITE(nDataChecksum);
    }

    void SetNull();
    void CalculateTotalLength(uint64_t datasize);
    void GenerateNewIdentifier();
};


// used to send on the network only. these are created and destroyed sending/reading the data,
// we store their data in the packet but dont store the data segment class anywhere
class CPacketDataSegment
{
    // Data members
private:
    uint8_t nFlags;
    uint32_t nFragmentOffset;
    std::vector<uint8_t> vData;

public:
    // Methods
private:
public:
    CPacketDataSegment()
    {
        nFlags = 0;
        nFragmentOffset = 0;
        vData.clear();
    }
    CPacketDataSegment(uint8_t nFlagsIn, uint32_t nFragmentOffsetIn)
    {
        nFlags = nFlagsIn;
        nFragmentOffset = nFragmentOffsetIn;
        vData.clear();
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nFlags);
        READWRITE(nFragmentOffset);
        READWRITE(vData);
    }

    bool AddData(const std::vector<uint8_t> &vDataIn);
    std::vector<uint8_t> GetData();
};

// CPacket class is never used over the network

class CPacket : public CPacketHeader
{
    /// Data members
private:
    std::vector<uint8_t> vData;

public:
    /// Methods
private:
    CPacket() : CPacketHeader() {}
    void ClearAndSetSize()
    {
        vData.clear();
        vData = std::vector<uint8_t>(0, 0);
    }


public:
    CPacket(const CPacketHeader &header) : CPacketHeader(header)
    {
        SetNull();
        *((CPacketHeader *)this) = header;
        ClearAndSetSize();
    }

    CPacket(uint16_t nProtocolIdIn) : CPacketHeader(nProtocolIdIn) { vData.clear(); }
    void PushBackData(const std::vector<uint8_t> &data);
    bool InsertData(CPacketDataSegment &newSegment);
    void ClearData();
    std::vector<uint8_t> GetData();
    bool IsComplete();
    CPacketHeader GetHeader();
    std::vector<CPacketDataSegment> GetSegments();
};

#endif
