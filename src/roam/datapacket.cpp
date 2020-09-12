// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "datapacket.h"

void CPacketHeader::SetNull()
{
    nPacketVersion = PACKET_VERSION;
    nTotalLength = PACKET_HEADER_SIZE;
    nIdenfitication = 0;
    nProtocolId = 0;
    nDataChecksum.SetNull();
}

void CPacketHeader::CalculateTotalLength(uint64_t datasize) { nTotalLength = PACKET_HEADER_SIZE + datasize; }
void CPacketHeader::GenerateNewIdentifier()
{
    uint64_t seed = GetTime();
    std::mt19937_64 rand(seed); // Standard mersenne_twister_engine seeded with rd()
    nIdenfitication = rand() % std::numeric_limits<uint16_t>::max();
}

bool CPacketDataSegment::AddData(const std::vector<uint8_t> &vDataIn)
{
    if ((vData.size() + vDataIn.size()) > MAX_DATA_SEGMENT_SIZE)
    {
        return false;
    }
    vData.insert(vData.end(), vDataIn.begin(), vDataIn.end());
    return true;
}

std::vector<uint8_t> CPacketDataSegment::GetData() { return vData; }
void CPacket::PushBackData(const std::vector<uint8_t> &data)
{
    vData.insert(vData.end(), data.begin(), data.end());
    CalculateTotalLength(vData.size());
}

bool CPacket::InsertData(CPacketDataSegment &newSegment)
{
    // TODO : check if there is already data in the specified range, if there is return false, if there
    // is not then move the data segment data into that slot and return true
    std::vector<uint8_t> packetData = newSegment.GetData();
    PushBackData(packetData);
    return true;
}

void CPacket::ClearData()
{
    vData.clear();
    this->CalculateTotalLength(0);
}

std::vector<uint8_t> CPacket::GetData() { return vData; }
bool CPacket::IsComplete() { return ((vData.size() + PACKET_HEADER_SIZE) == this->nTotalLength); }
CPacketHeader CPacket::GetHeader()
{
    CPacketHeader header;
    header.nPacketVersion = this->nPacketVersion;
    header.nProtocolId = this->nProtocolId;
    header.nTotalLength = this->nTotalLength;
    header.nIdenfitication = this->nIdenfitication;
    header.nDataChecksum = this->nDataChecksum;
    return header;
}

std::vector<CPacketDataSegment> CPacket::GetSegments()
{
    std::vector<CPacketDataSegment> segments;
    if (vData.size() < MAX_DATA_SEGMENT_SIZE)
    {
        CPacketDataSegment newSegment;
        newSegment.AddData(vData);
        segments.push_back(newSegment);
    }
    else
    {
    }
    return segments;
}
