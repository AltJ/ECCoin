// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "packetmanager.h"

////////////////////////
///
///  Private
///
void CPacketManager::FinalizePacket(const uint64_t &nonce, std::map<uint64_t, CPacket>::iterator iter)
{
    uint16_t protocolId = iter->second.nProtocolId;
    if (vBuffers[protocolId].IsUsed() == false)
    {
        // this is an error, the proper entry should have been made by BindBuffer
        return;
    }
    else
    {
        vBuffers[protocolId].vRecievedPackets.push_back(std::move(iter->second));
    }
    mapPacketLastUpdated.erase(nonce);
    mapPartialPackets.erase(nonce);
    GetMainSignals().PacketComplete(protocolId);
}

bool CPacketManager::BindBuffer(uint16_t protocolId, CKey &_key, CPubKey &_pubkey)
{
    if (_key.VerifyPubKey(_pubkey) == false)
    {
        return false;
    }
    if (vBuffers[protocolId].IsUsed())
    {
        return false;
    }
    vBuffers[protocolId].FreeBuffer();
    vBuffers[protocolId].nProtocolId = protocolId;
    vBuffers[protocolId].boundKey = _key;
    vBuffers[protocolId].boundPubkey = _pubkey;
    vBuffers[protocolId].requestCount = 0;
    return true;
}

bool CPacketManager::UnbindBuffer(const uint16_t &protocolId)
{
    if (vBuffers[protocolId].IsUsed() == false)
    {
        return true;
    }
    vBuffers[protocolId].FreeBuffer();
    return true;
}


////////////////////////
///
///  Public
///

bool CPacketManager::ProcessPacketHeader(const uint64_t &nonce, CPacketHeader &newHeader)
{
    if (mapPartialPackets.find(nonce) != mapPartialPackets.end())
    {
        return false;
    }
    if (vBuffers[newHeader.nProtocolId].IsUsed() == false)
    {
        // protocolId needs to be bound by BindBuffer
        return false;
    }
    CPacket newPacket(newHeader);
    mapPartialPackets.emplace(nonce, std::move(newPacket));
    mapPacketLastUpdated.emplace(nonce, GetTime());
    return true;
}

bool CPacketManager::ProcessDataSegment(const uint64_t &nonce, CPacketDataSegment newSegment)
{
    std::map<uint64_t, int64_t>::iterator updateIter;
    std::map<uint64_t, CPacket>::iterator partialIter;
    partialIter = mapPartialPackets.find(nonce);
    updateIter = mapPacketLastUpdated.find(nonce);
    if (partialIter == mapPartialPackets.end() || updateIter == mapPacketLastUpdated.end())
    {
        return false;
    }
    if (!partialIter->second.InsertData(newSegment))
    {
        return false;
    }
    updateIter->second = GetTime();
    if (partialIter->second.IsComplete())
    {
        FinalizePacket(nonce, partialIter);
    }
    return true;
}

void CPacketManager::CheckForTimeouts()
{
    // TODO : implement a thread to check for packet timeouts once a minute,
    // a timeout is any partial packet that hasnt been updated in 30 seconds or more
}

bool CPacketManager::SendPacket(const std::vector<unsigned char> &vPubKey, const uint16_t &nProtocolId, const std::vector<uint8_t> vData)
{
    NodeId peerNode;
    if (!g_aodvtable.GetKeyNode(vPubKey, peerNode))
    {
        return false;
    }
    CPubKey searchKey(vPubKey);
    CPacket newPacket(nProtocolId);
    newPacket.PushBackData(vData);

    uint64_t nonce = 0;
    while (nonce == 0)
    {
        GetStrongRandBytes((uint8_t *)&nonce, sizeof(nonce));
    }
    // segments might not be needed. it is a good way to keep message sizes low to prevent a DOS by sending someone an infinitely
    // large message but might now be necessary
    std::vector<CPacketDataSegment> segments = newPacket.GetSegments();
    {
        g_connman->PushMessageToId(peerNode, NetMsgType::SPH, nonce, searchKey, newPacket.GetHeader());
        for (auto segment : segments)
        {
            g_connman->PushMessageToId(peerNode, NetMsgType::SPD, nonce, searchKey, segment);
        }
    }
    return true;
}

bool CPacketManager::RegisterBuffer(uint16_t &protocolId, std::string &pubkey)
{
    if (vBuffers[protocolId].IsUsed())
    {
        // TODO : return an error object instead of just fales to provide more information
        return false;
    }
    // they new key
    CKey secret;
    secret.MakeNewKey(false);
    CPubKey _pubkey = secret.GetPubKey();
    if (BindBuffer(protocolId, secret, _pubkey))
    {
        pubkey = _pubkey.Raw64Encoded();
    }
    return true;
}

bool CPacketManager::ReleaseBuffer(const uint16_t &protocolId, const std::string &sig)
{
    if (vBuffers[protocolId].IsUsed() == false)
    {
        // the call did nothing, the buffer was not registered. the end state is the same as
        // the intended end state of the user so return true.
        return true;
    }
    PacketBuffer buffer = vBuffers[protocolId];
    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(sig.c_str(), &fInvalid);
    if (fInvalid)
    {
        return false;
    }
    CHashWriter ss(SER_GETHASH, 0);
    std::string requestMessage = "ReleaseBufferRequest";
    ss << requestMessage;
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
    {
        return false;
    }
    if (pubkey.GetID() != buffer.boundPubkey.GetID())
    {
        return false;
    }
    return UnbindBuffer(protocolId);
}

bool CPacketManager::GetBuffer(uint16_t &protocolId, std::vector<CPacket> &bufferData, const std::string &sig)
{
    if (vBuffers[protocolId].IsUsed())
    {
        PacketBuffer buffer = vBuffers[protocolId];
        bool fInvalid = false;
        std::vector<unsigned char> vchSig = DecodeBase64(sig.c_str(), &fInvalid);
        if (fInvalid)
        {
            return false;
        }
        CHashWriter ss(SER_GETHASH, 0);
        std::string requestMessage = "GetBufferRequest:";
        requestMessage += std::to_string(protocolId) + std::to_string(buffer.requestCount + 1);
        ss << requestMessage;
        CPubKey pubkey;
        if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        {
            return false;
        }
        if (pubkey.GetID() != buffer.boundPubkey.GetID())
        {
            return false;
        }
        bufferData = buffer.vRecievedPackets;
        vBuffers[protocolId].vRecievedPackets.clear();
        vBuffers[protocolId].requestCount = vBuffers[protocolId].requestCount + 1;
        return true;
    }
    return false;
}

bool CPacketManager::GetBufferKey(const CPubKey &pubkey, CKey &key)
{
    for (auto& buffer : vBuffers)
    {
        // TODO: do a reverse mapping of pubkeys to used buffers so we dont have to search
        // like this
        if (buffer.boundPubkey.GetID() == pubkey.GetID())
        {
            key = buffer.boundKey;
            return true;
        }
    }
    return false;
}
