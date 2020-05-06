// This file is part of the Eccoin project
// Copyright (c) 2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_NETCONSTANTS_H
#define ECCOIN_NETCONSTANTS_H

#include <cstdint>
#include <string>

/** nServices flags */
enum ServiceFlags : uint64_t
{
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the block chain. It is currently
    // set by all Bitcoin Core nodes, and is unset by SPV clients or other peers that just want
    // network services but don't provide them.
    NODE_NETWORK = (1 << 0),
    // NODE_GETUTXO means the node is capable of responding to the getutxo protocol request.
    // Bitcoin Core does not support this but a patch set called Bitcoin XT does.
    // See BIP 64 for details on how this is implemented.
    NODE_GETUTXO = (1 << 1),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    // Bitcoin Core nodes used to support this by default, without advertising this bit,
    // but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
    NODE_BLOOM = (1 << 2),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

// Default 24-hour ban.
// NOTE: When adjusting this, update rpcnet:setban's help ("24h")
static const unsigned int DEFAULT_MISBEHAVING_BANTIME = 60 * 60 * 24;
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;

/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this
 * delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;

/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static const unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

/** Average delay between feefilter broadcasts in seconds. */
static const unsigned int AVG_FEEFILTER_BROADCAST_INTERVAL = 10 * 60;

/** Default for using fee filter */
static const bool DEFAULT_FEEFILTER = true;

/** Maximum feefilter broadcast delay after significant change. */
static const unsigned int MAX_FEEFILTER_CHANGE_DELAY = 5 * 60;

// SHA256("main address relay")[0:8]
static const uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL;

/** Time between pings automatically sent out for latency probing and keepalive
 * (in seconds). */
static const int PING_INTERVAL = 2 * 60;
/** Time after which to disconnect, after waiting for a ping response (or
 * inactivity). */
static const int TIMEOUT_INTERVAL = 20 * 60;
/** Run the feeler connection loop once every 2 minutes or 120 seconds. **/
static const int FEELER_INTERVAL = 120;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
/** Maximum length of incoming protocol messages (no message over 32 MB is
 * currently acceptable). */
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 32 * 1000 * 1000;
/** Maximum length of strSubVer in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;
/** The maximum number of peer connections to maintain. */
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 125;
/** Maximum number of automatic outgoing nodes */
static const int MAX_OUTBOUND_CONNECTIONS = 75;
/** Maximum number of addnode outgoing nodes */
static const int MAX_ADDNODE_CONNECTIONS = 16;
/** -listen default */
static const bool DEFAULT_LISTEN = true;
/** -upnp default */
#ifdef USE_UPNP
static const bool DEFAULT_UPNP = USE_UPNP;
#else
static const bool DEFAULT_UPNP = false;
#endif
/** The maximum number of entries in mapAskFor */
static const size_t MAPASKFOR_MAX_SZ = MAX_INV_SZ;
/** The maximum number of entries in setAskFor (larger due to getdata latency)*/
static const size_t SETASKFOR_MAX_SZ = 2 * MAX_INV_SZ;
/** The default for -maxuploadtarget. 0 = Unlimited */
static const uint64_t DEFAULT_MAX_UPLOAD_TARGET = 0;
/** The default timeframe for -maxuploadtarget. 1 day. */
static const uint64_t MAX_UPLOAD_TIMEFRAME = 60 * 60 * 24;
/** Default for blocks only*/
static const bool DEFAULT_BLOCKSONLY = false;

// Force DNS seed use ahead of UAHF fork, to ensure peers are found
// as long as seeders are working.
// TODO: Change this back to false after the forked network is stable.
static const bool DEFAULT_FORCEDNSSEED = true;
static const size_t DEFAULT_MAXRECEIVEBUFFER = 5 * 1000;
static const size_t DEFAULT_MAXSENDBUFFER = 1 * 1000;

static const ServiceFlags REQUIRED_SERVICES = ServiceFlags(NODE_NETWORK);

static const std::string strRoutingFile = "routing.dat";

/** The maximum number of new addresses to accumulate before announcing. */
static const unsigned int MAX_ADDR_TO_SEND = 1000;

static const std::string NET_MESSAGE_COMMAND_OTHER = "*other*";

/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Block download timeout base, expressed in millionths of the block interval (i.e. 10 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = 1000000;
/** Additional block download timeout per parallel downloading peer (i.e. 5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;

/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 64;

// SHA256("netgroup")[0:8]
static const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL;
// SHA256("localhostnonce")[0:8]
static const uint64_t RANDOMIZER_ID_LOCALHOSTNONCE = 0xd93e69e2bbfa5735ULL;

/** The maximum number of headers in the mapUnconnectedHeaders cache **/
static const uint32_t MAX_UNCONNECTED_HEADERS = 144;
/** The maximum length of time, in seconds, we keep unconnected headers in the cache **/
static const uint32_t UNCONNECTED_HEADERS_TIMEOUT = 120;

#endif
