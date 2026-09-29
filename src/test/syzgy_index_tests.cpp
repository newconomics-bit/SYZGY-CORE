// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Regression tests guarding the persistence of the SYZGY RandomX (CPU) proof fields
// nRandomXNonce / hashRandomX on CBlockIndex and CDiskBlockIndex (fix b6361c03f).
//
// Before that fix LoadBlockIndexGuts restored nulls for the two RandomX fields while a
// freshly synced node held the real values, so the (not yet written) Sync Controller -- which
// derives miner-class presence from exactly these fields -- would have computed different
// difficulty statistics depending on whether the node had recently restarted. A restarted node
// and a fresh node disagreeing about the chain is a chain split.

#include <test/test_raven.h>

#include <boost/test/unit_test.hpp>

#include "chain.h"
#include "primitives/block.h"
#include "streams.h"
#include "serialize.h"
#include "uint256.h"

#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(syzgy_index_tests, BasicTestingSetup)

namespace {

// Sentinel uint256 built from a fixed, non-zero, high-bit-set pattern so that a silent
// "defaulted to null" round trip cannot accidentally compare equal.
uint256 SentinelHash(uint8_t fill)
{
    uint256 h;
    unsigned char* p = h.begin();
    for (int i = 0; i < 32; ++i) p[i] = (unsigned char)(fill + i);
    return h;
}

// nTime must be at or after the KAWPOW activation time, otherwise CDiskBlockIndex serialises
// the legacy nNonce field instead of nNonce64/mix_hash and the KawPoW half of these tests
// would exercise the wrong branch. Main net activates KAWPOW at 1588788000.
constexpr uint32_t POST_KAWPOW_TIME = 1600000000;

CBlockHeader MakeHeader()
{
    CBlockHeader h;
    h.nVersion       = 0x20000000;
    h.hashPrevBlock  = SentinelHash(0x11);
    h.hashMerkleRoot = SentinelHash(0x22);
    h.nTime          = POST_KAWPOW_TIME;
    h.nBits          = 0x1a02aa55;
    h.nNonce         = 0x0badc0de;
    h.nHeight        = 4242;
    h.nNonce64       = 0xFEDCBA9876543210ULL;
    h.mix_hash       = SentinelHash(0x33);
    h.nRandomXNonce  = 0x0123456789ABCDEFULL;
    h.hashRandomX    = SentinelHash(0x44);
    return h;
}

// Exactly what LoadBlockIndexGuts does: CBlockIndex -> CDiskBlockIndex -> CDataStream -> parse.
CBlockIndex DiskRoundTrip(CBlockIndex& in)
{
    CDiskBlockIndex diskindex(&in);
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << diskindex;
    CDiskBlockIndex read;
    ss >> read;
    return CBlockIndex(read);
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(syzgy_disk_index_roundtrip_preserves_randomx_proof)
{
    const CBlockHeader header = MakeHeader();

    CBlockIndex fresh(header);
    const CBlockIndex reloaded = DiskRoundTrip(fresh);

    BOOST_CHECK_MESSAGE(reloaded.nRandomXNonce == header.nRandomXNonce,
        "CDiskBlockIndex must round-trip nRandomXNonce (got " << reloaded.nRandomXNonce
        << ", expected " << header.nRandomXNonce << ")");
    BOOST_CHECK_MESSAGE(reloaded.hashRandomX == header.hashRandomX,
        "CDiskBlockIndex must round-trip hashRandomX (got " << reloaded.hashRandomX.ToString()
        << ", expected " << header.hashRandomX.ToString() << ")");
    BOOST_CHECK_MESSAGE(reloaded.nNonce64 == header.nNonce64,
        "CDiskBlockIndex must round-trip nNonce64");
    BOOST_CHECK_MESSAGE(reloaded.mix_hash == header.mix_hash,
        "CDiskBlockIndex must round-trip mix_hash");

    // Explicit non-zero / non-null assertions on the DESERIALISED side. Without these, a
    // round trip that silently drops the RandomX fields and leaves the defaults from
    // CBlockIndex::SetNull() in place could pass the comparisons above whenever the source
    // values also happen to be defaults.
    BOOST_CHECK_MESSAGE(reloaded.nRandomXNonce != 0,
        "deserialised nRandomXNonce must be non-zero, it was silently defaulted to null");
    BOOST_CHECK_MESSAGE(!reloaded.hashRandomX.IsNull(),
        "deserialised hashRandomX must be non-null, it was silently defaulted to null");
    // The sentinel is 0x0123456789ABCDEF: bit 63 is clear by construction, so assert on the
    // top and bottom set bits instead -- this proves the full 64 bits survive and that the
    // value was not truncated to 32 bits on the way through the disk encoding.
    BOOST_CHECK_MESSAGE((reloaded.nRandomXNonce & 0x100000001ULL) == 0x100000001ULL,
        "deserialised nRandomXNonce must preserve the full 64 bits of the sentinel value, got "
            << std::hex << reloaded.nRandomXNonce);
    BOOST_CHECK_MESSAGE(!reloaded.mix_hash.IsNull(),
        "deserialised mix_hash must be non-null");
}

BOOST_AUTO_TEST_CASE(syzgy_disk_index_roundtrip_preserves_all_header_proof_fields)
{
    struct Row {
        uint64_t nNonce64;
        uint8_t  mixFill;
        uint64_t nRandomXNonce;
        uint8_t  rxFill;
    };

    // Hardcoded deterministic table -- no wall clock, no unseeded randomness.
    static const Row rows[] = {
        {1ULL,                              0x80, 1ULL,                              0x81},
        {UINT64_MAX,                        0xA1, UINT64_MAX,                        0xA2},
        {0x8000000000000000ULL,             0xB1, 0x8000000000000000ULL,             0xB2},
        {0ULL,                              0xC1, 0ULL,                              0xC2},
        {0x0123456789ABCDEFULL,             0xD1, 0xFEDCBA9876543210ULL,             0xD2},
        {0xDEADBEEFCAFEBABEULL,             0xE1, 0x5555555555555555ULL,             0xE2},
    };

    for (const Row& r : rows) {
        CBlockHeader h = MakeHeader();
        h.nNonce64      = r.nNonce64;
        h.mix_hash      = SentinelHash(r.mixFill);
        h.nRandomXNonce = r.nRandomXNonce;
        h.hashRandomX   = SentinelHash(r.rxFill);

        CBlockIndex src(h);
        const CBlockIndex out = DiskRoundTrip(src);

        BOOST_CHECK_MESSAGE(out.nNonce64 == r.nNonce64,
            "nNonce64 must survive the disk round trip");
        BOOST_CHECK_MESSAGE(out.mix_hash == SentinelHash(r.mixFill),
            "mix_hash must survive the disk round trip");
        BOOST_CHECK_MESSAGE(out.nRandomXNonce == r.nRandomXNonce,
            "nRandomXNonce must survive the disk round trip (value " << r.nRandomXNonce
            << ", got " << out.nRandomXNonce << ")");
        BOOST_CHECK_MESSAGE(out.hashRandomX == SentinelHash(r.rxFill),
            "hashRandomX must survive the disk round trip");
    }
}

BOOST_AUTO_TEST_CASE(syzgy_block_index_ctor_copies_randomx_proof)
{
    const CBlockHeader header = MakeHeader();

    // CBlockIndex(const CBlockHeader&) copies both RandomX fields.
    CBlockIndex idx(header);
    BOOST_CHECK_MESSAGE(idx.nRandomXNonce == header.nRandomXNonce,
        "CBlockIndex ctor must copy nRandomXNonce out of the header");
    BOOST_CHECK_MESSAGE(idx.hashRandomX == header.hashRandomX,
        "CBlockIndex ctor must copy hashRandomX out of the header");

    // GetBlockHeader() writes them back.
    idx.pprev = nullptr;
    const CBlockHeader back = idx.GetBlockHeader();
    BOOST_CHECK_MESSAGE(back.nRandomXNonce == header.nRandomXNonce,
        "GetBlockHeader() must write nRandomXNonce back into the header");
    BOOST_CHECK_MESSAGE(back.hashRandomX == header.hashRandomX,
        "GetBlockHeader() must write hashRandomX back into the header");

    // SetNull() clears the nonce and nulls the hash.
    idx.SetNull();
    BOOST_CHECK_MESSAGE(idx.nRandomXNonce == 0,
        "CBlockIndex::SetNull() must clear nRandomXNonce to 0");
    BOOST_CHECK_MESSAGE(idx.hashRandomX.IsNull(),
        "CBlockIndex::SetNull() must null hashRandomX");
}

BOOST_AUTO_TEST_CASE(syzgy_restart_equivalence_index_state)
{
    // Build a 3-block chain, each header's hashPrevBlock being the previous header's hash.
    std::vector<CBlockHeader> headers;
    CBlockHeader prev;
    for (int i = 0; i < 3; ++i) {
        CBlockHeader h = MakeHeader();
        h.nHeight        = static_cast<uint32_t>(1000 + i);
        h.nTime          = POST_KAWPOW_TIME + static_cast<uint32_t>(i);
        h.nNonce64       = 0x1000000000000000ULL + static_cast<uint64_t>(i);
        h.mix_hash       = SentinelHash(static_cast<uint8_t>(0x50 + i));
        h.nRandomXNonce  = 0x2000000000000000ULL + static_cast<uint64_t>(i);
        h.hashRandomX    = SentinelHash(static_cast<uint8_t>(0x60 + i));
        h.hashPrevBlock  = prev.GetHash();
        headers.push_back(h);
        prev = h;
    }

    for (size_t i = 0; i < headers.size(); ++i) {
        // FRESH: what a node builds when it accepts the block over the network.
        CBlockIndex fresh(headers[i]);
        // RESTARTED: what a node rebuilds after a restart, i.e. the index that went through
        // CDiskBlockIndex and was restored by LoadBlockIndexGuts.
        const CBlockIndex restarted = DiskRoundTrip(fresh);

        BOOST_CHECK_MESSAGE(restarted.nNonce64 == fresh.nNonce64,
            "block " << i << ": restarted index must hold the same nNonce64 as a fresh one");
        BOOST_CHECK_MESSAGE(restarted.mix_hash == fresh.mix_hash,
            "block " << i << ": restarted index must hold the same mix_hash as a fresh one");
        BOOST_CHECK_MESSAGE(restarted.nRandomXNonce == fresh.nRandomXNonce,
            "block " << i << ": restarted index must hold the same nRandomXNonce as a fresh one");
        BOOST_CHECK_MESSAGE(restarted.hashRandomX == fresh.hashRandomX,
            "block " << i << ": restarted index must hold the same hashRandomX as a fresh one");
    }

    // The equalities above are precisely what guarantees identical Sync Controller statistics
    // for a fresh node and a restarted node: the controller groups blocks into miner classes
    // from nNonce64/mix_hash/nRandomXNonce/hashRandomX, so if the restarted index held nulls
    // the same chain would be reported as CPU-mined before a restart and as unknown after it,
    // which is the chain-split-class divergence fixed in b6361c03f.
    //
    // Once the Sync Controller exists, a further test must be added that runs the controller
    // itself over both a fresh and a restarted index and compares its actual output; this
    // test only proves the underlying index data is identical.
}

BOOST_AUTO_TEST_CASE(syzgy_randomx_input_includes_nonce_search_space)
{
    const CBlockHeader base = MakeHeader();

    // Two headers differing ONLY in nRandomXNonce must produce different template images:
    // the CPU miner needs a real grind space.
    CBlockHeader a = base;
    a.nRandomXNonce = base.nRandomXNonce;

    CBlockHeader b = base;
    b.nRandomXNonce = base.nRandomXNonce ^ 0x1ULL;

    CDataStream sa(SER_NETWORK, PROTOCOL_VERSION);
    sa << CRandomXInput{a};
    CDataStream sb(SER_NETWORK, PROTOCOL_VERSION);
    sb << CRandomXInput{b};

    BOOST_CHECK_MESSAGE(sa.size() == sb.size(),
        "two RandomX inputs differing only in nRandomXNonce must have the same length");
    BOOST_CHECK_MESSAGE(std::vector<unsigned char>(sa.begin(), sa.end()) !=
                            std::vector<unsigned char>(sb.begin(), sb.end()),
        "CRandomXInput must include nRandomXNonce, otherwise the CPU side has no search space");

    // Two headers differing ONLY in hashRandomX must produce IDENTICAL images: hashRandomX is
    // the OUTPUT of the RandomX hash, so including it would make the template circular.
    CBlockHeader c = base;
    c.hashRandomX = base.hashRandomX;

    CBlockHeader d = base;
    d.hashRandomX = SentinelHash(0x99);

    CDataStream sc(SER_NETWORK, PROTOCOL_VERSION);
    sc << CRandomXInput{c};
    CDataStream sd(SER_NETWORK, PROTOCOL_VERSION);
    sd << CRandomXInput{d};

    BOOST_CHECK_MESSAGE(std::vector<unsigned char>(sc.begin(), sc.end()) ==
                            std::vector<unsigned char>(sd.begin(), sd.end()),
        "CRandomXInput must exclude hashRandomX, otherwise the hashing template is circular");
}

BOOST_AUTO_TEST_SUITE_END()
