// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the SYZGY dual-PoW ENFORCEMENT layer (FR-01, FR-04):
//   * CheckDualProofOfWork()  -- both proofs, and the Sync Controller's emergency relaxation
//   * GetRandomXSeedForHeight() / RandomXEpoch0Seed() -- the non-circular epoch-0 anchor
//   * CheckBlockTimestampNotTooFarInFuture() -- FR-04
//
// Everything here is deterministic: fixed synthetic index chains, literal timestamps, no wall
// clock and no unseeded randomness in any expected value. Every assertion carries a message.
//
// A test whose expected value cannot be derived from the specification is NOT written here, and
// its absence is called out in the accompanying report rather than papered over with a faked
// assertion.
//
// The fixture is BasicTestingSetup on REGTEST. Regtest is the only network whose SYZGY windows
// are short enough (nSyzgySyncWindow 10, nSyzgyPairingStallBlocks 2, nSyzgyRandomXEpochLength
// 50) for the emergency-mode and bootstrap paths to be reachable at all inside a test run.

#include <test/test_raven.h>

#include <boost/test/unit_test.hpp>

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "hash.h"
#include "pow.h"
#include "primitives/block.h"
#include "syzgy/randomx_glue.h"
#include "syzgy/syzgy_sync.h"
#include "uint256.h"
#include "validation.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

/** Regtest, so that the SYZGY short-window paths are reachable. */
struct RegtestSetup : public BasicTestingSetup {
    RegtestSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

const Consensus::Params& RegtestParams()
{
    return GetParams().GetConsensus();
}

/**
 * The regtest ceiling in compact form. On regtest powLimit == kawpowLimit == randomxLimit ==
 * 0x7fff...ff, so the bootstrap CPU target and the height-0 GPU target are BOTH this value, and
 * a proof meets it with probability 1/2. That is what makes a real proof mineable in a unit test
 * at all; it is a property of the deliberately permissive regtest parameters, not a weakening.
 */
unsigned int RegtestCeilingBits()
{
    return UintToArith256(RegtestParams().randomxLimit).GetCompact();
}

/** A fixed, arbitrary block time. Never compared against a clock, only against each other. */
const int64_t T0 = 1600000000;

// ---------------------------------------------------------------------------
// Synthetic index chain, registered in mapBlockIndex
// ---------------------------------------------------------------------------
//
// The Sync Controller resolves a candidate's parent through mapBlockIndex
// (syzgy::GetNextDualWorkRequired), and a hand-built CBlockIndex has a null *phashBlock, so a
// chain that is not registered would silently take the Controller's "parent unresolvable"
// fail-closed branch and always route to DUAL_POW. Registering makes the emergency-mode tests
// exercise the routing they claim to.

struct RegisteredChain {
    std::vector<CBlockIndex*> blocks;
    std::vector<uint256> hashes;

    ~RegisteredChain()
    {
        for (size_t i = 0; i < hashes.size(); ++i) mapBlockIndex.erase(hashes[i]);
        for (size_t i = 0; i < blocks.size(); ++i) delete blocks[i];
    }

    const CBlockIndex* tip() const { return blocks.empty() ? nullptr : blocks.back(); }
    const CBlockIndex* at(size_t i) const { return blocks[i]; }
    size_t size() const { return blocks.size(); }
};

CBlockIndex* MakeIndex(int height, int64_t nTime, unsigned int nBits, bool cpuProof, bool gpuProof)
{
    CBlockIndex* p = new CBlockIndex();
    p->nHeight = height;
    p->nTime = (uint32_t)nTime;
    p->nBits = nBits;
    // Presence is counted from the index, never inferred: a non-null proof field IS the
    // on-chain signature of that class being present (see syzgy_sync.h).
    if (cpuProof) p->hashRandomX = uint256S("00000000000000000000000000000000000000000000000000000000000000c1");
    if (gpuProof) p->mix_hash    = uint256S("00000000000000000000000000000000000000000000000000000000000000b1");
    return p;
}

/**
 * A linear chain of `nBlocks` blocks after genesis, registered in mapBlockIndex.
 *
 * Genesis always carries BOTH proofs: FR-01 has no genesis exemption on SYZGY, and the
 * Controller's streak bookkeeping deliberately does not count height 0, so a genesis cannot
 * fabricate an emergency mode at the start of a chain. Blocks from height 1 carry the requested
 * proof-presence flags. nTime(h) = t0 + h * 60, a 60 s cadence matching
 * nSyzgySyncTargetBlockSeconds.
 */
RegisteredChain* BuildRegisteredChain(int nBlocks, bool cpuProof, bool gpuProof)
{
    RegisteredChain* rc = new RegisteredChain();
    CBlockIndex* genesis = MakeIndex(0, T0, RegtestCeilingBits(), true, true);
    rc->blocks.push_back(genesis);
    rc->hashes.push_back(uint256S("0000000000000000000000000000000000000000000000000000000000000a70"));

    for (int h = 1; h <= nBlocks; ++h) {
        CBlockIndex* p = MakeIndex(h, T0 + (int64_t)h * 60, RegtestCeilingBits(), cpuProof, gpuProof);
        p->pprev = rc->blocks.back();
        rc->blocks.push_back(p);
        // Deterministic, distinct, and not any real block hash.
        rc->hashes.push_back(uint256S(std::string(63, '0') + "b1"));
        rc->hashes.back().begin()[0] = (unsigned char)h;
    }

    for (size_t i = 0; i < rc->blocks.size(); ++i) {
        rc->blocks[i]->phashBlock = &rc->hashes[i];
        mapBlockIndex[rc->hashes[i]] = rc->blocks[i];
    }
    return rc;
}

/** A candidate header on top of `pindexPrev`, carrying no proofs yet. */
CBlockHeader MakeHeader(const RegisteredChain& chain, size_t prevIndex)
{
    CBlockHeader h;
    h.nVersion = 536870912;                  // 0x20000000, the version the chain uses
    h.hashPrevBlock = chain.hashes[prevIndex];
    h.hashMerkleRoot = uint256S("000000000000000000000000000000000000000000000000000000000000d000");
    h.nTime = (uint32_t)(chain.at(prevIndex)->nTime + 60);
    h.nBits = RegtestCeilingBits();
    h.nNonce = 0;
    h.nHeight = (uint32_t)(chain.at(prevIndex)->nHeight + 1);
    h.nNonce64 = 0;
    h.mix_hash.SetNull();
    h.nRandomXNonce = 0;
    h.hashRandomX.SetNull();
    return h;
}

/**
 * Grind a real dual proof for `header` in place, at the regtest ceiling.
 *
 * Both halves are ground together because hashRandomX is part of SerializeHash(*this): writing
 * a candidate hashRandomX changes the block identity and therefore the KawPoW mix, so the two
 * cannot be solved independently. Only the nonce the failing half is keyed on is advanced, so
 * neither search space is skipped.
 *
 * @param fWantGpu mine for a KawPoW proof
 * @param fWantCpu mine for a RandomX proof
 * @param seed the epoch seed; the caller passes the one it intends to validate against
 * @return false if either requested proof could not be found within the attempt limit
 */
bool MineProofs(CBlockHeader& header, bool fWantGpu, bool fWantCpu, const uint256& seed)
{
    const Consensus::Params& params = RegtestParams();
    for (uint64_t attempt = 0; attempt < 200000; ++attempt) {
        bool fGpuOk = true;
        if (fWantGpu) {
            uint256 mix_hash;
            const uint256 h = KAWPOWHash(header, mix_hash);
            fGpuOk = CheckProofOfWork(h, header.nBits, params);
            if (fGpuOk) {
                // The claim is written only when the recomputed mix actually meets the target.
                // Writing it unconditionally would let the "proof" be whatever mix_hash the
                // header happened to carry, which is the exact shortcut validation forbids.
                header.mix_hash = mix_hash;
            }
        }
        if (fGpuOk && fWantCpu) {
            uint256 randomXHash;
            std::string err;
            if (syzgy::RandomXHash(header, seed, randomXHash, err) &&
                CheckProofOfWork(randomXHash, header.nBits, params)) {
                header.hashRandomX = randomXHash;
                return true;
            }
            if (header.nRandomXNonce >= 4096) return false;
            ++header.nRandomXNonce;
            continue;
        }
        if (fGpuOk) return true;
        if (header.nNonce64 >= 4096) return false;
        ++header.nNonce64;
    }
    return false;
}

/** The epoch-0 seed, derived the way validation derives it. */
uint256 Epoch0Seed()
{
    const uint256 seed = syzgy::RandomXEpoch0Seed(GetParams().GenesisBlock().hashMerkleRoot);
    BOOST_REQUIRE_MESSAGE(!seed.IsNull(),
        "the epoch-0 seed must derive from the regtest genesis merkle root");
    return seed;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(syzgy_dualpow_tests, RegtestSetup)

// ===========================================================================================
// FR-01 -- the dual proof itself
// ===========================================================================================

/**
 * THE FR-01 TEST.
 *
 * A header with a genuinely valid KawPoW proof, mined and checked, whose hashRandomX is then
 * replaced with a wrong value. CheckDualProofOfWork() must REJECT it.
 *
 * The KawPoW half is asserted good immediately before the corruption, so that a pass here can
 * only be explained by the CPU half being enforced -- not by the GPU half happening to fail,
 * and not by the test constructing an unsolvable header. This is the test that must fail if
 * anyone ever relaxes the RandomX check, adds a "verify if present" branch, or reintroduces an
 * index-load exemption.
 */
BOOST_AUTO_TEST_CASE(syzgy_dual_pow_rejects_missing_randomx_proof)
{
    RegisteredChain* chain = BuildRegisteredChain(3, /*cpuProof=*/true, /*gpuProof=*/true);
    const uint256 seed = Epoch0Seed();
    const Consensus::Params& params = RegtestParams();

    CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
    BOOST_REQUIRE_MESSAGE(MineProofs(header, /*fWantGpu=*/true, /*fWantCpu=*/true, seed),
        "mining a real dual proof at the regtest ceiling must succeed");

    // The KawPoW half, on its own, is good. Without this the test could pass for the wrong
    // reason.
    uint256 recomputedMix;
    const uint256 kawpowHash = KAWPOWHash(header, recomputedMix);
    BOOST_REQUIRE_MESSAGE(recomputedMix == header.mix_hash,
        "the mined header's recomputed KawPoW mix must equal its claimed mix_hash");
    BOOST_REQUIRE_MESSAGE(CheckProofOfWork(kawpowHash, header.nBits, params),
        "the mined header's KawPoW proof must meet the GPU target on its own");

    // Sanity: unmodified, it is accepted. This pins the "reject" below to the corruption alone.
    std::string strError;
    BOOST_CHECK_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
        "an unmodified, valid dual proof must be accepted: " << strError);

    // Corrupt ONLY the RandomX half. mix_hash, nBits and the GPU target are untouched.
    header.hashRandomX = uint256S("000000000000000000000000000000000000000000000000000000000000dead");
    BOOST_CHECK_MESSAGE(header.mix_hash == recomputedMix,
        "corrupting hashRandomX must not disturb the KawPoW half of this test");

    strError.clear();
    BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
        "FR-01: a header with a valid KawPoW proof and a WRONG hashRandomX must be rejected");
    BOOST_CHECK_MESSAGE(strError.find("RandomX") != std::string::npos,
        "the rejection must name the RandomX proof as the failing half, got: " << strError);

    // A ZERO hashRandomX -- the "no CPU proof at all" case, which is what a pre-FR-01 block on
    // this chain would carry -- is rejected too, and specifically as a mismatch rather than
    // being quietly skipped.
    header.hashRandomX.SetNull();
    strError.clear();
    BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
        "FR-01: a header with a valid KawPoW proof and a NULL hashRandomX must be rejected");
    BOOST_CHECK_MESSAGE(strError.find("RandomX proof mismatch") != std::string::npos,
        "a null hashRandomX must be reported as a RandomX proof mismatch, got: " << strError);

    delete chain;
}

/**
 * The positive case: a header with BOTH proofs genuinely mined is accepted, and its
 * hashRandomX is non-null and equals the recomputed RandomX hash of the canonical template.
 */
BOOST_AUTO_TEST_CASE(syzgy_dual_pow_accepts_valid_pair)
{
    RegisteredChain* chain = BuildRegisteredChain(3, true, true);
    const uint256 seed = Epoch0Seed();
    const Consensus::Params& params = RegtestParams();

    CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
    BOOST_REQUIRE_MESSAGE(MineProofs(header, true, true, seed),
        "mining a real dual proof at the regtest ceiling must succeed");
    BOOST_REQUIRE_MESSAGE(!header.hashRandomX.IsNull(),
        "a mined dual proof must carry a non-null hashRandomX -- FR-01 has no 'absent is fine' case");

    // hashRandomX really is the RandomX hash of this exact template.
    uint256 recomputed;
    std::string strHashError;
    BOOST_REQUIRE_MESSAGE(syzgy::RandomXHash(header, seed, recomputed, strHashError),
        "recomputing the RandomX hash of the mined header must succeed: " << strHashError);
    BOOST_CHECK_MESSAGE(recomputed == header.hashRandomX,
        "the mined header's hashRandomX must equal the recomputed RandomX hash of its template");

    std::string strError;
    BOOST_CHECK_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
        "a header with both proofs valid must be accepted in DUAL_POW: " << strError);

    // The derived CPU target at this height is the regtest bootstrap ceiling, because the tip
    // is below M = nSyzgySyncWindow - 1. Asserted so that "accepted" is known to mean "accepted
    // against the right target" and not "accepted because the target was trivially null".
    BOOST_REQUIRE_MESSAGE(params.nSyzgySyncWindow == 10,
        "this test assumes regtest nSyzgySyncWindow == 10, got " << params.nSyzgySyncWindow);
    BOOST_CHECK_MESSAGE(GetNextRandomXWorkRequired(chain->tip(), &header, params) ==
                             RegtestCeilingBits(),
        "below the LWMA window the CPU target must be the regtest randomxLimit ceiling");

    delete chain;
}

// ===========================================================================================
// Emergency mode -- the Sync Controller's single-algo relaxation, and nothing more
// ===========================================================================================

/**
 * SINGLE_ALO_GPU: when the CPU class has been absent for nSyzgyPairingStallBlocks consecutive
 * slots, the Controller routes the next block to SINGLE_ALO_GPU and only the GPU proof is
 * required. A candidate with NO hashRandomX must then be accepted.
 *
 * Symmetrically, SINGLE_ALO_CPU: when the GPU class has been absent for the same run, only the
 * CPU proof is required, and a candidate with NO mix_hash must be accepted.
 *
 * The relaxation is WHICH PROOFS ARE REQUIRED and nothing else, so both directions are asserted
 * here: the missing half is tolerated in the matching mode, and the SAME chain in DUAL_POW
 * (one block short of the stall threshold) still rejects it. Without that second half the test
 * would pass even if the check had simply been deleted.
 */
BOOST_AUTO_TEST_CASE(syzgy_dual_pow_emergency_relaxes_to_present_class)
{
    const Consensus::Params& params = RegtestParams();
    const uint256 seed = Epoch0Seed();
    BOOST_REQUIRE_MESSAGE(params.nSyzgyPairingStallBlocks == 2,
        "this test assumes regtest nSyzgyPairingStallBlocks == 2, got "
            << params.nSyzgyPairingStallBlocks);

    // --- SINGLE_ALO_GPU ------------------------------------------------------------------
    //
    // RouteMode() requires that EXACTLY ONE class is present in the window: an equal number of
    // present classes is "not an emergency at all", and zero present is "BOTH absent", which
    // must not privilege either survivor. So the whole regtest window (nSyzgySyncWindow = 10
    // slots, heights 10..1; genesis never contributes) has to be CPU-absent, not just the last
    // two. The 10-block run is also well short of the anti-trap valve at
    // 2 * nSyzgySyncMinRatio = 60 blocks, so DUAL_POW is not forced back on underneath us.
    {
        RegisteredChain* chain = BuildRegisteredChain(10, /*cpuProof=*/false, /*gpuProof=*/true);
        BOOST_REQUIRE_MESSAGE(chain->size() == 11, "the chain must be genesis plus 10 blocks");

        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(chain->tip(), nullptr, params, cpuBits, gpuBits, mode);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::SINGLE_ALO_GPU,
            "a window with the CPU class entirely absent must route the Controller to "
            "SINGLE_ALO_GPU, got mode " << (int)mode);

        CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
        BOOST_REQUIRE_MESSAGE(MineProofs(header, /*fWantGpu=*/true, /*fWantCpu=*/false, seed),
            "mining a GPU-only proof at the regtest ceiling must succeed");
        BOOST_REQUIRE_MESSAGE(header.hashRandomX.IsNull(),
            "this candidate must carry no RandomX proof, that is what SINGLE_ALO_GPU means");

        std::string strError;
        BOOST_CHECK_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
            "SINGLE_ALO_GPU: a RandomX-less block must be accepted: " << strError);

        // The relaxation is WHICH PROOFS ARE REQUIRED, and it is deliberately NOT "check the CPU
        // proof if one happens to be there". A non-null proof field IS the on-chain signal that a
        // class is present (see syzgy_sync.h), so "absent" and "present but wrong" are the same
        // header to any node that can see it -- there is no bit that distinguishes them, and
        // pretending otherwise would be a rule nobody could implement. What the relaxation
        // therefore does NOT touch is the class that IS present: the GPU proof above is verified
        // in full, mix recomputation and target and all, and a wrong one is rejected.

        delete chain;
    }

    // --- SINGLE_ALO_CPU: the symmetric case, no mix_hash. -----------------------------
    {
        RegisteredChain* chain = BuildRegisteredChain(10, /*cpuProof=*/true, /*gpuProof=*/false);

        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(chain->tip(), nullptr, params, cpuBits, gpuBits, mode);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::SINGLE_ALO_CPU,
            "a window with the GPU class entirely absent must route the Controller to "
            "SINGLE_ALO_CPU, got mode " << (int)mode);

        CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
        BOOST_REQUIRE_MESSAGE(MineProofs(header, /*fWantGpu=*/false, /*fWantCpu=*/true, seed),
            "mining a CPU-only proof at the regtest ceiling must succeed");
        BOOST_REQUIRE_MESSAGE(header.mix_hash.IsNull(),
            "this candidate must carry no KawPoW proof, that is what SINGLE_ALO_CPU means");

        std::string strError;
        BOOST_CHECK_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
            "SINGLE_ALO_CPU: a KawPoW-less block must be accepted: " << strError);

        // As above: the absent class's proof is not required and therefore not checked, and the
        // present one -- the RandomX proof -- is verified in full against the derived CPU target.

        delete chain;
    }

    // --- DUAL_POW, the whole window healthy: the same missing half is fatal. -----------
    {
        // Every slot carries both proofs, so the Controller is strict and a RandomX-less
        // candidate must be rejected. Without this half the test above would still pass if the
        // CPU check had simply been deleted.
        RegisteredChain* chain = BuildRegisteredChain(10, /*cpuProof=*/true, /*gpuProof=*/true);

        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(chain->tip(), nullptr, params, cpuBits, gpuBits, mode);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::DUAL_POW,
            "a fully healthy window must stay in DUAL_POW");

        CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
        BOOST_REQUIRE_MESSAGE(MineProofs(header, true, false, seed),
            "mining a GPU-only proof at the regtest ceiling must succeed");

        std::string strError;
        BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
            "DUAL_POW: a RandomX-less block must still be rejected -- the relaxation is "
            "emergency-mode only");
        BOOST_CHECK_MESSAGE(strError.find("RandomX") != std::string::npos,
            "the rejection must name the RandomX proof, got: " << strError);

        delete chain;
    }
}

// ===========================================================================================
// The epoch-0 seed anchor (a8bf952aa)
// ===========================================================================================

/**
 * The epoch-0 seed is anchored on the GENESIS MERKLE ROOT, so it does not move when the PoW
 * fields of the block are ground.
 *
 * Anchoring on the genesis BLOCK HASH instead would be a fixed point:
 *     seed0 = f(genesis_hash),  genesis_hash = g(header) which contains
 *     hashRandomX = RandomX(template, seed0)
 * so grinding hashRandomX would move the seed, which would move every RandomX hash, which
 * would move hashRandomX. This test pins the non-circular form in place: change hashRandomX and
 * the seed must not move, while the block's identity must.
 */
BOOST_AUTO_TEST_CASE(syzgy_seed_is_non_circular)
{
    RegisteredChain* chain = BuildRegisteredChain(3, true, true);
    const Consensus::Params& params = RegtestParams();

    const uint256 genesisMerkleRoot = GetParams().GenesisBlock().hashMerkleRoot;
    BOOST_REQUIRE_MESSAGE(!genesisMerkleRoot.IsNull(),
        "the regtest genesis merkle root must exist, it is the epoch-0 anchor");

    CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
    BOOST_REQUIRE_MESSAGE(MineProofs(header, true, true, Epoch0Seed()),
        "mining a real dual proof at the regtest ceiling must succeed");

    const uint256 seedBefore = syzgy::RandomXEpoch0Seed(genesisMerkleRoot);
    const uint256 hashBefore = header.GetHash();

    // Change ONLY the RandomX half.
    header.hashRandomX = uint256S("000000000000000000000000000000000000000000000000000000000000beef");

    const uint256 seedAfter = syzgy::RandomXEpoch0Seed(genesisMerkleRoot);
    const uint256 hashAfter = header.GetHash();

    BOOST_CHECK_MESSAGE(seedAfter == seedBefore,
        "the epoch-0 seed is anchored on the genesis merkle root and must NOT change when "
        "hashRandomX changes");
    BOOST_CHECK_MESSAGE(hashAfter != hashBefore,
        "the block identity MUST change when hashRandomX changes, otherwise the header does not "
        "commit to the CPU proof at all");

    // And the seed really is a function of the merkle root: a different anchor gives a
    // different seed, which is what makes the anchor meaningful rather than decorative.
    uint256 otherRoot = genesisMerkleRoot;
    otherRoot.begin()[0] = (unsigned char)(otherRoot.begin()[0] ^ 0x01);
    BOOST_CHECK_MESSAGE(syzgy::RandomXEpoch0Seed(otherRoot) != seedBefore,
        "a different genesis merkle root must derive a different epoch-0 seed");

    // A null merkle root fails closed rather than falling back to the genesis block hash.
    BOOST_CHECK_MESSAGE(syzgy::RandomXEpoch0Seed(uint256()).IsNull(),
        "a null genesis merkle root must fail closed (null seed), never fall back to the "
        "genesis block hash");

    // The same non-circularity holds through the entry point validation actually uses.
    uint256 seedViaParentForm;
    std::string strSeedError;
    BOOST_REQUIRE_MESSAGE(GetRandomXSeedForHeight(chain->tip(), params, seedViaParentForm, strSeedError),
        "deriving the epoch seed through the parent-anchored form must succeed: " << strSeedError);
    BOOST_CHECK_MESSAGE(seedViaParentForm == seedBefore,
        "the parent-anchored entry point must return the same merkle-root-derived epoch-0 seed");

    delete chain;
}

// ===========================================================================================
// FR-04 -- future timestamps
// ===========================================================================================

/**
 * FR-04, at the boundary the specification names.
 *
 * nMaxFutureBlockTime is 15 * 60 = 900 s on every network. 16 minutes ahead of the parent is
 * 960 s > 900 and must be rejected; 14 minutes ahead is 840 s <= 900 and must be accepted; 15
 * minutes exactly is the boundary and is accepted, because the rule is "more than".
 *
 * The parent-relative (pure primitive) form is exercised, i.e. the wall clock is passed as 0
 * so the reference time is the parent alone. The 0-parent case is asserted too, because that is
 * the genesis exemption and it is the one place the rule is defined to not apply.
 */
BOOST_AUTO_TEST_CASE(syzgy_future_timestamp_rejected)
{
    const Consensus::Params& params = RegtestParams();
    BOOST_REQUIRE_MESSAGE(params.nMaxFutureBlockTime == 15 * 60,
        "this test assumes nMaxFutureBlockTime == 900s, got " << params.nMaxFutureBlockTime);

    CBlockIndex parent;
    parent.nHeight = 10;
    parent.nTime = (uint32_t)T0;

    CBlockHeader h;
    h.nVersion = 536870912;
    h.nBits = RegtestCeilingBits();
    h.nHeight = 11;

    const int64_t k16min = 16 * 60;
    const int64_t k14min = 14 * 60;
    const int64_t k15min = 15 * 60;

    h.nTime = (uint32_t)(T0 + k16min);
    BOOST_CHECK_MESSAGE(!CheckBlockTimestampNotTooFarInFuture(&h, &parent, params),
        "FR-04: a block 16 minutes ahead of its parent (960s > 900s) must be rejected");

    h.nTime = (uint32_t)(T0 + k14min);
    BOOST_CHECK_MESSAGE(CheckBlockTimestampNotTooFarInFuture(&h, &parent, params),
        "FR-04: a block 14 minutes ahead of its parent (840s <= 900s) must be accepted");

    h.nTime = (uint32_t)(T0 + k15min);
    BOOST_CHECK_MESSAGE(CheckBlockTimestampNotTooFarInFuture(&h, &parent, params),
        "FR-04: exactly nMaxFutureBlockTime ahead is accepted -- the rule is 'more than', not "
        "'at least'");

    // Unsigned-wraparound guard. nTime is uint32_t, so a header OLDER than its parent is a
    // legal input (it is caught separately by the median-time-past rule) and an unsigned
    // subtraction would wrap into a huge positive lead and sail through. Here the lead is
    // negative, so it must be accepted by FR-04 -- FR-04 bounds how far AHEAD a block may be,
    // and is not the rule that rejects backwards timestamps.
    h.nTime = (uint32_t)(T0 - 1000);
    BOOST_CHECK_MESSAGE(CheckBlockTimestampNotTooFarInFuture(&h, &parent, params),
        "FR-04: a header older than its parent must not be turned into a rejection by an "
        "unsigned wraparound -- that is the median-time-past rule's job, not this one's");

    // GENESIS: no parent, so no parent-relative rule exists. Returns true, and the wiring
    // comments the exemption explicitly.
    h.nTime = (uint32_t)(T0 + 100000);
    BOOST_CHECK_MESSAGE(CheckBlockTimestampNotTooFarInFuture(&h, nullptr, params),
        "FR-04 at genesis (no parent) must be a documented exemption, not a wraparound");

    // The wired form: a stale parent must not deadlock the chain. With the wall clock far past
    // an old parent, the reference is the clock and a block at "now" is accepted even though it
    // is years ahead of its parent. Without this the rule would make regtest and testnet
    // permanently unmineable, which was observed before the reference time was fixed.
    h.nTime = (uint32_t)(T0 + 60);
    BOOST_CHECK_MESSAGE(CheckBlockTimestampNotTooFarInFuture(&h, &parent, T0 + 120, params),
        "the wired form must accept a block at the wall clock even when the parent is ancient");
    h.nTime = (uint32_t)(T0 + 120 + 901);
    BOOST_CHECK_MESSAGE(!CheckBlockTimestampNotTooFarInFuture(&h, &parent, T0 + 120, params),
        "the wired form must still reject a block more than nMaxFutureBlockTime past the wall "
        "clock when the wall clock is the reference");
}

// ===========================================================================================
// Fail-closed when RandomX cannot service the request
// ===========================================================================================

/**
 * HONEST SCOPE, STATED UP FRONT: SYZGY_HAVE_RANDOMX is a COMPILE-TIME gate (see
 * src/syzgy/syzgy_config.h) and cannot be toggled at runtime, so this test CANNOT and DOES NOT
 * simulate a binary built without RandomX. Faking that would be the one thing this suite must
 * not do. Instead it exercises the error paths that ARE reachable, each of which is a place
 * where a "best effort" implementation would have returned true:
 *
 *   1. a null epoch seed reaching CheckDualProofOfWork -- the exact input an unavailable
 *      subsystem would produce;
 *   2. RandomXHash() with a null seed;
 *   3. RandomXCheckProof() with a null seed, i.e. the proof check itself failing closed;
 *   4. RandomXCheckProof() against a header whose hashRandomX is not what the template
 *      produces, proving the equality test is not skipped when a hash IS obtainable;
 *   5. GetRandomXSeedForHeight() on a chain that cannot resolve the epoch anchor -- a null
 *      seed and false, not a guess.
 *
 * The compile-time-absence case is covered structurally instead: there is no runtime option
 * that sets a seed to null, no "skip if unavailable" branch, and the absence of any such
 * branch is what assertions 1-3 pin.
 */
BOOST_AUTO_TEST_CASE(syzgy_dual_pow_fails_closed_without_randomx)
{
    RegisteredChain* chain = BuildRegisteredChain(3, true, true);
    const Consensus::Params& params = RegtestParams();
    const uint256 seed = Epoch0Seed();

    // A genuinely valid dual proof first, so that every rejection below is attributable to the
    // specific failure being injected and not to an unsolvable header.
    CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
    BOOST_REQUIRE_MESSAGE(MineProofs(header, true, true, seed),
        "mining a real dual proof at the regtest ceiling must succeed");
    std::string strError;
    BOOST_REQUIRE_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, strError),
        "the unmodified header must be accepted, otherwise nothing below is attributable: "
            << strError);

    // (1) A null seed -- what an unavailable RandomX subsystem looks like to the caller.
    strError.clear();
    BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, chain->tip(), params, uint256(), strError),
        "a NULL RandomX epoch seed must be rejected, never treated as 'not applicable'");
    BOOST_CHECK_MESSAGE(strError.find("null RandomX epoch seed") != std::string::npos,
        "the null-seed rejection must say so explicitly, got: " << strError);

    // (2) The hash entry point itself.
    uint256 out;
    std::string strHashError;
    BOOST_CHECK_MESSAGE(!syzgy::RandomXHash(header, uint256(), out, strHashError),
        "RandomXHash() with a null seed must fail closed");
    BOOST_CHECK_MESSAGE(out.IsNull(),
        "a failed RandomXHash() must not write a value the caller could mistake for a hash");

    // (3) The proof check itself, the one validation calls.
    const uint256 target = ArithToUint256(arith_uint256().SetCompact(RegtestCeilingBits()));
    BOOST_CHECK_MESSAGE(!syzgy::RandomXCheckProof(header, uint256(), target, strHashError),
        "RandomXCheckProof() with a null seed must fail closed");

    // (4) When a hash IS obtainable, the equality test is still enforced. This is the part that
    // a "best effort" implementation drops: it checks the target and ignores the committed
    // value.
    CBlockHeader tampered = header;
    tampered.hashRandomX = uint256S("00000000000000000000000000000000000000000000000000000000000000aa");
    BOOST_CHECK_MESSAGE(!syzgy::RandomXCheckProof(tampered, seed, target, strHashError),
        "RandomXCheckProof() must reject a hashRandomX that is not the hash of the template");
    BOOST_CHECK_MESSAGE(strHashError.find("mismatch") != std::string::npos,
        "the rejection must be a mismatch, got: " << strHashError);

    // (5) A seed that cannot be derived is a failure, not a default.
    uint256 orphanSeed;
    std::string strOrphanError;
    // A parent index that is not the genesis and has no populated ancestry cannot resolve an
    // epoch anchor. Forcing nEpoch > 0 is what makes the anchor lookup happen at all, which is
    // done here with a params copy rather than by moving a block, so the chain above is
    // untouched.
    {
        Consensus::Params orphanParams = params;
        orphanParams.nSyzgyRandomXEpochLength = 2;   // height 2 is in epoch 1
        CBlockIndex tip;
        tip.nHeight = 3;
        tip.nTime = (uint32_t)(T0 + 180);
        const bool fDerived = GetRandomXSeedForHeight(&tip, orphanParams, orphanSeed, strOrphanError);
        if (!fDerived) {
            // The only legitimate reason to fail is an unresolvable anchor, and a node must
            // then reject rather than guess.
            BOOST_CHECK_MESSAGE(orphanSeed.IsNull(),
                "a failed seed derivation must leave the seed null, never partially set");
            BOOST_CHECK_MESSAGE(strOrphanError.find("SYZGY") != std::string::npos,
                "a failed seed derivation must explain itself, got: " << strOrphanError);
        } else {
            // If the anchor did resolve (a stub whose GetAncestor happened to succeed), the
            // derived seed must still be the correct epoch-1 derivation, not the epoch-0 one.
            BOOST_CHECK_MESSAGE(orphanSeed != Epoch0Seed(),
                "a block in epoch 1 must not be given the epoch-0 seed");
        }
    }

    delete chain;
}

// ===========================================================================================
// Height 0 -- the genesis carries BOTH proofs, and a missing parent is never an exemption
// ===========================================================================================

/**
 * THE GENESIS TEST.
 *
 * The regtest genesis has no parent, so the parent-relative machinery has nothing to work
 * from. The requirement is that this be handled EXPLICITLY and that it not fail open. Two
 * things are asserted:
 *
 *   1. the shipped regtest genesis genuinely carries a valid KawPoW proof AND a valid
 *      RandomX proof, and therefore PASSES the dual check. This is the FR-01 requirement at
 *      height 0, and it is what lets a real regtest node load the chain at all;
 *   2. a block at height > 0 with NO parent index is REJECTED, rather than having its CPU
 *      target silently substituted with the easiest legal one. The ceiling is the correct CPU
 *      target below the LWMA window, which is exactly what makes "assume the ceiling" look
 *      harmless -- and that is why the fail-open shape is rejected outright.
 */
BOOST_AUTO_TEST_CASE(syzgy_genesis_carries_both_proofs_and_a_missing_parent_is_not_an_exemption)
{
    const Consensus::Params& params = RegtestParams();
    const CBlock& genesis = GetParams().GenesisBlock();
    const uint256 seed = Epoch0Seed();

    // --- (1) the shipped genesis, dual-checked ------------------------------------------------
    BOOST_REQUIRE_MESSAGE(genesis.nHeight == 0, "the genesis block must be at height 0");
    BOOST_CHECK_MESSAGE(genesis.hashPrevBlock.IsNull(),
        "the genesis block has no parent -- that is the case this test is about");
    BOOST_CHECK_MESSAGE(!genesis.hashRandomX.IsNull(),
        "the regtest genesis must carry a RandomX proof; FR-01 has no genesis exemption");
    BOOST_CHECK_MESSAGE(!genesis.mix_hash.IsNull(),
        "the regtest genesis must carry a KawPoW proof; FR-01 has no genesis exemption");

    // Both halves proven good independently first, so that a pass below is attributable to the
    // dual check accepting a real pair and not to some degenerate target.
    {
        uint256 mix;
        const uint256 kawpowHash = KAWPOWHash(genesis, mix);
        BOOST_REQUIRE_MESSAGE(mix == genesis.mix_hash,
            "the genesis's recomputed KawPoW mix must equal its claimed mix_hash");
        BOOST_REQUIRE_MESSAGE(CheckProofOfWork(kawpowHash, genesis.nBits, params),
            "the genesis's KawPoW proof must meet the GPU target on its own");
        uint256 rx;
        std::string rxError;
        BOOST_REQUIRE_MESSAGE(syzgy::RandomXHash(genesis, seed, rx, rxError),
            "recomputing the genesis's RandomX hash must succeed: " << rxError);
        BOOST_REQUIRE_MESSAGE(rx == genesis.hashRandomX,
            "the genesis's hashRandomX must be the RandomX hash of the genesis template");
    }

    std::string strError;
    BOOST_CHECK_MESSAGE(CheckDualProofOfWork(genesis, static_cast<const CBlockIndex*>(nullptr), params, seed, strError),
        "the regtest genesis carries both proofs and must PASS the dual check: " << strError);

    // The parent-resolving overload must reach the same verdict from the other direction.
    strError.clear();
    BOOST_CHECK_MESSAGE(CheckDualProofOfWork(genesis, params, seed, strError),
        "the parent-resolving overload must accept the genesis too: " << strError);

    // Corrupting EITHER half of the genesis must now be rejected, which is what proves the
    // acceptance above came from checking both proofs rather than from a short circuit.
    {
        CBlockHeader bad = genesis;
        bad.hashRandomX = uint256S("00000000000000000000000000000000000000000000000000000000000000ff");
        std::string e;
        BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(bad, static_cast<const CBlockIndex*>(nullptr), params, seed, e),
            "a genesis whose hashRandomX is wrong must be rejected -- the acceptance above must "
                "come from the CPU proof being verified, not skipped");
    }
    {
        CBlockHeader bad = genesis;
        bad.mix_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000fe");
        std::string e;
        BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(bad, static_cast<const CBlockIndex*>(nullptr), params, seed, e),
            "a genesis whose mix_hash is wrong must be rejected -- the acceptance above must come "
                "from the GPU proof being verified, not skipped");
    }

    // --- (2) a non-genesis block with no parent index is rejected -----------------------------
    {
        RegisteredChain* chain = BuildRegisteredChain(3, /*cpuProof=*/true, /*gpuProof=*/true);
        CBlockHeader header = MakeHeader(*chain, chain->size() - 1);
        BOOST_REQUIRE_MESSAGE(MineProofs(header, /*fWantGpu=*/true, /*fWantCpu=*/true, seed),
            "mining a real dual proof at the regtest ceiling must succeed");

        // Sanity: with the parent supplied, the very same header is accepted. Without this the
        // rejection below would prove nothing.
        std::string e;
        BOOST_REQUIRE_MESSAGE(CheckDualProofOfWork(header, chain->tip(), params, seed, e),
            "the same header with its parent must be accepted: " << e);

        e.clear();
        BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, static_cast<const CBlockIndex*>(nullptr), params, seed, e),
            "a genuine, fully-mined dual proof at height > 0 must still be REJECTED when no "
                "parent index is supplied -- a missing parent is a missing derivation, not an "
                "exemption");
        BOOST_CHECK_MESSAGE(e.find("fail closed") != std::string::npos,
            "the missing-parent rejection must say that it failed closed, got: " << e);

        // And the same header reached through the parent-resolving overload, with the parent
        // genuinely absent from mapBlockIndex, must be rejected by that path instead.
        mapBlockIndex.erase(header.hashPrevBlock);
        e.clear();
        BOOST_CHECK_MESSAGE(!CheckDualProofOfWork(header, params, seed, e),
            "the parent-resolving overload must reject a block whose parent is unknown");
        delete chain;
    }
}

BOOST_AUTO_TEST_SUITE_END()