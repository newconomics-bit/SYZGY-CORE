// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the SYZGY dual-PoW machinery introduced in Wave 2 Step 1:
//   * the LWMA-2 retarget for the RandomX (CPU) side  (syzgy_lwma)
//   * the five-layer Sync Controller                    (syzgy_sync)
//
// Everything here is deterministic: no wall clock, no unseeded randomness, fixed synthetic
// index chains built from literal values. Every assertion carries a message.

// A test whose expected value cannot be derived from the specification is NOT written here.
// Where a value is derived, the derivation is stated in the comment next to the assertion so
// a reader can check it without running the binary.

#include <test/test_raven.h>

#include <boost/test/unit_test.hpp>

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "amount.h"
#include "consensus/params.h"
#include "syzgy/syzgy_lwma.h"
#include "syzgy/syzgy_sync.h"
#include "uint256.h"

#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(syzgy_sync_tests, BasicTestingSetup)

namespace {

// ---------------------------------------------------------------------------
// Params helpers
// ---------------------------------------------------------------------------

// Mainnet params, straight from CMainParams via SelectParams() in BasicTestingSetup.
const Consensus::Params& MainParams()
{
    return GetParams().GetConsensus();
}

std::unique_ptr<CChainParams> MakeParams(const std::string& network)
{
    return CreateChainParams(network);
}

// Regtest carries the deliberately short SYZGY windows, which is what makes the machinery
// reachable in a test run at all (see the comment in CRegTestParams).
Consensus::Params RegtestParams()
{
    return MakeParams(CBaseChainParams::REGTEST)->GetConsensus();
}

// ---------------------------------------------------------------------------
// Synthetic chain helpers
// ---------------------------------------------------------------------------

uint256 Sentinel(uint8_t tag)
{
    (void)tag;
    return uint256S("00000000000000000000000000000000000000000000000000000000000000ff");
}

/**
 * A synthetic, fully-linked index chain owned by the test.
 *
 * Height 0 is genesis. Every block from height 1 up carries the requested nBits, nTime and
 * proof-presence flags, so the Sync Controller's direct index reads can be exercised without
 * mining anything.
 */
struct BuiltChain {
    std::vector<CBlockIndex*> blocks;
    CChain chain;

    ~BuiltChain()
    {
        for (size_t i = 0; i < blocks.size(); ++i) delete blocks[i];
    }

    const CBlockIndex* tip() const { return blocks.empty() ? nullptr : blocks.back(); }
};

CBlockIndex* MakeIndex(int height, uint32_t nTime, uint32_t nBits, bool cpuProof, bool gpuProof)
{
    CBlockIndex* p = new CBlockIndex();
    p->nHeight = height;
    p->nTime = nTime;
    p->nBits = nBits;
    if (cpuProof) p->hashRandomX = uint256S("00000000000000000000000000000000000000000000000000000000000000c1");
    if (gpuProof)  p->mix_hash    = uint256S("00000000000000000000000000000000000000000000000000000000000000b1");
    return p;
}

/**
 * Build a linear chain of `nBlocks` blocks after genesis.
 *
 * Genesis always carries BOTH proofs (FR-01 has no genesis exemption on SYZGY). Blocks from
 * height 1 carry the flags given by `cpuProof`/`gpuProof`. Every block gets nBits, and the
 * timestamp of height h is `t0 + h * nSpacing`.
 */
BuiltChain* BuildChain(int nBlocks, uint32_t nBits, int64_t t0, int64_t nSpacing,
                       bool cpuProof, bool gpuProof)
{
    BuiltChain* bc = new BuiltChain();
    CBlockIndex* genesis = MakeIndex(0, (uint32_t)t0, nBits, true, true);
    bc->blocks.push_back(genesis);

    for (int h = 1; h <= nBlocks; ++h) {
        CBlockIndex* p = MakeIndex(h, (uint32_t)(t0 + h * nSpacing), nBits, cpuProof, gpuProof);
        p->pprev = bc->blocks.back();
        bc->blocks.push_back(p);
    }

    bc->chain.SetTip(bc->blocks.back());
    return bc;
}

// A non-canonical-free sentinel compact for difficulty arithmetic: regtest's limit bits.
const uint32_t EASY_BITS = 0x207fffff;   // regtest powLimit == randomxLimit == kawpowLimit
const uint32_t HARD_BITS = 0x1b0404cb;   // arbitrary but fixed, strictly below EASY_BITS

} // anonymous namespace

// ===========================================================================================
// LWMA-2
// ===========================================================================================

BOOST_AUTO_TEST_CASE(syzgy_lwma_bootstrap)
{
    const Consensus::Params params = RegtestParams();   // window 10 -> M = 9
    const uint32_t kLimitCompact = UintToArith256(params.randomxLimit).GetCompact();

    // A null tip bootstraps.
    BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(nullptr, nullptr, params) == kLimitCompact,
        "a null tip must bootstrap to randomxLimit's compact form");

    // A tip below the window length must also bootstrap. M = nSyzgySyncWindow - 1 = 9, so a
    // 5-block chain is short of the samples.
    BOOST_REQUIRE_MESSAGE(params.nSyzgySyncWindow == 10,
        "this test assumes regtest nSyzgySyncWindow == 10, got " << params.nSyzgySyncWindow);
    BuiltChain* bc = BuildChain(5, EASY_BITS, 1000000, 60, true, true);
    BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(bc->tip(), nullptr, params) == kLimitCompact,
        "a chain shorter than the LWMA window must return randomxLimit's compact form");
    BOOST_CHECK_MESSAGE(kLimitCompact == EASY_BITS,
        "regtest randomxLimit compact should be the regtest limit bits, got " << kLimitCompact);
    delete bc;

    // Exactly at the window boundary (tip->nHeight == M) the window walk becomes possible, so
    // the answer is no longer forced to the ceiling. Asserted against the reference value
    // computed from the spec's own formulas.
    //
    // NOTE ON THE GUARD BAND. Step 5 clamps the TOTAL window timespan into [S/3, 3S] = [20, 180]
    // seconds. A 9-block window at a correct 60s spacing spans 9*60 = 540s, which is ABOVE 180,
    // so the clamp binds and pulls T_actual down to 180. That is what the specification as
    // written says to do, and this implementation follows it literally rather than silently
    // rescaling the band. The consequence (the band is a per-block quantity applied to a
    // total-window quantity, so on a correctly-timed network T_actual is always clamped to 3S)
    // is flagged to the founder as a units defect in the spec, not worked around here: changing
    // it unilaterally would fork the CPU target away from any other implementation.
    const Consensus::Params rp = params;
    const int64_t nM = rp.nSyzgySyncWindow - 1;
    const int64_t nT = nM * rp.nSyzgySyncTargetBlockSeconds;
    const unsigned int kAtBoundary = syzgy::CalculateLWMANextWorkRequired(
        arith_uint256().SetCompact(EASY_BITS), nM, 3 * rp.nSyzgySyncTargetBlockSeconds, nT,
        UintToArith256(rp.randomxLimit));
    BuiltChain* bc2 = BuildChain(9, EASY_BITS, 1000000, 60, true, true);
    BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(bc2->tip(), nullptr, params) == kAtBoundary,
        "at exactly tip->nHeight == M the window walk must run and produce the spec-derived "
        "target (got " << syzgy::GetNextRandomXWorkRequired(bc2->tip(), nullptr, params)
        << ", expected " << kAtBoundary << ")");
    BOOST_CHECK_MESSAGE(kAtBoundary != kLimitCompact,
        "just past the bootstrap boundary the answer must stop being the ceiling, otherwise the "
        "boundary check above proves nothing");
    delete bc2;
}

BOOST_AUTO_TEST_CASE(syzgy_lwma_holds_on_degenerate_timespan)
{
    // Direct check on the arithmetic: T_actual == 0 BEFORE the clamp is a hold, i.e. the
    // weighted average comes back out unchanged.
    const arith_uint256 bnAvg = arith_uint256().SetCompact(HARD_BITS);
    const arith_uint256 bnLimit = arith_uint256().SetCompact(EASY_BITS);
    const unsigned int uHeld = syzgy::CalculateLWMANextWorkRequired(bnAvg, 9, 0, 9 * 60, bnLimit);
    BOOST_CHECK_MESSAGE(uHeld == HARD_BITS,
        "a zero timespan must hold the previous target, got " << uHeld << " expected " << HARD_BITS);

    // M < 1 is also a hold, and must not divide by zero.
    const unsigned int uHeldM = syzgy::CalculateLWMANextWorkRequired(bnAvg, 0, 600, 9 * 60, bnLimit);
    BOOST_CHECK_MESSAGE(uHeldM == HARD_BITS,
        "nPastBlocks == 0 must hold the previous target, got " << uHeldM);

    // T_target <= 0 is a hold too.
    const unsigned int uHeldT = syzgy::CalculateLWMANextWorkRequired(bnAvg, 9, 600, 0, bnLimit);
    BOOST_CHECK_MESSAGE(uHeldT == HARD_BITS,
        "a non-positive target timespan must hold the previous target, got " << uHeldT);

    // End to end: an entire chain sharing a single timestamp gives T_actual == 0.
    // Every sample also carries the same nBits, so T_avg == SetCompact(HARD_BITS) and the
    // expected answer is exactly HARD_BITS.
    BuiltChain* bc = BuildChain(12, HARD_BITS, 1700000000, 0, true, true);
    BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(bc->tip(), nullptr, RegtestParams()) == HARD_BITS,
        "a chain whose blocks all share one timestamp must hold at the window average");
    delete bc;
}

BOOST_AUTO_TEST_CASE(syzgy_lwma_is_pure_function)
{
    const Consensus::Params params = RegtestParams();
    BuiltChain* bc = BuildChain(20, HARD_BITS, 1700000000, 60, true, true);

    const unsigned int a = syzgy::GetNextRandomXWorkRequired(bc->tip(), nullptr, params);
    const unsigned int b = syzgy::GetNextRandomXWorkRequired(bc->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(a == b,
        "calling the LWMA retarget twice on the same chain must give the same bits ("
            << a << " vs " << b << ")");

    // pblock is deliberately unread, so a completely different header must not move the answer.
    CBlockHeader hostile;
    hostile.nVersion = 0xdeadbeef;
    hostile.nTime = 1;
    hostile.nBits = 0x207fffff;
    hostile.nHeight = 999999;
    hostile.nNonce64 = 0x1122334455667788ULL;
    hostile.mix_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000ee");
    hostile.nRandomXNonce = 0x99aabbccddeeff00ULL;
    hostile.hashRandomX = uint256S("00000000000000000000000000000000000000000000000000000000000000dd");
    const unsigned int c = syzgy::GetNextRandomXWorkRequired(bc->tip(), &hostile, params);
    BOOST_CHECK_MESSAGE(c == a,
        "pblock must be ignored by the LWMA retarget (" << c << " vs " << a << ")");

    delete bc;
}

BOOST_AUTO_TEST_CASE(syzgy_lwma_clamps_absurd_timespan)
{
    const Consensus::Params params = RegtestParams();   // S = 60, window 10, M = 9
    const int64_t M = params.nSyzgySyncWindow - 1;
    const int64_t S = params.nSyzgySyncTargetBlockSeconds;
    const int64_t nTarget = M * S;                      // 540

    // Reference answer: the target that the 3x guard band produces. This is derived straight
    // from the spec's step 5/step 6 and is computed by the same function, so it checks that
    // the clamp is applied rather than that the clamp is numerically correct.
    const arith_uint256 bnAvg = arith_uint256().SetCompact(HARD_BITS);
    const arith_uint256 bnLimit = arith_uint256().SetCompact(EASY_BITS);
    const unsigned int kExpected = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, 3 * S, nTarget, bnLimit);

    // End to end: blocks 10x slower than target. Raw T_actual = 10 * nTarget = 5400, which is
    // far outside the [S/3, 3S] = [20, 180] band and must be pulled back to 180.
    BuiltChain* slow = BuildChain(14, HARD_BITS, 1700000000, 600, true, true);
    const unsigned int uSlow = syzgy::GetNextRandomXWorkRequired(slow->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uSlow == kExpected,
        "a 10x-slow window must clamp to the 3x guard band (got " << uSlow
            << ", expected " << kExpected << ")");

    // A chain at exactly 3x per-block spacing must give the identical answer.
    BuiltChain* edge = BuildChain(14, HARD_BITS, 1700000000, 3 * S, true, true);
    const unsigned int uEdge = syzgy::GetNextRandomXWorkRequired(edge->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uEdge == kExpected,
        "an exactly-3x window is the clamp boundary and must match the clamped 10x window");

    // And the low side: the guard band is [S/3, 3S] = [20, 180] seconds of TOTAL window time.
    // A 14-block window at 1s per block spans 14s, which is under the 20s floor and must be
    // pulled up to exactly S/3.
    const unsigned int kExpectedLow = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, S / 3, nTarget, bnLimit);
    BuiltChain* fast = BuildChain(14, HARD_BITS, 1700000000, 1, true, true);
    const unsigned int uFast = syzgy::GetNextRandomXWorkRequired(fast->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uFast == kExpectedLow,
        "a window far faster than target must clamp to the S/3 guard band (got " << uFast
            << ", expected " << kExpectedLow << ")");
    BOOST_CHECK_MESSAGE(kExpectedLow != kExpected,
        "the low and high clamp bands must produce different targets, otherwise this test is "
        "not distinguishing anything");

    delete slow;
    delete edge;
    delete fast;
}

// ===========================================================================================
// Sync Controller
// ===========================================================================================

BOOST_AUTO_TEST_CASE(syzgy_sync_freezes_absent_class)
{
    // THE SAFETY TEST. In SINGLE_ALO_CPU the GPU bits must come back BIT-IDENTICAL to the input;
    // symmetric for SINGLE_ALO_GPU. This is asserted for exact equality, not for a range: a
    // bound would still permit a target that decays steadily toward zero, which is precisely
    // the failure this invariant exists to prevent.
    const Consensus::Params params = RegtestParams();

    const unsigned int kGpuBits = 0x1b2c3d4e;
    const unsigned int kCpuBits = 0x1a00b0c1;

    {
        syzgy::SyncDataFeed feed;
        feed.window = params.nSyzgySyncWindow;
        feed.cpuBlocks = 10;
        feed.gpuBlocks = 0;
        feed.cpuDifficulty = (int64_t)kCpuBits;
        feed.gpuDifficulty = (int64_t)kGpuBits;

        syzgy::SyncHealth health;
        health.cpuPresent = true;
        health.gpuPresent = false;
        health.pairingStalled = true;
        health.consecutiveStalls = params.nSyzgyPairingStallBlocks;

        syzgy::SyncMode mode = syzgy::RouteMode(health, params);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::SINGLE_ALO_CPU,
            "a CPU-present/GPU-absent stall must route to SINGLE_ALO_CPU");

        unsigned int cpuOut = 0, gpuOut = 0;
        syzgy::ComputeBalancedBits(feed, health, mode, params, cpuOut, gpuOut);
        BOOST_CHECK_MESSAGE(gpuOut == kGpuBits,
            "EMERGENCY INVARIANT: in SINGLE_ALO_CPU the absent GPU target must be returned "
            "bit-identical (got 0x" << std::hex << gpuOut << ", expected 0x" << kGpuBits << std::dec
            << ") -- it must never be driven toward zero difficulty");
    }

    {
        syzgy::SyncDataFeed feed;
        feed.window = params.nSyzgySyncWindow;
        feed.cpuBlocks = 0;
        feed.gpuBlocks = 10;
        feed.cpuDifficulty = (int64_t)kCpuBits;
        feed.gpuDifficulty = (int64_t)kGpuBits;

        syzgy::SyncHealth health;
        health.cpuPresent = false;
        health.gpuPresent = true;
        health.pairingStalled = true;
        health.consecutiveStalls = params.nSyzgyPairingStallBlocks;

        syzgy::SyncMode mode = syzgy::RouteMode(health, params);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::SINGLE_ALO_GPU,
            "a GPU-present/CPU-absent stall must route to SINGLE_ALO_GPU");

        unsigned int cpuOut = 0, gpuOut = 0;
        syzgy::ComputeBalancedBits(feed, health, mode, params, cpuOut, gpuOut);
        BOOST_CHECK_MESSAGE(cpuOut == kCpuBits,
            "EMERGENCY INVARIANT: in SINGLE_ALO_GPU the absent CPU target must be returned "
            "bit-identical (got 0x" << std::hex << cpuOut << ", expected 0x" << kCpuBits << std::dec
            << ")");
    }

    // The guardrails must also be a no-op on the frozen side: prev == desired, so the
    // +/- nSyzgySyncMaxRetargetPercent band contains the value trivially and nothing is clamped.
    {
        syzgy::SyncGuardrails g = syzgy::ApplyGuardrails(kCpuBits, kGpuBits, kCpuBits, kGpuBits, params);
        BOOST_CHECK_MESSAGE(g.nextCpuBits == kCpuBits && g.nextGpuBits == kGpuBits,
            "applying the guardrails to an unchanged pair of targets must return them unchanged");
        BOOST_CHECK_MESSAGE(!g.clampedCpu && !g.clampedGpu,
            "an unchanged pair of targets must not be reported as clamped");
    }
}

BOOST_AUTO_TEST_CASE(syzgy_sync_guardrails_bound_retarget)
{
    const Consensus::Params params = RegtestParams();
    const int64_t maxPct = params.nSyzgySyncMaxRetargetPercent;
    BOOST_REQUIRE_MESSAGE(maxPct == 60,
        "this test asserts against the regtest guardrail of 60 percent, got " << maxPct);

    const unsigned int prevBits = 0x1b0404cb;
    const arith_uint256 bnPrev = arith_uint256().SetCompact(prevBits);
    const arith_uint256 bnLo = (bnPrev * arith_uint256((uint64_t)(100 - maxPct))) / arith_uint256((uint64_t)100);
    const arith_uint256 bnHi = (bnPrev * arith_uint256((uint64_t)(100 + maxPct))) / arith_uint256((uint64_t)100);
    // The bounds are asserted in COMPACT space because GetCompact() is a lossy encoding of the
    // low mantissa bits, so a round trip through it can land slightly below bnLo. Comparing the
    // raw 256-bit bound against the round-tripped result would be an assertion about mantissa
    // truncation, not about the guardrail.
    const unsigned int kLoBits = bnLo.GetCompact();
    const unsigned int kHiBits = bnHi.GetCompact();
    BOOST_REQUIRE_MESSAGE(kLoBits < prevBits && kHiBits > prevBits,
        "the +-" << maxPct << "% guardrail band must strictly bracket the previous target ("
                 << kLoBits << ", " << prevBits << ", " << kHiBits << ")");

    // Absurdly EASY target requested: must be pulled back to the +60% bound and reported clamped.
    // Using the algos' own limit as the "desired" is the most extreme request expressible.
    {
        const unsigned int desired = UintToArith256(params.kawpowLimit).GetCompact();
        syzgy::SyncGuardrails g = syzgy::ApplyGuardrails(prevBits, prevBits, prevBits, desired, params);
        BOOST_CHECK_MESSAGE(g.nextGpuBits == kHiBits,
            "a retarget beyond +60% must be clamped to exactly the +60% bound (got 0x"
                << std::hex << g.nextGpuBits << ", bound 0x" << kHiBits << std::dec << ")");
        BOOST_CHECK_MESSAGE(g.clampedGpu, "clamping the GPU side must be reported in the result struct");
        BOOST_CHECK_MESSAGE(!g.clampedCpu, "an unchanged CPU side must not be reported as clamped");
        BOOST_CHECK_MESSAGE(g.nextCpuBits == prevBits,
            "the untouched side must come back exactly unchanged");
    }

    // Absurdly HARD target requested: must be pulled up to the -60% bound and reported clamped.
    // 0x01003456 decodes to a target of 0, i.e. "impossibly hard", the other extreme.
    {
        syzgy::SyncGuardrails g = syzgy::ApplyGuardrails(prevBits, prevBits, 0x01003456, prevBits, params);
        BOOST_CHECK_MESSAGE(g.nextCpuBits == kLoBits,
            "a retarget beyond -60% must be clamped to exactly the -60% bound (got 0x"
                << std::hex << g.nextCpuBits << ", bound 0x" << kLoBits << std::dec << ")");
        BOOST_CHECK_MESSAGE(g.clampedCpu, "clamping the CPU side must be reported in the result struct");
    }

    // A request inside the band must pass through untouched and unclamped.
    {
        syzgy::SyncGuardrails g = syzgy::ApplyGuardrails(prevBits, prevBits, prevBits, prevBits, params);
        BOOST_CHECK_MESSAGE(g.nextCpuBits == prevBits && g.nextGpuBits == prevBits,
            "a target inside the guardrail band must pass through unchanged");
        BOOST_CHECK_MESSAGE(!g.clampedCpu && !g.clampedGpu,
            "an in-band target must not be reported as clamped");
    }

    // A target must never exceed its own algorithm's limit, whichever way it was asked for.
    {
        const arith_uint256 bnCpuLimit = UintToArith256(params.randomxLimit);
        const arith_uint256 bnGpuLimit = UintToArith256(params.kawpowLimit);
        const unsigned int easy = bnGpuLimit.GetCompact();
        // prevBits is much harder than the limit, so the +60% band may still sit above the
        // limit; either way the result must not exceed the limit.
        syzgy::SyncGuardrails g = syzgy::ApplyGuardrails(0x1b0404cb, 0x1b0404cb, easy, easy, params);
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(g.nextCpuBits) <= bnCpuLimit,
            "no CPU target may ever exceed randomxLimit");
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(g.nextGpuBits) <= bnGpuLimit,
            "no GPU target may ever exceed kawpowLimit");
    }
}

BOOST_AUTO_TEST_CASE(syzgy_sync_emergency_never_traps)
{
    // Property-style. Starting from a genuine single-alo emergency, the stall run grows by one
    // block at a time. DUAL_POW must become reachable again within R = 2 * nSyzgySyncMinRatio
    // steps, for every starting configuration and for both absent classes. If it did not,
    // emergency mode would be a one-way door and the chain would be stuck single-alo forever.
    struct Config { int nSyncWindow; int nStallBlocks; int nMinRatio; };

    const Config configs[] = {
        {90, 6, 15},   // mainnet
        {10, 2, 30},   // regtest, where R = 60 is deliberately LARGER than the window
    };

    for (const Config& c : configs) {
        Consensus::Params params = RegtestParams();
        params.nSyzgySyncWindow = c.nSyncWindow;
        params.nSyzgyPairingStallBlocks = c.nStallBlocks;
        params.nSyzgySyncMinRatio = c.nMinRatio;

        const int64_t nR = 2 * (int64_t)c.nMinRatio;

        for (int nAbsentClass = 0; nAbsentClass < 2; ++nAbsentClass) {
            for (int64_t nStartStall = 0; nStartStall <= nR; ++nStartStall) {
                bool bRecovered = false;
                for (int64_t nStall = nStartStall; nStall <= nR; ++nStall) {
                    syzgy::SyncHealth h;
                    h.cpuPresent = (nAbsentClass == 1);   // class 1 = GPU absent
                    h.gpuPresent = (nAbsentClass == 0);   // class 0 = CPU absent
                    h.pairingStalled = nStall >= (int64_t)c.nStallBlocks;
                    h.consecutiveStalls = (int)nStall;
                    h.cpuPresentStreak = h.cpuPresent ? (int)nR - 1 : 0;   // hysteresis NOT met
                    h.gpuPresentStreak = h.gpuPresent ? (int)nR - 1 : 0;
                    h.cpuPresencePercent = h.cpuPresent ? 100 : 0;
                    h.gpuPresencePercent = h.gpuPresent ? 100 : 0;

                    const syzgy::SyncMode m = syzgy::RouteMode(h, params);

                    if (!h.pairingStalled) {
                        // Below the stall threshold there is nothing to recover from; strict
                        // dual-PoW is the only legal answer.
                        BOOST_REQUIRE_MESSAGE(m == syzgy::SyncMode::DUAL_POW,
                            "an unstalled window must always route to DUAL_POW (absent class "
                                << nAbsentClass << ", stall " << nStall << ")");
                        continue;
                    }

                    // Invariant under test: a single-alo mode is only reachable while the stall
                    // run is strictly shorter than R; at exactly R the valve must have fired.
                    if (nStall >= nR) {
                        BOOST_REQUIRE_MESSAGE(m == syzgy::SyncMode::DUAL_POW,
                            "anti-trap valve: with a stall run of " << nStall << " >= R=" << nR
                            << " (window " << c.nSyncWindow << ", minRatio " << c.nMinRatio
                            << ", absent class " << nAbsentClass
                            << ") the router must have returned DUAL_POW, but it returned "
                            << (int)m);
                        bRecovered = true;
                    } else {
                        BOOST_CHECK_MESSAGE(m != syzgy::SyncMode::DUAL_POW,
                            "a stalled but recovering window must still be in a single-alo mode "
                            "(absent class " << nAbsentClass << ", stall " << nStall << ")");
                    }
                }
                BOOST_CHECK_MESSAGE(bRecovered,
                    "DUAL_POW must be reachable for every starting stall length and both absent "
                    "classes (window " << c.nSyncWindow << ", start stall " << nStartStall
                    << ", absent class " << nAbsentClass << ")");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(syzgy_sync_both_absent_is_not_single_algo)
{
    const Consensus::Params params = RegtestParams();

    syzgy::SyncDataFeed feed;
    feed.window = params.nSyzgySyncWindow;
    feed.cpuBlocks = 0;
    feed.gpuBlocks = 0;
    feed.cpuDifficulty = 0x1a00b0c1;
    feed.gpuDifficulty = 0x1b2c3d4e;

    syzgy::SyncHealth health = syzgy::EvaluateHealth(feed, params);
    // Make it a hard stall with both classes out, which is the dangerous case: nothing is
    // producing blocks, so there is no evidence of which class is the surviving one.
    health.pairingStalled = true;
    health.consecutiveStalls = 1000;

    const syzgy::SyncMode mode = syzgy::RouteMode(health, params);
    BOOST_CHECK_MESSAGE(mode == syzgy::SyncMode::DUAL_POW,
        "both classes absent must never yield a single-algo mode (got " << (int)mode << ")");

    // And the difficulty engine must hold both targets rather than freezing one arbitrarily.
    unsigned int cpuOut = 0, gpuOut = 0;
    syzgy::ComputeBalancedBits(feed, health, mode, params, cpuOut, gpuOut);
    BOOST_CHECK_MESSAGE(cpuOut == (unsigned int)feed.cpuDifficulty
                        && gpuOut == (unsigned int)feed.gpuDifficulty,
        "with both classes absent the difficulty engine must hold both targets");

    // The genuine evaluate-from-feed version must agree.
    syzgy::SyncDataFeed stalled = feed;
    stalled.cpuStallRun = 1000;
    stalled.gpuStallRun = 1000;
    const syzgy::SyncHealth h2 = syzgy::EvaluateHealth(stalled, params);
    BOOST_CHECK_MESSAGE(h2.pairingStalled, "a 1000-block stall run must register as a stall");
    BOOST_CHECK_MESSAGE(!h2.cpuPresent && !h2.gpuPresent,
        "no blocks in the window must mean neither class is present");
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(h2, params) == syzgy::SyncMode::DUAL_POW,
        "both-absent from a real feed must still route to DUAL_POW");
}

BOOST_AUTO_TEST_CASE(syzgy_sync_presence_is_counted_from_proof_fields)
{
    const Consensus::Params params = RegtestParams();

    // A dual chain and a GPU-only chain over identical nBits/nTime. Only the presence of
    // hashRandomX differs, so any difference in the feed can only have come from reading that
    // field directly.
    BuiltChain* dual = BuildChain(6, HARD_BITS, 1700000000, 60, true, true);
    BuiltChain* gpuOnly = BuildChain(6, HARD_BITS, 1700000000, 60, false, true);

    const syzgy::SyncDataFeed fd = syzgy::CollectDataFeed(dual->chain, params);
    const syzgy::SyncDataFeed fg = syzgy::CollectDataFeed(gpuOnly->chain, params);

    BOOST_CHECK_MESSAGE(fd.cpuBlocks == 6 && fd.gpuBlocks == 6,
        "a chain whose every non-genesis block carries both proofs must count 6 and 6, got "
            << fd.cpuBlocks << " and " << fd.gpuBlocks);
    BOOST_CHECK_MESSAGE(fg.cpuBlocks == 0 && fg.gpuBlocks == 6,
        "a null hashRandomX on a non-genesis block is an emergency-mode GPU-only block and must "
        "be counted ABSENT, not skipped as unknown; got cpuBlocks " << fg.cpuBlocks
            << " and gpuBlocks " << fg.gpuBlocks);
    BOOST_CHECK_MESSAGE(fd.cpuPresentStreak == 6,
        "a dual chain must show a 6-block CPU presence streak, got " << fd.cpuPresentStreak);
    BOOST_CHECK_MESSAGE(fg.cpuPresentStreak == 0 && fg.cpuStallRun == 6,
        "a GPU-only chain must show a 6-block CPU stall run, got streak "
            << fg.cpuPresentStreak << " and stall " << fg.cpuStallRun);
    BOOST_CHECK_MESSAGE(fg.stallStartHeight == 1,
        "the stall run started at height 1, got " << fg.stallStartHeight);

    // HEIGHT 0 IS EXPLICITLY EXCLUDED: the walk stops above genesis, so even if genesis were
    // counted the numbers above would be 7. Assert the count is exactly the six real blocks.
    BOOST_CHECK_MESSAGE(fd.cpuBlocks == 6,
        "genesis (height 0) must not contribute a window slot; a count of 7 means it did");

    // A CPU-only chain: the symmetric absence.
    BuiltChain* cpuOnly = BuildChain(6, HARD_BITS, 1700000000, 60, true, false);
    const syzgy::SyncDataFeed fc = syzgy::CollectDataFeed(cpuOnly->chain, params);
    BOOST_CHECK_MESSAGE(fc.cpuBlocks == 6 && fc.gpuBlocks == 0,
        "a null mix_hash must count the GPU class absent; got cpuBlocks " << fc.cpuBlocks
            << " and gpuBlocks " << fc.gpuBlocks);

    // The CChain and CBlockIndex overloads must agree exactly on the same chain.
    const syzgy::SyncDataFeed fp = syzgy::CollectDataFeed(dual->tip(), params);
    BOOST_CHECK_MESSAGE(fp.cpuBlocks == fd.cpuBlocks && fp.gpuBlocks == fd.gpuBlocks
                            && fp.cpuPresentStreak == fd.cpuPresentStreak
                            && fp.gpuPresentStreak == fd.gpuPresentStreak
                            && fp.cpuStallRun == fd.cpuStallRun
                            && fp.gpuStallRun == fd.gpuStallRun,
        "the CChain and CBlockIndex Data Feed overloads must produce identical feeds");

    // Routing: the GPU-only chain is a stall, so with regtest's 2-block threshold it is an
    // emergency; the dual chain is not. Note the direction: a GPU-only chain means the GPU is
    // PRESENT and the CPU is absent, so the mode is SINGLE_ALO_GPU.
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(syzgy::EvaluateHealth(fd, params), params) == syzgy::SyncMode::DUAL_POW,
        "a fully dual chain must route to DUAL_POW");
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(syzgy::EvaluateHealth(fg, params), params) == syzgy::SyncMode::SINGLE_ALO_GPU,
        "a GPU-only chain (CPU absent) past the stall threshold must route to SINGLE_ALO_GPU");
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(syzgy::EvaluateHealth(fc, params), params) == syzgy::SyncMode::SINGLE_ALO_CPU,
        "a CPU-only chain (GPU absent) past the stall threshold must route to SINGLE_ALO_CPU");

    // And the end-to-end freeze: on the GPU-only chain the CPU is the absent class, so the CPU
    // target must survive the whole five-layer pipeline bit-identical while the present GPU
    // side is free to retarget.
    {
        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(gpuOnly->tip(), nullptr, params, cpuBits, gpuBits, mode);
        BOOST_CHECK_MESSAGE(mode == syzgy::SyncMode::SINGLE_ALO_GPU,
            "the pipeline must route the GPU-only chain to SINGLE_ALO_GPU, got " << (int)mode);
        BOOST_CHECK_MESSAGE(cpuBits == syzgy::GetNextRandomXWorkRequired(gpuOnly->tip(), nullptr, params),
            "END TO END INVARIANT: the absent CPU target must survive the whole five-layer "
            "pipeline bit-identical (got 0x" << std::hex << cpuBits << ")");
        // And the symmetric end-to-end freeze on the CPU-only chain: the GPU side is frozen.
        unsigned int cpu2 = 0, gpu2 = 0;
        syzgy::SyncMode mode2 = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(cpuOnly->tip(), nullptr, params, cpu2, gpu2, mode2);
        BOOST_CHECK_MESSAGE(mode2 == syzgy::SyncMode::SINGLE_ALO_CPU,
            "the pipeline must route the CPU-only chain to SINGLE_ALO_CPU, got " << (int)mode2);
        BOOST_CHECK_MESSAGE(gpu2 == (unsigned int)HARD_BITS,
            "END TO END INVARIANT: the absent GPU target must survive the whole five-layer "
            "pipeline bit-identical (got 0x" << std::hex << gpu2 << ", expected 0x"
            << HARD_BITS << std::dec << ")");
    }

    delete dual;
    delete gpuOnly;
    delete cpuOnly;
}

BOOST_AUTO_TEST_CASE(syzgy_sync_anti_trap_valve_fires_on_regtest_chain)
{
    // The window walk cannot distinguish a stall run of 60 when the window is only 10, which is
    // why CollectDataFeed runs a SECOND, longer walk of max(window, R+1) slots. Regtest has
    // R = 60 > window = 10, so this chain is the case that breaks a window-length streak walk.
    const Consensus::Params params = RegtestParams();
    const int64_t nR = 2 * (int64_t)params.nSyzgySyncMinRatio;
    BOOST_REQUIRE_MESSAGE(nR > (int64_t)params.nSyzgySyncWindow,
        "this test is only meaningful when R exceeds the window, R=" << nR
            << " window=" << params.nSyzgySyncWindow);

// GPU-present, CPU-absent blocks, so the run being counted is the CPU stall run.
    BuiltChain* bc = BuildChain((int)nR + 10, HARD_BITS, 1700000000, 60, false, true);
    const syzgy::SyncDataFeed feed = syzgy::CollectDataFeed(bc->chain, params);
    BOOST_CHECK_MESSAGE(feed.cpuStallRun >= nR,
        "the stall run must be counted past the window length; got " << feed.cpuStallRun
            << " which is below R=" << nR);
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(syzgy::EvaluateHealth(feed, params), params) == syzgy::SyncMode::DUAL_POW,
        "the anti-trap valve must have returned DUAL_POW once the stall run reached R");

    // Just below R the emergency mode is still active -- proving the previous assertion was the
    // valve firing and not the mode simply never engaging.
    BuiltChain* shorter = BuildChain((int)nR - 1, HARD_BITS, 1700000000, 60, false, true);
    const syzgy::SyncDataFeed f2 = syzgy::CollectDataFeed(shorter->chain, params);
    BOOST_CHECK_MESSAGE(f2.cpuStallRun == nR - 1,
        "a stall run one block short of R must be counted exactly, got " << f2.cpuStallRun);
    BOOST_CHECK_MESSAGE(syzgy::RouteMode(syzgy::EvaluateHealth(f2, params), params) == syzgy::SyncMode::SINGLE_ALO_GPU,
        "one block short of R the network must still be in SINGLE_ALO_GPU emergency mode");

    delete bc;
    delete shorter;
}

BOOST_AUTO_TEST_CASE(syzgy_consensus_params_are_wired_on_every_network)
{
    // FR-04 and the emergency machinery must be reachable on all three networks, and regtest
    // must carry the short values that make the machinery testable at all.
    const Consensus::Params& main = MainParams();
    BOOST_CHECK_MESSAGE(main.nMaxFutureBlockTime == 15 * 60,
        "FR-04: main nMaxFutureBlockTime must be 900, got " << main.nMaxFutureBlockTime);
    BOOST_CHECK_MESSAGE(main.nSyzgyPairingStallBlocks == 6,
        "main nSyzgyPairingStallBlocks must be 6, got " << main.nSyzgyPairingStallBlocks);
    BOOST_CHECK_MESSAGE(main.nSyzgyRandomXPrepBlocks == 720,
        "main nSyzgyRandomXPrepBlocks must be 720 (the exact name is load-bearing), got "
            << main.nSyzgyRandomXPrepBlocks);
    BOOST_CHECK_MESSAGE(main.nSyzgyRandomXEpochLength == 129600,
        "main nSyzgyRandomXEpochLength must be 129600, got " << main.nSyzgyRandomXEpochLength);
    BOOST_CHECK_MESSAGE(main.nSyzgyGpuRewardPercent + main.nSyzgyCpuRewardPercent == 100,
        "the GPU and CPU reward shares must sum to 100 percent");
    BOOST_CHECK_MESSAGE(main.randomxLimit == main.kawpowLimit,
        "a fresh chain must start both algorithms at the same easiest target");
    BOOST_CHECK_MESSAGE(main.nSyzgyTailEmission == 50000000,
        "the tail emission must be 0.5 SYZ in satoshi, got " << main.nSyzgyTailEmission);

    const Consensus::Params test = MakeParams(CBaseChainParams::TESTNET)->GetConsensus();
    BOOST_CHECK_MESSAGE(test.nSyzgyPairingStallBlocks == 6,
        "testnet nSyzgyPairingStallBlocks must be 6, got " << test.nSyzgyPairingStallBlocks);
    BOOST_CHECK_MESSAGE(test.randomxLimit == test.kawpowLimit,
        "testnet must start both algorithms at the same easiest target");

    const Consensus::Params reg = RegtestParams();
    BOOST_CHECK_MESSAGE(reg.nSyzgySyncWindow == 10,
        "regtest nSyzgySyncWindow must be 10 so the machinery is reachable, got "
            << reg.nSyzgySyncWindow);
    BOOST_CHECK_MESSAGE(reg.nSyzgyPairingStallBlocks == 2,
        "regtest nSyzgyPairingStallBlocks must be 2, got " << reg.nSyzgyPairingStallBlocks);
    BOOST_CHECK_MESSAGE(reg.nSyzgyRandomXEpochLength == 50,
        "regtest nSyzgyRandomXEpochLength must be 50, got " << reg.nSyzgyRandomXEpochLength);
    BOOST_CHECK_MESSAGE(reg.nSyzgyRandomXPrepBlocks == 5,
        "regtest nSyzgyRandomXPrepBlocks must be 5, got " << reg.nSyzgyRandomXPrepBlocks);
    BOOST_CHECK_MESSAGE(reg.nSyzgySyncMinRatio == 30,
        "regtest nSyzgySyncMinRatio must be 30, got " << reg.nSyzgySyncMinRatio);
    BOOST_CHECK_MESSAGE(reg.randomxLimit == reg.kawpowLimit,
        "regtest must start both algorithms at the same target");
    BOOST_CHECK_MESSAGE(reg.nSyzgyTailEmissionThreshold == 1 * COIN,
        "the tail emission threshold must be 1 SYZ, got " << reg.nSyzgyTailEmissionThreshold);
}

BOOST_AUTO_TEST_SUITE_END()