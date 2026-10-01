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
#include "pow.h"
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
    // NOTE ON THE GUARD BAND. Step 5 clamps the TOTAL window timespan into [T_target/3,
    // T_target*3], i.e. TOTAL-relative (mainnet: [1780s, 16020s]). This chain is on time, so
    // T_actual = 9 * 60 = 540 = T_target exactly, which sits INSIDE the band and is not
    // touched; T_new = T_avg * T_target / T_target = T_avg. That is the whole point of the
    // corrected band: a correctly-timed chain must reproduce its own average target, not a
    // fraction of it. See syzgy_lwma_target_does_not_collapse below.
    //
    // The chain below is built at HARD_BITS rather than at the ceiling, so that "the answer is
    // no longer the ceiling" is a statement with teeth: on regtest randomxLimit's own compact
    // form IS 0x207fffff, so an EASY_BITS chain would prove nothing.
    const Consensus::Params rp = params;
    const int64_t nM = rp.nSyzgySyncWindow - 1;
    const int64_t nT = nM * rp.nSyzgySyncTargetBlockSeconds;
    const unsigned int kAtBoundary = syzgy::CalculateLWMANextWorkRequired(
        arith_uint256().SetCompact(HARD_BITS), nM, nT, nT,
        UintToArith256(rp.randomxLimit));
    BuiltChain* bc2 = BuildChain(9, HARD_BITS, 1000000, 60, true, true);
    BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(bc2->tip(), nullptr, params) == kAtBoundary,
        "at exactly tip->nHeight == M the window walk must run and produce the spec-derived "
        "target (got " << syzgy::GetNextRandomXWorkRequired(bc2->tip(), nullptr, params)
        << ", expected " << kAtBoundary << ")");
    BOOST_CHECK_MESSAGE(kAtBoundary == HARD_BITS,
        "an on-time window must leave the target exactly where the window average already had "
        "it, got " << kAtBoundary << " expected " << HARD_BITS);
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
    const int64_t nTarget = M * S;                      // T_target = 540
    // Step 5's band, TOTAL-relative: [T_target/3, T_target*3] = [180, 1620] seconds of TOTAL
    // window time. Regtest deliberately uses a tiny window, so 3x is reached at 180s spacing.
    const int64_t nBandLo = nTarget / 3;
    const int64_t nBandHi = nTarget * 3;

    // Reference answer: the target that the upper guard band produces, derived straight from
    // spec steps 5/6 -- T_actual pulled back to 3*T_target, so T_new = T_avg * 3.
    const arith_uint256 bnAvg = arith_uint256().SetCompact(HARD_BITS);
    const arith_uint256 bnLimit = arith_uint256().SetCompact(EASY_BITS);
    const unsigned int kExpected =
        syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nBandHi, nTarget, bnLimit);
    const unsigned int kExpectedLow =
        syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nBandLo, nTarget, bnLimit);

    // Sanity on the band edges themselves: inside the band the arithmetic is exact, so a 2x-slow
    // window yields exactly twice the average.
    {
        const unsigned int k2x = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, 2 * nTarget, nTarget, bnLimit);
        const arith_uint256 want = arith_uint256().SetCompact(arith_uint256(bnAvg * arith_uint256((uint64_t)2)).GetCompact());
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(k2x) == want,
            "a 2x-slow window lies inside the band and must be tracked exactly (got "
                << arith_uint256().SetCompact(k2x).GetHex() << " want " << want.GetHex() << ")");
        BOOST_CHECK_MESSAGE(nBandHi == 1620 && nBandLo == 180,
            "the regtest guard band must be [180, 1620] seconds of total window time, got ["
                << nBandLo << ", " << nBandHi << "]");
    }

    // End to end: blocks 10x slower than target. Raw T_actual = 10 * T_target = 5400, which is
    // above the 1620s ceiling and must be pulled back to exactly T_target*3.
    BuiltChain* slow = BuildChain(14, HARD_BITS, 1700000000, 10 * S, true, true);
    const unsigned int uSlow = syzgy::GetNextRandomXWorkRequired(slow->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uSlow == kExpected,
        "a 10x-slow window must clamp to the 3x guard band (got " << uSlow
            << ", expected " << kExpected << ")");

    // A chain at exactly 3x per-block spacing must give the identical answer.
    BuiltChain* edge = BuildChain(14, HARD_BITS, 1700000000, 3 * S, true, true);
    const unsigned int uEdge = syzgy::GetNextRandomXWorkRequired(edge->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uEdge == kExpected,
        "an exactly-3x window is the clamp boundary and must match the clamped 10x window");

    // And the low side: the guard band floor is T_target/3 = 180 seconds of TOTAL window time.
    // A 14-block window at 1s per block spans 9s over the averaged samples, which is under the
    // floor and must be pulled up to exactly T_target/3.
    BuiltChain* fast = BuildChain(14, HARD_BITS, 1700000000, 1, true, true);
    const unsigned int uFast = syzgy::GetNextRandomXWorkRequired(fast->tip(), nullptr, params);
    BOOST_CHECK_MESSAGE(uFast == kExpectedLow,
        "a window far faster than target must clamp to the T_target/3 guard band (got " << uFast
            << ", expected " << kExpectedLow << ")");
    BOOST_CHECK_MESSAGE(kExpectedLow != kExpected,
        "the low and high clamp bands must produce different targets, otherwise this test is "
        "not distinguishing anything");

    delete slow;
    delete edge;
    delete fast;
}

// -------------------------------------------------------------------------------------------
// REGRESSION: the step-5 units defect. Before the fix the band was [T_target/M/3, T_target/M*3]
// = [S/3, 3S] -- a PER-BLOCK bound applied to the TOTAL window timespan -- so its upper bound
// always bound and every window returned T_avg * 3/M, ratcheting the CPU target toward zero
// difficulty. These two tests are the lock on the fix.
// -------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(syzgy_lwma_target_does_not_collapse)
{
    // THE FR-02 TEST. A chain whose blocks arrive exactly on time must keep its target, window
    // after window, forever. Under the defective band the answer was T_avg/3 for regtest and
    // T_avg/29.7 for mainnet on EVERY window, so this chain would slide toward zero difficulty
    // with no misbehaviour on the network's part at all.
    const Consensus::Params params = RegtestParams();
    const int64_t S = params.nSyzgySyncTargetBlockSeconds;
    const int64_t M = params.nSyzgySyncWindow - 1;
    const int64_t nTarget = M * S;

    // 40 windows' worth of history, every block exactly S apart and every nBits identical, so the
    // weighted average T_avg is exactly SetCompact(HARD_BITS) throughout and the only thing that
    // can move the answer is the clamp.
    BuiltChain* bc = BuildChain(4 * (int)M, HARD_BITS, 1700000000, S, true, true);

    unsigned int prev = HARD_BITS;
    const arith_uint256 bnPrev = arith_uint256().SetCompact(HARD_BITS);
    const arith_uint256 bnLimit = UintToArith256(params.randomxLimit);
    for (int h = (int)M; h <= 4 * (int)M; ++h) {
        const unsigned int next = syzgy::GetNextRandomXWorkRequired(bc->blocks[h], nullptr, params);
        // Exact: an on-time window has T_actual == T_target, so step 6's ratio is exactly 1 and
        // the target comes back exactly where the window average already had it.
        BOOST_CHECK_MESSAGE(next == prev,
            "an on-time chain must not ratchet its target at height " << h << " (got 0x"
                << std::hex << next << ", previous 0x" << prev << std::dec << ")");
        // And a tolerance-style statement of the same thing, so the intent survives any future
        // re-derivation of the exact values: never more than 1% away from the previous target.
        const arith_uint256 bn = arith_uint256().SetCompact(next);
        BOOST_CHECK_MESSAGE(bn * arith_uint256((uint64_t)100) >= bnPrev * arith_uint256((uint64_t)99)
                                && bn * arith_uint256((uint64_t)100) <= bnPrev * arith_uint256((uint64_t)101),
            "an on-time chain must keep the target within 1% of the previous one, moved "
                << bnPrev.GetHex() << " -> " << bn.GetHex());
        BOOST_CHECK_MESSAGE(bn <= bnLimit, "the target must never exceed randomxLimit");
        prev = next;
    }

    // The step that would have collapsed it, spelled out: on-time must equal the raw average,
    // not average/M * 3.
    BOOST_CHECK_MESSAGE(prev == HARD_BITS,
        "after 4 windows an on-time chain must still sit exactly on its window average, got "
            << std::hex << prev << " expected " << HARD_BITS << std::dec);
    BOOST_CHECK_MESSAGE(nTarget == 540,
        "this test's arithmetic assumes regtest T_target == 540, got " << nTarget);

    delete bc;
}

BOOST_AUTO_TEST_CASE(syzgy_lwma_tracks_genuine_3x_hashrance)
{
    // The other side of the same fix: the band must not be so WIDE that it ignores real
    // difficulty movement, nor so TIGHT that it breaks FR-02 (blocks pinned to 60s).
    //
    // A 3x hashrate change means blocks arrive 3x faster, i.e. every S/3 seconds, so
    // T_actual = M*(S/3) = T_target/3 -- which is exactly the band's LOWER BOUND. Step 6 then
    // divides by 3 and the difficulty genuinely triples. Nothing is clamped away.
    const Consensus::Params params = RegtestParams();
    const int64_t S = params.nSyzgySyncTargetBlockSeconds;
    const int64_t M = params.nSyzgySyncWindow - 1;
    const int64_t nTarget = M * S;
    const int64_t nThird = S / 3;               // per-block time at 3x hashrate
    const int64_t nThirdTotal = M * nThird;     // M*(S/3) = T_target/3, the band's lower bound
    const arith_uint256 bnAvg = arith_uint256().SetCompact(HARD_BITS);
    const arith_uint256 bnLimit = UintToArith256(params.randomxLimit);

    // 3x hashrate IN: block time S/3 = 20s, T_actual = 180 = T_target/3.
    {
        const unsigned int got = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nThirdTotal, nTarget, bnLimit);
        // GetCompact() drops the low mantissa bits, so the comparison is made through a round
        // trip on both sides: an assertion about the arithmetic, not about mantissa truncation.
        const arith_uint256 want = arith_uint256().SetCompact(arith_uint256(bnAvg / arith_uint256((uint64_t)3)).GetCompact());
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(got) == want,
            "a genuine 3x hashrate increase must triple the difficulty exactly (got "
                << arith_uint256().SetCompact(got).GetHex() << " want " << want.GetHex() << ")");
        BOOST_CHECK_MESSAGE(got < HARD_BITS,
            "a 3x hashrate increase must move the target toward zero difficulty (FR-02, harder "
            "is fine) -- got 0x" << std::hex << got << " from 0x" << HARD_BITS << std::dec);
    }

    // 3x hashrate OUT: block time 3S = 180s, T_actual = 1620 = T_target*3.
    {
        const unsigned int got = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nTarget * 3, nTarget, bnLimit);
        const arith_uint256 want = arith_uint256().SetCompact(arith_uint256(bnAvg * arith_uint256((uint64_t)3)).GetCompact());
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(got) == want,
            "a genuine 3x hashrate drop must divide the difficulty by 3 exactly (got "
                << arith_uint256().SetCompact(got).GetHex() << " want " << want.GetHex() << ")");
        BOOST_CHECK_MESSAGE(got > HARD_BITS,
            "a 3x hashrate drop must move the target toward zero difficulty (FR-02) -- got 0x"
                << std::hex << got << " from 0x" << HARD_BITS << std::dec);
    }

    // Same thing end to end through the index walk, so the clamp is exercised on real B_k data
    // rather than on the raw arithmetic.
    {
        BuiltChain* faster = BuildChain(14, HARD_BITS, 1700000000, nThird, true, true);
        const unsigned int uFaster =
            syzgy::GetNextRandomXWorkRequired(faster->tip(), nullptr, params);
        const unsigned int wantFaster =
            syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nThirdTotal, nTarget, bnLimit);
        BOOST_CHECK_MESSAGE(uFaster == wantFaster,
            "end to end: a chain at S/3 spacing must land exactly on the T_target/3 bound (got 0x"
                << std::hex << uFaster << ", expected 0x" << wantFaster << std::dec << ")");
        BOOST_CHECK_MESSAGE(uFaster < HARD_BITS,
            "end to end: a 3x-faster chain must not be frozen at the previous target");
        delete faster;
    }
    {
        BuiltChain* slower = BuildChain(14, HARD_BITS, 1700000000, 3 * S, true, true);
        const unsigned int uSlower =
            syzgy::GetNextRandomXWorkRequired(slower->tip(), nullptr, params);
        const unsigned int wantSlower =
            syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nTarget * 3, nTarget, bnLimit);
        BOOST_CHECK_MESSAGE(uSlower == wantSlower,
            "end to end: a chain at 3S spacing must land exactly on the 3*T_target bound (got 0x"
                << std::hex << uSlower << ", expected 0x" << wantSlower << std::dec << ")");
        BOOST_CHECK_MESSAGE(uSlower > HARD_BITS,
            "end to end: a 3x-slower chain must raise the difficulty, i.e. lower the target value "
            "toward zero difficulty without being clamped flat");
        delete slower;
    }

    // NOT too tight: an on-time chain (T_actual == T_target) must be left completely alone --
    // a band tighter than [T_target/3, 3*T_target] would already have begun distorting it.
    {
        BuiltChain* onTime = BuildChain(14, HARD_BITS, 1700000000, S, true, true);
        BOOST_CHECK_MESSAGE(syzgy::GetNextRandomXWorkRequired(onTime->tip(), nullptr, params) == HARD_BITS,
            "an on-time chain must be left exactly untouched by the guard band");
        delete onTime;
    }

    // And the band's own limits: 4x slower is outside the band and must be pinned to the bound
    // rather than followed, which is what bounds a single retarget's reaction to a stale chain.
    {
        const unsigned int got = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nTarget * 4, nTarget, bnLimit);
        const unsigned int atBound = syzgy::CalculateLWMANextWorkRequired(bnAvg, M, nTarget * 3, nTarget, bnLimit);
        BOOST_CHECK_MESSAGE(got == atBound,
            "a 4x-slow window must be pinned to the 3x bound, not followed to 4x");
    }
}

// -------------------------------------------------------------------------------------------
// REGRESSION: two 256-bit overflows in the LWMA arithmetic itself (steps 3 and 6). Both are
// reachable in normal operation, because randomxLimit on a fresh chain -- and on ALL of regtest
// -- is 0x7fff...ff, so "a target near the ceiling" is the normal state at low height, not an
// edge case.
// -------------------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(syzgy_lwma_arithmetic_does_not_overflow_at_the_ceiling)
{
    const Consensus::Params params = RegtestParams();

    // STEP 3. The weighted sum of nine ceiling-valued samples is ~2^260 and wrapped mod 2^256,
    // which made an on-time window at the ceiling return 0x202d8cc instead of the ceiling itself.
    // kCeiling is regtest randomxLimit's compact form; a chain sitting exactly on it must come
    // back exactly on it.
    const unsigned int kCeiling = UintToArith256(params.randomxLimit).GetCompact();
    BOOST_REQUIRE_MESSAGE(kCeiling == EASY_BITS,
        "this test assumes regtest randomxLimit compact == 0x207fffff, got " << kCeiling);
    {
        BuiltChain* atCeiling = BuildChain(9, EASY_BITS, 1000000, 60, true, true);
        const unsigned int got = syzgy::GetNextRandomXWorkRequired(atCeiling->tip(), nullptr, params);
        BOOST_CHECK_MESSAGE(got == EASY_BITS,
            "STEP 3 OVERFLOW: an on-time window whose every sample is the ceiling must return the "
            "ceiling, got " << std::hex << got << " expected 0x" << EASY_BITS << std::dec
            << " (0x202d8cc here is the signature of the wrapped weighted sum)");
        delete atCeiling;
    }

    // STEP 6. `T_avg * T_actual` alone exceeds 256 bits at the ceiling even when T_actual ==
    // T_target, i.e. when the retarget is a no-op. The exact quotient must be T_avg itself.
    {
        const arith_uint256 bnCeiling = UintToArith256(params.randomxLimit);
        const int64_t nT = 540;                       // M * S on regtest
        const unsigned int got = syzgy::CalculateLWMANextWorkRequired(
            bnCeiling, 9, nT, nT, bnCeiling);
        // Compared in COMPACT space: GetCompact() is a lossy encoding, so the round trip of the
        // exact 2^256-1 is not 2^256-1. The assertion is that the function returns precisely the
        // compact form of its own input, with no arithmetic at all done to it.
        const unsigned int want = bnCeiling.GetCompact();
        BOOST_CHECK_MESSAGE(got == want,
            "STEP 6 OVERFLOW: T_new = T_avg * T_target / T_target must be exactly T_avg, got "
                << std::hex << got << " want " << want << std::dec
                << " (0x1f7956eb here is the signature of the wrapped multiply)");
    }

    // AND the helper must be a fix, not a retune: wherever the naive 256-bit expression does
    // not overflow, the two agree bit for bit. HARD_BITS is far enough below the ceiling for
    // every product here to fit.
    {
        const arith_uint256 bnAvg = arith_uint256().SetCompact(HARD_BITS);
        const arith_uint256 bnLimit = UintToArith256(params.randomxLimit);
        const int64_t ratios[] = {180, 200, 540, 900, 1500, 1620};
        for (size_t i = 0; i < sizeof(ratios) / sizeof(ratios[0]); ++i) {
            const int64_t t = ratios[i];
            const unsigned int got = syzgy::CalculateLWMANextWorkRequired(bnAvg, 9, t, 540, bnLimit);
            const unsigned int naive = arith_uint256(
                (bnAvg * arith_uint256((uint64_t)t)) / arith_uint256((uint64_t)540)).GetCompact();
            BOOST_CHECK_MESSAGE(got == naive,
                "the 512-bit step 6 must agree with the naive 256-bit expression wherever that "
                    "one does not overflow (T_actual=" << t << ", got 0x" << std::hex << got
                    << ", naive 0x" << naive << std::dec << ")");
        }
    }
}

// -------------------------------------------------------------------------------------------
// Sync Controller
// -------------------------------------------------------------------------------------------

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

// -------------------------------------------------------------------------------------------
// FR-03 -- the GPU side retargets against kawpowLimit, NOT powLimit
// -------------------------------------------------------------------------------------------

/**
 * THE FR-03 PER-ALGORITHM TEST.
 *
 * Why this test has to build its own params. On all three shipped networks
 * powLimit == kawpowLimit == randomxLimit, so a test written against the real params CANNOT
 * distinguish "the GPU retargets against kawpowLimit" from "the GPU retargets against
 * powLimit" -- both produce the same number and the test passes either way. That is a test
 * that proves nothing.
 *
 * So this test constructs a params copy in which the two limits DELIBERATELY DIFFER, with
 * powLimit made EASIER (numerically larger) than kawpowLimit:
 *
 *     powLimit    = 0x7fff...ff   -> compact 0x207fffff   (the EASY one; the wrong answer)
 *     kawpowLimit = SetCompact(0x1d00ffff)  ~2^224      (the HARD one; the RIGHT answer)
 *
 * Any code path that still reads powLimit for the GPU side now returns 0x207fffff and fails
 * these assertions; only a path that reads kawpowLimit returns 0x1d00ffff. randomxLimit is
 * set equal to kawpowLimit so the CPU side is unaffected by the substitution and any failure
 * is unambiguously on the GPU half.
 */
BOOST_AUTO_TEST_CASE(syzgy_gpu_side_retargets_against_kawpow_limit)
{
    Consensus::Params params = RegtestParams();

    const unsigned int kKawpowBits = 0x1d00ffff;
    params.kawpowLimit  = ArithToUint256(arith_uint256().SetCompact(kKawpowBits));
    params.randomxLimit = params.kawpowLimit;
    params.powLimit     = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    // The legacy min-difficulty shortcut inside DarkGravityWave is a single-algorithm rule
    // that predates dual-PoW and returns powLimit; it is disabled here so that the assertion
    // below is about the RETARGET bound, not about that pre-KawPoW special case.
    params.fPowAllowMinDifficultyBlocks = false;

    const unsigned int kPowLimitBits = UintToArith256(params.powLimit).GetCompact();
    BOOST_REQUIRE_MESSAGE(kPowLimitBits != kKawpowBits,
        "this test is only meaningful when powLimit and kawpowLimit disagree, got 0x"
            << std::hex << kPowLimitBits << " for both" << std::dec);
    BOOST_REQUIRE_MESSAGE(arith_uint256().SetCompact(kKawpowBits) < UintToArith256(params.powLimit),
        "this test needs powLimit to be the EASIER of the two, otherwise the two possible wrong "
        "and right answers are not distinguishable");

    // --- Layer 5: the guardrail ceiling on the GPU side ------------------------------
    {
        // Ask for a GPU target far above kawpowLimit. The only bound that may apply is
        // kawpowLimit itself, so the band is opened wide enough that the +/-n% guardrail can
        // never be what clamps first. If the ceiling were powLimit the answer would be
        // kPowLimitBits.
        Consensus::Params wide = params;
        wide.nSyzgySyncMaxRetargetPercent = 100000;
        const syzgy::SyncGuardrails g =
            syzgy::ApplyGuardrails(kKawpowBits, kKawpowBits, kPowLimitBits, kPowLimitBits, wide);
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(g.nextGpuBits)
                                == arith_uint256().SetCompact(kKawpowBits),
            "FR-03: the GPU target must be clamped to kawpowLimit, not powLimit (got 0x"
                << std::hex << g.nextGpuBits << ", powLimit compact 0x" << kPowLimitBits
                << ", kawpowLimit compact 0x" << kKawpowBits << std::dec << ")");
        // The CPU side is bounded by ITS OWN limit, which is a different field; here it is
        // coincidentally the same value, so the assertion pins only that the CPU side is not
        // accidentally bounded by the (easier) powLimit either.
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(g.nextCpuBits) <= UintToArith256(params.randomxLimit),
            "FR-03: the CPU target must be clamped to randomxLimit, not powLimit");
    }

    // --- Layer 4: Dark Gravity Wave itself ------------------------------------------
    {
        // A 250-block chain, past regtest's nDGWActivationBlock of 200, so GetNextWorkRequired
        // really dispatches to DarkGravityWave. Every block sits at 0x207fffff -- i.e. at
        // powLimit, which is EASIER than kawpowLimit -- and every block is exactly 60 s apart,
        // so DGW's own arithmetic is an identity and kawpowLimit is the only thing that can
        // move the answer.
        BuiltChain* bc = BuildChain(250, kPowLimitBits, 1700000000, 60, true, true);
        CBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.nHeight = 251;
        hdr.nBits = kPowLimitBits;
        hdr.nTime = (uint32_t)(1700000000 + 250 * 60);

        const unsigned int gpu = GetNextWorkRequired(bc->tip(), &hdr, params);
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(gpu) == arith_uint256().SetCompact(kKawpowBits),
            "FR-03: Dark Gravity Wave must bound the GPU target at kawpowLimit, not powLimit "
                "(got 0x" << std::hex << gpu << "; powLimit would be 0x" << kPowLimitBits
                << ", kawpowLimit is 0x" << kKawpowBits << std::dec << ")");

        // The negative control, so the assertion above is not passing by accident: the same
        // call against the UNMODIFIED regtest params (where both limits are 0x207fffff) must
        // return 0x207fffff. Two different params, two different answers, one field apart.
        {
            const Consensus::Params plain = RegtestParams();
            const unsigned int gpuPlain = GetNextWorkRequired(bc->tip(), &hdr, plain);
            BOOST_CHECK_MESSAGE(gpuPlain == kPowLimitBits,
                "the negative control must return the regtest powLimit compact (0x"
                    << std::hex << gpuPlain << " vs 0x" << kPowLimitBits << std::dec
                << "); if this fails the test above proves nothing");
        }

        delete bc;
    }

    // --- The wiring: GetNextDualWorkRequired must not leak powLimit to the GPU side ----
    {
        // Same chain, but through the full five-layer pipeline. Both classes are present, so
        // neither is frozen, and the pipeline's GPU output must still respect kawpowLimit.
        //
        // pblock is nullptr on purpose: the chain is synthetic and its indexes are not in
        // mapBlockIndex, so a header with a hashPrevBlock would take the unresolvable-parent
        // fail-closed branch instead of the retarget branch this assertion is about. That
        // branch is exercised separately, below.
        BuiltChain* bc = BuildChain(250, kPowLimitBits, 1700000000, 60, true, true);

        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
        syzgy::GetNextDualWorkRequired(bc->tip(), nullptr, params, cpuBits, gpuBits, mode);
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(gpuBits) <= UintToArith256(params.kawpowLimit),
            "FR-03: the Sync Controller's GPU output must never exceed kawpowLimit, even when the "
                "chain's own nBits sits at the (easier) powLimit (got 0x" << std::hex << gpuBits
                << ")" << std::dec);
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(cpuBits) <= UintToArith256(params.randomxLimit),
            "FR-03: the Sync Controller's CPU output must never exceed randomxLimit (got 0x"
                << std::hex << cpuBits << ")" << std::dec);
        BOOST_REQUIRE_MESSAGE(mode == syzgy::SyncMode::DUAL_POW,
            "a fully dual chain must route to DUAL_POW, got " << (int)mode);
        delete bc;
    }

    // --- The unresolvable-parent fail-closed branch ------------------------------------
    {
        // A header whose hashPrevBlock is not in mapBlockIndex cannot be placed, so the
        // pipeline must not guess. It holds the parent's target and stays in DUAL_POW -- and
        // it must still respect the per-algorithm ceilings on that held value, because the
        // parent's nBits here is the powLimit, which is EASIER than kawpowLimit by
        // construction. Before the guardrails were applied on this path the GPU output was
        // the raw parent nBits, i.e. 0x207fffff, which is above kawpowLimit. That was found
        // by this test, not by inspection.
        BuiltChain* bc = BuildChain(3, kPowLimitBits, 1700000000, 60, true, true);
        CBlockHeader orphan;
        orphan.nVersion = 4;
        orphan.nHeight = 4;
        orphan.nBits = kPowLimitBits;
        orphan.nTime = (uint32_t)(1700000000 + 4 * 60);
        orphan.hashPrevBlock = uint256S("000000000000000000000000000000000000000000000000000000000000dead");

        unsigned int cpuBits = 0, gpuBits = 0;
        syzgy::SyncMode mode = syzgy::SyncMode::SINGLE_ALO_CPU;
        syzgy::GetNextDualWorkRequired(bc->tip(), &orphan, params, cpuBits, gpuBits, mode);
        BOOST_CHECK_MESSAGE(mode == syzgy::SyncMode::DUAL_POW,
            "an unplaceable header must fall back to strict DUAL_PoW, never to an emergency mode "
                "that would drop a proof obligation");
        BOOST_CHECK_MESSAGE(arith_uint256().SetCompact(gpuBits) <= UintToArith256(params.kawpowLimit),
            "FR-03: the fail-closed branch must still clamp the held GPU target to kawpowLimit "
                "(got 0x" << std::hex << gpuBits << ", kawpowLimit 0x" << kKawpowBits << std::dec
                << ")");
        delete bc;
    }
}

BOOST_AUTO_TEST_SUITE_END()