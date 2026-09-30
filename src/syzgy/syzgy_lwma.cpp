// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * ============================================================================================
 * SYZGY RandomX (CPU) difficulty -- LWMA-2, Monero style.
 * ============================================================================================
 *
 * This file is deliberately written so that the entire retarget rule can be verified from this
 * comment alone, without reading the rest of the file. It is the CPU half of the SYZGY dual-PoW
 * difficulty engine; the GPU half is Dark Gravity Wave (src/pow.cpp).
 *
 * WHY LWMA AND NOT DGW FOR THE CPU SIDE
 * -------------------------------------
 * The CPU class is home PCs and VPS. Its aggregate hashrate is volatile: miners switch machines,
 * a VPS provider is throttled, a laptop sleeps. DGW is an exponential moving average with a
 * long memory and reacts far too late to a step change in hashrate, which on the CPU side
 * manifests as multi-hour block-time excursions. LWMA weights recent blocks linearly, so a
 * hashrate change is fully reflected within a few blocks. That responsiveness is the entire
 * reason the two sides use different algorithms (design decision D3).
 *
 * THE ALGORITHM, EXACTLY
 * ---------------------
 * Let:
 *     N = params.nSyzgySyncWindow                 (90 main / 10 regtest)
 *     M = N - 1                                   number of samples; the oldest sample is dropped
 *     S = params.nSyzgySyncTargetBlockSeconds     (60)
 *     L = UintToArith256(params.randomxLimit)     the per-algorithm CPU target CEILING
 * and let B_k denote the block index entry at height (tipHeight - k + 1), so B_1 is the tip.
 *
 *  Step 1 -- BOOTSTRAP.
 *      if (pindexLast == nullptr || pindexLast->nHeight < M)
 *          return L.GetCompact();
 *      Not enough history to average: the only legal answer is the ceiling, which is the easiest
 *      legal target. This also makes the result identical on every node at a given height.
 *
 *  Step 2 -- WEIGHTS.
 *      w_i = (M + 1) - i     for i = 1..M
 *      so w_1 = M (the tip, heaviest) down to w_M = 1 (the oldest of the M samples, lightest).
 *      Dropping the (M+1)-th oldest block is the LWMA-2 convention: it keeps the weight
 *      sequence a run of consecutive integers so the sum is exactly W = M(M+1)/2, which makes
 *      the average exact in integer arithmetic instead of approximate.
 *
 *  Step 3 -- WEIGHTED AVERAGE TARGET.
 *      T_avg = ( sum over i=1..M of ( w_i * SetCompact(B_i.nBits) ) ) / W,      W = M(M+1)/2
 *      256-bit integer division, truncation toward zero.
 *      A window sample whose compact nBits does not fit in 256 bits (negative or overflow) is
 *      treated as L, i.e. as the easiest legal target. A malformed sample therefore widens the
 *      window towards the ceiling; it can never produce a target above the ceiling.
 *
 *  Step 4 -- OBSERVED TIMESPAN.
 *      T_actual = B_1.nTime - B_{M+1}.nTime
 *      B_{M+1} is one block older than the oldest averaged sample, so T_actual spans exactly the
 *      M block intervals whose targets were averaged. Signed, because block timestamps are not
 *      required to be monotonic.
 *
 *  Step 5 -- TARGET TIMESPAN AND CLAMP.
 *      T_target = M * S
 *      T_actual is clamped into [ T_target/M/3, T_target/M*3 ] = [ S/3, 3S ]  ( [20s, 180s] )
 *      The 3x band is the whole point of the algorithm: it bounds a single retarget's reaction to
 *      a manipulated or wildly stale timestamp.
 *
 *      >>> OPEN SPEC ISSUE, FLAGGED TO THE FOUNDER, NOT WORKED AROUND HERE. <<<
 *      Note the units. T_actual is a TOTAL window timespan (step 4) and T_target is a total as
 *      well (M * S), so step 6's ratio is dimensionally sound. But the clamp band [T_target/M/3,
 *      T_target/M*3] = [S/3, 3S] is a PER-BLOCK quantity, and it is being applied to a TOTAL.
 *      On a correctly-timed network T_actual ~ M*S is one to two orders of magnitude larger
 *      than 3S, so the upper clamp ALWAYS binds: T_new = T_avg * 3S / (M*S) = T_avg * 3/M.
 *      With the production M = 89 that is T_avg / 29.7 EVERY window -- a monotone collapse of the
 *      CPU target toward zero difficulty, i.e. exactly the sub-second-spam failure mode the
 *      whole freeze/guardrail design exists to prevent (FR-02). The regtest numbers are less
 *      extreme (M = 9 -> T_avg/3) but still a collapse.
 *      This implementation follows the specification LITERALLY, because deviating unilaterally
 *      would put this node's CPU target on a different chain from any other implementation and
 *      silently fork the network. The likely intended band is a fraction of the TOTAL, e.g.
 *      clamp T_actual into [ T_target*3/4, T_target*5/4 ] or [ T_target/M*3, T_target*M*3 ],
 *      which only bites on genuinely anomalous timestamps. That is a consensus-parameter change
 *      and is the founder's call, not this file's.
 *
 *  Step 6 -- NEW TARGET.
 *      T_new = T_avg * T_actual / T_target
 *      256-bit integer division. If the blocks arrived slower than targeted (T_actual > T_target)
 *      the target value rises, i.e. the difficulty falls, which is correct: lower the target to
 *      make blocks easier.
 *
 *  Step 7 -- CEILING AND FLOOR.
 *      clamp T_new into [1, L]; return T_new.GetCompact().
 *
 *  Step 8 -- DEGENERATE CASES -> HOLD.
 *      if (M < 1) or (T_target <= 0) or (T_actual == 0 before the step-5 clamp)
 *          return T_avg.GetCompact();
 *      "Hold" means: emit the weighted average, i.e. make no adjustment at all. Note this is
 *      taken on the RAW T_actual; a zero raw timespan is a distinct fact (every sampled block
 *      shares one timestamp) and is a hold, whereas a raw timespan outside the band is clamped
 *      and still retargets. M < 1 (nSyzgySyncWindow < 2) can never produce T_target > 0 with a
 *      positive sample count, so it is unreachable in a correctly configured network but is
 *      checked anyway: no division is ever performed by zero or negative on this path.
 *
 * DETERMINISM
 * -----------
 * Everything above is a function of committed block data (nTime, nBits) and of params. No wall
 * clock is read, no static or mutable state exists, `pblock` is never dereferenced. The same
 * index chain yields the same compact target on every node, on every run.
 * ============================================================================================
 */

#include "syzgy/syzgy_lwma.h"

#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

namespace syzgy {

namespace {

/** Largest sample that may be averaged, as a sanity ceiling on a misconfigured params value. */
const int64_t LWMA_MAX_SAMPLES = 100000;

} // namespace

unsigned int CalculateLWMANextWorkRequired(const arith_uint256& bnPastTargetAvg,
                                           int64_t nPastBlocks, int64_t nActualTimespan,
                                           int64_t nTargetTimespan, const arith_uint256& bnLimit)
{
    // Step 8 (precondition): a non-positive target timespan makes the step-6 division
    // meaningless, and a non-positive sample count makes the weight sum meaningless. Hold.
    if (nPastBlocks < 1 || nTargetTimespan <= 0) {
        return bnPastTargetAvg.GetCompact();
    }

    // Step 5 (precondition): T_actual == 0 BEFORE clamping is a hold, not a retarget. Every
    // block in the window shares one timestamp, so there is no signal to act on.
    if (nActualTimespan == 0) {
        return bnPastTargetAvg.GetCompact();
    }

    // Step 5: T_target / M == S exactly, because T_target was built as M * S. A non-positive
    // value here means S <= 0, which the nTargetTimespan check above already excludes.
    const int64_t nAvgBlockTime = nTargetTimespan / nPastBlocks;
    if (nAvgBlockTime <= 0) {
        return bnPastTargetAvg.GetCompact();
    }
    const int64_t nMinTimespan = nAvgBlockTime / 3;
    const int64_t nMaxTimespan = nAvgBlockTime * 3;
    if (nActualTimespan < nMinTimespan) nActualTimespan = nMinTimespan;
    if (nActualTimespan > nMaxTimespan) nActualTimespan = nMaxTimespan;

    // A weighted average of in-range samples cannot exceed the ceiling. Enforcing it here as
    // well keeps the step-6 multiply inside 256 bits for any bnLimit.
    arith_uint256 bnAvg = bnPastTargetAvg;
    if (bnAvg > bnLimit) bnAvg = bnLimit;

    // Step 6.
    arith_uint256 bnNew = (bnAvg * arith_uint256((uint64_t)nActualTimespan)) /
                          arith_uint256((uint64_t)nTargetTimespan);

    // Step 7.
    if (bnNew == arith_uint256(0)) bnNew = arith_uint256(1);
    if (bnNew > bnLimit) bnNew = bnLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextRandomXWorkRequired(const CBlockIndex* pindexLast,
                                        const CBlockHeader* pblock,
                                        const Consensus::Params& params)
{
    (void)pblock; // deliberately unread: the CPU target is derived, never header-supplied.

    const arith_uint256 bnLimit = UintToArith256(params.randomxLimit);

    const int64_t nWindow = params.nSyzgySyncWindow;
    if (nWindow < 2 || nWindow > LWMA_MAX_SAMPLES) {
        return bnLimit.GetCompact();
    }
    const int64_t nPastBlocks = nWindow - 1; // M
    const int64_t nTargetBlockSeconds = params.nSyzgySyncTargetBlockSeconds;

    // Step 1 -- bootstrap.
    if (pindexLast == nullptr || pindexLast->nHeight < nPastBlocks) {
        return bnLimit.GetCompact();
    }

    // Steps 2 and 3.
    const int64_t nWeightSum = nPastBlocks * (nPastBlocks + 1) / 2; // W
    if (nWeightSum <= 0) {
        return bnLimit.GetCompact();
    }

    arith_uint256 bnWeightedSum = arith_uint256(0);
    const CBlockIndex* pindex = pindexLast;
    for (int64_t i = 1; i <= nPastBlocks; ++i) {
        bool fNegative = false;
        bool fOverflow = false;
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits, &fNegative, &fOverflow);
        // A malformed (negative or overflow) compact sample counts as the ceiling.
        if (fNegative || fOverflow) bnTarget = bnLimit;

        const int64_t nWeight = (nPastBlocks + 1) - i; // w_i, heaviest on the tip
        bnWeightedSum += bnTarget * arith_uint256((uint64_t)nWeight);

        // The i-th sample is B_i, at height (tipHeight - i + 1), so i = M lands on
        // height (tipHeight - M + 1). Never walked off the start: pindexLast->nHeight >= M
        // guarantees the deepest sample is at height >= 1.
        if (i < nPastBlocks) {
            if (pindex->pprev == nullptr) {
                return bnLimit.GetCompact();
            }
            pindex = pindex->pprev;
        }
    }

    // Step 4. B_{M+1} is ONE BLOCK OLDER than the oldest averaged sample, i.e. height
    // (tipHeight - M), not (tipHeight - M + 1). The loop above stops on the oldest sample, so
    // exactly one more step back is needed here. tipHeight >= M guarantees this index exists
    // (at worst it is genesis).
    if (pindex->pprev == nullptr) {
        return bnLimit.GetCompact();
    }
    pindex = pindex->pprev;

    const arith_uint256 bnPastTargetAvg = bnWeightedSum / arith_uint256((uint64_t)nWeightSum);

    // Step 4. pindexLast is B_1, pindex is B_{M+1}.
    const int64_t nActualTimespan =
        (int64_t)pindexLast->nTime - (int64_t)pindex->nTime;

    // Step 5.
    const int64_t nTargetTimespan = nPastBlocks * nTargetBlockSeconds;

    // Steps 6, 7 and 8.
    return CalculateLWMANextWorkRequired(bnPastTargetAvg, nPastBlocks, nActualTimespan,
                                         nTargetTimespan, bnLimit);
}

} // namespace syzgy