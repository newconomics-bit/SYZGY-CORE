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
 *      T_actual is clamped into [ T_target/3, T_target*3 ].
 *      The 3x band is the whole point of the algorithm: it bounds a single retarget's reaction to
 *      a manipulated or wildly stale timestamp, and it is TOTAL-RELATIVE -- the standard
 *      dark-gravity-style guard band, in the same form the GPU half uses.
 *
 *      >>> DEFECT AND FIX (Wave 2, founder-approved). READ THIS BEFORE CHANGING THE BAND. <<<
 *      The band used to read [ T_target/M/3, T_target/M*3 ] = [ S/3, 3S ] = [20s, 180s].
 *      That is a UNITS DEFECT: the numerator is a total (M * S) and the divisor is a per-block
 *      count, so the band came out with PER-BLOCK units, while T_actual is a TOTAL window
 *      timespan (step 4). On a correctly-timed network T_actual ~ T_target = M*S, which on
 *      mainnet (M = 89, S = 60) is 5340s -- about 30x above the 180s ceiling. The upper clamp
 *      therefore ALWAYS bound, on every window, forever:
 *
 *          T_new = T_avg * 3S / (M*S) = T_avg * 3/M = T_avg / 29.7   (mainnet)
 *          T_new = T_avg / 3                                        (regtest, M = 9)
 *
 *      i.e. a monotone collapse of the CPU target toward zero difficulty -- precisely the
 *      sub-second-block-spam failure FR-02 exists to prevent. Nothing about the network's
 *      behaviour was required to trigger it; a perfectly timed chain was enough.
 *
 *      THE FIX: the band is expressed relative to the TOTAL, [T_target/3, T_target*3], the same
 *      shape DGW uses on the GPU side. Correct arithmetic, mainnet (T_target = 5340):
 *          band = [ 5340/3 , 5340*3 ] = [ 1780s , 16020s ]  = [ ~29.7 min , ~4.45 h ]
 *      A correctly-timed window (5340s) sits INSIDE the band and is untouched; only a window
 *      that arrived more than 3x faster or more than 3x slower than targeted is pulled to the
 *      bound. That is exactly the intended behaviour of a guard band, and it is wide enough
 *      that a genuine multi-fold hashrate change is still tracked (step 6's ratio is computed
 *      from the real T_actual, not the clamped one) while still bounding a single retarget.
 *
 *      This is a consensus change: it alters the CPU target at every height. It was made
 *      deliberately, on the founder's direction, and it is recorded in
 *      SYZGY-IMPLEMENTATION-SPEC.md section 6.1 step 5.
 *
 *  Step 6 -- NEW TARGET.
 *      T_new = T_avg * T_actual / T_target
 *      Floor division, evaluated as an exact 512-bit intermediate (see MulDivFloor()). The
 *      naive 256-bit `T_avg * T_actual` wraps for any target near the ceiling -- which is every
 *      target at genesis, and every target on regtest -- and a wrapped product then divides down
 *      to a target unrelated to T_avg. The helper agrees with the naive expression bit for bit
 *      wherever the naive expression does not overflow, so this is a correctness fix only.
 *      If the blocks arrived slower than targeted (T_actual > T_target) the target value rises,
 *      i.e. the difficulty falls, which is correct: lower the target to make blocks easier.
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

/**
 * Minimal non-negative 512-bit accumulator: exactly as much as the LWMA rule needs, and no more.
 *
 * WHY IT IS NEEDED -- steps 3 and 6 of the formula block at the top of this file both form a
 * value wider than 256 bits, and both wrapped before this type existed. Because `randomxLimit`
 * on a fresh chain -- and on ALL of regtest -- is 0x7fff...ff, "a target near the ceiling" is
 * not an edge case, it is the normal state of every chain at low height:
 *
 *   step 3: T_avg = sum_i (w_i * t_i) / W, with W = M(M+1)/2 = 45 on regtest. Nine samples at
 *           the ceiling sum to ~2^260. The 256-bit sum wrapped and the division then produced a
 *           target with no relation to the samples: an on-time regtest window returned
 *           0x202d8cc where the correct answer is 0x207fffff.
 *   step 6: T_new = T_avg * T_actual / T_target. On an on-time window T_actual == T_target, so
 *           `T_avg * 540` alone wraps at the ceiling and returned 0x1f7956eb.
 *
 * Both are pure functions of their inputs and both agree with the naive 256-bit form bit for
 * bit wherever the naive form does not overflow, so this is a correctness fix, not a retune.
 * Div() saturates rather than wrapping when the true quotient does not fit in 256 bits; the
 * only caller clamps to bnLimit immediately afterwards, and saturating is the correct direction
 * there -- a quotient above the ceiling must become the ceiling, never wrap back to a small one.
 */
struct UInt512 {
    arith_uint256 hi;   // bits 256..511
    arith_uint256 lo;   // bits 0..255

    UInt512() : hi(0), lo(0) {}

    /** A += b. Caller must bound the running total so that `hi` itself cannot overflow. */
    void Add256(const arith_uint256& b)
    {
        const arith_uint256 loSum = lo + b;
        const uint64_t carry = (loSum < lo) ? 1 : 0;   // the low addition wrapped
        lo = loSum;
        hi += arith_uint256(carry);
    }

    /** A += x * m, for any uint64 m. `x` may be the full 256 bits.
     *
     *  x*m = xl*m + (xh*m)*2^128 with xh, xl < 2^128, so each partial product is < 2^192 and
     *  fits in a 256-bit limb. The `(xh*m)` term straddles the accumulator's 128-bit mark: its
     *  low 128 bits are added at offset 128 inside `lo` (which carries into `hi` automatically)
     *  and its high bits go straight into `hi`.
     */
    void AddMul(const arith_uint256& x, uint64_t m)
    {
        const arith_uint256 kShifted1 = arith_uint256(1) << 128;
        const arith_uint256 kMask = kShifted1 - arith_uint256(1);
        const arith_uint256 xh = x >> 128;        // < 2^128
        const arith_uint256 xl = x & kMask;       // < 2^128
        const arith_uint256 bnM = m;
        const arith_uint256 p0 = xl * bnM;        // < 2^192
        const arith_uint256 p1 = xh * bnM;        // < 2^192
        Add256(p0);
        Add256((p1 & kMask) << 128);
        hi += (p1 >> 128);                        // < 2^64
    }

    /** floor(A / b) for b > 0. Saturates at 2^256-1 if the quotient does not fit. */
    arith_uint256 Div(uint64_t b) const
    {
        const arith_uint256 bnB = b;
        const arith_uint256 kShifted1 = arith_uint256(1) << 128;
        const arith_uint256 kMask = kShifted1 - arith_uint256(1);

        // Long division of A = hi*2^256 + lo by b, in 128-bit-scaled steps so that no
        // intermediate exceeds 256 bits. Each `r` is < b, so each `r << 128` stays inside.
        const arith_uint256 q2 = hi / bnB;
        const arith_uint256 r2 = hi - q2 * bnB;              // < b

        const arith_uint256 loHi = lo >> 128;
        const arith_uint256 loLo = lo & kMask;

        const arith_uint256 t = (r2 << 128) + loHi;          // <= b*2^128 - 1
        const arith_uint256 q1 = t / bnB;                    // <= 2^128 - 1
        const arith_uint256 r1 = t - q1 * bnB;               // < b

        const arith_uint256 rem2 = (r1 << 128) + loLo;       // <= b*2^128 - 1
        const arith_uint256 q0 = rem2 / bnB;                 // <= 2^128 - 1

        // The quotient is q2*2^256 + q1*2^128 + q0. A non-zero q2 means it is >= 2^256 and
        // cannot be represented; q1 and q0 are both bounded by 2^128-1 by construction above.
        if (q2 != arith_uint256(0)) {
            return arith_uint256(~arith_uint256(0));
        }
        return arith_uint256((q1 << 128) + q0);
    }
};

/** floor(x * a / b), evaluated in 512 bits so the intermediate product cannot wrap. b > 0. */
arith_uint256 MulDivFloor(const arith_uint256& x, uint64_t a, uint64_t b)
{
    UInt512 acc;
    acc.AddMul(x, a);
    return acc.Div(b);
}

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

    // Step 5: the guard band is TOTAL-RELATIVE, [T_target/3, T_target*3] -- the same shape the
    // GPU half (Dark Gravity Wave) uses. See the DEFECT AND FIX block in the header comment:
    // the previous band, [T_target/M/3, T_target/M*3] = [S/3, 3S], was a per-block quantity
    // applied to a total-window quantity, so its upper bound always bound and collapsed the
    // target toward zero difficulty on a correctly-timed network.
    //
    // Guard the arithmetic: a misconfigured S large enough to overflow T_target*3 must hold
    // rather than wrap into a negative band.
    if (nTargetTimespan > ((int64_t)1 << 62) / 3) {
        return bnPastTargetAvg.GetCompact();
    }
    const int64_t nMinTimespan = nTargetTimespan / 3;
    const int64_t nMaxTimespan = nTargetTimespan * 3;
    if (nMinTimespan <= 0) {
        return bnPastTargetAvg.GetCompact();
    }
    if (nActualTimespan < nMinTimespan) nActualTimespan = nMinTimespan;
    if (nActualTimespan > nMaxTimespan) nActualTimespan = nMaxTimespan;

    // A weighted average of in-range samples cannot exceed the ceiling. Enforcing it here as
    // well keeps the value the step-6 multiply starts from inside [0, bnLimit].
    arith_uint256 bnAvg = bnPastTargetAvg;
    if (bnAvg > bnLimit) bnAvg = bnLimit;

    // Step 6, evaluated through the 512-bit helper: T_new = T_avg * T_actual / T_target.
    arith_uint256 bnNew =
        MulDivFloor(bnAvg, (uint64_t)nActualTimespan, (uint64_t)nTargetTimespan);

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

    // Step 3 accumulates in 512 bits: W samples of a target that may be as large as the
    // ceiling produce a sum wider than 256 bits, and a wrapped sum silently returns a target
    // unrelated to the window. See UInt512.
    UInt512 accWeightedSum;
    const CBlockIndex* pindex = pindexLast;
    for (int64_t i = 1; i <= nPastBlocks; ++i) {
        bool fNegative = false;
        bool fOverflow = false;
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits, &fNegative, &fOverflow);
        // A malformed (negative or overflow) compact sample counts as the ceiling.
        if (fNegative || fOverflow) bnTarget = bnLimit;

        const int64_t nWeight = (nPastBlocks + 1) - i; // w_i, heaviest on the tip
        accWeightedSum.AddMul(bnTarget, (uint64_t)nWeight);

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

    const arith_uint256 bnPastTargetAvg = accWeightedSum.Div((uint64_t)nWeightSum);

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