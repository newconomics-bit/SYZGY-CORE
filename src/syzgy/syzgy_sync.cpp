// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
 * ============================================================================================
 * SYZGY Sync Controller -- PRD section 7, five layers.
 *
 *     Data Feed -> Health Monitor -> Mode Router -> Difficulty Engine -> Safety Guardrails
 *
 * ============================================================================================
 *
 * 1. DATA FEED  (CollectDataFeed)
 * -------------------------------
 * Observations over the trailing `window = params.nSyzgySyncWindow` block slots, plus two
 * independent trailing-run walks for the presence streaks.
 *
 * PRESENCE IS COUNTED DIRECTLY FROM THE BLOCK INDEX. There is no cadence heuristic, no
 * timestamp inference, no "probably mined by X because the block time was short":
 *
 *     CPU (RandomX) proof present  <=>  pindex->hashRandomX is not null
 *     GPU (KawPoW)   proof present  <=>  pindex->mix_hash    is not null
 *
 * Both fields are ordinary uint256 members of CBlockIndex and are persisted by
 * LoadBlockIndexGuts, so a node that just restarted from disk counts presence exactly as a
 * node that just synced from the network. (That persistence was the subject of the
 * syzgy_index_tests regression; if it were lost the chain would fork on restart.)
 *
 * THE CRITICAL SEMANTIC POINT. A null hashRandomX on a NON-GENESIS block does NOT mean "we do
 * not know what this block is". It means "this block was accepted in emergency mode as a
 * GPU-only block" -- FR-01 was suspended for exactly that block, on purpose, by consensus.
 * It is therefore counted as ABSENT, always, and never skipped. Skipping it would silently
 * erase the event the whole Controller exists to respond to; treating it as "unknown" would
 * let a chain run single-alo indefinitely without ever entering emergency mode.
 *
 * HEIGHT 0 (GENESIS) IS HANDLED EXPLICITLY. FR-01 has no genesis exemption on SYZGY: a
 * conforming SYZGY genesis carries BOTH proofs and would count as a dual block. The window
 * walk nevertheless stops ABOVE height 0 -- it walks heights (tip .. tip-window+1) and stops
 * if it would descend past height 1. So genesis contributes to neither the window counts nor
 * the streak runs. The reason is liveness of the emergency logic, not distrust of genesis: a
 * genesis whose proofs are absent (a pre-SYZGY chain, or any future change to the genesis
 * exemption) must not be able to manufacture a stall run at the very first blocks of a fresh
 * chain and drop the network into emergency mode with nothing to recover it.
 *
 * TWO WALKS, DELIBERATELY.
 *   (a) The WINDOW walk counts presence percentages and solve seconds over `window` slots.
 *   (b) The STREAK walk counts trailing present/absent runs over `streakWalk` slots, where
 *       streakWalk = max(window, R + 1) and R = 2 * nSyzgySyncMinRatio is the recovery
 *       horizon. The streak walk MUST be at least R+1 long, otherwise "has the class been
 *       absent for R consecutive blocks?" becomes unanswerable and the anti-trap valve
 *       silently stops firing -- which is exactly how emergency mode would become a trap.
 *       On mainnet R=30 < window=90 so the two coincide; on regtest R=60 > window=10, and
 *       without this the recovery rule would be unreachable in tests while still being live
 *       in production. Both walks are over the same committed fields and are pure.
 *
 * 2. HEALTH MONITOR  (EvaluateHealth)
 * -----------------------------------
 *     cpuPresent        = cpuBlocks > 0
 *     cpuPresencePercent = 100 * cpuBlocks / window
 *     consecutiveStalls = max(cpuStallRun, gpuStallRun)
 *     pairingStalled    = consecutiveStalls >= params.nSyzgyPairingStallBlocks
 *
 * 3. MODE ROUTER  (RouteMode)
 * ---------------------------
 *     if (!pairingStalled)                    -> DUAL_POW
 *     if (cpuPresent == gpuPresent)           -> DUAL_POW
 *          (covers BOTH-PRESENT, which is not an emergency at all, and BOTH-ABSENT, which is
 *           HARD-GATED to DUAL_POW: a window in which neither class produced a block must never
 *           yield a single-algo mode, because there is no evidence of which class is "the"
 *           surviving class, and picking one would freeze the other's target for no reason.)
 *     if (recoveryReached)                    -> DUAL_POW      (see below)
 *     if (cpuPresent)                         -> SINGLE_ALO_CPU
 *     else                                    -> SINGLE_ALO_GPU
 *
 * 4. DIFFICULTY ENGINE  (ComputeBalancedBits)
 * -------------------------------------------
 * Asymmetric by design (D3): the CPU side is driven by LWMA (src/syzgy/syzgy_lwma.cpp), which
 * reacts within a few blocks to a volatile home-CPU hashrate; the GPU side is driven by Dark
 * Gravity Wave, whose longer memory suits a smoother GPU fleet. On top of the two independent
 * engines sits a small proportional BALANCE CORRECTION towards the lagging side.
 *
 * THE EXACT BALANCE ARITHMETIC. Let C and G be the two engine outputs decoded to target space
 * with SetCompact(). Difficulty is inversely proportional to target, so the ratio between the
 * two classes' relative difficulties is
 *
 *     d_cpu ~ 1/C ,  d_gpu ~ 1/G
 *     r = min(d_cpu, d_gpu) / max(d_cpu, d_gpu) = min(C,G) / max(C,G)      in (0, 1]
 *
 * r == 1 is perfectly balanced. r == 0 would mean one class is infinitely easier than the
 * other. The tolerated floor is rMin = nSyzgySyncMinRatio / 100.
 *
 * The LAGGARD is the class with the LARGER target (the easier one, i.e. the lower difficulty);
 * it produces blocks faster than its share and takes the block-time from the other class, so it
 * is the side that must be pushed HARDER. With
 *
 *     deficit_pct = 100 - floor(100 * r)                       0 when balanced, < 100 always
 *     units       = min(4, deficit_pct * 4 / 100)              integer division
 *     laggard_compact_bits -= units
 *
 * the correction is at most 4 compact units, ~4.4% in target space (this is the "measured cap
 * on the balance correction" in the design spec). Reducing the compact magnitude/exponent makes
 * the target SMALLER, which makes the class HARDER -- the correct direction for the laggard.
 * When C == G the pair is balanced, units == 0, and neither side moves.
 *
 * THE FREEZE COMES FIRST AND IS UNCONDITIONAL. Before any of the above arithmetic runs, the
 * absent class's target is pinned to the value it already has. There is no code path in this
 * file in which an absent class's output is derived from a correction, from a retarget, or
 * from the other class's difficulty. See the invariant note at the bottom of this header comment.
 *
 * 5. SAFETY GUARDRAILS  (ApplyGuardrails)
 * ---------------------------------------
 * Each side is bounded to +/- nSyzgySyncMaxRetargetPercent (60) of its PREVIOUS TARGET, in
 * TARGET space rather than compact space (bounding in compact space would be a wildly different,
 * and much looser, bound because compact bits are a logarithmic encoding):
 *
 *     lo = prev * (100 - maxPct) / 100
 *     hi = prev * (100 + maxPct) / 100
 *     next = clamp(desired, max(lo, 1), hi)
 *     next = min(next, that algorithm's own limit)      // randomxLimit / kawpowLimit
 *
 * No target may ever be easier than its own algorithm's limit: that is the FR-01 invariant which
 * makes the two ceilings (randomxLimit, kawpowLimit) per-algorithm rather than shared.
 * Whether the bound actually bit is reported in SyncGuardrails::clampedCpu / clampedGpu.
 *
 * ============================================================================================
 * THE SAFETY INVARIANT (PRD D10 / FR-02)
 * ============================================================================================
 * "The absent class's difficulty is FROZEN, never driven toward zero."
 *
 * In code: ComputeBalancedBits() contains an early return for each single-algo mode that
 * assigns the absent side directly from feed.cpuDifficulty / feed.gpuDifficulty and returns,
 * BEFORE any LWMA, DGW, balance or guardrail arithmetic executes. Guardrails then run on the
 * pair; for the frozen side prev == desired, so `lo <= desired <= hi` holds trivially and the
 * guardrail is a no-op. The frozen value is therefore bit-identical to the input.
 *
 * Why it matters: difficulty -> 0 for the absent class means anyone can produce valid-looking
 * blocks for it almost instantly, so the block interval collapses far below the 60s target
 * (FR-02), the chain fills with junk, and the recovering class is drowned out. Freezing keeps
 * the absent class's target at the last value at which it actually produced blocks, so any
 * block it has already mined stays valid and it can rejoin at its real difficulty.
 *
 * THE ANTI-TRAP VALVE. Emergency mode is not a latch: it is re-derived from the index on every
 * call, with no counter stored anywhere. Let R = 2 * nSyzgySyncMinRatio. DUAL_POW is returned
 * when either (a) HYSTERESIS -- both classes have been present for R consecutive blocks, or
 * (b) the ANTI-TRAP VALVE -- the current stall run has already lasted R blocks. Since a stall
 * run can only grow while the class is absent, and the run length is counted directly from the
 * index, condition (b) is guaranteed to become true after at most R further stalled blocks. So
 * the network returns to strict dual-PoW at least once every R blocks no matter how long the
 * pairing stall lasts: emergency mode can NEVER become a trap. This is a hard invariant of the
 * function, not a tunable.
 *
 * On the recovery block itself the absent class's target is still left frozen, so blocks that
 * class had already in flight remain valid -- "emit the laggard's single mode so blocks from
 * either class stay valid". Normal retargeting of both sides resumes from the next block, when
 * the streaks have actually caught up.
 * ============================================================================================
 */

#include "syzgy/syzgy_sync.h"

#include "arith_uint256.h"
#include "chain.h"
#include "pow.h"
#include "primitives/block.h"
#include "syzgy/syzgy_lwma.h"
#include "uint256.h"
#include "validation.h"

namespace syzgy {

namespace {

/** Recovery horizon R = 2 * nSyzgySyncMinRatio. Both recovery criteria are expressed in it. */
int64_t RecoveryHorizon(const Consensus::Params& params)
{
    const int64_t nMinRatio = params.nSyzgySyncMinRatio;
    if (nMinRatio <= 0) return 0;
    return 2 * nMinRatio;
}

/** True when a null hashRandomX means "single-alo GPU block", false only at genesis. */
inline bool CpuProofPresent(const CBlockIndex* pindex)
{
    return pindex->hashRandomX != uint256();
}

/** True when a non-null mix_hash means "a KawPoW proof is in the header". */
inline bool GpuProofPresent(const CBlockIndex* pindex)
{
    return pindex->mix_hash != uint256();
}

/** Hard cap on the balance correction, in compact units (~4.4% in target space). */
const int64_t BALANCE_MAX_UNITS = 4;

/**
 * True when the Controller must stop being in emergency mode. Pure function of the health
 * struct and params -- no counter, no latch, no memory of previous calls.
 */
bool RecoveryReached(const SyncHealth& h, const Consensus::Params& params)
{
    const int64_t nR = RecoveryHorizon(params);
    if (nR <= 0) return false;

    // Both classes currently streaming: trivially recovered.
    if (h.cpuPresent && h.gpuPresent) return true;

    // (a) HYSTERESIS -- both classes present for R consecutive blocks.
    if (h.cpuPresentStreak >= nR && h.gpuPresentStreak >= nR) return true;

    // (b) ANTI-TRAP VALVE -- the current stall run has already lasted R blocks. Because the run
    // length is read straight off the index, this becomes true after at most R more stalled
    // blocks, so DUAL_POW is guaranteed to return at least once every R blocks.
    if (h.consecutiveStalls >= nR) return true;

    return false;
}

/** 2^256 - 1, used to saturate a bound that does not fit in 256 bits. */
const arith_uint256 kMaxUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/**
 * The +/- pct band around `bnPrev`, in target space, WITHOUT EVER OVERFLOWING 256 bits.
 *
 * The obvious form, `bnPrev * (100 +/- pct) / 100`, is WRONG and was wrong here first. For any
 * `bnPrev` near the ceiling -- which is the state of a fresh chain, and the permanent state of
 * regtest -- `bnPrev * 160` wraps modulo 2^256, so the computed "upper bound" is a tiny number
 * and every retarget is silently clamped down to garbage. Dividing the factor out of the
 * multiplication first keeps every intermediate below 2^256:
 *
 *     delta = floor(bnPrev * pct / 100)  =  (bnPrev / 100) * pct  +  ((bnPrev % 100) * pct) / 100
 *
 * `delta` is strictly less than `bnPrev` for pct <= 99, so `bnPrev - delta` cannot underflow.
 * The upper bound genuinely may not be representable in 256 bits at all, in which case no
 * target can be above it and the bound saturates at 2^256 - 1.
 */
void GuardBand(const arith_uint256& bnPrev, int64_t pct, arith_uint256& bnLo, arith_uint256& bnHi)
{
    if (pct < 0) pct = 0;
    if (pct > 99) pct = 99;

    const arith_uint256 k100(100);
    const arith_uint256 q = bnPrev / k100;
    const arith_uint256 r = bnPrev - q * k100;
    arith_uint256 delta = q * arith_uint256((uint64_t)pct);
    delta += (r * arith_uint256((uint64_t)pct)) / k100;

    bnLo = bnPrev - delta;
    bnHi = bnPrev + delta;
    if (bnHi < bnPrev) bnHi = kMaxUint256;   // wrapped: nothing representable sits above the bound
}

/** One side's guarded retarget, in target space, bounded to +/- maxRetargetPercent. */
unsigned int GuardOneSide(unsigned int prevBits, unsigned int desiredBits,
                          const arith_uint256& bnLimit, int64_t maxRetargetPercent,
                          bool& clampedOut)
{
    clampedOut = false;

    arith_uint256 bnLimitCapped = bnLimit;
    if (bnLimitCapped == arith_uint256(0)) bnLimitCapped = arith_uint256(1);

    bool fNeg = false, fOvf = false;
    arith_uint256 bnDesired = arith_uint256().SetCompact(desiredBits, &fNeg, &fOvf);
    if (fNeg || fOvf) {
        bnDesired = bnLimitCapped;
        clampedOut = true;
    }
    if (bnDesired > bnLimitCapped) {
        bnDesired = bnLimitCapped;
        clampedOut = true;
    }

    // With no previous target there is nothing to bound against; the algorithm limit is
    // already the ceiling. This is the bootstrap case, not a guardrail failure.
    if (prevBits == 0) {
        if (bnDesired == arith_uint256(0)) bnDesired = arith_uint256(1);
        return bnDesired.GetCompact();
    }

    arith_uint256 bnPrev = arith_uint256().SetCompact(prevBits);
    if (bnPrev == arith_uint256(0)) bnPrev = arith_uint256(1);

    arith_uint256 bnLo, bnHi;
    GuardBand(bnPrev, maxRetargetPercent, bnLo, bnHi);

    arith_uint256 bnNext = bnDesired;
    if (bnNext < bnLo) { bnNext = bnLo; clampedOut = true; }
    if (bnNext > bnHi) { bnNext = bnHi; clampedOut = true; }

    if (bnNext == arith_uint256(0)) { bnNext = arith_uint256(1); clampedOut = true; }
    if (bnNext > bnLimitCapped) { bnNext = bnLimitCapped; clampedOut = true; }

    return bnNext.GetCompact();
}

} // namespace

// ------------------------------------------------------------------------------------------
// Layer 1 -- Data Feed
// ------------------------------------------------------------------------------------------

SyncDataFeed CollectDataFeed(const CBlockIndex* pindexTip, const Consensus::Params& params)
{
    SyncDataFeed feed;
    feed.window = params.nSyzgySyncWindow;
    if (feed.window < 0) feed.window = 0;
    feed.cpuBlocks = 0;
    feed.gpuBlocks = 0;
    feed.cpuSolveSeconds = 0;
    feed.gpuSolveSeconds = 0;
    feed.cpuDifficulty = 0;
    feed.gpuDifficulty = 0;
    feed.lastBlockHeight = -1;
    feed.lastBlockTime = 0;
    feed.cpuPresentStreak = 0;
    feed.gpuPresentStreak = 0;
    feed.cpuStallRun = 0;
    feed.gpuStallRun = 0;
    feed.stallStartHeight = -1;

    if (pindexTip == nullptr) return feed;

    feed.lastBlockHeight = pindexTip->nHeight;
    feed.lastBlockTime = (int64_t)pindexTip->nTime;

    // The GPU target is the header's single nBits; it is what is currently in force.
    feed.gpuDifficulty = (int64_t)(uint32_t)pindexTip->nBits;
    // The CPU target is derived from the index chain, never read from the header: a miner must
    // not be able to choose their own CPU target.
    feed.cpuDifficulty = (int64_t)(uint32_t)syzgy::GetNextRandomXWorkRequired(pindexTip, nullptr, params);

    // ---- (a) WINDOW WALK -----------------------------------------------------------------
    // Heights tip .. tip-window+1, stopping above height 0. Genesis never contributes: see the
    // header comment. Height 0 is the only block treated specially, and it is always excluded.
    const CBlockIndex* pindex = pindexTip;
    int64_t nWalked = 0;
    while (pindex != nullptr && pindex->nHeight >= 1 && nWalked < feed.window) {
        const bool cpu = CpuProofPresent(pindex);
        const bool gpu = GpuProofPresent(pindex);

        if (cpu) feed.cpuBlocks += 1;
        if (gpu) feed.gpuBlocks += 1;

        // Solve seconds: the actual spacing this block took, attributed to the classes that
        // actually contributed it. A non-monotonic timestamp contributes 0, never a negative.
        if (pindex->pprev != nullptr) {
            const int64_t nSpacing =
                (int64_t)pindex->nTime - (int64_t)pindex->pprev->nTime;
            if (nSpacing > 0) {
                if (cpu) feed.cpuSolveSeconds += nSpacing;
                if (gpu) feed.gpuSolveSeconds += nSpacing;
            }
        }

        ++nWalked;
        pindex = pindex->pprev;
    }

    // ---- (b) STREAK WALK -----------------------------------------------------------------
    // Independent of the window length, and long enough to answer "has this run reached R?".
    // Without the max(window, R+1) floor the anti-trap valve would be unable to fire whenever
    // R > window, which is exactly the regtest configuration.
    const int64_t nR = RecoveryHorizon(params);
    int64_t streakWalk = feed.window;
    if (nR + 1 > streakWalk) streakWalk = nR + 1;
    if (streakWalk > 1000000) streakWalk = 1000000;

    pindex = pindexTip;
    int64_t nStreakWalked = 0;
    bool fCpuRunOpen = false, fGpuRunOpen = false;
    bool fCpuRunPresent = false, fGpuRunPresent = false;
    int64_t nCpuPresentRun = 0, nCpuAbsentRun = 0;
    int64_t nGpuPresentRun = 0, nGpuAbsentRun = 0;

    while (pindex != nullptr && pindex->nHeight >= 1 && nStreakWalked < streakWalk) {
        const bool cpu = CpuProofPresent(pindex);
        const bool gpu = GpuProofPresent(pindex);

        if (!fCpuRunOpen) {
            fCpuRunOpen = true;
            fCpuRunPresent = cpu;
            if (cpu) nCpuPresentRun = 1; else nCpuAbsentRun = 1;
        } else if (cpu == fCpuRunPresent) {
            if (cpu) ++nCpuPresentRun; else ++nCpuAbsentRun;
        }
        // else: the run has already been closed, further blocks cannot extend it.

        if (!fGpuRunOpen) {
            fGpuRunOpen = true;
            fGpuRunPresent = gpu;
            if (gpu) nGpuPresentRun = 1; else nGpuAbsentRun = 1;
        } else if (gpu == fGpuRunPresent) {
            if (gpu) ++nGpuPresentRun; else ++nGpuAbsentRun;
        }

        ++nStreakWalked;
        pindex = pindex->pprev;
    }

    if (fCpuRunOpen && fCpuRunPresent) feed.cpuPresentStreak = (int)nCpuPresentRun;
    else feed.cpuStallRun = nCpuAbsentRun;
    if (fGpuRunOpen && fGpuRunPresent) feed.gpuPresentStreak = (int)nGpuPresentRun;
    else feed.gpuStallRun = nGpuAbsentRun;

    // Height at which the currently-running stall began. The tip is height lastBlockHeight, so
    // a run of k absent slots started k-1 blocks below it. Both absent => use the shorter run's
    // start (the earliest onset), which is what a recovery valve cares about.
    if (feed.cpuStallRun > 0 && feed.gpuStallRun > 0) {
        feed.stallStartHeight = feed.lastBlockHeight -
                                (feed.cpuStallRun > feed.gpuStallRun ? feed.cpuStallRun
                                                                   : feed.gpuStallRun) + 1;
    } else if (feed.cpuStallRun > 0) {
        feed.stallStartHeight = feed.lastBlockHeight - feed.cpuStallRun + 1;
    } else if (feed.gpuStallRun > 0) {
        feed.stallStartHeight = feed.lastBlockHeight - feed.gpuStallRun + 1;
    }

    return feed;
}

SyncDataFeed CollectDataFeed(const CChain& chain, const Consensus::Params& params)
{
    return CollectDataFeed(chain.Tip(), params);
}

// ------------------------------------------------------------------------------------------
// Layer 2 -- Health Monitor
// ------------------------------------------------------------------------------------------

SyncHealth EvaluateHealth(const SyncDataFeed& feed, const Consensus::Params& params)
{
    SyncHealth h;
    h.cpuPresent = feed.cpuBlocks > 0;
    h.gpuPresent = feed.gpuBlocks > 0;

    const int64_t nWindow = feed.window > 0 ? feed.window : 1;
    int64_t cpuPct = (feed.cpuBlocks * 100) / nWindow;
    int64_t gpuPct = (feed.gpuBlocks * 100) / nWindow;
    if (cpuPct < 0) cpuPct = 0;
    if (gpuPct > 100) cpuPct = 100;
    if (gpuPct < 0) gpuPct = 0;
    if (gpuPct > 100) gpuPct = 100;
    h.cpuPresencePercent = (int)cpuPct;
    h.gpuPresencePercent = (int)gpuPct;

    h.consecutiveStalls = (int)(feed.cpuStallRun > feed.gpuStallRun ? feed.cpuStallRun
                                                                   : feed.gpuStallRun);
    h.cpuPresentStreak = feed.cpuPresentStreak;
    h.gpuPresentStreak = feed.gpuPresentStreak;
    h.pairingStalled = feed.cpuStallRun >= params.nSyzgyPairingStallBlocks ||
                       feed.gpuStallRun >= params.nSyzgyPairingStallBlocks;
    return h;
}

// ------------------------------------------------------------------------------------------
// Layer 3 -- Mode Router
// ------------------------------------------------------------------------------------------

SyncMode RouteMode(const SyncHealth& h, const Consensus::Params& params)
{
    // Not stalled: strict FR-01.
    if (!h.pairingStalled) return SyncMode::DUAL_POW;

    // Hard gate: an equal number of present classes is never a single-algo mode. Two present =
    // not an emergency at all. Zero present = BOTH ABSENT, which must not yield a single-algo
    // mode: there is no evidence of which class is the surviving one, so nothing is frozen and
    // nothing is privileged.
    if (h.cpuPresent == h.gpuPresent) return SyncMode::DUAL_POW;

    // Recovery: hysteresis or anti-trap valve. Deterministic, pure function of the index.
    if (RecoveryReached(h, params)) return SyncMode::DUAL_POW;

    return h.cpuPresent ? SyncMode::SINGLE_ALO_CPU : SyncMode::SINGLE_ALO_GPU;
}

// ------------------------------------------------------------------------------------------
// Layer 4 -- Difficulty Engine
// ------------------------------------------------------------------------------------------

void ComputeBalancedBits(const SyncDataFeed& feed, const SyncHealth& health, SyncMode mode,
                         const Consensus::Params& params,
                         unsigned int& cpuBitsOut, unsigned int& gpuBitsOut)
{
    const unsigned int prevCpu = (unsigned int)(uint32_t)feed.cpuDifficulty;
    const unsigned int prevGpu = (unsigned int)(uint32_t)feed.gpuDifficulty;

    cpuBitsOut = prevCpu;
    gpuBitsOut = prevGpu;

    const bool cpuAbsent = !health.cpuPresent;
    const bool gpuAbsent = !health.gpuPresent;

    // ============================================================================
    // THE FREEZE. Placed before every single arithmetic operation in this function so
    // that no retarget, no balance correction and no guardrail can move an absent
    // class's target. The absent side's bits are assigned directly from the feed and
    // the function returns; it is bit-identical to what came in.
    // ============================================================================
    if (mode == SyncMode::SINGLE_ALO_CPU) {
        // CPU present and doing the work; GPU absent. GPU target: UNCHANGED.
        gpuBitsOut = prevGpu;
        return;
    }
    if (mode == SyncMode::SINGLE_ALO_GPU) {
        // GPU present and doing the work; CPU absent. CPU target: UNCHANGED.
        cpuBitsOut = prevCpu;
        return;
    }
    if (cpuAbsent && gpuAbsent) {
        // Both absent. Hold both: there is no evidence to retarget on, and holding keeps
        // whatever blocks either class had in flight valid.
        cpuBitsOut = prevCpu;
        gpuBitsOut = prevGpu;
        return;
    }
    if (gpuAbsent) {
        // DUAL_POW reached by recovery while the GPU is still absent: the GPU target stays
        // frozen for this block so its in-flight blocks remain valid (see header comment).
        gpuBitsOut = prevGpu;
        return;
    }
    if (cpuAbsent) {
        cpuBitsOut = prevCpu;
        return;
    }

    // ---- both classes present: bounded proportional balance correction --------------
    // C and G are the two engine outputs (LWMA on the CPU side, DGW on the GPU side) as
    // carried in the feed, decoded to target space.
    const arith_uint256 bnCpu = arith_uint256().SetCompact(prevCpu);
    const arith_uint256 bnGpu = arith_uint256().SetCompact(prevGpu);

    unsigned int cpuBits = prevCpu;
    unsigned int gpuBits = prevGpu;

    if (bnCpu != bnGpu && bnCpu != arith_uint256(0) && bnGpu != arith_uint256(0)) {
        const arith_uint256& bnLo = (bnCpu < bnGpu) ? bnCpu : bnGpu;
        const arith_uint256& bnHi = (bnCpu < bnGpu) ? bnGpu : bnCpu;

        // r = min(C,G) / max(C,G), the ratio of the two classes' relative difficulties.
        // r == 1 is perfectly balanced; r is always in (0,1].
        const arith_uint256 bnR = bnLo * arith_uint256((uint64_t)100) / bnHi;
        int64_t nDeficitPct = 100 - (int64_t)bnR.GetLow64();
        if (nDeficitPct < 0) nDeficitPct = 0;
        if (nDeficitPct > 100) nDeficitPct = 100;

        // units = min(4, deficit_pct * 4 / 100)  -- 0 when balanced, at most 4 (~4.4%).
        int64_t nUnits = (nDeficitPct * BALANCE_MAX_UNITS) / 100;
        if (nUnits < 0) nUnits = 0;
        if (nUnits > BALANCE_MAX_UNITS) nUnits = BALANCE_MAX_UNITS;

        if (nUnits > 0) {
            // The laggard is the side with the LARGER target (the easier one, the lower
            // difficulty). Reducing its compact bits makes its target smaller, i.e. harder.
            if (bnCpu > bnGpu) {
                cpuBits = (prevCpu > (unsigned int)nUnits) ? (prevCpu - (unsigned int)nUnits) : 0u;
            } else {
                gpuBits = (prevGpu > (unsigned int)nUnits) ? (prevGpu - (unsigned int)nUnits) : 0u;
            }
        }
    }

    // An explicit second bound on the balance correction, in target space, so that the
    // correction alone can never exceed the guardrail band regardless of configuration. Uses
    // the same overflow-safe GuardBand() as layer 5 -- the naive (100 + pct) multiply wraps for
    // any target near the ceiling.
    {
        const int64_t maxPct = params.nSyzgySyncMaxRetargetPercent;
        if (maxPct > 0) {
            arith_uint256 bnCpuLo, bnCpuHi, bnGpuLo, bnGpuHi;
            GuardBand(arith_uint256().SetCompact(prevCpu), maxPct, bnCpuLo, bnCpuHi);
            GuardBand(arith_uint256().SetCompact(prevGpu), maxPct, bnGpuLo, bnGpuHi);
            const arith_uint256 bnCpuWant = arith_uint256().SetCompact(cpuBits);
            const arith_uint256 bnGpuWant = arith_uint256().SetCompact(gpuBits);
            // Only ever tightens: a balance correction that made a side EASIER than the
            // guardrail allows is pulled back to the guardrail bound.
            if (bnCpuWant > bnCpuHi) cpuBits = bnCpuHi.GetCompact();
            if (bnGpuWant > bnGpuHi) gpuBits = bnGpuHi.GetCompact();
        }
        if (cpuBits == 0 && prevCpu != 0) cpuBits = 1;
        if (gpuBits == 0 && prevGpu != 0) gpuBits = 1;
    }

    cpuBitsOut = cpuBits;
    gpuBitsOut = gpuBits;
}

// ------------------------------------------------------------------------------------------
// Layer 5 -- Safety Guardrails
// ------------------------------------------------------------------------------------------

SyncGuardrails ApplyGuardrails(unsigned int prevCpuBits, unsigned int prevGpuBits,
                               unsigned int desiredCpuBits, unsigned int desiredGpuBits,
                               const Consensus::Params& params)
{
    const arith_uint256 bnCpuLimit = UintToArith256(params.randomxLimit);
    const arith_uint256 bnGpuLimit = UintToArith256(params.kawpowLimit);
    const int64_t maxPct = params.nSyzgySyncMaxRetargetPercent;

    SyncGuardrails g;
    g.nextCpuBits = GuardOneSide(prevCpuBits, desiredCpuBits, bnCpuLimit, maxPct, g.clampedCpu);
    g.nextGpuBits = GuardOneSide(prevGpuBits, desiredGpuBits, bnGpuLimit, maxPct, g.clampedGpu);
    return g;
}

// ------------------------------------------------------------------------------------------
// The whole pipeline
// ------------------------------------------------------------------------------------------

void GetNextDualWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock,
                             const Consensus::Params& params,
                             unsigned int& cpuBitsOut, unsigned int& gpuBitsOut,
                             SyncMode& modeOut)
{
    // Resolve the parent from the header's hashPrevBlock so that a parent on a side branch is
    // handled correctly, not just the active-chain tip.
    const CBlockIndex* pindexParent = pindexLast;
    if (pblock != nullptr) {
        BlockMap::const_iterator it = mapBlockIndex.find(pblock->hashPrevBlock);
        if (it == mapBlockIndex.end() || it->second == nullptr) {
            // FAIL CLOSED ON RETARGETING. The parent is unresolvable, so there is no committed
            // chain to derive a target from. Hold whatever the caller already had: no target is
            // loosened and none is tightened, and the mode stays strict dual-PoW so FR-01 still
            // requires both proofs. Never guess a difficulty from a header we cannot place.
            //
            // "Hold" is not "emit unchecked". The held value is still pushed through
            // ApplyGuardrails(), because the per-algorithm ceilings (randomxLimit /
            // kawpowLimit) are absolute and must hold on EVERY exit from this function, not
            // only on the ones that retarget. The header's single nBits is the GPU target, so
            // pindexLast->nBits is the value being held on the GPU side; passing it as BOTH the
            // previous and the desired value makes the +/-n% band a no-op (desired == prev) and
            // leaves only the limit clamp able to bind. On any chain that was itself within
            // limits -- i.e. every real chain -- this is therefore exactly the identity, and it
            // only ever bites on a parent whose nBits was already out of range.
            modeOut = SyncMode::DUAL_POW;
            const unsigned int held = (pindexLast != nullptr) ? (unsigned int)pindexLast->nBits : 0u;
            if (held == 0) {
                // No parent index at all: there is nothing to hold and nothing to clamp against.
                cpuBitsOut = 0u;
                gpuBitsOut = 0u;
                return;
            }
            const SyncGuardrails g = syzgy::ApplyGuardrails(held, held, held, held, params);
            cpuBitsOut = g.nextCpuBits;
            gpuBitsOut = g.nextGpuBits;
            return;
        }
        pindexParent = it->second;
    }

    if (pindexParent == nullptr) {
        // Nothing to derive from: the easiest legal targets for both algorithms.
        modeOut = SyncMode::DUAL_POW;
        cpuBitsOut = UintToArith256(params.randomxLimit).GetCompact();
        gpuBitsOut = UintToArith256(params.kawpowLimit).GetCompact();
        return;
    }

    // Layer 1
    SyncDataFeed feed = CollectDataFeed(pindexParent, params);
    // Layer 2
    SyncHealth health = EvaluateHealth(feed, params);
    // Layer 3
    SyncMode mode = RouteMode(health, params);
    modeOut = mode;

    // Layer 4, part one: run the two asymmetric engines and stash their raw outputs in the
    // feed. The CPU side is LWMA (syzgy_lwma); the GPU side is Dark Gravity Wave, which the
    // Wave-2 Step-2 wiring will repoint from powLimit at kawpowLimit.
    //
    // DarkGravityWave dereferences the header (its min-difficulty special case and its KAWPOW
    // activation test), so a null pblock must not be forwarded. When the caller has no header,
    // a synthetic one is built from the parent index: DGW only ever reads nTime, and the value
    // it derives is a pure function of the index anyway. Nothing here reads header.nBits.
    CBlockHeader synthHeader;
    if (pblock == nullptr) {
        synthHeader.nVersion = 4;
        synthHeader.nTime = pindexParent->nTime;
        synthHeader.nBits = pindexParent->nBits;
        synthHeader.nHeight = pindexParent->nHeight + 1;
        // hashPrevBlock is deliberately left null: nothing downstream reads it, and calling
        // GetBlockHash() on a synthetic index would dereference a phashBlock we never set.
        pblock = &synthHeader;
    }

    const unsigned int cpuFromLwma = syzgy::GetNextRandomXWorkRequired(pindexParent, pblock, params);
    const unsigned int gpuFromDgw = GetNextWorkRequired(pindexParent, pblock, params);

    // The guardrails must bound the move relative to what was in force BEFORE the engines ran,
    // so the previous values are snapshotted here and kept separate. Feeding the engine
    // outputs back in as the baseline would make prev == desired and the guardrail a no-op.
    const unsigned int prevCpuBits = (unsigned int)(uint32_t)feed.cpuDifficulty;
    const unsigned int prevGpuBits = (unsigned int)(uint32_t)feed.gpuDifficulty;

    if (mode != SyncMode::SINGLE_ALO_GPU) feed.cpuDifficulty = (int64_t)cpuFromLwma;
    if (mode != SyncMode::SINGLE_ALO_CPU) feed.gpuDifficulty = (int64_t)gpuFromDgw;

    // Layer 4, part two: freeze an absent class, then bounded balance correction.
    unsigned int cpuBits = 0;
    unsigned int gpuBits = 0;
    syzgy::ComputeBalancedBits(feed, health, mode, params, cpuBits, gpuBits);

    // Layer 5
    SyncGuardrails g = syzgy::ApplyGuardrails(prevCpuBits, prevGpuBits, cpuBits, gpuBits, params);
    cpuBitsOut = g.nextCpuBits;
    gpuBitsOut = g.nextGpuBits;
}

} // namespace syzgy