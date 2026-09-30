// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RAVEN_SYZGY_SYZGY_SYNC_H
#define RAVEN_SYZGY_SYZGY_SYNC_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class CChain;

namespace syzgy {

/**
 * SYZGY Sync Controller -- PRD section 7 five-layer architecture:
 *
 *     Data Feed -> Health Monitor -> Mode Router -> Difficulty Engine -> Safety Guardrails
 *
 * Each layer is a separate, individually testable function in this header, and the pipeline is
 * literal: CollectDataFeed() feeds EvaluateHealth() feeds RouteMode() feeds
 * ComputeBalancedBits() feeds ApplyGuardrails(). GetNextDualWorkRequired() is the one-call
 * entry point that runs all five in order; the individual layers are exported so that the
 * Step-2 wiring (pow.cpp / newvld.cpp) and the unit tests can call them directly.
 *
 * WHY A CONTROLLER AT ALL. FR-01 makes the RandomX (CPU) proof and the KawPoW (GPU) proof both
 * mandatory in every block. That guarantees both networks are secured, but it means the block
 * interval is set by the SLOWER class: if the CPU side stops hashing, blocks stop entirely, and a
 * chain halt is fatal for a proof-of-work network. The Controller exists so that liveness has a
 * bounded, deterministic escape, while the escape itself can never become a trap.
 */

/** Which proof obligations the next block is being issued under. */
enum class SyncMode {
    /** Strict FR-01. Both proofs required, both targets retargeted. The normal mode. */
    DUAL_POW,
    /** Emergency. CPU (RandomX) present, GPU (KawPoW) absent. The GPU target is FROZEN. */
    SINGLE_ALO_CPU,
    /** Emergency. GPU (KawPoW) present, CPU (RandomX) absent. The CPU target is FROZEN. */
    SINGLE_ALO_GPU,
};

/**
 * Layer 1 -- Data Feed.
 *
 * Per-algorithm observations over the trailing `params.nSyzgySyncWindow` block slots.
 * Every field is derived from committed index data; nothing here reads a wall clock.
 *
 * PRESENCE IS COUNTED DIRECTLY FROM THE BLOCK INDEX, never inferred from cadence or spacing:
 *     CPU (RandomX) proof present  <=>  pindex->hashRandomX is not null
 *     GPU (KawPoW)   proof present  <=>  pindex->mix_hash    is not null
 *
 * A null proof on a NON-GENESIS block is NOT "unknown" and is NOT skipped. It is the on-chain
 * signature of a block that was accepted in emergency mode as a single-algo block: FR-01 was
 * suspended for that one block on purpose. Counting it as absent is exactly right, and skipping
 * it as unknown would hide the very event the Controller exists to respond to.
 *
 * Height 0 (genesis) is the one exception and is handled explicitly: FR-01 has no genesis
 * exemption on SYZGY, so a conforming SYZGY genesis carries BOTH proofs and is counted as a
 * dual block like any other. It is nevertheless excluded from the streak/stall bookkeeping in
 * CollectDataFeed() (the window is walked downwards from the tip and height 0 terminates the
 * walk rather than contributing a slot), so a genesis whose proofs are missing for some
 * pre-SYZGY reason cannot fabricate an emergency mode at the start of the chain.
 */
struct SyncDataFeed {
    int window;                 ///< params.nSyzgySyncWindow, the number of slots walked
    int64_t cpuBlocks;          ///< slots in which a RandomX proof was present
    int64_t gpuBlocks;          ///< slots in which a KawPoW proof was present
    int64_t cpuSolveSeconds;    ///< summed observed spacing across present CPU slots
    int64_t gpuSolveSeconds;    ///< summed observed spacing across present GPU slots
    int64_t cpuDifficulty;      ///< compact CPU target in force at the tip (0 if unavailable)
    int64_t gpuDifficulty;      ///< compact GPU target in force at the tip (0 if unavailable)
    int64_t lastBlockHeight;    ///< height of the tip the feed was collected at (-1 if none)
    int64_t lastBlockTime;      ///< nTime of the tip the feed was collected at

    /** Trailing run of consecutive slots in which the class WAS present. */
    int cpuPresentStreak;
    int gpuPresentStreak;

    /**
     * Trailing run of consecutive slots in which the class was ABSENT, and the height at which
     * that run began. 0 when the class is currently present, so `stallRun > 0` is exactly
     * "currently stalled" with no additional state.
     */
    int64_t cpuStallRun;
    int64_t gpuStallRun;
    int64_t stallStartHeight;
};

/**
 * Layer 2 -- Health Monitor. Distils the feed into the booleans the router needs.
 */
struct SyncHealth {
    bool cpuPresent;        ///< at least one present CPU slot in the window
    bool gpuPresent;        ///< at least one present GPU slot in the window
    int cpuPresencePercent; ///< 100 * cpuBlocks / window
    int gpuPresencePercent; ///< 100 * gpuBlocks / window
    int consecutiveStalls;  ///< max(cpuStallRun, gpuStallRun)
    bool pairingStalled;    ///< consecutiveStalls >= params.nSyzgyPairingStallBlocks

    /**
     * Trailing run of consecutive slots in which the class was present, copied up from the
     * feed. These live here (rather than only in SyncDataFeed) because the Mode Router's
     * recovery rule is stated in terms of them: hysteresis is "both classes present for R
     * consecutive blocks". A caller hand-building a SyncHealth for a test must set them; a
     * default-constructed SyncHealth has them at 0, i.e. "hysteresis not met", which is the
     * fail-closed direction.
     */
    int cpuPresentStreak;
    int gpuPresentStreak;
};

/**
 * Layer 5 -- Safety Guardrails result. `clamped*` reports whether the bound actually bit, so
 * callers can log/metric a persistently clamped retarget (which means something upstream is
 * wrong) without having to re-derive it.
 */
struct SyncGuardrails {
    unsigned int nextCpuBits;
    unsigned int nextGpuBits;
    bool clampedCpu;
    bool clampedGpu;
};

/**
 * Layer 1.
 *
 * The CChain overload and the CBlockIndex overload are two views of the SAME walk and produce
 * byte-identical feeds for the same chain: the CChain form forwards to the pointer form using
 * chain.Tip(). The pointer form exists because GetNextDualWorkRequired() resolves the parent
 * out of mapBlockIndex (which may be on a side branch) and has no active chain to hand.
 */
SyncDataFeed CollectDataFeed(const CChain& chain, const Consensus::Params& params);
SyncDataFeed CollectDataFeed(const CBlockIndex* pindexTip, const Consensus::Params& params);

/** Layer 2. */
SyncHealth EvaluateHealth(const SyncDataFeed& feed, const Consensus::Params& params);

/** Layer 3. */
SyncMode RouteMode(const SyncHealth& health, const Consensus::Params& params);

/**
 * Layer 4. Runs the CPU side on LWMA and the GPU side on Dark Gravity Wave, then applies the
 * bounded proportional balance correction to whichever side is lagging.
 *
 * EMERGENCY INVARIANT: when `mode` is a single-algo mode, the ABSENT class's output bits are
 * returned BIT-IDENTICAL to its input target. No retargeting, no balance correction. This is a
 * hard invariant, not a tuning knob: driving an absent class toward zero difficulty would let
 * anyone mint sub-second blocks and would break the 60s block target (FR-02).
 */
void ComputeBalancedBits(const SyncDataFeed& feed, const SyncHealth& health, SyncMode mode,
                         const Consensus::Params& params,
                         unsigned int& cpuBitsOut, unsigned int& gpuBitsOut);

/**
 * Layer 5. Bounds each side to +/- params.nSyzgySyncMaxRetargetPercent of its previous target,
 * in TARGET space (not compact space), and never lets a target exceed its own algorithm limit.
 */
SyncGuardrails ApplyGuardrails(unsigned int prevCpuBits, unsigned int prevGpuBits,
                               unsigned int desiredCpuBits, unsigned int desiredGpuBits,
                               const Consensus::Params& params);

/**
 * The whole five-layer pipeline for the next block.
 *
 * Resolves the parent from `block->hashPrevBlock` via `mapBlockIndex` so side-branch parents are
 * handled, and FAILS CLOSED if the parent cannot be resolved. Ignores `block->nBits`: the
 * header's single nBits is the GPU target, and the CPU target is derived from the index.
 */
void GetNextDualWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock,
                             const Consensus::Params& params,
                             unsigned int& cpuBitsOut, unsigned int& gpuBitsOut,
                             SyncMode& modeOut);

} // namespace syzgy

#endif // RAVEN_SYZGY_SYZGY_SYNC_H