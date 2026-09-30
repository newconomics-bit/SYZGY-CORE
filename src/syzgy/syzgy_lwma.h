// Copyright (c) 2024 SYZGY developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RAVEN_SYZGY_SYZGY_LWMA_H
#define RAVEN_SYZGY_SYZGY_LWMA_H

#include "arith_uint256.h"
#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;

namespace syzgy {

/**
 * LWMA-2 (Monero style) retarget for the SYZGY RandomX / CPU target.
 *
 * This is the CPU half of the dual-PoW difficulty engine. The GPU half is Dark Gravity Wave.
 * LWMA is chosen over DGW for the CPU side because home-CPU and VPS hashrate is volatile: LWMA
 * weights recent blocks linearly and therefore reacts to a hashrate change within a handful of
 * blocks, while DGW's exponential moving average lags badly behind a miner that switches machines.
 *
 * CONSENSUS CONTRACT -- both functions are pure functions of (index chain, params).
 *   * No wall-clock time is read. Only the nTime values already committed in the block index.
 *   * No statics, no mutable state, no caching. Two nodes with the same index compute the same
 *     bits, in the same process or across a restart.
 *   * `pblock` is deliberately NOT read. It exists only so this function can be dropped into the
 *     existing GetNextWorkRequired() call signature unchanged.
 *
 * On-chain role: the block header's single `nBits` field is the GPU (KawPoW) target. The CPU
 * target is *derived* from the index chain at validation time, never read from the header -- a
 * miner must not be able to pick their own CPU target.
 */
unsigned int GetNextRandomXWorkRequired(const CBlockIndex* pindexLast,
                                        const CBlockHeader* pblock,
                                        const Consensus::Params& params);

/**
 * The LWMA-2 arithmetic proper, exposed for unit testing.
 *
 * @param bnPastTargetAvg  T_avg  -- the linearly time-weighted average target over the window.
 * @param nPastBlocks      M      -- number of samples averaged (M = N-1).
 * @param nActualTimespan  T_actual -- observed seconds elapsed across those M samples.
 * @param nTargetTimespan  T_target -- M * S, the seconds those M samples should have taken.
 * @param bnLimit          L      -- the per-algorithm target ceiling (params.randomxLimit).
 * @return the new target, already clamped to [1, L], in compact form.
 *
 * THE STEP-5 GUARD BAND IS [nTargetTimespan/3, nTargetTimespan*3] -- TOTAL-relative, i.e.
 * relative to the TOTAL window timespan T_target, NOT to a per-block figure. The earlier band
 * [T_target/M/3, T_target/M*3] = [S/3, 3S] mixed units (per-block bound applied to a total),
 * so its upper bound always bound on a correctly-timed chain and drove the CPU target down by
 * a factor of M/3 every window -- the FR-02 collapse. Fixed on the founder's direction; see
 * the DEFECT AND FIX block at the top of syzgy_lwma.cpp and section 6.1 step 5 of
 * SYZGY-IMPLEMENTATION-SPEC.md.
 */
unsigned int CalculateLWMANextWorkRequired(const arith_uint256& bnPastTargetAvg,
                                           int64_t nPastBlocks, int64_t nActualTimespan,
                                           int64_t nTargetTimespan, const arith_uint256& bnLimit);

} // namespace syzgy

#endif // RAVEN_SYZGY_SYZGY_LWMA_H