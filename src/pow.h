// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RAVEN_POW_H
#define RAVEN_POW_H

#include "consensus/params.h"
#include "syzgy/syzgy_sync.h"

#include <stdint.h>
#include <string>

class CBlockHeader;
class CBlockIndex;
class uint256;
struct arith_uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

// ============================================================================================
// SYZGY dual-PoW (FR-01..FR-04).
//
// The header carries two independent proofs: a KawPoW (GPU) proof under the header's single
// nBits field, and a RandomX (CPU) proof under its own target, which is DERIVED from the index
// chain rather than read from the header. Both are mandatory; neither may be skipped, and there
// is no option, flag or build switch that turns either off.
//
// Everything below fails CLOSED: if a value cannot be derived, or a check cannot be performed,
// the caller gets false and a human-readable reason. Nothing here ever treats "could not
// verify" as "verified".
// ============================================================================================

/**
 * The CPU (RandomX) target for the block built on `pindexLast`, in compact form.
 *
 * Delegates to syzgy::GetNextRandomXWorkRequired() -- the LWMA-2 retarget in
 * src/syzgy/syzgy_lwma.cpp. This declaration exists so that consensus code has ONE spelling for
 * the dual target rule and never reaches into the syzgy namespace directly.
 */
unsigned int GetNextRandomXWorkRequired(const CBlockIndex* pindexLast,
                                        const CBlockHeader* pblock,
                                        const Consensus::Params& params);

/**
 * Both targets for the next block, plus the proof obligations they imply.
 *
 * `modeOut` is the Sync Controller's routing decision:
 *   DUAL_POW      -- both proofs are mandatory (the normal case);
 *   SINGLE_ALO_GPU-- only the KawPoW proof is mandatory; the CPU target is FROZEN;
 *   SINGLE_ALO_CPU-- only the RandomX proof is mandatory; the GPU target is FROZEN.
 *
 * A single-algo mode is reachable only after one class has been ABSENT from the window for
 * nSyzgyPairingStallBlocks consecutive blocks, and the Controller's anti-trap valve forces
 * DUAL_POW back on within 2 * nSyzgySyncMinRatio blocks, so it can never be a one-way door.
 */
void GetNextDualWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock,
                             const Consensus::Params& params,
                             unsigned int& cpuBitsOut, unsigned int& gpuBitsOut,
                             syzgy::SyncMode& modeOut);

/**
 * FR-01. Verify BOTH proofs of `block` under the obligations of the Sync Controller's mode for
 * the block's parent.
 *
 * GPU (recomputed, never trusted):
 *   1. KAWPOWHash(block, mix_hash) is run over the header, and the recomputed mix MUST equal
 *      block.mix_hash; the resulting hash must meet the header's own nBits, and nBits may not
 *      exceed params.kawpowLimit.
 * CPU (CPU target derived from the parent index; the header cannot choose it):
 *   2. syzgy::RandomXCheckProof(block, seed, cpuTarget, strError) -- which itself recomputes the
 *      RandomX hash of the canonical template, requires it to equal block.hashRandomX, and
 *      requires it to meet cpuTarget. cpuTarget may not exceed params.randomxLimit.
 *
 * Obligation per mode: DUAL_POW requires both; SINGLE_ALO_GPU requires only step 1;
 * SINGLE_ALO_CPU requires only step 2. The two are gated SYMMETRICALLY on purpose: a block from
 * the absent class carries no proof of that class, so checking for one would make the emergency
 * mode unreachable (the Controller could route to it and every such block would then be
 * rejected). The relaxation is WHICH PROOFS ARE REQUIRED -- never whether a required proof is
 * valid, and never how strictly it is checked.
 *
 * FAILS CLOSED, never open:
 *   * RandomX not initialised / not linked -> step 2 fails with a clear error. There is no
 *     fallback, no "best effort" and no switch.
 *   * a null epoch seed where the CPU proof is required -> false, "null seed".
 *   * a derived CPU target that is malformed or above randomxLimit -> false, before the proof is
 *     even evaluated.
 *   * the parent index cannot be resolved at a height where the CPU target is no longer simply
 *     the bootstrap ceiling -> false, "cannot derive" (see the parent-less overload).
 *
 * @param randomxSeed the epoch seed, from GetRandomXSeedForHeight().
 * @return true only if every proof required by the mode is present and valid.
 */
bool CheckDualProofOfWork(const CBlockHeader& block, const Consensus::Params& params,
                          const uint256& randomxSeed, std::string& strError);

/**
 * As above, but with the parent index supplied by the caller. Every caller that HAS the parent
 * (contextual validation, index load) must use this form; the parent is not optional for any
 * block whose CPU target has left the bootstrap ceiling, because LWMA cannot be evaluated
 * without the window.
 */
bool CheckDualProofOfWork(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                          const Consensus::Params& params, const uint256& randomxSeed,
                          std::string& strError);

/**
 * The RandomX epoch seed for the block at `nHeight`.
 *
 * epoch  = nHeight / nSyzgyRandomXEpochLength
 * anchor = the GENESIS MERKLE ROOT for epoch 0, else the block hash at (epoch * length - 1)
 * seed   = CHash256(SYZGY_RANDOMX_SEED_TAG || anchor)
 *
 * Fails closed: a null/unknown anchor, a non-positive epoch length, or an unavailable anchor
 * block all return false with the reason in the caller's string.
 *
 * This form resolves the anchor from the ACTIVE chain. See the overload taking pindexPrev for
 * why, and for the form every consensus path must use.
 */
bool GetRandomXSeedForHeight(int64_t nHeight, const Consensus::Params& params, uint256& seedOut);

/**
 * The RandomX epoch seed for the block whose parent is `pindexPrev` (nullptr = genesis).
 *
 * This is the authoritative form. For epoch N > 0 the anchor block is resolved on `pindexPrev`'s
 * own branch -- walked back with GetAncestor() and memoised per (epoch, anchor hash) -- so a
 * candidate is always checked against the seed its own branch implies, and the memo can never
 * change an answer: it is a cache of a pure function of (epoch, anchor), not consensus state.
 *
 * WHY NOT JUST THE ACTIVE CHAIN: on a side branch the two differ, and a per-branch seed would
 * give each branch a different CPU target, i.e. a different RandomX dataset and a different
 * notion of "balanced difficulty". The seed is a NETWORK-GLOBAL value per epoch. The active
 * chain is still consulted first, so on the common (active-branch) path the two agree by
 * construction. This asymmetry is called out for the founder in SYZGY-IMPLEMENTATION-SPEC.md.
 */
bool GetRandomXSeedForHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params,
                             uint256& seedOut, std::string& strError);

/**
 * FR-04. A block may not be timestamped more than params.nMaxFutureBlockTime (15 minutes)
 * AHEAD OF ITS PARENT.
 *
 * Deliberately parent-relative and NOT purely wall-clock-relative: a wall-clock bound alone
 * does not stop a miner from printing a run of blocks whose timestamps are all allowed to sit
 * slightly in the future, compressing the retarget window's timespan and driving the network's
 * difficulty up for everyone else. What FR-04 bounds is how fast the CHAIN may advance.
 *
 * Guarded: the times are widened to signed 64-bit before subtracting, so a header whose nTime
 * is below its parent's (legal, and caught separately by the median-time-past rule) cannot wrap
 * the unsigned subtraction into a pass. A null parent is the genesis case -- the rule is defined
 * relative to a parent, and the genesis timestamp is a consensus constant fixed in chainparams
 * that no miner can choose -- so it returns true, and the caller comments the exemption.
 *
 * The pure parent-relative form. This is the FR-04 primitive the specification describes.
 */
bool CheckBlockTimestampNotTooFarInFuture(const CBlockHeader* block,
                                          const CBlockIndex* pindexPrev,
                                          const Consensus::Params& params);

/**
 * FR-04 AS WIRED. Identical, except the reference time is max(parent nTime, nNowTime) rather
 * than the parent alone.
 *
 * The parent alone is unusable as a wiring reference: a genesis timestamp is a constant fixed
 * at chain launch and on a real chain it is years old, so a 15-minute parent-relative bound
 * would mean "no block may ever be dated more than 15 minutes after the chain was created" --
 * which rejects EVERY block on regtest, on testnet, and on any fresh chain resumed from an old
 * genesis. That is not a liveness escape hatch, it is a permanent halt, and it was observed
 * before this overload was written. max(parent, now) keeps the parent-relative property exactly
 * where it is meaningful (blocks running ahead of their parents) and degrades to the wall clock
 * where the parent is stale.
 *
 * @param nNowTime the node's adjusted time; pass 0 for the pure parent-relative form.
 */
bool CheckBlockTimestampNotTooFarInFuture(const CBlockHeader* block,
                                          const CBlockIndex* pindexPrev,
                                          int64_t nNowTime,
                                          const Consensus::Params& params);

#endif // RAVEN_POW_H
