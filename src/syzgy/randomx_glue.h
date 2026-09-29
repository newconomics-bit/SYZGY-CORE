// Copyright (c) 2026 The SYZGY Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYZGY_RANDOMX_GLUE_H
#define SYZGY_RANDOMX_GLUE_H

#include <stdint.h>
#include <string>

#include "primitives/block.h"
#include "uint256.h"

/**
 * Thin consensus wrapper around the vendored official RandomX implementation
 * (tevador/RandomX, BSD-3-Clause -- see src/syzgy/README.md).
 *
 * FAIL CLOSED: every entry point below returns false / a null hash when RandomX is
 * not initialised or cannot service the request. There is deliberately NO option,
 * flag or build switch that disables verification, and no "best effort" path. A node
 * that cannot compute the RandomX half of the dual proof rejects the block.
 */
namespace syzgy {

/**
 * Domain-separation tag for epoch seed derivation. Prepended to the 32-byte epoch
 * anchor hash before hashing. Bump the version suffix if the derivation ever changes.
 */
extern const char* const SYZGY_RANDOMX_SEED_TAG;

/**
 * Initialise the RandomX subsystem for the active seed. Safe to call more than once;
 * subsequent calls are no-ops while already initialised.
 *
 * @return true on success. On failure strError holds a human-readable reason.
 */
bool RandomXInit(std::string& strError);

/**
 * Release all RandomX resources (dataset, VMs, seed). Idempotent. After this call
 * every RandomXHash()/RandomXCheckProof() fails closed until RandomXInit() succeeds.
 */
void RandomXShutdown();

/**
 * Build (and cache) the RandomX dataset for `seed` WITHOUT changing the active seed.
 *
 * Dataset construction is expensive (seconds to minutes), so callers precompute this
 * ahead of an epoch switch and only then flip the active seed. See RandomXSetActiveSeed().
 */
bool RandomXPrepareDataset(const uint256& seed, std::string& strError);

/**
 * Select `seed` as the active seed, initialising it if necessary. Any cached VMs
 * belonging to a different seed are destroyed.
 */
bool RandomXSetActiveSeed(const uint256& seed, std::string& strError);

/** The currently active seed, or a null uint256 if none has been set. */
uint256 RandomXActiveSeed();

/** True once RandomXInit() has succeeded and a seed is active. */
bool RandomXIsAvailable();

/**
 * Compute the RandomX proof for `header` under `seed`.
 *
 * This is the miner-side entry point. Verification must use RandomXCheckProof().
 *
 * @param hashOut receives the 32-byte RandomX hash (RANDOMX_HASH_SIZE). Only written
 *                on success.
 * @return false on any failure (unavailable, not initialised, allocation failure).
 */
bool RandomXHash(const CBlockHeader& header, const uint256& seed, uint256& hashOut, std::string& strError);

/**
 * Verify a header's committed RandomX proof (FR-01): recompute the RandomX hash of
 * the canonical template under `seed`, require it to equal `header.hashRandomX`, and
 * require the result to meet `target`.
 *
 * Fails closed: returns false if RandomX is unavailable, if the seed is unknown, if
 * the recomputed hash does not match, or if the hash is above the target.
 */
bool RandomXCheckProof(const CBlockHeader& header, const uint256& seed, const uint256& target, std::string& strError);

/**
 * Deterministic epoch seed derivation -- CONSENSUS CRITICAL.
 *
 * For epoch N with epoch length L:
 *   - N == 0 : the anchor is the GENESIS block hash.
 *   - N >  0 : the anchor is the hash of the block at height N*L - 1, i.e. the LAST
 *              block of the previous epoch.
 *
 * seed = CHash256( SYZGY_RANDOMX_SEED_TAG || anchor_hash_32bytes )
 *
 * Every node derives the same seed from the chain alone, so no coordination message
 * and no miner-selectable randomness is involved. Any change to this rule is a hard
 * fork: do not alter the tag, the anchor selection, or the hashing without a version
 * bump in the tag.
 */
uint256 DeriveRandomXSeed(const uint8_t* anchorHash32, const std::string& tag);

/** Epoch containing `nHeight`. Heights < 0 are clamped to epoch 0. */
int64_t RandomXEpochForHeight(int64_t nHeight, int64_t nEpochLength);

/**
 * Height of the anchor block for `nEpoch`.
 * Epoch 0 anchors on the genesis block (height 0); epoch N > 0 anchors on
 * N*nEpochLength - 1.
 */
int64_t RandomXAnchorHeightForEpoch(int64_t nEpoch, int64_t nEpochLength);

} // namespace syzgy

#endif // SYZGY_RANDOMX_GLUE_H
