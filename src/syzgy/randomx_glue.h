// Copyright (c) 2026 The SYZGY Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYZGY_RANDOMX_GLUE_H
#define SYZGY_RANDOMX_GLUE_H

#include <stdint.h>
#include <functional>
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
 * seed = CHash256( SYZGY_RANDOMX_SEED_TAG || anchor_32bytes )
 *
 * The single hashing rule above is the same for EVERY epoch. What differs per epoch is only
 * WHICH 32 bytes are the anchor (see RandomXAnchorForEpoch()):
 *
 *   - N == 0 : the GENESIS MERKLE ROOT.
 *   - N >  0 : the block hash at height N*nEpochLength - 1, i.e. the LAST block of the
 *              previous epoch.
 *
 * WHY NOT THE GENESIS BLOCK HASH FOR N == 0 (auditors: read this)
 * -------------------------------------------------------------
 * Block identity is SerializeHash(*this) over the canonical dual-PoW header, and that header
 * COMMITS to hashRandomX -- the RandomX proof is a serialised header field. Anchoring epoch 0
 * on the genesis block hash is therefore a FIXED POINT:
 *
 *     seed0        = f(genesis_hash)
 *     genesis_hash = g(header) which contains hashRandomX = RandomX(CRandomXInput, seed0)
 *
 * i.e. grinding hashRandomX changes the genesis hash, which changes seed0, which changes every
 * RandomX hash, which changes hashRandomX. No such value exists to search for; the rule is not
 * merely awkward, it is undefined.
 *
 * The genesis merkle root commits to the genesis coinbase (manifesto, output script) and to
 * NOTHING in the header's PoW fields -- not nNonce64/mix_hash, not nRandomXNonce/hashRandomX.
 * It is therefore computable BEFORE any proof exists, identical on every node, and closes the
 * loop. Two consequences an auditor can check:
 *   1. FR-01 makes both proofs mandatory from block 0, so a genesis with a null hashRandomX is
 *      invalid. A non-circular seed0 is a PRE-CONDITION for the chain existing at all.
 *   2. seed0 does not move when the genesis PoW fields are ground, which is what makes the
 *      epoch-0 RandomX search well-posed: the search space is nRandomXNonce only, and the
 *      target is a function of seed0 alone.
 *
 * REJECTED ALTERNATIVE: computing the genesis hash with hashRandomX zeroed and using that as the
 * anchor. Rejected because it is a genesis-only special-case PRE-IMAGE -- correct only at height
 * 0, silently divergent everywhere else, and discoverable only by reading code rather than the
 * spec. That is the recurring bug class in this codebase (see the GetX16RHash/ReadBlockFromDisk
 * identity bugs). The merkle root avoids it by being a different INPUT, not a different HASH, so
 * the one rule above stays literally true for every epoch.
 *
 * Every node derives the same seed from the chain alone, so no coordination message and no
 * miner-selectable randomness is involved. Any change to this rule is a hard fork: do not alter
 * the tag, the anchor selection, or the hashing without a version bump in the tag.
 */
uint256 DeriveRandomXSeed(const uint8_t* anchor32, const std::string& tag);

/**
 * Epoch-0 seed, from the genesis merkle root.
 *
 *   seed0 = CHash256(SYZGY_RANDOMX_SEED_TAG || genesisMerkleRoot)
 *
 * Pass `chainparams.Genesis().hashMerkleRoot` -- NOT `consensus.hashGenesisBlock`, which is the
 * circular input described above. Fails closed (returns a null uint256) on a null merkle root.
 */
uint256 RandomXEpoch0Seed(const uint256& genesisMerkleRoot,
                          const std::string& tag = SYZGY_RANDOMX_SEED_TAG);

/**
 * Caller-supplied block-hash-at-height lookup: returns false when the block is unknown to the
 * caller (which makes the seed derivation fail closed rather than silently use a stale value).
 */
typedef std::function<bool(int64_t nHeight, uint256& hashOut)> RandomXBlockHashLookup;

/**
 * Resolve the 32-byte anchor for `nEpoch` (see the rule in the DeriveRandomXSeed() comment):
 * the genesis merkle root for epoch 0, the previous epoch's last block hash otherwise.
 */
bool RandomXAnchorForEpoch(int64_t nEpoch, int64_t nEpochLength,
                           const uint256& genesisMerkleRoot,
                           const RandomXBlockHashLookup& blockHashAtHeight,
                           uint256& anchorOut,
                           std::string& strError);

/** Full seed for `nEpoch`: RandomXAnchorForEpoch() followed by DeriveRandomXSeed(). */
bool RandomXSeedForEpoch(int64_t nEpoch, int64_t nEpochLength,
                         const uint256& genesisMerkleRoot,
                         const RandomXBlockHashLookup& blockHashAtHeight,
                         uint256& seedOut,
                         std::string& strError);

/** Epoch containing `nHeight`. Heights < 0 are clamped to epoch 0. */
int64_t RandomXEpochForHeight(int64_t nHeight, int64_t nEpochLength);

/**
 * Height of the anchor BLOCK for `nEpoch`.
 *
 * Epoch 0 has no anchor block: its anchor is the genesis merkle root (see above), so the 0
 * returned here identifies "genesis" and must NOT be used to fetch a block hash for epoch 0 --
 * use RandomXAnchorForEpoch(), which handles that case. Epoch N > 0 anchors on the block at
 * N*nEpochLength - 1.
 */
int64_t RandomXAnchorHeightForEpoch(int64_t nEpoch, int64_t nEpochLength);

} // namespace syzgy

#endif // SYZGY_RANDOMX_GLUE_H
