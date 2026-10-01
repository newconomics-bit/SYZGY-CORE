// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "hash.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "chainparams.h"
#include "tinyformat.h"

#include "syzgy/randomx_glue.h"
#include "syzgy/syzgy_lwma.h"

unsigned int static DarkGravityWave(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    /* current difficulty formula, dash - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    assert(pindexLast != nullptr);

    // SYZGY: the GPU (KawPoW) side now retargets against ITS OWN limit, params.kawpowLimit,
    // exactly as the CPU (RandomX) side retargets against params.randomxLimit. The two
    // algorithms are independent proofs with independent difficulty engines, and a first-class
    // per-algorithm limit is what lets either of them be moved without touching the other.
    // params.powLimit survives only as the legacy height-0 fallback below and inside the
    // pre-KawPoW min-difficulty rules, which predate dual-PoW and describe a chain in which
    // there is only one algorithm.
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    const arith_uint256 bnGpuLimit = UintToArith256(params.kawpowLimit);
    int64_t nPastBlocks = 180; // ~3hr

    // make sure we have at least (nPastBlocks + 1) blocks, otherwise just return the GPU limit
    if (!pindexLast || pindexLast->nHeight < nPastBlocks) {
        return bnGpuLimit.GetCompact();
    }

    if (params.fPowAllowMinDifficultyBlocks && params.fPowNoRetargeting) {
        // Special difficulty rule:
        // If the new block's timestamp is more than 2 * 1 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
            return nProofOfWorkLimit;
        else {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex *pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                   pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
    }

    const CBlockIndex *pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    int nKAWPOWBlocksFound = 0;
    for (unsigned int nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++) {
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        if (nCountBlocks == 1) {
            bnPastTargetAvg = bnTarget;
        } else {
            // NOTE: that's not an average really...
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        // Count how blocks are KAWPOW mined in the last 180 blocks
        if (pindex->nTime >= nKAWPOWActivationTime) {
            nKAWPOWBlocksFound++;
        }

        if(nCountBlocks != nPastBlocks) {
            assert(pindex->pprev); // should never fail
            pindex = pindex->pprev;
        }
    }

    // If we are mining a KAWPOW block. We check to see if we have mined
    // 180 KAWPOW blocks already. If we haven't we are going to return our
    // temp limit. This will allow us to change algos to kawpow without having to
    // change the DGW math.
    if (pblock->nTime >= nKAWPOWActivationTime) {
        if (nKAWPOWBlocksFound != nPastBlocks) {
            return bnGpuLimit.GetCompact();
        }
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    // NOTE: is this accurate? nActualTimespan counts it for (nPastBlocks - 1) blocks only...
    int64_t nTargetTimespan = nPastBlocks * params.nPowTargetSpacing;

    if (nActualTimespan < nTargetTimespan/3)
        nActualTimespan = nTargetTimespan/3;
    if (nActualTimespan > nTargetTimespan*3)
        nActualTimespan = nTargetTimespan*3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnGpuLimit) {
        bnNew = bnGpuLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredBTC(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
//    int64_t nPrevBlockTime = (pindexLast->pprev ? pindexLast->pprev->GetBlockTime() : pindexLast->GetBlockTime());  //<- Commented out - fixes "not used" warning

    if (IsDGWActive(pindexLast->nHeight + 1)) {
//        LogPrint(BCLog::NET, "Block %s - version: %s: found next work required using DGW: [%s] (BTC would have been [%s]\t(%+d)\t(%0.3f%%)\t(%s sec))\n",
//                 pindexLast->nHeight + 1, pblock->nVersion, dgw, btc, btc - dgw, (float)(btc - dgw) * 100.0 / (float)dgw, pindexLast->GetBlockTime() - nPrevBlockTime);
        return DarkGravityWave(pindexLast, pblock, params);
    }
    else {
//        LogPrint(BCLog::NET, "Block %s - version: %s: found next work required using BTC: [%s] (DGW would have been [%s]\t(%+d)\t(%0.3f%%)\t(%s sec))\n",
//                  pindexLast->nHeight + 1, pblock->nVersion, btc, dgw, dgw - btc, (float)(dgw - btc) * 100.0 / (float)btc, pindexLast->GetBlockTime() - nPrevBlockTime);
        return GetNextWorkRequiredBTC(pindexLast, pblock, params);
    }

}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

// ============================================================================================
// SYZGY dual-PoW -- FR-01..FR-04.
// ============================================================================================

namespace {

/**
 * As CheckProofOfWork(), but range-checked against an explicit limit rather than params.powLimit.
 *
 * The GPU half of a dual block is checked against params.kawpowLimit, because that -- not the
 * legacy single-algorithm powLimit -- is now the GPU algorithm's own ceiling. On all three
 * networks the two values are currently equal, so this changes no answer today; it is here so
 * that moving either limit in the future cannot silently move the other.
 *
 * Comparisons go through UintToArith256, never uint256's own operators: uint256's comparison
 * operators are a raw memcmp over the little-endian byte array and are NOT numeric.
 */
bool CheckProofOfWorkAgainstLimit(const uint256& hash, unsigned int nBits, const uint256& limit)
{
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 bnTarget = arith_uint256().SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(limit)) {
        return false;
    }
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }
    return true;
}

} // namespace

unsigned int GetNextRandomXWorkRequired(const CBlockIndex* pindexLast,
                                        const CBlockHeader* pblock,
                                        const Consensus::Params& params)
{
    return syzgy::GetNextRandomXWorkRequired(pindexLast, pblock, params);
}

void GetNextDualWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock,
                             const Consensus::Params& params,
                             unsigned int& cpuBitsOut, unsigned int& gpuBitsOut,
                             syzgy::SyncMode& modeOut)
{
    // Deliberately a thin, single-line forwarding wrapper. The five-layer Sync Controller
    // (src/syzgy/syzgy_sync.cpp) is the ONLY implementation of the dual rule; if a second copy
    // of these rules existed here, the miner and the validator could disagree and the chain
    // would fork on difficulty rather than on a proof. This wrapper exists so that consensus
    // code has one spelling for "give me both targets" and never reaches into the syzgy
    // namespace for difficulty.
    syzgy::GetNextDualWorkRequired(pindexLast, pblock, params, cpuBitsOut, gpuBitsOut, modeOut);
}

bool GetRandomXSeedForHeight(const CBlockIndex* pindexPrev, const Consensus::Params& params,
                             uint256& seedOut, std::string& strError)
{
    strError.clear();
    seedOut.SetNull();

    const int64_t nEpochLength = params.nSyzgyRandomXEpochLength;
    if (nEpochLength <= 0) {
        strError = strprintf("SYZGY: nSyzgyRandomXEpochLength is %d, cannot derive a RandomX seed",
                             (int)nEpochLength);
        return false;
    }

    // The block this seed is FOR is the child of pindexPrev; a null parent means genesis.
    const int64_t nHeight = (pindexPrev == nullptr) ? 0 : (int64_t)pindexPrev->nHeight + 1;
    const int64_t nEpoch = syzgy::RandomXEpochForHeight(nHeight, nEpochLength);

    // epoch 0 anchors on the GENESIS MERKLE ROOT, never on the genesis block hash: the header
    // commits to hashRandomX, so anchoring on the block hash is a fixed point with no solution.
    // See the long derivation in src/syzgy/randomx_glue.h.
    const uint256& genesisMerkleRoot = GetParams().GenesisBlock().hashMerkleRoot;
    if (genesisMerkleRoot.IsNull()) {
        strError = "SYZGY: genesis merkle root is null, cannot derive the epoch-0 RandomX seed";
        return false;
    }

    const syzgy::RandomXBlockHashLookup lookup =
        [pindexPrev](int64_t nAnchorHeight, uint256& hashOut) -> bool {
            // The active chain first: on the common case (a block extending the active tip) it
            // is the same block pindexPrev's branch would name, and it is a single lookup.
            if (nAnchorHeight >= 0 && chainActive.Height() >= nAnchorHeight) {
                const CBlockIndex* pindexAnchor = chainActive[nAnchorHeight];
                if (pindexAnchor == nullptr) {
                    return false;
                }
                hashOut = pindexAnchor->GetBlockHash();
                return true;
            }
            // Otherwise resolve it on the candidate's own branch. GetAncestor() is exact; where
            // the skip pointers have not been built it degrades to a pprev walk, which is
            // correct and merely slower.
            //
            // The phashBlock test is a guard, not a formality. A real index entry always has it
            // set (insertBlockIndex assigns it at creation), and an entry that does not is a
            // stub whose pprev chain may be absent entirely -- GetAncestor() walks pprev with an
            // assert that a release build compiles away, so a stub would be a null dereference
            // rather than the fail-closed return this function promises. A seed derived from a
            // chain that is not in the index is not a seed at all, so refuse it.
            if (pindexPrev == nullptr || pindexPrev->phashBlock == nullptr) {
                return false;
            }
            const CBlockIndex* pindexAnchor = pindexPrev->GetAncestor((int)nAnchorHeight);
            if (pindexAnchor == nullptr || pindexAnchor->phashBlock == nullptr) {
                return false;
            }
            hashOut = pindexAnchor->GetBlockHash();
            return true;
        };

    uint256 seed;
    std::string strAnchorError;
    if (!syzgy::RandomXSeedForEpoch(nEpoch, nEpochLength, genesisMerkleRoot, lookup, seed,
                                     strAnchorError)) {
        strError = strprintf("SYZGY: cannot derive the RandomX seed for epoch %lld (height %lld): %s",
                             (long long)nEpoch, (long long)nHeight, strAnchorError);
        return false;
    }

    // NOTE ON MEMOISATION. An earlier revision of this file memoised the seed on (epoch, anchor
    // hash) to avoid re-walking to the epoch anchor. That memo was removed because it was both
    // useless and unbounded: the lookup key it *read* was built from an uninitialised uint256,
    // so it could never hit, while the entries it *wrote* accumulated one per header for the
    // life of the process. It is also unnecessary. CChain::operator[] is an O(1) index into the
    // vChain vector, and CBlockIndex::GetAncestor() uses the skip list, so resolving an anchor
    // is not the O(nSyzgyRandomXEpochLength) walk the memo was defending against. Removing it
    // deletes a cache that could have held a stale value without changing any answer.
    seedOut = seed;
    return true;
}

bool GetRandomXSeedForHeight(int64_t nHeight, const Consensus::Params& params, uint256& seedOut)
{
    // The parent-free form: the anchor is resolved from the ACTIVE chain only. Correct for the
    // active branch and for every consensus path that has a parent to hand (all of which use the
    // overload above); it fails closed rather than guessing on a side branch.
    const int64_t nEpochLength = params.nSyzgyRandomXEpochLength;
    if (nEpochLength <= 0) {
        return false;
    }
    const int64_t nEpoch = syzgy::RandomXEpochForHeight(nHeight, nEpochLength);
    const uint256& genesisMerkleRoot = GetParams().GenesisBlock().hashMerkleRoot;
    if (genesisMerkleRoot.IsNull()) {
        return false;
    }
    const syzgy::RandomXBlockHashLookup lookup =
        [](int64_t nAnchorHeight, uint256& hashOut) -> bool {
            if (nAnchorHeight < 0 || chainActive.Height() < nAnchorHeight) {
                return false;
            }
            const CBlockIndex* pindexAnchor = chainActive[nAnchorHeight];
            if (pindexAnchor == nullptr) {
                return false;
            }
            hashOut = pindexAnchor->GetBlockHash();
            return true;
        };
    std::string strError;
    return syzgy::RandomXSeedForEpoch(nEpoch, nEpochLength, genesisMerkleRoot, lookup, seedOut,
                                      strError);
}

bool CheckDualProofOfWork(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                          const Consensus::Params& params, const uint256& randomxSeed,
                          std::string& strError)
{
    strError.clear();

    // ---------------------------------------------------------------------------------------
    // The Sync Controller's mode decides which proofs are REQUIRED. It is resolved FIRST, so
    // that the requirement set and the checks that follow cannot disagree.
    //
    // SINGLE_ALO_CPU means the GPU class is ABSENT, and a block from that class carries no
    // mix_hash. Requiring the GPU proof in that mode would make the mode unreachable -- the
    // Controller could route to it and every such block would then be rejected -- so the two
    // proofs are gated symmetrically. The relaxation is WHICH PROOFS ARE REQUIRED, and nothing
    // else: a proof that IS required is verified in full, with no partial or best-effort form.
    // ---------------------------------------------------------------------------------------
    unsigned int cpuBits = 0;
    unsigned int gpuBits = 0;
    syzgy::SyncMode mode = syzgy::SyncMode::DUAL_POW;
    if (pindexPrev != nullptr) {
        syzgy::GetNextDualWorkRequired(pindexPrev, &block, params, cpuBits, gpuBits, mode);
    } else {
        // GENESIS (height 0), EXPLICITLY. FR-01 has no genesis exemption on SYZGY: the genesis
        // block carries BOTH proofs, so the mode is DUAL_POW here rather than "whatever the
        // controller would say about an empty chain" -- which is DUAL_POW as well, but is
        // stated outright so that a future Controller change cannot silently exempt height 0.
        //
        // The CPU target is params.randomxLimit: 0 < M = nSyzgySyncWindow-1 for every window
        // the code accepts, so LWMA's step-1 bootstrap applies and its answer is the same for
        // any parent including none.
        cpuBits = GetNextRandomXWorkRequired(nullptr, &block, params);
        gpuBits = UintToArith256(params.kawpowLimit).GetCompact();
    }

    // ---------------------------------------------------------------------------------------
    // THE PARENT IS NOT OPTIONAL, AND ITS ABSENCE IS NOT AN EXEMPTION.
    //
    // Below M = nSyzgySyncWindow-1 the bootstrap ceiling IS the correct CPU target, so a null
    // parent looks harmless at first glance. It is not: at height h > 0 the CPU target is
    // supposed to be derived from a committed window, and substituting the easiest legal target
    // for a MISSING derivation is a weaker check than the one FR-01 asks for. Every real caller
    // (ContextualCheckBlockHeader and the txdb index-load re-verification) passes the parent it
    // actually has, which is non-null for every block above height 0, so this branch is
    // unreachable in normal operation -- which is exactly why it is stated as a hard rejection
    // rather than left to the caller's discretion. It was added because "assume the ceiling"
    // is a fail-open shape and the requirement is that there be none.
    //
    // Height 0 is the one admitted null-parent case, handled just above, where the ceiling is
    // the correct answer rather than a substitute for a missing derivation.
    // ---------------------------------------------------------------------------------------
    if (pindexPrev == nullptr && block.nHeight > 0) {
        strError = strprintf("SYZGY: no parent index for height %u, so the RandomX target cannot "
                             "be derived -- refusing the block (fail closed)",
                             block.nHeight);
        return false;
    }

    const bool fGpuRequired = (mode != syzgy::SyncMode::SINGLE_ALO_CPU);
    const bool fCpuRequired = (mode != syzgy::SyncMode::SINGLE_ALO_GPU);

    if (!fGpuRequired && !fCpuRequired) {
        // Unreachable: the Controller never routes to a mode with no obligations. Fail closed
        // rather than accepting a block nobody checked.
        strError = "SYZGY: Sync Controller produced a mode with no proof obligations -- refusing "
                   "the block (fail closed)";
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Step 1 -- GPU / KawPoW. Recomputed from the header's inputs; the claimed mix_hash is
    // never trusted. Only required in DUAL_POW and SINGLE_ALO_GPU.
    // ---------------------------------------------------------------------------------------
    if (fGpuRequired) {
        uint256 mix_hash;
        const uint256 hashKawpow = KAWPOWHash(block, mix_hash);
        if (mix_hash != block.mix_hash) {
            strError = strprintf("SYZGY: invalid KawPoW proof -- recomputed mix %s does not match "
                                 "the claimed mix_hash %s",
                                 mix_hash.ToString(), block.mix_hash.ToString());
            return false;
        }
        // The GPU target is the header's own nBits, which ContextualCheckBlockHeader already
        // pins to GetNextWorkRequired(). Here it is range-checked against the GPU algorithm's
        // own ceiling so that a header can never present a target easier than kawpowLimit.
        if (!CheckProofOfWorkAgainstLimit(hashKawpow, block.nBits, params.kawpowLimit)) {
            strError = strprintf("SYZGY: invalid KawPoW proof -- hash %s does not meet the GPU "
                                 "target 0x%08x",
                                 hashKawpow.ToString(), block.nBits);
            return false;
        }
    }

    // ---------------------------------------------------------------------------------------
    // The CPU target is DERIVED, never read from the header, so the parent index is what it is
    // derived from -- which is why the header cannot choose how easy its own RandomX proof has
    // to be.
    //
    // There is deliberately NO "assume the ceiling when the parent is missing" behaviour at
    // greater heights: the parent-less overload below FAILS CLOSED in that case, because
    // checking a RandomX proof against the easiest legal target is not verification. The only
    // null-parent case admitted here is height 0, handled above, where the ceiling IS the
    // correct answer rather than a substitute for a missing derivation.
    // ---------------------------------------------------------------------------------------

    // Never let the controller, or a caller that got it wrong, walk the CPU target above its own
    // algorithm limit. Done in arith_uint256, not by comparing the compact forms: the compact
    // encoding is a mantissa/exponent pair, and a comparison of two compact values is only
    // monotonic within an exponent, so a compact comparison could reject a perfectly legal
    // derived target. SetCompact's sign/overflow flags are checked at the same time, so a
    // malformed controller output is rejected here rather than silently decoding to zero.
    bool fCpuNegative = false;
    bool fCpuOverflow = false;
    const arith_uint256 bnCpuTarget = arith_uint256().SetCompact(cpuBits, &fCpuNegative, &fCpuOverflow);
    if (fCpuNegative || fCpuOverflow || bnCpuTarget == 0 ||
        bnCpuTarget > UintToArith256(params.randomxLimit)) {
        strError = strprintf("SYZGY: derived RandomX target 0x%08x is not a legal target at or "
                             "below randomxLimit",
                             cpuBits);
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Step 2 -- CPU / RandomX. syzgy::RandomXCheckProof recomputes the hash of the canonical
    // template, requires it to equal block.hashRandomX, and requires it to meet cpuBits. It
    // FAILS CLOSED when RandomX is unavailable; there is no option, flag or build switch that
    // disables it and no path that treats "could not verify" as "verified".
    // ---------------------------------------------------------------------------------------
    if (fCpuRequired) {
        if (randomxSeed.IsNull()) {
            strError = "SYZGY: null RandomX epoch seed -- refusing the block (fail closed)";
            return false;
        }
        const uint256 cpuTarget = ArithToUint256(arith_uint256().SetCompact(cpuBits));
        std::string strRandomXError;
        if (!syzgy::RandomXCheckProof(block, randomxSeed, cpuTarget, strRandomXError)) {
            strError = strprintf("SYZGY: invalid RandomX proof at height %u: %s",
                                 block.nHeight, strRandomXError);
            return false;
        }
    }

    return true;
}

bool CheckDualProofOfWork(const CBlockHeader& block, const Consensus::Params& params,
                          const uint256& randomxSeed, std::string& strError)
{
    // Resolve the parent from mapBlockIndex. Genesis (hashPrevBlock null / height 0) has no
    // parent and is handled explicitly below.
    const CBlockIndex* pindexPrev = nullptr;
    if (block.nHeight > 0) {
        BlockMap::const_iterator it = mapBlockIndex.find(block.hashPrevBlock);
        if (it == mapBlockIndex.end()) {
            strError = strprintf("SYZGY: parent block %s of height %u is unknown, cannot derive "
                                 "the RandomX target -- refusing the block (fail closed)",
                                 block.hashPrevBlock.ToString(), block.nHeight);
            return false;
        }
        pindexPrev = it->second;
    }
    return CheckDualProofOfWork(block, pindexPrev, params, randomxSeed, strError);
}

bool CheckBlockTimestampNotTooFarInFuture(const CBlockHeader* block,
                                          const CBlockIndex* pindexPrev,
                                          const Consensus::Params& params)
{
    // Pure parent-relative form: nNowTime == 0 means "no wall clock available", so the
    // reference is the parent's nTime alone. This is the FR-04 primitive the specification
    // describes, and the form the unit tests exercise.
    return CheckBlockTimestampNotTooFarInFuture(block, pindexPrev, 0, params);
}

bool CheckBlockTimestampNotTooFarInFuture(const CBlockHeader* block,
                                          const CBlockIndex* pindexPrev,
                                          int64_t nNowTime,
                                          const Consensus::Params& params)
{
    if (block == nullptr) {
        return false;
    }

    // GENESIS, EXPLICITLY. FR-04 is defined relative to a parent, and genesis has none. The
    // genesis timestamp is a consensus constant fixed in chainparams and is not miner-chosen,
    // so there is nothing for the rule to protect here. This is NOT a fail-open on any later
    // block: every non-genesis block reaches this with a non-null pindexPrev.
    if (pindexPrev == nullptr) {
        return true;
    }

    const int64_t nBlockTime = (int64_t)block->nTime;
    const int64_t nParentTime = (int64_t)pindexPrev->nTime;

    // nTime is uint32_t and nNowTime is a signed epoch second count, so both sides are widened
    // to signed 64-bit BEFORE the subtraction. Without that, an unsigned difference wraps for
    // any header older than the reference -- legal input, caught separately by the
    // median-time-past rule -- and the wrap would sail straight through this check.

    // Reference time is the LATER of the parent and the wall clock, not the parent alone.
    //
    // WHY NOT THE PARENT ALONE. A genesis timestamp is a constant fixed at chain launch, and on
    // a real chain it is years old. A pure parent-relative bound of 15 minutes therefore means
    // "no block may ever be timestamped more than 15 minutes after the chain was created" --
    // on regtest, testnet, and any fresh chain started from an existing genesis, EVERY block is
    // rejected, forever, and the chain is unmineable. That is not a liveness escape hatch, it
    // is a permanent halt.
    //
    // max(parent, now) keeps the property FR-04 actually wants -- on a chain whose blocks are
    // running AHEAD of their parents, which is the only situation in which a fabricated future
    // timestamp can compress the retarget window, the bound is measured against the parent --
    // while making the rule degrade to the wall clock exactly where the parent is stale and
    // meaningless. It can only ever be the stricter of the two, never the looser.
    //
    // HONEST LIMIT OF FR-04 AS SPECIFIED, which the founder must know: nMaxFutureBlockTime is
    // 15 * 60 = 900 s, while the pre-existing wall-clock bound in ContextualCheckBlockHeader is
    // MAX_FUTURE_BLOCK_TIME_DGW = MAX_FUTURE_BLOCK_TIME / 10 = 720 s. FR-01's sibling rule is
    // therefore LOOSER than the rule it sits next to, and on a live chain where now > parent it
    // never rejects anything the 720 s bound has not already rejected. FR-04 as specified is a
    // no-op on every network. Making it bind requires nMaxFutureBlockTime < 720, which is a
    // consensus-parameter change and therefore the founder's call, not this commit's. What this
    // rule does guarantee, and what it must never be mistaken for, is that it can never WIDEN
    // acceptance: it is the union of the parent-relative and wall-clock bounds, and the 720 s
    // wall-clock bound continues to apply unchanged beside it.
    const int64_t nReferenceTime = (nNowTime > nParentTime) ? nNowTime : nParentTime;
    const int64_t nReferenceLead = nBlockTime - nReferenceTime;
    if (nReferenceLead > params.nMaxFutureBlockTime) {
        return false;
    }
    return true;
}
