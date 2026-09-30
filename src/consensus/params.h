// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RAVEN_CONSENSUS_PARAMS_H
#define RAVEN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <cstdint>
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_ASSETS, // Deployment of RIP2
    DEPLOYMENT_MSG_REST_ASSETS, // Delpoyment of RIP5 and Restricted assets
    DEPLOYMENT_TRANSFER_SCRIPT_SIZE,
    DEPLOYMENT_ENFORCE_VALUE,
    DEPLOYMENT_COINBASE_ASSETS,
    // DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
//    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** Use to override the confirmation window on a specific BIP */
    uint32_t nOverrideMinerConfirmationWindow;
    /** Use to override the the activation threshold on a specific BIP */
    uint32_t nOverrideRuleChangeActivationThreshold;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    bool nBIP34Enabled;
    bool nBIP65Enabled;
    bool nBIP66Enabled;
    // uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    // int BIP65Height;
    /** Block height at which BIP66 becomes active */
    // int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 kawpowLimit;

    // ---------------------------------------------------------------------------------------
    // SYZGY dual-PoW consensus parameters (FR-01..FR-04).
    //
    // FR-01: every block carries BOTH a KawPoW (GPU) proof and a RandomX (CPU) proof. Neither
    // algorithm has a single shared target: the CPU target is retargeted by Monero-style LWMA
    // (src/syzgy/syzgy_lwma.cpp) and the GPU target by Dark Gravity Wave. randomxLimit is the
    // per-algorithm ceiling for the CPU/RandomX side, exactly as kawpowLimit is for the
    // GPU/KawPoW side. No target may ever be easier than its own algorithm's limit.
    // ---------------------------------------------------------------------------------------

    /** Per-algorithm RandomX/CPU target limit. A target strictly above this is invalid. */
    uint256 randomxLimit;

    /** Block reward split between the two miner classes, in percent of the miner total. */
    int nSyzgyGpuRewardPercent;
    int nSyzgyCpuRewardPercent;

    /** Fixed tail emission, paid once the computed base subsidy drops below the threshold. */
    int64_t nSyzgyTailEmission;
    int64_t nSyzgyTailEmissionThreshold;

    /** RandomX dataset epoch length, and the pre-switch preparation window before each change. */
    int nSyzgyRandomXEpochLength;
    int nSyzgyRandomXPrepBlocks;

    /** Sync Controller: LWMA window (blocks), target block time, and balance/retarget bounds. */
    int nSyzgySyncWindow;
    int nSyzgySyncTargetBlockSeconds;
    int nSyzgySyncMinRatio;
    int nSyzgySyncMaxRetargetPercent;

    /** Consecutive slots a miner class may be absent before emergency (single-algo) mode. */
    int nSyzgyPairingStallBlocks;

    /** FR-04: how far into the future a block timestamp may be, relative to adjusted network time. */
    int64_t nMaxFutureBlockTime;

    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    bool nSegwitEnabled;
    bool nCSVEnabled;
};
} // namespace Consensus

#endif // RAVEN_CONSENSUS_PARAMS_H
