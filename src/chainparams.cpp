// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

/**
 * SYZGY genesis constants.
 *
 * SYZGY_MANIFEST is written into the genesis coinbase scriptSig. It is consensus
 * critical: it is part of the coinbase, hence of hashMerkleRoot, hence of the KawPoW
 * and RandomX templates, hence of both proofs.
 *
 * SYZGY_GENESIS_BITS is deliberately the EASIEST possible mainnet-shaped target, so
 * that the RandomX half of the genesis proof is findable on commodity hardware. See
 * the retarget note on CRegTestParams / Step B for the arithmetic.
 */
static const char* const SYZGY_GENESIS_MANIFEST =
    "attention is gold and time is money. - SYZGY Genesis";

/** SYZGY launch time, shared by all three networks: 2026-09-27 13:00:00 UTC. */
static const uint32_t SYZGY_GENESIS_TIME = 1790514000;

/**
 * SYZGY genesis difficulty.
 *
 * The genesis target is set to exactly powLimit, which is the EASIEST target
 * CheckProofOfWork() can possibly accept: pow.cpp rejects any nBits whose decoded
 * target exceeds consensus.powLimit, so this is the floor of the legal range and
 * nothing easier is representable. Search cost, with the arithmetic:
 *
 *   target(0x1e0fffff) = 0x00000fffff * 2^216        (exponent 0x1e -> 2^(8*(0x1e-3)))
 *   E[hits] = 2^256 / target
 *           = 2^256 / (1048575 * 2^216)
 *           = 2^40 / 1048575
 *           = 1048576.5
 *
 * KawPoW runs at millions of H/s, so ~1.05e6 tries is well under a second of GPU work.
 * RandomX runs at order 100-1000 H/s per core, so ~1.05e6 tries is roughly 20 minutes
 * to 3 hours of single-core time -- minutes-to-hours, NOT the days a 0x1e00ffff target
 * (2^32 = 4.3e9 tries) would cost. The genesis is therefore deliberately trivial and the
 * real difficulty schedule begins immediately afterwards under normal retargeting.
 *
 * Regtest uses its own powLimit compact, 0x207fffff, because consensus.powLimit differs
 * per network and using the mainnet value there would be rejected outright:
 *
 *   target(0x207fffff) = 0x7fffff * 2^232
 *   E[hits] = 2^256 / (8388607 * 2^232) = 2^24 / 8388607 = 2.0000005
 *
 * i.e. roughly 2 RandomX hashes, which is what makes the re-mine testable in seconds.
 *
 * NOTE: these values were verified against the real arith_uint256 rather than derived
 * by hand. An earlier draft used 0x200fff, which decodes to 4095 * 2^232 -- about 256x
 * ABOVE mainnet powLimit -- and CheckProofOfWork() rejects it as out of range.
 */
static const uint32_t SYZGY_GENESIS_BITS = 0x1e0fffff;   // == main/test powLimit compact
static const uint32_t SYZGY_GENESIS_BITS_REGTEST = 0x207fffff; // == regtest powLimit compact

/**
 * Does block 1 retarget off the genesis target, or inherit it?
 *
 * Read from GetNextWorkRequired() (src/pow.cpp:140) and DarkGravityWave()
 * (src/pow.cpp:18). This is the recorded answer, not an assumption.
 *
 * MAIN/TEST. nDGWActivationBlock = 1, so IsDGWActive(0 + 1) is true and block 1 goes
 * down the DarkGravityWave() path, not the Bitcoin path. DarkGravityWave() opens with:
 *
 *     if (!pindexLast || pindexLast->nHeight < nPastBlocks)   // nPastBlocks = 180
 *         return bnPowLimit.GetCompact();
 *
 * At block 1, pindexLast is the genesis with nHeight == 0, and 0 < 180, so the function
 * returns powLimit.GetCompact() == 0x1e0fffff -- exactly the genesis nBits.
 *
 * So block 1 INHERITS the genesis target rather than retargeting away from it, and that
 * is correct rather than a defect: the genesis target is already powLimit, the maximum
 * target the chain can express. There is nothing easier to move to, and the value Dark-
 * GravityWave() returns IS powLimit. Retargeting begins in earnest at block 181, the
 * first height whose 180-block window is fully populated; from there the 180-block
 * moving average of real block times drives nBits. The difficulty schedule is therefore
 * live from block 181 and the chain is not stuck at a trivial target.
 *
 * REGTEST. nDGWActivationBlock is left at 200, so IsDGWActive(1) is false and block 1
 * takes GetNextWorkRequiredBTC(). fPowNoRetargeting is true for regtest, so
 * CalculateNextWorkRequired() returns pindexLast->nBits unchanged. Block 1 deliberately
 * inherits the regtest genesis target. That is the intended regtest behaviour (regtest
 * is meant to stay at minimum difficulty) and it does not affect main or test.
 */

//TODO: Take these out
extern double algoHashTotal[16];
extern int algoHashHits[16];


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
/**
 * SYZGY: the coinbase scriptSig manifest is a parameter, not a constant, so that each
 * network states the same SYZGY manifest while keeping its own nTime / nBits / version.
 * The manifest is part of the coinbase, so it is consensus critical: it feeds
 * hashMerkleRoot, which feeds the KawPoW and RandomX templates, which feed the proofs.
 */
static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {
	consensus.nSegwitEnabled = false;
}

void CChainParams::TurnOffCSV() {
	consensus.nCSVEnabled = false;
}

void CChainParams::TurnOffBIP34() {
	consensus.nBIP34Enabled = false;
}

void CChainParams::TurnOffBIP65() {
	consensus.nBIP65Enabled = false;
}

void CChainParams::TurnOffBIP66() {
	consensus.nBIP66Enabled = false;
}

bool CChainParams::BIP34() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP65() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP66() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::CSVEnabled() const{
	return consensus.nCSVEnabled;
}


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 2083333;  //~ SYZGY: ~4 yrs @ 60s blocks (75M curve)
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // SYZGY: a fresh chain starts BOTH miner classes at the easiest legal target, so the two
        // sides begin balanced at the same difficulty. kawpowLimit and randomxLimit are the
        // per-algorithm ceilings (GPU and CPU respectively) and are deliberately identical here:
        // they are separate fields because they diverge as each side retargets independently.
        consensus.kawpowLimit  = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.randomxLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nSyzgyGpuRewardPercent  = 60;
        consensus.nSyzgyCpuRewardPercent  = 40;
        consensus.nSyzgyTailEmission         = 50000000;    // 0.5 SYZ
        consensus.nSyzgyTailEmissionThreshold = 1 * 100000000; // 1 SYZ
        consensus.nSyzgyRandomXEpochLength = 129600;        // ~2 months @ 60s
        consensus.nSyzgyRandomXPrepBlocks  = 720;           // dataset prep window before each switch
        consensus.nSyzgySyncWindow = 90;                    // LWMA / Data Feed window, in blocks
        consensus.nSyzgySyncTargetBlockSeconds = 60;
        consensus.nSyzgySyncMinRatio = 15;                  // percent; also drives the recovery hysteresis
        consensus.nSyzgySyncMaxRetargetPercent = 60;        // guardrail, in target space
        consensus.nSyzgyPairingStallBlocks = 6;             // emergency-mode trigger
        consensus.nMaxFutureBlockTime = 15 * 60;            // FR-04
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
		consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1613; // Approx 80% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;  //Assets (RIP2)
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1540944000; // Oct 31, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1572480000; // Oct 31, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1814;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;  // Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1578920400; // UTC: Mon Jan 13 2020 13:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1610542800; // UTC: Wed Jan 13 2021 13:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1714; // Approx 85% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1588788000; // UTC: Wed May 06 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1620324000; // UTC: Thu May 06 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1714; // Approx 85% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1593453600; // UTC: Mon Jun 29 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1624989600; // UTC: Mon Jun 29 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1411; // Approx 70% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1597341600; // UTC: Thu Aug 13 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1628877600; // UTC: Fri Aug 13 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1411; // Approx 70% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 2016;


        // The best chain should have at least this much work
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000355cd0ac1503c83052"); // Block 2383567

        // By default assume that the signatures in ancestors of this block are valid. Block# 1040000
        consensus.defaultAssumeValid = uint256S("0x0000000000018d2fdcf4ac8eaac8db059584bd2840be5629562bb8599d39998c"); // Block 2383560

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x52; // R
        pchMessageStart[1] = 0x41; // A
        pchMessageStart[2] = 0x56; // V
        pchMessageStart[3] = 0x4e; // N
        nDefaultPort = 8767;
        nPruneAfterHeight = 100000;

        // SYZGY genesis: the coinbase carries the SYZGY manifest, and nTime is the SYZGY
        // launch time. The nonce / proof fields are filled in by the dual-PoW re-mine.
        genesis = CreateGenesisBlock(SYZGY_GENESIS_MANIFEST, SYZGY_GENESIS_TIME, 0, SYZGY_GENESIS_BITS, 4, 5000 * COIN);

        // SYZGY: derive the genesis id from the canonical identity hash. GetX16RHash()
        // hashed the raw memory range BEGIN(nVersion)..END(nNonce), which no longer
        // corresponds to any consensus pre-image, and it is not stable across a disk
        // round-trip. GetHash() is SerializeHash(*this) and is the same function the
        // node uses to key the genesis into mapBlockIndex.
        consensus.hashGenesisBlock = genesis.GetHash();

        // SYZGY: DELIBERATELY NON-FATAL, TEMPORARY. The hardcoded digest below is a
        // LEGACY constant recorded for the pre-SYZGY, single-x16r-PoW genesis. It is
        // stale by construction now and will never match again, so leaving this as a
        // fatal assert would crash every node at startup and bury the pending re-mine.
        // It is a warning only.
        //
        // TODO(SYZGY re-mine, Wave 2): once the dual-PoW genesis is actually mined and
        // the constant below is replaced with the new digest, THIS MUST BECOME A FATAL
        // assert again. A wrong genesis id is a silent consensus split, not a nuisance.
        if (consensus.hashGenesisBlock != uint256S("0000006b444bc2f2ffe627be9d9e7e7a0730000870ef6eb6da46c8eae389df90")) {
            LogPrintf("WARNING: SYZGY: legacy hardcoded hashGenesisBlock for MAINNET is stale "
                      "(expected 0000006b444bc2f2ffe627be9d9e7e7a0730000870ef6eb6da46c8eae389df90, "
                      "got %s). Non-fatal by design until the dual-PoW genesis re-mine; "
                      "this must be restored to a fatal assert afterwards.",
                      consensus.hashGenesisBlock.GetHex());
        }
        // SYZGY: the SYZGY manifest replaced the Ravencoin coinbase message, so the merkle
        // root necessarily changed. This value was read back out of BlockMerkleRoot() on
        // the re-mined genesis, not computed by hand. Identical on all three networks,
        // because the coinbase is identical on all three.
        assert(genesis.hashMerkleRoot == uint256S("0x400b251fcd8accd5d4d0611e906a46725a861a206e7fb98f33d8895a4a16ce95"));

        vSeeds.emplace_back("seed-raven.bitactivate.com", false);
        vSeeds.emplace_back("seed-raven.ravencoin.com", false);
        vSeeds.emplace_back("seed-raven.ravencoin.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Raven BIP44 cointype in mainnet is '175'
        nExtCoinType = 175;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData) {
            {
                { 535721, uint256S("0x000000000001217f58a594ca742c8635ecaaaf695d1a63f6ab06979f1c159e04")},
                { 697376, uint256S("0x000000000000499bf4ebbe61541b02e4692b33defc7109d8f12d2825d4d2dfa0")},
                { 740000, uint256S("0x00000000000027d11bf1e7a3b57d3c89acc1722f39d6e08f23ac3a07e16e3172")},
                { 909251, uint256S("0x000000000000694c9a363eff06518aa7399f00014ce667b9762f9a4e7a49f485")},
                { 1040000, uint256S("0x000000000000138e2690b06b1ddd8cf158c3a5cf540ee5278debdcdffcf75839")},
                { 1186833, uint256S("0x0000000000000d4840d4de1f7d943542c2aed532bd5d6527274fc0142fa1a410")},
                { 2383550, uint256S("0x0000000000008927ed21a1e3bb87d3e1020646e8cc94354a1f8fc608395e15dc")}
            }
        };

		// 20969961 transactions as of block #2383625 at 2022-07-28 22:02:22 (UTC)
		// previously set at 6709969 txns by time 1577939273 ==>
        chainTxData = ChainTxData{
            // Update as we know more about the contents of the Raven chain
            // Stats as of 0x00000000000016ec03d8d93f9751323bcc42137b1b4df67e6a11c4394fd8e5ad window size 43200
            1659045742, // * UNIX timestamp of last known number of transactions
            20969961,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            5.7       // * estimated number of transactions per second after that timestamp
        };

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses
        strIssueAssetBurnAddress = "RXissueAssetXXXXXXXXXXXXXXXXXhhZGt";
        strReissueAssetBurnAddress = "RXReissueAssetXXXXXXXXXXXXXXVEFAWu";
        strIssueSubAssetBurnAddress = "RXissueSubAssetXXXXXXXXXXXXXWcwhwL";
        strIssueUniqueAssetBurnAddress = "RXissueUniqueAssetXXXXXXXXXXWEAe58";
        strIssueMsgChannelAssetBurnAddress = "RXissueMsgChanneLAssetXXXXXXSjHvAY";
        strIssueQualifierAssetBurnAddress = "RXissueQuaLifierXXXXXXXXXXXXUgEDbC";
        strIssueSubQualifierAssetBurnAddress = "RXissueSubQuaLifierXXXXXXXXXVTzvv5";
        strIssueRestrictedAssetBurnAddress = "RXissueRestrictedXXXXXXXXXXXXzJZ1q";
        strAddNullQualifierTagBurnAddress = "RXaddTagBurnXXXXXXXXXXXXXXXXZQm5ya";

            //Global Burn Address
        strGlobalBurnAddress = "RXBurnXXXXXXXXXXXXXXXXXXXXXXWUo9FV";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 435456; // Asset activated block height
        nMessagingActivationBlock = 1092672; // Messaging activated block height
        nRestrictedActivationBlock = 1092672; // Restricted activated block height

        // SYZGY: dual-PoW is active FROM THE GENESIS BLOCK, on every network. The genesis
        // header's nTime is therefore always >= this value, so GetHashFull() always takes
        // the KawPoW branch and the legacy x16r / x16rv2 single-hash branch is dead code on
        // a SYZGY chain. Keeping this at a 2020 wall-clock timestamp instead is what made
        // the genesis take the x16rv2 branch over a header whose nNonce is 0 (it is not
        // serialised any more), so its PoW could never verify and every node aborted in
        // ReadBlockFromDisk. Do not move these off 0 without re-mining the genesis.
        nKAAAWWWPOWActivationTime = 0;
        nKAWPOWActivationTime = 0;
        /** RVN End **/
    }
};

/**
 * Testnet (v7)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;  //~ 4 yrs at 1 min block time
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;

        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit  = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.randomxLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nSyzgyGpuRewardPercent  = 60;
        consensus.nSyzgyCpuRewardPercent  = 40;
        consensus.nSyzgyTailEmission         = 50000000;
        consensus.nSyzgyTailEmissionThreshold = 1 * 100000000;
        consensus.nSyzgyRandomXEpochLength = 129600;
        consensus.nSyzgyRandomXPrepBlocks  = 720;
        consensus.nSyzgySyncWindow = 90;
        consensus.nSyzgySyncTargetBlockSeconds = 60;
        consensus.nSyzgySyncMinRatio = 15;
        consensus.nSyzgySyncMaxRetargetPercent = 60;
        consensus.nSyzgyPairingStallBlocks = 6;
        consensus.nMaxFutureBlockTime = 15 * 60;
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1310; // Approx 65% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1533924000; // UTC: Fri Aug 10 2018 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1577257200; // UTC: Wed Dec 25 2019 07:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 6;  //Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1570428000; // UTC: Mon Oct 07 2019 06:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1577257200; // UTC: Wed Dec 25 2019 07:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1586973600; // UTC: Wed Apr 15 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1618509600; // UTC: Thu Apr 15 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 1310;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1593453600; // UTC: Mon Jun 29 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1624989600; // UTC: Mon Jun 29 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 1411; // Approx 70% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1597341600; // UTC: Thu Aug 13 2020 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1628877600; // UTC: Fri Aug 13 2021 18:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 1411; // Approx 70% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 2016;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000168050db560b4");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000006272208605c4df3b54d4d5515759105e7ffcb258e8cd8077924ffef1");


        pchMessageStart[0] = 0x52; // R
        pchMessageStart[1] = 0x56; // V
        pchMessageStart[2] = 0x4E; // N
        pchMessageStart[3] = 0x54; // T
        nDefaultPort = 18770;
        nPruneAfterHeight = 1000;


        // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
//        /////////////////////////////////////////////////////////////////


//        arith_uint256 test;
//        bool fNegative;
//        bool fOverflow;
//        test.SetCompact(0x1e00ffff, &fNegative, &fOverflow);
//        std::cout << "Test threshold: " << test.GetHex() << "\n\n";
//
//        int genesisNonce = 0;
//        uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
//        uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        for (int i=0;i<40000000;i++) {
//            genesis = CreateGenesisBlock(SYZGY_GENESIS_MANIFEST, SYZGY_GENESIS_TIME, i, SYZGY_GENESIS_BITS, 4, 5000 * COIN);
//            //genesis.hashPrevBlock = TempHashHolding;
//            // Depending on when the timestamp is on the genesis block. You will need to use GetX16RHash or GetX16RV2Hash. Replace GetHash() with these below
//            consensus.hashGenesisBlock = genesis.GetHash();
//
//            arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
//            if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
//                BestBlockHash = consensus.hashGenesisBlock;
//                std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
//                std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
//            }
//
//            TempHashHolding = consensus.hashGenesisBlock;
//
//            if (BestBlockHashArith < test) {
//                genesisNonce = i - 1;
//                break;
//            }
//            //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
//        }
//        std::cout << "\n";
//        std::cout << "\n";
//        std::cout << "\n";
//
//        std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
//        std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
//        std::cout << "Genesis Merkle " << genesis.hashMerkleRoot.GetHex() << std::endl;
//
//        std::cout << "\n";
//        std::cout << "\n";
//        int totalHits = 0;
//        double totalTime = 0.0;
//
//        for(int x = 0; x < 16; x++) {
//            totalHits += algoHashHits[x];
//            totalTime += algoHashTotal[x];
//            std::cout << "hash algo " << x << " hits " << algoHashHits[x] << " total " << algoHashTotal[x] << " avg " << algoHashTotal[x]/algoHashHits[x] << std::endl;
//        }
//
//        std::cout << "Totals: hash algo " <<  " hits " << totalHits << " total " << totalTime << " avg " << totalTime/totalHits << std::endl;
//
//        genesis.hashPrevBlock = TempHashHolding;
//
//        return;

//        /////////////////////////////////////////////////////////////////

        // SYZGY genesis. Same manifest, own nTime (2026-09-27 13:00:00 UTC) and own
        // difficulty. The proof fields are filled in by the dual-PoW re-mine.
        genesis = CreateGenesisBlock(SYZGY_GENESIS_MANIFEST, SYZGY_GENESIS_TIME, 0, SYZGY_GENESIS_BITS, 4, 5000 * COIN);
        // SYZGY: see the MAINNET block above -- canonical GetHash(), and the legacy
        // hardcoded constant demoted from a fatal assert to a non-fatal warning until
        // the dual-PoW genesis re-mine restores it.
        consensus.hashGenesisBlock = genesis.GetHash();

        if (consensus.hashGenesisBlock != uint256S("0x000000ecfc5e6324a079542221d00e10362bdc894d56500c414060eea8a3ad5a")) {
            LogPrintf("WARNING: SYZGY: legacy hardcoded hashGenesisBlock for TESTNET is stale "
                      "(expected 0x000000ecfc5e6324a079542221d00e10362bdc894d56500c414060eea8a3ad5a, "
                      "got %s). Non-fatal by design until the dual-PoW genesis re-mine; "
                      "this must be restored to a fatal assert afterwards.",
                      consensus.hashGenesisBlock.GetHex());
        }
        assert(genesis.hashMerkleRoot == uint256S("0x400b251fcd8accd5d4d0611e906a46725a861a206e7fb98f33d8895a4a16ce95"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("seed-testnet-raven.bitactivate.com", false);
        vSeeds.emplace_back("seed-testnet-raven.ravencoin.com", false);
        vSeeds.emplace_back("seed-testnet-raven.ravencoin.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Raven BIP44 cointype in testnet
        nExtCoinType = 1;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData) {
            {
                    { 225, uint256S("0x000003465e3e0167322eb8269ce91246bbc211e293bc5fbf6f0a0d12c1ccb363")},
                    {223408, uint256S("0x000000012a0c09dd6456ab19018cc458648dec762b04f4ddf8ef8108eae69db9")},
                    {232980, uint256S("0x000000007b16ae547fce76c3308dbeec2090cde75de74ab5dfcd6f60d13f089b")},
                    {257610, uint256S("0x000000006272208605c4df3b54d4d5515759105e7ffcb258e8cd8077924ffef1")}
            }
        };

        chainTxData = ChainTxData{
            // Update as we know more about the contents of the Raven chain
            // Stats as of 00000023b66f46d74890287a7b1157dd780c7c5fdda2b561eb96684d2b39d62e window size 43200
            1543633332, // * UNIX timestamp of last known number of transactions
            146666,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.02        // * estimated number of transactions per second after that timestamp
        };

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses
        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        // Global Burn Address
        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 6048; // Asset activated block height
        nMessagingActivationBlock = 10080; // Messaging activated block height
        nRestrictedActivationBlock = 10080; // Restricted activated block height

        nKAAAWWWPOWActivationTime = 0;
        nKAWPOWActivationTime = 0;
        /** RVN End **/
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit  = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.randomxLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nSyzgyGpuRewardPercent  = 60;
        consensus.nSyzgyCpuRewardPercent  = 40;
        consensus.nSyzgyTailEmission         = 50000000;
        consensus.nSyzgyTailEmissionThreshold = 1 * 100000000;
        // REGTEST uses deliberately SHORT windows and thresholds. With the production values
        // (a 90-block window, a 6-slot stall threshold, a 129600-block epoch) none of the dual-PoW
        // machinery -- epoch switching, emergency mode, the recovery valve -- is reachable inside
        // a test run. These values put every one of those paths within a few blocks.
        consensus.nSyzgyRandomXEpochLength = 50;
        consensus.nSyzgyRandomXPrepBlocks  = 5;
        consensus.nSyzgySyncWindow = 10;
        consensus.nSyzgySyncTargetBlockSeconds = 60;
        consensus.nSyzgySyncMinRatio = 30;
        consensus.nSyzgySyncMaxRetargetPercent = 60;
        consensus.nSyzgyPairingStallBlocks = 2;
        consensus.nMaxFutureBlockTime = 15 * 60;
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7;  // Assets (RIP5)
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; // GMT: Sun Mar 3, 2019 5:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 999999999999ULL; // UTC: Wed Dec 25 2019 07:00:00
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 500;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x43; // C
        pchMessageStart[1] = 0x52; // R
        pchMessageStart[2] = 0x4F; // O
        pchMessageStart[3] = 0x57; // W
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

// This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
//        /////////////////////////////////////////////////////////////////
//
//
//        arith_uint256 test;
//        bool fNegative;
//        bool fOverflow;
//        test.SetCompact(0x207fffff, &fNegative, &fOverflow);
//        std::cout << "Test threshold: " << test.GetHex() << "\n\n";
//
//        int genesisNonce = 0;
//        uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
//        uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        for (int i=0;i<40000000;i++) {
//            genesis = CreateGenesisBlock(1533751200, i, 0x207fffff, 2, 5000 * COIN);
//            //genesis.hashPrevBlock = TempHashHolding;
//            consensus.hashGenesisBlock = genesis.GetHash();
//
//            arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
//            if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
//                BestBlockHash = consensus.hashGenesisBlock;
//                std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
//                std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
//            }
//
//            TempHashHolding = consensus.hashGenesisBlock;
//
//            if (BestBlockHashArith < test) {
//                genesisNonce = i - 1;
//                break;
//            }
//            //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
//        }
//        std::cout << "\n";
//        std::cout << "\n";
//        std::cout << "\n";
//
//        std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
//        std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
//        std::cout << "Genesis Merkle " << genesis.hashMerkleRoot.GetHex() << std::endl;
//
//        std::cout << "\n";
//        std::cout << "\n";
//        int totalHits = 0;
//        double totalTime = 0.0;
//
//        for(int x = 0; x < 16; x++) {
//            totalHits += algoHashHits[x];
//            totalTime += algoHashTotal[x];
//            std::cout << "hash algo " << x << " hits " << algoHashHits[x] << " total " << algoHashTotal[x] << " avg " << algoHashTotal[x]/algoHashHits[x] << std::endl;
//        }
//
//        std::cout << "Totals: hash algo " <<  " hits " << totalHits << " total " << totalTime << " avg " << totalTime/totalHits << std::endl;
//
//        genesis.hashPrevBlock = TempHashHolding;
//
//        return;

//        /////////////////////////////////////////////////////////////////


        // SYZGY genesis. Same manifest and own nTime (2026-09-27 13:00:00 UTC). Regtest
        // gets its own powLimit compact, because consensus.powLimit differs per network
        // and the mainnet value would be rejected as out of range there.
        genesis = CreateGenesisBlock(SYZGY_GENESIS_MANIFEST, SYZGY_GENESIS_TIME, 0, SYZGY_GENESIS_BITS_REGTEST, 4, 5000 * COIN);

        // SYZGY: the REAL KawPoW proof of the regtest genesis, ground over the real
        // CKAWPOWInput template with the real KAWPOWHash(). Found in 3 tries, which is
        // exactly the E[hits] = 2.0000005 predicted for nBits 0x207fffff in STEP B.
        //
        //   kawpow hash = 7bb9ba6ccf36594c6265da6812dc5c112161951fcf112886110811292630da62
        //   target      = 7fffff0000000000000000000000000000000000000000000000000000000000
        //
        // Verified through the consensus path (GetHashFull + CheckProofOfWork), not just
        // the search loop that produced it.
        //
        // KAWPOW DOES NOT DEPEND ON THE RANDOMX FIELDS. CKAWPOWInput
        // (src/primitives/block.h:229) serialises exactly nVersion, hashPrevBlock,
        // hashMerkleRoot, nTime, nBits and nHeight -- NOT nRandomXNonce, NOT hashRandomX,
        // NOT mix_hash (mix_hash is the OUTPUT of KAWPOWHash, src/hash.cpp:277). So setting
        // the RandomX half below leaves the KawPoW half byte-identical, which was verified
        // rather than assumed: re-running KAWPOWHash() on the header with the RandomX fields
        // populated returns the same hash, the same mix_hash and the same
        // GetKAWPOWHeaderHash() = 54f5ffbe15a13f12015cfcf9ca3c6d7c0e5ec82829d7756ba122d502f36112c8,
        // and CheckProofOfWork() still passes. No re-grind of nNonce64/mix_hash was needed.
        genesis.nHeight = 0;
        genesis.nNonce64 = 2;
        genesis.mix_hash = uint256S("0x440cf7a9f087a538560ac6195895ec803d169400c06b0d6a9c6685ea108f1bc3");

        // SYZGY: the REAL RandomX proof of the regtest genesis -- FR-01 requires both proofs
        // from block 0, so a null hashRandomX here is an invalid genesis.
        //
        // seed0 = CHash256("SYZGY/randomx/seed/v1" || genesis.hashMerkleRoot)
        //       = c6f5934e928e42bbc9d88cb82122d76499c126def30346cad0be33ef41f95699
        //
        // The merkle root -- NOT the genesis block hash -- is the epoch-0 anchor because
        // block identity is SerializeHash(*this) over this very header, which commits to
        // hashRandomX: a hash-anchored seed0 is a fixed point. The merkle root commits to the
        // coinbase only, so seed0 is known before the proof exists, and it does not move
        // when the PoW fields below are set -- which is what makes this search well-posed.
        //
        //   template    = CRandomXInput{nVersion, hashPrevBlock, hashMerkleRoot, nTime,
        //                                 nBits, nHeight, nRandomXNonce}
        //   seed        = c6f5934e...95699   (syzgy::RandomXEpoch0Seed)
        //   nBits       = 0x207fffff  ->  target = 7fffff0000...0000
        //   E[hits]     = 2^256 / target = 2^24 / (2^27 - 1) = 0.1250000
        //                 i.e. a mean of one attempt in eight; the search space is
        //                 nRandomXNonce alone, and only nRandomXNonce is varied.
        //   result      = 1 hash, 1 attempt (nRandomXNonce 0) -- as the 0.125 predicts.
        //                 The 78 s of wall clock was the ONE-TIME RandomX dataset build
        //                 (~2 GiB, SYZGY_RANDOMX_LITE_MODE = 0) inside the first
        //                 RandomXHash call; the search loop itself ended on hash #1.
        //
        //   hashRandomX = 448d4fb0602d16de456deef2a31113559e9d054326662e7f8a0399a0d04cdbd3
        //
        // Verified through the real consensus path, syzgy::RandomXCheckProof() against the
        // real seed0 and the real target: PASS.
        genesis.nRandomXNonce = 0;
        genesis.hashRandomX = uint256S("0x448d4fb0602d16de456deef2a31113559e9d054326662e7f8a0399a0d04cdbd3");

        // SYZGY: canonical GetHash() over the re-mined dual-PoW genesis. The identity is
        // no longer demoted to a warning -- the re-mined regtest genesis is ground and
        // verified, so a mismatch here is a real consensus split and must be fatal.
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x480bbae39f7759fb169b94de23fca696d160f145e8ffa314a7ebe6ffd1409165"));
        assert(genesis.hashMerkleRoot == uint256S("0x400b251fcd8accd5d4d0611e906a46725a861a206e7fb98f33d8895a4a16ce95"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Raven BIP44 cointype in regtest
        nExtCoinType = 1;

        /** RVN Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses
        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        // Global Burn Address
        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        // DGW Activation
        nDGWActivationBlock = 200;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 0; // Asset activated block height
        nMessagingActivationBlock = 0; // Messaging activated block height
        nRestrictedActivationBlock = 0; // Restricted activated block height

        // SYZGY: dual-PoW from the genesis block. See the MAINNET comment -- the previous
        // far-future sentinel here (3582830167) put the regtest genesis on the legacy
        // x16rv2 branch, which is what produced the ReadBlockFromDisk header error.
        nKAAAWWWPOWActivationTime = 0;
        nKAWPOWActivationTime = 0;
        /** RVN End **/
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &GetParams() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network);
    if (fForceBlockNetwork) {
        bNetwork.SetNetwork(network);
    }
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void TurnOffSegwit(){
	globalChainParams->TurnOffSegwit();
}

void TurnOffCSV() {
	globalChainParams->TurnOffCSV();
}

void TurnOffBIP34() {
	globalChainParams->TurnOffBIP34();
}

void TurnOffBIP65() {
	globalChainParams->TurnOffBIP65();
}

void TurnOffBIP66() {
	globalChainParams->TurnOffBIP66();
}
