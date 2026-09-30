// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include <hash.h>
#include <streams.h>
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"


static const uint32_t MAINNET_X16RV2ACTIVATIONTIME = 1569945600;
static const uint32_t TESTNET_X16RV2ACTIVATIONTIME = 1567533600;
static const uint32_t REGTEST_X16RV2ACTIVATIONTIME = 1569931200;

uint32_t nKAWPOWActivationTime;

BlockNetwork bNetwork = BlockNetwork();

BlockNetwork::BlockNetwork()
{
    fOnTestnet = false;
    fOnRegtest = false;
}

void BlockNetwork::SetNetwork(const std::string& net)
{
    if (net == "test") {
        fOnTestnet = true;
    } else if (net == "regtest") {
        fOnRegtest = true;
    }
}

// SYZGY: canonical block identity.
//
// The identity hash MUST be a pure function of the SERIALISED header. The previous
// implementation hashed the raw in-memory byte range BEGIN(nVersion)..END(nNonce), which
// spans the legacy nNonce field. nNonce is no longer part of SerializationOp (the chain is
// pre-launch with a re-mined genesis and one fixed dual-PoW layout), it is zeroed by
// SetNull() and it is never restored on a disk read. A block therefore hashed differently
// depending on whether it came from the network, the mempool or the block file: the same
// block had two identities, ReadBlockFromDisk disagreed with mapBlockIndex, ConnectTip
// treated the block as PoW-invalid and AbortNode killed the process.
//
// SerializeHash(*this) commits to the canonical dual-PoW serialisation: nVersion,
// hashPrevBlock, hashMerkleRoot, nTime, nBits, nHeight, nNonce64, mix_hash,
// nRandomXNonce and hashRandomX. It is stable across memory and disk images, and because it
// commits to BOTH proof outputs (mix_hash and hashRandomX) two different valid solutions to
// the same template cannot collapse onto one mapBlockIndex key -- which is the property
// dual-PoW mandatory pairing (FR-01) requires.
uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

// Proof-of-work hash. This is a DIFFERENT quantity from the block identity returned by
// GetHash(): the identity commits to the two proof outputs, while this recomputes one proof
// from the inputs. Callers must pass the claimed mix_hash in; for the KawPoW branch the mix
// is recomputed from the header (nHeight / nNonce64 / header hash) rather than trusted, so
// this is strictly stronger than the old KAWPOWHash_OnlyMix() path GetHash() used to take.
//
// NOTE (SYZGY): the pre-KAWPOW branches below hash the raw range BEGIN(nVersion)..END(nNonce).
// That is intentional and NOT the identity bug: x16r / x16rv2 are real single-hash proof
// algorithms whose pre-image genuinely includes the 32-bit nNonce. It is the pre-re-mine
// legacy path only and is retained until the dual-PoW re-mine moves the chain past
// nKAWPOWActivationTime.
uint256 CBlockHeader::GetHashFull(uint256& mix_hash) const
{
    if (nTime < nKAWPOWActivationTime) {
        uint32_t nTimeToUse = MAINNET_X16RV2ACTIVATIONTIME;
        if (bNetwork.fOnTestnet) {
            nTimeToUse = TESTNET_X16RV2ACTIVATIONTIME;
        } else if (bNetwork.fOnRegtest) {
            nTimeToUse = REGTEST_X16RV2ACTIVATIONTIME;
        }
        if (nTime >= nTimeToUse) {
            return HashX16RV2(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }

        return HashX16R(BEGIN(nVersion), END(nNonce), hashPrevBlock);
    } else {
        return KAWPOWHash(*this, mix_hash);
    }
}




// ---------------------------------------------------------------------------
// LEGACY / NON-CONSENSUS -- DO NOT USE FOR BLOCK IDENTITY OR BLOCK LOOKUP.
//
// These two helpers hash the raw memory range BEGIN(nVersion)..END(nNonce) and are retained
// ONLY so that the historical x16r / x16rv2 genesis digests stay reproducible for diagnostics
// and migration tooling. They are NOT stable across a disk round-trip (nNonce is not
// serialised and is never restored on read), so nothing on a consensus path may call them.
// Consensus identity is CBlockHeader::GetHash(); the proof check is
// CBlockHeader::GetHashFull(mix_hash). Removing them is Wave 2 cleanup.
// ---------------------------------------------------------------------------
uint256 CBlockHeader::GetX16RHash() const
{
    return HashX16R(BEGIN(nVersion), END(nNonce), hashPrevBlock);
}

uint256 CBlockHeader::GetX16RV2Hash() const
{
    return HashX16RV2(BEGIN(nVersion), END(nNonce), hashPrevBlock);
}

/**
 * @brief This takes a block header, removes the nNonce64 and the mixHash. Then performs a serialized hash of it SHA256D.
 * This will be used as the input to the KAAAWWWPOW hashing function
 * @note Only to be called and used on KAAAWWWPOW block headers
 */
uint256 CBlockHeader::GetKAWPOWHeaderHash() const
{
    CKAWPOWInput input{*this};

    return SerializeHash(input);
}

/**
 * @brief This takes a block header and serialises the canonical RandomX template
 * (see CRandomXInput): the KawPoW/GPU side is not part of it, the RandomX nonce is.
 * @note The result is a SERIALISED IMAGE, not a hash. RandomX hashes arbitrary
 * length inputs, so the raw template bytes are what gets fed to randomx_calculate_hash().
 */
uint256 CBlockHeader::GetRandomXHeaderHash() const
{
    CRandomXInput input{*this};

    return SerializeHash(input);
}

std::vector<unsigned char> GetRandomXTemplateImage(const CBlockHeader& header)
{
    CBlockHeader h = header;
    h.hashRandomX.SetNull();

    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << CRandomXInput{h};

    return std::vector<unsigned char>(ss.begin(), ss.end());
}

std::string CBlockHeader::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nNonce64=%u, nHeight=%u)\n",
                   nVersion,
                   hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(),
                   nTime, nBits, nNonce, nNonce64, nHeight);
    return s.str();
}



std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nNonce64=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nNonce64,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

/// Used to test algo switching between X16R and X16RV2

//uint256 CBlockHeader::TestTiger() const
//{
//    return HashTestTiger(BEGIN(nVersion), END(nNonce), hashPrevBlock);
//}
//
//uint256 CBlockHeader::TestSha512() const
//{
//    return HashTestSha512(BEGIN(nVersion), END(nNonce), hashPrevBlock);
//}
//
//uint256 CBlockHeader::TestGost512() const
//{
//    return HashTestGost512(BEGIN(nVersion), END(nNonce), hashPrevBlock);
//}

//CBlock block = GetParams().GenesisBlock();
//int64_t nStart = GetTimeMillis();
//LogPrintf("Starting Tiger %dms\n", nStart);
//block.TestTiger();
//LogPrintf("Tiger Finished %dms\n", GetTimeMillis() - nStart);
//
//nStart = GetTimeMillis();
//LogPrintf("Starting Sha512 %dms\n", nStart);
//block.TestSha512();
//LogPrintf("Sha512 Finished %dms\n", GetTimeMillis() - nStart);
//
//nStart = GetTimeMillis();
//LogPrintf("Starting Gost512 %dms\n", nStart);
//block.TestGost512();
//LogPrintf("Gost512 Finished %dms\n", GetTimeMillis() - nStart);
