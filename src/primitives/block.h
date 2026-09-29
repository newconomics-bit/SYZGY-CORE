// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RAVEN_PRIMITIVES_BLOCK_H
#define RAVEN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */

extern uint32_t nKAWPOWActivationTime;

class BlockNetwork
{
public:
    BlockNetwork();
    bool fOnRegtest;
    bool fOnTestnet;
    void SetNetwork(const std::string& network);
};

extern BlockNetwork bNetwork;


class CBlockHeader
{
public:

    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    //KAAAWWWPOW data
    uint32_t nHeight;
    uint64_t nNonce64;
    uint256 mix_hash;

    // SYZGY dual-PoW: RandomX (CPU) proof fields (FR-01). Appended after the KawPoW
    // fields so the serialisation prefix stays byte-compatible with the upstream layout.
    uint64_t nRandomXNonce;
    uint256  hashRandomX;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    // SYZGY removed the legacy nNonce serialisation path. The chain is pre-launch
    // with a re-mined genesis (FR-01), so a single fixed dual-PoW layout is used from block 0.
    // Do not reintroduce the nTime branch -- it is a consensus-divergence hazard.
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nHeight);
        READWRITE(nNonce64);
        READWRITE(mix_hash);
        READWRITE(nRandomXNonce);
        READWRITE(hashRandomX);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;

        nNonce64 = 0;
        nHeight = 0;
        mix_hash.SetNull();

        nRandomXNonce = 0;
        hashRandomX.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;
    uint256 GetX16RHash() const;
    uint256 GetX16RV2Hash() const;

    uint256 GetHashFull(uint256& mix_hash) const;
    uint256 GetKAWPOWHeaderHash() const;
    uint256 GetRandomXHeaderHash() const;
    std::string ToString() const;

    /// Use for testing algo switch
    uint256 TestTiger() const;
    uint256 TestSha512() const;
    uint256 TestGost512() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;


    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;

        // KAWPOW
        block.nHeight        = nHeight;
        block.nNonce64       = nNonce64;
        block.mix_hash       = mix_hash;

        // SYZGY RandomX (CPU) proof
        block.nRandomXNonce  = nRandomXNonce;
        block.hashRandomX    = hashRandomX;
        return block;
    }

    // void SetPrevBlockHash(uint256 prevHash) 
    // {
    //     block.hashPrevBlock = prevHash;
    // }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

/**
 * Custom serializer for CBlockHeader that omits the nNonce and mixHash, for use
 * as input to ProgPow.
 */
class CKAWPOWInput : private CBlockHeader
{
public:
    CKAWPOWInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nHeight);
    }
};

/** Canonical hashing template for the SYZGY RandomX (CPU) proof. `nRandomXNonce` is
 *  included so the CPU miner has a search space; `hashRandomX` is deliberately
 *  EXCLUDED because it is the OUTPUT of the RandomX hash -- including it would be
 *  circular. Both this template and CKAWPOWInput cover the same block template, which
 *  is what makes mandatory pairing (FR-01) meaningful: neither algorithm can be
 *  satisfied against a different header than the other. */
class CRandomXInput : private CBlockHeader
{
public:
    CRandomXInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(nHeight);
        READWRITE(nRandomXNonce);   // the CPU search space
    }
};

/** Returns the canonical RandomX template image for `header`, with hashRandomX zeroed. */
std::vector<unsigned char> GetRandomXTemplateImage(const CBlockHeader& header);

#endif // RAVEN_PRIMITIVES_BLOCK_H
