# SYZGY RandomX (CPU) proof — consensus glue

SYZGY is a dual-PoW Layer-1: every valid block must contain **both** a KawPoW proof
(GPU, `src/pow.cpp`) and a RandomX proof (CPU), computed over the *same* block
template. This directory holds the thin consensus wrapper around RandomX.

## Why the official tevador/RandomX

* **Licence.** RandomX is BSD-3-Clause. SYZGY (like Ravencoin Core) is MIT, so
  linking RandomX is a non-issue.
* **xmrig is GPLv3.** XMRig/RandomX-miner forks are GPLv3. Linking a GPLv3 miner
  into a consensus binary would contaminate the MIT codebase, and it is *miner-side*
  software anyway — we must not depend on a project whose licence we cannot absorb.
* **Audited and battle-tested.** tevador/RandomX is the reference implementation
  behind Monero's PoW, the most heavily deployed and reviewed CPU PoW in existence.
  The vendored tree is pinned at commit **`9bf592c6b3241a026f0e35951a1132e2bdbfa421`**.
* **Reference-consensus correctness.** Only the upstream C API is used
  (`randomx_alloc_cache`, `randomx_init_cache`, `randomx_alloc_dataset`,
  `randomx_init_dataset`, `randomx_create_vm`, `randomx_vm_set_cache`,
  `randomx_vm_set_dataset`, `randomx_calculate_hash`, `randomx_destroy_vm`, …),
  read straight from `src/randomx/src/randomx.h`. No algorithm is reimplemented.

## The hashing template

`CRandomXInput` (in `src/primitives/block.h`) serialises, in order:

    nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nHeight, nRandomXNonce

`nRandomXNonce` **must** be in the template — without it the CPU side has no search
space and the RandomX half of a header cannot be ground at all. `hashRandomX` is
deliberately excluded because it is the *output* of the hash (including it would be
circular). `GetRandomXTemplateImage()` returns the raw serialised image, with
`hashRandomX` zeroed defensively.

`CKAWPOWInput` covers the same block template minus both nonces. That shared
coverage is what makes mandatory pairing (FR-01) meaningful: a KawPoW proof cannot
be satisfied for one header while a RandomX proof is satisfied for another.

## Epoch / anchor rule (CONSENSUS CRITICAL)

RandomX's dataset is expensive to build, so SYZGY re-derives it periodically from
chain data. For epoch length `L` and epoch `N`:

* `N == 0` → the anchor is the **genesis merkle root** (`genesis.hashMerkleRoot`),
  *not* the genesis block hash.
* `N >  0` → the anchor is the hash of the block at height `N*L - 1`, i.e. the
  **last block of the previous epoch**.

    seed = CHash256( "SYZGY/randomx/seed/v1" || anchor_32bytes )

**Why the merkle root for epoch 0.** Block identity is `SerializeHash(*this)` over the
canonical dual-PoW header, and that header commits to `hashRandomX`. Deriving `seed0`
from the genesis *block hash* is therefore a fixed point — grinding `hashRandomX`
changes the genesis hash, which changes `seed0`, which changes every RandomX hash.
The merkle root commits to the genesis coinbase only, so it is known before any proof
exists. Without this rule FR-01 cannot be satisfied at height 0 at all: a null
`hashRandomX` at genesis is an invalid genesis. Do not "fix" this by hashing a
genesis hash computed with `hashRandomX` zeroed — that genesis-only special-case
pre-image is the same bug class that has bitten this codebase before.

Every node derives the same seed from the chain alone — no consensus chatter, no
miner-selectable randomness, no off-chain coordination. Changing the tag, the
anchor selection, or the hashing is a **hard fork**; bump the `/v1` suffix if a
future change is ever made.

Nodes should call `syzgy::RandomXPrepareDataset()` for the *next* epoch's seed well
before the boundary, then `syzgy::RandomXSetActiveSeed()` at the switch; the active
switch destroys every cached VM bound to the old seed.

## Lite vs full dataset

RandomX has a *light* mode (only the ~256 MiB cache resident, dataset items computed
on the fly) and a *full* mode (the whole ~2 GiB dataset resident). **The two modes
produce bit-identical hashes** — the choice is purely speed versus RAM and is *not*
consensus critical. It is selected at build time with
`-DSYZGY_RANDOMX_LITE_MODE` (handy for memory-constrained nodes and CI) and is
deliberately not a runtime or user-facing option, so a node's mode can never change
its answers.

## Fail-closed

If RandomX is unavailable — not initialised, no active seed, allocation failure,
unsupported flags — every entry point returns `false` with a diagnostic, and
`RandomXHash()` / `RandomXHash_OnlyTemplate()` in `src/hash.cpp` return a **null
uint256**. There is no option, flag, or build switch that disables RandomX
verification, and no best-effort or "assume valid" path. A node that cannot compute
the CPU half of the dual proof rejects the block.

## Locking

One global `std::recursive_mutex` in `src/syzgy/randomx_glue.cpp` guards the
seed→context map, the active seed, and a per-thread `randomx_vm` table. The
upstream API has no internal locking and a `randomx_vm` is not safe for concurrent
use, so hashing is serialised. This is a deliberate simplicity-over-throughput
choice: a RandomX hash costs ~0.1–2 ms, and a validator needs one per block. Miners
do **not** go through this path — they run their own multi-threaded engine against
the published seed.

## Initialising the submodule

RandomX is vendored as a git submodule at `src/randomx`, pinned to
`9bf592c6b3241a026f0e35951a1132e2bdbfa421`:

    git submodule update --init --recursive src/randomx

The upstream CMake build is deliberately **not** used. `src/Makefile.am` compiles
the tree into a `librandomx.a` convenience library (under the Wave 0
`USE_RANDOMX` conditional) so it can carry its own `-O3 -maes` and per-file
`-mssse3` / `-mavx2` flags without leaking them into the rest of the tree; see
`doc/randomx.md`.

## Status

The glue computes and verifies proofs, but **no consensus validation of the
RandomX proof is wired into `CheckProofOfWork()` yet** — that is the next wave. The
activation of the seed schedule, `RandomXInit()`/`RandomXSetActiveSeed()` at
startup and at epoch boundaries, and the `CheckProofOfWork` call site are all still
to do. Until those land, the dual-PoW rule is defined but not enforced on chain.
