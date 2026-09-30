# SYZGY ($SYZ) — Implementation Specification

> **STATUS: DESIGN COMPLETE, CODE NOT YET LANDED.**
> This document is the consolidated output of the SYZGY design + implementation planning passes.
> It exists because the sandbox filesystem is ephemeral and an earlier implementation run was lost.
> Treat this as the source of truth for re-implementation.

Base code: Ravencoin Core @ `8cf7097da` (MIT).
Product requirements: see the SYZGY PRD v1.0 supplied by the founder.

---

## 1. Locked design decisions

These were decided in Q&A with the founder. **Do not revisit without asking.**

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Single block header carries BOTH proofs: `rx_nonce` + `rx_hash` appended after the existing KawPoW fields. No version gating, no linked-block pair, nothing in the coinbase. | Prefix-compatible append; satisfies FR-01; keeps header-only/SPV validation intact for the light wallet (FR-12). Two linked blocks would break the 60s spacing and halving math at 2,083,333 blocks. |
| D2 | RandomX = official `tevador/RandomX` (mirror `monero-project/randomx`), vendored, **BSD-3-Clause**. Thin C++ consensus glue. Never a custom implementation, never xmrig. | xmrig is GPLv3 → license contamination of the MIT base, and is miner-side not consensus code. PRD risk mitigation demands a battle-tested base. BSD-3-Clause is MIT-compatible (both permissive, notice-retention only), so vendoring it into the MIT base is safe. |
| D3 | Per-algo difficulty: **LWMA for RandomX/CPU**, **DGW for KawPoW/GPU**, plus a cross-algo **Sync Controller**. Never a single shared target; never DGW on the CPU side. | FR-01 makes both proofs mandatory → block time = slower class. LWMA's fast response suits volatile home-CPU hashrate. |
| D4 | Single coinbase, consensus-enforced outputs. Founder 1 SYZ is **carved from** the block subsidy, not added on top. | Preserves the ~75M curve; keeps the transparent-UTXO pillar. Separate coinbases are impossible (one coinbase per block); a purely off-chain split would break on-chain vesting. |
| D5 | Fresh genesis with the manifesto in the coinbase scriptSig, `nTime = 1790514000`, nonce re-mined. No trusted setup. | Fair launch + independent network identity. PoW needs no ceremony. |
| D6 | TwinStratum is a **separate C++ service**, not part of the daemon, talking standard `getblocktemplate`/`submitblock` RPC. | Security isolation (share-spam/IP bans must never endanger a consensus node); auditability of the Ravencoin-derived base. No existing pool implements a mandatory dual-proof pairing engine. |
| D7 | Shared consensus library `libsyzgy_consensus` linked by BOTH the daemon and the pool. | The pool's O(1) share pre-validation (FR-08) must match daemon acceptance exactly; divergence = orphans and unpaid miners. RPC-only validation would push spam at the daemon. |
| D8 | Keep **autotools**. No CMake migration, no hybrid. | Minimises fork divergence from upstream, keeps the base auditable, makes upstream fixes easy to merge. |
| D9 | Monero-style **periodic RandomX epochs**, ~129,600 blocks (~2 months @ 60s), with a preparation window before each switch. Never a fixed seed; never a 1-year epoch. | Preserves RandomX ASIC-resistance (PRD explicitly excludes ASICs) while bounding dataset-rebuild cost for VPS/home miners. |
| D10 | **Emergency mode**: if one class is absent for a stall threshold, single-algo blocks are accepted to preserve liveness. Absent class's difficulty is **FROZEN**, never driven toward zero. Its reward share is **burned**. Smooth, deterministic return to strict dual-PoW. | A chain halt is fatal for a PoW network. Dropping the absent algo's difficulty to ~0 causes sub-second spam and invites spam attacks. Emergency mode must never become a trap. |
| D11 | P2SH, **not** P2WSH, for the founder multisig — see §7.1. This tree cannot encode witness-script destinations. | `CTxDestination` is `boost::variant<CNoDestination, CKeyID, CScriptID>`; a 32-byte P2WSH payload makes `CRavenAddress::IsValid()` fail. |

---

## 2. File map

### Daemon (existing, modified)

| File | Change |
|------|--------|
| `src/consensus/params.h` | Add SYZGY consensus constants (see §3) |
| `src/chainparams.h` | Add genesis manifesto/time/reward accessors |
| `src/chainparams.cpp` | Full network rebrand + genesis + tokenomics + seeds/checkpoints removal |
| `src/primitives/block.h/.cpp` | Append `nRandomXNonce` / `hashRandomX`; add `CRandomXInput`, `GetRandomXHeaderHash()`; **remove** the `nTime < nKAWPOWActivationTime` serialization branch |
| `src/hash.h/.cpp` | `RandomXHash(header, seed)`, `RandomXHash_OnlyTemplate(header)` |
| `src/pow.h/.cpp` | LWMA hook, `GetNextDualWorkRequired`, `CheckDualProofOfWork`, `GetRandomXSeedForHeight`, `CheckBlockTimestampNotTooFarInFuture`; DGW retargets `kawpowLimit` |
| `src/newvld.cpp` | Dual-PoW header check (fail-closed on seed), coinbase split enforcement, FR-04 future-timestamp rejection, subsidy delegation |
| `src/chain.h` | `CBlockIndex`/`CDiskBlockIndex` carry `nRandomXNonce` + `hashRandomX` |
| `src/txdb.cpp` | `LoadBlockIndexGuts` must restore those two fields |
| `src/init.cpp` | `syzgy::RandomXInit()` on start (fatal on failure), `RandomXShutdown()` on stop |
| `src/clientversion.cpp/.h` | `CLIENT_NAME` → "Syzgy Core"; copyright/licence untouched |
| `src/Makefile.am`, `configure.ac` | Wire the new TUs + `AC_CONFIG_FILES([src/syzgy/syzgy_config.h])` |
| `src/Makefile.test.include` | Register the new test files |

### New — consensus layer `src/syzgy/`

| File | Contents |
|------|----------|
| `randomx_glue.h/.cpp` | RandomX VM lifecycle, dataset prep, `RandomXHash`, `RandomXCheckProof`, `DeriveRandomXSeed`, `RandomXEpochForHeight`, `RandomXAnchorHeightForEpoch` |
| `syzgy_config.h.in` | `SYZGY_HAVE_RANDOMX`, `SYZGY_RANDOMX_LITE_MODE` |
| `syzgy_lwma.h/.cpp` | LWMA-2 for the RandomX/CPU target |
| `syzgy_sync.h/.cpp` | Sync Controller: `SyncMode`, `SyncDataFeed`, `SyncHealth`, `SyncGuardrails`, `EvaluateHealth`, `RouteMode`, `ComputeBalancedBits`, `ApplyGuardrails`, `GetNextDualWorkRequired` |
| `syzgy_subsidy.h/.cpp` | Emission schedule + `CoinbaseSplit` + coinbase validator impl |
| `syzgy_coinbase.h` | Declaration-only: burn script, founder script, `CheckSyzgyCoinbase` |
| `syzgy_gentest.cpp` | Standalone genesis re-mining utility |
| `README.md` | Why the official RandomX library, how to vendor, epoch/anchor rule, and its BSD-3-Clause licence (see `doc/randomx.md` and §8.1) |

### New — pool service `pool/`

`CMakeLists.txt`, `README.md`, `PROTOCOL.md`, `main.cpp`, and:
`config`, `log`, `sha256`, `json`, `httpclient`, `daemon`, `blocktemplate`, `verify`,
`stratum`, `pairing`, `pplns`, `ipban`, `metrics` (each `.h`/`.cpp`).

### New — tests `src/test/`

`syzgy_tests.cpp` (consensus/algorithm), `syzgy_subsidy_tests.cpp` (tokenomics).

---

## 3. Consensus constants (`Consensus::Params` additions)

```
uint256   randomxLimit                     // per-algo CPU target limit
int       nSyzgyGpuRewardPercent  = 60
int       nSyzgyCpuRewardPercent  = 40
int64_t   nSyzgyFounderSubsidy    = 1 * COIN
int       nSyzgyFounderVestingStart = 1
int       nSyzgyFounderVestingEnd   = 1000000
int64_t   nSyzgyTailEmission         = 50000000    // 0.5 SYZ
int64_t   nSyzgyTailEmissionThreshold= 1 * COIN
int64_t   nSyzgyBugBountyReserve   = 750000 * COIN
std::string strFounderMultisigAddress
int64_t   nMaxFutureBlockTime      = 15 * 60
int       nSyzgyRandomXEpochLength = 129600
int       nSyzgyRandomXPrepBlocks  = 720
int       nSyzgySyncWindow         = 90
int       nSyzgySyncTargetBlockSeconds = 60
int       nSyzgySyncMinRatio       = 15
int       nSyzgySyncMaxRetargetPercent = 60
int       nSyzgyPairingStallBlocks = 6
```

Helpers: `IsSyzgyFounderVesting(h)`, `RandomXEpochStart(e)`, `RandomXEpochFor(h)`.

> **Naming:** use `nSyzgyRandomXPrepBlocks` (not `...EpochPrepBlocks`). This mismatch occurred
> once during implementation and must not be reintroduced.

Regtest uses short values so the epoch switch and emergency mode are actually reachable:
`nSyzgySyncWindow = 10`, `nSyzgyPairingStallBlocks = 2`, `nSyzgyRandomXEpochLength = 50`,
`nSyzgyRandomXPrepBlocks = 5`. Testnet shortens the founder vesting end to 100,000.

---

## 4. Network identity

| | Main | Test | Regtest |
|---|---|---|---|
| Magic bytes | `SYZG` `53 59 5A 47` | `SYZT` `53 59 5A 54` | `SYZR` `53 59 5A 52` |
| P2P port | 8765 | 18765 | 18445 |
| PUBKEY prefix | 63 (`S`) | 111 (`t`) | 111 |
| SCRIPT prefix | 123 (`s`) | 196 | 196 |
| SECRET prefix | 179 | 239 | 239 |
| Ext pubkey | `04 88 B2 7E` | `04 35 87 CF` | `04 35 87 CF` |
| SLIP-44 | 501 (**unregistered**) | 1 | 1 |

- **Ravencoin DNS seeds removed entirely.** `vSeeds` and `vFixedSeeds` empty. Do not reference
  `pnSeed6_main` / `pnSeed6_test` from the SYZGY classes.
- **Checkpoints empty at launch** (SEC-01 adds them post-launch).
- `chainTxData` all zeros. `nMinimumChainWork` / `defaultAssumeValid` = `0x00`.
- `nKAWPOWActivationTime = nKAAAWWWPOWActivationTime = 0`; `nDGWActivationBlock = 1`.
- Asset system disabled: all burn amounts `0`; asset/messaging/restricted activation heights
  `2147483647`. BIP9 `ASSETS`, `MSG_REST_ASSETS`, `COINBASE_ASSETS` pinned to the expired
  `1199145601..1230767999` window so they can never activate. `TRANSFER_SCRIPT_SIZE` and
  `ENFORCE_VALUE` stay active (generic hardening).

**Genesis:** `nTime = 1790514000` (2026-09-26 20:00 WIB), `nVersion = 4`, `nBits = 0x1e00ffff`,
reward `0 * COIN`, manifesto in the coinbase scriptSig:
`"attention is gold and time is money. - SYZGY Genesis"`.

---

## 5. Block header layout

```
nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits,
nHeight, nNonce64, mix_hash,            // KawPoW / GPU
nRandomXNonce, hashRandomX              // RandomX / CPU  (appended)
```

Unconditional, from block 0. **The legacy `if (nTime < nKAWPOWActivationTime)` branch is
removed** — a dead path on a pre-launch chain and a consensus-divergence hazard. Do not
reintroduce it.

**Both** `CKAWPOWInput` and `CRandomXInput` serialise the *same* field set
(`nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nHeight`) — no nonce fields. This is
what makes mandatory pairing meaningful: neither algorithm can be satisfied against a different
header than the other.

`nBits` is the **GPU (KawPoW)** target. The **CPU target is derived** from the index chain, not
header-committed — a miner must not be able to pick their own CPU target.

**`nBits` is not searchable in the RandomX input.** Consequence: the RandomX half of the genesis
is a *single deterministic value*, not a search space. Only `nNonce64` (KawPoW) can be ground.

---

## 6. Difficulty + Sync Controller

### 6.1 LWMA-2 (RandomX / CPU)

`N = nSyzgySyncWindow` (90), `M = N-1` (89), `S = nSyzgySyncTargetBlockSeconds` (60),
`L = randomxLimit`.

1. `tip == null || tip->nHeight < M` → `L.GetCompact()` (bootstrap).
2. Weights `w_i = (M+1) - i` for `i = 1..M` (oldest sample excluded — LWMA-2 convention);
   `W = M(M+1)/2`.
3. `T_avg = Σ w_i · SetCompact(B_i.nBits) / W`.
4. `T_actual = B_1.nTime - B_{M+1}.nTime`.
5. `T_target = M · S`; clamp `T_actual` to `[T_target/M/3, T_target/M·3]` = `[20s, 180s]`.
6. `T_new = T_avg · T_actual / T_target` (256-bit integer division).
7. Clamp `1 <= T_new <= L`. Return `T_new.GetCompact()`.
8. Degenerate (`M<1`, `T_target<=0`, or `T_actual==0` pre-clamp) → return `T_avg.GetCompact()` (hold).

Pure function of the index chain. No wall clock, no statics. `pblock` is deliberately unread.

### 6.2 DGW (KawPoW / GPU)

Existing Ravencoin `DarkGravityWave` retained, retargeting `kawpowLimit` instead of `powLimit`.
The KAWPOW-activation special case is removed (dead with `nKAWPOWActivationTime = 0`).

### 6.3 Sync Controller — five layers

```
Data Feed -> Health Monitor -> Mode Router -> Difficulty Engine -> Safety Guardrails
```

- **Data Feed** — per-algorithm observations over `nSyzgySyncWindow`:
  `cpuBlocks`, `gpuBlocks`, `cpuSolveSeconds`, `gpuSolveSeconds`, `cpuDifficulty`,
  `gpuDifficulty`, plus trailing presence streaks and stall-run start heights.
  Presence is counted **directly** from the block index:
  `cpuPresent <=> pindex->hashRandomX` non-null, `gpuPresent <=> pindex->mix_hash` non-null.
  A null proof on a non-genesis block means "accepted in emergency mode as a single-algo block",
  **not** "unknown" — never treat it as missing data.
- **Health Monitor** — `cpuPresent` / `gpuPresent` booleans, presence percentages,
  `consecutiveStalls = max(cpuStallRun, gpuStallRun)`, `pairingStalled = consecutiveStalls >=
  nSyzgyPairingStallBlocks`.
- **Mode Router** — `DUAL_POW` normally; `SINGLE_ALO_CPU` when the GPU is absent and stalled;
  `SINGLE_ALO_GPU` when the CPU is absent and stalled. **Both** absent must never yield a
  single-algo mode.
- **Difficulty Engine** — asymmetric: the CPU side moves on LWMA with a tight clamp, the GPU side
  on DGW with a looser clamp, then a small additional proportional correction is applied to
  whichever side lags, bounded by the guardrail. Measured cap on the balance correction: ~4
  compact units (~4.4%).
- **Safety Guardrails** — each side bounded to ±`nSyzgySyncMaxRetargetPercent` (60%) in target
  space; clamping is reported in the returned struct.

### 6.4 Emergency mode (D10)

- **Trigger** — `pairingStalled` and exactly one class present.
- **Freeze** — in `SINGLE_ALO_CPU` the GPU target is returned **unchanged** (`feed.gpuDifficulty`);
  symmetric for `SINGLE_ALO_GPU`. No retargeting, no balance correction. The absent class can
  therefore never be driven toward zero difficulty → no sub-second spam, FR-02 safe.
- **Reward** — the absent class's share is **burned** to an `OP_RETURN` output. It is not
  redirected anywhere, and total supply for the block is unchanged.
- **Recovery (deterministic, no mutable counter).** Let `R = 2 · nSyzgySyncMinRatio` (30). Return
  to `DUAL_POW` when **either**:
  - *hysteresis*: both classes present for `R` consecutive blocks; or
  - *anti-trap valve*: the current stall run has already lasted `R` blocks.

  The valve forces a return at least once every `R` blocks — **emergency mode can never trap
  the chain.** While recovering, the router emits the laggard's single mode so blocks from
  either class stay valid.

**`GetNextDualWorkRequired` resolves the parent via `mapBlockIndex[hashPrevBlock]`** (covers side
branches) and rejects if the parent is unresolvable. It ignores `block.nBits`; the header's single
`nBits` is the GPU target and the CPU target is derived.

Cost note: the Data Feed re-runs LWMA per window slot (~8k index steps/call). Acceptable for
block validation; memoise by height walking oldest→newest if profiling demands it.

---

## 7. Tokenomics

### 7.1 Founder multisig — P2SH, not P2WSH (D11)

`CTxDestination` is `boost::variant<CNoDestination, CKeyID, CScriptID>` — there is **no**
witness-program alternative, and `CRavenAddress::IsValid()` requires a 20-byte payload. A P2WSH
address (32 bytes) would make `GetFounderScript()` return false and the coinbase check **fail
closed**, bricking heights 1..1,000,000. Use P2SH:

```
redeemScript = OP_2 <pk1> <pk2> <pk3> <pk4> OP_4 OP_CHECKMULTISIG
address      = base58check(SCRIPT_ADDRESS || hash160(redeemScript))
             -> CScriptID(uint160) -> OP_HASH160 <h> OP_EQUAL
```

The previously-assigned derivation (PLACEHOLDER — keys are public, must be regenerated before
mainnet):

```
priv_i = (SHA256("SYZGY founder multisig key i/4") as BE int) mod (n-1) + 1

priv0 f8339807596ba9573085531d39806c128b06586a8721153e3e48b59c4a43ec69
priv1 e6556a2c34b1ebc71ab9ed8a3fff45c7058416388eee060ba78ca4ac856679db
priv2 115929701581255e2d3ef84bede9b9e510931dc58ede1a2038609da520b265ea
priv3 a72ee8339c66dbe293dc36764d1f7dfa4f32c58964308184e8eb7046e95ad589

hash160(redeem) = 33819075859e6645095800f951bf96eae7175036
main    (123) raGXnRd5xP63xEcHFULrTofQbJYd4szgNV
test    (196) 2MwwZfMP7nYv1esnc36f7rxXqY8MV1DUwLT
regtest (196) 2MwwZfMP7nYv1esnc36f7rxXqY8MV1DUwLT
```

All four points were verified on-curve (`y² ≡ x³+7 mod p`) and in range; the three addresses
were decoded back and compared byte-for-byte. Re-verify on landing and add a static-init
self-check in `chainparams.cpp` that recomputes the redeem script, `hash160` and all three
addresses and `abort()`s on mismatch — "verified offline" becomes "verified every process start".

### 7.2 Emission schedule

Epoch `e = nHeight / 2,083,333`. Base subsidy = `1800000000 >> e` satoshis (18 SYZ, exact
satoshi-precise halving).

> **Deviation from the PRD, deliberate.** The PRD's `18 × 2,083,333 × 2 = 74,999,988` is an
> *asymptote* of the halving curve. Whole-SYZ truncation (18, 9, 4, 2, 1) totals **70,833,322**,
> not ~75M — the two statements in the PRD are mutually exclusive. Satoshi-precise halving
> (18, 9, 4.5, 2.25, 1.125) preserves the stated asymptote and is exact at every step. **This
> must be settled before launch**; `BaseSubsidyForEpoch` is the single line to change.

| Height | Epoch | Base | Founder | Miner | GPU 60% | CPU 40% |
|---|---|---|---|---|---|---|
| 1 | 0 | 18 | 1 | 17 | 10.2 | 6.8 |
| 1,000,000 | 0 | 18 | 1 | 17 | 10.2 | 6.8 |
| 1,000,001 | 0 | 18 | 0 | 18 | 10.8 | 7.2 |
| 2,083,332 | 0 | 18 | 0 | 18 | 10.8 | 7.2 |
| 2,083,333 | 1 | 9 | 0 | 9 | 5.4 | 3.6 |
| 4,166,666 | 2 | 4.5 | 0 | 4.5 | 2.7 | 1.8 |

**The founder output *increases* the miner portion by 1 SYZ after height 1,000,000** (17 → 18).
This is the correct reading of "founder 1M is carved FROM emission, keeping total supply at
~75M". Document it in-code so an auditor can check it against the PRD.

**Hard invariant:** `gpuAmount + cpuAmount == minerTotal`, always. Assign the remainder to GPU
deterministically. Without this, nodes compute different amounts and reject each other's blocks.

**Tail emission:** once the computed base subsidy is strictly below
`nSyzgyTailEmissionThreshold` (1 SYZ), pay exactly `nSyzgyTailEmission` (0.5 SYZ) forever.
This replaces the zero-subsidy regime.

**Consequence — be honest about this:** the tail emission converts the 74,999,988 asymptote
into a linear overflow. Cumulative supply crosses 75,000,000 SYZ at **height 15,104,224** and
grows without bound. "75M hard cap" is a curve, not a ceiling. The PRD acknowledges this.

### 7.3 Coinbase enforcement

Required value-bearing outputs:
1. GPU output, exactly `split.gpuAmount`
2. CPU output, exactly `split.cpuAmount`
3. founder output, exactly `split.founderAmount`, to the 2-of-4 multisig — iff `hasFounder`
4. burn `OP_RETURN`, exactly the absent class's amount — iff `burnAbsentClass` (emergency only)

Allowances: transaction fees on the **GPU output only**; any zero-valued output (this is how the
SegWit witness commitment passes); witness data untouched.
Rejections: a third value-bearing output, a wrong amount, a missing required output, a burn
output outside emergency mode, duplicate burn/founder.

Destination **amounts** are matched by value; exact output count does the rest. GPU/CPU
destination *addresses* cannot be matched at consensus time (they live in the block template, not
in `params`).

Enforced from height 1; **genesis is skipped entirely**. Must not break the `fDBCheck` /
reload-from-disk paths.

---

## 8. RandomX epochs

- Epoch `N = height / nSyzgyRandomXEpochLength`.
- Seed = `CHash256(fixed_tag || anchor32)`, where the tag is `"SYZGY/randomx/seed/v1"`.
  Every node derives an identical seed with no consensus chatter.
- **Anchor for epoch `N > 0`** is the hash of the block at height `N × epochLength - 1`, i.e. the
  last block of the previous epoch. Unchanged.
- **Anchor for epoch `0` is the GENESIS MERKLE ROOT, not the genesis block hash:**

  ```
  seed0 = CHash256("SYZGY/randomx/seed/v1" || genesis.hashMerkleRoot)
  ```

  **Why the merkle root and not the genesis hash — circularity.** Block identity is
  `SerializeHash(*this)` over the canonical dual-PoW header, and that header COMMITS to
  `hashRandomX` (the RandomX proof is a serialised header field). So anchoring epoch 0 on the
  genesis block hash is a fixed point:

  ```
  seed0 = f(genesis_hash)
  genesis_hash = g(header) ⊇ hashRandomX = RandomX(CRandomXInput, seed0)
  ```

  Grinding `hashRandomX` changes the genesis hash → changes `seed0` → changes every RandomX hash →
  changes `hashRandomX`. There is no value to search for: it is not merely awkward, it is
  undefined. The merkle root commits to the genesis coinbase (manifesto, output script) and to
  nothing in the header's PoW fields — not `nNonce64`/`mix_hash`, not `nRandomXNonce`/`hashRandomX`.
  It is therefore computable *before* any proof exists, is identical on every node, and closes the
  loop. Note that `seed0` also does not move when the genesis PoW fields are ground, which is what
  makes the epoch-0 search well-posed: the RandomX search space is over `nRandomXNonce` only, and
  the target it must meet is a function of `seed0` alone.

  **FR-01 implication.** FR-01 makes both proofs mandatory from block 0. A genesis block that
  carries a null `hashRandomX` is *invalid under FR-01* — there is no "genesis is exempt" clause.
  A non-circular seed0 rule is therefore a PRE-CONDITION for the chain existing at all: without it
  the genesis block cannot carry a valid RandomX proof, and therefore cannot be mined, and
  therefore there is no chain to validate. This is the single reason the rule is fixed the way it
  is.

  **Rejected alternative: computing the genesis hash with `hashRandomX` zeroed** (i.e. defining
  `seed0` from a "pre-proof" genesis hash). Rejected: it is a special-case pre-image that is
  correct only for height 0 and wrong for every later block, i.e. it introduces a second, invisible
  hash rule that an auditor must discover by reading the code rather than the spec. That is the
  recurring bug class in this codebase — genesis-only special cases that silently diverge from the
  general rule (the same class as the earlier `ReadBlockFromDisk`/`GetX16RHash` identity bugs).
  The merkle root needs no special case: it is a *different input*, not a *different hash*, so the
  single `CHash256(tag || anchor32)` rule stays literally true for every epoch.
- `nSyzgyRandomXPrepBlocks` (720) of preparation before each switch, so nodes, miners and the pool
  precompute the next dataset without stalling block production. The pool pre-loads the next key
  so O(1) share verification stays fast across the transition.
- `SYZGY_RANDOMX_LITE_MODE` selects the light (low-RAM VPS) dataset. It affects **speed only, not
  the resulting hash** — not consensus critical, safe as a compile-time option.
- If `SYZGY_HAVE_RANDOMX == 0` every CPU-side verification returns false and the daemon refuses to
  start. **Never fail open.**

### 8.1 Vendored RandomX: licence and pin verification

**Licence — BSD-3-Clause, not dual MIT/BSD.** Verified against the upstream tree at the pinned
commit, not recalled: `src/randomx/LICENSE` is the *only* licence file, it carries the canonical
3-clause BSD body, and its two copyright lines are `tevador 2018-2019` and
`The Monero Project 2014-2019`. There is **no MIT permission grant anywhere in the tree**. (The
one `Permission is hereby granted` string in the repo is in `vcxproj/h2inc.ps1`, an unrelated MIT
build helper we do not use.) Monero's *pre-4.0* codebase was dual MIT/BSD, but that is a different
codebase and does not apply here — do not restate the licence as "MIT/BSD".

BSD-3-Clause **is** MIT-compatible for our purposes: both are permissive and the only obligation is
retaining the copyright notice and disclaimer, which the submodule checkout plus `doc/randomx.md`
satisfy. Vendoring it into the MIT base is therefore sound. The xmrig rejection stands unchanged:
xmrig is GPLv3 and would contaminate the MIT base.

**Pin — verified, keep it.**

| | |
|---|---|
| Pinned commit | `7607fb2faed24d5a679e139a9828d194bbc644a4` |
| Tree hash | `9bf592c6b3241a026f0e35951a1132e2bdbfa421` |
| Position | tip of `master` in **both** `tevador/RandomX` and the official mirror `monero-project/randomx` — identical tree hash in each |
| Describe | `v2.0.1-5-g7607fb2` — 5 commits **ahead** of `v2.0.1` (`aaafe71322df6602c21a5c72937ac284724ae561`) |
| Tagged release? | **No.** The pin is an untagged master commit, deliberately. |

Being ahead of `v2.0.1` is a feature, not drift: the 5 commits include two genuine correctness
fixes — #340 (incorrect dataset-size read) and #343 (x86 JIT template reads on execute-only
systems). A tagged `v2.0.1` pin would carry both bugs. The `v1.2.3` tag sits on a divergent v1.x
branch and is **not** a successor to the v2 line; do not "upgrade" to it.

**Two build facts, now known** (details in `doc/randomx.md`):

* RandomX needs **no generated headers on the GCC path.** The CMake generation step
  (`vcxproj/h2inc.ps1` → `src/asm/configuration.asm`) exists only on the `if(MSVC)` branch, and
  `src/randomx_constants.hpp` does not exist at this revision. Everything the assembler needs is
  committed upstream.
* `configure.ac` **must** carry `AM_PROG_AS`, because the submodule contributes preprocessed `.S`
  sources that automake routes through `CCAS`/`CCASFLAGS`.

---

## 9. TwinStratum pool

### 9.1 Ports and wire protocol

Class is fixed by port with no client-supplied override. CPU `3333` = RandomX, GPU `4444` = KawPoW.

```
mining.subscribe   -> [["mining.set_extranonce","1a2b",true],["mining.notify","cpu"|"gpu"]]
mining.authorize   -> true, then an immediate mining.notify for the live slot
mining.notify      -> (job_id, header_hash, height, bits, curtime, block_id)   [all strings:
                      height exceeds 2^53]
CPU mining.submit        (worker, job_id, randomx_nonce64, nHeight)
GPU mining.submit_kawpow (worker, job_id, header_hash, mix_hash, nNonce64, nHeight)
```

CPU and GPU jobs for a slot share the same `header_hash` but have different job ids. Cross-port
submits are rejected before any other processing. A `header_hash` mismatch is rejected as
consensus-critical.

### 9.2 Slot state machine

```
IDLE -> WAITING -> CPU_ONLY | GPU_ONLY -> PAIRED -> SUBMITTING -> SUBMITTED | FAILED
                     TIMED_OUT reachable from WAITING and from *_ONLY at 45s
```

`TIMED_OUT` records metrics, logs which class was missing and which port to check, prunes the
ring, re-fetches. **An incomplete block is never submitted and no flag can make it.**

### 9.3 PPLNS arithmetic order

```
fee            = R * fee% / 100
distributable  = R - fee
gpuPot         = distributable * 60 / 100
cpuPot         = distributable - gpuPot
finderBonus    = fee * finderBonus% / 100
opsWallet      = fee - finderBonus
each pot split across ITS OWN ring, share value W_i = 2^(i/(N-1)) scaled by share difficulty
finder bonus added on top
```

The bonus comes out of the **fee**, so `sum(miner payouts) <= distributable`. Two distinct
`PplnsRing` objects — a CPU share can never touch the GPU pot.

### 9.4 FR-08 O(1) pre-validation

Genuinely O(1) per share: authorization bool; IP ban via an open-addressed table with a hard
8-probe cap and **fully preallocated** per-IP rings (zero allocation on the share path); field
sanity with fields capped at 16 × 80 bytes and lines at 4 KiB; lazy-refill token bucket with no
timer.

Two bounds are **weaker than a strict worst-case guarantee** and must be documented as such:
1. `std::unordered_map` job lookup is O(1) *expected*, not worst case. The absolute bound comes
   from the 64-entry registry cap, not the container.
2. Per-IP ring retirement is amortised O(1) *per share*, not per call — after a long idle gap one
   call can retire up to `ip_ban_threshold` entries. A strict per-call bound needs a per-IP timer,
   which is exactly the unbounded structure FR-08 forbids.

The expensive dual-proof verification happens in a **bounded worker pool**, never on the socket
read path, and no lock is held while hashing.

### 9.5 Fail-closed verifier

`DualProofVerifier` with `VerifyGpuProof` / `VerifyCpuProof`. With no verifier linked, the pool
rejects every share and logs a loud operator message. A linked verifier returning `Unavailable`
also rejects. **The `Unavailable -> accept` mapping must not exist in the code.** No config key,
env var or flag may change it.

### 9.6 Config keys (24 total, all documented in `pool/README.md`)

`rpc_url`, `rpc_user`, `rpc_password`, `cpu_port` (3333), `gpu_port` (4444), `fee_percent`
(1.0–2.0, default 2.0, **hard error outside**), `pplns_window`, `finder_bonus_percent`,
`operations_wallet` (empty is a hard error), `pairing_timeout_seconds` (45), `slot_seconds` (60),
`ip_ban_threshold`, `ip_ban_seconds`, `share_rate_limit`, `max_connections`, `listen_address`,
`verify_timeout_ms`, `log_level`. `cpu_port == gpu_port` and
`pairing_timeout_seconds >= slot_seconds` are hard startup errors.

---

## 10. Test plan

`src/test/syzgy_tests.cpp` (Boost, `BOOST_FIXTURE_TEST_SUITE(syzgy_tests, BasicTestingSetup)`):

- `syzgy_dual_pow_header_serialization` — round-trip a header with both proofs through a
  `CDataStream` at `PROTOCOL_VERSION`; fixed byte length; a zeroed `hashRandomX` serialises
  **differently** (the fields are genuinely committed).
- `syzgy_randomx_input_is_algo_independent` — `CRandomXInput` and `CKAWPOWInput` serialise the
  **byte-identical** image. This is what makes mandatory pairing meaningful.
- `syzgy_randomx_epoch_math` — epoch boundaries and the `N*len - 1` anchor rule for `N > 0`.
- `syzgy_randomx_epoch0_seed_anchor` — **non-circularity test.** `seed0` derives from the genesis
  merkle root, and `seed0` is unchanged when `hashRandomX` / `nRandomXNonce` are mutated; also
  assert `seed0 != DeriveRandomXSeed(genesis.GetHash())` so a regression to the circular rule
  (or to the zeroed-pre-image variant) fails the suite.
- `syzgy_sync_mode_router` — all four presence combinations; both-absent must not yield a
  single-algo mode; DUAL_POW always reachable (anti-trap).
- `syzgy_sync_guardrails` — ±`nSyzgySyncMaxRetargetPercent` bound; absurd input clamped; clamping
  reported.
- `syzgy_sync_freezes_absent_class` — **critical safety test.** In emergency mode the absent
  class's difficulty is unchanged, not retargeted toward zero.
- `syzgy_lwma_bootstrap` / `syzgy_lwma_holds_on_degenerate_timespan`.

`src/test/syzgy_subsidy_tests.cpp`:

- `syzgy_split_invariant` — **most important test.** `gpu + cpu == minerTotal` and
  `gpu + cpu + founder == total created`, swept across both eras and several halvings. A
  violation is a consensus split.
- `syzgy_halving_schedule`, `syzgy_founder_vesting_window`, `syzgy_tail_emission` (never zero),
  `syzgy_cumulative_supply_monotonic`, `syzgy_supply_crosses_75m`,
  `syzgy_burn_in_emergency` (burn does not change total created).

Every assertion carries a descriptive message. Table-driven loops over repetitive cases.
Deterministic only. **A test whose expected value cannot be determined must be omitted, not
faked** — a green-but-meaningless test is worse than none.

---

## 11. Launch blockers

None of these are optional. Items 1–5 are hard blockers.

1. **Genesis never re-mined.** All networks use `nNonce = 0`; `hashGenesisBlock` is whatever that
   produces; the `assert(hashGenesisBlock == ...)` and `assert(hashMerkleRoot == ...)` lines are
   commented out. Run `syzgy-gentest` once RandomX is vendored. Note §5: only the KawPoW half is
   searchable; if the RandomX half misses, change `nTime` — the tool exits non-zero rather than
   emitting a genesis the node would reject at height 0.
2. **Founder keys are placeholders and burned.** The chain will start and pay vesting, to an
   address nobody can spend.
3. **No DNS seeds, no fixed seeds.** A node with no `-connect` finds no peers.
4. **`src/randomx/` is not vendored** → `SYZGY_HAVE_RANDOMX == 0` → every build produced today
   refuses to start. `git submodule update --init --recursive src/randomx`.
5. **`src/txdb.cpp::LoadBlockIndexGuts` must restore `nRandomXNonce`/`hashRandomX`.** Without it
   a restarted node computes different Sync Controller presence than a fresh one — a chain-split
   risk. (It does copy `nNonce64` and `mix_hash` correctly; only the new fields are missing.)
6. SLIP-44 coin type 501 is unregistered.
7. Binary names are still `ravend` / `raven-cli` / `raven-tx`. `CLIENT_NAME` is `"Syzgy Core"`.
   A rename also needs `Makefile.qt.include`, the three `raven-*-res.rc` files,
   `libravenconsensus.pc.in`, `test/util/raven-util-test.py`, `share/setup.nsi`, `doc/` and
   packaging — do it as one dedicated pass, not piecemeal.
8. **Pre-existing, unrelated:** `src/Makefile.am` listed `validation.cpp`, deleted in `8cf7097da`
   in favour of `newvld.cpp`. Already corrected during the wiring pass; noted because it shows
   the build system had not been exercised since the split.

### 11.1 On-disk format change

Adding the proof fields to `CDiskBlockIndex` changes the LevelDB `DB_BLOCK_INDEX` value layout.
Pre-launch safe **only** because SYZGY ships a new chain with a re-mined genesis and has no index
to migrate; a node with a pre-existing index fails to reindex rather than mis-reading. On an
established chain this would need a version bump and a migration.

---

## 12. Re-implementation order

Work in disjoint-file waves so parallel agents never collide. **No wave may assume an earlier
wave's code exists without grepping for it.**

```
Wave 1 (parallel, disjoint files)
  1A  consensus/params.h, chainparams.h, chainparams.cpp
  1B  primitives/block.h/.cpp, hash.h/.cpp, syzgy/randomx_glue.*, syzgy_config.h.in

Wave 2 (parallel, disjoint files)
  2C  pow.h, pow.cpp, syzgy/syzgy_lwma.*, syzgy/syzgy_sync.*      (needs 1A, 1B)
  2D  newvld.cpp, syzgy/syzgy_subsidy.*, syzgy/syzgy_coinbase.h   (needs 1A, 1B)

Wave 3
  3E  pool/**                                                      (needs 1B header layout)

Wave 4 (parallel, disjoint files)
  4F  Makefile.am, configure.ac, chainparams.cpp, chain.h, init.cpp, clientversion.*,
      syzgy/syzgy_gentest.cpp
  4G  txdb.cpp, syzgy/syzgy_sync.*, test/syzgy_*_tests.cpp, Makefile.test.include
  4H  README.md, whitepaper/, doc/, INSTALL.md, about
```

**Grep before you edit.** Every `Consensus::Params` field name must be confirmed against the
actual `src/consensus/params.h`, not recalled from this document. A single wrong field name
breaks the build, and a single wrong *semantic* (e.g. a null proof treated as "unknown" rather
than "absent") breaks consensus.

Commit after each wave. The filesystem here is ephemeral and uncommitted work has already been
lost once.
