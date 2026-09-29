// Copyright (c) 2026 The SYZGY Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "syzgy/randomx_glue.h"

#include "crypto/common.h"
#include "hash.h"

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <randomx.h>

/**
 * Weak references to the RandomX C API
 * -----------------------------------
 * librandomx.a is a convenience archive linked into ravend only. The unit-test and
 * tool binaries (and raven-qt) do not link it. If we referenced the RandomX entry
 * points strongly, those binaries would fail to link the moment anything in
 * libraven_consensus (hash.cpp) mentions this module. So we reference them weakly:
 * when the archive is absent every pointer is null and RandomX is reported
 * UNAVAILABLE, which every entry point below treats as a hard failure.
 *
 * The daemon gets the archive pulled in by syzgy/randomx_anchor.cpp, which holds
 * one strong reference.
 */
#if defined(__GNUC__) || defined(__clang__)
#define SYZGY_RX_WEAK __attribute__((weak))
#else
#error "SYZGY RandomX consensus glue requires a compiler with weak symbol support"
#endif

extern "C" {
RANDOMX_EXPORT randomx_flags randomx_get_flags(void) SYZGY_RX_WEAK;
RANDOMX_EXPORT randomx_cache* randomx_alloc_cache(randomx_flags) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_init_cache(randomx_cache*, const void*, size_t) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_release_cache(randomx_cache*) SYZGY_RX_WEAK;
RANDOMX_EXPORT randomx_dataset* randomx_alloc_dataset(randomx_flags) SYZGY_RX_WEAK;
RANDOMX_EXPORT unsigned long randomx_dataset_item_count(void) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_init_dataset(randomx_dataset*, randomx_cache*, unsigned long, unsigned long) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_release_dataset(randomx_dataset*) SYZGY_RX_WEAK;
RANDOMX_EXPORT randomx_vm* randomx_create_vm(randomx_flags, randomx_cache*, randomx_dataset*) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_vm_set_cache(randomx_vm*, randomx_cache*) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_vm_set_dataset(randomx_vm*, randomx_dataset*) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_destroy_vm(randomx_vm*) SYZGY_RX_WEAK;
RANDOMX_EXPORT void randomx_calculate_hash(randomx_vm*, const void*, size_t, void*) SYZGY_RX_WEAK;
}

namespace {

/** True iff the vendored RandomX library is actually linked into this binary. */
bool RandomXLibraryPresent()
{
    return randomx_get_flags != nullptr
        && randomx_alloc_cache != nullptr
        && randomx_init_cache != nullptr
        && randomx_release_cache != nullptr
        && randomx_alloc_dataset != nullptr
        && randomx_dataset_item_count != nullptr
        && randomx_init_dataset != nullptr
        && randomx_release_dataset != nullptr
        && randomx_create_vm != nullptr
        && randomx_vm_set_cache != nullptr
        && randomx_vm_set_dataset != nullptr
        && randomx_destroy_vm != nullptr
        && randomx_calculate_hash != nullptr;
}

/**
 * LITE vs FULL dataset
 * --------------------
 * RandomX has two modes:
 *   - "light"  : only the ~256 MiB cache is kept resident and dataset items are
 *                computed on the fly (randomx_vm_set_cache).
 *   - "full"   : the whole ~2 GiB dataset is kept resident (randomx_alloc_dataset +
 *                randomx_init_dataset + randomx_vm_set_dataset).
 *
 * Both modes produce BIT-IDENTICAL hashes -- the mode is a speed/RAM trade-off only
 * and is therefore NOT consensus critical. Select it at build time with
 * -DSYZGY_RANDOMX_LITE_MODE (useful on memory-constrained nodes and CI). There is
 * intentionally no runtime toggle, so a node's mode cannot change its answers.
 */
#ifdef SYZGY_RANDOMX_LITE_MODE
static const bool SYZGY_RANDOMX_LITE = true;
#else
static const bool SYZGY_RANDOMX_LITE = false;
#endif

/** Per-seed RandomX state: the cache, plus the dataset in full mode. */
struct SeedContext {
    randomx_cache* cache = nullptr;
    randomx_dataset* dataset = nullptr;   // nullptr in lite mode

    ~SeedContext()
    {
        if (dataset) randomx_release_dataset(dataset);
        if (cache) randomx_release_cache(cache);
    }

    SeedContext() = default;
    SeedContext(const SeedContext&) = delete;
    SeedContext& operator=(const SeedContext&) = delete;
};

/** Per-thread virtual machine bound to a particular seed. */
struct VMEntry {
    randomx_vm* vm = nullptr;
    uint256 seed;                          // null => destroyed/invalid
};

/**
 * Locking model
 * -------------
 * One global recursive mutex `g_randomx_mutex` guards ALL RandomX state:
 *   - the seed -> SeedContext map (cache/dataset),
 *   - the active seed,
 *   - the per-thread VM table.
 *
 * The RandomX public API exposes no internal locking and a single randomx_vm is NOT
 * safe for concurrent use, so hashing is serialised. That is a deliberate
 * simplicity-over-throughput choice: a RandomX hash is ~0.1-2 ms, the validator needs
 * one per block plus (in the next wave) two per candidate, and this keeps the code
 * obviously correct. Mining does NOT go through this path -- a miner runs its own
 * multi-threaded RandomX engine against the published seed.
 *
 * A thread_local VMEntry is reused across calls on the same thread to avoid
 * re-allocating a ~2 MiB scratchpad per hash; it is re-created whenever the seed
 * changes. Because the thread_local map itself lives under the global mutex, the
 * lock is never held recursively from the same thread.
 */
std::recursive_mutex g_randomx_mutex;

std::map<uint256, std::shared_ptr<SeedContext>> g_seed_contexts;
std::map<std::thread::id, VMEntry> g_thread_vms;

uint256 g_active_seed;
bool g_initialised = false;

/** Base flags for every VM/dataset we create. No LARGE_PAGES: large-page availability
 *  is a machine property and we do not want a node to fail init for lack of privilege. */
randomx_flags SyzgyRandomXFlags()
{
    randomx_flags flags = randomx_get_flags();
    flags |= RANDOMX_FLAG_JIT;
    return flags;
}

void DestroyVMLocked(VMEntry& entry)
{
    if (entry.vm) {
        randomx_destroy_vm(entry.vm);
        entry.vm = nullptr;
    }
    entry.seed.SetNull();
}

void DestroyAllVMsLocked()
{
    for (auto& kv : g_thread_vms) {
        DestroyVMLocked(kv.second);
    }
    g_thread_vms.clear();
}

void DestroyAllLocked()
{
    DestroyAllVMsLocked();
    g_seed_contexts.clear();
    g_active_seed.SetNull();
    g_initialised = false;
}

/** Build (but do not activate) the cache/dataset for `seed`. Caller holds the lock. */
bool BuildContextLocked(const uint256& seed, std::shared_ptr<SeedContext>& out, std::string& strError)
{
    auto it = g_seed_contexts.find(seed);
    if (it != g_seed_contexts.end()) {
        out = it->second;
        return true;
    }

    if (!RandomXLibraryPresent()) {
        strError = "the vendored RandomX library is not linked into this binary";
        return false;
    }

    std::shared_ptr<SeedContext> ctx = std::make_shared<SeedContext>();

    ctx->cache = randomx_alloc_cache(SyzgyRandomXFlags());
    if (!ctx->cache) {
        strError = "randomx_alloc_cache failed (out of memory?)";
        return false;
    }

    // randomx_init_cache takes an arbitrary-length key; we use the 32-byte seed.
    randomx_init_cache(ctx->cache, seed.begin(), seed.size());

    if (!SYZGY_RANDOMX_LITE) {
        ctx->dataset = randomx_alloc_dataset(SyzgyRandomXFlags());
        if (!ctx->dataset) {
            strError = "randomx_alloc_dataset failed (out of memory? ~2 GiB required in full mode)";
            return false;
        }
        // itemCount may be split across calls, but a single call is simpler and
        // correct; the vendored library is thread-safe for non-overlapping ranges.
        randomx_init_dataset(ctx->dataset, ctx->cache, 0, randomx_dataset_item_count());
    }

    g_seed_contexts.emplace(seed, ctx);
    out = ctx;
    return true;
}

} // anonymous namespace

namespace syzgy {

const char* const SYZGY_RANDOMX_SEED_TAG = "SYZGY/randomx/seed/v1";

bool RandomXInit(std::string& strError)
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);

    if (g_initialised) {
        strError.clear();
        return true;
    }

    if (!RandomXLibraryPresent()) {
        strError = "SYZGY: the vendored RandomX library is not linked into this binary "
                   "(build with --enable-randomx) -- RandomX is UNAVAILABLE and every "
                   "RandomX proof will be rejected";
        return false;
    }

    g_initialised = true;
    g_active_seed.SetNull();
    strError.clear();
    return true;
}

void RandomXShutdown()
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);
    DestroyAllLocked();
}

bool RandomXPrepareDataset(const uint256& seed, std::string& strError)
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);

    if (!g_initialised) {
        strError = "RandomX not initialised (call RandomXInit first)";
        return false;
    }
    if (seed.IsNull()) {
        strError = "null RandomX seed";
        return false;
    }

    std::shared_ptr<SeedContext> ctx;
    if (!BuildContextLocked(seed, ctx, strError)) {
        return false;
    }
    strError.clear();
    return true;
}

bool RandomXSetActiveSeed(const uint256& seed, std::string& strError)
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);

    if (!g_initialised) {
        strError = "RandomX not initialised (call RandomXInit first)";
        return false;
    }
    if (seed.IsNull()) {
        strError = "null RandomX seed";
        return false;
    }

    std::shared_ptr<SeedContext> ctx;
    if (!BuildContextLocked(seed, ctx, strError)) {
        return false;
    }

    if (g_active_seed == seed && !g_active_seed.IsNull()) {
        strError.clear();
        return true;
    }

    // Epoch change: every VM bound to the previous seed is invalid. Evicting the
    // per-thread entries also drops their scratchpads, so the caller should keep the
    // previous context alive only as long as in-flight verification needs it.
    DestroyAllVMsLocked();

    g_active_seed = seed;
    strError.clear();
    return true;
}

uint256 RandomXActiveSeed()
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);
    return g_active_seed;
}

bool RandomXIsAvailable()
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);
    return g_initialised && !g_active_seed.IsNull();
}

bool RandomXHash(const CBlockHeader& header, const uint256& seed, uint256& hashOut, std::string& strError)
{
    std::lock_guard<std::recursive_mutex> lock(g_randomx_mutex);

    if (!g_initialised) {
        strError = "RandomX not initialised";
        return false;
    }
    if (seed.IsNull()) {
        strError = "null RandomX seed";
        return false;
    }

    std::shared_ptr<SeedContext> ctx;
    if (!BuildContextLocked(seed, ctx, strError)) {
        return false;
    }

    // One VM per (thread, seed). Reused across calls; the scratchpad lives inside
    // the randomx_vm, so there is no separate buffer to allocate per call.
    const std::thread::id self = std::this_thread::get_id();
    VMEntry& entry = g_thread_vms[self];
    if (!entry.vm || entry.seed != seed) {
        DestroyVMLocked(entry);
        entry.vm = randomx_create_vm(SyzgyRandomXFlags(), ctx->cache, ctx->dataset);
        if (!entry.vm) {
            strError = "randomx_create_vm failed";
            return false;
        }
        entry.seed = seed;
    }

    // The canonical template image, with hashRandomX zeroed.
    const std::vector<unsigned char> image = GetRandomXTemplateImage(header);
    if (image.empty()) {
        strError = "empty RandomX template image";
        return false;
    }

    unsigned char out[RANDOMX_HASH_SIZE];
    randomx_calculate_hash(entry.vm, image.data(), image.size(), out);

    uint256 result;
    memcpy(result.begin(), out, RANDOMX_HASH_SIZE);
    hashOut = result;
    strError.clear();
    return true;
}

bool RandomXCheckProof(const CBlockHeader& header, const uint256& seed, const uint256& target, std::string& strError)
{
    // RandomXHash() itself fails closed when RandomX is not initialised or the seed
    // is unknown; we do not need a separate pre-check here.
    uint256 computed;
    if (!RandomXHash(header, seed, computed, strError)) {
        strError = "SYZGY: RandomX unavailable or errored (" + strError + ") -- refusing the block (fail closed)";
        return false;
    }

    if (computed != header.hashRandomX) {
        strError = "SYZGY: RandomX proof mismatch";
        return false;
    }

    if (target.IsNull() || target < computed) {
        strError = "SYZGY: RandomX proof is above the block target";
        return false;
    }

    strError.clear();
    return true;
}

uint256 DeriveRandomXSeed(const uint8_t* anchorHash32, const std::string& tag)
{
    // CONSENSUS CRITICAL -- see the header comment. Do not change.
    CHash256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
    hasher.Write(anchorHash32, 32);
    uint256 out;
    hasher.Finalize(out.begin());
    return out;
}

int64_t RandomXEpochForHeight(int64_t nHeight, int64_t nEpochLength)
{
    if (nEpochLength <= 0) return 0;
    if (nHeight < 0) return 0;
    return nHeight / nEpochLength;
}

int64_t RandomXAnchorHeightForEpoch(int64_t nEpoch, int64_t nEpochLength)
{
    if (nEpoch <= 0) return 0;                       // epoch 0 anchors on the genesis block
    if (nEpochLength <= 0) return 0;
    return nEpoch * nEpochLength - 1;               // last block of the previous epoch
}

} // namespace syzgy
