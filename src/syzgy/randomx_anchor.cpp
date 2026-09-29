// Copyright (c) 2026 The SYZGY Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Link anchor for the vendored RandomX library.
 *
 * src/syzgy/randomx_glue.cpp resolves the RandomX C entry points through WEAK
 * references, so that binaries which do not link librandomx.a (the unit-test and
 * tool binaries, raven-qt) still link and simply run with RandomX UNAVAILABLE --
 * which the glue treats as fail-closed.
 *
 * The side effect of weak references is that the linker never pulls members out of
 * the librandomx.a convenience archive on their behalf. This translation unit
 * contains an ordinary STRONG reference to one RandomX symbol, which forces the
 * archive members to be extracted. It is compiled into ravend only -- the one
 * binary whose LDADD already contains $(LIBRANDOMX) -- so RandomX is genuinely
 * available in the daemon that validates the chain.
 *
 * This file contains no logic. Do not call anything; do not remove it without
 * also giving ravend a strong reference to RandomX some other way.
 */

#include <randomx.h>

#include <cstddef>

extern "C" RANDOMX_EXPORT unsigned long randomx_dataset_item_count(void);

namespace syzgy {
/** Never dereferenced. Its address exists solely to create a strong link reference. */
extern unsigned long (*const RANDOMX_LINK_ANCHOR)(void) = &randomx_dataset_item_count;
}
