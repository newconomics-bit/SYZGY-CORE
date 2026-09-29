# RandomX dependency (vendored)

This file documents how the official RandomX proof-of-work library is vendored and
built inside this repository. It lives **outside** the `src/randomx` submodule on
purpose: git refuses to track files inside a submodule path
(`fatal: Pathspec 'src/randomx/README.syzgy.md' is in submodule 'src/randomx'`), so
anything written there would be lost on the next `git submodule update`.

## Upstream

| | |
|---|---|
| Upstream URL | <https://github.com/tevador/RandomX> |
| Vendored at | `src/randomx` (git submodule) |
| Pinned commit | `7607fb2faed24d5a679e139a9828d194bbc644a4` |
| Upstream describe | `v2.0.1-5-g7607fb2` (master) |
| Fetched with | full clone (not shallow) — all 537 refs present, history is complete |

The canonical upstream is `tevador/RandomX`; `monero-project/randomx` is a mirror of
the same project. We pin the canonical one.

Initialise/update with:

```
git submodule update --init --recursive
```

## Licence

RandomX is **BSD-3-Clause** — the `LICENSE` file in the submodule is a single
BSD-3-Clause text and does *not* offer a dual MIT alternative, and every library
source header repeats the same 3-clause BSD text. The first lines of
`src/randomx/LICENSE` are:

```
Copyright (c) 2018-2019, tevador <tevador@gmail.com>

Copyright (c) 2014-2019, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without
```

(One unrelated file in the repo, `vcxproj/h2inc.ps1`, is separately MIT-licensed;
it is a build helper we do not use. The Argon2 sources are CC0, per their headers.)

The SYZGY/Raven base is MIT (see `COPYING`). BSD-3-Clause is permissive and
MIT-compatible: the only obligations are retaining the copyright notice and
disclaimer in redistributions, which the submodule checkout plus this file
satisfy. Linking RandomX into an MIT work keeps the combined work distributable
under MIT terms for our own code. Nothing in the licence file was modified.

Note the contrast with **xmrig**, which is GPLv3. Xmrig may never be used as the
RandomX implementation here: linking a GPLv3 library into an MIT/BSD-3 work would
impose GPLv3 on the combined binary. Only the official BSD-3-Clause (permissive)
RandomX is vendored. This is the concrete reason the official library is mandatory
rather than any RandomX-compatible miner.

## How it is built (autotools, not CMake)

Upstream RandomX ships a CMake build. We deliberately do **not** invoke it: this
repository has a single autotools build system and a nested CMake build would break
VPATH builds, cross-compilation and the existing `EXTRA_LIBRARIES` ordering.

Instead, RandomX's C/C++/assembly sources are compiled directly by our automake
build into a convenience library, `src/librandomx.a`, declared in `src/Makefile.am`
as `librandomx_a_SOURCES` with per-target flags `librandomx_a_CPPFLAGS`,
`librandomx_a_CXXFLAGS` and `librandomx_a_CFLAGS`. The list is a transcription of
the `randomx_sources` variable and the arch-conditional `list(APPEND ...)` blocks in
RandomX's own `CMakeLists.txt`.

`configure.ac` mirrors the same conditionals:

* `--without-randomx` disables it. By default it is built when the host is `x86_64`
  or `aarch64` **and** `src/randomx` is actually checked out; otherwise configure
  warns and continues without it. An explicit `--with-randomx` turns those warnings
  into errors.
* `AM_CONDITIONAL`s: `USE_RANDOMX`, `RANDOMX_X86_64`, `RANDOMX_AARCH64`.
* `AX_CHECK_COMPILE_FLAG` probes reproduce upstream's `add_flag()`/`check_*_flag()`
  logic and export `RANDOMX_AES_CFLAGS` (`-maes`, x86-64 only),
  `RANDOMX_SSSE3_CFLAGS` (`-mssse3`) and `RANDOMX_AVX2_CFLAGS` (`-mavx2`).

Flags, and why each is scoped the way it is:

* `-O3` on the whole library — upstream builds `Release`, i.e. `-O3`.
* `-maes` on the whole library — upstream's default (non-`native`) x86-64 build adds
  it globally; `intrin_portable.h` maps `rx_aesenc_vec_i128` to `_mm_aesenc_si128`
  under `__AES__` and to a soft-AES fallback otherwise.
* `-mssse3` on `argon2_ssse3.c` and `-mavx2` on `argon2_avx2.c` **only**, via
  `librandomx_a-argon2_ssse3.$(OBJEXT): CFLAGS += ...`. Upstream also applies these
  per source file. They must not be global: `randomx.cpp` selects the portable,
  SSSE3 or AVX2 Argon2 implementation at *runtime* based on `Cpu::hasSsse3()` /
  `Cpu::hasAvx2()`, and each of those files is `#if defined(__SSSE3__)` /
  `#if defined(__AVX2__)` guarded. A global `-mavx2` would make the binary
  unconditionally require AVX2 and defeat the runtime dispatch.
* `$(PIC_FLAGS)` / `$(PIE_FLAGS)` — upstream sets `POSITION_INDEPENDENT_CODE ON`;
  the same applies here since the objects go into a PIE-capable daemon.
* C++ standard: the tree is already configured for C++17, which satisfies RandomX's
  `CXX_STANDARD 11` requirement.

No `AC_DEFINE`s are needed. Upstream has no `RANDOMX_EXPORT` / `RANDOMX_VERSION_*`
plumbing of its own on this revision (`randomx.h` defines `RANDOMX_EXPORT` to nothing
when it is not already defined, and the library is compiled straight into our
archive, so there is no shared-library symbol visibility to arrange), and the
`HAVE_HWCAP` define in `CMakeLists.txt` is aarch64-only. The only arch-conditional
`AC_DEFINE` candidates we would need on other ports are handled by the automake
conditionals above.

The archive is added to `EXTRA_LIBRARIES` and to `ravend_LDADD`.

## Generated files

**Nothing needs to be generated for the GCC/Clang autotools build.** The only
build-time generation in RandomX's CMake is the MSVC/MASM-only rule that runs
`vcxproj/h2inc.ps1` (PowerShell) over `src/configuration.h` to produce
`src/asm/configuration.asm`; it only exists on the `if(MSVC)` branch. The GCC build
instead assembles `src/jit_compiler_x86_static.S`, which `#include`s the committed
`src/configuration.h` and the committed `src/asm/*.inc` fragments directly.

All of those files are tracked in the upstream git repository, so there is nothing
to run and nothing to commit on our side:

* `src/configuration.h` — tracked upstream, plain C preprocessor header.
* `src/asm/configuration.asm` — tracked upstream (MASM syntax), MSVC only.
* `src/asm/program_*.inc`, `src/asm/randomx_reciprocal.inc` — tracked upstream,
  used by `jit_compiler_x86_static.S` via the preprocessor.

Because the submodule pins a commit, regenerating `configuration.asm` would only
happen upstream. If you ever need to reproduce it, from the submodule root:

```
powershell -ExecutionPolicy Bypass -File vcxproj/h2inc.ps1 ..\\src\\configuration.h > ..\\src\\asm\\configuration.asm
```

No Makefile rule is added for it: the tool is PowerShell/Windows-only, the output is
only consumed by MSVC, and the file is already committed — a rule would be dead code
that can never run in this build.

## Regenerating / re-pinning the submodule

```
cd src/randomx
git fetch origin
git checkout <new-sha>
cd -
git add src/randomx          # records the new pinned commit
```

Update the "Pinned commit" row above at the same time, and re-check
`librandomx_a_SOURCES` in `src/Makefile.am` against upstream's `CMakeLists.txt` —
new or renamed files upstream will otherwise be silently missing.
