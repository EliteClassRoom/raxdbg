# Third-party notices

raxdbg is a Rust port of [unidbg](https://github.com/zhkl0228/unidbg) and bundles
the same Android binaries unidbg ships so that emulation works offline. This
file lists every third-party work the repository carries, where it came from,
and its licence. `tools/fetch-libs.ps1` copies the `libs/` tree from the
`reference/unidbg` submodule; the other entries are dependencies resolved by
Cargo.

## Ported code

| Work | Version / commit | Licence | What raxdbg uses it for |
|---|---|---|---|
| [unidbg](https://github.com/zhkl0228/unidbg) | `7f5da98e623d886084366e81d9bcef82c9460c82` | Apache-2.0 | The behavioural specification for the whole port. Every ported module cites the Java file it came from as `//! Port of unidbg: <path>@7f5da98e`. |

## Bundled binaries (`libs/`)

All of these are copied verbatim from
`unidbg-android/src/main/resources/` at the commit above; `tools/fetch-libs.ps1`
reproduces the tree. They are test and runtime fixtures — no source is derived
from them.

### Android system libraries

Built from the Android Open Source Project (Apache-2.0, with the exceptions the
AOSP `NOTICE` files list — bionic is BSD-3-Clause for the parts derived from
BSD, and `libc++` is MIT/BSD-2-Clause dual-licensed):

| Path | Origin |
|---|---|
| `libs/android/sdk23/lib64/{libc,libm,libz,liblog,libdl,libstdcpp,libcpp,libcrypto,libssl}.so` | AOSP / Android 6.0 (API 23), 64-bit |
| `libs/android/sdk23/lib/{same}` | AOSP / Android 6.0 (API 23), 32-bit |
| `libs/android/sdk19/lib/{libc,libm,libz,liblog,libdl,libstdcpp,libcrypto,libssl}.so` | AOSP / Android 4.4 (API 19), 32-bit |
| `libs/android/sdk23/proc/stat`, `libs/android/sdk2{19,23}/dev/__properties__` | Android property-area image and `/proc/stat` fixture |
| `libs/android/sdk2{19,23}/system/usr/share/zoneinfo/tzdata` | IANA time zone database, as shipped in Android |

`libcrypto.so` and `libssl.so` are OpenSSL (Apache-2.0 for 1.1.0 and later; the
Android 4.4 build is OpenSSL 1.0.1, which is the OpenSSL + SSLeay dual licence).

### Hook engines

| Path | Project | Licence |
|---|---|---|
| `libs/android/lib/{arm64-v8a,armeabi-v7a}/libdobby.so` | [Dobby](https://github.com/jmpews/Dobby) | Apache-2.0 |
| `libs/android/lib/{arm64-v8a,armeabi-v7a}/libhookzz.so` | [HookZz](https://github.com/jmpews/HookZz) | Apache-2.0 |
| `libs/android/lib/{arm64-v8a,armeabi-v7a}/libxhook.so` | [xHook](https://github.com/iqiyi/xHook) | MIT |

## Vendored source (`vendor/rax`)

| Work | Version | Licence | Why it is vendored |
|---|---|---|---|
| [rax](https://github.com/HexRaysSA/rax) | `c468ca32087553bb6c16aad10c17c08fee24ce95` | MIT AND BSD-3-Clause | The CPU engine. Vendored because raxdbg needs two public `CPACR_EL1` accessors that upstream does not expose; see `vendor/rax/PATCHES.md`. |

## Cargo dependencies

Resolved from crates.io by `Cargo.lock`; each crate carries its own licence in
its published manifest. The direct dependencies and their licences:

| Crate | Licence |
|---|---|
| `goblin` | MIT |
| `yaxpeax-arm`, `yaxpeax-arch` | 0BSD |
| `zip` | MIT |
| `log`, `env_logger` | MIT OR Apache-2.0 |
| `thiserror` | MIT OR Apache-2.0 |
| `parking_lot` | MIT OR Apache-2.0 |
| `hex` | MIT OR Apache-2.0 |
| `object` (dev-only) | Apache-2.0 OR MIT |
| `md-5`, `sha1`, `sha2` (for the JNI `MessageDigest` defaults) | MIT OR Apache-2.0 |

`linux-loader` is patched to a one-line fork
(`github.com/19h/linux-loader` @ `f745b555942c4e840a784bca61e6f3976d101960`,
MIT OR Apache-2.0) because the published versions force `vm-memory`'s `rawfd`
feature, which is a `compile_error!` on Windows.

## Fixtures

`fixtures/src/*.c` are raxdbg's own, built by `tools/build-fixtures.ps1` with
either `zig cc` or the Android NDK's clang, and the resulting `.so` files are
committed under `fixtures/prebuilt/`. They are Apache-2.0 like the rest of the
repository.
