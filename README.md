# raxdbg

A Rust port of [unidbg](https://github.com/zhkl0228/unidbg)'s Android
emulation, with the [rax](https://github.com/HexRaysSA/rax) CPU engine in place
of unicorn.

unidbg runs an Android `.so` — or an APK's native library — in user mode: it
maps the ELF, resolves the relocations, runs the real bionic `libc.so`, answers
Linux syscalls, and speaks the JNI invocation API so native code can call back
into a Java side that the caller supplies. raxdbg does the same thing in Rust,
with a CPU engine written in Rust.

Scope for v1: **Android only, arm64 + arm32.** No MCP server, no GDB stub, no
IDA `android_server` protocol, no iOS.

## Quick start

```console
$ cargo build --release
$ cargo run -p raxdbg-cli -- run fixtures/prebuilt/arm64-v8a/libctest.so --call "hello()V"
hello 42
```

To see what a library asks the kernel for, and check its protection
wrapper, use the `syscalls` command — every syscall with its arguments and
return value, then a report of the anti-debug checks it made:

```console
$ cargo run -p raxdbg-cli -- syscalls fixtures/prebuilt/arm64-v8a/libctest.so -v
-- syscalls --
#6     pid=1          openat@0x1236a6a4 in libc.so(0xffffff9c, "/proc/stat", 0x80000, ...) = 3
-- protection --
18 syscalls inspected, 2 finding(s)
```

[`docs/syscalls-and-protection.md`](docs/syscalls-and-protection.md) is a
worked guide, based on a real packed library, covering reading a trace,
the protection report, driving `JNI_OnLoad`, and what a DEX packer needs
before it can be emulated.

The bundled Android libraries live in `libs/`, populated from the
`reference/unidbg` submodule:

```console
$ git submodule update --init
$ pwsh tools/fetch-libs.ps1
```

`RAXDBG_LIBS_DIR` (or `--libs-dir`) points the resolver at a different tree, so
another SDK level is a directory of the same shape:
`<libs>/android/sdk<level>/{lib,lib64}/*.so`.

## What works

| Area | State |
|---|---|
| CPU engine | AArch64 EL0 and AArch32 user mode on rax, with per-access memory hooks, fault retry, code/block/interrupt/event hooks, stop conditions and context snapshots. The adapters are differential-tested against rax's own adapters register-for-register. |
| Guest memory | unidbg's allocation model: `mmap2`, `brk`, `malloc` (through the guest's own libc once it is loaded), the stack, thread stacks, `errno`, and the region tree with unidbg's gap-filling and region-splitting rules. |
| ELF loading | Segments, the relocation set unidbg implements, symbol resolution across modules, `DT_NEEDED` recursion, `init_array`/`DT_INIT`, the TLS bootstrap, `dlopen`/`dlsym`/`dlclose`, virtual modules. |
| bionic | The bundled `libc.so` boots: `init_array` runs, `malloc`/`free`, `printf`, `strlen`/`memcpy`, `getpid`, `clock_gettime`, `__system_property_get` and `dlopen("libm.so")` + `dlsym("sin")` all work. |
| Syscalls | The arm64 table from unidbg's `ARM64SyscallHandler`, the SVC stub page, the fd table, host-backed file IO (files, `/dev/*`, pipes, sockets, `/proc`), and the resolver chain. |
| Android host services | `AndroidResolver` over `libs/`, the `libandroid.so`/`libjnigraphics.so`/`libmediandk.so`/system-property virtual modules, the `libdl` SVC trampolines, and the system property hook (including a real parse of the bundled `__properties__` trie). |
| APK | `Apk`/`ApkFile`/`ApkDir` with a binary-`AndroidManifest.xml` parser (package, version code, version name) and `assets/` and `lib/<abi>/` access. |

Everything else in the plan's phases (JNI `dvm`, threads, hook engines, arm32
parity, the console debugger, the CLI) is in progress or pending;
`docs/known-gaps.md` is the running record.

## How it is put together

```
crates/
  raxdbg-core/          Backend trait, RegId, memory facade, Pointer, modules,
                        syscalls framework, file IO, threads, debugger, unwinder
                        [≈ unidbg-api]
  raxdbg-backend-rax/   The rax CPU backend: adapters, memory bridge, run loop,
                        hooks, context        [≈ backend/unicorn2]
  raxdbg-android/       AndroidElfLoader, AndroidEmulator, syscall handlers,
                        resolver, virtual modules, dvm, hook engines, APK, console
                        [≈ unidbg-android]
  raxdbg-cli/           the `raxdbg` binary
```

`raxdbg-core` has no dependency on rax: the engine is confined to
`raxdbg-backend-rax`, and every rax item the port touches is listed in
`crates/raxdbg-backend-rax/RAX_API.md`.

The reference tree is a submodule at the commit the port was written against,
and every ported module cites its source:

```rust
//! Port of unidbg: unidbg-api/src/main/java/com/github/unidbg/memory/Memory.java@7f5da98e
```

## Testing

```console
$ cargo test --workspace
```

The suites are organised by what they prove rather than by module:

| Suite | What it covers |
|---|---|
| `raxdbg-backend-rax/tests/backend.rs` | The `Backend` contract: registers, hooks, stop conditions, faults, contexts. |
| `raxdbg-backend-rax/tests/diff_rax_adapters.rs` | The adapters against rax's own, register-for-register, on arithmetic/branch/load-store/FP/NEON/Thumb blobs. |
| `raxdbg-core/tests/memory.rs` | unidbg's allocation algorithms, the region tree, `Pointer`, the tracker. |
| `raxdbg-android/tests/elf_loader.rs` | Synthetic ELF objects (every relocation type, `DT_INIT_ARRAY`, `DT_NEEDED`) and the real bionic `libc.so`/`libm.so`. |
| `raxdbg-android/tests/libc_boot.rs` | The bionic boot milestone. |
| `raxdbg-android/tests/syscalls.rs` | SVC dispatch, the syscall table, the fd table, captured stdout. |
| `raxdbg-android/tests/syscall_trace.rs` | The syscall tracer: that a trace installed before the load sees the load, that it does not change what the guest sees, and the protection report. |
| `raxdbg-android/tests/virtual_modules.rs` | The virtual modules, the system property hook, the `libdl` trampolines. |

Fixtures are committed, so no cross toolchain is needed to run the tests. To
rebuild them, install either [zig](https://ziglang.org/download/) or the Android
NDK and run:

```console
$ pwsh tools/build-fixtures.ps1
```

## Differences from unidbg

* **No host JVM.** unidbg can drive a real JVM through `ProxyJni`; raxdbg has no
  such mode. The `Jni` trait plus the ported `AbstractJni`/`FallbackJni`
  behaviour is the Java side, and an application overrides it to supply its own
  semantics.
* **No DEX execution** — unidbg has none either; native code calls into Java
  through the `Jni` implementation, and nothing interprets bytecode.
* **Read and write hooks get a context, not the whole backend.** A per-access
  hook fires inside the in-flight instruction, where rax's core is mutably
  borrowed; `MemHookCtx` carries the PC, guest memory and the stop flag.
  Registers are available to every other hook type. See the module docs in
  `crates/raxdbg-core/src/backend.rs`.
* **Two `pub` accessors are added to rax** (vendored, `vendor/rax/PATCHES.md`):
  without them EL0 FP/SIMD traps, and real bionic cannot run.

## Licence

Apache-2.0, as a derivative of unidbg. See `NOTICE` and
`THIRD_PARTY_NOTICES.md`.
