# Known gaps

Where the port stands, and exactly what is left. Everything below was
reproduced with the command given.

## Green

`cargo test --workspace` passes: 165 tests across the backend, memory facade,
ELF loader, syscall layer, APK, file IO, debugger core and the Android host
services. Highlights:

* the rax adapters match rax's own adapters register-for-register on a corpus
  of arithmetic, branch, load/store, FP/NEON, Thumb and Thumb-2 blobs
  (`crates/raxdbg-backend-rax/tests/diff_rax_adapters.rs`);
* the real bundled bionic `libc.so` and `libm.so` load, relocate, resolve their
  dependencies and leave no relocation unresolved
  (`crates/raxdbg-android/tests/elf_loader.rs`);
* the syscall layer answers `write`, `read`, `openat`, `getpid`,
  `clock_gettime`, `mmap`, `brk`, `set_tid_address`, `futex`, `getrandom`, and
  dispatches SVC stubs (`crates/raxdbg-android/tests/syscalls.rs`);
* the four Android virtual modules, the `libdl` trampolines and the system
  property hook work, including a real parse of the bundled `__properties__`
  trie (`crates/raxdbg-android/tests/virtual_modules.rs`).

## bionic boot: green

`cargo test -p raxdbg-android --test libc_boot` — 9/9. `libc.so` maps,
relocates, runs its `init_array`, and answers `malloc`/`free`, `strlen`,
`memcpy`, `printf` (captured into the host sink), `getpid`, `clock_gettime`,
`__system_property_get` (`ro.build.version.sdk` -> `"23"`) and
`dlopen("libm.so")` + `dlsym("sin")`. Three bugs stood between the first boot
attempt and this, each worth remembering:

1. **`AT_RANDOM`'s auxv value is a pointer, not the guard.** bionic's
   `__libc_init_common` reads it and dereferences it, so `initializeTLS` must
   write the guard slot's *address*.
2. **SVC stub numbers belong to the SVC page.** `StubDispatch` kept its own
   counter, so the `libdl` stubs were numbered 2, 3, 4... while the dispatch
   looked them up in `SvcMemory`; they were never reached. Numbering now lives
   in `SvcMemory::register_svc_numbered` alone.
3. **A host-driven call must align the stack.** `write_stack_string` aligns to
   four bytes, and `call_function` pushed 16 more, leaving SP 4 mod 16; bionic's
   `ldp`/`stp` take an SP-alignment fault, which surfaced as a confusing
   "unmapped write" inside the stack region. `call_function` now aligns to 16
   (8 on arm32) before the call.

One more, for output rather than correctness: `StdoutFileIO` must answer
`ioctl` successfully (unidbg's `SimpleFileIO` does for `stdout`/`stderr`), or
bionic's `isatty` is false and stdout stays block-buffered, so a `printf` with
a newline never reaches the host.

## Handoff notes for the remaining phases

The five phases below were each delegated to a subagent with a full brief; every
one of those runs died with exit 1 while reading the reference sources (long
exploration, then a crash — a context limit rather than a task problem). The
lessons for whoever picks them up:

* **Scope one file per agent.** The failures all happened after 10-20 large file
  reads. A brief that says "port `ARM32SyscallHandler.java`" pulls in the whole
  syscall layer, the memory facade and the loader; a brief that says "port
  `ARM32SyscallHandler.java`'s `nr::OPENAT` arm into `syscall/arm32.rs`, whose
  helpers are `UnixSyscallHandler::{open,resolve}`" does not.
* **The interfaces are stable and documented.** `crates/raxdbg-android/src/emulator.rs`
  and `crates/raxdbg-android/src/syscall/arm64.rs` are the two files to read
  first: the emulator shows how the loader, the syscall layer, the trap page and
  the host services are wired, and the arm64 table shows the shape a syscall
  table takes (`nr` constants, a table struct with `arg_u64`, a free `dispatch`).
* **The fixtures are ready.** `fixtures/prebuilt/{arm64-v8a,armeabi-v7a}/`
  carry every symbol the P6-P9 acceptance tests call; `libs/` carries both SDK
  levels. Nothing needs building to run a new test.

## Not started

* **P6 JNI (`dvm`)** — the fixture (`fixtures/prebuilt/arm64-v8a/libjnitest.so`)
  and its full symbol surface are in place; the runtime is not.
* **P7 threads** — `futex` currently answers `-EAGAIN`/0 with no waiter
  machinery; `pthread_create` will not work until the dispatcher, the clone
  patchers and the thread glue land.
* **P8 hook engines** — Dobby/HookZz/xHook.
* **P9 arm32 parity** — the arm32 syscall table, kuser traps and the arm32
  fixtures. The AArch32 CPU adapter, run loop and differential tests are done.
* **P11 debugger console** — the core (breakpoints, code history, trace hooks)
  is done and tested; the `yaxpeax-arm` disassembler seam and the REPL are not.
* **P12 CLI** — `raxdbg-cli` is still the placeholder binary.
* **P13 docs** — `README.md`, `THIRD_PARTY_NOTICES.md`, the acceptance matrix.
