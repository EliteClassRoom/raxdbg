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

## bionic boot: 6 of 9

`cargo test -p raxdbg-android --test libc_boot`. Passing:

* `libc_loads_with_its_initialisers_run` — `libc.so` maps, relocates and runs
  its `init_array` through the emulator's `call_function`;
* `malloc_and_free_work_through_the_guest_libc`,
  `malloc_through_the_memory_facade_uses_the_guest_allocator`;
* `string_and_memory_functions_answer` (`strlen`, `memcpy`);
* `getpid_and_clock_gettime_reach_the_syscall_layer`;
* `the_loader_reports_no_unresolved_relocations`.

Failing, with the reproduction:

```
cargo test -p raxdbg-android --test libc_boot printf -- --nocapture
```

### 1. `printf` and `__system_property_get` fault on a stack write

`RunError::UnmappedMemory { addr: 0xe4fff704, .. }`, reported by the emulator's
event-memory hook as an **unmapped write**. The address is inside the stack
region, which the loader has mapped `rw` and which rax serves correctly:

* `Loader::get_memory_map()` at the moment of the call lists
  `0xe4b00000..0xe5000000 rw`;
* `RaxBackend::mem_write(0xe4fff704, ..)` and the guest path
  `AddressSpace::write(0xe4fff704, ..)` both succeed on a freshly mapped
  5 MiB region in `crates/raxdbg-backend-rax` (verified with a scratch test
  that has since been removed).

Narrowed down since: the faulting call is libc's `enlarge` (offset `0x49f28`),
whose `bl` at `0x49f30` targets the PLT entry for **`realloc`**
(`R_AARCH64_JUMP_SLOT` at GOT `0xd86e0`). The write at `0xe4fff704` is the
`str x0, [x19, #0x18]` at `0x49f38` — the FILE's buffer field — so `x19`, the
`FILE*`, is `0xe4fff6ec`: a **stack address**, not `stdout` (`0x120db480`, which
relocated correctly and reads back as `__sF[1]`).

Two consequences, both worth checking first:

1. **Something unmapped the stack in rax mid-call.** The region list still
   lists `0xe4b00000..0xe5000000 rw` and a freshly mapped 5 MiB region is
   writable end to end, so the two disagree only *during* the call. The prime
   suspect is `Loader::munmap_impl`: it calls `guest.unmap(start, aligned)`
   before looking at its own region tree, so one bogus guest `munmap` — from
   bionic's allocator reacting to a bad pointer — takes the stack with it.
2. **Whatever handed `enlarge` a stack address as a `FILE*`.** `stdout` itself
   is fine, so the caller's frame is the thing to inspect: print `x19` and the
   call stack at the fault (the debugger core in `raxdbg-core::debug` can
   already do the breakpoint half).

### 2. `dlopen("libm.so")` returns 0

`cargo test -p raxdbg-android --test libc_boot dlopen -- --nocapture`. The
`libdl` stub is reached (the SVC page lists `dlopen.256`), so the failure is
inside `DlOpen::handle`: either the resolver rejects the name or
`AndroidElfLoader::dlopen` returns `None`. Check that
`AndroidResolver::resolve_library("libm.so")` finds
`libs/android/sdk23/lib64/libm.so` through the *emulator's* resolver (the ELF
loader test resolves it through a `DirectoryResolver`, which is a different
path).

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
