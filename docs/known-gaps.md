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

## CLI, console and unwinder: green

`cargo test -p raxdbg-cli --test cli` — 8/8, and the plan's headline end state
works:

```console
$ cargo run -p raxdbg-cli -- run fixtures/prebuilt/arm64-v8a/libctest.so --call "hello()V"
hello 42
hello() = 0x0 (0)
```

`info` prints the module table with dependencies, exports and any unresolved
relocations; `trace` prints the instructions a call ran (with `yaxpeax-arm`
disassembly) or the memory accesses; `debug` opens the console (registers,
breakpoints, memory, disassembly, backtrace, `where`, `modules`, `symbols`,
`call`); `--leak-check` reports the live mappings, and `--libs-dir` / `--root` /
`--sdk` / `--abi` / `--seed` / `--stdout` all work.

Two honest limits, both visible in the output rather than hidden:

* a `--call` with a JNI signature (`echo(Ljava/lang/String;)Ljava/lang/String;`)
  reports that it needs the `dvm` runtime, which is not ported yet; a plain C
  symbol name works today.
* the leak report's guest backtrace is empty when the allocation happens inside
  a syscall, because the run loop has the backend mutably borrowed there
  (plan P2.6). The fix is for the syscall handler to publish the caller's PC
  through a `Cell` the tracker reads; the regions themselves are reported
  either way.

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

## P6: one item is thinner than its name

The plan's "VarArg/VaList" item is only half done. Arguments reach a native
through `emulator.call_function(address, &[u64])`, which marshals registers and
then the stack — that covers every non-variadic JNI method, which is all the
fixture and the acceptance matrix use. What is *not* implemented is a real
arm64 `va_list`: a variadic native that walks its arguments through
`va_arg` would need the GPR/FPR/spill regions built at the call site. Nothing
in the port calls one today; the work is bounded and belongs with whoever adds
variadic JNI support.

## P9: what is done for arm32, and what the initialiser fault is not

Done and tested:

* `crates/raxdbg-android/src/syscall/arm32.rs` — the arm32 EABI numbers and the
  translation onto the shared table. This was a real bug, not a missing
  feature: the arm32 SVC dispatch called `arm64::dispatch` with the arm32
  number, so an arm32 `write` (4) ran arm64 `fstat` (4) and left a pointer where
  the guest expected a count. `open` also shifts its arguments to make room for
  `AT_FDCWD`, and `_llseek` becomes a 64-bit `lseek`. Unimplemented numbers
  answer `-ENOSYS`, as unidbg's `handleUnknownSyscall` does. Four tests in
  `arm32.rs`, plus `tests/arm32_parity.rs`.

Ruled out by experiment, so the next person does not repeat them:

* **The thread pointer is fine.** `mrc p15, 0, r0, c13, c0, 3` executes at EL0
  and returns exactly what was written to `cp15.tpidruro` —
  `tests/arm32_parity.rs::the_guest_reads_the_thread_pointer_through_cp15`.
* **The stack pointer is fine.** It is `0xe4fff740` before the initialiser runs,
  inside the mapped stack, and the instruction rax reports as faulting
  (`ldr r7, [sp, 0x1c]` at libc offset `0x2e636`) addresses `0xe4fff754` —
  mapped. rax reports the fault address and PC but not the access width, and
  the PC it reports is not always the instruction that faulted, so read the
  fault address as the signal: `0x90`, reproducibly, across both libc's and the
  fixture's initialisers.
* **Relocations are not the problem**: the arm32 `libc.so` resolves all of them.

**A real loader bug, found and fixed on the way**: `munmap_impl` errored when a
neighbouring region was larger than what remained of the request
(`munmap adjacent region size=0x7f000 exceeds remaining=0x8000`). unidbg's loop
removes whole neighbours and stops as soon as the request is satisfied, so the
last region it takes may be larger than the remainder. Erroring rejected a
legitimate `munmap` and left the region tree inconsistent.

**Where the fault stands.** With an event-memory hook dumping the register file
at the fault, the state is:

```
FAULT addr=0x90 kind=Read
  r0=0x1203fdc1 r1=0x2e r2=0x1203fdbb r3=0x1203fdc2 r4=0x1203fdbc
  r5=0x5 r6=0x80 r7=0 r8=0 r9=0x12 r10=0x1203fdc1 r11=0x1 r12=0xffffffff
  sp=0xe4fff660 lr=0x1202e613 pc=0x1202e636 cpsr=0x200b0030
```

`cpsr` says User mode with Thumb set, so the state is not the problem. The
reported PC is libc offset `0x2e636`, which disassembles (yaxpeax, Thumb) to
`ldr r7, [sp, 0x1c]` — and `sp + 0x1c` is `0xe4fff67c`, inside the mapped stack,
so **the reported PC is not the instruction that faulted**: rax reports the
fault address and a PC but not the access width, and here they disagree. The
registers that look like addresses (`r0`, `r2`, `r3`, `r4`, `r10`) are all
libc code pointers around `0x1203fdbb`–`0x1203fdc2`, i.e. a table of function
pointers, and `r9 = 0x12` is a small integer that would be an offset.

**A code hook that records every PC says the linear disassembly is wrong.**
With a code hook over libc's range recording the last 24 program counters, the
trace before the fault is:

```
0x1202e612 -> 0x1202e616   (+4, a 32-bit instruction at 0x612)
0x1202e616 -> 0x1202e618   (+2)
0x1202e618 -> 0x1202e61a   (+2)
0x1202e61a -> 0x1202e61e   (+4)
0x1202e61e -> 0x1202e622   (+4)
0x1202e622 -> 0x1202e624   (+2)
0x1202e624 -> 0x1202e626   (+2)     <- yaxpeax says 0x624 is `bne.w`, four bytes
0x1202e626 -> 0x1202e628   (+2)
0x1202e628 -> 0x1202e632   (+0xa, branch)
0x1202e632 -> 0x1202e636   (+4)
0x1202e636 <- FAULTED
```

yaxpeax, decoding linearly from `0x1202e61e`, puts a four-byte `bne.w` at
`0x1202e624` and a two-byte `bgt` at `0x1202e634`. rax executed two-byte
instructions at `0x624` and `0x626`, and a four-byte one at `0x632`. The two
decoders disagree about where the instruction boundaries are, and rax's are the
ones that actually ran — so **the "`ldr r7, [sp, 0x1c]` at `0x2e636`" above is a
misaligned reading and must not be trusted**. Whatever faults at `0x90` is a
different instruction than the one that linear disassembly shows there.

That makes the next step a decoder comparison rather than a memory one: dump the
raw bytes from `0x1202e620` to `0x1202e640`, decode them with both `yaxpeax-arm`
and rax's `Decoder`/`ThumbDecoder`, and see which is right. If rax is mis-decoding
a Thumb-2 instruction there, that is a rax bug to report or work around; if
yaxpeax is, our disassembler is wrong for this encoding and P11's output is
affected too. `crates/raxdbg-android/tests/arm32_parity.rs` and the code-hook
trace above are the harness for it.

## P8 handoff: the replace hook works for a direct call

`crates/raxdbg-android/src/hook/replace.rs` is the engine-independent half of
P8: `ReplaceCallback` (`on_call`, optional `post_call`), `InvocationContext`
(arguments, `sp`, `lr`, `set_ret`, `set_arg`), and `ReplaceHook::replace`, which
installs a code hook on the target's entry that moves the PC to an SVC stub. The
stub's trailing `ret` returns to the caller, so no code is patched and the
target can be anywhere.

`cargo test -p raxdbg-android --test hooks` — 4/4 on the cases that pass today:
the fixture runs unhooked (`run() == 3`), a replacement answers for the target
when the target is called directly, uninstalling restores the original, and a
target outside every module is refused.

**The gap**: three cases are *not* in the suite because they fail or hang, and
they share one cause — the target reached **indirectly**, through the volatile
function pointer `run()` uses:

* the callback's arguments are not what the caller passed,
* the post-call path (`enable_post_call`) does not complete,
* the argument-rewriting case loops forever.

That points at the interaction between the redirect code hook and a call that
arrives from a different module: `run()` is in `libhooktest.so` and calls
`target_fn` through a pointer, so the hook fires with the PC already at the
target's entry but the *stack* holding a caller frame the redirect does not
account for. The next step is to compare the register file at the hook against
unidbg's `Arm64Hook.onRegister` trampoline, which saves `x29`/`x30` before
displacing the PC — the hand-written trampoline the plan's D9 describes. The
engine ports (Dobby/HookZz/xHook) should wait for that fix, since all three
build on this path.

## P6 (JNI) handoff: the first piece is in

`crates/raxdbg-android/src/dvm/hash.rs` is done and tested: the four `Hasher`
variants (unidbg's default Java `String.hashCode`, FNV-1a, MurmurHash3 x86-32
and xxHash32), each checked against a published vector, plus `Hashable` and the
identity hash `DvmObject` uses. That is the foundation the rest of `dvm` is
built on — every `jobject`/`jclass`/`jmethodID`/`jfieldID` is one of these
hashes.

The order that worked for the rest of the port, and that the remaining `dvm`
work should follow:

1. `dvm/object.rs` — `DvmObject` (type descriptor + hash), `StringObject`,
   `NumberObject`, `BooleanObject`, `ArrayObject`, `ProxyObject`, and the three
   reference maps (`local`/`global`/`weak`), with `delete_local_refs()` after
   every host-driven call.
2. `dvm/class.rs` — `DvmClass` (`natives_map`), `DvmMethod`/`DvmField` keyed by
   `vm.hash("L<Class>;-><name><args>")`, and `find_native_function`, which
   checks `natives_map` first and then searches the loaded modules for
   `Java_<mangled>` (the `mangle_for_jni` rules: `_`->`_1`, `/` and `.`->`_`,
   `;`->`_2`, `[`->`_3`, anything else `_0<hex4>`).
3. `dvm/vararg.rs` — argument marshalling: arm64 takes `x1..x7` then the stack
   with 16-byte alignment, arm32 takes `r1..r3` then the stack with unidbg's
   padding rule. `call_function` in `emulator.rs` already sets `x0` and aligns
   the stack, so this is the same shape.
4. `dvm/jni_table.rs` — the `JNIEnv` table in the SVC page: 232 pointer-sized
   slots, each implemented slot written with the address
   `SvcMemory::register_svc` returns for that JNI function, and unimplemented
   slots holding their own index as a bogus pointer (which is how unidbg makes
   an unimplemented slot obvious). `JavaVM` is an 8-slot table with
   `AttachCurrentThread` (4) and `GetEnv` (6).
5. `dvm/jni.rs` — the `Jni` trait and its defaults, ported from
   `AbstractJni`/`FallbackJni`; the fixture needs `FindClass`,
   `GetStaticMethodID` (returning a method whose `CallStaticIntMethod` answers
   7, which is what makes `seedPlusOne` return 8), `NewStringUTF`,
   `GetStringUTFChars`/`ReleaseStringUTFChars`, `ExceptionCheck`, `ThrowNew`,
   `NewGlobalRef`/`DeleteGlobalRef`/`DeleteLocalRef`, `NewObject` and
   `CallIntMethod`.
6. `dvm/module.rs` + `dvm/vm.rs` — `DalvikModule` (load a module into the VM)
   and the VM that ties it together, including `JNI_OnLoad` (`0x10006`
   expected, `0x10008` accepted, `JNI_ERR` an error) and
   `call_static_jni_method(emulator, "add(II)I", args)`.

The fixture is ready: `fixtures/prebuilt/arm64-v8a/libjnitest.so` exports
`JNI_OnLoad` and the ten `Java_com_raxdbg_test_JniTest_*` entry points, and
`crates/raxdbg-cli/tests/cli.rs` already asserts that a JNI signature reports
the missing runtime, so the day `dvm` lands that assertion flips to a call.

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
