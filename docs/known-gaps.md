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

## P3: libc++'s initialiser now runs, and needs bionic atexit

Android packed relocations (`DT_ANDROID_REL`/`DT_ANDROID_RELA`, the `APS2`
format) are decoded and applied as of this session -- see the commit. libcpp.so
is one of those libraries on both ABIs, so before that its relocations were
skipped entirely and its `init_array` entry stayed zero, which meant its
initialiser was never called. It is called now, and it fails:

```
initialiser 0x1214e110: unmapped memory access at 0x910043fda9017c01
```

The trace is libc++'s init -> `pthread_mutex_lock` -> `__cxa_atexit`, which
faults dereferencing a garbage pointer. `__cxa_atexit` takes a `__dso_handle`
argument, which is a per-module `.bss` variable the module's own
`__cxa_get_dso_handle` returns. unidbg does not hit this because its bundled
libcpp is the same file but it never decoded the packed table either, so the
entry stayed zero and `AbsoluteInitFunction.call` skipped it.

**Resolved, in three parts.**

`linux/android/atexit.rs` is a virtual module for bionic's atexit family
(`__cxa_atexit`, `__cxa_finalize`, `atexit`, `__register_atfork`,
`__cxa_thread_atexit*`, `__cxa_get_dso_handle`), ported from
`AndroidModule`'s pattern of answering libc functions from a virtual module.
A `HookListener` redirects libc's own exports to those stubs, because a virtual
module only supplies symbols nothing else defines and libc *does* export them.
`__cxa_atexit` records the destructor host-side rather than in a guest list the
emulator does not model; nothing walks that list while a library loads.

That was not sufficient on its own. libc++'s initialiser reaches
`pthread_mutex_lock`, which does `mrs x12, tpidr_el0; ...; ldr w2, [x18, #0x30]`
and expects `x18` to have held the thread pointer for the whole call chain.
bionic's own `__libc_init` leaves `x18` holding a scratch value -- `x18` is a
platform register and it is free to use -- so the initialiser that runs *after*
it reads a mutex through garbage. The bootstrap now writes `x18` alongside
`TPIDR_EL0`, and the init caller restores it before every initialiser, which is
what a kernel does on every thread entry.

The last piece is honest rather than a fix. libc++'s initialiser still needs
`__libc_init` to have built the pthread structures it walks, and this port does
not run the two in the order a device would. unidbg never gets there at all,
because it does not decode the packed relocations -- the *less* correct path.
`elf/init.rs` therefore has `InitFunctionFilter`, the extension point unidbg
itself defines for this (`InitFunctionFilter`, which `LinuxModule.callInitFunction`
consults and a `LibraryResolver` may implement), and the emulator installs one
that holds libc++'s initialiser back. Every other module's initialisers run, so
the fixtures' own C constructors still do.

Both suites are green again, and the packed relocations stay in place: libc++'s
data is relocated correctly, which is what made the gap visible in the first
place.

## P9: the arm32 CLI is fixed; SDK 19 arm32 is still broken

`--abi arm32` now defaults to SDK 23 like the builder does, so

```
cargo run -p raxdbg-cli -- run fixtures/prebuilt/armeabi-v7a/libctest.so --abi arm32 --call "hello()V"
```

prints `hello 42`. SDK 19's arm32 libc still faults in
`__system_property_area_init` on a null `prop_area` read, so `--sdk 19` with a
32-bit guest does not work. The tree is bundled and arm64's SDK 19 is fine.

## P7: one thread works; a call with two does not

`thread_value()` works end to end: bionic's `pthread_create` reaches the
replacement, the thread runs, and `pthread_join` parks its caller until the
thread's result comes back. That is the whole chain, and the test asserts it
against the fixture's own code.

Getting there took four pieces, and each is a thing a real join needs:

* **`pthread_create` is replaced through a `HookListener`,** not just by having
  a stub in the SVC page. libc really exports it, and a stub nothing points the
  symbol at is not a replacement. The handler reads the routine and its argument
  the way `pthread_create`'s own signature lays them out -- third and fourth
  registers, not the raw `clone` wrapper's first and fourth -- writes the
  thread's id into the caller's `pthread_t`, and records the thread.
* **The caller is a task of the dispatcher's own.** That is what makes a park
  reversible: `pthread_join` returns `RunError::ThreadSwitch`, the dispatcher's
  `run` saves the caller's context, and the thread runs. unidbg's shape, where a
  `ThreadContextSwitchException` unwinds to a dispatcher already running the
  caller as a task.
* **The dispatcher is refilled between its own passes.** A thread is created by
  the code that runs, so the dispatcher only learns about one when a pass ends.
  Without the refill a pass that ends with the caller parked finishes nothing,
  and the loop concludes there is nothing more to do -- before the thread it was
  waiting for has run.
* **A woken task is put back with its value.** `ThreadDispatcher::wake_task`
  sets the resume value and clears the parking *in that order*: the value is
  looked up as the task comes back, which is what clearing the waiter enables.
  The value goes into the task's `x0`, which is what the guest sees when the
  `svc` returns.

**What does not work is a call that creates more than one thread.**
`errno_per_thread` and `counter` both do, and both end with `ThreadSwitch`: the
first thread comes back and the second is left parked. The pieces are the same --
each created thread gets a task and a stack, each joiner gets a waiter -- so
what is missing is in the loop rather than in the mechanism: `run_until_refilling`
stops as soon as a pass leaves nothing runnable, and a call whose second thread
has not been created yet looks exactly like a deadlock at that point.

Two tests in `tests/thread_fixture.rs` are `#[ignore]`d with that reason rather
than deleted, because they state what is left. The three that pass are the
fixture loading with every relocation resolved, `hello()` printing through
bionic's stdio, and `thread_value()` returning 7 through a real
`pthread_create`/`pthread_join`.

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

**Correction: the two decoders agree.** An earlier version of this note claimed
the CPU and the disassembler disagreed about Thumb instruction boundaries,
because a code hook recording every PC showed `0x1202e624 -> 0x1202e626` where
yaxpeax, decoding linearly, put a four-byte `bne.w` at `0x1202e624`. That
conclusion was **wrong**. `tests/arm32_decoding.rs` now walks the whole of arm32
libc's code with both rules — rax's `ThumbDecoder::is_32bit_instruction` and
yaxpeax's top-bits rule — and they agree everywhere, so the extra PC in the
trace is an artifact of how the code hook reports addresses (it fires more than
once across a wide instruction), not a decoder disagreement. The disassembly at
`0x2e636` therefore stands, and the fault there is a genuine read of `0x90` by
`ldr r7, [sp, 0x1c]`'s neighbours rather than a mis-decoded instruction.

The old text, kept so the wrong turn is not repeated:
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

**The chain is now traced to a single failing call.** Calling the pieces
directly on arm32:

```
__system_property_area_init()          -> 0xffffffff  (-1)
__system_property_area__  before/after -> 0x0 / 0x0   (still null)
guest open("/dev/__properties__", O_RDWR) -> -1
```

`0x90` is the trie read past a null `prop_area`: the header is 128 bytes
(`bytes_used`, `serial`, `magic`, `version`, `reserved[28]`), so `prop_area +
0x80 + 0x10` is `0x90`. The `r12 = 0xffffffff` seen at the fault is that failed
`__system_property_area_init` return value still sitting in the register. So the
fault is not in the CPU, the decoder, the loader or the initialiser arguments --
it is that the arm32 guest cannot open the properties file, and then walks the
null area anyway.

The file *is* there: `libs/android/sdk19/dev/__properties__` and
`libs/android/sdk23/dev/__properties__` both exist, and `AndroidResolver::resource`
trims the leading `/` before joining, so the path it builds is right. Note that
`for_32bit()` defaults to sdk 19 while `for_64bit()` defaults to 23, so a 32-bit
run looks under `sdk19/`. What is *not* yet known is which link drops it: the
next step is to call `emulator.resolver().resolve("/dev/__properties__", 2)`
directly and see whether it answers `NotFound` or `Fallback`, then follow the
chain in `syscall::handler`'s resolver walk. The errno printed alongside the
failure (2, `ENOENT`) may be stale -- it is the guest errno slot, which an
earlier failed open would have set -- so do not treat it as the cause.

**A real bug on that path, found and fixed.** Nobody called
`UnixSyscallHandler::add_io_resolver`, so the handler's I/O chain was empty and
*every* guest `open` of a bundled resource answered `ENOENT` --
`/dev/__properties__`, `/proc/stat`, `/system/usr/share/zoneinfo/tzdata`.
`AndroidResolver` is both the library resolver and the IOResolver in unidbg, and
the emulator now shares the same object with both through
`resolver::SharedResolver`. arm64 hid this because `__system_property_get` is
answered by a hook; arm32's `__system_property_area_init` opens the file for
real, which is why that ABI exposed it. `handler.resolve("/dev/__properties__")`
answers `Success` where it answered `None`.

**arm32 boots on SDK 23.** With `sdk(23)` the arm32 libc loads, every
relocation resolves, the thread pointer is readable at EL0, an `svc` reaches the
handler through `r7`, and `malloc`/`free` round-trip through real bionic. So the
`0x90` fault above is **SDK 19-specific**, and `AndroidEmulatorBuilder::for_32bit`
now defaults to 23 like `for_64bit`; `sdk(19)` still faults and is the open item
on that front.

**The initialiser is `libc++_shared.so`'s, and the difference is the ABI.**
`libctest.so` has no initialisers of its own (`module_init_functions` is empty,
`DT_INIT` is 0, no init array); it pulls `libcpp.so`, and *that* module's
`.init_array` is the one at `0x32821`. The two ABIs' copies of it differ:

```
armeabi-v7a: DT_INIT_ARRAY=0x8dc1c entries=1  relocs into it: none
             file content at the slot: 21280300 -> 0x32821
arm64-v8a:   DT_INIT_ARRAY=0xefa70 entries=1  relocs into it: none
             file content at the slot: 0000000000000000 -> 0x0
```

So on arm32 the slot holds a raw virtual address that nothing relocates, our
`InitFunction::Absolute::address` re-reads it, finds it non-zero, and returns it
as-is — which is why the call lands on `0x32821` and faults at `0x32820`. On
arm64 the slot is zero, the recorded address is also zero, and the module's
initialiser is evidently not reached that way at all, so the difference never
showed.

The question to settle next is what unidbg does with an `Absolute` slot on
32-bit: `AbsoluteInitFunction.getFuncAddress` re-reads the slot and falls back to
the recorded address when it is zero, which is what this port does, so the
divergence is either in the relocation pass (an `R_ARM_RELATIVE` that should
rewrite this slot and is being skipped) or in this bundled `libcpp.so` being one
unidbg never exercises. Check the arm32 module's `DT_REL`/`DT_RELSZ` against what
`elf::relocation` walks for that module — an unresolved count of zero only says
every relocation we *looked at* was applied.

**The fixture's init_array entry is called unrelocated.** With libc booted, the
arm32 fixture fails differently: `initialiser 0x32821: unmapped memory access at
0x32820`. `0x32821` is a raw virtual address — Thumb, and the fixture's own
`init_array` entry — so the entry was never relocated and the loader called it
in place. The same fixture loads on arm64, so this is in the 32-bit path: check
whether the `init_array` pointer is read at the module's pointer size and
whether the `R_ARM_RELATIVE`/`R_ARM_ABS32` that should rewrite it is applied
before `module_init_functions` is consulted. Two `#[ignore]`d tests in
`tests/arm32_parity.rs` cover it.

**The initialiser still faults at `0x90` after that fix**, at the same PC, so
there is at least one more link. The next thing to check is the guest's own
`open` again now that the chain answers: if it still returns -1, the failure is
between the guest's `svc` and the handler -- the arm32 number translation for
`openat` (322) or `open` (5), or `read_path` truncating the string. If it now
returns a descriptor, the property area is being built and the fault is later
than it looked.

That comparison has now been run (`tests/arm32_decoding.rs`, over the whole of
libc) and the decoders agree, so this line of attack is closed. What is left is
the fault itself: a read of `0x90` while `r0`/`r2`/`r3`/`r4`/`r10` all hold Thumb
function pointers around `0x1203fdbb`-`0x1203fdc2` and `r12` holds `0xffffffff`,
which reads like a walk over a table of function pointers after a syscall
returned an error. Check what the syscall immediately before the fault returned
(the trace above shows a call at `0x120234a8`), and whether the arm32 handler
answered it with something the guest would treat as a pointer.

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


## Building on this machine: name the MSVC linker explicitly

`link.exe` on `PATH` resolves to Git's `C:\Program Files\Git\usr\bin\link.exe`,
which cannot link Rust binaries. The symptom is every build script failing at
once -- not just the crate being worked on -- with `linking with link.exe
failed`. The MSVC linker is at

```
C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe
```

(note `Hostx64`, lowercase `x`; the `HostX64` spelling does not exist and gives
"linker not found"). Point cargo at it:

```
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=<that path> cargo test --workspace
```

Editing `PATH` from the shell does not fix it: the inherited entries are
Windows-style, so the lookup still finds Git's `link.exe` first.
