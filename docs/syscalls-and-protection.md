# Running a protected Android library with raxdbg

This guide is written against `test_lib/l1296851e_a64.so` — the sample you
provided. Every command below was run against that file, and the output
shown is what it actually printed.

---

## 1. What the sample is

Run `info` first. It maps the ELF, resolves the `DT_NEEDED` set, and
prints what every loaded module offers:

```console
$ raxdbg info test_lib/l1296851e_a64.so
libapk_android_a64.so base=0x12000000 size=0x1b8000 entry=0x7b2d0 init=0 refs=1
  needs: libandroid.so, liblog.so, libm.so, libdl.so, libc.so
  exports (1):
    JNI_OnLoad@0x120ff250
  unresolved relocations (2): ["AAsset_seek64", "AAsset_isAllocated"]
```

What that tells you before you run anything:

| Fact | Where it comes from | Why it matters |
|---|---|---|
| AArch64, PIE (`ET_DYN`) | `machine=183`, `type=3` | Maps at a non-fixed base, `0x12000000` here |
| SONAME `libapk_android_a64.so` | `.dynamic` | **The file name is not the module name.** A packed binary's name is arbitrary; the loader records the SONAME, and every message names it. |
| One export: `JNI_OnLoad` | `.dynsym` | There is no ordinary entry point to call. The library is reached through the JVM. |
| 193 undefined symbols | `.dynsym` | What it expects from the system: `AAsset_*`, `pthread_*`, `__system_property_get`, `dl_iterate_phdr`, `open`, `read`, `strstr`… |
| 2 unresolved relocations | loader | `AAsset_seek64` / `AAsset_isAllocated` are not implemented; anything reaching them fails |

The `AAsset_*` family is Android's APK asset API. Its absence from the
bundled `libandroid.so` is a real gap — see §8.

---

## 2. Loading it

```console
$ raxdbg run test_lib/l1296851e_a64.so
```

That succeeds silently. What it did: mapped the object at `0x12000000`,
resolved relocations against the bundled bionic (`libc.so`, `libm.so`,
`libdl.so`, `liblog.so`, `libc++.so`), mapped the two virtual modules
(`libandroid.so`, `libsystemproperties.so`), and ran the four
`.init_array` functions at `0x115740`, `0x11588c`, `0x1158f0`, `0x15a644`.

**Those initialisers make no syscalls of their own.** That is worth knowing
before you go looking for the protection in the wrong place: the protection
is not in `.init_array`, it is behind `JNI_OnLoad`.

---

## 3. Logging every syscall

```console
$ raxdbg syscalls test_lib/l1296851e_a64.so
```

Three verbosity levels, cumulative:

| Flag | What it prints |
|---|---|
| *(none)* | The summary counts and the protection report |
| `-v` | Also the calls that carry a path or a captured buffer |
| `-vv` | Every syscall, with its arguments and return value |

`-vv` against the sample:

```console
$ raxdbg syscalls test_lib/l1296851e_a64.so -vv
-- syscalls --
#1     pid=1             brk@0x1236b0c4 in libc.so(0x0, 0x0, 0x0, 0x0, 0x2000, 0x0) = 134512640
#2     pid=1            mmap@0x1236a7ac in libc.so(0x0, 0x40000, 0x3, 0x22, 0xffffffff, 0x0) = 306446336
#3     pid=1           prctl@0x1236ac2c in libc.so(0x53564d41, 0x0, 0x12440000, 0x40000, ...) = 0
#6     pid=1          openat@0x1236a6a4 in libc.so(0xffffff9c, "/proc/stat", 0x80000, ...) = 3
#10    pid=1            read@0x1236a434 in libc.so(0x3, 0x12489000, 0x1000, ...) = 1884
         x1 = "cpu  4421 1123 3145 10469 1223 142 89 0 0 0\x0d\ncpu0 1379 118 819 838..."
#18    pid=1            futex@0x1231bf20 in libc.so(0x123de7f8, 0x81, 0x7fffffff, ...) = 0
```

### Reading a line

```
#10  pid=1  read@0x1236a434 in libc.so(0x3, 0x12489000, 0x1000, ...) = 1884
 │    │      │       │        │   │         │        │       │      │    └ what it returned
 │    │      │       │        │   │         │        │       │      └──────── the 6 argument registers
 │    │      │       │        │   │         │        │       └─────────────── the module that issued it
 │    │      │       │        │   │         │        └─────────────────────── return address
 │    │      │       │        │   │         └──────────────────────────────── the path, when x1 is a string
 │    │      │       │        │   └────────────────────────────────────────── a path argument prints as "…"
 │    │      │       │        └────────────────────────────────────────────── syscall number (56 = openat)
 │    │      │       └─────────────────────────────────────────────────────── PC of the svc instruction
 │    │      └─────────────────────────────────────────────────────────────── syscall name
 │    └───────────────────────────────────────────────────────────────────────── guest pid
 └───────────────────────────────────────────────────────────────────────────── sequence number
```

Path arguments are read out of guest memory and printed as strings, so
`openat(AT_FDCWD, "/proc/stat", …)` is readable without a hex dump. `read`
and `write` payloads are captured (up to 512 bytes) and shown indented
beneath the call — that is how you see what came *back* from `/proc`.

Numbers that are not path arguments print as `0x…`, which is right for a
mask or a flag. `AT_FDCWD` shows as `0xffffff9c` for the same reason: the
tracer does not second-guess a register value.

---

## 4. Protection checking

The same command, default verbosity, adds a report:

```console
$ raxdbg syscalls test_lib/l1296851e_a64.so
-- protection --
18 syscalls inspected, 2 finding(s)
[info] prctl: prctl(PR_SET_VMA, addr=0x12440000, len=262144) -> Some(0)
       bionic tagging an anonymous mapping; not a protection check
[info] prctl: prctl(PR_SET_VMA, addr=0x12480000, len=262144) -> Some(0)
       bionic tagging an anonymous mapping; not a protection check
```

Each finding is graded:

| Grade | Meaning |
|---|---|
| `RISK` | Would end or derail the run — a `kill(getpid(), SIGTRAP)` after a check failed |
| `GAP` | The emulation does not answer this correctly; the guest's conclusion reflects raxdbg, not a device |
| `info` | The guest asked; the answer was harmless |

The analyser watches for:

* **`ptrace`** — `PTRACE_TRACEME` and friends. The table answers 0, which is
  the "nobody is tracing me" state.
* **`prctl`** — `PR_SET_DUMPABLE`, and bionic's two magics: `PR_SET_VMA`
  (`0x53564d41`, ASCII `SVMA`) and `PR_SET_PTRACER` (`0x59616d61`).
* **`kill`/`tgkill`** — a self-directed `SIGTRAP`/`SIGKILL` means a check
  has already failed.
* **`openat`/`getdents64` of a probe path** — `/proc/self/status`,
  `/proc/self/maps`, `/proc/self/mem`, `/proc/self/task`, `/proc/net/tcp`,
  `/system/bin/su` and relatives.
* **`read` payloads** — a `TracerPid:` line, or the strings `frida`,
  `xposed`, `magisk`, `gdb`, `substrate`.

The bionic `prctl` magics matter more than they look. bionic's `prctl`
wrapper does **not** shift its arguments for the kernel, so the syscall
really does arrive with the magic in the option slot. Reading `x0` as the
option without accounting for that gives you `1398164801` — which is what
the first version of this tool reported before it was fixed. The same
handling is in unidbg (`ARM32SyscallHandler.BIONIC_PR_SET_VMA@7f5da98e`).

---

## 5. What makes a run stop

Every run ends one of two ways: a **clean stop** (`RunOutcome`) or an
**error** (`RunError`). The run loop is `crates/raxdbg-backend-rax/src/run.rs`;
these are all the exits it has.

### Clean stops — the run finished

| Outcome | Cause |
|---|---|
| `Until` | PC reached the `until` address. **This is how a normal `--call` ends.** `call_function` sets `LR` to the trap page (`0x7ffff0000` arm64, `0xffff0000` arm32) — a page of `svc #0` mapped read+exec — and passes the same address as `until`. The guest's `ret` lands there, `pc == until`, and the run ends. The instruction at `until` never runs. |
| `Count` | The instruction budget ran out (`count != 0`). |
| `Timeout` | The host-time deadline ran out. Checked every 1024 instructions, not per instruction. |
| `Stopped` | A hook called `emu_stop()` — a breakpoint, or the console debugger's `step`/`continue`. |
| `Idle` | The guest executed a `WFI`/`WFE` with nothing left to do. How a thread with no work yields. |

### Errors — something went wrong

| `RunError` | Cause |
|---|---|
| `UnmappedMemory` | The guest touched memory that is not mapped and no hook fixed it. **The most common one**, and the message names the address, the size, and the PC. A memory hook that *reports* the fault fixed makes the loop retry the instruction, so an unmapped access only becomes an error when nothing handled it. |
| `StopEmulator` | The guest called `exit`/`exit_group`. A clean end in substance; the CLI prints `name() called exit()` rather than treating it as a failure. |
| `ThreadSwitch` | A blocking syscall (`futex` wait, `nanosleep`, `pthread_join`) parked the thread. The dispatcher saves the context and runs somebody else. The caller sees it in the return value, not as a failure. |
| `PopContext` | The running thread finished — its `lr` reached the exit stub, or it joined. Retires the task. |
| `LongJump` | A guest `setjmp`/`longjmp`. |
| `Backend(..)` | The backend itself failed: an unhandled `SVC`, an undefined instruction, a `BRK` no hook claimed, re-entering `emu_start`, or an internal rax error. |

### Reading a fault

The three fields in `UnmappedMemory` are the whole diagnosis:

```
unmapped memory access at 0x30 (size 0) from pc 0x12126e54
                         │         │         │
                         │         │         └── the faulting instruction
                         │         └──────────── access width; 0 when rax
                         │                      does not report one
                         └────────────────────── the address the guest wanted
```

The address tells you *what* the guest was reaching for:

* **A small offset like `0x30` or `0x6d8`** — the guest dereferenced NULL (or a
  near-null handle) plus a field offset. `0x30` is the 7th word of a null
  `JNIEnv*`; `0x6d8` was an unimplemented JNI table slot. These are missing
  *emulation*, not a bug in the guest.
* **A plausible guest address** — the region was never mapped. Check
  `raxdbg info` for the base it was loaded at, and `--root` if it is a path
  the loader should have resolved.
* **A huge or garbled value** — usually a *value* used as a pointer, which
  means the guest decoded something wrongly. `0x10006` in §6 is exactly that:
  `JNI_VERSION_1_6` read as an address.

### Stopping on purpose

A faulting instruction can be retried rather than fatal, which is how a
memory hook answers an unmapped access by mapping it. That is the mechanism
behind a breakpoint: the hook stops the context, the run returns
`Stopped`, and the caller inspects the registers.

---

## 6. Reaching the protection: `JNI_OnLoad`

`JNI_OnLoad` is the only export, so it is the only way in:

```console
$ raxdbg syscalls test_lib/l1296851e_a64.so --jni-on-load
JNI_OnLoad: libapk_android_a64.so: unmapped access of 8 byte(s) at 0x10006
```

`0x10006` is `JNI_VERSION_1_6` — a *value*, not an address. The library
dereferenced it, so the VM handed `JNI_OnLoad` something other than a
`JavaVM*`. This is the honest result, and it is a different failure from
the one you get without the flag:

```console
$ raxdbg run test_lib/l1296851e_a64.so --call "JNI_OnLoad()"
raxdbg: calling JNI_OnLoad: unmapped memory access at 0x30 (size 0) from pc 0x12126e54
```

`0x30` is the 7th word of a null `JNIEnv*` — the guest dereferenced NULL
immediately. The `--jni-on-load` path is strictly better: it builds a real
`JNIEnv`/`JavaVM` first.

The plumbing itself is sound. Against the JNI fixture:

```console
$ raxdbg syscalls fixtures/prebuilt/arm64-v8a/libjnitest.so --jni-on-load
JNI_OnLoad: libjnitest.so returned 0x10006 (JNI version)
```

---

## 7. What this library actually is

The fault is the useful part. Strings in the binary:

```
0x17f1c7  %s/vbp.dex
0x17f1d2  %s/vbp.odex
0x17efef  Ldalvik/system/DexPathList;
0x17f00b  dexElements
0x17e98e  _ZN3art7DexFile10OpenMemoryE...
0x17ecdc  _ZNK3art16ArtDexFileLoader4OpenE...
0x17ea84  libdexfile.so
0x183ddc  de/robv/android/xposed/XposedBridge
0x1839c0  /proc/self/status
0x17e8cc  /assets/
```

`vbp` + `DexFile` + `ArtDexFileLoader` + `DexPathList`: this is a **DEX
packer**. The real payload is `vbp.dex`, an APK asset, and this `.so` is
the loader that hands it to ART. The `/proc/self/*` and `xposed` strings
are the anti-analysis side of the same wrapper.

**The blocking prerequisite is therefore not JNI — it is DEX.** raxdbg
answers JNI calls (19 of them) but has no DEX parser and no ART runtime, so
`JNI_OnLoad` dereferences a class or loader reference that does not exist
here. Until a DEX layer exists, this library's payload cannot be reached by
emulation. The static evidence above is what identifies it; the tracer is
what would show you the `open("/assets/...")` once the DEX layer is in.

Reaching the loader's own logic without ART is still possible — it is just
native code:

```console
$ raxdbg syscalls test_lib/l1296851e_a64.so --call 0x12115740
0x12115740() = 0x0 (0)
```

A bare address is accepted when `--call` is given a number rather than a
name, which is how a packed binary with no usable exports is driven. The
address comes from `info`'s `base=` line plus an offset from your
disassembler. (Note: with a JNI signature the tool refuses, because a
parenthesised signature means a Java method that needs the `dvm` runtime.)

---

## 8. Gaps this run exposed

Recorded here rather than in `docs/known-gaps.md`, because they are
specific to this binary:

1. **`AAsset_*` is not implemented.** Two relocations (`AAsset_seek64`,
   `AAsset_isAllocated`) stay unresolved, and `AAssetManager_open` /
   `AAsset_getBuffer` have no stub. A DEX packer needs exactly these to
   reach `vbp.dex`, so this is the first thing to implement for this
   library. They are not in unidbg either.

2. **No DEX/ART runtime.** `Vm` models JNI references and a class table;
   it does not parse `classes.dex` or execute bytecode. This is the hard
   blocker for §6.

3. **`/proc/self/status` is absent** from the bundled `libs/android/sdk23/proc/`
   tree (only `proc/stat` is there). A `TracerPid` check that opens it gets
   `-ENOENT` — a passing answer, but for the wrong reason. The analyser
   reports the probe either way, so the gap is visible rather than silent.

4. **No `ptrace` state.** Every request answers 0 and no `TracerPid` is
   ever produced, so a self-attach check cannot be distinguished from a
   successful one.

---

## 9. Command reference

```console
raxdbg <command> <lib.so> [options]

  run       load the library, run its initialisers, optionally call a function
  info      print the modules, their exports and their dependencies
  trace     trace instructions or memory accesses while calling a function
  syscalls  log every syscall, then report the protection checks seen
  debug     open the console debugger
```

Options that matter for this work:

| Option | Effect |
|---|---|
| `-v` / `-vv` | syscall trace verbosity (`syscalls`) |
| `--jni-on-load` | run `JNI_OnLoad` before anything else (`syscalls`) |
| `--call <name>` | C symbol **or** a guest address; arguments follow it |
| `--abi arm64\|arm32` | guest ABI, default `arm64` |
| `--sdk <level>` | bundled bionic level, default 23 |
| `--root <dir>` | the directory guest paths resolve under — point it at an unpacked APK to give `open()` real files |
| `--seed <n>` | seed the random source, for a reproducible run |
| `--log <filter>` | `env_logger` filter, e.g. `--log raxdbg=debug` |
| `--stdout <file>` | write the guest's stdout to a file |
| `--leak-check` | report live allocations when the run finishes |

A worked sequence for a new protected library:

```console
# 1. What is it, and what does it need?
$ raxdbg info target.so

# 2. Does it load at all?
$ raxdbg run target.so

# 3. What does it ask the kernel for, and what is it checking?
$ raxdbg syscalls target.so -v

# 4. The same, with every call, once the interesting ones are known
$ raxdbg syscalls target.so -vv

# 5. If it is a JNI library, reach the code behind the VM
$ raxdbg syscalls target.so --jni-on-load -v
```

---

## 10. Using it from Rust

The same trace is available as a library, for driving a library
programmatically:

```rust
use raxdbg_android::emulator::AndroidEmulatorBuilder;

let emulator = AndroidEmulatorBuilder::for_64bit().sdk(23).build()?;

// Before the load: the initialisers' own syscalls are part of the record.
let trace = emulator.syscall().borrow_mut().set_trace();

let file = raxdbg_android::android_file::ElfLibraryFile::open("target.so")?;
emulator.load(Box::new(file), false)?;

let address = emulator.loader().dlsym(0, "entry").map(|s| s.address).unwrap_or(0);
let result = emulator.call_function(address, &[])?;

// One pass, after the run, to name the module behind each `pc`.
let modules = emulator.loader().module_infos();
let mut trace = trace.borrow_mut();
trace.attribute_modules(|pc| {
    modules.iter()
        .find(|m| pc >= m.base && pc < m.base + m.size)
        .map(|m| m.name.clone())
});

for event in trace.events() {
    println!("{} {} -> {:?}", event.label(), event.args[0], event.result);
}
for finding in trace.protection().findings {
    println!("{:?} {}: {}", finding.severity, finding.kind, finding.evidence);
}
```

`set_trace` returns a handle to the *same* recording the dispatcher writes
into, so read it after the run. The tracer is observation only: a run with
one installed produces byte-identical guest state to a run without
(`a_run_without_a_trace_is_unaffected` asserts exactly this).
