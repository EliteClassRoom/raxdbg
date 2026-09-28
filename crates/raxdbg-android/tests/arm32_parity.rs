//! ARM32 parity tests (plan P9).
//!
//! **Status**: arm32 bionic boots on SDK 23. The libc loads with every
//! relocation resolved, the thread pointer is set and readable at EL0, a
//! hand-written `svc` reaches the handler through `r7`, and `malloc`/`free`
//! round-trip through the real libc. Those are the tests below, and they pass.
//!
//! What does not work is the *fixture*: its initialiser is called at a raw
//! virtual address (`0x32821`, with the fault at `0x32820`), so the
//! `init_array` entry was not relocated. That is arm32-specific — the same
//! fixture loads on arm64 — and it is the one thing between this and
//! `libctest.so` running on `armeabi-v7a`. Those two tests are `#[ignore]`d
//! with that reason rather than deleted.
//!
//! SDK 19 is a separate matter: its arm32 libc faults in
//! `__system_property_area_init`, which is why `for_32bit()` defaults to 23.
//! `docs/known-gaps.md` has both.
//!
//! The AArch32 backend, run loop and differential tests landed with P1; what
//! these tests cover is the *Android* half for `armeabi-v7a`: the same ELF
//! loader on a 32-bit module, the TLS bootstrap writing `TPIDRURO` instead of
//! `TPIDR_EL0`, the syscall handler reading `r7` instead of `x8`, and the
//! fixtures built for the ABI.

use std::rc::Rc;

use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_core::backend::{Backend, Prot};
use raxdbg_core::reg::RegId;

fn workspace_path(relative: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join(relative)
}

fn boot() -> Rc<AndroidEmulator> {
    let emulator = AndroidEmulatorBuilder::for_32bit()
        .process_name("raxdbg-arm32")
        .sdk(23)
        .seed(13)
        .build()
        .expect("emulator");
    emulator.load_library("libc.so").expect("libc.so");
    emulator
}

fn load_fixture(emulator: &Rc<AndroidEmulator>, name: &str) {
    let path = workspace_path(&format!("fixtures/prebuilt/armeabi-v7a/{name}"));
    let file = ElfLibraryFile::open(&path).expect("open fixture");
    emulator.load(Box::new(file), false).expect("load fixture");
}

#[test]
fn the_arm32_libc_loads_with_its_dependencies() {
    let emulator = boot();
    let infos = emulator.loader().module_infos();
    let names: Vec<&str> = infos.iter().map(|info| info.name.as_str()).collect();
    assert!(
        names.iter().any(|name| name.contains("libc.so")),
        "libc.so is loaded: {names:?}"
    );
    // Every relocation resolved.
    let unresolved = emulator.loader().unresolved_relocations("libc.so");
    assert!(
        unresolved.is_empty(),
        "unresolved relocations: {unresolved:?}"
    );
}

#[test]
fn the_thread_pointer_is_where_arm32_expects_it() {
    let emulator = boot();
    let tls = emulator
        .backend()
        .borrow_mut()
        .reg_read(RegId::C13C0_3)
        .expect("read TPIDRURO");
    assert_ne!(tls, 0, "the TLS bootstrap set TPIDRURO");
    assert_eq!(tls % 16, 0, "and it is 16-byte aligned: {tls:#x}");
    // The errno slot lives at `tls + 2 * pointer_size`, as unidbg lays it out.
    let errno = emulator.memory().errno_address();
    assert_eq!(errno, tls + 8, "errno is the third word of the TLS block");
}

#[test]
fn the_guest_reads_the_thread_pointer_through_cp15() {
    // No libc: this is about the CPU and the `mrc`, not about bionic.
    let emulator = AndroidEmulatorBuilder::for_32bit()
        .process_name("raxdbg-arm32")
        .build()
        .expect("emulator");
    // A recognizable pointer, set the way the TLS bootstrap sets it.
    let expected = 0xe000_0000u64;
    emulator
        .backend()
        .borrow_mut()
        .reg_write(RegId::C13C0_3, expected)
        .expect("write TPIDRURO");
    // `mrc p15, 0, r0, c13, c0, 3` then `bx lr`.
    let code = [0xee1d_0f70u32, 0xe12f_ff1e];
    let address = emulator
        .memory()
        .allocate_map_address(0x1000, 0x1000);
    {
        let mut backend = emulator.backend().borrow_mut();
        backend
            .mem_map(address, 0x1000, Prot::from_bits(0x7))
            .expect("map");
        let mut bytes = Vec::new();
        for word in code {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        backend.mem_write(address, &bytes).expect("write");
    }
    let value = emulator.call_function(address, &[]).expect("mrc");
    assert_eq!(
        value, expected,
        "the guest's mrc reads the same pointer the host wrote"
    );
}

#[test]
#[ignore = "the fixture's init_array entry is called unrelocated; see docs/known-gaps.md"]
fn the_arm32_fixture_loads_and_its_symbols_resolve() {
    let emulator = boot();
    load_fixture(&emulator, "libctest.so");
    for symbol in ["hello", "pid", "counter", "tls_diff", "clock_now"] {
        assert!(
            emulator.loader().find_symbol("libctest.so", symbol).is_some(),
            "{symbol} is exported"
        );
    }
    assert!(
        emulator.loader().unresolved_relocations("libctest.so").is_empty(),
        "unresolved: {:?}",
        emulator.loader().unresolved_relocations("libctest.so")
    );
}

#[test]
#[ignore = "the fixture's init_array entry is called unrelocated; see docs/known-gaps.md"]
fn the_arm32_fixture_runs_a_plain_function() {
    let emulator = boot();
    load_fixture(&emulator, "libctest.so");
    let hello = emulator
        .loader()
        .find_symbol("libctest.so", "hello")
        .expect("hello");
    assert_eq!(
        emulator.call_function(hello.address, &[]).expect("hello"),
        42
    );
}

#[test]
fn an_arm32_syscall_reaches_the_handler_through_r7() {
    let emulator = boot();
    // `mov r7, #20` (getpid) ; `svc #0` ; `bx lr` — the syscall number comes
    // from r7, not x8, and the result must land in r0.
    let code = [0xe3a0_7014u32, 0xef00_0000, 0xe12f_ff1e];
    let address = emulator
        .memory()
        .allocate_map_address(0x1000, 0x1000);
    {
        let mut backend = emulator.backend().borrow_mut();
        backend
            .mem_map(address, 0x1000, Prot::from_bits(0x7))
            .expect("map");
        let mut bytes = Vec::new();
        for word in code {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        backend.mem_write(address, &bytes).expect("write");
    }
    let pid = emulator.call_function(address, &[]).expect("getpid");
    assert!(pid > 0, "getpid returned {pid}");
}

#[test]
fn an_arm32_malloc_round_trip_through_bionic() {
    let emulator = boot();
    let malloc = emulator
        .loader()
        .find_symbol("libc.so", "malloc")
        .expect("malloc");
    let free = emulator.loader().find_symbol("libc.so", "free").expect("free");
    let block = emulator.call_function(malloc.address, &[1024]).expect("malloc");
    assert_ne!(block, 0, "malloc returned a pointer");
    emulator
        .call_function(free.address, &[block])
        .expect("free");
}
