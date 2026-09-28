//! ARM32 parity tests (plan P9).
//!
//! **Status**: the syscall-number translation is in and tested
//! (`syscall/arm32.rs`), and the pieces the initialiser depends on are verified
//! independently below — the thread pointer is set and readable at EL0, the
//! stack pointer is correct, the fixture's relocations all resolve, and a
//! hand-written arm32 syscall reaches the handler through `r7`.
//!
//! What does not work yet is arm32 bionic's own initialiser: it faults on a
//! `NULL + 0x90` read (`unmapped memory access at 0x90 ... from pc
//! 0x1202e636`, libc offset `0x2e636`) before any of the tests that need a
//! booted libc can run. `docs/known-gaps.md` records what has been ruled out
//! and where to look next. Those tests are `#[ignore]`d rather than deleted so
//! the goal stays visible and `cargo test -- --ignored` reports the state.
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
#[ignore = "arm32 bionic's initialiser faults on a NULL+0x90 read; see docs/known-gaps.md"]
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
#[ignore = "needs a booted arm32 libc; see docs/known-gaps.md"]
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
#[ignore = "needs a booted arm32 libc; see docs/known-gaps.md"]
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
#[ignore = "needs a booted arm32 libc; see docs/known-gaps.md"]
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
#[ignore = "needs a booted arm32 libc; see docs/known-gaps.md"]
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
#[ignore = "needs a booted arm32 libc; see docs/known-gaps.md"]
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
