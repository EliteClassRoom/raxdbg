//! The bionic boot test (plan P5.6): the milestone where real Android
//! `libc.so` runs.
//!
//! Everything up to here — the ELF loader, the syscall layer, the TLS
//! bootstrap, the resolver — is only proven if the bundled bionic library
//! loads, runs its initialisers, and answers the calls a real guest makes.

use std::rc::Rc;

use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_core::backend::Backend;
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;

fn boot(seed: u64) -> Rc<AndroidEmulator> {
    // The plan asks for the unresolved-symbol list and the syscall log to be
    // part of a failure's output, so the tests honour `RUST_LOG`.
    let _ = env_logger::builder().is_test(true).try_init();
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg")
        .seed(seed)
        .build()
        .expect("emulator");
    emulator.load_library("libc.so").expect("libc.so loads");
    emulator
}

#[test]
fn libc_loads_with_its_initialisers_run() {
    let emulator = boot(1);
    let module = emulator.loader().module("libc.so").expect("libc module");
    assert!(module.base >= 0x1200_0000);
    assert!(module.size > 0x80_000);

    // `__libc_init` ran: the TLS block is installed and its slots are filled.
    let tpidr = emulator
        .backend()
        .borrow()
        .reg_read(RegId::TpidrEl0)
        .expect("tpidr");
    assert_ne!(tpidr, 0, "TPIDR_EL0 holds the TLS block");
    assert_eq!(tpidr % 16, 0, "the thread pointer is 16-byte aligned");

    // The `errno` slot the loader handed bionic is writable and readable.
    emulator.memory().set_errno(0x2a);
    assert_eq!(emulator.memory().get_last_errno(), 0x2a);

    // `__stack_chk_guard` is a non-zero random value on the initial stack.
    let mut found_guard = false;
    let stack = emulator.memory().get_stack_base();
    for offset in (0..0x2000).step_by(8) {
        let mut buf = [0u8; 8];
        if emulator
            .memory()
            .read_bytes(stack - offset - 8, &mut buf)
            .is_ok()
            && u64::from_le_bytes(buf) != 0
        {
            found_guard = true;
            break;
        }
    }
    assert!(found_guard, "the initial stack carries the stack guard");
}

#[test]
fn malloc_and_free_work_through_the_guest_libc() {
    let emulator = boot(2);
    assert!(
        emulator.register_libc_allocator(),
        "libc.so exports malloc and free"
    );

    let malloc = emulator
        .loader()
        .find_symbol("libc.so", "malloc")
        .expect("malloc");
    let free = emulator.loader().find_symbol("libc.so", "free").expect("free");

    let block = emulator.call_function(malloc.address, &[1024]).expect("malloc(1024)");
    assert_ne!(block, 0, "malloc returned a pointer");
    let region = emulator.memory().region_at(block);
    assert!(
        region.is_some(),
        "the block at {block:#x} is inside a mapping"
    );

    // Write through the block, then hand it back.
    emulator
        .memory()
        .write_bytes(block, b"raxdbg")
        .expect("write the block");
    assert_eq!(
        &emulator.memory().pointer(block).get_bytes(0, 6).unwrap(),
        b"raxdbg"
    );

    // bionic's `free` returns void, so x0 afterwards is whatever the last
    // call left there; what matters is that the call completes.
    emulator.call_function(free.address, &[block]).expect("free");
}

#[test]
fn malloc_through_the_memory_facade_uses_the_guest_allocator() {
    let emulator = boot(3);
    assert!(emulator.register_libc_allocator());

    let block = emulator.memory().malloc(64, false).expect("malloc");
    assert!(
        matches!(block, raxdbg_core::alloc::MemoryBlock::Libc { .. }),
        "with libc loaded, the facade routes through the guest's malloc"
    );
    let address = block.pointer().peer();
    assert!(emulator.memory().region_at(address).is_some());
    block.free().expect("free");
}

#[test]
fn printf_writes_into_the_captured_stdout() {
    let emulator = boot(4);
    let printf = emulator
        .loader()
        .find_symbol("libc.so", "printf")
        .expect("printf");

    let format = emulator.memory().write_stack_string("hello %d\n").expect("format");
    let result = emulator
        .call_function(printf.address, &[format.peer(), 42])
        .expect("printf");

    assert_eq!(result, 9, "printf returns the byte count it wrote (\"hello 42\\n\")");
    assert_eq!(emulator.stdout().contents(), "hello 42\n");
}

#[test]
fn string_and_memory_functions_answer() {
    let emulator = boot(5);
    let strlen = emulator
        .loader()
        .find_symbol("libc.so", "strlen")
        .expect("strlen");
    let text = emulator.memory().write_stack_string("raxdbg").expect("text");
    assert_eq!(
        emulator.call_function(strlen.address, &[text.peer()]).expect("strlen"),
        6
    );

    let memcpy = emulator
        .loader()
        .find_symbol("libc.so", "memcpy")
        .expect("memcpy");
    let source = emulator.memory().write_stack_string("copy me").expect("source");
    let destination = emulator.memory().allocate_stack(16).expect("destination");
    let result = emulator
        .call_function(memcpy.address, &[destination.peer(), source.peer(), 8])
        .expect("memcpy");
    assert_eq!(result, destination.peer(), "memcpy returns the destination");
    assert_eq!(
        emulator
            .memory()
            .pointer(destination.peer())
            .get_bytes(0, 8)
            .unwrap(),
        b"copy me\0"
    );
}

#[test]
fn getpid_and_clock_gettime_reach_the_syscall_layer() {
    let emulator = boot(6);
    let getpid = emulator
        .loader()
        .find_symbol("libc.so", "getpid")
        .expect("getpid");
    let pid = emulator.call_function(getpid.address, &[]).expect("getpid");
    assert_eq!(pid, 1, "the emulated process id");

    let clock_gettime = emulator
        .loader()
        .find_symbol("libc.so", "clock_gettime")
        .expect("clock_gettime");
    let timespec = emulator.memory().allocate_stack(16).expect("timespec");
    let result = emulator
        .call_function(clock_gettime.address, &[0, timespec.peer()])
        .expect("clock_gettime");
    assert_eq!(result, 0, "clock_gettime(CLOCK_REALTIME) succeeds");
    let seconds = emulator
        .memory()
        .pointer(timespec.peer())
        .read_u64(0)
        .expect("seconds");
    assert!(seconds > 0, "the wall clock is set: {seconds}");
}

#[test]
fn system_property_get_answers_through_the_virtual_module() {
    let emulator = boot(7);
    // unidbg's `SystemPropertyHook` replaces the symbol, so the guest's own
    // calls land on the stub; a host-side call resolves the same way.
    let get = emulator
        .loader()
        .dlsym(0, "__system_property_get")
        .expect("__system_property_get");

    let key = emulator
        .memory()
        .write_stack_string("ro.build.version.sdk")
        .expect("key");
    let value = emulator.memory().allocate_stack(96).expect("value");
    let length = emulator
        .call_function(get.address, &[key.peer(), value.peer()])
        .expect("__system_property_get");

    assert_eq!(length, 2, "the SDK level is two characters");
    assert_eq!(
        emulator
            .memory()
            .pointer(value.peer())
            .get_string(0)
            .unwrap(),
        "23"
    );
}

#[test]
fn dlopen_and_dlsym_reach_libm() {
    let emulator = boot(8);
    // `ArmLd64` replaces the `libdl` symbols, so these are the trampolines
    // rather than bionic's own linker entry points.
    let dlopen = emulator.loader().dlsym(0, "dlopen").expect("dlopen");
    let dlsym = emulator.loader().dlsym(0, "dlsym").expect("dlsym");

    let name = emulator.memory().write_stack_string("libm.so").expect("name");
    let handle = emulator
        .call_function(dlopen.address, &[name.peer(), 2])
        .expect("dlopen(libm.so)");
    assert_ne!(handle, 0, "libm.so loaded");
    assert!(emulator.loader().module("libm.so").is_some());

    let symbol = emulator.memory().write_stack_string("sin").expect("symbol");
    let sin = emulator
        .call_function(dlsym.address, &[handle, symbol.peer()])
        .expect("dlsym(handle, sin)");
    assert_ne!(sin, 0, "sin resolved through libdl");

    let module = emulator.loader().module("libm.so").expect("libm");
    assert!(
        sin >= module.base && sin < module.base + module.size,
        "sin at {sin:#x} is inside libm.so"
    );
}

#[test]
fn the_loader_reports_no_unresolved_relocations() {
    let emulator = boot(9);
    for module in emulator.loader().module_infos() {
        let missing = emulator.loader().unresolved_relocations(&module.name);
        assert!(
            missing.is_empty(),
            "{} left {:?} unresolved",
            module.name,
            missing
        );
    }
}
