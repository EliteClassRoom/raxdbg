//! The bionic boot test (plan P5.6): the milestone where real Android
//! `libc.so` runs.
//!
//! Everything up to here — the ELF loader, the syscall layer, the TLS
//! bootstrap, the resolver — is only proven if the bundled bionic library
//! loads, runs its initialisers, and answers the calls a real guest makes.

use std::rc::Rc;

use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
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
    let free = emulator
        .loader()
        .find_symbol("libc.so", "free")
        .expect("free");

    let block = emulator
        .call_function(malloc.address, &[1024])
        .expect("malloc(1024)");
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
    emulator
        .call_function(free.address, &[block])
        .expect("free");
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

    let format = emulator
        .memory()
        .write_stack_string("hello %d\n")
        .expect("format");
    let result = emulator
        .call_function(printf.address, &[format.peer(), 42])
        .expect("printf");

    assert_eq!(
        result, 9,
        "printf returns the byte count it wrote (\"hello 42\\n\")"
    );
    assert_eq!(emulator.stdout().contents(), "hello 42\n");
}

#[test]
fn string_and_memory_functions_answer() {
    let emulator = boot(5);
    let strlen = emulator
        .loader()
        .find_symbol("libc.so", "strlen")
        .expect("strlen");
    let text = emulator
        .memory()
        .write_stack_string("raxdbg")
        .expect("text");
    assert_eq!(
        emulator
            .call_function(strlen.address, &[text.peer()])
            .expect("strlen"),
        6
    );

    let memcpy = emulator
        .loader()
        .find_symbol("libc.so", "memcpy")
        .expect("memcpy");
    let source = emulator
        .memory()
        .write_stack_string("copy me")
        .expect("source");
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

    let name = emulator
        .memory()
        .write_stack_string("libm.so")
        .expect("name");
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

/// The auxv tags the guest reads back through its own `getauxval`.
mod auxv_tag {
    /// `AT_PHDR`.
    pub const PHDR: u64 = 3;
    /// `AT_PHENT`.
    pub const PHENT: u64 = 4;
    /// `AT_PHNUM`.
    pub const PHNUM: u64 = 5;
    /// `AT_PAGESZ`.
    pub const PAGESZ: u64 = 6;
    /// `AT_BASE`.
    pub const BASE: u64 = 7;
    /// `AT_ENTRY`.
    pub const ENTRY: u64 = 9;
    /// `AT_RANDOM`.
    pub const RANDOM: u64 = 25;
}

/// Calls the guest's own `getauxval` for `tag`.
///
/// Going through bionic rather than reading the loader's fields is what makes
/// this a test of the array the *guest* walks: `getauxval` scans the pairs
/// with a 16-byte stride and stops at the first zero tag, so an array whose
/// entries overlap or whose terminator sits on a tag reads back as missing.
fn guest_getauxval(emulator: &Rc<AndroidEmulator>, tag: u64) -> u64 {
    let getauxval = emulator
        .loader()
        .find_symbol("libc.so", "getauxval")
        .expect("libc.so exports getauxval");
    emulator
        .call_function(getauxval.address, &[tag])
        .expect("getauxval")
}

#[test]
fn the_auxv_describes_a_real_main_program() {
    let emulator = boot(10);

    // Every tag bionic reads unconditionally is present. A missing AT_RANDOM
    // is not a soft failure: `__libc_init_common` dereferences the result
    // without a null check, so the guest faults before it reaches any code.
    for (tag, name) in [
        (auxv_tag::RANDOM, "AT_RANDOM"),
        (auxv_tag::PAGESZ, "AT_PAGESZ"),
        (auxv_tag::PHDR, "AT_PHDR"),
        (auxv_tag::BASE, "AT_BASE"),
        (auxv_tag::ENTRY, "AT_ENTRY"),
        (auxv_tag::PHENT, "AT_PHENT"),
        (auxv_tag::PHNUM, "AT_PHNUM"),
    ] {
        assert_ne!(guest_getauxval(&emulator, tag), 0, "{name} is in the auxv");
    }

    assert_eq!(
        guest_getauxval(&emulator, auxv_tag::PAGESZ),
        raxdbg_core::memory::PAGE_SIZE,
        "AT_PAGESZ is the guest page size"
    );
    assert_eq!(guest_getauxval(&emulator, auxv_tag::PHENT), 56, "AT_PHENT");
    assert_eq!(guest_getauxval(&emulator, auxv_tag::PHNUM), 2, "AT_PHNUM");

    // AT_PHDR and AT_BASE must address a real ELF image. Protected code reads
    // the magic at both and gives up when it does not match, which is how a
    // packed library decides whether it was loaded by a real linker.
    let phdr = guest_getauxval(&emulator, auxv_tag::PHDR);
    let base = guest_getauxval(&emulator, auxv_tag::BASE);
    for (label, address) in [("AT_PHDR", phdr & !0xfff), ("AT_BASE", base)] {
        let mut magic = [0u8; 4];
        emulator
            .memory()
            .pointer(address)
            .read_bytes(0, &mut magic)
            .unwrap_or_else(|error| panic!("{label} at {address:#x} is readable: {error}"));
        assert_eq!(
            magic,
            [0x7f, b'E', b'L', b'F'],
            "{label} at {address:#x} carries the ELF magic"
        );
    }

    // AT_ENTRY is inside the image, and AT_PHDR sits in the header table the
    // image's own `e_phnum`/`e_phentsize` describe.
    let entry = guest_getauxval(&emulator, auxv_tag::ENTRY);
    assert!(
        entry >= base && entry < base + raxdbg_core::memory::PAGE_SIZE,
        "AT_ENTRY {entry:#x} is inside the image at {base:#x}"
    );
    assert_eq!(phdr, base + 64, "AT_PHDR follows the 64-byte ELF header");
}

#[test]
fn the_auxv_image_is_a_relocatable_pie() {
    let emulator = boot(11);
    let base = guest_getauxval(&emulator, auxv_tag::BASE);
    let header = emulator.memory().pointer(base);

    // `e_phoff` is a *file offset*, not an address. A guest that relocates the
    // image -- which is exactly what a linker does -- computes
    // `bias + e_phoff`; storing the absolute address there instead makes it
    // compute `bias + bias + offset` and walk into unmapped memory.
    let phoff = header.read_u64(32).expect("e_phoff");
    assert_eq!(phoff, 64, "e_phoff is the file offset of the header table");
    let entry = header.read_u64(24).expect("e_entry");
    assert!(
        entry < raxdbg_core::memory::PAGE_SIZE,
        "e_entry is relative to the load bias, got {entry:#x}"
    );

    // The first program header is a `PT_LOAD` whose `p_vaddr` is relative and
    // whose extent covers the image, so `p_vaddr + bias` lands on the header
    // the walk started from.
    let load = emulator.memory().pointer(base + phoff);
    assert_eq!(load.read_u32(0).expect("p_type"), 1, "PT_LOAD");
    assert_eq!(
        load.read_u64(16).expect("p_vaddr"),
        0,
        "p_vaddr is relative"
    );

    // The second is `PT_PHDR`, which is what a guest uses to find the table
    // inside the image without trusting `AT_PHDR`.
    let phdr_entry = emulator.memory().pointer(base + phoff + 56);
    assert_eq!(phdr_entry.read_u32(0).expect("p_type"), 6, "PT_PHDR");
    assert_eq!(
        phdr_entry.read_u64(16).expect("p_vaddr"),
        64,
        "PT_PHDR vaddr"
    );
}

#[test]
fn dlopen_and_dlsym_reach_the_linkers_private_symbols() {
    let emulator = boot(12);
    // A packer resolves the interpreter out of its own program headers and
    // then opens it to reach the linker's internals. `g_dl_mutex` and the
    // `do_dlopen` overloads are private to `linker64`: no shared library
    // exports them, so without a virtual module the lookup returns NULL and
    // the unpack stops before it starts.
    let dlopen = emulator.loader().dlsym(0, "dlopen").expect("dlopen");
    let dlsym = emulator.loader().dlsym(0, "dlsym").expect("dlsym");

    let name = emulator
        .memory()
        .write_stack_string("linker64")
        .expect("name");
    let handle = emulator
        .call_function(dlopen.address, &[name.peer(), 2])
        .expect("dlopen(linker64)");
    assert_ne!(handle, 0, "linker64 opened");

    for symbol in [
        "__dl__ZL10g_dl_mutex",
        "__dl__Z9do_dlopenPKciPK17android_dlextinfo",
        "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv",
        "__dl__Z8__dlopenPKciPKv",
    ] {
        let name = emulator
            .memory()
            .write_stack_string(symbol)
            .expect("symbol");
        let address = emulator
            .call_function(dlsym.address, &[handle, name.peer()])
            .expect("dlsym");
        assert_ne!(address, 0, "{symbol} resolved through linker64");
    }

    // The full interpreter path resolves too, because `dlopen` keys on the
    // basename and a guest may pass either form.
    let path = emulator
        .memory()
        .write_stack_string("/system/bin/linker64")
        .expect("path");
    assert_ne!(
        emulator
            .call_function(dlopen.address, &[path.peer(), 2])
            .expect("dlopen(path)"),
        0,
        "/system/bin/linker64 opened"
    );
}

#[test]
fn bionics_initialisers_run_on_demand_after_a_deferred_load() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-deferred")
        .seed(23)
        .build()
        .expect("emulator");
    // The load is asked not to run initialisers, which is what a `--jni-on-load`
    // run does so its trace covers them.
    emulator.loader().set_call_init_function(false);
    emulator.load_library("libc.so").expect("libc.so loads");
    emulator.loader().set_call_init_function(true);

    let marks = Rc::new(std::cell::RefCell::new(Vec::new()));
    emulator
        .loader()
        .set_init_function_listener(Rc::new(MarkerLog {
            marks: Rc::clone(&marks),
        }));

    assert_eq!(
        emulator.loader().module_init_functions("libc.so").len(),
        11,
        "libc carries 11 init_array entries and no DT_INIT"
    );
    assert!(marks.borrow().is_empty(), "nothing ran at load time");

    let count = emulator
        .loader()
        .call_constructors("libc.so")
        .expect("bionic's own initialisers run on real guest code");
    assert_eq!(count, 11);
    assert_eq!(marks.borrow().len(), 11);
    assert!(
        marks
            .borrow()
            .iter()
            .all(|label| label.starts_with("[libc.so] .init_array[")),
        "every entry came from init_array: {marks:?}"
    );
    let pending = emulator.loader().module_init_functions("libc.so");
    assert_eq!(
        marks.borrow()[0],
        format!("[libc.so] .init_array[1/11] 0x{:x}", pending[0]),
        "the first marker names the first slot"
    );
    assert_eq!(
        marks.borrow()[10],
        format!("[libc.so] .init_array[11/11] 0x{:x}", pending[10]),
        "and the last names the eleventh"
    );
    assert_eq!(
        emulator.loader().call_constructors("libc.so").unwrap(),
        0,
        "and they run at most once"
    );
}

struct MarkerLog {
    marks: Rc<std::cell::RefCell<Vec<String>>>,
}

impl raxdbg_android::elf::InitFunctionListener for MarkerLog {
    fn on_pre_call_init_function(&self, call: &raxdbg_android::elf::InitCall<'_>) {
        self.marks.borrow_mut().push(call.label());
    }
}
