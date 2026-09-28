//! Virtual-module and libdl SVC trampoline tests (plan P5).
//!
//! Two surfaces under test:
//!
//! * The four Android virtual modules — `libandroid.so`,
//!   `libsystemproperties.so`, `libjnigraphics.so`, `libmediandk.so` —
//!   install SVC stubs whose symbols appear in the loader's module table.
//! * The `libdl` trampolines (`ArmLd64`) substitute `dlsym`, `dlerror`,
//!   `dlopen`, `dlclose`, `dladdr`, and `dl_iterate_phdr` with SVC stubs
//!   that dispatch to the loader's module table.
//!
//! The run loop's interrupt hook is not available in a unit test, so each
//! stub is driven the way the loop drives it: `take_svc(number)`, set up the
//! guest registers with `reg_write`, then call `handle(&mut *backend)`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::elf::loader::AndroidElfLoader;
use raxdbg_android::linux::android::system_property::StubDispatch;
use raxdbg_android::linux::android::{
    AndroidModule, ArmLd64, JniGraphics, MediaNdkModule, PROP_VALUE_MAX, SystemProperties,
    SystemPropertyHook, SystemPropertyProvider,
};
use raxdbg_backend_rax::RaxBackend;
use raxdbg_core::backend::{Backend, GuestMemory, Prot};
use raxdbg_core::hook::HookListener;
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{SvcMemory, SVC_BASE};

/// A backend plus the borrow-free handle to its address space that the loader
/// needs (plan P2.6).
fn new_loaded_backend() -> (Rc<RefCell<dyn Backend>>, std::sync::Arc<dyn GuestMemory>) {
    let backend = RaxBackend::new_arm64(RaxBackend::default_space());
    let guest = backend.guest_memory();
    (Rc::new(RefCell::new(backend)), guest)
}

fn new_loader(seed: u64) -> Rc<AndroidElfLoader> {
    let (backend, guest) = new_loaded_backend();
    AndroidElfLoader::new(backend, guest, true, "raxdbg", seed).expect("loader")
}

fn libs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("libs/android/sdk23/lib64")
}

/// Builds a `SvcMemory` and wires it into the loader, returning it.
fn new_svc_memory(loader: &AndroidElfLoader) -> Rc<SvcMemory> {
    let svc_memory = Rc::new(SvcMemory::new(loader.memory().as_ref(), true).expect("svc memory"));
    loader.set_svc_memory(Rc::clone(&svc_memory));
    svc_memory
}

#[test]
fn android_module_registers_libandroid_symbols() {
    let loader = new_loader(31);
    let _svc = new_svc_memory(&loader);
    AndroidModule::register(&loader).expect("register libandroid.so");

    let info = loader.module("libandroid.so").expect("module");
    assert_eq!(info.name, "libandroid.so");

    for symbol in [
        "AAssetManager_fromJava",
        "AAssetManager_open",
        "AAsset_close",
        "AAsset_getBuffer",
        "AAsset_getLength",
        "AAsset_read",
    ] {
        let found = loader
            .find_symbol("libandroid.so", symbol)
            .unwrap_or_else(|| panic!("{symbol} missing from libandroid.so"));
        assert!(
            found.address >= SVC_BASE,
            "{symbol} address {:#x} is outside the SVC page",
            found.address
        );
    }
}

#[test]
fn jnigraphics_module_registers_three_symbols() {
    let loader = new_loader(32);
    let _svc = new_svc_memory(&loader);
    JniGraphics::register(&loader).expect("register libjnigraphics.so");

    for symbol in [
        "AndroidBitmap_getInfo",
        "AndroidBitmap_lockPixels",
        "AndroidBitmap_unlockPixels",
    ] {
        let found = loader
            .find_symbol("libjnigraphics.so", symbol)
            .unwrap_or_else(|| panic!("{symbol} missing"));
        assert!(found.address >= SVC_BASE);
    }
}

#[test]
fn media_ndk_module_registers_four_symbols() {
    let loader = new_loader(33);
    let _svc = new_svc_memory(&loader);
    MediaNdkModule::register(&loader).expect("register libmediandk.so");

    for symbol in [
        "AMediaDrm_createByUUID",
        "AMediaDrm_getPropertyByteArray",
        "AMediaDrm_getPropertyString",
        "AMediaDrm_release",
    ] {
        let found = loader
            .find_symbol("libmediandk.so", symbol)
            .unwrap_or_else(|| panic!("{symbol} missing"));
        assert!(found.address >= SVC_BASE);
    }
}

#[test]
fn system_properties_module_registers_the_callback() {
    let loader = new_loader(34);
    let _svc = new_svc_memory(&loader);
    SystemProperties::register(&loader).expect("register libsystemproperties.so");
    let found = loader
        .find_symbol("libsystemproperties.so", "__system_property_read_callback")
        .expect("callback symbol");
    assert!(found.address >= SVC_BASE);
}

#[test]
fn system_property_get_writes_value_and_returns_length() {
    let loader = new_loader(35);
    let svc_memory = new_svc_memory(&loader);

    let provider = SystemPropertyProvider::with_defaults(23, true);
    let dispatch = Rc::new(StubDispatch::new());
    let hook = SystemPropertyHook::register(
        svc_memory.as_ref(),
        loader.memory().as_ref(),
        Rc::clone(&dispatch),
        true,
        loader.pointer_size(),
        provider.clone(),
    )
    .expect("hook");

    let stub_address =
        HookListener::hook(&hook, svc_memory.as_ref(), Some("libc.so"), "__system_property_get", 0);
    assert!(stub_address >= SVC_BASE);

    let key = "ro.build.version.sdk";
    let key_bytes = key.as_bytes();
    let key_ptr = loader
        .memory()
        .mmap(key_bytes.len() + 1, Prot::READ)
        .expect("key buffer")
        .peer();
    loader
        .memory()
        .write_bytes(key_ptr, key_bytes)
        .expect("write key");

    let value_ptr = loader
        .memory()
        .mmap(PROP_VALUE_MAX + 1, Prot::WRITE)
        .expect("value buffer")
        .peer();

    with_backend(&loader, |backend| { backend.reg_write(RegId::X(0), key_ptr).expect("set x0") });
    with_backend(&loader, |backend| { backend.reg_write(RegId::X(1), value_ptr).expect("set x1") });

    let number = hook.stubs().get.number;
    let mut svc = svc_memory.take_svc(number).expect("get stub registered");
    let length = with_backend(&loader, |backend| svc.handle(backend).expect("handle")) as usize;
    assert_eq!(length, 2, "ro.build.version.sdk = 23 (two bytes)");

    let mut buf = vec![0u8; length + 1];
    with_backend(&loader, |backend| { backend.mem_read_into(value_ptr, &mut buf).expect("read value") });
    let value = std::str::from_utf8(&buf[..length]).expect("utf-8 value");
    assert_eq!(value, "23");

    svc_memory.put_svc(number, svc);
}

#[test]
fn system_property_get_reads_keys_only_in_bundled_properties() {
    let loader = new_loader(36);
    let svc_memory = new_svc_memory(&loader);

    let properties_path = libs_dir()
        .parent()
        .expect("sdk23 tree")
        .join("dev/__properties__");
    assert!(
        properties_path.is_file(),
        "missing bundled __properties__: {}",
        properties_path.display()
    );
    let defaults = SystemPropertyProvider::with_defaults(23, true);
    let provider = SystemPropertyProvider::from_properties_file(&properties_path, defaults)
        .expect("parse properties");

    let dispatch = Rc::new(StubDispatch::new());
    let hook = SystemPropertyHook::register(
        svc_memory.as_ref(),
        loader.memory().as_ref(),
        Rc::clone(&dispatch),
        true,
        loader.pointer_size(),
        provider.clone(),
    )
    .expect("hook");
    let stub_address =
        HookListener::hook(&hook, svc_memory.as_ref(), Some("libc.so"), "__system_property_get", 0);

    let key = "ro.hardware";
    let key_ptr = loader
        .memory()
        .mmap(key.len() + 1, Prot::READ)
        .expect("key buffer")
        .peer();
    loader
        .memory()
        .write_bytes(key_ptr, key.as_bytes())
        .expect("write key");
    let value_ptr = loader
        .memory()
        .mmap(PROP_VALUE_MAX + 1, Prot::WRITE)
        .expect("value buffer")
        .peer();

    with_backend(&loader, |backend| { backend.reg_write(RegId::X(0), key_ptr).expect("x0") });
    with_backend(&loader, |backend| { backend.reg_write(RegId::X(1), value_ptr).expect("x1") });

    let number = hook.stubs().get.number;
    let mut svc = svc_memory.take_svc(number).expect("get stub registered");
    let length = with_backend(&loader, |backend| svc.handle(backend).expect("handle")) as usize;
    assert!(length > 0, "ro.hardware has a non-empty value");
    let mut buf = vec![0u8; length + 1];
    with_backend(&loader, |backend| { backend.mem_read_into(value_ptr, &mut buf).expect("read value") });
    let value = std::str::from_utf8(&buf[..length]).expect("utf-8 value");
    assert_eq!(value, "bullhead");

    svc_memory.put_svc(number, svc);
}

#[test]
fn armld64_registers_libdl_symbols_and_dlsym_resolves_a_real_export() {
    let (loader, _name) = load_bionic();
    let svc_memory = new_svc_memory(&loader);
    let dispatch = Rc::new(StubDispatch::new());
    let arm_ld = ArmLd64::register(
        svc_memory.as_ref(),
        loader.memory().as_ref(),
        Rc::clone(&dispatch),
        Rc::clone(&loader),
    )
    .expect("register arm_ld64");

    let dlerror_addr =
        HookListener::hook(&arm_ld, svc_memory.as_ref(), Some("libdl.so"), "dlerror", 0);
    assert!(dlerror_addr >= SVC_BASE, "dlerror stub lives in the SVC page");
    let dlerror_number = arm_ld.stubs.dlerror.number;
    let number = dlerror_number;
    let mut svc = svc_memory
        .take_svc(number)
        .expect("dlerror stub registered");
    let return_value = with_backend(&loader, |backend| svc.handle(backend).expect("handle"));
    assert_eq!(
        return_value as u64, SVC_BASE,
        "dlerror returns the error buffer, which `Dlfcn` allocates first in the SVC page"
    );
    svc_memory.put_svc(number, svc);

    let dlsym_addr =
        HookListener::hook(&arm_ld, svc_memory.as_ref(), Some("libdl.so"), "dlsym", 0);
    let dlsym_number = arm_ld.stubs.dlsym.number;
    let number = dlsym_number;
    let mut svc = svc_memory
        .take_svc(number)
        .expect("dlsym stub");

    let name = "malloc";
    let name_ptr = loader
        .memory()
        .mmap(name.len() + 1, Prot::READ)
        .expect("name buffer")
        .peer();
    loader
        .memory()
        .write_bytes(name_ptr, name.as_bytes())
        .expect("write name");

    with_backend(&loader, |backend| { backend.reg_write(RegId::X(0), 0).expect("x0 = RTLD_DEFAULT") });
    with_backend(&loader, |backend| { backend.reg_write(RegId::X(1), name_ptr).expect("x1 = name") });

    let symbol_address = with_backend(&loader, |backend| svc.handle(backend).expect("handle")) as u64;
    assert_ne!(
        symbol_address, 0,
        "dlsym should resolve `malloc` from the loaded libc.so"
    );

    let libc = loader.module("libc.so").expect("libc module");
    assert!(
        symbol_address >= libc.base && symbol_address < libc.base + libc.size,
        "malloc address {symbol_address:#x} is outside libc.so [{:#x}..{:#x})",
        libc.base,
        libc.base + libc.size
    );

    svc_memory.put_svc(number, svc);
}

/// Runs `f` with the loader's own backend borrowed, and nothing else.
///
/// The borrowing rule from plan P2.6: a stub's handler is handed the backend
/// and must use that reference, so the test must not hold the borrow across a
/// call that reaches back into the loader.
fn with_backend<R>(loader: &Rc<AndroidElfLoader>, f: impl FnOnce(&mut dyn Backend) -> R) -> R {
    let mut backend = loader.backend().borrow_mut();
    f(&mut *backend)
}

fn load_bionic() -> (Rc<AndroidElfLoader>, String) {
    let loader = new_loader(40);
    let path = libs_dir().join("libc.so");
    let file = ElfLibraryFile::open(&path)
        .unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
    let name = loader
        .load(Box::new(file), false)
        .unwrap_or_else(|e| panic!("cannot load libc.so: {e}"));
    (loader, name)
}
