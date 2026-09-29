//! Replace-hook tests (plan P8's engine-independent half).
//!
//! The fixtures give three targets: `target_fn` (a leaf that adds its two
//! arguments), `run` (which calls it through a volatile pointer, so the call is
//! not inlined away) and `imported_target` (which calls libc through the PLT).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_android::hook::{ReplaceCallback, ReplaceHook};
use raxdbg_core::memory::Memory;

fn boot() -> Rc<AndroidEmulator> {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-hook")
        .seed(7)
        .build()
        .expect("emulator");
    emulator.load_library("libc.so").expect("libc.so");
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("fixtures/prebuilt/arm64-v8a/libhooktest.so");
    let file = raxdbg_android::android_file::ElfLibraryFile::open(&path).expect("open fixture");
    emulator.load(Box::new(file), false).expect("load fixture");
    emulator
}

fn symbol(emulator: &Rc<AndroidEmulator>, name: &str) -> u64 {
    emulator
        .loader()
        .find_symbol("libhooktest.so", name)
        .unwrap_or_else(|| panic!("{name} is not exported"))
        .address
}

#[test]
fn the_fixture_runs_unhooked() {
    let emulator = boot();
    let run = symbol(&emulator, "run");
    // `run()` calls `target_fn(1, 2)` through a volatile pointer, so it must
    // reach the real function.
    assert_eq!(emulator.call_function(run, &[]).expect("run"), 3);
}

#[test]
fn an_uninstalled_replacement_leaves_the_function_alone() {
    let emulator = boot();
    let target = symbol(&emulator, "target_fn");
    let hook = ReplaceHook::replace(
        &emulator,
        target,
        ReplaceCallback {
            on_call: Box::new(|_ctx| 100),
            post_call: None,
        },
    )
    .expect("replace");
    let run = symbol(&emulator, "run");
    assert_eq!(emulator.call_function(run, &[]).expect("hooked"), 100);
    hook.uninstall(&emulator);
    assert_eq!(
        emulator.call_function(run, &[]).expect("unhooked"),
        3,
        "the original is back"
    );
}

#[test]
fn replacing_something_outside_a_module_is_refused() {
    let emulator = boot();
    let error = ReplaceHook::replace(
        &emulator,
        0x9000_0000,
        ReplaceCallback {
            on_call: Box::new(|_ctx| 0),
            post_call: None,
        },
    )
    .expect_err("an address outside every module is refused");
    assert!(matches!(
        error,
        raxdbg_android::hook::HookError::NotInModule { .. }
    ));
}

#[test]
fn the_replaced_function_still_returns_to_its_own_caller() {
    // The replacement must not disturb the stack: `second_fn` is called from
    // `run` too, and both calls have to return to the right place.
    let emulator = boot();
    let second = symbol(&emulator, "second_fn");
    let hook = ReplaceHook::replace(
        &emulator,
        second,
        ReplaceCallback {
            on_call: Box::new(|_ctx| 7),
            post_call: None,
        },
    )
    .expect("replace");
    let second_call = emulator.call_function(second, &[1, 2]).expect("call");
    assert_eq!(second_call, 7);
    hook.uninstall(&emulator);
    assert_eq!(
        emulator.call_function(second, &[1, 2]).expect("call"),
        3,
        "second_fn also adds its arguments"
    );
}

/// One mapped, executable page, named for the failure it is here to explain.
fn page(emulator: &std::rc::Rc<AndroidEmulator>, what: &str) -> u64 {
    emulator
        .memory()
        .mmap2_impl(0, 0x1000, raxdbg_core::backend::Prot::from_bits(0x5), 0x22, -1, 0)
        .unwrap_or_else(|error| panic!("{what} page: {error}"))
}

/// A function at `address` that returns `value` and then returns to its caller.
fn returns(emulator: &std::rc::Rc<AndroidEmulator>, address: u64, value: u16) {
    use raxdbg_core::memory::Memory;
    // `mov x0, #value` is 0xd2800000 | (value << 5).
    emulator
        .memory()
        .pointer(address)
        .write_u32(0, 0xd280_0000 | (u32::from(value) << 5))
        .expect("mov");
    emulator
        .memory()
        .pointer(address + 4)
        .write_u32(0, 0xd65f_03c0)
        .expect("ret");
}

/// The three bundled hook engines load and their entry points resolve.
///
/// Port of unidbg: `Dobby`, `HookZz` and `xhook`, whose binaries ship under
/// `android/lib/<abi>/`. They are the same idea -- patch a function's first
/// instructions so calls land in a replacement -- and the difference between
/// them is what they have to cope with in a real process, not the idea.
#[test]
fn the_bundled_hook_engines_load_and_resolve() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-engines")
        .sdk(23)
        .seed(5)
        .build()
        .expect("emulator");

    let dobby = raxdbg_android::hook::HookEngine::load(
        &emulator,
        raxdbg_android::hook::Engine::Dobby,
    )
    .expect("libdobby.so loads");
    assert_eq!(dobby.engine(), raxdbg_android::hook::Engine::Dobby);
    assert_ne!(dobby.entry(), 0, "DobbyHook resolved");
    assert!(dobby.module().contains("dobby"), "{}", dobby.module());

    let hookzz = raxdbg_android::hook::HookEngine::load(
        &emulator,
        raxdbg_android::hook::Engine::HookZz,
    )
    .expect("libhookzz.so loads");
    assert_ne!(hookzz.entry(), 0, "ZzReplace resolved");
    assert!(hookzz.module().contains("hookzz"), "{}", hookzz.module());

    let xhook = raxdbg_android::hook::HookEngine::load(
        &emulator,
        raxdbg_android::hook::Engine::XHook,
    )
    .expect("libxhook.so loads");
    assert_ne!(xhook.entry(), 0, "the JNI entry point resolved");
    assert!(
        xhook.engine().needs_vm(),
        "xHook is driven through its Java side, so it needs a VM rather than a call"
    );
}

/// The shared mechanism underneath the three engines: a branch written at a
/// function's entry, with the instruction it displaced saved.
#[test]
fn an_inline_hook_redirects_a_call_and_can_be_removed() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-inline")
        .seed(5)
        .build()
        .expect("emulator");
    emulator.load_library("libc.so").expect("libc.so");

    // A function that returns 42, and a trampoline in the same page. The page
    // has to be shared: the SVC page is gigabytes away, and a branch reaches
    // 128 MiB at most, so the trampoline cannot live where every other stub
    // does.
    let target = page(&emulator, "target");
    returns(&emulator, target, 42);
    let trampoline = target + 0x100;
    returns(&emulator, trampoline, 13);

    assert_eq!(
        emulator.call_function(target, &[]).expect("unhooked"),
        42,
        "before the hook the function returns its own value"
    );

    let hooks = std::rc::Rc::new(raxdbg_android::hook::InlineHooks::new());
    {
        use raxdbg_core::backend::Backend;
        let mut backend = emulator.backend().borrow_mut();
        raxdbg_android::hook::inline::install(
            &mut *backend,
            &hooks,
            target,
            trampoline,
            true,
        )
        .expect("the hook installs");
    }
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks.trampoline_for(target), Some(trampoline));
    assert_eq!(
        emulator.call_function(target, &[]).expect("hooked"),
        13,
        "the call now reaches the trampoline"
    );

    {
        use raxdbg_core::backend::Backend;
        let mut backend = emulator.backend().borrow_mut();
        assert!(raxdbg_android::hook::inline::uninstall(
            &mut *backend,
            &hooks,
            target
        ));
    }
    assert!(hooks.is_empty());
    assert_eq!(
        emulator.call_function(target, &[]).expect("unhooked again"),
        42,
        "and the original is back"
    );
}

/// A hook whose trampoline is out of range is refused, not written.
#[test]
fn an_out_of_range_trampoline_is_refused() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-inline-range")
        .build()
        .expect("emulator");
    emulator.load_library("libc.so").expect("libc.so");
    let target = page(&emulator, "out-of-range target");
    returns(&emulator, target, 42);
    let hooks = std::rc::Rc::new(raxdbg_android::hook::InlineHooks::new());
    {
        use raxdbg_core::backend::Backend;
        let mut backend = emulator.backend().borrow_mut();
        let error = raxdbg_android::hook::inline::install(
            &mut *backend,
            &hooks,
            target,
            0xffff_0000,
            true,
        )
        .expect_err("the SVC page is too far away to branch to");
        assert!(
            matches!(error, raxdbg_android::hook::inline::HookError::OutOfRange { .. }),
            "{error}"
        );
    }
    assert!(hooks.is_empty(), "nothing was patched");
    // And the function still works, because nothing was written.
    assert_eq!(emulator.call_function(target, &[]).expect("runs"), 42);
}

/// AArch32 cannot use the same mechanism: a Thumb `b` reaches 4 MiB, and the
/// SVC page is gigabytes away.
#[test]
fn a_thumb_trampoline_is_refused_rather_than_written() {
    let emulator = AndroidEmulatorBuilder::for_32bit()
        .process_name("raxdbg-inline-thumb")
        .build()
        .expect("emulator");
    let hooks = std::rc::Rc::new(raxdbg_android::hook::InlineHooks::new());
    {
        use raxdbg_core::backend::Backend;
        let mut backend = emulator.backend().borrow_mut();
        let error = raxdbg_android::hook::inline::install(
            &mut *backend,
            &hooks,
            0x0010_0000,
            0x0010_0100,
            false,
        )
        .expect_err("AArch32 needs a near trampoline and a multi-instruction patch");
        assert!(
            matches!(error, raxdbg_android::hook::inline::HookError::OutOfRange { .. }),
            "{error}"
        );
    }
    assert!(hooks.is_empty());
}

/// The fixture drives the engines itself: it `dlopen`s each one, resolves the
/// entry point with `dlsym`, and calls it. So an engine only has to be findable
/// by the resolver for the guest to reach it, and this is the test that says so.
///
/// It is also the honest boundary of the port: Dobby's `DobbyHook` needs to
/// disassemble and patch the target itself, which is the part a real Android
/// process needs and an emulator lays out for itself. The resolver half --
/// finding the binary and its symbol -- is what this port provides.
#[test]
fn every_engine_is_reachable_through_the_resolver() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-engines-resolver")
        .sdk(23)
        .seed(5)
        .build()
        .expect("emulator");

    for (library, symbol) in [
        ("libdobby.so", "DobbyHook"),
        ("libhookzz.so", "ZzReplace"),
        ("libxhook.so", "Java_com_qiyi_xhook_NativeHandler_refresh"),
    ] {
        // The resolver is what a guest `dlopen` goes through, so loading the
        // engine this way is the same path the fixture takes.
        let module = emulator
            .loader()
            .dlopen(library, false)
            .unwrap_or_else(|| panic!("dlopen({library}): the engine is not bundled"));
        let entry = emulator
            .loader()
            .dlsym(0, symbol)
            .unwrap_or_else(|| panic!("dlsym({symbol}) in {module}"));
        assert_ne!(entry.address, 0, "{symbol} resolved in {module}");
    }
}

/// `hello()` in `libctest.so` calls `printf`, which is a different path from
/// anything else these tests touch -- it goes through the whole stdio machinery
/// rather than arithmetic on a register.
#[test]
fn hello_from_the_ctest_fixture_prints_through_bionic() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-printf")
        .seed(5)
        .build()
        .expect("emulator");
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("fixtures/prebuilt/arm64-v8a/libctest.so");
    let file = ElfLibraryFile::open(&path).expect("open");
    emulator.load(Box::new(file), false).expect("load");
    let hello = emulator
        .loader()
        .find_symbol("libctest.so", "hello")
        .expect("hello");
    match emulator.call_function(hello.address, &[]) {
        Ok(value) => assert_eq!(value, 0, "hello returns void"),
        Err(error) => panic!("hello: {error}"),
    }
    let printed = emulator.stdout().contents();
    assert!(printed.contains("hello 42"), "{printed}");
}
