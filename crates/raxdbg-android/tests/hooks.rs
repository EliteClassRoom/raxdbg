//! Replace-hook tests (plan P8's engine-independent half).
//!
//! The fixtures give three targets: `target_fn` (a leaf that adds its two
//! arguments), `run` (which calls it through a volatile pointer, so the call is
//! not inlined away) and `imported_target` (which calls libc through the PLT).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

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
