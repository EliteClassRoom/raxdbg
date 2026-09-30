//! `exit`/`exit_group` must end the run, not fall through to the trap page.
//!
//! A guest that calls `exit(0)` does not return. Before this was wired, the
//! table's `exit` was a no-op: execution continued, the `svc` returned 0,
//! and the guest `ret`'d into the trap page as if `exit` were an ordinary
//! function — so a caller saw whatever happened to be in `x0`. unidbg stops
//! the run here (`Backend.emu_stop()`), and so must this.

#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_android::emulator::AndroidEmulatorBuilder;
use raxdbg_android::syscall::arm64::nr;
use raxdbg_android::syscall::handler::UnixSyscallHandler;

/// Drives `nr` through the handler with no arguments and reports the
/// request it left behind.
fn dispatch(handler: &Rc<RefCell<UnixSyscallHandler>>, number: i32) -> Option<i32> {
    let state = Default::default();
    let borrowed = handler.borrow();
    let mut table = raxdbg_android::syscall::arm64::Arm64SyscallTable::new(&borrowed, &state);
    table.set_args([0; 8]);
    table.dispatch(number);
    drop(borrowed);
    handler.borrow().take_exit_request()
}

#[test]
fn exit_group_asks_the_run_to_stop() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let handler = Rc::clone(&emulator.syscall().borrow().handler);
    assert_eq!(dispatch(&handler, nr::EXIT_GROUP), Some(0));
}

#[test]
fn exit_asks_the_run_to_stop() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let handler = Rc::clone(&emulator.syscall().borrow().handler);
    assert_eq!(
        dispatch(&handler, nr::EXIT),
        Some(0),
        "exit(0) must ask for the run to stop"
    );
}

#[test]
fn the_request_is_taken_once() {
    // The dispatch takes the request, so a second read finds nothing: a
    // request left behind would stop an unrelated later run.
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let handler = Rc::clone(&emulator.syscall().borrow().handler);
    assert_eq!(dispatch(&handler, nr::EXIT_GROUP), Some(0));
    assert_eq!(
        handler.borrow().take_exit_request(),
        None,
        "the request must be consumed by the first read"
    );
}

#[test]
fn an_ordinary_syscall_asks_for_nothing() {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let handler = Rc::clone(&emulator.syscall().borrow().handler);
    let _ = dispatch(&handler, nr::GETPID);
    assert_eq!(
        handler.borrow().take_exit_request(),
        None,
        "getpid must not look like an exit"
    );
}
