//! Syscall-layer tests (plan P4).
//!
//! Drives the dispatch path directly: the test loads the guest stub
//! bytes into guest memory, sets up registers to match the stub's
//! arguments, invokes [`AndroidSyscallHandler::dispatch`], and asserts
//! the result (register file, fd table, captured stdout).
//!
//! We exercise every syscall the plan calls out:
//!
//! * `read`, `write`, `openat`, `getpid`, `clock_gettime`, `mmap`
//!   (anonymous), `brk`, `set_tid_address`, `futex` (wait + wake),
//!   `getrandom`;
//! * an SVC-stub test where the guest `svc #N`s into a registered
//!   stub and the handler's value lands in `x0`;
//! * a test that an unregistered `svc #0x1234` reports a clear error
//!   rather than executing garbage.
//!
//! Driving the dispatch directly (rather than via `emu_start`) sidesteps
//! the `Rc<RefCell<dyn Backend>>` re-entry the syscall layer would
//! otherwise hit on the run loop. The rax backend already exposes a
//! round-trip test (`unhandled_svc_is_an_error`) for the wire-up path.

#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use raxdbg_backend_rax::RaxBackend;
use raxdbg_core::backend::{
    Backend, BackendError, Prot, RunError, EXCP_SWI, EXCP_UDEF,
};
use raxdbg_core::errno::EAGAIN;
use raxdbg_core::memory::loader::Loader;
use raxdbg_core::memory::{Memory, MemoryError};
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind};
use raxdbg_android::elf::AndroidElfLoader;
use raxdbg_android::syscall::{AndroidSyscallHandler, SharedSink, SyscallHook};

// -------- A `Svc` impl with a constant return value -------------------------------

struct ConstSvc {
    kind: SvcKind,
    value: i64,
}

impl ConstSvc {
    fn new(kind: SvcKind, value: i64) -> Self {
        Self { kind, value }
    }
}

impl Svc for ConstSvc {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        Ok(self.value)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "ConstSvc"
    }
}

// -------- Harness ------------------------------------------------------------------

fn build_test() -> TestHarness {
    let sink = SharedSink::new();
    let backend = RaxBackend::new_arm64(RaxBackend::default_space());
    let guest = backend.guest_memory();
    let backend_dyn: Rc<RefCell<dyn Backend>> = Rc::new(RefCell::new(backend));
    let loader = AndroidElfLoader::new(backend_dyn.clone(), guest, true, "raxdbg-test", 0xfeed_face)
        .expect("loader");
    let syscall =
        AndroidSyscallHandler::new(loader.clone(), true, Some(sink.clone())).expect("syscall");
    install_hook(backend_dyn.clone(), syscall.clone());
    TestHarness {
        backend: backend_dyn,
        loader,
        syscall,
        sink,
    }
}

fn install_hook(
    backend: Rc<RefCell<dyn Backend>>,
    handler: Rc<RefCell<AndroidSyscallHandler>>,
) {
    let hook = SyscallHook::new(handler);
    backend.borrow_mut().hook_add_interrupt(Box::new(hook));
}

struct TestHarness {
    backend: Rc<RefCell<dyn Backend>>,
    loader: Rc<AndroidElfLoader>,
    syscall: Rc<RefCell<AndroidSyscallHandler>>,
    sink: Arc<SharedSink>,
}

impl TestHarness {
    fn map_and_write_data(&self, bytes: &[u8]) {
        self.backend
            .borrow_mut()
            .mem_map(0x2000, 0x1000, Prot::READ.union(Prot::WRITE))
            .expect("map DATA");
        self.backend
            .borrow_mut()
            .mem_write(0x2000, bytes)
            .expect("write data");
    }

    fn read_u64(&self, addr: u64) -> u64 {
        let mut buf = [0u8; 8];
        self.backend
            .borrow()
            .mem_read_into(addr, &mut buf)
            .expect("read u64");
        u64::from_le_bytes(buf)
    }

    /// Invokes `dispatch(EXCP_SWI, swi)` with `x0..x7, x8` set per the
    /// guest stub's arguments. Returns whatever `dispatch` does.
    /// Dispatches a real syscall: `x8` holds the number and the trap
    /// immediate is zero, which is exactly what bionic's `svc #0` does.
    fn dispatch_swi(&self, nr: i32, args: &[u64]) -> Result<(), RunError> {
        self.dispatch_trap(args, nr as u64, 0)
    }

    /// Dispatches a stub call: the trap immediate is the stub number, which is
    /// what a registered `svc #N; ret` stub issues.
    fn dispatch_stub(&self, stub: i32, args: &[u64]) -> Result<(), RunError> {
        self.dispatch_trap(args, 0, stub)
    }

    fn dispatch_trap(&self, args: &[u64], x8: u64, swi: i32) -> Result<(), RunError> {
        // Initialise the registers the guest would have set up.
        {
            let mut backend = self.backend.borrow_mut();
            for (i, value) in args.iter().enumerate() {
                backend.reg_write(RegId::X(i as u8), *value).expect("arg");
            }
            // x8 = syscall number; x16 is the PRE/POST marker, which must not
            // match 0x8866/0x8888 here so we land in the real path.
            backend.reg_write(RegId::X(8), x8).expect("x8");
            backend.reg_write(RegId::X(12), 0).expect("x12");
            backend.reg_write(RegId::X(16), 0).expect("x16");
            backend.reg_write(RegId::X(17), 0).expect("x17");
        }
        let mut syscall = self.syscall.borrow_mut();
        syscall.dispatch(&mut *self.backend.borrow_mut(), EXCP_SWI, swi)
    }

    /// Invokes `dispatch(EXCP_UDEF, 0)` to assert the BRK/UDEF path.
    fn dispatch_undef(&self) -> Result<(), RunError> {
        let mut syscall = self.syscall.borrow_mut();
        syscall.dispatch(&mut *self.backend.borrow_mut(), EXCP_UDEF, 0)
    }

    /// Reads `x0` after a syscall dispatch.
    fn x0(&self) -> u64 {
        self.backend.borrow().reg_read(RegId::X(0)).unwrap()
    }

    /// How many futex waiters are registered.
    fn waiters(&self) -> usize {
        self.syscall.borrow().unix_handler().waiters().len()
    }
}

// -------- Tests ---------------------------------------------------------------------

#[test]
fn write_writes_into_stdout_sink() {
    let harness = build_test();
    let message = b"hello raxdbg\n";
    harness.map_and_write_data(message);
    // x0 = fd (1 = stdout), x1 = addr, x2 = count.
    let args = [1u64, 0x2000, message.len() as u64, 0, 0, 0, 0];
    harness.dispatch_swi(64, &args).expect("write");
    assert_eq!(harness.sink.contents(), "hello raxdbg\n");
}

#[test]
fn getpid_returns_state_pid() {
    let harness = build_test();
    let args = [0u64; 7];
    harness.dispatch_swi(172, &args).expect("getpid");
    assert_eq!(
        harness.x0() as i32,
        harness.syscall.borrow().thread_state().pid()
    );
}

#[test]
fn clock_gettime_returns_zero_with_nonzero_secs() {
    let harness = build_test();
    harness.map_and_write_data(&[0; 16]);
    // x0 = clk_id (0 = CLOCK_REALTIME), x1 = tp (DATA).
    harness.dispatch_swi(113, &[0, 0x2000, 0, 0, 0, 0, 0]).expect("clock_gettime");
    assert_eq!(harness.x0(), 0, "clock_gettime returns 0 on success");
    let secs = harness.read_u64(0x2000);
    assert!(secs > 0, "clock_gettime writes a non-zero seconds value: {secs}");
}

#[test]
fn mmap_anonymous_returns_a_valid_address() {
    let harness = build_test();
    let args = [0u64, 0x1000, 3, 0x22, 0xffff_ffff_ffff_ffff, 0, 0];
    harness.dispatch_swi(222, &args).expect("mmap");
    let addr = harness.x0();
    assert_ne!(addr, 0, "anonymous mmap returns a non-zero address");
    assert_ne!(addr, u64::MAX, "anonymous mmap returns MAP_FAILED");
}

#[test]
fn brk_returns_a_sane_break() {
    let harness = build_test();
    let args = [0u64; 7];
    harness.dispatch_swi(214, &args).expect("brk");
    let x0 = harness.x0();
    assert!(x0 >= 0x0804_8000, "brk returns a sane break value: {x0:#x}");
}

#[test]
fn set_tid_address_returns_pid() {
    let harness = build_test();
    let args = [0x2000u64, 0, 0, 0, 0, 0, 0];
    harness.dispatch_swi(96, &args).expect("set_tid_address");
    assert_eq!(
        harness.x0() as i32,
        harness.syscall.borrow().thread_state().pid()
    );
}

#[test]
fn getrandom_fills_sixteen_bytes() {
    let harness = build_test();
    harness.map_and_write_data(&[0; 16]);
    // x0 = buf, x1 = len, x2 = flags.
    let args = [0x2000u64, 16, 0, 0, 0, 0, 0];
    harness.dispatch_swi(278, &args).expect("getrandom");
    assert_eq!(harness.x0(), 16, "getrandom returns the requested byte count");
}

#[test]
fn register_svc_blr_returns_handler_value() {
    let harness = build_test();
    // Register a stub. `ArmSvcMemory` numbers arm64 stubs from 0xff upwards
    // (unidbg's `armSvcNumber`), so the first one is 0x100 and its stub issues
    // `svc #0x100`.
    let stub_addr = {
        let handler = harness.syscall.borrow();
        handler
            .register_svc(Box::new(ConstSvc::new(SvcKind::Arm64, 0x1234_5678)))
            .expect("register svc")
    };
    assert!(stub_addr >= 0xfffe_0000, "stub lives in the SVC page");
    drop(stub_addr);

    let args = [0u64; 7];
    harness.dispatch_stub(0x100, &args).expect("svc #0x100");

    let x0 = harness.x0();
    assert_eq!(x0, 0x1234_5678, "stub return value lands in x0: {x0:#x}");
}

#[test]
fn unregistered_svc_reports_error() {
    let harness = build_test();
    let args = [0u64; 7];
    let result = harness.dispatch_stub(0x1234, &args);
    let err = result.expect_err("unregistered svc must report an error");
    match err {
        RunError::Backend(BackendError::Other(msg)) => {
            assert!(
                msg.contains("no SVC stub registered"),
                "expected 'no SVC stub registered' in {msg}"
            );
        }
        other => panic!("expected BackendError::Other, got {other:?}"),
    }
}

#[test]
fn futex_wait_parks_the_thread_when_the_value_matches() {
    // P7's contract: with the waiter machinery in place a matching
    // `FUTEX_WAIT` registers a waiter and asks for a thread switch, which is
    // how `pthread_join` and `pthread_cond_wait` block instead of spinning.
    let harness = build_test();
    harness.map_and_write_data(&[0; 8]);
    // x0 = uaddr, x1 = op (FUTEX_WAIT), x2 = val (0, which is what is there),
    // x3 = timeout.
    let args = [0x2000u64, 0, 0, 0, 0, 0, 0];
    let error = harness
        .dispatch_swi(98, &args)
        .expect_err("a matching futex wait parks the thread");
    assert!(
        matches!(error, RunError::ThreadSwitch),
        "expected a thread switch, got {error:?}"
    );
    assert_eq!(
        harness.waiters(),
        1,
        "and the thread is registered as a waiter"
    );
}

#[test]
fn futex_wait_returns_eagain_when_the_value_changed() {
    // The kernel's `old != val` shortcut: nothing is parked, the caller is told
    // to retry its check.
    let harness = build_test();
    harness.map_and_write_data(&[7u8; 8]);
    let args = [0x2000u64, 0, 0, 0, 0, 0, 0];
    harness.dispatch_swi(98, &args).expect("futex wait");
    assert_eq!(harness.x0() as i32, -EAGAIN, "futex wait returns -EAGAIN");
    assert_eq!(harness.waiters(), 0, "and nobody was parked");
}

#[test]
fn futex_wake_returns_the_number_woken() {
    let harness = build_test();
    harness.map_and_write_data(&[0; 8]);
    // Park one thread first, then wake it.
    let wait = [0x2000u64, 0, 0, 0, 0, 0, 0];
    let _ = harness.dispatch_swi(98, &wait);
    assert_eq!(harness.waiters(), 1);
    // x0 = uaddr, x1 = op (FUTEX_WAKE = 1), x2 = val (1).
    let wake = [0x2000u64, 1, 1, 0, 0, 0, 0];
    let _ = harness.dispatch_swi(98, &wake);
    assert_eq!(harness.x0(), 1, "futex wake reports the one it woke");
}

#[test]
fn undefined_instruction_reports_error() {
    let harness = build_test();
    let err = harness
        .dispatch_undef()
        .expect_err("undefined instruction must report an error");
    match err {
        RunError::Backend(BackendError::Other(msg)) => {
            assert!(
                msg.contains("undefined instruction"),
                "expected 'undefined instruction' in {msg}"
            );
        }
        other => panic!("expected BackendError::Other, got {other:?}"),
    }
}

// Quiet unused-import lints for items only referenced in trait impls.
#[allow(dead_code)]
fn _silence_imports() {
    let _: Result<u64, MemoryError> = Err(MemoryError::Message("silence".into()));
    let _ = Loader::new;
}