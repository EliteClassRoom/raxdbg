//! Guest thread tests (plan P7).
//!
//! These drive [`ThreadDispatcher`] with hand-assembled arm64 code rather than
//! through bionic's `pthread_create`, so they test the dispatcher itself: the
//! register file each task starts with, its own stack, cooperative switching
//! through [`RunError::ThreadSwitch`], and retiring a task through the exit
//! stub. The `pthread_create` interception that turns a guest `pthread_create`
//! into a task is the next piece of P7 and is not what these assert.

use std::cell::Cell;
use std::rc::Rc;

use raxdbg_android::emulator::{AndroidEmulator, AndroidEmulatorBuilder};
use raxdbg_android::thread::ThreadRuntime;
use raxdbg_core::backend::{Backend, Prot, RunError};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

/// Assembles a code page and returns its address.
struct CodePage {
    address: u64,
}

impl CodePage {
    fn write(emulator: &Rc<AndroidEmulator>, words: &[u32]) -> CodePage {
        // Map through the loader, not the backend: `allocate_map_address` walks
        // the loader's region tree, so a page mapped behind its back is handed
        // out again and the second page silently overwrites the first.
        let address = emulator
            .memory()
            .mmap2_impl(0, 0x1000, Prot::from_bits(0x7), 0x22, -1, 0)
            .expect("map");
        let mut bytes = Vec::with_capacity(words.len() * 4);
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let mut backend = emulator.backend().borrow_mut();
        backend.mem_write(address, &bytes).expect("write");
        CodePage { address }
    }
}

/// `mov x0, #imm` — the 64-bit form for a value that fits in 16 bits.
fn mov_x0(value: u16) -> u32 {
    0xd280_0000 | (u32::from(value) << 5)
}

/// `ret`.
const RET: u32 = 0xd65f_03c0;

/// `svc #number`.
fn svc(number: i32) -> u32 {
    0xd400_0001 | ((number as u32) << 5)
}

/// An SVC stub that yields the running task, as a blocking syscall does.
struct YieldStub {
    kind: SvcKind,
    yields: Rc<Cell<usize>>,
}

impl Svc for YieldStub {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        self.yields.set(self.yields.get() + 1);
        Err(RunError::ThreadSwitch)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "TestYield"
    }
}

fn emulator() -> Rc<AndroidEmulator> {
    AndroidEmulatorBuilder::for_64bit()
        .process_name("raxdbg-threads")
        .seed(17)
        .build()
        .expect("emulator")
}

#[test]
fn a_task_runs_its_function_and_its_result_comes_back() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let code = CodePage::write(&emulator, &[mov_x0(42), RET]);
    let mut dispatcher = runtime.dispatcher(&emulator);
    let stack = runtime.allocate_stack(&emulator).expect("stack");
    let id = dispatcher.create(code.address, &[], stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    assert_eq!(results, vec![(id, 42)]);
    assert_eq!(dispatcher.task(id).expect("task").state(), raxdbg_core::thread::TaskState::Finished);
    assert_eq!(dispatcher.pending(), 0);
}

#[test]
fn each_task_gets_its_own_arguments() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    // `add x0, x0, x1` then `ret`.
    let add = CodePage::write(&emulator, &[0x8b01_0000, RET]);
    let mut dispatcher = runtime.dispatcher(&emulator);
    let first_stack = runtime.allocate_stack(&emulator).expect("stack");
    let second_stack = runtime.allocate_stack(&emulator).expect("stack");
    assert_ne!(first_stack, second_stack, "each task has its own stack");
    let first = dispatcher.create(add.address, &[20, 22], first_stack);
    let second = dispatcher.create(add.address, &[1000, 337], second_stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    let results: Vec<(usize, u64)> = results;
    assert!(results.contains(&(first, 42)), "{results:?}");
    assert!(results.contains(&(second, 1337)), "{results:?}");
}

#[test]
fn a_task_that_yields_lets_the_other_one_run() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let yields = Rc::new(Cell::new(0));
    let (yield_stub, yield_number) = {
        let svc: Rc<SvcMemory> = emulator.loader().svc_memory().expect("svc page");
        svc.register_svc_numbered(
            emulator.memory().as_ref(),
            Box::new(YieldStub {
                kind: SvcKind::Arm64,
                yields: Rc::clone(&yields),
            }),
        )
        .expect("register")
    };
    assert_ne!(yield_stub, 0);

    // Each task yields once, then returns its own value.
    let first = CodePage::write(&emulator, &[svc(yield_number), mov_x0(1), RET]);
    let second = CodePage::write(&emulator, &[svc(yield_number), mov_x0(2), RET]);
    let mut dispatcher = runtime.dispatcher(&emulator);
    let first_stack = runtime.allocate_stack(&emulator).expect("stack");
    let second_stack = runtime.allocate_stack(&emulator).expect("stack");
    let first_id = dispatcher.create(first.address, &[], first_stack);
    let second_id = dispatcher.create(second.address, &[], second_stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    assert_eq!(yields.get(), 2, "both tasks reached the yield stub");
    assert_eq!(dispatcher.switches(), 2, "each yield switched once");
    assert!(results.contains(&(first_id, 1)), "{results:?}");
    assert!(results.contains(&(second_id, 2)), "{results:?}");
}

#[test]
fn a_task_that_finishes_frees_its_context_and_the_others_keep_running() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let yields = Rc::new(Cell::new(0));
    let yield_number = {
        let svc: Rc<SvcMemory> = emulator.loader().svc_memory().expect("svc page");
        svc.register_svc_numbered(
            emulator.memory().as_ref(),
            Box::new(YieldStub {
                kind: SvcKind::Arm64,
                yields: Rc::clone(&yields),
            }),
        )
        .expect("register")
        .1
    };

    // The first task yields twice before returning; the second returns at once.
    let slow = CodePage::write(
        &emulator,
        &[svc(yield_number), svc(yield_number), mov_x0(11), RET],
    );
    let quick = CodePage::write(&emulator, &[mov_x0(22), RET]);
    let mut dispatcher = runtime.dispatcher(&emulator);
    let slow_stack = runtime.allocate_stack(&emulator).expect("stack");
    let quick_stack = runtime.allocate_stack(&emulator).expect("stack");
    let slow_id = dispatcher.create(slow.address, &[], slow_stack);
    let quick_id = dispatcher.create(quick.address, &[], quick_stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    assert_eq!(dispatcher.pending(), 0, "every task finished");
    // The quick task finishes first, while the slow one still has a yield left.
    assert_eq!(results[0], (quick_id, 22), "{results:?}");
    assert!(results.contains(&(slow_id, 11)), "{results:?}");
    assert_eq!(yields.get(), 2);
}

#[test]
fn a_task_runs_on_its_own_stack() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    // `mov x0, sp` — report the stack pointer the task actually runs on.
    let code = CodePage::write(&emulator, &[0x9100_03e0, RET]);
    let mut dispatcher = runtime.dispatcher(&emulator);
    let stack = runtime.allocate_stack(&emulator).expect("stack");
    let id = dispatcher.create(code.address, &[], stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    let (_, reported) = results[0];
    assert_eq!(id, results[0].0);
    // The stack pointer the task saw is the top of its own area, and the
    // function's prologue does not move it.
    assert!(
        reported <= stack && reported > stack - 0x1000,
        "the task reported sp {reported:#x}, expected just below its stack {stack:#x}"
    );
    assert_eq!(reported % 16, 0, "and it is 16-byte aligned");
}

#[test]
fn a_task_that_traps_reports_the_fault_rather_than_hanging() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    // A load from an unmapped address.
    let code = CodePage::write(&emulator, &[0xf940_0000, RET]); // ldr x0, [x0]
    let mut dispatcher = runtime.dispatcher(&emulator);
    let stack = runtime.allocate_stack(&emulator).expect("stack");
    dispatcher.create(code.address, &[0xdead_0000], stack);

    let outcome = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend)
    };
    match outcome {
        Err(RunError::UnmappedMemory { addr, .. }) => assert_eq!(addr, 0xdead_0000),
        other => panic!("expected an unmapped-memory error, got {other:?}"),
    }
}

#[test]
fn the_thread_stack_area_is_below_the_main_stack() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let main = emulator.memory().get_stack_point();
    let stack = runtime.allocate_stack(&emulator).expect("stack");
    assert!(
        stack < main,
        "thread stacks are allocated below the main stack: {stack:#x} vs {main:#x}"
    );
    // A second one is below the first, as `allocate_thread_stack` walks down.
    let second = runtime.allocate_stack(&emulator).expect("stack");
    assert!(second < stack, "{second:#x} vs {stack:#x}");
    // And both are readable, which is what a thread's prologue needs.
    let probe = emulator.memory().pointer(stack - 8);
    probe.write_u64(0, 0x1234).expect("the stack is mapped");
    assert_eq!(probe.read_u64(0).expect("read back"), 0x1234);
}

/// `movz xN, #imm16, lsl #16` — the high half of an address.
fn movz_x_hi(reg: u32, value: u16) -> u32 {
    0xd2a0_0000 | (u32::from(value) << 5) | reg
}

/// `movk xN, #imm16` — the low half.
fn movk_x(reg: u32, value: u16) -> u32 {
    0xf280_0000 | (u32::from(value) << 5) | reg
}

/// `movz xN, #imm16`.
fn movz_x(reg: u32, value: u16) -> u32 {
    0xd280_0000 | (u32::from(value) << 5) | reg
}

/// The two instructions that put a 32-bit address in `xN`.
fn load_address(reg: u32, address: u32) -> [u32; 2] {
    [
        movz_x_hi(reg, (address >> 16) as u16),
        movk_x(reg, (address & 0xffff) as u16),
    ]
}

#[test]
fn a_task_that_waits_on_a_futex_runs_again_when_it_is_woken() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let waiters = emulator.syscall().borrow().unix_handler().waiters().clone();
    let futex = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("futex page");
    emulator
        .memory()
        .pointer(futex)
        .write_u32(0, 0)
        .expect("zero the futex");
    let futex = futex as u32;

    // Task A: `futex(addr, FUTEX_WAIT, 0)` — parks — then returns 1.
    let [hi, lo] = load_address(0, futex);
    let waiter_code = CodePage::write(
        &emulator,
        &[
            hi,
            lo,
            movz_x(1, 0),     // FUTEX_WAIT
            movz_x(2, 0),     // the value it expects to find
            movz_x(8, 98),    // futex
            svc(0),
            movz_x(0, 1),
            RET,
        ],
    );

    // Task B: store 1 at the futex, then `futex(addr, FUTEX_WAKE, 1)`, then
    // return 2. The store is what makes A's wait satisfiable.
    let [b_hi, b_lo] = load_address(0, futex);
    let waker_code = CodePage::write(
        &emulator,
        &[
            b_hi,
            b_lo,
            movz_x(9, 1),
            0xb900_0009,      // str w9, [x0]
            movz_x(1, 1),     // FUTEX_WAKE
            movz_x(2, 1),     // wake one
            movz_x(8, 98),    // futex
            svc(0),
            movz_x(0, 2),
            RET,
        ],
    );

    let mut dispatcher = runtime.dispatcher(&emulator);
    dispatcher.set_waiters(Rc::clone(&waiters));
    let a_stack = runtime.allocate_stack(&emulator).expect("stack");
    let b_stack = runtime.allocate_stack(&emulator).expect("stack");
    let a = dispatcher.create(waiter_code.address, &[], a_stack);
    let b = dispatcher.create(waker_code.address, &[], b_stack);

    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    assert_eq!(dispatcher.pending(), 0, "both tasks finished: {results:?}");
    assert!(results.contains(&(a, 1)), "the waiting task ran to the end: {results:?}");
    assert!(results.contains(&(b, 2)), "{results:?}");
    assert_eq!(
        emulator.memory().pointer(u64::from(futex)).read_u32(0).expect("read"),
        1,
        "the waker's store landed"
    );
    assert!(dispatcher.switches() >= 2, "the wait and the wake both switched");
}

#[test]
fn a_futex_wait_on_a_changed_value_does_not_park() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let futex = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("futex page");
    // The word already holds 7, and the guest waits for 0: the kernel's
    // `old != val` shortcut returns `-EAGAIN` without parking anyone.
    emulator
        .memory()
        .pointer(futex)
        .write_u32(0, 7)
        .expect("write the futex");
    let futex = futex as u32;
    let [hi, lo] = load_address(0, futex);
    let code = CodePage::write(
        &emulator,
        &[
            hi,
            lo,
            movz_x(1, 0),  // FUTEX_WAIT
            movz_x(2, 0),  // expects 0, finds 7
            movz_x(8, 98), // futex
            svc(0),
            RET,           // x0 is the syscall's return: -EAGAIN
        ],
    );
    let mut dispatcher = runtime.dispatcher(&emulator);
    dispatcher.set_waiters(emulator.syscall().borrow().unix_handler().waiters().clone());
    let stack = runtime.allocate_stack(&emulator).expect("stack");
    dispatcher.create(code.address, &[], stack);
    let results = {
        let mut backend = emulator.backend().borrow_mut();
        dispatcher.run(&mut *backend).expect("run")
    };
    assert_eq!(
        results[0].1 as i32, -11,
        "the syscall returned -EAGAIN and nobody parked"
    );
    assert_eq!(dispatcher.switches(), 0, "no switch was needed");
}
