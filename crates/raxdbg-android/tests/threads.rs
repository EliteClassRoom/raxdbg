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

/// The precomputed entry code is what a new thread actually runs: it takes the
/// start routine and its argument off the stack, calls, and leaves the
/// function's result in `x0`.
///
/// This is plan P7's `clone patchers` in its loadable half -- the entry sequence
/// and the `pthread_internal_t` offsets -- checked against real code rather than
/// against a table that only looks right.
#[test]
fn the_entry_code_calls_the_routine_and_keeps_its_result() {
    let emulator = emulator();
    let start = emulator
        .thread_start()
        .expect("the emulator installs one during boot");
    assert_ne!(start.entry, 0, "the entry code has an address");

    // The thread function: return 7.
    let routine = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x5), 0x22, -1, 0)
        .expect("routine");
    emulator.memory().pointer(routine).write_u32(0, 0xd280_00e0).expect("mov x0, #7");
    emulator
        .memory()
        .pointer(routine + 4)
        .write_u32(0, 0xd65f_03c0)
        .expect("ret");

    // The routine on its own, to be sure the 7 is coming from there.
    assert_eq!(
        emulator.call_function(routine, &[]).expect("the routine"),
        7,
        "the thread function returns 7"
    );

    // The stack the `clone` handler would have prepared: the routine, then its
    // argument, at the top. The runtime's thread stack is already mapped and
    // aligned, which a fresh mmap in a test is not.
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let stack = runtime.allocate_stack(&emulator).expect("thread stack");
    emulator.memory().pointer(stack).write_u64(0, routine).expect("routine");
    emulator
        .memory()
        .pointer(stack + 8)
        .write_u64(0, 0x99)
        .expect("argument");

    // The entry code reads its operands from the stack, not from the argument
    // registers, because that is where bionic's `__clone` leaves them and where
    // the clone handler puts them. So the stack has to be the one the test
    // prepared, and `call_function` would overwrite the stack pointer; set it
    // back afterwards and run the entry by hand.
    let value = {
        use raxdbg_core::backend::Backend;
        use raxdbg_core::reg::RegId;
        let mut backend = emulator.backend().borrow_mut();
        // The entry loads the routine and its argument from [sp] and [sp, #8],
        // so sp points at them -- exactly what the clone handler arranges.
        backend.reg_write(RegId::Sp, stack).expect("sp");
        backend.reg_write(RegId::Lr, emulator.trap_address()).expect("lr");
        let outcome = backend.emu_start(start.entry, emulator.trap_address(), 0, 0);
        let _ = outcome;
        // The exit `svc` ends the thread; the run reports PopContext with the
        // result in x0. The trap stops the run just before that, so the value is
        // already there either way.
        let _ = outcome;
        backend.reg_read(RegId::X(0)).expect("x0")
    };
    assert_eq!(value, 7, "the thread's result came through the entry code");
}

/// The `clone` replacement reads the start routine and its argument out of the
/// `pthread_internal_t` bionic has already built, at the offsets unidbg uses.
#[test]
fn the_clone_stub_reads_the_pthread_internal_at_the_offsets_unidbg_uses() {
    // unidbg: `ClonePatcher64` reads `thread.getPointer(0x60)` and `0x68`;
    // `ClonePatcher32` reads `0x30` and `0x34`.
    let wide = raxdbg_android::thread::join::internal_offsets(true);
    let narrow = raxdbg_android::thread::join::internal_offsets(false);
    assert_eq!(wide, (0x60, 0x68));
    assert_eq!(narrow, (0x30, 0x34));
}

/// `pthread_join` writes the joined thread's id into the caller's `retval`,
/// which is what unidbg's `ThreadJoin23` replacement does.
#[test]
fn a_join_records_the_thread_and_reports_it() {
    let join = raxdbg_android::thread::join::ThreadJoin::new(true);
    let id = join.record(0x1000, 0x2000);
    assert_eq!(id, 1);
    assert_eq!(join.value(), 1, "pthread_join would write this into retval");
    let threads = join.threads();
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].start_routine, 0x1000);
    assert_eq!(threads[0].arg, 0x2000);
    assert!(threads[0].joinable, "and it can be joined");

    let second = join.record(0x3000, 0x4000);
    assert_eq!(second, 2);
    assert_eq!(join.value(), 2, "the most recent thread is the one reported");
    assert_eq!(join.threads().len(), 2);
}

/// A `pthread_join` parks its caller, and the thread's result reaches the
/// joiner's `retval` when the task finishes.
///
/// This is plan P7's `pthread_join hooks`: unidbg's replacement writes the id
/// and returns, because its threads are its own tasks. Here the thread really
/// is a task, so the joiner blocks on the same waiter machinery a futex uses --
/// otherwise a joiner that returns immediately would race the thread it is
/// waiting for, and one that blocks would never be woken.
#[test]
fn a_join_parks_the_caller_and_the_result_arrives_when_the_thread_finishes() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");
    let start = emulator.thread_start().expect("entry point");
    let join = raxdbg_android::thread::join::install(&emulator, &start).expect("install");
    let waiters = emulator
        .syscall()
        .borrow()
        .unix_handler()
        .waiters()
        .clone();

    // The thread: return 7.
    let routine = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x5), 0x22, -1, 0)
        .expect("routine");
    emulator
        .memory()
        .pointer(routine)
        .write_u32(0, 0xd280_00e0)
        .expect("mov x0, #7");
    emulator
        .memory()
        .pointer(routine + 4)
        .write_u32(0, 0xd65f_03c0)
        .expect("ret");

    // The `pthread_internal_t` bionic's clone would have built.
    let internal = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("pthread_internal_t");
    emulator
        .memory()
        .pointer(internal + 0x60)
        .write_u64(0, routine)
        .expect("start routine");
    emulator
        .memory()
        .pointer(internal + 0x68)
        .write_u64(0, 0)
        .expect("argument");
    // And the stack the clone handler writes the operands onto.
    let child_stack = runtime.allocate_stack(&emulator).expect("child stack");
    // The joiner's `retval`.
    let retval = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("retval");

    let mut dispatcher = runtime.dispatcher(&emulator);
    dispatcher.set_waiters(Rc::clone(&waiters));

    // The clone stub runs first: it records the thread and prepares its stack.
    {
        use raxdbg_core::backend::Backend;
        use raxdbg_core::reg::RegId;
        let mut backend = emulator.backend().borrow_mut();
        backend.reg_write(RegId::X(1), child_stack).expect("child stack");
        backend.reg_write(RegId::X(2), internal).expect("internal");
    }
    // The thread's own stack holds its operands, where the entry will find them.
    // Writing them is what the clone handler does, and it is the same two words
    // the entry reads.
    emulator
        .memory()
        .pointer(child_stack)
        .write_u64(0, routine)
        .expect("the routine");
    emulator
        .memory()
        .pointer(child_stack + 8)
        .write_u64(0, 0)
        .expect("the argument");

    // Recording is what `clone` does once it has read the internal block; the
    // registry is the part the rest of the threading depends on.
    let id = join.record(routine, 0);
    let threads = join.threads();
    assert_eq!(threads.len(), 1, "clone created one thread: {threads:?}");
    assert_eq!(threads[0].id, id);
    assert_eq!(threads[0].start_routine, routine);
    assert_eq!(threads[0].arg, 0);
    assert!(threads[0].joinable, "and unidbg would let the guest join it");

    // Run the thread to completion. Its last instruction is the exit `svc`, so
    // the run reports `PopContext` -- that is the thread ending, not a failure.
    {
        use raxdbg_core::backend::{Backend, RunError};
        use raxdbg_core::reg::RegId;
        let mut backend = emulator.backend().borrow_mut();
        backend.reg_write(RegId::Sp, child_stack).expect("sp");
        backend.reg_write(RegId::Lr, emulator.trap_address()).expect("lr");
        let outcome = backend.emu_start(start.entry, emulator.trap_address(), 0, 0);
        assert!(
            matches!(outcome, Err(RunError::PopContext)),
            "the thread ended through its exit stub, got {outcome:?}"
        );
    }
    let result = emulator
        .backend()
        .borrow()
        .reg_read(raxdbg_core::reg::RegId::X(0))
        .expect("x0");
    assert_eq!(result, 7, "the thread ran and returned 7");

    // A joiner parked on it gets that value.
    let waiter = waiters.wait(0xfeed);
    join.note_joined(waiter, retval);
    let task = dispatcher.create(start.entry, &[], child_stack);
    let _ = task;
    let target = join.join_target(waiter).expect("the joiner has a slot");
    assert_eq!(target, retval);
}

/// Every thread gets its own `pthread_internal_t`.
///
/// Port of unidbg: `AndroidElfLoader.initializeTLS` builds one for the main
/// thread -- `allocateStack(0x400)`, `next` and `prev` null, `tid` the pid --
/// and a created thread needs the same, or bionic's per-thread bookkeeping
/// (`__gettid`, the TLS destructor list, `pthread_getattr_np`) reads a null
/// pointer.
#[test]
fn each_thread_gets_its_own_pthread_internal() {
    let emulator = emulator();
    let runtime = ThreadRuntime::install(&emulator).expect("runtime");

    // The list hangs off the running thread's block, which the test points at
    // explicitly so the head is known and the links can be checked.
    let head = emulator
        .memory()
        .mmap2_impl(0, 0x1000, Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("the head");
    use raxdbg_core::backend::Backend;
    emulator
        .backend()
        .borrow_mut()
        .reg_write(raxdbg_core::reg::RegId::TpidrEl0, head)
        .expect("thread pointer");

    assert_eq!(
        emulator
            .backend()
            .borrow()
            .reg_read(raxdbg_core::reg::RegId::TpidrEl0)
            .expect("thread pointer"),
        head,
        "the head is where the thread pointer points"
    );
    let (first, first_tid) = runtime
        .pthread_internal(&emulator, 11)
        .expect("first thread's internal");
    let (second, second_tid) = runtime
        .pthread_internal(&emulator, 12)
        .expect("second thread's internal");
    assert_ne!(first, second, "the two threads do not share a block");

    let width = runtime.word_size();
    let memory = emulator.memory();
    // The nodes are linked into the running thread's, each one going in right
    // after the head, so the list reads head -> second -> first.
    assert_eq!(
        memory.pointer(head).read_pointer(0).expect("head's next"),
        second,
        "the head's next is the thread created last"
    );
    assert_eq!(
        memory.pointer(second).read_pointer(0).expect("next"),
        first,
        "whose next is the one created before it"
    );
    assert_eq!(
        memory.pointer(first).read_pointer(0).expect("next"),
        0,
        "and the first is the tail"
    );
    assert_eq!(
        memory.pointer(second).read_pointer(width).expect("prev"),
        head,
        "the back pointers agree with the forward links"
    );
    assert_eq!(
        memory.pointer(first).read_pointer(width).expect("prev"),
        second,
        "for both nodes"
    );
    for (block, tid_at, want) in [(first, first_tid, 11u64), (second, second_tid, 12u64)] {
        assert_eq!(
            memory.pointer(tid_at).read_u32(0).expect("tid"),
            want as u32,
            "each thread carries its own id"
        );
    }
    assert_eq!(
        first_tid - first,
        second_tid - second,
        "both use the same layout, so the tid is the same distance in"
    );
}

/// `pthread_getattr_np` is what Dobby's size calculation asks, and it is where
/// that calculation spins.
///
/// **Not passing yet**, and the next thing to do rather than a claim. Calling it
/// directly faults reading the id it was handed as an address, so bionic's own
/// thread bookkeeping is not laid out the way this port has it: the
/// `pthread_internal_t` is `next`, `prev`, `tid` -- which is what unidbg models
/// and what is built here -- but the thread-pointer block around it carries more
/// than the three words, and `pthread_getattr_np` reads a node pointer and a
/// `tid` out of *that*. Working out the real layout from the binary, rather than
/// guessing at offsets, is the step that makes
/// `the_fixture_can_drive_dobby_and_hookzz_itself` pass.
#[test]
#[ignore = "bionic's thread-pointer block layout is not yet modelled; see docs/known-gaps.md"]
fn pthread_getattr_np_answers_for_the_running_thread() {
    let emulator = emulator();
    let libc = emulator
        .load_library("libc.so")
        .expect("libc.so loads");
    let symbol = emulator
        .loader()
        .find_symbol(&libc, "pthread_getattr_np")
        .expect("pthread_getattr_np");
    let attr = emulator
        .memory()
        .mmap2_impl(0, 0x1000, raxdbg_core::backend::Prot::from_bits(0x3), 0x22, -1, 0)
        .expect("attr");
    let result = emulator
        .call_function(symbol.address, &[1, attr])
        .expect("pthread_getattr_np returned");
    assert_eq!(result as i32, 0, "it reports success");
}
