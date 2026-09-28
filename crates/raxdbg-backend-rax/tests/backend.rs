//! Backend acceptance tests (plan P1).
//!
//! Every test drives the public `Backend` contract, so it guards the same
//! surface unidbg's Java tests guard.

mod common;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use common::{a32, a64, arm32_backend, arm64_backend, map_data, map_rw, new_space, CODE, DATA};
use raxdbg_backend_rax::RaxBackend;
use raxdbg_core::backend::{
    Backend, CodeHook, EventMemHook, InterruptHook, MemHookCtx, MemoryFaultKind, Prot, ReadHook,
    RunError, RunOutcome, UnmappedKind, WriteHook, EXCP_SWI,
};
use raxdbg_core::reg::{ARM32_REGS, ARM64_REGS, RegId};

fn run(backend: &mut RaxBackend, count: u64) -> RunOutcome {
    backend
        .emu_start(CODE, 0, 0, count)
        .expect("run should not fail")
}

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

#[test]
fn arm64_register_roundtrip() {
    let mut backend = arm64_backend(&[a64::nop()]);
    for (index, reg) in ARM64_REGS.iter().copied().enumerate() {
        let value = 0x1111_0000_0000_0000u64 | (index as u64 + 1);
        if reg.is_zero() {
            // Writes to the zero registers are discarded.
            backend.reg_write(reg, value).expect("write");
            assert_eq!(backend.reg_read(reg).expect("read"), 0, "{reg}");
            continue;
        }
        let expected = match reg {
            RegId::W(_) | RegId::Wsp => value as u32 as u64,
            RegId::Nzcv => value & 0xf,
            _ => value,
        };
        backend.reg_write(reg, value).expect("write");
        assert_eq!(backend.reg_read(reg).expect("read"), expected, "{reg}");
    }
    for index in 0..32u8 {
        for (reg, mask) in [
            (RegId::Q(index), u128::MAX),
            (RegId::D(index), u128::from(u64::MAX)),
            (RegId::S(index), u128::from(u32::MAX)),
            (RegId::H(index), u128::from(u16::MAX)),
            (RegId::B(index), u128::from(u8::MAX)),
        ] {
            let value = u128::MAX - u128::from(index);
            backend.reg_write_vector(reg, value.to_le_bytes()).expect("write");
            let read = u128::from_le_bytes(backend.reg_read_vector(reg).expect("read"));
            assert_eq!(read, value & mask, "{reg}");
        }
    }
}

#[test]
fn arm64_aliases_track_their_backing_register() {
    let mut backend = arm64_backend(&[a64::nop()]);
    backend.reg_write(RegId::X(30), 0x1234).expect("write x30");
    assert_eq!(backend.reg_read(RegId::Lr).expect("read lr"), 0x1234);
    backend.reg_write(RegId::Lr, 0x5678).expect("write lr");
    assert_eq!(backend.reg_read(RegId::X(30)).expect("read x30"), 0x5678);

    backend.reg_write(RegId::X(29), 0xaaaa).expect("write x29");
    assert_eq!(backend.reg_read(RegId::Fp).expect("read fp"), 0xaaaa);

    backend.reg_write(RegId::X(16), 0xbeef).expect("write x16");
    assert_eq!(backend.reg_read(RegId::Ip).expect("read ip"), 0xbeef);

    backend.reg_write(RegId::W(3), 0xffff_ffff).expect("write w3");
    assert_eq!(backend.reg_read(RegId::X(3)).expect("read x3"), 0xffff_ffff);
}

#[test]
fn arm64_rejects_the_other_isas_registers() {
    let backend = arm64_backend(&[a64::nop()]);
    for reg in [RegId::R(0), RegId::Cpsr, RegId::Fpexc, RegId::C13C0_3] {
        assert!(backend.reg_read(reg).is_err(), "{reg} should be rejected");
    }
}

#[test]
fn arm32_register_roundtrip() {
    let mut backend = arm32_backend(&a32::words(&[a32::mov_r0(1)]));
    for (index, reg) in ARM32_REGS.iter().copied().enumerate() {
        if reg == RegId::Cpsr || reg == RegId::Pc {
            // CPSR's IT-state bits are split across the word, so an arbitrary
            // value does not survive the round trip, and a PC write drops bit 0
            // (`BXWritePC` semantics). Both have dedicated tests.
            continue;
        }
        let value = 0x2222_0000u64 | (index as u64 + 1);
        backend.reg_write(reg, value).expect("write");
        assert_eq!(backend.reg_read(reg).expect("read"), value as u32 as u64, "{reg}");
    }
    for index in 0..16u8 {
        let reg = RegId::D(index);
        let value = 0x0102_0304_0506_0708u64 + u64::from(index);
        backend.reg_write(reg, value).expect("write");
        assert_eq!(backend.reg_read(reg).expect("read"), value, "{reg}");
    }
}

#[test]
fn arm32_cpsr_roundtrip_preserves_flags_mode_and_state() {
    let mut backend = arm32_backend(&a32::words(&[a32::mov_r0(1)]));
    // NZCV = 1010, I and F set, T set, mode = User (0x10).
    let cpsr = (0b1010u32 << 28) | (1 << 7) | (1 << 6) | (1 << 5) | 0x10;
    backend.reg_write(RegId::Cpsr, u64::from(cpsr)).expect("write");
    assert_eq!(backend.reg_read(RegId::Cpsr).expect("read"), u64::from(cpsr));
    assert!(backend.arm32().unwrap().thumb());
}

#[test]
fn arm32_pc_write_selects_the_instruction_set() {
    let mut backend = arm32_backend(&a32::halfwords(&[a32::t16_nop()]));
    backend.reg_write(RegId::Pc, common::CODE | 1).expect("write");
    assert!(backend.arm32().unwrap().thumb(), "bit 0 selects T32");
    assert_eq!(backend.reg_read(RegId::Pc).expect("read"), common::CODE);
    backend.reg_write(RegId::Pc, common::CODE).expect("write");
    assert!(!backend.arm32().unwrap().thumb(), "an even PC selects A32");
}

#[test]
fn arm32_aliases_track_their_backing_register() {
    let mut backend = arm32_backend(&a32::words(&[a32::mov_r0(1)]));
    backend.reg_write(RegId::R(14), 0x1111).expect("write r14");
    assert_eq!(backend.reg_read(RegId::Lr).expect("read lr"), 0x1111);
    backend.reg_write(RegId::R(13), 0x2222).expect("write r13");
    assert_eq!(backend.reg_read(RegId::Sp).expect("read sp"), 0x2222);
    backend.reg_write(RegId::R(12), 0x3333).expect("write r12");
    assert_eq!(backend.reg_read(RegId::Ip).expect("read ip"), 0x3333);
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

#[test]
fn count_stops_after_n_instructions() {
    let mut backend = arm64_backend(&[a64::add_x0_1(); 8]);
    let outcome = run(&mut backend, 3);
    assert_eq!(outcome, RunOutcome::Count);
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 3);
}

#[test]
fn until_stops_before_the_target_instruction() {
    let mut backend = arm64_backend(&[a64::add_x0_1(); 8]);
    let outcome = backend.emu_start(CODE, CODE + 8, 0, 0).expect("run");
    assert_eq!(outcome, RunOutcome::Until);
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 2);
    assert_eq!(backend.reg_read(RegId::Pc).unwrap(), CODE + 8);
}

#[test]
fn timeout_ends_a_run_that_never_reaches_until() {
    // `b .` branches to itself, so the run never leaves the mapped page.
    let mut backend = arm64_backend(&[0x1400_0000]);
    // One microsecond of host time cannot fit a million iterations of the
    // budget, so the deadline is what ends the run.
    let outcome = backend.emu_start(CODE, 0, 1, 0).expect("run");
    assert_eq!(outcome, RunOutcome::Timeout);
}

#[test]
fn svc_reaches_the_interrupt_hook() {
    struct SvcHook {
        seen: Rc<Cell<Option<i32>>>,
    }
    impl InterruptHook for SvcHook {
        fn hook(&mut self, backend: &mut dyn Backend, intno: i32, swi: i32) {
            assert_eq!(intno, EXCP_SWI);
            self.seen.set(Some(swi));
            backend.reg_write(RegId::X(0), 0x99).expect("write x0");
        }
    }

    let seen = Rc::new(Cell::new(None));
    let mut backend = arm64_backend(&[a64::svc(7), a64::add_x0_1()]);
    backend.hook_add_interrupt(Box::new(SvcHook { seen: seen.clone() }));
    let outcome = run(&mut backend, 2);

    assert_eq!(outcome, RunOutcome::Count);
    assert_eq!(seen.get(), Some(7));
    // The hook's write survives, and the SVC's `ret`-free stub continues at
    // the next instruction.
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 0x9a);
}

#[test]
fn unhandled_svc_is_an_error() {
    let mut backend = arm64_backend(&[a64::svc(1)]);
    match backend.emu_start(CODE, 0, 0, 0) {
        Err(RunError::Backend(error)) => {
            assert!(error.to_string().contains("unhandled SVC"), "{error}");
        }
        other => panic!("expected an unhandled-SVC error, got {other:?}"),
    }
}

#[test]
fn unmapped_fetch_reports_the_faulting_address() {
    let mut backend = arm64_backend(&[a64::nop()]);
    match backend.emu_start(0x9000_0000, 0, 0, 1) {
        Err(RunError::UnmappedMemory { addr, pc, .. }) => {
            assert_eq!(addr, 0x9000_0000);
            assert_eq!(pc, 0x9000_0000);
        }
        other => panic!("expected an unmapped-memory error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

#[test]
fn code_hook_fires_only_inside_its_range() {
    struct Recorder {
        hits: Rc<RefCell<Vec<u64>>>,
    }
    impl CodeHook for Recorder {
        fn hook(&mut self, _backend: &mut dyn Backend, address: u64, size: u32) {
            assert_eq!(size, 4);
            self.hits.borrow_mut().push(address);
        }
    }

    let hits = Rc::new(RefCell::new(Vec::new()));
    let mut backend = arm64_backend(&[a64::add_x0_1(); 5]);
    backend.hook_add_code(
        Box::new(Recorder { hits: hits.clone() }),
        CODE + 4,
        CODE + 8,
    );
    run(&mut backend, 5);
    assert_eq!(*hits.borrow(), vec![CODE + 4, CODE + 8]);
}

#[test]
fn code_hook_can_move_the_program_counter() {
    struct Skipper {
        done: bool,
    }
    impl CodeHook for Skipper {
        fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
            if !self.done {
                self.done = true;
                // Skip the instruction at `address`: jump to the one after it.
                backend.reg_write(RegId::Pc, address + 4).expect("write pc");
            }
        }
    }

    let mut backend = arm64_backend(&[a64::add_x0_1(), a64::add_x0_1(), a64::add_x0_1(), a64::nop()]);
    backend.hook_add_code(Box::new(Skipper { done: false }), CODE, CODE);
    run(&mut backend, 3);
    // The hook replaced the first instruction: two adds and a nop retired.
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 2);
}

#[test]
fn code_hook_can_delete_itself_while_running() {
    struct Once {
        id: Rc<Cell<Option<u64>>>,
        hits: Rc<Cell<u32>>,
    }
    impl CodeHook for Once {
        fn hook(&mut self, backend: &mut dyn Backend, _address: u64, _size: u32) {
            self.hits.set(self.hits.get() + 1);
            if let Some(id) = self.id.take() {
                // A one-shot breakpoint: removing a hook from inside its own
                // callback is deferred to the end of the dispatch.
                backend.hook_del(id);
            }
        }
    }

    let hits = Rc::new(Cell::new(0));
    let id_slot = Rc::new(Cell::new(None));
    let mut backend = arm64_backend(&[a64::add_x0_1(); 4]);
    let id = backend.hook_add_code(
        Box::new(Once {
            id: id_slot.clone(),
            hits: hits.clone(),
        }),
        CODE,
        CODE + 0x100,
    );
    id_slot.set(Some(id));
    run(&mut backend, 4);
    assert_eq!(hits.get(), 1, "the hook removed itself after its first hit");
}

#[test]
fn block_hook_fires_at_basic_block_entries() {
    struct Recorder {
        hits: Rc<RefCell<Vec<u64>>>,
    }
    impl raxdbg_core::backend::BlockHook for Recorder {
        fn hook_block(&mut self, _backend: &mut dyn Backend, address: u64, _size: u32) {
            self.hits.borrow_mut().push(address);
        }
    }

    // `b #8` skips one instruction, so the entry after it is a new block.
    const B_8: u32 = 0x1400_0002;
    let hits = Rc::new(RefCell::new(Vec::new()));
    let mut backend = arm64_backend(&[B_8, a64::add_x0_1(), a64::add_x0_1(), a64::nop(), a64::nop()]);
    backend.hook_add_block(
        Box::new(Recorder { hits: hits.clone() }),
        CODE,
        CODE + 0x100,
    );
    run(&mut backend, 4);
    let hits = hits.borrow();
    assert_eq!(hits[0], CODE, "the entry point is a block entry");
    assert_eq!(hits[1], CODE + 8, "the branch target is a block entry");
}

#[test]
fn read_hook_sees_loads_and_can_rewrite_memory() {
    struct Rewriter {
        seen: Arc<Mutex<Vec<(u64, usize)>>>,
    }
    impl ReadHook for Rewriter {
        fn hook(&mut self, ctx: &mut MemHookCtx<'_>, address: u64, size: usize) {
            self.seen.lock().unwrap().push((address, size));
            if address == DATA {
                // unidbg's ReadHook has no value parameter either: the way to
                // change what the guest sees is to write memory.
                ctx.write(DATA, &0x77u64.to_le_bytes()).expect("write");
            }
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut backend = arm64_backend(&[a64::ldr_x1_x0(), a64::ldr_x2_x0(), a64::nop()]);
    map_data(backend.address_space());
    backend
        .mem_write(DATA, &0x11u64.to_le_bytes())
        .expect("seed");
    backend.reg_write(RegId::X(0), DATA).expect("write x0");
    backend.hook_add_read(Box::new(Rewriter { seen: seen.clone() }), DATA, DATA);
    run(&mut backend, 2);

    assert_eq!(&*seen.lock().unwrap(), &[(DATA, 8), (DATA, 8)]);
    assert_eq!(backend.reg_read(RegId::X(1)).unwrap(), 0x11);
    assert_eq!(
        backend.reg_read(RegId::X(2)).unwrap(),
        0x77,
        "the second load sees what the hook wrote"
    );
}

#[test]
fn write_hook_observes_the_stored_value() {
    struct Recorder {
        seen: Arc<Mutex<Vec<(u64, usize, u64)>>>,
    }
    impl WriteHook for Recorder {
        fn hook(&mut self, _ctx: &mut MemHookCtx<'_>, address: u64, size: usize, value: u64) {
            self.seen.lock().unwrap().push((address, size, value));
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut backend = arm64_backend(&[a64::str_x1_x0(), a64::nop()]);
    map_data(backend.address_space());
    backend.reg_write(RegId::X(0), DATA).expect("write x0");
    backend.reg_write(RegId::X(1), 0xdead_beef).expect("write x1");
    backend.hook_add_write(Box::new(Recorder { seen: seen.clone() }), DATA, DATA);
    run(&mut backend, 1);

    assert_eq!(&*seen.lock().unwrap(), &[(DATA, 8, 0xdead_beef)]);
    assert_eq!(
        backend.mem_read(DATA, 8).unwrap(),
        0xdead_beefu64.to_le_bytes().to_vec()
    );
}

#[test]
fn event_mem_hook_that_maps_the_page_makes_the_loop_retry() {
    struct Mapper {
        mapped: bool,
    }
    impl EventMemHook for Mapper {
        fn hook(
            &mut self,
            backend: &mut dyn Backend,
            address: u64,
            _size: usize,
            _value: u64,
            kind: UnmappedKind,
        ) -> bool {
            assert_eq!(kind, UnmappedKind::Fetch);
            assert_eq!(address, CODE);
            if self.mapped {
                return false;
            }
            self.mapped = true;
            backend
                .mem_map(CODE, 0x1000, Prot::READ.union(Prot::WRITE).union(Prot::EXEC))
                .expect("map");
            backend
                .mem_write(CODE, &a64::mov_x0(0x2a).to_le_bytes())
                .expect("write code");
            true
        }
    }

    let space = new_space();
    let mut backend = RaxBackend::new_arm64(space);
    backend.hook_add_event_mem(Box::new(Mapper { mapped: false }), UnmappedKind::Fetch);
    let outcome = backend.emu_start(CODE, 0, 0, 1).expect("run");
    assert_eq!(outcome, RunOutcome::Count);
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 0x2a);
}

#[test]
fn event_mem_hook_that_declines_reports_unmapped_memory() {
    struct Decliner;
    impl EventMemHook for Decliner {
        fn hook(
            &mut self,
            _backend: &mut dyn Backend,
            _address: u64,
            _size: usize,
            _value: u64,
            _kind: UnmappedKind,
        ) -> bool {
            false
        }
    }

    let mut backend = arm64_backend(&[a64::nop()]);
    backend.hook_add_event_mem(Box::new(Decliner), UnmappedKind::Fetch);
    match backend.emu_start(0x9000_0000, 0, 0, 1) {
        Err(RunError::UnmappedMemory { addr, .. }) => assert_eq!(addr, 0x9000_0000),
        other => panic!("expected an unmapped-memory error, got {other:?}"),
    }
}

#[test]
fn emu_stop_from_a_hook_ends_the_run() {
    struct Stopper {
        at: u64,
    }
    impl CodeHook for Stopper {
        fn hook(&mut self, backend: &mut dyn Backend, address: u64, _size: u32) {
            if address == self.at {
                backend.emu_stop();
            }
        }
    }

    let mut backend = arm64_backend(&[a64::add_x0_1(); 8]);
    backend.hook_add_code(Box::new(Stopper { at: CODE + 4 }), CODE, CODE + 0x100);
    let outcome = backend.emu_start(CODE, 0, 0, 0).expect("run");
    assert_eq!(outcome, RunOutcome::Stopped);
    assert_eq!(backend.reg_read(RegId::X(0)).unwrap(), 2);
}

#[test]
fn hook_del_stops_dispatch() {
    struct Recorder {
        hits: Rc<Cell<u32>>,
    }
    impl CodeHook for Recorder {
        fn hook(&mut self, _backend: &mut dyn Backend, _address: u64, _size: u32) {
            self.hits.set(self.hits.get() + 1);
        }
    }

    let hits = Rc::new(Cell::new(0));
    let mut backend = arm64_backend(&[a64::add_x0_1(); 4]);
    let id = backend.hook_add_code(Box::new(Recorder { hits: hits.clone() }), CODE, CODE + 0x100);
    run(&mut backend, 1);
    assert_eq!(hits.get(), 1);
    backend.hook_del(id);
    run(&mut backend, 2);
    assert_eq!(hits.get(), 1, "the hook was removed");
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

#[test]
fn context_roundtrip_restores_the_whole_register_file() {
    let mut backend = arm64_backend(&[a64::add_x0_1(); 32]);
    backend.reg_write(RegId::X(1), 0x1111).expect("write");
    backend.reg_write(RegId::X(30), 0x2222).expect("write");
    backend.reg_write(RegId::TpidrEl0, 0x3333).expect("write");
    backend.reg_write_vector(RegId::Q(5), [7u8; 16]).expect("write");
    run(&mut backend, 20);

    let snapshot: Vec<u64> = ARM64_REGS
        .iter()
        .filter(|reg| !reg.is_vector())
        .map(|reg| backend.reg_read(*reg).expect("read"))
        .collect();
    let vectors: Vec<[u8; 16]> = (0..32)
        .map(|index| backend.reg_read_vector(RegId::Q(index)).expect("read"))
        .collect();

    let id = backend.context_save();
    backend.reg_write(RegId::X(0), 0xdead).expect("write");
    backend.reg_write(RegId::Pc, 0x9000).expect("write");
    backend
        .reg_write_vector(RegId::Q(5), [0u8; 16])
        .expect("write");

    backend.context_restore(id);
    for (reg, expected) in ARM64_REGS.iter().filter(|r| !r.is_vector()).zip(snapshot) {
        assert_eq!(backend.reg_read(*reg).expect("read"), expected, "{reg}");
    }
    for (index, expected) in vectors.into_iter().enumerate() {
        assert_eq!(
            backend.reg_read_vector(RegId::Q(index as u8)).expect("read"),
            expected,
            "q{index}"
        );
    }
}

#[test]
fn context_free_releases_the_slot() {
    let mut backend = arm64_backend(&[a64::nop()]);
    let first = backend.context_save();
    let second = backend.context_save();
    assert_ne!(first, second);
    backend.context_free(first);
    assert_eq!(backend.context_save(), first, "the freed slot is reused");
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

#[test]
fn mem_map_protect_and_unmap_round_trip() {
    let mut backend = arm64_backend(&[a64::nop()]);
    let base = 0x4000_0000u64;
    map_rw(&mut backend, base, 0x2000);
    backend.mem_write(base, b"hello").expect("write");
    assert_eq!(&backend.mem_read(base, 5).unwrap(), b"hello");

    backend
        .mem_protect(base, 0x1000, Prot::READ)
        .expect("protect");
    // A host write still reaches the mapping: unidbg writes guest memory
    // through unicorn's host API, which is how the ELF loader fills segments it
    // mapped `READ | EXEC`. The guest's own stores are what the protection
    // stops, which the next test covers.
    backend.mem_write(base, b"x").expect("host write");

    backend.mem_unmap(base, 0x2000).expect("unmap");
    match backend.mem_read(base, 1) {
        Err(raxdbg_core::backend::BackendError::Memory(fault)) => {
            assert_eq!(fault.kind, MemoryFaultKind::Unmapped);
        }
        other => panic!("expected an unmapped fault, got {other:?}"),
    }
}

#[test]
fn a_guest_store_to_a_read_only_page_faults() {
    let base = 0x4000_0000u64;
    let mut backend = arm64_backend(&[a64::str_x1_x0()]);
    map_rw(&mut backend, base, 0x1000);
    backend
        .mem_protect(base, 0x1000, Prot::READ)
        .expect("protect");
    backend.reg_write(RegId::X(0), base).expect("x0");
    backend.reg_write(RegId::X(1), 0x1234).expect("x1");

    match backend.emu_start(CODE, 0, 0, 1) {
        Err(RunError::UnmappedMemory { addr, .. }) => assert_eq!(addr, base),
        other => panic!("expected the store to fault, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// AArch32
// ---------------------------------------------------------------------------

#[test]
fn arm32_runs_arm_state_code() {
    let mut backend = arm32_backend(&a32::words(&[a32::mov_r0(0x2a), a32::add_r0_1(), a32::bx_lr()]));
    let outcome = run(&mut backend, 2);
    assert_eq!(outcome, RunOutcome::Count);
    assert_eq!(backend.reg_read(RegId::R(0)).unwrap(), 0x2b);
}

#[test]
fn arm32_runs_thumb_code() {
    let mut backend = arm32_backend(&a32::halfwords(&[a32::t16_movs_r0(0x2a), a32::t16_adds_r0_1()]));
    // Enter Thumb state: the PC's bit 0 selects T32.
    backend.reg_write(RegId::Cpsr, 0x10 | (1 << 5)).expect("write cpsr");
    backend.emu_start(CODE | 1, 0, 0, 2).expect("run");
    assert_eq!(backend.reg_read(RegId::R(0)).unwrap(), 0x2b);
    assert!(backend.arm32().unwrap().thumb());
}

#[test]
fn arm32_until_and_count_work() {
    let mut backend = arm32_backend(&a32::words(&[a32::add_r0_1(); 8]));
    assert_eq!(backend.emu_start(CODE, CODE + 8, 0, 0).unwrap(), RunOutcome::Until);
    assert_eq!(backend.reg_read(RegId::R(0)).unwrap(), 2);

    let mut backend = arm32_backend(&a32::words(&[a32::add_r0_1(); 8]));
    assert_eq!(backend.emu_start(CODE, 0, 0, 5).unwrap(), RunOutcome::Count);
    assert_eq!(backend.reg_read(RegId::R(0)).unwrap(), 5);
}

#[test]
fn arm32_svc_reaches_the_interrupt_hook() {
    struct SvcHook {
        seen: Rc<Cell<Option<i32>>>,
    }
    impl InterruptHook for SvcHook {
        fn hook(&mut self, backend: &mut dyn Backend, intno: i32, swi: i32) {
            assert_eq!(intno, EXCP_SWI);
            self.seen.set(Some(swi));
            backend.reg_write(RegId::R(0), 0x99).expect("write r0");
        }
    }

    let seen = Rc::new(Cell::new(None));
    let mut backend = arm32_backend(&a32::words(&[a32::svc0(), a32::add_r0_1()]));
    backend.hook_add_interrupt(Box::new(SvcHook { seen: seen.clone() }));
    run(&mut backend, 2);
    assert_eq!(seen.get(), Some(0));
    assert_eq!(backend.reg_read(RegId::R(0)).unwrap(), 0x9a);
}

#[test]
fn arm32_context_roundtrip() {
    let mut backend = arm32_backend(&a32::words(&[a32::add_r0_1(); 16]));
    backend.reg_write(RegId::Cpsr, 0x6000_0010).expect("write cpsr");
    backend.reg_write(RegId::D(3), 0x0123_4567_89ab_cdef).expect("write d3");
    run(&mut backend, 8);

    let snapshot: Vec<u64> = ARM32_REGS
        .iter()
        .map(|reg| backend.reg_read(*reg).expect("read"))
        .collect();
    let d3 = backend.reg_read(RegId::D(3)).expect("read d3");

    let id = backend.context_save();
    backend.reg_write(RegId::R(0), 0).expect("write");
    backend.reg_write(RegId::Cpsr, 0).expect("write");
    backend.reg_write(RegId::D(3), 0).expect("write");
    backend.context_restore(id);

    for (reg, expected) in ARM32_REGS.iter().zip(snapshot) {
        assert_eq!(backend.reg_read(*reg).expect("read"), expected, "{reg}");
    }
    assert_eq!(backend.reg_read(RegId::D(3)).expect("read"), d3);
}

#[test]
fn arm32_unmapped_fetch_reports_the_faulting_address() {
    let mut backend = arm32_backend(&a32::words(&[a32::bx_lr()]));
    match backend.emu_start(0x9000_0000, 0, 0, 1) {
        Err(RunError::UnmappedMemory { addr, .. }) => assert_eq!(addr, 0x9000_0000),
        other => panic!("expected an unmapped-memory error, got {other:?}"),
    }
}

#[test]
fn arm32_code_hook_fires() {
    struct Recorder {
        hits: Rc<Cell<u32>>,
    }
    impl CodeHook for Recorder {
        fn hook(&mut self, _backend: &mut dyn Backend, _address: u64, _size: u32) {
            self.hits.set(self.hits.get() + 1);
        }
    }

    let hits = Rc::new(Cell::new(0));
    let mut backend = arm32_backend(&a32::words(&[a32::add_r0_1(); 4]));
    backend.hook_add_code(Box::new(Recorder { hits: hits.clone() }), CODE, CODE + 0x100);
    run(&mut backend, 4);
    assert_eq!(hits.get(), 4);
}

#[test]
fn arm32_memory_bridge_dispatches_hooks() {
    struct Recorder {
        seen: Arc<Mutex<u32>>,
    }
    impl WriteHook for Recorder {
        fn hook(&mut self, _ctx: &mut MemHookCtx<'_>, _address: u64, _size: usize, _value: u64) {
            *self.seen.lock().unwrap() += 1;
        }
    }

    // `str r1, [r0]` in ARM state.
    const STR_R1_R0: u32 = 0xe580_1000;
    let seen = Arc::new(Mutex::new(0));
    let mut backend = arm32_backend(&a32::words(&[STR_R1_R0]));
    backend
        .mem_map(DATA, 0x1000, Prot::READ.union(Prot::WRITE))
        .expect("map data");
    backend.reg_write(RegId::R(0), DATA).expect("write r0");
    backend.reg_write(RegId::R(1), 0x1234_5678).expect("write r1");
    backend.hook_add_write(Box::new(Recorder { seen: seen.clone() }), DATA, DATA);
    run(&mut backend, 1);
    assert_eq!(*seen.lock().unwrap(), 1);
    assert_eq!(
        backend.mem_read(DATA, 4).unwrap(),
        0x1234_5678u32.to_le_bytes().to_vec()
    );
}
