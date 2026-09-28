//! Debugger core tests (plan P11).
//!
//! Stand-in backend pattern (mirrors `tests/memory.rs`); the production
//! `BreakerImpl`, `TraceCode`, `TraceMemory` are unchanged.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use raxdbg_core::backend::{
    Backend, BackendError, BlockHook, CodeHook, ContextId, EventMemHook, GuestMemoryAccess, HookId,
    InterruptHook, MemHookCtx, MemoryFault, MemoryFaultKind, Prot, ReadHook, RunError, RunOutcome,
    UnmappedKind, WriteHook,
};
use raxdbg_core::debug::{
    BreakControl, Breaker, BreakerImpl, CodeHistory, Disassembler, HistoryEntry, MemTraceEvent,
    NoopDisassembler, TraceCode, TraceMemory,
};
use raxdbg_core::memory::PAGE_SIZE;
use raxdbg_core::reg::RegId;

// ---------------------------------------------------------------------------
// Backend stand-in
// ---------------------------------------------------------------------------

/// A backend that records hook registrations and lets the test fire them.
///
/// `pending_deletions` tracks hook ids the production code asked us to remove
/// during the most recent `fire_*` call. `fire_*` consults this set to decide
/// whether to leave the rec in the map (the hook removed itself) or
/// re-insert it so the next call can fire it again.
#[derive(Default)]
struct TestBackend {
    regions: BTreeMap<u64, Vec<u8>>,
    pc: u64,
    sp: u64,
    emu_stop_count: u32,

    pending_deletions: RefCell<Vec<HookId>>,

    code_hooks: BTreeMap<HookId, CodeHookRec>,
    read_hooks: BTreeMap<HookId, ReadHookRec>,
    write_hooks: BTreeMap<HookId, WriteHookRec>,

    next_id: HookId,
}

struct CodeHookRec {
    begin: u64,
    end: u64,
    #[allow(dead_code)]
    callback: Box<dyn CodeHook>,
}

struct ReadHookRec {
    #[allow(dead_code)]
    begin: u64,
    #[allow(dead_code)]
    end: u64,
    callback: Box<dyn ReadHook + Send>,
}

struct WriteHookRec {
    #[allow(dead_code)]
    begin: u64,
    #[allow(dead_code)]
    end: u64,
    callback: Box<dyn WriteHook + Send>,
}

impl TestBackend {
    fn new() -> Self {
        Self {
            next_id: 1,
            ..Self::default()
        }
    }

    fn region_at(&self, addr: u64) -> Option<(u64, &[u8])> {
        self.regions
            .iter()
            .find(|(base, region)| addr >= **base && addr < **base + region.len() as u64)
            .map(|(base, region)| (*base, region.as_slice()))
    }

    fn fire_code(&mut self, hook_id: HookId, address: u64, size: u32) {
        self.pending_deletions.borrow_mut().clear();
        let Some(mut rec) = self.code_hooks.remove(&hook_id) else {
            return;
        };
        rec.callback.hook(self, address, size);
        let was_deleted = self
            .pending_deletions
            .borrow()
            .contains(&hook_id);
        self.pending_deletions.borrow_mut().clear();
        if !was_deleted {
            self.code_hooks.insert(hook_id, rec);
        }
    }

    fn fire_read(&mut self, hook_id: HookId, pc: u64, address: u64, size: usize) {
        self.pending_deletions.borrow_mut().clear();
        let Some(mut rec) = self.read_hooks.remove(&hook_id) else {
            return;
        };
        let stop = fresh_stop();
        let access = NoMemory;
        let mut ctx = MemHookCtx::new(pc, &access, &stop);
        rec.callback.hook(&mut ctx, address, size);
        let was_deleted = self.pending_deletions.borrow().contains(&hook_id);
        self.pending_deletions.borrow_mut().clear();
        if !was_deleted {
            self.read_hooks.insert(hook_id, rec);
        }
    }

    fn fire_write(&mut self, hook_id: HookId, pc: u64, address: u64, size: usize, value: u64) {
        self.pending_deletions.borrow_mut().clear();
        let Some(mut rec) = self.write_hooks.remove(&hook_id) else {
            return;
        };
        let stop = fresh_stop();
        let access = NoMemory;
        let mut ctx = MemHookCtx::new(pc, &access, &stop);
        rec.callback.hook(&mut ctx, address, size, value);
        let was_deleted = self.pending_deletions.borrow().contains(&hook_id);
        self.pending_deletions.borrow_mut().clear();
        if !was_deleted {
            self.write_hooks.insert(hook_id, rec);
        }
    }
}

fn fresh_stop() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// `GuestMemoryAccess` that always reports unmapped — matches the way
/// unidbg's `TraceMemoryHook` handles a failed read by recording `value = 0`.
struct NoMemory;

impl GuestMemoryAccess for NoMemory {
    fn read(&self, _addr: u64, _buf: &mut [u8]) -> Result<(), MemoryFault> {
        Err(MemoryFault {
            addr: 0,
            size: 0,
            kind: MemoryFaultKind::Unmapped,
        })
    }
    fn write(&self, _addr: u64, _data: &[u8]) -> Result<(), MemoryFault> {
        Err(MemoryFault {
            addr: 0,
            size: 0,
            kind: MemoryFaultKind::Unmapped,
        })
    }
}

impl Backend for TestBackend {
    fn on_initialize(&mut self) {}
    fn switch_user_mode(&mut self) {}
    fn enable_vfp(&mut self) {}

    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError> {
        match reg {
            RegId::Pc => Ok(self.pc),
            RegId::Sp => Ok(self.sp),
            RegId::Lr | RegId::Fp => Ok(0),
            RegId::X(n) if n <= 2 => Ok(0),
            RegId::R(n) if n <= 2 => Ok(0),
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match reg {
            RegId::Pc => {
                self.pc = value;
                Ok(())
            }
            RegId::Sp => {
                self.sp = value;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }

    fn reg_write_vector(&mut self, _reg: RegId, _v: [u8; 16]) -> Result<(), BackendError> {
        Ok(())
    }

    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError> {
        let mut out = Vec::with_capacity(size);
        for index in 0..size {
            let address = addr + index as u64;
            let Some((base, region)) = self.region_at(address) else {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                }));
            };
            out.push(region[(address - base) as usize]);
        }
        Ok(out)
    }

    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError> {
        for (index, byte) in bytes.iter().enumerate() {
            let address = addr + index as u64;
            let Some((base, _region)) = self.region_at(address) else {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                }));
            };
            self.regions.get_mut(&base).unwrap()[(address - base) as usize] = *byte;
        }
        Ok(())
    }

    fn mem_map(&mut self, addr: u64, size: u64, _perms: Prot) -> Result<(), BackendError> {
        if addr % PAGE_SIZE != 0 || size == 0 {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "misaligned or empty".into(),
            });
        }
        if self
            .regions
            .iter()
            .any(|(base, region)| addr < base + region.len() as u64 && addr + size > *base)
        {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "overlaps an existing mapping".into(),
            });
        }
        self.regions.insert(addr, vec![0u8; size as usize]);
        Ok(())
    }

    fn mem_protect(&mut self, _addr: u64, _size: u64, _perms: Prot) -> Result<(), BackendError> {
        Ok(())
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.regions
            .retain(|base, region| !(addr < base + region.len() as u64 && addr + size > *base));
        Ok(())
    }

    fn hook_add_code(&mut self, cb: Box<dyn CodeHook>, begin: u64, end: u64) -> HookId {
        let id = self.next_id;
        self.next_id += 1;
        self.code_hooks.insert(
            id,
            CodeHookRec {
                begin,
                end,
                callback: cb,
            },
        );
        id
    }
    fn hook_add_block(&mut self, _cb: Box<dyn BlockHook>, _begin: u64, _end: u64) -> HookId {
        0
    }
    fn hook_add_read(&mut self, cb: Box<dyn ReadHook + Send>, begin: u64, end: u64) -> HookId {
        let id = self.next_id;
        self.next_id += 1;
        self.read_hooks.insert(
            id,
            ReadHookRec {
                begin,
                end,
                callback: cb,
            },
        );
        id
    }
    fn hook_add_write(&mut self, cb: Box<dyn WriteHook + Send>, begin: u64, end: u64) -> HookId {
        let id = self.next_id;
        self.next_id += 1;
        self.write_hooks.insert(
            id,
            WriteHookRec {
                begin,
                end,
                callback: cb,
            },
        );
        id
    }
    fn hook_add_event_mem(&mut self, _cb: Box<dyn EventMemHook>, _kind: UnmappedKind) -> HookId {
        0
    }
    fn hook_add_interrupt(&mut self, _cb: Box<dyn InterruptHook>) -> HookId {
        0
    }
    fn hook_del(&mut self, id: HookId) {
        self.pending_deletions.borrow_mut().push(id);
        self.code_hooks.remove(&id);
        self.read_hooks.remove(&id);
        self.write_hooks.remove(&id);
    }

    fn emu_start(
        &mut self,
        _begin: u64,
        _until: u64,
        _timeout_us: u64,
        _count: u64,
    ) -> Result<RunOutcome, RunError> {
        Ok(RunOutcome::Stopped)
    }
    fn emu_stop(&mut self) {
        self.emu_stop_count += 1;
    }
    fn set_pending_error(&mut self, _error: RunError) {}
    fn take_pending_error(&mut self) -> Option<RunError> {
        None
    }
    fn is_running(&self) -> bool {
        false
    }
    fn context_save(&mut self) -> ContextId {
        0
    }
    fn context_restore(&mut self, _id: ContextId) {}
    fn context_free(&mut self, _id: ContextId) {}
    fn page_size(&self) -> usize {
        PAGE_SIZE as usize
    }
    fn remove_jit_code_cache(&mut self, _begin: u64, _end: u64) {}
}

// ---------------------------------------------------------------------------
// BreakPoint / BreakerImpl
// ---------------------------------------------------------------------------

fn harness() -> (
    Rc<RefCell<dyn Backend>>,
    Rc<RefCell<TestBackend>>,
    Rc<RefCell<BreakerImpl>>,
) {
    let backend = Rc::new(RefCell::new(TestBackend::new()));
    let backend_dyn: Rc<RefCell<dyn Backend>> = backend.clone();
    let breaker = Rc::new(RefCell::new(BreakerImpl::new(backend_dyn.clone())));
    (backend_dyn, backend, breaker)
}

#[test]
fn breakpoint_fires_and_is_removed_by_remove_break_point() {
    let (backend_dyn, backend, breaker) = harness();
    let bp = breaker.borrow_mut().add_break_point(0x1000, None);
    assert_eq!(bp.address(), 0x1000);

    let hook_id = {
        let b = backend.borrow();
        assert_eq!(b.code_hooks.len(), 1);
        let rec = b.code_hooks.values().next().unwrap();
        assert_eq!(rec.begin, 0x1000);
        assert_eq!(rec.end, 0x1000);
        *b.code_hooks.keys().next().unwrap()
    };

    backend.borrow_mut().fire_code(hook_id, 0x1000, 4);
    assert_eq!(backend.borrow().emu_stop_count, 1);

    let removed = breaker.borrow_mut().remove_break_point(0x1000);
    assert!(removed);
    assert!(backend.borrow().code_hooks.is_empty());

    assert!(!breaker.borrow_mut().remove_break_point(0x9999));
    let _ = backend_dyn;
}

#[test]
fn temporary_breakpoint_removes_itself_on_first_hit() {
    let (_backend_dyn, backend, breaker) = harness();
    let bp = breaker.borrow_mut().add_break_point(0x2000, None);
    bp.set_temporary(true);

    let hook_id = *backend.borrow().code_hooks.keys().next().unwrap();

    backend.borrow_mut().fire_code(hook_id, 0x2000, 4);
    assert_eq!(backend.borrow().emu_stop_count, 1);
    assert!(backend.borrow().code_hooks.is_empty(), "temporary hook removed");
    assert!(bp.temporary(), "handle still reports the temporary flag");
}

#[test]
fn breakpoint_callback_can_skip_the_hit() {
    let (_backend_dyn, backend, breaker) = harness();
    let callback: Box<dyn FnMut(u64) -> BreakControl> = Box::new(|_| BreakControl::Continue);
    let _bp = breaker
        .borrow_mut()
        .add_break_point(0x3000, Some(callback));

    let hook_id = *backend.borrow().code_hooks.keys().next().unwrap();
    backend.borrow_mut().fire_code(hook_id, 0x3000, 4);
    assert_eq!(
        backend.borrow().emu_stop_count,
        0,
        "Continue must not ask the run loop to stop"
    );
    assert_eq!(backend.borrow().code_hooks.len(), 1, "hook still installed");
}

#[test]
fn single_step_stops_after_n_instructions() {
    let (_backend_dyn, backend, breaker) = harness();
    breaker.borrow_mut().set_single_step(3);

    let hook_id = {
        let b = backend.borrow();
        assert_eq!(b.code_hooks.len(), 1);
        let rec = b.code_hooks.values().next().unwrap();
        assert_eq!(rec.begin, 0);
        assert_eq!(rec.end, u64::MAX);
        *b.code_hooks.keys().next().unwrap()
    };

    assert_eq!(breaker.borrow().single_step_remaining(), Some(3));

    backend.borrow_mut().fire_code(hook_id, 0x4000, 4);
    assert_eq!(backend.borrow().emu_stop_count, 0);
    assert_eq!(breaker.borrow().single_step_remaining(), Some(2));

    backend.borrow_mut().fire_code(hook_id, 0x4004, 4);
    assert_eq!(backend.borrow().emu_stop_count, 0);
    assert_eq!(breaker.borrow().single_step_remaining(), Some(1));

    backend.borrow_mut().fire_code(hook_id, 0x4008, 4);
    assert_eq!(backend.borrow().emu_stop_count, 1);
    assert!(backend.borrow().code_hooks.is_empty());
    assert_eq!(breaker.borrow().single_step_remaining(), None);

    breaker.borrow_mut().set_single_step(0);
    assert_eq!(breaker.borrow().single_step_remaining(), None);
}

#[test]
fn single_step_zero_clears_a_pending_step() {
    let (_backend_dyn, backend, breaker) = harness();
    breaker.borrow_mut().set_single_step(5);
    assert_eq!(
        backend.borrow().code_hooks.len(),
        1,
        "single-step installed a hook"
    );
    breaker.borrow_mut().set_single_step(0);
    assert!(backend.borrow().code_hooks.is_empty());
    assert_eq!(breaker.borrow().single_step_remaining(), None);
}

#[test]
fn fast_debug_skips_the_callback_and_always_stops() {
    let (_backend_dyn, backend, breaker) = harness();
    let callback: Box<dyn FnMut(u64) -> BreakControl> = Box::new(|_| BreakControl::Continue);
    let bp = breaker
        .borrow_mut()
        .add_break_point(0x5000, Some(callback));
    bp.set_temporary(true);

    breaker.borrow_mut().set_fast_debug(true);

    let hook_id = *backend.borrow().code_hooks.keys().next().unwrap();
    backend.borrow_mut().fire_code(hook_id, 0x5000, 4);
    assert_eq!(backend.borrow().emu_stop_count, 1, "fast-debug forces a stop");
    assert!(backend.borrow().code_hooks.is_empty());
    assert!(breaker.borrow().fast_debug());
}

#[test]
fn thumb_address_strips_the_low_bit() {
    let (_backend_dyn, backend, breaker) = harness();
    let bp = breaker.borrow_mut().add_break_point(0x1001, None);
    assert_eq!(bp.address(), 0x1000);
    assert!(bp.thumb());
    let hook_id = *backend.borrow().code_hooks.keys().next().unwrap();
    let rec = backend.borrow().code_hooks[&hook_id].begin;
    assert_eq!(rec, 0x1000);
}

// ---------------------------------------------------------------------------
// CodeHistory
// ---------------------------------------------------------------------------

#[test]
fn code_history_evicts_oldest_past_its_bound() {
    let mut history = CodeHistory::new(4);
    for pc in 0u64..10 {
        let mut regs = BTreeMap::new();
        regs.insert(RegId::Pc, pc * 0x1000);
        history.add(pc * 0x1000, regs, 4);
    }
    assert_eq!(history.len(), 4);
    assert_eq!(history.capacity(), 4);
    let entries: Vec<&HistoryEntry> = history.iter().collect();
    assert_eq!(
        entries.iter().map(|e| e.pc).collect::<Vec<_>>(),
        vec![0x6000, 0x7000, 0x8000, 0x9000],
        "ring buffer holds the last 4 entries"
    );
    let window: Vec<u64> = history.last(3).into_iter().map(|e| e.pc).collect();
    assert_eq!(window, vec![0x7000, 0x8000, 0x9000]);
    assert_eq!(history.latest().unwrap().pc, 0x9000);
    history.clear();
    assert!(history.is_empty());
}

// ---------------------------------------------------------------------------
// TraceCode
// ---------------------------------------------------------------------------

struct FixedDisassembler(&'static str);

impl Disassembler for FixedDisassembler {
    fn disassemble(&self, _addr: u64, _bytes: &[u8], _thumb: bool) -> Option<String> {
        Some(self.0.to_string())
    }
}

#[test]
fn trace_code_collects_instructions_it_saw() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceCode::new(Rc::new(FixedDisassembler("nop"))));
    let hook_id = trace.attach(&backend_dyn, 0, u64::MAX);

    backend.borrow_mut().pc = 0x6000;
    backend.borrow_mut().fire_code(hook_id, 0x6000, 4);
    backend.borrow_mut().pc = 0x6004;
    backend.borrow_mut().fire_code(hook_id, 0x6004, 4);
    backend.borrow_mut().pc = 0x6008;
    backend.borrow_mut().fire_code(hook_id, 0x6008, 4);

    let entries = trace.entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].pc, 0x6000);
    assert_eq!(entries[1].pc, 0x6004);
    assert_eq!(entries[2].pc, 0x6008);
    assert_eq!(entries[0].disassembly.as_deref(), Some("nop"));
    assert_eq!(entries[0].registers.get(&RegId::Pc), Some(&0x6000));
    assert_eq!(entries[1].registers.get(&RegId::Pc), Some(&0x6004));
}

#[test]
fn trace_code_stop_trace_clears_entries() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceCode::new(Rc::new(NoopDisassembler)));
    let hook_id = trace.attach(&backend_dyn, 0, u64::MAX);
    backend.borrow_mut().mem_map(0x6000, 0x1000, Prot::READ).unwrap();
    backend.borrow_mut().pc = 0x6000;
    backend.borrow_mut().fire_code(hook_id, 0x6000, 4);
    backend.borrow_mut().fire_code(hook_id, 0x6004, 4);
    assert_eq!(trace.entries().len(), 2);
    trace.stop_trace();
    assert!(trace.entries().is_empty());
}

#[test]
fn trace_code_works_with_the_noop_disassembler() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceCode::new(Rc::new(NoopDisassembler)));
    let hook_id = trace.attach(&backend_dyn, 0, u64::MAX);
    backend.borrow_mut().mem_map(0x8000, 0x1000, Prot::READ).unwrap();
    backend.borrow_mut().pc = 0x8000;
    backend.borrow_mut().fire_code(hook_id, 0x8000, 4);
    let entries = trace.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].disassembly.is_none());
}

#[test]
fn trace_code_writes_lines_through_the_redirect() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceCode::new(Rc::new(FixedDisassembler("mov x0, #0"))));
    let redirect = Box::new(CaptureWriter::default());
    trace.set_redirect(redirect);

    let hook_id = trace.attach(&backend_dyn, 0, u64::MAX);
    backend.borrow_mut().mem_map(0x7000, 0x1000, Prot::READ).unwrap();
    backend.borrow_mut().pc = 0x7000;
    backend.borrow_mut().fire_code(hook_id, 0x7000, 4);
    backend.borrow_mut().fire_code(hook_id, 0x7004, 4);

    let entries = trace.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].disassembly.as_deref(), Some("mov x0, #0"));
}

// ---------------------------------------------------------------------------
// TraceMemory
// ---------------------------------------------------------------------------

#[test]
fn trace_memory_collects_a_stores_value() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceMemory::new(true));
    let (read_id, write_id) = trace.attach(&backend_dyn, 0, u64::MAX);

    backend.borrow_mut().mem_map(0x9000, 0x1000, Prot::READ).unwrap();
    backend.borrow_mut().pc = 0x1234;

    backend
        .borrow_mut()
        .fire_write(write_id, 0x1234, 0x9000, 4, 0xdead_beef);

    let writes = trace.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0],
        MemTraceEvent {
            pc: 0x1234,
            address: 0x9000,
            size: 4,
            value: 0xdead_beef,
        }
    );

    backend
        .borrow_mut()
        .fire_read(read_id, 0x1238, 0x9000, 4);
    let reads = trace.reads();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].pc, 0x1238);
    assert_eq!(reads[0].address, 0x9000);
    assert_eq!(reads[0].size, 4);
    assert_eq!(reads[0].value, 0);
}

#[test]
fn trace_memory_stop_trace_clears_entries() {
    let (backend_dyn, backend, _breaker) = harness();
    let trace = Rc::new(TraceMemory::new(true));
    let (_r, w) = trace.attach(&backend_dyn, 0, u64::MAX);
    backend.borrow_mut().mem_map(0xb000, 0x1000, Prot::READ).unwrap();
    backend.borrow_mut().fire_write(w, 0, 0xb000, 4, 1);
    backend.borrow_mut().fire_write(w, 0, 0xb004, 4, 2);
    assert_eq!(trace.writes().len(), 2);
    trace.stop_trace();
    assert!(trace.writes().is_empty());
}

// ---------------------------------------------------------------------------
// Capture writer
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CaptureWriter {
    bytes: RefCell<Vec<u8>>,
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
