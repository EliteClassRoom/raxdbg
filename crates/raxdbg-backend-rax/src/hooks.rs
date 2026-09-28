//! Hook storage and dispatch.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/UnicornBackend.java`
//! `hook_add_new`/`hook_del`@7f5da98e, split in two because rax's address space
//! is owned by the CPU core:
//!
//! * [`CpuHooks`] — code, block, interrupt and event-memory hooks. They fire at
//!   instruction boundaries in the run loop, where the core is not borrowed, so
//!   they are handed the backend itself.
//! * [`MemShared`] — read and write hooks, which fire *inside* the in-flight
//!   instruction and therefore hand the hook a
//!   [`MemHookCtx`](raxdbg_core::backend::MemHookCtx). The type is shared with
//!   rax's `ArmMemory`, which is `Send + Sync`, so its callbacks must be `Send`
//!   as well.
//!
//! Dispatch moves the hook vector out of the table for the duration of the call
//! (`O(1)`), so a hook may add or remove hooks without aliasing the table it is
//! being called from; hooks registered meanwhile are appended when the vector
//! is put back.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::Mutex;
use rax::error::GuestMemoryFault;
use rax::user::mm::{AddressSpace, Perms};
use raxdbg_core::backend::{
    BlockHook, CodeHook, EventMemHook, GuestMemoryAccess, HookId, InterruptHook, MemHookCtx,
    MemoryFault, MemoryFaultKind, ReadHook, RunControl, UnmappedKind, WriteHook,
};

/// The inclusive address range a hook is registered for, matching unicorn's
/// `begin`/`end` arguments (both ends are hookable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HookRange {
    /// First hooked address.
    pub begin: u64,
    /// Last hooked address.
    pub end: u64,
}

impl HookRange {
    /// A range covering `[begin, end]`.
    pub const fn new(begin: u64, end: u64) -> Self {
        HookRange { begin, end }
    }

    /// A range covering everything.
    pub const ALL: HookRange = HookRange {
        begin: 0,
        end: u64::MAX,
    };

    /// Whether `addr` falls inside the range.
    pub const fn contains(self, addr: u64) -> bool {
        addr >= self.begin && addr <= self.end
    }
}

/// A hook with an address range.
pub(crate) struct Ranged<T> {
    pub(crate) id: HookId,
    pub(crate) range: HookRange,
    pub(crate) cb: T,
}

/// The hooks taken out of a [`CpuHooks`] for the duration of a dispatch.
///
/// The run loop takes them out before calling a callback, so the callback may
/// use the backend it is handed (a second borrow of the table would otherwise
/// not type-check); hooks registered meanwhile are appended on restore.
#[derive(Default)]
pub struct TakenHooks {
    pub(crate) code: Vec<Ranged<Box<dyn CodeHook>>>,
    pub(crate) block: Vec<Ranged<Box<dyn BlockHook>>>,
}

/// Code, block, interrupt and event-memory hooks.
///
/// Owned by the backend; the callbacks are called with the backend itself.
#[derive(Default)]
pub struct CpuHooks {
    code: Vec<Ranged<Box<dyn CodeHook>>>,
    block: Vec<Ranged<Box<dyn BlockHook>>>,
    interrupt: Vec<(HookId, Box<dyn InterruptHook>)>,
    event: Vec<(HookId, UnmappedKind, Box<dyn EventMemHook>)>,
    /// Removals that arrived while a dispatch was in flight; applied when the
    /// dispatch finishes.
    removed: Vec<HookId>,
    /// Nesting depth of in-flight dispatches.
    depth: u32,
}

impl fmt::Debug for CpuHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuHooks")
            .field("code", &self.code.len())
            .field("block", &self.block.len())
            .field("interrupt", &self.interrupt.len())
            .field("event", &self.event.len())
            .finish()
    }
}

impl CpuHooks {
    /// Registers a code hook.
    pub fn add_code(&mut self, id: HookId, cb: Box<dyn CodeHook>, range: HookRange) {
        self.code.push(Ranged { id, range, cb });
    }

    /// Registers a block hook.
    pub fn add_block(&mut self, id: HookId, cb: Box<dyn BlockHook>, range: HookRange) {
        self.block.push(Ranged { id, range, cb });
    }

    /// Registers an interrupt hook.
    pub fn add_interrupt(&mut self, id: HookId, cb: Box<dyn InterruptHook>) {
        self.interrupt.push((id, cb));
    }

    /// Registers an event-memory hook for one fault kind.
    pub fn add_event(&mut self, id: HookId, kind: UnmappedKind, cb: Box<dyn EventMemHook>) {
        self.event.push((id, kind, cb));
    }

    /// Removes a hook by id.
    ///
    /// A removal that arrives while a dispatch is in flight is deferred to the
    /// end of that dispatch, because the hook being removed is not in the table
    /// at that moment.
    pub fn remove(&mut self, id: HookId) {
        if self.depth > 0 {
            self.removed.push(id);
            return;
        }
        self.remove_now(id);
    }

    fn remove_now(&mut self, id: HookId) {
        self.code.retain(|e| e.id != id);
        self.block.retain(|e| e.id != id);
        self.interrupt.retain(|(i, _)| *i != id);
        self.event.retain(|(i, _, _)| *i != id);
    }

    fn apply_removals(&mut self) {
        for id in std::mem::take(&mut self.removed) {
            self.remove_now(id);
        }
    }

    /// Whether any code or block hook covers `addr`.
    pub fn has_hooks_at(&self, addr: u64) -> bool {
        self.code.iter().any(|e| e.range.contains(addr))
            || self.block.iter().any(|e| e.range.contains(addr))
    }

    /// Whether any interrupt hook is registered.
    pub fn has_interrupt(&self) -> bool {
        !self.interrupt.is_empty()
    }

    /// Whether any event-memory hook is registered.
    pub fn has_event(&self) -> bool {
        !self.event.is_empty()
    }

    /// Takes the code and block hooks out for a dispatch.
    pub fn take_step_hooks(&mut self) -> TakenHooks {
        self.depth += 1;
        TakenHooks {
            code: std::mem::take(&mut self.code),
            block: std::mem::take(&mut self.block),
        }
    }

    /// Puts the code and block hooks back, appending anything registered
    /// meanwhile and dropping anything removed meanwhile.
    pub fn restore_step_hooks(&mut self, mut taken: TakenHooks) {
        taken.code.retain(|e| !self.removed.contains(&e.id));
        taken.code.extend(std::mem::take(&mut self.code));
        self.code = taken.code;
        taken.block.retain(|e| !self.removed.contains(&e.id));
        taken.block.extend(std::mem::take(&mut self.block));
        self.block = taken.block;
        self.end_dispatch();
    }

    /// Takes the interrupt hooks out for a dispatch.
    pub fn take_interrupt_hooks(&mut self) -> Vec<(HookId, Box<dyn InterruptHook>)> {
        self.depth += 1;
        std::mem::take(&mut self.interrupt)
    }

    /// Puts the interrupt hooks back.
    pub fn restore_interrupt_hooks(&mut self, mut taken: Vec<(HookId, Box<dyn InterruptHook>)>) {
        taken.retain(|(id, _)| !self.removed.contains(id));
        taken.extend(std::mem::take(&mut self.interrupt));
        self.interrupt = taken;
        self.end_dispatch();
    }

    /// Takes the event-memory hooks out for a dispatch.
    pub fn take_event_hooks(&mut self) -> Vec<(HookId, UnmappedKind, Box<dyn EventMemHook>)> {
        self.depth += 1;
        std::mem::take(&mut self.event)
    }

    /// Puts the event-memory hooks back.
    pub fn restore_event_hooks(
        &mut self,
        mut taken: Vec<(HookId, UnmappedKind, Box<dyn EventMemHook>)>,
    ) {
        taken.retain(|(id, _, _)| !self.removed.contains(id));
        taken.extend(std::mem::take(&mut self.event));
        self.event = taken;
        self.end_dispatch();
    }

    fn end_dispatch(&mut self) {
        self.depth -= 1;
        if self.depth == 0 {
            self.apply_removals();
        }
    }
}

/// Maps a rax address-space fault onto the backend's fault kind.
pub fn fault_kind(fault: GuestMemoryFault) -> MemoryFaultKind {
    match fault.kind {
        rax::error::MemoryFaultKind::Unmapped => MemoryFaultKind::Unmapped,
        rax::error::MemoryFaultKind::Permission => MemoryFaultKind::Permission,
        rax::error::MemoryFaultKind::Other => MemoryFaultKind::Bus,
    }
}

/// Translates rax's protection bits into the backend's.
pub const fn prot_of(perms: Perms) -> raxdbg_core::backend::Prot {
    let mut bits = 0u8;
    if perms.contains(Perms::READ) {
        bits |= raxdbg_core::backend::Prot::READ.bits();
    }
    if perms.contains(Perms::WRITE) {
        bits |= raxdbg_core::backend::Prot::WRITE.bits();
    }
    if perms.contains(Perms::EXEC) {
        bits |= raxdbg_core::backend::Prot::EXEC.bits();
    }
    raxdbg_core::backend::Prot::from_bits(bits)
}

/// Translates the backend's protection bits into rax's.
pub const fn perms_of(prot: raxdbg_core::backend::Prot) -> Perms {
    let mut perms = Perms::empty();
    if prot.contains(raxdbg_core::backend::Prot::READ) {
        perms = perms.union(Perms::READ);
    }
    if prot.contains(raxdbg_core::backend::Prot::WRITE) {
        perms = perms.union(Perms::WRITE);
    }
    if prot.contains(raxdbg_core::backend::Prot::EXEC) {
        perms = perms.union(Perms::EXEC);
    }
    perms
}

/// Read and write hooks plus the guest memory they observe.
///
/// Shared between the backend (which registers hooks) and rax's `ArmMemory`
/// (which dispatches them), hence `Send + Sync`.
pub struct MemShared {
    space: AddressSpace,
    read: Mutex<Vec<Ranged<Box<dyn ReadHook + Send>>>>,
    write: Mutex<Vec<Ranged<Box<dyn WriteHook + Send>>>>,
    active: AtomicUsize,
    pc: AtomicU64,
    control: RunControl,
}

impl fmt::Debug for MemShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemShared")
            .field("read_hooks", &self.read.lock().len())
            .field("write_hooks", &self.write.lock().len())
            .field("pc", &self.pc.load(Ordering::Relaxed))
            .finish()
    }
}

impl MemShared {
    /// Wraps a guest address space.
    pub fn new(space: AddressSpace) -> Self {
        MemShared {
            space,
            read: Mutex::new(Vec::new()),
            write: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            pc: AtomicU64::new(0),
            control: RunControl::new(),
        }
    }

    /// The guest address space.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// The run-loop control flag shared with the backend.
    pub fn control(&self) -> &RunControl {
        &self.control
    }

    /// Publishes the PC of the instruction about to execute, for hook contexts.
    pub fn set_pc(&self, pc: u64) {
        self.pc.store(pc, Ordering::Relaxed);
    }

    /// Registers a read hook.
    pub fn add_read(&self, id: HookId, cb: Box<dyn ReadHook + Send>, range: HookRange) {
        self.read.lock().push(Ranged { id, range, cb });
        self.active.fetch_add(1, Ordering::Release);
    }

    /// Registers a write hook.
    pub fn add_write(&self, id: HookId, cb: Box<dyn WriteHook + Send>, range: HookRange) {
        self.write.lock().push(Ranged { id, range, cb });
        self.active.fetch_add(1, Ordering::Release);
    }

    /// Removes a read or write hook by id.
    pub fn remove(&self, id: HookId) {
        let mut removed = 0usize;
        {
            let mut read = self.read.lock();
            let before = read.len();
            read.retain(|e| e.id != id);
            removed += before - read.len();
        }
        {
            let mut write = self.write.lock();
            let before = write.len();
            write.retain(|e| e.id != id);
            removed += before - write.len();
        }
        if removed > 0 {
            self.active.fetch_sub(removed, Ordering::Release);
        }
    }

    /// Whether any read or write hook is registered.
    pub fn has_hooks(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    /// Dispatches the read hooks covering `addr` for an access of `size` bytes.
    pub fn dispatch_read(&self, addr: u64, size: usize) {
        if !self.has_hooks() {
            return;
        }
        let mut hooks = std::mem::take(&mut *self.read.lock());
        if hooks.iter().any(|e| e.range.contains(addr)) {
            let mut ctx = MemHookCtx::new(self.pc.load(Ordering::Relaxed), self, self.control.flag());
            for entry in &mut hooks {
                if entry.range.contains(addr) {
                    entry.cb.hook(&mut ctx, addr, size);
                }
            }
        }
        hooks.extend(std::mem::take(&mut *self.read.lock()));
        *self.read.lock() = hooks;
    }

    /// Dispatches the write hooks covering `addr` with the stored `value`.
    pub fn dispatch_write(&self, addr: u64, size: usize, value: u64) {
        if !self.has_hooks() {
            return;
        }
        let mut hooks = std::mem::take(&mut *self.write.lock());
        if hooks.iter().any(|e| e.range.contains(addr)) {
            let mut ctx = MemHookCtx::new(self.pc.load(Ordering::Relaxed), self, self.control.flag());
            for entry in &mut hooks {
                if entry.range.contains(addr) {
                    entry.cb.hook(&mut ctx, addr, size, value);
                }
            }
        }
        hooks.extend(std::mem::take(&mut *self.write.lock()));
        *self.write.lock() = hooks;
    }
}

impl GuestMemoryAccess for MemShared {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        self.space.read(addr, buf).map_err(|fault| MemoryFault {
            addr: fault.address,
            size: buf.len(),
            kind: fault_kind(fault),
        })
    }

    fn write(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        self.space.write(addr, data).map_err(|fault| MemoryFault {
            addr: fault.address,
            size: data.len(),
            kind: fault_kind(fault),
        })
    }
}

/// Every hook of a backend, with a shared id counter.
#[derive(Debug)]
pub struct HookTable {
    next_id: HookId,
    cpu: CpuHooks,
    mem: Arc<MemShared>,
}

impl HookTable {
    /// Creates a table whose memory hooks live in `mem`.
    pub fn new(mem: Arc<MemShared>) -> Self {
        HookTable {
            next_id: 1,
            cpu: CpuHooks::default(),
            mem,
        }
    }

    /// Allocates a hook id.
    pub fn alloc_id(&mut self) -> HookId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// The CPU-side hooks.
    pub fn cpu(&mut self) -> &mut CpuHooks {
        &mut self.cpu
    }

    /// The shared memory hooks.
    pub fn mem(&self) -> &Arc<MemShared> {
        &self.mem
    }

    /// Removes a hook from every table.
    pub fn remove(&mut self, id: HookId) {
        self.cpu.remove(id);
        self.mem.remove(id);
    }
}
