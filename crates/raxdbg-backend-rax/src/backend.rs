//! `RaxBackend`: the rax CPU engine behind unidbg's `Backend` contract.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/AbstractBackend.java`
//! and `UnicornBackend.java`@7f5da98e, with rax replacing unicorn.
//!
//! The backend owns the CPU adapters and the hook table, and shares the guest
//! address space with them through [`MemShared`]. The run loop lives in
//! [`crate::run`].

use std::sync::Arc;

use rax::user::cpu::Isa;
use rax::user::mm::{AddressSpace, Mapping};
use raxdbg_core::backend::{
    Backend, BackendError, BlockHook, CodeHook, ContextId, EventMemHook, GuestMemory,
    GuestMemoryAccess, HookId, InterruptHook, MemoryFault, Prot, ReadHook, RunError, RunOutcome,
    UnmappedKind, WriteHook,
};
use raxdbg_core::reg::RegId;

use crate::context::CpuContext;
use crate::cpu::{Cpu, RaxArm32Cpu, RaxArm64Cpu};
use crate::hooks::{HookRange, HookTable, MemShared, perms_of};

/// The guest page size. rax's address spaces are 4 KiB throughout.
pub const PAGE_SIZE: usize = 4096;

/// A rax-backed guest CPU.
pub struct RaxBackend {
    pub(crate) cpu: Cpu,
    pub(crate) shared: Arc<MemShared>,
    pub(crate) hooks: HookTable,
    pub(crate) contexts: Vec<Option<CpuContext>>,
    /// A control-flow event raised by a hook, waiting for the run loop.
    pub(crate) pending: Option<RunError>,
    pub(crate) running: bool,
}

impl std::fmt::Debug for RaxBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaxBackend")
            .field("isa", &self.isa())
            .field("pc", &self.cpu.pc())
            .field("running", &self.running)
            .field("hooks", &self.hooks)
            .finish()
    }
}

impl RaxBackend {
    /// A user address space with raxdbg's defaults: a 48-bit virtual address
    /// limit and a 64 MiB frame arena, which is what the Android loader, the
    /// stack area and a few mapped libraries need.
    pub fn default_space() -> AddressSpace {
        AddressSpace::new(rax::user::mm::SpaceConfig {
            va_limit: 1 << 48,
            arena_bytes: 64 * 1024 * 1024,
            reserved_phys: Vec::new(),
        })
        .expect("a 48-bit address space with a 64 MiB arena is always valid")
    }

    /// Creates a backend for `isa` over a fresh address space.
    pub fn new(space: AddressSpace, isa: Isa) -> Self {
        let shared = Arc::new(MemShared::new(space));
        let cpu = match isa {
            Isa::Aarch64 => Cpu::Arm64(RaxArm64Cpu::new(
                rax::isa::arm::aarch64::AArch64Config::v8_2(),
                Arc::clone(&shared),
            )),
            Isa::Arm => Cpu::Arm32(RaxArm32Cpu::new(Arc::clone(&shared))),
            other => panic!("raxdbg does not support the {other} ISA"),
        };
        let hooks = HookTable::new(Arc::clone(&shared));
        RaxBackend {
            cpu,
            shared,
            hooks,
            contexts: Vec::new(),
            pending: None,
            running: false,
        }
    }

    /// Creates an AArch64 backend over a fresh address space.
    pub fn new_arm64(space: AddressSpace) -> Self {
        Self::new(space, Isa::Aarch64)
    }

    /// Creates an AArch32 backend over a fresh address space.
    pub fn new_arm32(space: AddressSpace) -> Self {
        Self::new(space, Isa::Arm)
    }

    /// The ISA this backend runs.
    pub fn isa(&self) -> Isa {
        match self.cpu {
            Cpu::Arm64(_) => Isa::Aarch64,
            Cpu::Arm32(_) => Isa::Arm,
        }
    }

    /// The AArch64 adapter, if this is an AArch64 backend.
    pub fn arm64(&self) -> Option<&RaxArm64Cpu> {
        match &self.cpu {
            Cpu::Arm64(cpu) => Some(cpu),
            Cpu::Arm32(_) => None,
        }
    }

    /// The AArch64 adapter, if this is an AArch64 backend.
    pub fn arm64_mut(&mut self) -> Option<&mut RaxArm64Cpu> {
        match &mut self.cpu {
            Cpu::Arm64(cpu) => Some(cpu),
            Cpu::Arm32(_) => None,
        }
    }

    /// The AArch32 adapter, if this is an AArch32 backend.
    pub fn arm32(&self) -> Option<&RaxArm32Cpu> {
        match &self.cpu {
            Cpu::Arm32(cpu) => Some(cpu),
            Cpu::Arm64(_) => None,
        }
    }

    /// The AArch32 adapter, if this is an AArch32 backend.
    pub fn arm32_mut(&mut self) -> Option<&mut RaxArm32Cpu> {
        match &mut self.cpu {
            Cpu::Arm32(cpu) => Some(cpu),
            Cpu::Arm64(_) => None,
        }
    }

    /// The guest address space.
    pub fn address_space(&self) -> &AddressSpace {
        self.shared.space()
    }

    /// A handle to the address space that does not borrow the backend.
    ///
    /// The loader holds one of these so a syscall handler can reach guest
    /// memory while the run loop has the backend mutably borrowed (plan P2.6).
    pub fn guest_memory(&self) -> Arc<dyn GuestMemory> {
        Arc::new(SpaceHandle {
            space: self.shared.space().clone(),
        })
    }

    /// The shared memory bridge, for hooks that need the same stop flag.
    pub fn shared(&self) -> &Arc<MemShared> {
        &self.shared
    }

    /// The run-loop control flag.
    pub fn control(&self) -> &raxdbg_core::backend::RunControl {
        self.shared.control()
    }

    /// Records a control-flow event for the run loop to unwind with
    /// (unidbg's `ThreadContextSwitchException` and friends).
    pub fn set_pending_error(&mut self, error: RunError) {
        self.pending = Some(error);
    }

    /// Takes the pending control-flow event, if any.
    pub fn take_pending_error(&mut self) -> Option<RunError> {
        self.pending.take()
    }

    /// Runs the code and block hooks registered for `pc`.
    ///
    /// `block_entry` is true when `pc` is the first instruction of a basic
    /// block, which is where unidbg's block hooks fire.
    pub(crate) fn dispatch_step_hooks(&mut self, pc: u64, size: u32, block_entry: bool) {
        if !self.hooks.cpu().has_hooks_at(pc) {
            return;
        }
        let mut taken = self.hooks.cpu().take_step_hooks();
        for entry in &mut taken.code {
            if entry.range.contains(pc) {
                entry.cb.hook(self, pc, size);
            }
        }
        if block_entry {
            for entry in &mut taken.block {
                if entry.range.contains(pc) {
                    entry.cb.hook_block(self, pc, size);
                }
            }
        }
        self.hooks.cpu().restore_step_hooks(taken);
    }

    /// Runs the interrupt hooks; returns whether any ran.
    pub(crate) fn dispatch_interrupt_hooks(&mut self, intno: i32, swi: i32) -> bool {
        if !self.hooks.cpu().has_interrupt() {
            return false;
        }
        let mut taken = self.hooks.cpu().take_interrupt_hooks();
        let ran = !taken.is_empty();
        for (_, cb) in &mut taken {
            cb.hook(self, intno, swi);
        }
        self.hooks.cpu().restore_interrupt_hooks(taken);
        ran
    }

    /// Runs the event-memory hooks registered for `kind`; returns whether any
    /// reported that it fixed the fault.
    pub(crate) fn dispatch_event_hooks(
        &mut self,
        addr: u64,
        size: usize,
        value: u64,
        kind: UnmappedKind,
    ) -> bool {
        if !self.hooks.cpu().has_event() {
            return false;
        }
        let mut taken = self.hooks.cpu().take_event_hooks();
        let mut handled = false;
        for (_, registered, cb) in &mut taken {
            if *registered == kind && cb.hook(self, addr, size, value, kind) {
                handled = true;
            }
        }
        self.hooks.cpu().restore_event_hooks(taken);
        handled
    }
}

/// The address space behind an `Arc`, so it can be shared with the loader.
struct SpaceHandle {
    space: AddressSpace,
}

impl GuestMemory for SpaceHandle {
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        self.space
            .read_raw(addr, buf)
            .map_err(|fault| memory_fault(fault, buf.len()))
    }

    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        self.space
            .write_raw(addr, data)
            .map_err(|fault| memory_fault(fault, data.len()))
    }

    fn map(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        self.space
            .map(addr, size, Mapping::anonymous(perms_of(perms)))
            .map_err(|e| BackendError::Map {
                addr,
                size,
                reason: e.to_string(),
            })
    }

    fn protect(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        self.space
            .protect(addr, size, perms_of(perms))
            .map_err(|e| BackendError::Map {
                addr,
                size,
                reason: e.to_string(),
            })
    }

    fn unmap(&self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.space.unmap(addr, size).map_err(|e| BackendError::Map {
            addr,
            size,
            reason: e.to_string(),
        })
    }
}

impl GuestMemoryAccess for RaxBackend {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        self.shared.read(addr, buf)
    }

    fn write(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        self.shared.write(addr, data)
    }
}

impl Backend for RaxBackend {
    fn on_initialize(&mut self) {}

    /// Port of unidbg: `AbstractBackend.switchUserMode`.
    fn switch_user_mode(&mut self) {
        if let Cpu::Arm32(cpu) = &mut self.cpu {
            cpu.core_mut().cpsr.mode = rax::isa::arm::ProcessorMode::User as u8;
        }
    }

    /// Port of unidbg: `AbstractBackend.enableVFP`.
    fn enable_vfp(&mut self) {
        match &mut self.cpu {
            Cpu::Arm64(cpu) => {
                let cpacr = cpu.core().cpacr_el1();
                cpu.core_mut().set_cpacr_el1(cpacr | (0b11 << 20));
            }
            Cpu::Arm32(cpu) => {
                let core = cpu.core_mut();
                core.cp15.cpacr =
                    rax::isa::arm::cp15::Cpacr::from_bits(core.cp15.cpacr.bits() | 0x00f0_0000);
                core.vfp.fpexc = 0x4000_0000;
            }
        }
    }

    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError> {
        match &self.cpu {
            Cpu::Arm64(cpu) => cpu.read_reg(reg),
            Cpu::Arm32(cpu) => cpu.read_reg(reg),
        }
    }

    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match &mut self.cpu {
            Cpu::Arm64(cpu) => cpu.write_reg(reg, value),
            Cpu::Arm32(cpu) => cpu.write_reg(reg, value),
        }
    }

    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        match &self.cpu {
            Cpu::Arm64(cpu) => cpu.read_vector(reg),
            Cpu::Arm32(cpu) => cpu.read_vector(reg),
        }
    }

    fn reg_write_vector(&mut self, reg: RegId, v: [u8; 16]) -> Result<(), BackendError> {
        match &mut self.cpu {
            Cpu::Arm64(cpu) => cpu.write_vector(reg, v),
            Cpu::Arm32(cpu) => cpu.write_vector(reg, v),
        }
    }

    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; size];
        self.mem_read_into(addr, &mut buf)?;
        Ok(buf)
    }

    fn mem_read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), BackendError> {
        // unidbg reads guest memory through unicorn's host API, which checks
        // that the range is mapped but not the guest's own permissions; the
        // guest's accesses are the ones the CPU enforces.
        self.shared
            .space()
            .read_raw(addr, buf)
            .map_err(|fault| BackendError::Memory(memory_fault(fault, buf.len())))
    }

    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError> {
        // As with `mem_read_into`: a host write reaches a read-only mapping,
        // which is how unidbg loads segments it mapped `READ | EXEC`.
        self.shared
            .space()
            .write_raw(addr, bytes)
            .map_err(|fault| BackendError::Memory(memory_fault(fault, bytes.len())))
    }

    fn mem_map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        self.shared
            .space()
            .map(addr, size, Mapping::anonymous(perms_of(perms)))
            .map_err(|e| BackendError::Map {
                addr,
                size,
                reason: e.to_string(),
            })
    }

    fn mem_protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        self.shared
            .space()
            .protect(addr, size, perms_of(perms))
            .map_err(|e| BackendError::Map {
                addr,
                size,
                reason: e.to_string(),
            })?;
        if perms.contains(Prot::EXEC) {
            self.cpu.invalidate_code();
        }
        Ok(())
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.shared
            .space()
            .unmap(addr, size)
            .map_err(|e| BackendError::Map {
                addr,
                size,
                reason: e.to_string(),
            })?;
        self.cpu.invalidate_code();
        Ok(())
    }

    fn hook_add_code(&mut self, cb: Box<dyn CodeHook>, begin: u64, end: u64) -> HookId {
        let id = self.hooks.alloc_id();
        self.hooks.cpu().add_code(id, cb, HookRange::new(begin, end));
        id
    }

    fn hook_add_block(&mut self, cb: Box<dyn BlockHook>, begin: u64, end: u64) -> HookId {
        let id = self.hooks.alloc_id();
        self.hooks
            .cpu()
            .add_block(id, cb, HookRange::new(begin, end));
        id
    }

    fn hook_add_read(&mut self, cb: Box<dyn ReadHook + Send>, begin: u64, end: u64) -> HookId {
        let id = self.hooks.alloc_id();
        self.shared.add_read(id, cb, HookRange::new(begin, end));
        id
    }

    fn hook_add_write(&mut self, cb: Box<dyn WriteHook + Send>, begin: u64, end: u64) -> HookId {
        let id = self.hooks.alloc_id();
        self.shared.add_write(id, cb, HookRange::new(begin, end));
        id
    }

    fn hook_add_event_mem(&mut self, cb: Box<dyn EventMemHook>, kind: UnmappedKind) -> HookId {
        let id = self.hooks.alloc_id();
        self.hooks.cpu().add_event(id, kind, cb);
        id
    }

    fn hook_add_interrupt(&mut self, cb: Box<dyn InterruptHook>) -> HookId {
        let id = self.hooks.alloc_id();
        self.hooks.cpu().add_interrupt(id, cb);
        id
    }

    fn hook_del(&mut self, id: HookId) {
        self.hooks.remove(id);
    }

    fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_us: u64,
        count: u64,
    ) -> Result<RunOutcome, RunError> {
        crate::run::emu_start(self, begin, until, timeout_us, count)
    }

    fn emu_stop(&mut self) {
        self.control().request_stop();
    }

    fn set_pending_error(&mut self, error: RunError) {
        self.pending = Some(error);
    }

    fn take_pending_error(&mut self) -> Option<RunError> {
        self.pending.take()
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn context_save(&mut self) -> ContextId {
        let context = CpuContext::save(&self.cpu);
        for (index, slot) in self.contexts.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(context);
                return index as ContextId;
            }
        }
        self.contexts.push(Some(context));
        (self.contexts.len() - 1) as ContextId
    }

    fn context_restore(&mut self, id: ContextId) {
        if let Some(Some(context)) = self.contexts.get(id as usize) {
            context.restore(&mut self.cpu);
        }
    }

    fn context_free(&mut self, id: ContextId) {
        if let Some(slot) = self.contexts.get_mut(id as usize) {
            *slot = None;
        }
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE
    }

    fn remove_jit_code_cache(&mut self, _begin: u64, _end: u64) {
        self.cpu.invalidate_code();
    }
}

/// Maps a rax address-space fault onto the backend's fault type.
pub(crate) fn memory_fault(fault: rax::error::GuestMemoryFault, size: usize) -> MemoryFault {
    MemoryFault {
        addr: fault.address,
        size,
        kind: crate::hooks::fault_kind(fault),
    }
}
