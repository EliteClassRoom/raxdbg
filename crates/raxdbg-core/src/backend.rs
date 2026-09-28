//! The CPU backend contract.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/Backend.java`
//! and `AbstractBackend.java`@7f5da98e.
//!
//! Differences from the Java contract, all deliberate:
//!
//! * `emu_start` returns a typed [`RunOutcome`]/[`RunError`] instead of throwing
//!   `BackendException`; unidbg encodes thread switches, context pops and stop
//!   requests as Java exceptions, which are values here (plan D5).
//! * Read and write hooks take a [`MemHookCtx`] rather than the whole backend:
//!   a per-access hook fires *inside* the in-flight instruction, where the CPU
//!   core is mutably borrowed and cannot be aliased into the hook. The context
//!   still carries the PC, guest memory access and the stop flag, which is
//!   everything unidbg's `ReadHook`/`WriteHook` can use except registers.
//!   Register access is available to code, block, interrupt and event-memory
//!   hooks, which run between instructions.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::reg::RegId;

/// Handle of a registered hook.
pub type HookId = u64;

/// Handle of a saved CPU context.
pub type ContextId = u32;

/// Memory protection bits, matching unidbg's `PROT_*` arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Prot(u8);

impl Prot {
    /// No access.
    pub const NONE: Prot = Prot(0);
    /// `PROT_READ`.
    pub const READ: Prot = Prot(1);
    /// `PROT_WRITE`.
    pub const WRITE: Prot = Prot(2);
    /// `PROT_EXEC`.
    pub const EXEC: Prot = Prot(4);

    /// Builds a protection set from raw bits.
    pub const fn from_bits(bits: u8) -> Self {
        Prot(bits & 7)
    }

    /// The raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every bit of `other` is present.
    pub const fn contains(self, other: Prot) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two protection sets.
    pub const fn union(self, other: Prot) -> Self {
        Prot(self.0 | other.0)
    }

    /// The intersection of two protection sets.
    pub const fn intersection(self, other: Prot) -> Self {
        Prot(self.0 & other.0)
    }

    /// Whether this set grants no access at all.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Prot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;
        for (bit, name) in [(Prot::READ, 'r'), (Prot::WRITE, 'w'), (Prot::EXEC, 'x')] {
            if self.contains(bit) {
                f.write_fmt(format_args!("{name}"))?;
                wrote = true;
            }
        }
        if !wrote {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// Why a guest memory access failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryFaultKind {
    /// No mapping covers the address.
    Unmapped,
    /// A mapping covers the address but forbids the access.
    Permission,
    /// The access is misaligned for its size.
    Alignment,
    /// The backing store failed.
    Bus,
}

impl fmt::Display for MemoryFaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MemoryFaultKind::Unmapped => "unmapped",
            MemoryFaultKind::Permission => "permission denied",
            MemoryFaultKind::Alignment => "misaligned",
            MemoryFaultKind::Bus => "bus error",
        })
    }
}

/// Why a guest memory access failed, with the address it failed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryFault {
    /// The address that faulted.
    pub addr: u64,
    /// The access size in bytes.
    pub size: usize,
    /// The kind of failure.
    pub kind: MemoryFaultKind,
}

impl fmt::Display for MemoryFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} access of {} byte(s) at {:#x}",
            self.kind, self.size, self.addr
        )
    }
}

impl std::error::Error for MemoryFault {}

/// A backend operation that failed.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The register does not exist in the backend's ISA.
    #[error("register {0} does not exist in this backend")]
    UnsupportedRegister(RegId),
    /// The register index is out of range.
    #[error("register index {reg} is out of range (max {max})")]
    RegisterOutOfRange {
        /// The offending index.
        reg: u8,
        /// The highest valid index.
        max: u8,
    },
    /// A guest memory access failed.
    #[error("{0}")]
    Memory(#[from] MemoryFault),
    /// A mapping operation failed.
    #[error("cannot map {size:#x} bytes at {addr:#x}: {reason}")]
    Map {
        /// The requested base address.
        addr: u64,
        /// The requested length.
        size: u64,
        /// Why the mapping failed.
        reason: String,
    },
    /// The operation requires a running emulator.
    #[error("emulation is not running")]
    NotRunning,
    /// The backend is already running.
    #[error("emulation is already running")]
    AlreadyRunning,
    /// The backend rejected the operation for an ISA-specific reason.
    #[error("{0}")]
    Other(String),
}

/// Why a run loop returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Execution reached the `until` address; the instruction there did not run.
    Until,
    /// The instruction budget ran out.
    Count,
    /// The host-time limit ran out.
    Timeout,
    /// A hook (or the host) called [`Backend::emu_stop`].
    Stopped,
    /// The guest executed a `WFI`/`WFE` with nothing left to do.
    Idle,
}

impl fmt::Display for RunOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RunOutcome::Until => "reached the stop address",
            RunOutcome::Count => "instruction count exhausted",
            RunOutcome::Timeout => "timeout",
            RunOutcome::Stopped => "stopped",
            RunOutcome::Idle => "idle",
        })
    }
}

/// A control-flow event that unwinds the run loop.
///
/// unidbg models these as Java exceptions
/// (`ThreadContextSwitchException`, `PopContextException`,
/// `StopEmulatorException`, `LongJumpException`); here they are values that
/// propagate up the run-loop stack (plan D5).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The running guest thread must be swapped out (plan D4).
    #[error("thread context switch")]
    ThreadSwitch,
    /// The current emulation context is finished and must be popped.
    #[error("pop context")]
    PopContext,
    /// Emulation must stop entirely.
    #[error("emulation stopped")]
    StopEmulator,
    /// A guest `longjmp`: unwind to a saved host-side context.
    #[error("longjmp to {value:#x} (errno {errno})")]
    LongJump {
        /// The value the `setjmp` call will observe.
        value: i64,
        /// The errno to restore.
        errno: i32,
    },
    /// The guest touched memory that is not mapped and no hook fixed it.
    #[error("unmapped memory access at {addr:#x} (size {size}) from pc {pc:#x}")]
    UnmappedMemory {
        /// The faulting address.
        addr: u64,
        /// The access size in bytes.
        size: usize,
        /// The program counter of the faulting instruction.
        pc: u64,
    },
    /// The backend itself failed.
    #[error(transparent)]
    Backend(#[from] BackendError),
}

/// The kind of access that faulted, as delivered to an [`EventMemHook`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmappedKind {
    /// A load.
    Read,
    /// A store.
    Write,
    /// An instruction fetch.
    Fetch,
}

impl fmt::Display for UnmappedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UnmappedKind::Read => "read",
            UnmappedKind::Write => "write",
            UnmappedKind::Fetch => "fetch",
        })
    }
}

/// Host-side access to guest memory that does not borrow the backend.
///
/// A syscall handler runs with the backend already mutably borrowed by the run
/// loop (plan P2.6), so it cannot reach memory through
/// [`Backend::mem_read`]/[`Backend::mem_write`]: that would be a second borrow
/// of the same cell. The address space itself is shared (`Arc` inside rax) and
/// has no such restriction, so the loader holds one of these instead.
pub trait GuestMemory: Send + Sync {
    /// Reads `buf.len()` bytes, ignoring guest permissions.
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault>;
    /// Writes `data`, ignoring guest permissions.
    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault>;
    /// Maps `[addr, addr + size)`.
    fn map(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError>;
    /// Changes the protection of `[addr, addr + size)`.
    fn protect(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError>;
    /// Unmaps `[addr, addr + size)`.
    fn unmap(&self, addr: u64, size: u64) -> Result<(), BackendError>;
}

/// Guest memory as seen by a [`MemHookCtx`].
pub trait GuestMemoryAccess {
    /// Reads `buf.len()` bytes from `addr`.
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault>;
    /// Writes `data` at `addr`.
    fn write(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault>;
}

/// The context handed to a per-access read or write hook.
///
/// See the module docs for why this is not the full backend.
pub struct MemHookCtx<'a> {
    pc: u64,
    mem: &'a dyn GuestMemoryAccess,
    stop: &'a AtomicBool,
}

impl<'a> MemHookCtx<'a> {
    /// Creates a context for an access made by the instruction at `pc`.
    pub fn new(pc: u64, mem: &'a dyn GuestMemoryAccess, stop: &'a AtomicBool) -> Self {
        MemHookCtx { pc, mem, stop }
    }

    /// The program counter of the instruction making the access.
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Reads guest memory.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        self.mem.read(addr, buf)
    }

    /// Writes guest memory.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        self.mem.write(addr, data)
    }

    /// Asks the run loop to stop as soon as the current instruction retires.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Whether a stop has already been requested.
    pub fn is_stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// Shared run-loop control flag.
///
/// Cloned into the memory bridge so a per-access hook can request a stop, and
/// into the backend so the host can (`emu_stop`).
#[derive(Clone, Debug, Default)]
pub struct RunControl {
    stop: Arc<AtomicBool>,
}

impl RunControl {
    /// A fresh, unset control flag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests a stop.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Clears a previous stop request.
    pub fn clear(&self) {
        self.stop.store(false, Ordering::Relaxed);
    }

    /// Whether a stop was requested.
    pub fn is_stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// The underlying flag, for handing to a [`MemHookCtx`].
    pub fn flag(&self) -> &AtomicBool {
        &self.stop
    }
}

/// Called before the instruction at `address` executes.
///
/// Port of unidbg: `.../arm/backend/CodeHook.java`. A hook may change the PC
/// and registers through the backend it is handed.
pub trait CodeHook {
    /// Handles one instruction boundary.
    fn hook(&mut self, backend: &mut dyn Backend, address: u64, size: u32);
}

/// Called at the start of a basic block.
///
/// Port of unidbg: `.../arm/backend/BlockHook.java`.
pub trait BlockHook {
    /// Handles one basic-block entry.
    fn hook_block(&mut self, backend: &mut dyn Backend, address: u64, size: u32);
}

/// Called after every guest load.
///
/// Port of unidbg: `.../arm/backend/ReadHook.java` (which also has no value
/// parameter; a hook that wants to change what was read writes guest memory).
pub trait ReadHook {
    /// Handles one load of `size` bytes at `address`.
    fn hook(&mut self, ctx: &mut MemHookCtx<'_>, address: u64, size: usize);
}

/// Called after every guest store.
///
/// Port of unidbg: `.../arm/backend/WriteHook.java`.
pub trait WriteHook {
    /// Handles one store of `size` bytes at `address`.
    fn hook(&mut self, ctx: &mut MemHookCtx<'_>, address: u64, size: usize, value: u64);
}

/// Called when the guest touches memory that is not accessible.
///
/// Port of unidbg: `.../arm/backend/EventMemHook.java`. Returning `true` after
/// mapping the page makes the run loop retry the faulting instruction;
/// returning `false` turns the fault into
/// [`RunError::UnmappedMemory`].
pub trait EventMemHook {
    /// Handles one faulting access.
    fn hook(
        &mut self,
        backend: &mut dyn Backend,
        address: u64,
        size: usize,
        value: u64,
        kind: UnmappedKind,
    ) -> bool;
}

/// Called for `SVC`, `BRK` and undefined-instruction traps.
///
/// Port of unidbg: `.../arm/backend/InterruptHook.java`. `intno` is a unicorn
/// exception number ([`EXCP_UDEF`], [`EXCP_BKPT`], [`EXCP_SWI`]) and `swi` is
/// the trap immediate.
pub trait InterruptHook {
    /// Handles one trap.
    fn hook(&mut self, backend: &mut dyn Backend, intno: i32, swi: i32);
}

/// Undefined instruction (`EXCP_UDEF`).
pub const EXCP_UDEF: i32 = 0;
/// Breakpoint (`EXCP_BKPT`).
pub const EXCP_BKPT: i32 = 1;
/// Supervisor call (`EXCP_SWI`).
pub const EXCP_SWI: i32 = 2;

/// A guest CPU.
///
/// Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/Backend.java`.
/// The trait is object-safe so that host code can hold a
/// `Rc<RefCell<dyn Backend>>` (plan P2.6).
pub trait Backend {
    /// Finishes backend-specific initialization.
    fn on_initialize(&mut self);

    /// Switches the CPU to user mode (AArch32 `CPSR` mode / AArch64 EL0).
    fn switch_user_mode(&mut self);

    /// Enables the VFP/NEON unit.
    fn enable_vfp(&mut self);

    /// Reads a general-purpose register.
    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError>;

    /// Writes a general-purpose register.
    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError>;

    /// Reads a 128-bit vector register.
    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError>;

    /// Writes a 128-bit vector register.
    fn reg_write_vector(&mut self, reg: RegId, v: [u8; 16]) -> Result<(), BackendError>;

    /// Reads `size` bytes of guest memory.
    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError>;

    /// Reads `buf.len()` bytes of guest memory into `buf`.
    ///
    /// The default allocates through [`Backend::mem_read`]; backends override it
    /// to fill `buf` directly, which is what `Pointer`'s typed accessors use.
    fn mem_read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), BackendError> {
        let bytes = self.mem_read(addr, buf.len())?;
        buf.copy_from_slice(&bytes);
        Ok(())
    }

    /// Writes guest memory.
    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError>;

    /// Maps guest memory.
    fn mem_map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError>;

    /// Changes the protection of an existing mapping.
    fn mem_protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError>;

    /// Unmaps guest memory.
    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError>;

    /// Registers a code hook for `[begin, end]`.
    fn hook_add_code(&mut self, cb: Box<dyn CodeHook>, begin: u64, end: u64) -> HookId;

    /// Registers a basic-block hook for `[begin, end]`.
    fn hook_add_block(&mut self, cb: Box<dyn BlockHook>, begin: u64, end: u64) -> HookId;

    /// Registers a read hook for `[begin, end]`.
    ///
    /// The callback must be `Send`: read and write hooks live in the memory
    /// bridge, which rax's `ArmMemory` requires to be `Send + Sync`.
    fn hook_add_read(&mut self, cb: Box<dyn ReadHook + Send>, begin: u64, end: u64) -> HookId;

    /// Registers a write hook for `[begin, end]`. See [`Backend::hook_add_read`]
    /// for the `Send` requirement.
    fn hook_add_write(&mut self, cb: Box<dyn WriteHook + Send>, begin: u64, end: u64) -> HookId;

    /// Registers a hook for faulting accesses of `kind`.
    fn hook_add_event_mem(&mut self, cb: Box<dyn EventMemHook>, kind: UnmappedKind) -> HookId;

    /// Registers a trap hook.
    fn hook_add_interrupt(&mut self, cb: Box<dyn InterruptHook>) -> HookId;

    /// Removes a hook.
    fn hook_del(&mut self, id: HookId);

    /// Runs from `begin` until `until` (exclusive), or until `count`
    /// instructions, or `timeout_us` microseconds, whichever comes first.
    ///
    /// `until == 0`, `timeout_us == 0` and `count == 0` each mean "no limit",
    /// matching unidbg's `emu_start` contract.
    fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_us: u64,
        count: u64,
    ) -> Result<RunOutcome, RunError>;

    /// Asks the current run to stop at the next instruction boundary.
    fn emu_stop(&mut self);

    /// Records a control-flow event for the run loop to unwind with.
    ///
    /// This is how a hook (the syscall handler, a thread-switch waiter) raises
    /// what unidbg raises as a Java exception: the run loop takes the event
    /// after the hook returns and ends the run with it (plan D5).
    fn set_pending_error(&mut self, error: RunError);

    /// Takes the pending control-flow event, if any.
    fn take_pending_error(&mut self) -> Option<RunError>;

    /// Whether a run is in progress.
    fn is_running(&self) -> bool;

    /// Snapshots the CPU state.
    fn context_save(&mut self) -> ContextId;

    /// Restores a previously saved snapshot.
    fn context_restore(&mut self, id: ContextId);

    /// Releases a snapshot slot.
    fn context_free(&mut self, id: ContextId);

    /// The guest page size.
    fn page_size(&self) -> usize;

    /// Discards any cached translation of `[begin, end)`.
    fn remove_jit_code_cache(&mut self, begin: u64, end: u64);
}
