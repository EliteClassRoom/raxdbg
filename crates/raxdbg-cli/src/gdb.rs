//! The remote GDB debugging server.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/debugger/gdb/`
//! — `GdbStub`, `AbstractDebugServer` and the per-command handlers — against the
//! GDB remote serial protocol (`sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol`)
//! rather than unidbg's own framing.
//!
//! Where unidbg runs its socket on a second thread and parks the emulation
//! thread on a semaphore, raxdbg's backend is `Rc<RefCell<dyn Backend>>`: it is
//! neither `Send` nor `Sync`, so the protocol loop and the guest run on the
//! same thread and the run loop is entered straight from
//! [`BlockingEventLoop::wait_for_stop_reason`]. One consequence is visible to a
//! client: `Ctrl-C` is delivered when the run loop next hands control back,
//! not asynchronously inside a guest instruction.
//!
//! The session drives one guest call — the `--call` the CLI resolved — set up
//! but not yet run, exactly as unidbg's `attach(GDB_SERVER)` parks before the
//! first instruction. It reports a single thread because that is what it
//! drives; the emulator's cooperative guest threads are not scheduled here.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::rc::Rc;

use gdbstub::common::Signal;
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccess;
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccessOps;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use raxdbg_android::emulator::{AndroidEmulator, PreparedFunctionCall};
use raxdbg_core::backend::{Backend, BackendError, RunError, RunOutcome};
use raxdbg_core::debug::{BreakPoint, Breaker, BreakerImpl};
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;

use crate::options::Options;
use crate::{boot, resolve_callable};

/// The `EFAULT` a memory access the guest cannot satisfy answers with.
///
/// gdbstub sends `TargetError::Errno(code)` verbatim, and GDB reads the code
/// as an `errno`, so an unmapped address is EFAULT rather than a generic error.
const EFAULT: u8 = 14;

/// Serves one GDB session for `library` on `port`.
///
/// The library is loaded and the `--call` target is resolved before the
/// listener is bound, so a name that does not resolve is reported before the
/// user is told where to connect.
pub fn debug_session(options: &Options, library: &str, port: u16) -> Result<(), String> {
    let (emulator, _) = boot(options, library)?;
    let call = options
        .call
        .as_ref()
        .ok_or_else(|| "the GDB server needs a --call to stop at".to_string())?;
    let address = resolve_callable(&emulator, call)?;
    // Set the call up now and leave it unrun: the client attaches to a guest
    // stopped at the callee's first instruction.
    let prepared = emulator
        .prepare_function_call(address, &options.call_arguments)
        .map_err(|error| format!("preparing {}: {error}", call.name))?;

    let bind: IpAddr = options
        .gdb_bind
        .parse()
        .map_err(|_| "--gdb-bind needs an IP address".to_string())?;
    let listener = TcpListener::bind(SocketAddr::new(bind, port))
        .map_err(|error| format!("GDB server: cannot listen on {bind}:{port}: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("GDB server: {error}"))?;
    eprintln!("gdb server listening on {local}; connect with: target remote {local}");

    let (stream, _) = listener
        .accept()
        .map_err(|error| format!("GDB server: {error}"))?;
    serve(stream, emulator, prepared)
}

/// Drives the stub over one connection, then cleans the guest up.
///
/// The session can end any of several ways, and only one of them is the guest
/// call finishing on its own. Whichever it was, the breakpoints GDB installed
/// and the stack frame the call reserved have to be given back, so both are
/// released here rather than on the path that happens to feel like the end.
fn serve(
    stream: TcpStream,
    emulator: Rc<AndroidEmulator>,
    prepared: PreparedFunctionCall,
) -> Result<(), String> {
    let trap = emulator.trap_address();
    let (outcome, cleanup) = if emulator.is_64bit() {
        let mut target = Target64::new(emulator, prepared, trap);
        let outcome = GdbStub::new(stream).run_blocking::<Arm64EventLoop>(&mut target);
        let cleanup = Cleanup::new(
            target.state.breaker.clone(),
            std::mem::take(&mut target.state.breakpoints),
            target.state.call.take(),
        );
        (outcome, cleanup)
    } else {
        let mut target = Target32::new(emulator, prepared, trap);
        let outcome = GdbStub::new(stream).run_blocking::<Arm32EventLoop>(&mut target);
        let cleanup = Cleanup::new(
            target.state.breaker.clone(),
            std::mem::take(&mut target.state.breakpoints),
            target.state.call.take(),
        );
        (outcome, cleanup)
    };
    drop(cleanup);
    match outcome {
        Ok(DisconnectReason::Disconnect) | Ok(DisconnectReason::Kill) => {
            eprintln!("gdb: the client disconnected; the guest call was left unrun");
            Ok(())
        }
        Ok(DisconnectReason::TargetExited(code)) => {
            eprintln!("gdb: the guest call returned with exit status {code}");
            Ok(())
        }
        Ok(DisconnectReason::TargetTerminated(signal)) => {
            eprintln!("gdb: the guest call ended on signal {signal}");
            Ok(())
        }
        Err(error) if error.is_connection_error() => {
            let (io, kind) = error.into_connection_error().expect("a connection error");
            Err(format!("GDB server: {kind:?} failed: {io}"))
        }
        Err(error) if error.is_target_error() => Err(format!(
            "GDB server: {}",
            error.into_target_error().expect("a target error")
        )),
        Err(error) => Err(format!("GDB server: {error}")),
    }
}

/// What a finished session owes the emulator.
///
/// Dropped on every path out of [`serve`]: the breakpoints GDB installed and
/// the frame the call reserved are released together, so no way of ending the
/// session can leak one without the other.
struct Cleanup {
    breaker: Rc<RefCell<BreakerImpl>>,
    breakpoints: BTreeMap<u64, BreakPoint>,
    call: Option<PreparedFunctionCall>,
}

impl Cleanup {
    fn new(
        breaker: Rc<RefCell<BreakerImpl>>,
        breakpoints: BTreeMap<u64, BreakPoint>,
        call: Option<PreparedFunctionCall>,
    ) -> Self {
        Cleanup {
            breaker,
            breakpoints,
            call,
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for breakpoint in self.breakpoints.values() {
            self.breaker
                .borrow_mut()
                .remove_break_point(breakpoint.address());
        }
        if let Some(call) = self.call.take() {
            call.finish();
        }
    }
}

/// What the client asked for last: run, or run one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunMode {
    Continue,
    Step,
}

/// The guest state both ARM targets share.
///
/// The `Arch` of a gdbstub `Target` is a compile-time choice, so ARM64 and
/// ARM32 need two target types; this is everything they have in common.
struct TargetState {
    emulator: Rc<AndroidEmulator>,
    breaker: Rc<RefCell<BreakerImpl>>,
    /// The call the session is set up to run, and the frame it reserved.
    call: Option<PreparedFunctionCall>,
    /// The `LR` trap page a finished call branches to.
    trap: u64,
    /// Breakpoints GDB installed, kept so their hooks outlive the `Z0`.
    breakpoints: BTreeMap<u64, BreakPoint>,
    /// What `resume`/`step` asked for.
    mode: RunMode,
}

impl TargetState {
    fn new(emulator: Rc<AndroidEmulator>, call: PreparedFunctionCall, trap: u64) -> Self {
        let breaker = Rc::new(RefCell::new(BreakerImpl::new(Rc::clone(
            emulator.backend(),
        ))));
        TargetState {
            emulator,
            breaker,
            call: Some(call),
            trap,
            breakpoints: BTreeMap::new(),
            mode: RunMode::Continue,
        }
    }

    fn backend(&self) -> Rc<RefCell<dyn Backend>> {
        self.emulator.backend().clone()
    }

    /// Runs the guest and answers why it stopped.
    ///
    /// Every reason the run loop can end is classified here, because the
    /// protocol has no way to say "it stopped, and I do not know why" — GDB
    /// shows the reply verbatim. The address type is the target's, so ARM32's
    /// `u32` and ARM64's `u64` both come out of the same classification.
    fn run<U>(&mut self) -> Result<SingleThreadStopReason<U>, RunError> {
        let mode = std::mem::replace(&mut self.mode, RunMode::Continue);
        let count = u64::from(mode == RunMode::Step);
        let pc = self
            .backend()
            .borrow()
            .reg_read(RegId::Pc)
            .map_err(RunError::Backend)?;
        let backend = self.backend();
        let outcome = backend.borrow_mut().emu_start(pc, self.trap, 0, count)?;
        let pc = backend
            .borrow()
            .reg_read(RegId::Pc)
            .map_err(RunError::Backend)?;
        Ok(match outcome {
            // One instruction is the whole budget: GDB asked for one.
            RunOutcome::Count => SingleThreadStopReason::DoneStep,
            // A hook stopped the run, which for this session means a
            // breakpoint. Anywhere else, the guest asked to stop.
            RunOutcome::Stopped if self.breakpoints.contains_key(&pc) => {
                SingleThreadStopReason::SwBreak(())
            }
            RunOutcome::Stopped => SingleThreadStopReason::Signal(Signal::SIGSTOP),
            // The callee's `ret` reached the trap page: the call is over.
            RunOutcome::Until => {
                if let Some(call) = self.call.take() {
                    call.finish();
                }
                SingleThreadStopReason::Exited(0)
            }
            // A guest `WFI`/`WFE` with nothing to wake it.
            RunOutcome::Idle => SingleThreadStopReason::Signal(Signal::SIGSTOP),
            RunOutcome::Timeout => SingleThreadStopReason::Signal(Signal::SIGSTOP),
        })
    }

    /// Adds a breakpoint, refusing an address that already has one.
    ///
    /// `BreakerImpl` replaces the hook of an address it already holds, so a
    /// duplicate `Z0` would answer `OK` while leaving the old hook installed.
    fn add_breakpoint(&mut self, address: u64, thumb: bool) -> bool {
        let key = address & !1;
        if self.breakpoints.contains_key(&key) {
            return true;
        }
        let hook_address = if thumb { address | 1 } else { key };
        let breakpoint = self
            .breaker
            .borrow_mut()
            .add_break_point(hook_address, None);
        self.breakpoints.insert(key, breakpoint);
        true
    }

    fn remove_breakpoint(&mut self, address: u64) -> bool {
        let key = address & !1;
        let Some(breakpoint) = self.breakpoints.remove(&key) else {
            return false;
        };
        self.breaker
            .borrow_mut()
            .remove_break_point(breakpoint.address());
        true
    }

    /// Reads guest memory, or reports EFAULT for a range the guest cannot reach.
    ///
    /// Both directions go through the backend rather than the memory facade:
    /// a loaded module is mapped `READ | EXEC`, and the facade enforces the
    /// guest's own permissions. The backend deliberately does not — a
    /// debugger has to be able to write a breakpoint or a patched instruction
    /// into code, which is exactly what the loader itself does at load time.
    fn read_memory(&self, address: u64, data: &mut [u8]) -> ArmResult<usize> {
        let backend = self.backend();
        match backend.borrow().mem_read_into(address, data) {
            Ok(()) => Ok(data.len()),
            Err(_) => Err(TargetError::Errno(EFAULT)),
        }
    }

    /// Writes guest memory, all or nothing.
    ///
    /// The range is validated before any of it is written, so a rejected
    /// `M` packet leaves no partial store behind — which is what GDB assumes
    /// when it reads the range back.
    fn write_memory(&self, address: u64, data: &[u8]) -> ArmResult<()> {
        let mut probe = vec![0u8; data.len()];
        self.read_memory(address, &mut probe)?;
        let backend = self.backend();
        backend
            .borrow_mut()
            .mem_write(address, data)
            .map_err(|_| TargetError::Errno(EFAULT))
    }
}

/// A non-fatal target error, as gdbstub's `TargetResult` carries one.
type ArmResult<T> = Result<T, TargetError<RunError>>;

/// A register access the backend refused, as a protocol-level error.
///
/// The backend answers EFAULT for memory and its own error kinds for
/// registers; neither is meaningful to GDB, which wants the transfer refused
/// so it falls back to another way of reading the value.
fn reg<T>(value: Result<T, BackendError>) -> ArmResult<T> {
    value.map_err(|_| TargetError::NonFatal)
}

/// The AArch64 GDB target.
struct Target64 {
    state: TargetState,
}

impl Target64 {
    fn new(emulator: Rc<AndroidEmulator>, call: PreparedFunctionCall, trap: u64) -> Self {
        Target64 {
            state: TargetState::new(emulator, call, trap),
        }
    }
}

/// The AArch32 GDB target.
struct Target32 {
    state: TargetState,
}

impl Target32 {
    fn new(emulator: Rc<AndroidEmulator>, call: PreparedFunctionCall, trap: u64) -> Self {
        Target32 {
            state: TargetState::new(emulator, call, trap),
        }
    }
}

impl Target for Target64 {
    type Arch = gdbstub_arch::aarch64::AArch64;
    type Error = RunError;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl Target for Target32 {
    type Arch = gdbstub_arch::arm::Armv4t;
    type Error = RunError;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

/// GDB's `cpsr` for AArch64: the NZCV bits where the architecture keeps them.
///
/// raxdbg's register model holds `NZCV` as a four-bit value, while GDB's
/// AArch64 core description is a 32-bit process-state register with the
/// condition flags in bits 31:28. Only those bits are real here, so the rest
/// reads as zero rather than as invented state.
fn cpsr_to_gdb(nzcv: u64) -> u32 {
    ((nzcv & 0xf) as u32) << 28
}

/// The GDB side of a `cpsr`, narrowed to the condition flags.
fn cpsr_from_gdb(cpsr: u32) -> u64 {
    u64::from(cpsr >> 28)
}

impl SingleThreadBase for Target64 {
    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::aarch64::reg::AArch64CoreRegs,
    ) -> ArmResult<()> {
        let backend = self.state.backend();
        let backend = backend.borrow();
        for (index, slot) in regs.x.iter_mut().enumerate() {
            *slot = reg(backend.reg_read(RegId::X(index as u8)))?;
        }
        regs.sp = reg(backend.reg_read(RegId::Sp))?;
        regs.pc = reg(backend.reg_read(RegId::Pc))?;
        regs.cpsr = cpsr_to_gdb(reg(backend.reg_read(RegId::Nzcv))?);
        for (index, slot) in regs.v.iter_mut().enumerate() {
            *slot = u128::from_le_bytes(reg(backend.reg_read_vector(RegId::Q(index as u8)))?);
        }
        regs.fpcr = reg(backend.fpcr_read())?;
        regs.fpsr = reg(backend.fpsr_read())?;
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::aarch64::reg::AArch64CoreRegs,
    ) -> ArmResult<()> {
        // The stack pointer goes through the memory facade, and that reaches
        // the backend itself, so it must happen before this borrow — the cell
        // would already be taken otherwise.
        self.state.emulator.memory().set_stack_point(regs.sp);
        let backend = self.state.backend();
        let mut backend = backend.borrow_mut();
        for (index, value) in regs.x.iter().enumerate() {
            reg(backend.reg_write(RegId::X(index as u8), *value))?;
        }
        reg(backend.reg_write(RegId::Pc, regs.pc))?;
        reg(backend.reg_write(RegId::Nzcv, cpsr_from_gdb(regs.cpsr)))?;
        for (index, value) in regs.v.iter().enumerate() {
            reg(backend.reg_write_vector(RegId::Q(index as u8), value.to_le_bytes()))?;
        }
        reg(backend.fpcr_write(regs.fpcr))?;
        reg(backend.fpsr_write(regs.fpsr))?;
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
        self.state.read_memory(start_addr, data)
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
        self.state.write_memory(start_addr, data)
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }
}

impl SingleThreadResume for Target64 {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), RunError> {
        if signal.is_some() {
            // Delivering a signal to the guest means injecting it into the
            // instruction stream, which this backend does not model.
            return Err(RunError::Backend(
                raxdbg_core::backend::BackendError::Other(
                    "continuing with a signal is not supported".into(),
                ),
            ));
        }
        self.state.mode = RunMode::Continue;
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for Target64 {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), RunError> {
        if signal.is_some() {
            return Err(RunError::Backend(
                raxdbg_core::backend::BackendError::Other(
                    "stepping with a signal is not supported".into(),
                ),
            ));
        }
        self.state.mode = RunMode::Step;
        Ok(())
    }
}

impl Breakpoints for Target64 {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for Target64 {
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        // AArch64 instructions are fixed at four bytes and never interwork, so
        // the kind carries nothing this backend has to act on.
        Ok(self.state.add_breakpoint(addr, false))
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        Ok(self.state.remove_breakpoint(addr))
    }
}

impl SingleRegisterAccess<()> for Target64 {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        use gdbstub_arch::aarch64::reg::id::AArch64RegId;
        let value = match reg_id {
            AArch64RegId::X(index) => reg(self.state.backend().borrow().reg_read(RegId::X(index)))?,
            AArch64RegId::Sp => reg(self.state.backend().borrow().reg_read(RegId::Sp))?,
            AArch64RegId::Pc => reg(self.state.backend().borrow().reg_read(RegId::Pc))?,
            AArch64RegId::Pstate => {
                cpsr_to_gdb(reg(self.state.backend().borrow().reg_read(RegId::Nzcv))?) as u64
            }
            AArch64RegId::V(index) => u128::from_le_bytes(reg(self
                .state
                .backend()
                .borrow()
                .reg_read_vector(RegId::Q(index)))?) as u64,
            AArch64RegId::FPSR => u64::from(reg(self.state.backend().borrow().fpsr_read())?),
            AArch64RegId::FPCR => u64::from(reg(self.state.backend().borrow().fpcr_read())?),
            // System registers are advertised by the target description but
            // the backend models none of them.
            _ => return Err(TargetError::NonFatal),
        };
        let width = buf.len().min(8);
        buf[..width].copy_from_slice(&value.to_le_bytes()[..width]);
        Ok(width)
    }

    fn write_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        use gdbstub_arch::aarch64::reg::id::AArch64RegId;
        let mut word = [0u8; 8];
        let width = val.len().min(8);
        word[..width].copy_from_slice(&val[..width]);
        let value = u64::from_le_bytes(word);
        let backend = self.state.backend();
        match reg_id {
            AArch64RegId::X(index) => reg(backend.borrow_mut().reg_write(RegId::X(index), value)),
            AArch64RegId::Sp => {
                self.state.emulator.memory().set_stack_point(value);
                Ok(())
            }
            AArch64RegId::Pc => reg(backend.borrow_mut().reg_write(RegId::Pc, value)),
            AArch64RegId::Pstate => reg(backend
                .borrow_mut()
                .reg_write(RegId::Nzcv, cpsr_from_gdb(value as u32))),
            AArch64RegId::V(index) => {
                let mut bytes = [0u8; 16];
                let width = val.len().min(16);
                bytes[..width].copy_from_slice(&val[..width]);
                reg(backend
                    .borrow_mut()
                    .reg_write_vector(RegId::Q(index), bytes))
            }
            AArch64RegId::FPSR => reg(backend.borrow_mut().fpsr_write(value as u32)),
            AArch64RegId::FPCR => reg(backend.borrow_mut().fpcr_write(value as u32)),
            _ => Err(TargetError::NonFatal),
        }
    }
}

impl SingleThreadBase for Target32 {
    fn read_registers(&mut self, regs: &mut gdbstub_arch::arm::reg::ArmCoreRegs) -> ArmResult<()> {
        let backend = self.state.backend();
        let backend = backend.borrow();
        for (index, slot) in regs.r.iter_mut().enumerate() {
            *slot = reg(backend.reg_read(RegId::R(index as u8)))? as u32;
        }
        regs.sp = reg(backend.reg_read(RegId::Sp))? as u32;
        regs.lr = reg(backend.reg_read(RegId::Lr))? as u32;
        regs.pc = reg(backend.reg_read(RegId::Pc))? as u32;
        regs.cpsr = reg(backend.reg_read(RegId::Cpsr))? as u32;
        Ok(())
    }

    fn write_registers(&mut self, regs: &gdbstub_arch::arm::reg::ArmCoreRegs) -> ArmResult<()> {
        // The stack pointer goes through the memory facade, and that reaches
        // the backend itself, so it must happen before this borrow — the cell
        // would already be taken otherwise.
        self.state
            .emulator
            .memory()
            .set_stack_point(u64::from(regs.sp));
        let backend = self.state.backend();
        let mut backend = backend.borrow_mut();
        for (index, value) in regs.r.iter().enumerate() {
            reg(backend.reg_write(RegId::R(index as u8), u64::from(*value)))?;
        }
        reg(backend.reg_write(RegId::Lr, u64::from(regs.lr)))?;
        // `RegId::Pc` is where the Thumb bit lives: bit 0 selects T32, which
        // is how AArch32 interworks, and a debugger sets it that way.
        reg(backend.reg_write(RegId::Pc, u64::from(regs.pc)))?;
        reg(backend.reg_write(RegId::Cpsr, u64::from(regs.cpsr)))?;
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<usize, Self> {
        self.state.read_memory(u64::from(start_addr), data)
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        self.state.write_memory(u64::from(start_addr), data)
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }
}

impl SingleThreadResume for Target32 {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), RunError> {
        if signal.is_some() {
            return Err(RunError::Backend(
                raxdbg_core::backend::BackendError::Other(
                    "continuing with a signal is not supported".into(),
                ),
            ));
        }
        self.state.mode = RunMode::Continue;
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for Target32 {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), RunError> {
        if signal.is_some() {
            return Err(RunError::Backend(
                raxdbg_core::backend::BackendError::Other(
                    "stepping with a signal is not supported".into(),
                ),
            ));
        }
        self.state.mode = RunMode::Step;
        Ok(())
    }
}

impl Breakpoints for Target32 {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for Target32 {
    fn add_sw_breakpoint(
        &mut self,
        addr: u32,
        kind: gdbstub_arch::arm::ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        // A Thumb address has bit 0 set; `BreakerImpl` reads that bit as the
        // instruction set and strips it for the hook's own address.
        let thumb = matches!(
            kind,
            gdbstub_arch::arm::ArmBreakpointKind::Thumb16
                | gdbstub_arch::arm::ArmBreakpointKind::Thumb32
        );
        Ok(self.state.add_breakpoint(u64::from(addr), thumb))
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u32,
        _kind: gdbstub_arch::arm::ArmBreakpointKind,
    ) -> TargetResult<bool, Self> {
        Ok(self.state.remove_breakpoint(u64::from(addr)))
    }
}

impl SingleRegisterAccess<()> for Target32 {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        use gdbstub_arch::arm::reg::id::ArmCoreRegId;
        let value = match reg_id {
            ArmCoreRegId::Gpr(index) => {
                reg(self.state.backend().borrow().reg_read(RegId::R(index)))?
            }
            ArmCoreRegId::Sp => reg(self.state.backend().borrow().reg_read(RegId::Sp))?,
            ArmCoreRegId::Lr => reg(self.state.backend().borrow().reg_read(RegId::Lr))?,
            // The PC reads back without its Thumb bit, because `RegId::Pc`
            // stores the even address and the state lives in the CPSR's T bit.
            ArmCoreRegId::Pc => reg(self.state.backend().borrow().reg_read(RegId::Pc))?,
            ArmCoreRegId::Cpsr => reg(self.state.backend().borrow().reg_read(RegId::Cpsr))?,
            // The historical FPA registers sit between the PC and the CPSR in
            // the packet; this emulator has no FPA state for them, and neither
            // does any register the enum may grow later.
            _ => return Err(TargetError::NonFatal),
        };
        let width = buf.len().min(4);
        buf[..width].copy_from_slice(&(value as u32).to_le_bytes()[..width]);
        Ok(width)
    }

    fn write_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as gdbstub::arch::Arch>::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        use gdbstub_arch::arm::reg::id::ArmCoreRegId;
        let mut word = [0u8; 4];
        let width = val.len().min(4);
        word[..width].copy_from_slice(&val[..width]);
        let value = u64::from(u32::from_le_bytes(word));
        let backend = self.state.backend();
        match reg_id {
            ArmCoreRegId::Gpr(index) => reg(backend.borrow_mut().reg_write(RegId::R(index), value)),
            ArmCoreRegId::Sp => {
                self.state.emulator.memory().set_stack_point(value);
                Ok(())
            }
            ArmCoreRegId::Lr => reg(backend.borrow_mut().reg_write(RegId::Lr, value)),
            ArmCoreRegId::Pc => reg(backend.borrow_mut().reg_write(RegId::Pc, value)),
            ArmCoreRegId::Cpsr => reg(backend.borrow_mut().reg_write(RegId::Cpsr, value)),
            // The historical FPA registers have no state here to write.
            _ => Err(TargetError::NonFatal),
        }
    }
}

/// The AArch64 guest's blocking event loop.
struct Arm64EventLoop;

impl BlockingEventLoop for Arm64EventLoop {
    type Target = Target64;
    type Connection = TcpStream;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        _conn: &mut Self::Connection,
    ) -> Result<Event<Self::StopReason>, WaitForStopReasonError<RunError, std::io::Error>> {
        // There is no second thread to interrupt: the run below owns the
        // backend until it returns, and the connection is read again only
        // once the guest has stopped.
        target
            .state
            .run()
            .map(Event::TargetStopped)
            .map_err(WaitForStopReasonError::Target)
    }

    fn on_interrupt(_target: &mut Self::Target) -> Result<Option<Self::StopReason>, RunError> {
        // An interrupt that arrives while the guest is stopped is answered
        // here; one that arrives mid-run is read at the next loop boundary,
        // when `wait_for_stop_reason` has returned.
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

/// The AArch32 guest's blocking event loop.
struct Arm32EventLoop;

impl BlockingEventLoop for Arm32EventLoop {
    type Target = Target32;
    type Connection = TcpStream;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        _conn: &mut Self::Connection,
    ) -> Result<Event<Self::StopReason>, WaitForStopReasonError<RunError, std::io::Error>> {
        target
            .state
            .run()
            .map(Event::TargetStopped)
            .map_err(WaitForStopReasonError::Target)
    }

    fn on_interrupt(_target: &mut Self::Target) -> Result<Option<Self::StopReason>, RunError> {
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdbstub::target::ext::base::singlethread::SingleThreadBase;
    use raxdbg_android::emulator::AndroidEmulatorBuilder;

    /// Unwraps a target result. Its error type carries no `Debug`, so the
    /// failure is reported by variant rather than by formatting it.
    fn ok<T>(result: ArmResult<T>) -> T {
        match result {
            Ok(value) => value,
            Err(TargetError::Errno(code)) => {
                panic!("the target refused the request with errno {code}")
            }
            Err(_) => panic!("the target refused the request"),
        }
    }

    /// The workspace root, which is where the committed fixtures live.
    fn workspace_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root")
            .to_path_buf()
    }

    /// An emulator with a fixture loaded, stopped at a call of `symbol`.
    ///
    /// Returns the emulator, its `LR` trap page and the prepared call, so a
    /// test can build whichever target it is about.
    fn prepared_call(
        is_64bit: bool,
        abi: &str,
    ) -> (Rc<AndroidEmulator>, u64, PreparedFunctionCall) {
        let emulator = if is_64bit {
            AndroidEmulatorBuilder::for_64bit()
        } else {
            AndroidEmulatorBuilder::for_32bit()
        }
        .process_name("raxdbg-gdb-test")
        .sdk(23)
        .build()
        .expect("the emulator builds");
        let fixture = workspace_root().join(format!("fixtures/prebuilt/{abi}/libctest.so"));
        let file = raxdbg_android::android_file::ElfLibraryFile::open(&fixture)
            .expect("the fixture opens");
        emulator
            .load(Box::new(file), false)
            .expect("the fixture loads");
        let address = emulator
            .loader()
            .dlsym(0, "ctest_malloc_ok")
            .expect("ctest_malloc_ok is exported")
            .address;
        let trap = emulator.trap_address();
        let call = emulator
            .prepare_function_call(address, &[])
            .expect("the call is prepared");
        (emulator, trap, call)
    }

    /// An AArch64 emulator with the fixture loaded, stopped at a call.
    fn arm64_target() -> Target64 {
        let (emulator, trap, call) = prepared_call(true, "arm64-v8a");
        Target64::new(emulator, call, trap)
    }

    /// An AArch32 emulator with the fixture loaded, stopped at a call.
    fn arm32_target() -> Target32 {
        let (emulator, trap, call) = prepared_call(false, "armeabi-v7a");
        Target32::new(emulator, call, trap)
    }

    #[test]
    fn the_process_state_register_carries_the_condition_flags() {
        // GDB's AArch64 `cpsr` is a 32-bit process-state register with NZCV in
        // bits 31:28; raxdbg holds those four bits on their own. Round-tripping
        // through the mapping is what keeps `info registers cpsr` honest.
        for nzcv in 0u64..16 {
            assert_eq!(cpsr_from_gdb(cpsr_to_gdb(nzcv)), nzcv);
        }
        assert_eq!(cpsr_to_gdb(0b1010), 0xa000_0000);
        assert_eq!(cpsr_from_gdb(0xffff_ffff), 0xf);
    }

    #[test]
    fn arm64_registers_round_trip_through_the_gdb_layout() {
        let mut target = arm64_target();
        let backend = target.state.backend();
        backend
            .borrow_mut()
            .reg_write(RegId::X(7), 0x1122_3344_5566_7788)
            .unwrap();
        backend.borrow_mut().reg_write(RegId::Nzcv, 0b0101).unwrap();
        backend
            .borrow_mut()
            .reg_write_vector(RegId::Q(0), [7u8; 16])
            .unwrap();
        // Bit 24 is `FPCR.FZ`, one of the bits rax models; the reserved ones read
        // back as zero exactly as the hardware drops them.
        backend.borrow_mut().fpcr_write(1 << 24).unwrap();
        backend.borrow_mut().fpsr_write(1 << 0).unwrap();

        let mut regs = gdbstub_arch::aarch64::reg::AArch64CoreRegs::default();
        ok(target.read_registers(&mut regs));
        assert_eq!(regs.x[7], 0x1122_3344_5566_7788);
        assert_eq!(regs.cpsr, 0x5000_0000, "NZCV 0101 in bits 31:28");
        assert_eq!(regs.v[0], u128::from_le_bytes([7u8; 16]));
        assert_eq!(regs.fpcr, 1 << 24, "FZ survives the round trip");
        assert_eq!(regs.fpsr, 1 << 0, "IOC survives the round trip");

        // And the other direction, so a debugger can set them.
        regs.x[7] = 0xdead_beef_0000_0001;
        regs.cpsr = 0x3000_0000;
        regs.v[3] = u128::MAX;
        regs.fpcr = 0x2;
        ok(target.write_registers(&regs));
        let backend = target.state.backend();
        assert_eq!(
            backend.borrow().reg_read(RegId::X(7)).unwrap(),
            0xdead_beef_0000_0001
        );
        assert_eq!(backend.borrow().reg_read(RegId::Nzcv).unwrap(), 0b0011);
        assert_eq!(
            u128::from_le_bytes(backend.borrow().reg_read_vector(RegId::Q(3)).unwrap()),
            u128::MAX
        );
        assert_eq!(backend.borrow().fpcr_read().unwrap(), 2);
    }

    #[test]
    fn a_call_is_prepared_at_the_callee_without_running_it() {
        let target = arm64_target();
        let entry = target
            .state
            .backend()
            .borrow()
            .reg_read(RegId::Pc)
            .expect("the pc is readable");
        let symbol = target
            .state
            .emulator
            .loader()
            .dlsym(0, "ctest_malloc_ok")
            .expect("the symbol resolves")
            .address;
        assert_eq!(entry, symbol, "the guest is parked at the callee");
        // The link register points at the trap page, so the callee's `ret`
        // ends the call rather than returning to the host.
        assert_eq!(
            target.state.backend().borrow().reg_read(RegId::Lr).unwrap(),
            target.state.trap
        );
    }

    #[test]
    fn arm32_registers_round_trip_through_the_gdb_layout() {
        let mut target = arm32_target();
        let backend = target.state.backend();
        backend
            .borrow_mut()
            .reg_write(RegId::R(3), 0x1122_3344)
            .unwrap();
        backend
            .borrow_mut()
            .reg_write(RegId::Cpsr, 0x0000_0010)
            .unwrap();

        let mut regs = gdbstub_arch::arm::reg::ArmCoreRegs::default();
        ok(target.read_registers(&mut regs));
        assert_eq!(regs.r[3], 0x1122_3344);
        assert_eq!(regs.cpsr, 0x10, "User mode");

        regs.r[4] = 0x5566_7788;
        ok(target.write_registers(&regs));
        assert_eq!(
            target
                .state
                .backend()
                .borrow()
                .reg_read(RegId::R(4))
                .unwrap(),
            0x5566_7788
        );
    }

    #[test]
    fn writing_the_program_counter_selects_the_instruction_set() {
        // AArch32 interworks through bit 0: an odd PC is Thumb code. GDB sets
        // the register the way the architecture does, so the write has to land
        // through the backend rather than around it.
        let mut target = arm32_target();
        let even = target.state.backend().borrow().reg_read(RegId::Pc).unwrap();
        let mut regs = gdbstub_arch::arm::reg::ArmCoreRegs::default();
        ok(target.read_registers(&mut regs));
        // GDB sets both: the PC's bit 0 says "this is Thumb", and the CPSR's
        // T bit is the state the CPU actually runs in. The PC write derives
        // T, and the CPSR write follows, so both have to agree.
        regs.pc = (even | 1) as u32;
        regs.cpsr |= 1 << 5;
        ok(target.write_registers(&regs));

        let backend = target.state.backend();
        assert_eq!(
            backend.borrow().reg_read(RegId::Cpsr).unwrap() & (1 << 5),
            1 << 5,
            "the guest is in Thumb state"
        );
        assert_eq!(backend.borrow().reg_read(RegId::Pc).unwrap(), even & !1);
    }

    #[test]
    fn an_unreachable_address_is_e_fault_and_writes_nothing() {
        let target = arm64_target();
        // Address 1 is below every mapping the loader makes, so the read must
        // fail rather than answer zeroes for memory the guest cannot reach.
        let mut buffer = [0u8; 8];
        assert!(matches!(
            target.state.read_memory(1, &mut buffer),
            Err(TargetError::Errno(EFAULT))
        ));
        let mut buffer = [0u8; 8];
        target
            .state
            .read_memory(target.state.trap, &mut buffer)
            .ok()
            .expect("the trap page is mapped");
        assert_eq!(buffer.len(), 8);

        // A write into an address the guest cannot reach is refused whole, so no
        // part of it lands.
        assert!(matches!(
            target.state.write_memory(1, &[0xaa; 8]),
            Err(TargetError::Errno(EFAULT))
        ));

        // A mapped write does land, which is the case the refusal above has to
        // be told apart from.
        let mapped = target.state.backend().borrow().reg_read(RegId::Sp).unwrap();
        let mut before = [0u8; 4];
        ok(target.state.read_memory(mapped - 4, &mut before));
        ok(target.state.write_memory(mapped - 4, &[0xbb; 4]));
        let mut after = [0u8; 4];
        ok(target.state.read_memory(mapped - 4, &mut after));
        assert_eq!(&after[..], &[0xbb; 4], "a mapped write is visible");
    }

    #[test]
    fn a_duplicate_breakpoint_is_answered_without_a_second_hook() {
        // `BreakerImpl` replaces an address's hook rather than refusing it, so
        // a second `Z0` has to be answered here or the first hook leaks.
        let mut target = arm64_target();
        let address = 0x1000;
        assert!(target.state.add_breakpoint(address, false));
        assert_eq!(target.state.breakpoints.len(), 1);
        assert!(target.state.add_breakpoint(address, false));
        assert_eq!(target.state.breakpoints.len(), 1, "one entry, one hook");
        assert!(target.state.remove_breakpoint(address));
        assert!(!target.state.remove_breakpoint(address), "it is gone");
        assert!(target.state.breakpoints.is_empty());
    }
}
