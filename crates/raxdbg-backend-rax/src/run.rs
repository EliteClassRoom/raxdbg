//! The run loop, shared by both ISAs.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/UnicornBackend.java`
//! `emu_start`@7f5da98e, which delegates the loop to unicorn. rax has no such
//! entry point for user-mode embedders, so the loop lives here:
//!
//! * the instruction at `until` is **not** executed (unidbg's contract, which
//!   the `LR` trap page at `0x7ffff0000` relies on);
//! * `timeout_us == 0` and `count == 0` mean "no limit";
//! * `SVC`, `BRK` and undefined instructions go to the interrupt hooks with
//!   unicorn's exception numbers, `SVC` with the trap immediate;
//! * a faulting access goes to the event-memory hooks; one that reports it
//!   fixed the fault makes the loop retry the instruction (the core preserves
//!   the PC on a fault), otherwise the run ends with
//!   [`RunError::UnmappedMemory`];
//! * a hook that calls `emu_stop` (or a per-access hook that stops the
//!   context) ends the run with [`RunOutcome::Stopped`];
//! * a completed `WFI`/`WFE` ends the run with [`RunOutcome::Idle`], which is
//!   how a thread that has nothing to do yields to the cooperative scheduler.

use raxdbg_core::backend::{
    BackendError, EXCP_BKPT, EXCP_SWI, EXCP_UDEF, RunError, RunOutcome, UnmappedKind,
};

use crate::backend::RaxBackend;
use crate::cpu::CpuEvent;
use crate::time::host_micros;

/// How often the host clock is consulted for a run timeout. Reading the clock
/// costs more than an interpreted instruction, so the deadline is checked
/// every this many instructions.
const TIMEOUT_CHECK_INTERVAL: u64 = 1024;

/// Runs the guest as unidbg's `Backend.emu_start` does.
pub fn emu_start(
    backend: &mut RaxBackend,
    begin: u64,
    until: u64,
    timeout_us: u64,
    count: u64,
) -> Result<RunOutcome, RunError> {
    if backend.running {
        return Err(RunError::Backend(BackendError::AlreadyRunning));
    }
    let control = backend.shared.control().clone();
    control.clear();
    backend.pending = None;
    backend.cpu.set_pc(begin);
    backend.cpu.update_counter();
    backend.running = true;
    let outcome = run(backend, until, timeout_us, count);
    backend.running = false;
    outcome
}

fn run(
    backend: &mut RaxBackend,
    until: u64,
    timeout_us: u64,
    count: u64,
) -> Result<RunOutcome, RunError> {
    let control = backend.shared.control().clone();
    let deadline = (timeout_us > 0).then(|| host_micros().saturating_add(timeout_us));
    let mut executed = 0u64;
    // Address after the previous instruction; `u64::MAX` forces the next
    // instruction to count as a basic-block entry.
    let mut next_sequential = u64::MAX;

    loop {
        if control.is_stop_requested() {
            return Ok(RunOutcome::Stopped);
        }
        if let Some(error) = backend.pending.take() {
            return Err(error);
        }
        if count != 0 && executed >= count {
            return Ok(RunOutcome::Count);
        }
        if let Some(deadline) = deadline
            && executed.is_multiple_of(TIMEOUT_CHECK_INTERVAL)
            && host_micros() >= deadline
        {
            return Ok(RunOutcome::Timeout);
        }

        let pc = backend.cpu.pc();
        if until != 0 && pc == until {
            return Ok(RunOutcome::Until);
        }

        backend.dispatch_step_hooks(pc, 4, pc != next_sequential);
        if let Some(error) = backend.pending.take() {
            return Err(error);
        }
        // A code hook may have moved the PC (unidbg's replace-hook semantics).
        let pc = backend.cpu.pc();
        if until != 0 && pc == until {
            return Ok(RunOutcome::Until);
        }

        let event = backend.cpu.step();
        // A faulting access is retried, so it must not consume the budget: the
        // instruction has not retired yet.
        if !matches!(event, Some(CpuEvent::Fault(_))) {
            executed += 1;
        }
        let after = backend.cpu.pc();
        next_sequential = if after == pc.wrapping_add(2) || after == pc.wrapping_add(4) {
            after
        } else {
            u64::MAX
        };

        let Some(event) = event else {
            continue;
        };
        match event {
            CpuEvent::Svc { imm } => {
                if !backend.dispatch_interrupt_hooks(EXCP_SWI, imm as i32) {
                    return Err(unhandled("SVC", imm, pc));
                }
            }
            CpuEvent::Brk { imm } => {
                if !backend.dispatch_interrupt_hooks(EXCP_BKPT, imm as i32) {
                    return Err(unhandled("BRK", imm, pc));
                }
            }
            CpuEvent::Undefined { reason } => {
                if !backend.dispatch_interrupt_hooks(EXCP_UDEF, 0) {
                    return Err(RunError::Backend(BackendError::Other(format!(
                        "undefined instruction at {pc:#x}: {reason}"
                    ))));
                }
            }
            CpuEvent::Fault(fault) => {
                let kind = match fault.access {
                    rax::error::MemoryAccessKind::Fetch => UnmappedKind::Fetch,
                    rax::error::MemoryAccessKind::Write => UnmappedKind::Write,
                    rax::error::MemoryAccessKind::Read => UnmappedKind::Read,
                };
                // rax reports the faulting address but not the access width, so
                // hooks that need the width read it from the instruction.
                if !backend.dispatch_event_hooks(fault.addr, 0, 0, kind) {
                    return Err(RunError::UnmappedMemory {
                        addr: fault.addr,
                        size: 0,
                        pc: fault.pc,
                    });
                }
            }
            CpuEvent::Idle => return Ok(RunOutcome::Idle),
            CpuEvent::Internal(reason) => {
                return Err(RunError::Backend(BackendError::Other(reason)));
            }
        }
        if let Some(error) = backend.pending.take() {
            return Err(error);
        }
    }
}

fn unhandled(trap: &str, imm: u32, pc: u64) -> RunError {
    RunError::Backend(BackendError::Other(format!(
        "unhandled {trap} #{imm:#x} at {pc:#x}: no interrupt hook is registered"
    )))
}
