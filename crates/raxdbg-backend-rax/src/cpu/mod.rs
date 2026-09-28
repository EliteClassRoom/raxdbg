//! User-mode CPU adapters.
//!
//! Each adapter drives one rax core in its unprivileged mode (AArch64 EL0,
//! AArch32 User) with raxdbg's memory bridge, and classifies the events the
//! core reports the way rax's own user-mode adapters do — see
//! [`RaxArm64Cpu`] and [`RaxArm32Cpu`].

pub mod aarch64;
pub mod arm32;

pub use aarch64::RaxArm64Cpu;
pub use arm32::RaxArm32Cpu;

use rax::isa::arm::common::cpu::ArmCpu;
use rax::user::cpu::AccessFault;

/// The event a single instruction ended with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpuEvent {
    /// A supervisor call; the PC is past it.
    Svc {
        /// The trap immediate.
        imm: u32,
    },
    /// A breakpoint; the PC is at it.
    Brk {
        /// The trap immediate.
        imm: u32,
    },
    /// An undefined instruction; the PC is at it.
    Undefined {
        /// Why the core rejected it.
        reason: String,
    },
    /// A faulting memory access; the PC is at the instruction.
    Fault(AccessFault),
    /// A completed `WFI`/`WFE`: nothing interrupts a user thread.
    Idle,
    /// The core failed in a way no guest program can cause.
    Internal(String),
}

/// A guest CPU of either supported ISA.
pub enum Cpu {
    /// AArch64 at EL0.
    Arm64(RaxArm64Cpu),
    /// AArch32 in User mode.
    Arm32(RaxArm32Cpu),
}

impl std::fmt::Debug for Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cpu::Arm64(cpu) => cpu.fmt(f),
            Cpu::Arm32(cpu) => cpu.fmt(f),
        }
    }
}

impl Cpu {
    /// The program counter.
    pub fn pc(&self) -> u64 {
        match self {
            Cpu::Arm64(cpu) => cpu.core().get_pc(),
            Cpu::Arm32(cpu) => u64::from(cpu.core().regs[15]),
        }
    }

    /// Sets the program counter.
    ///
    /// On AArch32 this has `BXWritePC` semantics (bit 0 selects T32), matching
    /// unidbg, which writes the PC through unicorn.
    pub fn set_pc(&mut self, pc: u64) {
        match self {
            Cpu::Arm64(cpu) => cpu.core_mut().set_pc(pc),
            Cpu::Arm32(cpu) => {
                let _ = cpu.write_reg(raxdbg_core::reg::RegId::Pc, pc);
            }
        }
    }

    /// Runs one instruction, normalising the two adapters' exit types.
    pub fn step(&mut self) -> Option<CpuEvent> {
        match self {
            Cpu::Arm64(cpu) => cpu.step().map(|exit| match exit {
                rax::user::cpu::aarch64::A64Exit::Svc { imm, .. } => CpuEvent::Svc {
                    imm: u32::from(imm),
                },
                rax::user::cpu::aarch64::A64Exit::Brk { imm, .. } => CpuEvent::Brk {
                    imm: u32::from(imm),
                },
                rax::user::cpu::aarch64::A64Exit::Undefined { reason, .. } => {
                    CpuEvent::Undefined { reason }
                }
                rax::user::cpu::aarch64::A64Exit::Fault(fault) => CpuEvent::Fault(fault),
                rax::user::cpu::aarch64::A64Exit::Yield => CpuEvent::Idle,
                rax::user::cpu::aarch64::A64Exit::Internal(reason) => CpuEvent::Internal(reason),
            }),
            Cpu::Arm32(cpu) => cpu.step().map(|exit| match exit {
                rax::user::cpu::arm::A32Exit::Svc { imm, .. } => CpuEvent::Svc { imm },
                rax::user::cpu::arm::A32Exit::Bkpt { imm, .. } => CpuEvent::Brk {
                    imm: u32::from(imm),
                },
                rax::user::cpu::arm::A32Exit::Undefined { reason, .. } => {
                    CpuEvent::Undefined { reason }
                }
                rax::user::cpu::arm::A32Exit::Fault(fault) => CpuEvent::Fault(fault),
                rax::user::cpu::arm::A32Exit::Yield => CpuEvent::Idle,
                rax::user::cpu::arm::A32Exit::Internal(reason) => CpuEvent::Internal(reason),
            }),
        }
    }

    /// Advances the guest's system counter to host time.
    pub fn update_counter(&mut self) {
        match self {
            Cpu::Arm64(cpu) => cpu.update_counter(),
            Cpu::Arm32(cpu) => cpu.update_counter(),
        }
    }

    /// Discards any compiled code after a code-invalidating change.
    pub fn invalidate_code(&mut self) {
        match self {
            Cpu::Arm64(cpu) => cpu.invalidate_code(),
            Cpu::Arm32(cpu) => cpu.invalidate_code(),
        }
    }

    /// Instructions retired since construction.
    pub fn instruction_count(&self) -> u64 {
        match self {
            Cpu::Arm64(cpu) => cpu.instruction_count(),
            Cpu::Arm32(cpu) => cpu.instruction_count(),
        }
    }
}
