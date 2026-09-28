//! AArch64 EL0 adapter over rax's AArch64 core.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/UnicornBackend.java`
//! (`emu_start`/`context`/`reg_*`)@7f5da98e, with the exit classification copied
//! verbatim from rax's own adapter, `rax/src/user/cpu/aarch64.rs@c468ca32`
//! (`A64UserCpu::run`/`run_inner`).
//!
//! Differences from rax's adapter, both required by unidbg's `Backend` contract:
//!
//! * memory accesses go through [`RaxMemory`], which dispatches raxdbg's
//!   read/write hooks, instead of rax's hook-free `UserArmMemory`;
//! * [`RaxArm64Cpu::step`] is public, so the run loop can check hooks, stop
//!   conditions and the trap address between instructions instead of running a
//!   blind budget.

use std::sync::Arc;

use rax::error::MemoryAccessKind;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{AccessType, ArmCpu, ArmError, CpuExit, MemoryFaultType};
use rax::user::cpu::aarch64::A64Exit;
use rax::user::cpu::{AccessFault, AccessFaultKind};
use raxdbg_core::backend::BackendError;
use raxdbg_core::reg::RegId;

use crate::hooks::MemShared;
use crate::memory::RaxMemory;
use crate::time::host_nanos;

/// An AArch64 EL0 CPU with raxdbg's memory hooks.
pub struct RaxArm64Cpu {
    cpu: AArch64Cpu,
    shared: Arc<MemShared>,
    /// Instructions retired since construction.
    insns: u64,
}

impl std::fmt::Debug for RaxArm64Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaxArm64Cpu")
            .field("pc", &self.cpu.get_pc())
            .field("insns", &self.insns)
            .finish()
    }
}

impl RaxArm64Cpu {
    /// Creates a CPU at EL0 with zeroed registers over `shared`'s address space.
    pub fn new(config: AArch64Config, shared: Arc<MemShared>) -> Self {
        // User mode has no asynchronous interrupts; dropping the controller
        // keeps the GIC lock off the step path (rax's adapter does the same).
        let config = AArch64Config {
            gic_config: None,
            ..config
        };
        let mut cpu = AArch64Cpu::new(config, Box::new(RaxMemory::new(Arc::clone(&shared))));
        cpu.enter_el0();
        // unidbg's `enableVFP`: CPACR_EL1.FPEN = 0b11, so EL0 may use FP/SIMD.
        cpu.set_cpacr_el1(cpu.cpacr_el1() | (0b11 << 20));
        RaxArm64Cpu {
            cpu,
            shared,
            insns: 0,
        }
    }

    /// A CPU for another thread of the same process, with this CPU's register
    /// state (rax's `A64UserCpu::clone_thread` field list).
    pub fn clone_thread(&self) -> Self {
        let mut child = RaxArm64Cpu::new(self.cpu.config().clone(), Arc::clone(&self.shared));
        child.cpu.set_counter_frequency(self.cpu.counter_frequency());
        child.cpu.set_cpacr_el1(self.cpu.cpacr_el1());
        for r in 0..31 {
            child.cpu.set_x(r, self.cpu.get_x(r));
        }
        child.cpu.set_current_sp(self.cpu.get_sp());
        child.cpu.set_pc(self.cpu.get_pc());
        child.cpu.set_nzcv_bits(self.cpu.nzcv_bits());
        for v in 0..32 {
            child.cpu.set_simd(v, self.cpu.get_simd(v));
        }
        child.cpu.set_fpcr_value(self.cpu.fpcr_value());
        child.cpu.set_fpsr_value(self.cpu.fpsr_value());
        child.cpu.set_tpidr_el0(self.cpu.tpidr_el0());
        child.cpu.set_tpidrro_el0(self.cpu.tpidrro_el0());
        child
    }

    /// The underlying core.
    pub fn core(&self) -> &AArch64Cpu {
        &self.cpu
    }

    /// Mutable access to the underlying core.
    pub fn core_mut(&mut self) -> &mut AArch64Cpu {
        &mut self.cpu
    }

    /// The shared memory bridge.
    pub fn shared(&self) -> &Arc<MemShared> {
        &self.shared
    }

    /// Instructions retired since construction.
    pub fn instruction_count(&self) -> u64 {
        self.insns
    }

    /// Advances the guest's system counter to host time, as rax's adapter does
    /// once per run slice (`ticks = ns * freq / 1e9`, in 128 bits).
    pub fn update_counter(&mut self) {
        let freq = u128::from(self.cpu.counter_frequency());
        let ticks = (u128::from(host_nanos()) * freq / 1_000_000_000) as u64;
        self.cpu.set_generic_counter(ticks);
    }

    /// Discards compiled code, for a code-cache-invalidating write or
    /// protection change.
    pub fn invalidate_code(&mut self) {
        self.cpu.clear_jit_cache();
    }

    /// Runs one instruction.
    ///
    /// `None` means the instruction retired with no operating-system-visible
    /// event; `Some` is the event that ended it.
    pub fn step(&mut self) -> Option<A64Exit> {
        let pc = self.cpu.get_pc();
        self.shared.set_pc(pc);
        self.insns += 1;
        match self.cpu.step() {
            Ok(CpuExit::Continue) => None,
            Ok(CpuExit::Svc(imm)) => Some(A64Exit::Svc {
                imm: imm as u16,
                pc,
            }),
            Ok(CpuExit::Breakpoint(imm)) => {
                // BRK retires with the PC advanced; the exception's preferred
                // return address is the BRK itself.
                self.cpu.set_pc(pc);
                Some(A64Exit::Brk {
                    imm: imm as u16,
                    pc,
                })
            }
            Ok(CpuExit::Hvc(_)) => Some(self.undefined(pc, "HVC at EL0".into())),
            Ok(CpuExit::Smc(_)) => Some(self.undefined(pc, "SMC at EL0".into())),
            Ok(CpuExit::Halt) => {
                // HLT without halting debug enabled is UNDEFINED.
                self.cpu.clear_halt();
                Some(self.undefined(pc, "HLT at EL0".into()))
            }
            Ok(CpuExit::Undefined(insn)) => {
                Some(self.undefined(pc, format!("undefined instruction {insn:#010x}")))
            }
            Ok(CpuExit::Wfi) | Ok(CpuExit::Wfe) => {
                // Linux lets EL0 execute WFI/WFE; with no interrupt source they
                // complete immediately. A wait usually spins on another thread,
                // so end the slice.
                self.cpu.clear_wait();
                Some(A64Exit::Yield)
            }
            Ok(other) => Some(A64Exit::Internal(format!(
                "unexpected AArch64 exit {other:?} at {pc:#x}"
            ))),
            Err(ArmError::MemoryError(info)) => {
                let access = match info.access {
                    AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                    AccessType::Read => MemoryAccessKind::Read,
                    AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
                };
                let kind = match info.fault_type {
                    MemoryFaultType::Translation | MemoryFaultType::AddressSize => {
                        AccessFaultKind::Unmapped
                    }
                    MemoryFaultType::Permission | MemoryFaultType::AccessFlag => {
                        AccessFaultKind::Permission
                    }
                    MemoryFaultType::Alignment => AccessFaultKind::Alignment,
                    _ => AccessFaultKind::Bus,
                };
                self.cpu.set_pc(pc);
                Some(A64Exit::Fault(AccessFault {
                    addr: info.address,
                    access,
                    kind,
                    pc,
                }))
            }
            Err(ArmError::UndefinedInstruction(insn)) => {
                Some(self.undefined(pc, format!("undefined instruction {insn:#010x}")))
            }
            Err(ArmError::InvalidExceptionLevel(_)) => {
                Some(self.undefined(pc, "EL1 system register or instruction at EL0".into()))
            }
            Err(ArmError::Unimplemented(what)) => Some(self.undefined(
                pc,
                format!("not implemented by the emulator: {what}"),
            )),
            Err(other) => Some(A64Exit::Internal(format!("{other} at {pc:#x}"))),
        }
    }

    /// Runs at most `budget` instructions, stopping at the first
    /// operating-system-visible event (rax's `A64UserCpu::run`).
    pub fn run(&mut self, budget: u64) -> A64Exit {
        self.update_counter();
        let exit = (0..budget)
            .find_map(|_| self.step())
            .unwrap_or(A64Exit::Yield);
        // A host budget yield (or a completed EL0 WFI/WFE) is not an
        // architectural exception; preserve the reservation. Anything else is
        // synchronous and clears it, as rax's adapter does.
        if !matches!(exit, A64Exit::Yield) {
            self.cpu.clear_exclusive_monitor();
        }
        exit
    }

    fn undefined(&mut self, pc: u64, reason: String) -> A64Exit {
        self.cpu.set_pc(pc);
        A64Exit::Undefined { pc, reason }
    }

    /// Reads a register, mapping the backend's register model onto the core.
    pub fn read_reg(&self, reg: RegId) -> Result<u64, BackendError> {
        let value = match reg {
            RegId::X(n) => self.x(n)?,
            RegId::W(n) => u64::from(self.core().get_w(n)),
            RegId::Xzr | RegId::Wzr => 0,
            RegId::Sp => self.core().get_sp(),
            RegId::Wsp => self.core().get_sp() as u32 as u64,
            RegId::Pc => self.core().get_pc(),
            RegId::Lr => self.x(30)?,
            RegId::Fp => self.x(29)?,
            RegId::Ip => self.x(16)?,
            RegId::Ip1 => self.x(17)?,
            RegId::Nzcv => u64::from(self.core().nzcv_bits()),
            RegId::CpacrEl1 => self.core().cpacr_el1(),
            RegId::TpidrEl0 => self.core().tpidr_el0(),
            RegId::TpidrroEl0 => self.core().tpidrro_el0(),
            other => return Err(BackendError::UnsupportedRegister(other)),
        };
        Ok(value)
    }

    /// Writes a register, mapping the backend's register model onto the core.
    pub fn write_reg(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match reg {
            RegId::X(n) => self.set_x(n, value)?,
            RegId::W(n) => self.set_w(n, value as u32)?,
            RegId::Xzr | RegId::Wzr => {}
            RegId::Sp => self.core_mut().set_current_sp(value),
            RegId::Wsp => {
                let sp = self.core().get_sp();
                self.core_mut()
                    .set_current_sp((sp & !0xffff_ffff) | u64::from(value as u32));
            }
            RegId::Pc => self.core_mut().set_pc(value),
            RegId::Lr => self.set_x(30, value)?,
            RegId::Fp => self.set_x(29, value)?,
            RegId::Ip => self.set_x(16, value)?,
            RegId::Ip1 => self.set_x(17, value)?,
            RegId::Nzcv => self.core_mut().set_nzcv_bits(value as u8),
            RegId::CpacrEl1 => self.core_mut().set_cpacr_el1(value),
            RegId::TpidrEl0 => self.core_mut().set_tpidr_el0(value),
            RegId::TpidrroEl0 => self.core_mut().set_tpidrro_el0(value),
            other => return Err(BackendError::UnsupportedRegister(other)),
        }
        Ok(())
    }

    /// Reads a 128-bit vector register.
    pub fn read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        let (index, mask) = self.vector_selector(reg)?;
        Ok((self.core().get_simd(index) & mask).to_le_bytes())
    }

    /// Writes a 128-bit vector register; bits outside the named register's
    /// width are preserved, as on hardware.
    pub fn write_vector(&mut self, reg: RegId, value: [u8; 16]) -> Result<(), BackendError> {
        let (index, mask) = self.vector_selector(reg)?;
        let current = self.core().get_simd(index);
        let incoming = u128::from_le_bytes(value);
        self.core_mut()
            .set_simd(index, (current & !mask) | (incoming & mask));
        Ok(())
    }

    fn vector_selector(&self, reg: RegId) -> Result<(u8, u128), BackendError> {
        let (index, mask) = match reg {
            RegId::Q(n) => (n, u128::MAX),
            RegId::D(n) => (n, u128::from(u64::MAX)),
            RegId::S(n) => (n, u128::from(u32::MAX)),
            RegId::H(n) => (n, u128::from(u16::MAX)),
            RegId::B(n) => (n, u128::from(u8::MAX)),
            other => return Err(BackendError::UnsupportedRegister(other)),
        };
        if index > 31 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 31 });
        }
        Ok((index, mask))
    }

    fn x(&self, index: u8) -> Result<u64, BackendError> {
        if index > 30 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 30 });
        }
        Ok(self.core().get_x(index))
    }

    fn set_x(&mut self, index: u8, value: u64) -> Result<(), BackendError> {
        if index > 30 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 30 });
        }
        self.core_mut().set_x(index, value);
        Ok(())
    }

    fn set_w(&mut self, index: u8, value: u32) -> Result<(), BackendError> {
        if index > 30 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 30 });
        }
        self.core_mut().set_w(index, value);
        Ok(())
    }
}
