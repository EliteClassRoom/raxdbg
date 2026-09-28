//! CPU context snapshots.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/Backend.java`
//! `context_alloc`/`context_save`/`context_restore`/`context_free`@7f5da98e. The
//! field list is rax's `A64UserCpu::clone_thread` / `A32UserCpu::clone_thread`
//! plus the registers unidbg's `context_*` callers touch.

use rax::isa::arm::common::cpu::ArmCpu;

use crate::cpu::{RaxArm32Cpu, RaxArm64Cpu};

/// An AArch64 EL0 thread's complete architectural state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm64Context {
    /// `X0`-`X30`.
    pub x: [u64; 31],
    /// `SP_EL0`.
    pub sp: u64,
    /// The program counter.
    pub pc: u64,
    /// `NZCV` as a four-bit field.
    pub nzcv: u8,
    /// `V0`-`V31`.
    pub v: [u128; 32],
    /// `FPCR`.
    pub fpcr: u32,
    /// `FPSR`.
    pub fpsr: u32,
    /// `TPIDR_EL0`.
    pub tpidr_el0: u64,
    /// `TPIDRRO_EL0`.
    pub tpidrro_el0: u64,
    /// `CPACR_EL1`.
    pub cpacr_el1: u64,
}

impl Arm64Context {
    /// Snapshots `cpu`.
    pub fn save(cpu: &RaxArm64Cpu) -> Self {
        let core = cpu.core();
        let mut x = [0u64; 31];
        for (index, value) in x.iter_mut().enumerate() {
            *value = core.get_x(index as u8);
        }
        let mut v = [0u128; 32];
        for (index, value) in v.iter_mut().enumerate() {
            *value = core.get_simd(index as u8);
        }
        Arm64Context {
            x,
            sp: core.get_sp(),
            pc: core.get_pc(),
            nzcv: core.nzcv_bits(),
            v,
            fpcr: core.fpcr_value(),
            fpsr: core.fpsr_value(),
            tpidr_el0: core.tpidr_el0(),
            tpidrro_el0: core.tpidrro_el0(),
            cpacr_el1: core.cpacr_el1(),
        }
    }

    /// Restores this state into `cpu`.
    pub fn restore(&self, cpu: &mut RaxArm64Cpu) {
        let core = cpu.core_mut();
        for (index, value) in self.x.iter().enumerate() {
            core.set_x(index as u8, *value);
        }
        core.set_current_sp(self.sp);
        core.set_pc(self.pc);
        core.set_nzcv_bits(self.nzcv);
        for (index, value) in self.v.iter().enumerate() {
            core.set_simd(index as u8, *value);
        }
        core.set_fpcr_value(self.fpcr);
        core.set_fpsr_value(self.fpsr);
        core.set_tpidr_el0(self.tpidr_el0);
        core.set_tpidrro_el0(self.tpidrro_el0);
        core.set_cpacr_el1(self.cpacr_el1);
    }
}

/// An AArch32 User-mode thread's complete architectural state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm32Context {
    /// `R0`-`R15`.
    pub r: [u32; 16],
    /// `CPSR`.
    pub cpsr: u32,
    /// `D0`-`D31`.
    pub d: [u64; 32],
    /// `FPSCR`.
    pub fpscr: u32,
    /// `FPEXC`.
    pub fpexc: u32,
    /// `TPIDRURW`.
    pub tpidrurw: u32,
    /// `TPIDRURO`.
    pub tpidruro: u32,
    /// `CPACR` (`C1_C0_2`).
    pub cpacr: u32,
}

impl Arm32Context {
    /// Snapshots `cpu`.
    pub fn save(cpu: &RaxArm32Cpu) -> Self {
        let core = cpu.core();
        Arm32Context {
            r: core.regs,
            cpsr: core.cpsr.to_u32(),
            d: core.vfp.dregs,
            fpscr: core.vfp.fpscr.bits(),
            fpexc: core.vfp.fpexc,
            tpidrurw: core.cp15.tpidrurw,
            tpidruro: core.cp15.tpidruro,
            cpacr: core.cp15.cpacr.bits(),
        }
    }

    /// Restores this state into `cpu`.
    pub fn restore(&self, cpu: &mut RaxArm32Cpu) {
        let core = cpu.core_mut();
        core.regs = self.r;
        core.cpsr = rax::isa::arm::Psr::from_u32(self.cpsr);
        core.vfp.dregs = self.d;
        core.vfp.fpscr = rax::isa::arm::vfp::Fpscr::from_bits(self.fpscr);
        core.vfp.fpexc = self.fpexc;
        core.cp15.tpidrurw = self.tpidrurw;
        core.cp15.tpidruro = self.tpidruro;
        core.cp15.cpacr = rax::isa::arm::cp15::Cpacr::from_bits(self.cpacr);
    }
}

/// A saved CPU context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpuContext {
    /// An AArch64 EL0 snapshot.
    Arm64(Arm64Context),
    /// An AArch32 User-mode snapshot.
    Arm32(Arm32Context),
}

impl CpuContext {
    /// Snapshots whichever core `cpu` is.
    pub fn save(cpu: &crate::cpu::Cpu) -> Self {
        match cpu {
            crate::cpu::Cpu::Arm64(cpu) => CpuContext::Arm64(Arm64Context::save(cpu)),
            crate::cpu::Cpu::Arm32(cpu) => CpuContext::Arm32(Arm32Context::save(cpu)),
        }
    }

    /// Restores this state into `cpu`; a context from the other ISA is
    /// ignored.
    pub fn restore(&self, cpu: &mut crate::cpu::Cpu) {
        match (self, cpu) {
            (CpuContext::Arm64(context), crate::cpu::Cpu::Arm64(cpu)) => context.restore(cpu),
            (CpuContext::Arm32(context), crate::cpu::Cpu::Arm32(cpu)) => context.restore(cpu),
            _ => {}
        }
    }
}
