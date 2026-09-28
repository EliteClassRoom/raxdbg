//! AArch32 (ARM/Thumb) user-mode adapter over rax's ARMv7 core.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/UnicornBackend.java`
//! @7f5da98e, with the fetch/decode/execute/IT-advance sequence copied verbatim
//! from rax's own adapter, `rax/src/user/cpu/arm.rs@c468ca32`
//! (`A32UserCpu::step`/`run`).
//!
//! Differences from rax's adapter:
//!
//! * memory accesses go through [`RaxArm32Memory`], which dispatches raxdbg's
//!   read/write hooks;
//! * [`RaxArm32Cpu::step`] is public, so the run loop can check hooks, stop
//!   conditions and the trap address between instructions.

use std::sync::Arc;

use rax::isa::arm::aarch32::cpu::MemoryError as Arm32MemoryError;
use rax::isa::arm::aarch32::instructions::ExclusiveMonitor;
use rax::isa::arm::decoder::ThumbDecoder;
use rax::isa::arm::{
    Armv7Cpu, Decoder, ExceptionType, ExecResult, ExecutionState, Executor, Mnemonic, ProcessorMode,
    Psr,
};
use rax::user::cpu::arm::{A32Exit, COUNTER_HZ};
use rax::user::cpu::{AccessFault, AccessFaultKind};
use rax::error::MemoryAccessKind;
use raxdbg_core::backend::BackendError;
use raxdbg_core::reg::RegId;

use crate::hooks::MemShared;
use crate::memory::RaxArm32Memory;
use crate::time::host_nanos;

/// An AArch32 user-mode CPU with raxdbg's memory hooks.
pub struct RaxArm32Cpu {
    cpu: Armv7Cpu,
    mem: RaxArm32Memory,
    monitor: ExclusiveMonitor,
    decoder: Decoder,
    shared: Arc<MemShared>,
    /// Instructions retired since construction.
    insns: u64,
}

impl std::fmt::Debug for RaxArm32Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaxArm32Cpu")
            .field("pc", &self.cpu.regs[15])
            .field("thumb", &self.cpu.cpsr.t)
            .field("insns", &self.insns)
            .finish()
    }
}

impl RaxArm32Cpu {
    /// Creates a CPU in User mode (A32 state, flags and interrupt masks clear)
    /// with zeroed registers over `shared`'s address space. Mirrors
    /// `A32UserCpu::new`.
    pub fn new(shared: Arc<MemShared>) -> Self {
        let mut cpu = Armv7Cpu::new();
        cpu.change_mode(ProcessorMode::User);
        cpu.cpsr = Psr::from_u32(ProcessorMode::User as u32);
        cpu.regs = [0; 16];
        cpu.vfp.fpexc = 1 << 30;
        cpu.cp15.sctlr = rax::isa::arm::cp15::Sctlr::from_bits(0);
        // arch_counter_set_user_access: EL0 reads the virtual counter (and
        // CNTFRQ), not the physical one.
        cpu.cp15.cntkctl = rax::isa::arm::aarch32::cp15::CNTKCTL_PL0VCTEN;
        cpu.cp15.cntfrq = COUNTER_HZ;
        RaxArm32Cpu {
            cpu,
            mem: RaxArm32Memory::new(Arc::clone(&shared)),
            monitor: ExclusiveMonitor::new(),
            decoder: Decoder::new(ExecutionState::Arm),
            shared,
            insns: 0,
        }
    }

    /// A CPU for another thread of the same process, with this CPU's register
    /// state (rax's `A32UserCpu::clone_thread` field list).
    pub fn clone_thread(&self) -> Self {
        let mut child = RaxArm32Cpu::new(Arc::clone(&self.shared));
        child.cpu.regs = self.cpu.regs;
        child.cpu.cpsr = self.cpu.cpsr.clone();
        child.cpu.vfp.dregs = self.cpu.vfp.dregs;
        child.cpu.vfp.fpscr = self.cpu.vfp.fpscr;
        child.cpu.vfp.fpexc = self.cpu.vfp.fpexc;
        child.cpu.cp15.tpidrurw = self.cpu.cp15.tpidrurw;
        child.cpu.cp15.tpidruro = self.cpu.cp15.tpidruro;
        child
    }

    /// The underlying core.
    pub fn core(&self) -> &Armv7Cpu {
        &self.cpu
    }

    /// Mutable access to the underlying core.
    pub fn core_mut(&mut self) -> &mut Armv7Cpu {
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

    /// Whether the thread executes T32 (Thumb) code.
    pub fn thumb(&self) -> bool {
        self.cpu.cpsr.t
    }

    /// Advances the guest's system counter to host time, as rax's adapter does
    /// once per run slice.
    pub fn update_counter(&mut self) {
        let freq = u128::from(self.cpu.cp15.cntfrq);
        self.cpu.cp15.cntpct = (u128::from(host_nanos()) * freq / 1_000_000_000) as u64;
    }

    /// Discards compiled code. The ARMv7 core is a pure interpreter, so this
    /// only drops the adapter's own state.
    pub fn invalidate_code(&mut self) {}

    /// Runs at most `budget` instructions, stopping at the first
    /// operating-system-visible event (rax's `A32UserCpu::run`).
    pub fn run(&mut self, budget: u64) -> A32Exit {
        // Returning to the thread is an exception return, which takes the PC's
        // bit 0 (T32) or bits 1:0 (A32) as zero.
        self.cpu.regs[15] &= if self.cpu.cpsr.t { !1 } else { !3 };
        self.update_counter();
        let exit = (0..budget)
            .find_map(|_| self.step())
            .unwrap_or(A32Exit::Yield);
        // Leaving the guest is an exception entry, which clears the local
        // exclusive monitor.
        self.monitor.clear();
        exit
    }

    /// Runs one instruction.
    ///
    /// `None` means the instruction retired with no operating-system-visible
    /// event; `Some` is the event that ended it.
    pub fn step(&mut self) -> Option<A32Exit> {
        let pc = self.cpu.regs[15];
        let thumb = self.cpu.cpsr.t;
        // An A32 PC that is not word-aligned (after a branch to one) takes a
        // PC alignment fault at the fetch.
        if !thumb && pc & 3 != 0 {
            return Some(A32Exit::Fault(AccessFault {
                addr: u64::from(pc),
                access: MemoryAccessKind::Fetch,
                kind: AccessFaultKind::Alignment,
                pc: u64::from(pc),
            }));
        }
        self.shared.set_pc(u64::from(pc));
        self.insns += 1;
        let mut bytes = [0u8; 4];
        let (len, insn) = if thumb {
            if let Err(e) = self.fetch(pc, pc, &mut bytes[..2]) {
                return Some(e);
            }
            let hw1 = u16::from_le_bytes([bytes[0], bytes[1]]);
            if ThumbDecoder::is_32bit_instruction(hw1) {
                if let Err(e) = self.fetch(pc, pc.wrapping_add(2), &mut bytes[2..]) {
                    return Some(e);
                }
                let hw2 = u16::from_le_bytes([bytes[2], bytes[3]]);
                (4, (u32::from(hw1) << 16) | u32::from(hw2))
            } else {
                (2, u32::from(hw1))
            }
        } else {
            if let Err(e) = self.fetch(pc, pc, &mut bytes) {
                return Some(e);
            }
            (4, u32::from_le_bytes(bytes))
        };
        self.decoder.set_state(if thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Arm
        });
        let decoded = match self.decoder.decode(&bytes[..len as usize]) {
            Ok(d) => d,
            Err(e) => return Some(self.undefined(pc, insn, thumb, format!("decode: {e:?}"))),
        };
        if decoded.mnemonic == Mnemonic::SWP {
            return Some(self.undefined(pc, insn, thumb, "SWP is not in ARMv8".into()));
        }
        if is_setend(insn, thumb, len) {
            return Some(self.undefined(pc, insn, thumb, "no mixed-endian EL0".into()));
        }

        let in_it = thumb && self.cpu.cpsr.in_it_block();
        self.mem.clear_fault();
        let mut exec = Executor::new(&mut self.cpu, &mut self.mem);
        exec.exclusive_monitor = std::mem::take(&mut self.monitor);
        let result = exec.execute(&decoded);
        self.monitor = std::mem::take(&mut exec.exclusive_monitor);

        let next = |cpu: &mut Armv7Cpu| {
            cpu.regs[15] = pc.wrapping_add(len);
            if in_it {
                cpu.cpsr.advance_it_state();
            }
        };
        match result {
            ExecResult::Continue => {
                next(&mut self.cpu);
                None
            }
            ExecResult::Branch(target) => {
                // The executor sets the T bit of an interworking branch; a
                // target with bit 0 set is Thumb code in either case.
                if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                }
                self.cpu.regs[15] = target & !1;
                if in_it {
                    self.cpu.cpsr.advance_it_state();
                }
                None
            }
            ExecResult::Exception(ExceptionType::SupervisorCall(imm)) => {
                next(&mut self.cpu);
                Some(A32Exit::Svc {
                    imm,
                    pc: u64::from(pc),
                })
            }
            ExecResult::Exception(ExceptionType::Breakpoint(imm)) => Some(A32Exit::Bkpt {
                imm,
                pc: u64::from(pc),
            }),
            ExecResult::Exception(ExceptionType::UndefinedInstruction) | ExecResult::Undefined => {
                let reason = format!("undefined {:?}", decoded.mnemonic);
                Some(self.undefined(pc, insn, thumb, reason))
            }
            ExecResult::Halt => {
                // WFI and WFE complete at once: nothing interrupts a user
                // thread. A wait usually spins on another thread, so yield.
                self.cpu.is_halted = false;
                next(&mut self.cpu);
                Some(A32Exit::Yield)
            }
            ExecResult::MemoryFault(e) => Some(match (self.mem.take_fault(), e) {
                (Some(f), _) => A32Exit::Fault(AccessFault::from_memory(f, u64::from(pc))),
                // An alignment fault the executor raises itself (exclusive and
                // ordered accesses must be naturally aligned).
                (None, Arm32MemoryError::Unaligned(addr)) => A32Exit::Fault(AccessFault {
                    addr: u64::from(addr),
                    access: if is_store(decoded.mnemonic) {
                        MemoryAccessKind::Write
                    } else {
                        MemoryAccessKind::Read
                    },
                    kind: AccessFaultKind::Alignment,
                    pc: u64::from(pc),
                }),
                (None, e) => A32Exit::Internal(format!("{e} at {pc:#x} without an access fault")),
            }),
            ExecResult::Exception(other) => Some(A32Exit::Internal(format!(
                "unexpected AArch32 exception {other:?} at {pc:#x}"
            ))),
        }
    }

    /// Fetches `buf` from `addr` for the instruction at `pc`, requiring
    /// execute permission.
    fn fetch(&self, pc: u32, addr: u32, buf: &mut [u8]) -> Result<(), A32Exit> {
        self.mem
            .shared()
            .space()
            .fetch(u64::from(addr), buf)
            .map_err(|f| A32Exit::Fault(AccessFault::from_memory(f, u64::from(pc))))
    }

    fn undefined(&self, pc: u32, insn: u32, thumb: bool, reason: String) -> A32Exit {
        A32Exit::Undefined {
            pc: u64::from(pc),
            insn,
            thumb,
            reason,
        }
    }

    /// Reads a register, mapping the backend's register model onto the core.
    pub fn read_reg(&self, reg: RegId) -> Result<u64, BackendError> {
        let value = match reg {
            RegId::R(n) => self.gpr(n)?,
            RegId::Sp => u64::from(self.cpu.regs[13]),
            RegId::Lr => u64::from(self.cpu.regs[14]),
            RegId::Pc => u64::from(self.cpu.regs[15]),
            RegId::Fp => u64::from(self.cpu.regs[11]),
            RegId::Ip => u64::from(self.cpu.regs[12]),
            RegId::Sb => u64::from(self.cpu.regs[9]),
            RegId::Sl => u64::from(self.cpu.regs[10]),
            RegId::Cpsr => u64::from(self.cpu.cpsr.to_u32()),
            RegId::D(n) => self.dreg(n)?,
            RegId::Fpexc => u64::from(self.cpu.vfp.fpexc),
            RegId::Fpscr => u64::from(self.cpu.vfp.fpscr.bits()),
            RegId::C1C0_2 => u64::from(self.cpu.cp15.cpacr.bits()),
            RegId::C13C0_3 => u64::from(self.cpu.cp15.tpidruro),
            other => return Err(BackendError::UnsupportedRegister(other)),
        };
        Ok(value)
    }

    /// Writes a register, mapping the backend's register model onto the core.
    pub fn write_reg(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match reg {
            RegId::R(n) => self.set_gpr(n, value as u32)?,
            RegId::Sp => self.cpu.regs[13] = value as u32,
            RegId::Lr => self.cpu.regs[14] = value as u32,
            RegId::Pc => {
                // unidbg writes the PC through unicorn, whose AArch32 PC write
                // has `BXWritePC` semantics: bit 0 selects T32. rax's own
                // adapter instead keeps the odd bit and masks it on entry to
                // `run`, which is the kernel's convention, not a `reg_write`.
                let target = value as u32;
                self.cpu.cpsr.t = target & 1 != 0;
                self.cpu.regs[15] = target & !1;
            }
            RegId::Fp => self.cpu.regs[11] = value as u32,
            RegId::Ip => self.cpu.regs[12] = value as u32,
            RegId::Sb => self.cpu.regs[9] = value as u32,
            RegId::Sl => self.cpu.regs[10] = value as u32,
            RegId::Cpsr => self.cpu.cpsr = Psr::from_u32(value as u32),
            RegId::D(n) => self.set_dreg(n, value)?,
            RegId::Fpexc => self.cpu.vfp.fpexc = value as u32,
            RegId::Fpscr => self.cpu.vfp.fpscr = rax::isa::arm::vfp::Fpscr::from_bits(value as u32),
            RegId::C1C0_2 => {
                self.cpu.cp15.cpacr = rax::isa::arm::cp15::Cpacr::from_bits(value as u32)
            }
            RegId::C13C0_3 => self.cpu.cp15.tpidruro = value as u32,
            other => return Err(BackendError::UnsupportedRegister(other)),
        }
        Ok(())
    }

    /// Reads a 128-bit vector register (the AArch32 `D0`-`D15` view; `Q` and
    /// the narrow views are not part of the AArch32 register model).
    pub fn read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        match reg {
            RegId::D(n) => {
                let value = self.dreg(n)?;
                let mut out = [0u8; 16];
                out[..8].copy_from_slice(&value.to_le_bytes());
                Ok(out)
            }
            RegId::Q(n) => {
                let low = self.dreg(n * 2)?;
                let high = self.dreg(n * 2 + 1)?;
                let mut out = [0u8; 16];
                out[..8].copy_from_slice(&low.to_le_bytes());
                out[8..].copy_from_slice(&high.to_le_bytes());
                Ok(out)
            }
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    /// Writes a 128-bit vector register (the AArch32 `D0`-`D15` view).
    pub fn write_vector(&mut self, reg: RegId, value: [u8; 16]) -> Result<(), BackendError> {
        match reg {
            RegId::D(n) => {
                let raw = u64::from_le_bytes(value[..8].try_into().expect("eight bytes"));
                self.set_dreg(n, raw)
            }
            RegId::Q(n) => {
                let low = u64::from_le_bytes(value[..8].try_into().expect("eight bytes"));
                let high = u64::from_le_bytes(value[8..].try_into().expect("eight bytes"));
                self.set_dreg(n * 2, low)?;
                self.set_dreg(n * 2 + 1, high)
            }
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn gpr(&self, index: u8) -> Result<u64, BackendError> {
        if index > 15 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 15 });
        }
        Ok(u64::from(self.cpu.regs[index as usize]))
    }

    fn set_gpr(&mut self, index: u8, value: u32) -> Result<(), BackendError> {
        if index > 15 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 15 });
        }
        self.cpu.regs[index as usize] = value;
        Ok(())
    }

    fn dreg(&self, index: u8) -> Result<u64, BackendError> {
        if index > 15 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 15 });
        }
        Ok(self.cpu.vfp.dregs[index as usize])
    }

    fn set_dreg(&mut self, index: u8, value: u64) -> Result<(), BackendError> {
        if index > 15 {
            return Err(BackendError::RegisterOutOfRange { reg: index, max: 15 });
        }
        self.cpu.vfp.dregs[index as usize] = value;
        Ok(())
    }
}

/// `SETEND` (A32 `1111 0001 0000 0001 0000 00E0 0000 0000`, T16
/// `1011 0110 010E 0000`); copied from rax's `src/user/cpu/arm.rs`.
fn is_setend(insn: u32, thumb: bool, len: u32) -> bool {
    match (thumb, len) {
        (false, _) => insn & 0xFFFF_FDFF == 0xF101_0000,
        (true, 2) => insn & 0xFFF7 == 0xB650,
        (true, _) => false,
    }
}

/// The stores among the instructions whose alignment the executor checks;
/// copied from rax's `src/user/cpu/arm.rs`.
fn is_store(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::STXR
            | Mnemonic::STXRB
            | Mnemonic::STXRH
            | Mnemonic::STXP
            | Mnemonic::STLXR
            | Mnemonic::STLXRB
            | Mnemonic::STLXRH
            | Mnemonic::STLXP
            | Mnemonic::STLR
            | Mnemonic::STLRB
            | Mnemonic::STLRH
            | Mnemonic::STP
            | Mnemonic::STM
            | Mnemonic::STMIA
            | Mnemonic::STMIB
            | Mnemonic::STMDA
            | Mnemonic::STMDB
            | Mnemonic::PUSH
            | Mnemonic::VSTR
            | Mnemonic::VSTM
            | Mnemonic::VPUSH
            | Mnemonic::VST1
            | Mnemonic::VST2
            | Mnemonic::VST3
            | Mnemonic::VST4
    )
}
