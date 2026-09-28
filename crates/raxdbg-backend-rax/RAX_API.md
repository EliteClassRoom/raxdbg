# rax API surface used by raxdbg

Every rax item raxdbg depends on, so an upstream rename is a single-file fix.
Engine pin: `c468ca32087553bb6c16aad10c17c08fee24ce95`, vendored at `vendor/rax`
(two `pub` additions, see `vendor/rax/PATCHES.md`), consumed with
`default-features = false` (drops `kvm`, Linux-only, and `smir-jit`, Unix-only
W^X).

Touch points are confined to `crates/raxdbg-backend-rax`. `raxdbg-core` has no
rax dependency at all.

## Address space — `rax::user::mm`

| Item | Signature |
|---|---|
| `AddressSpace::new` | `fn new(config: SpaceConfig) -> Result<Self, MmError>` |
| `AddressSpace::map` | `fn map(&self, start: u64, len: u64, mapping: Mapping) -> Result<(), MmError>` |
| `AddressSpace::unmap` | `fn unmap(&self, start: u64, len: u64) -> Result<(), MmError>` |
| `AddressSpace::protect` | `fn protect(&self, start: u64, len: u64, perms: Perms) -> Result<(), MmError>` |
| `AddressSpace::read` | `fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), GuestMemoryFault>` |
| `AddressSpace::write` | `fn write(&self, addr: u64, data: &[u8]) -> Result<(), GuestMemoryFault>` |
| `AddressSpace::fetch` | `fn fetch(&self, addr: u64, buf: &mut [u8]) -> Result<(), GuestMemoryFault>` |
| `AddressSpace::code_epoch` / `code_changes_since` | cache-invalidation bookkeeping (unused: `smir-jit` is off, so `clear_jit_cache` is the only cache hook) |
| `SpaceConfig` | fields `va_limit`, `arena_bytes`, `reserved_phys` |
| `Mapping::anonymous` | `fn anonymous(perms: Perms) -> Self` |
| `Perms` | bitflags `READ`, `WRITE`, `EXEC`; `contains`, `union`, `empty` |
| `PAGE_SIZE` | `pub const PAGE_SIZE: u64 = 4096` |

`AddressSpace` is `Clone` and shares its frames, which is what lets the memory
facade, the adapters and tests hold views of the same guest memory.

## AArch64 core — `rax::isa::arm::aarch64`

| Item | Signature |
|---|---|
| `AArch64Config::v8_2` | `fn v8_2() -> Self`; fields `version`, `features`, `initial_el`, `gic_config`, `num_breakpoints`, `num_watchpoints` |
| `AArch64Cpu::new` | `fn new(config: AArch64Config, memory: Box<dyn ArmMemory>) -> Self` |
| `AArch64Cpu::step` | `fn step(&mut self) -> Result<CpuExit, ArmError>` (from `ArmCpu`) |
| `enter_el0`, `cpacr_el1`, `set_cpacr_el1` | EL0 entry and FP/SIMD enablement (`set_cpacr_el1`/`cpacr_el1` are the vendored patch) |
| `get_x` / `set_x`, `get_w` / `set_w` | `fn get_x(&self, reg: u8) -> u64`, `fn set_x(&mut self, reg: u8, value: u64)` |
| `get_simd` / `set_simd` | `fn get_simd(&self, n: u8) -> u128`, `fn set_simd(&mut self, n: u8, value: u128)` |
| `fpcr_value` / `set_fpcr_value`, `fpsr_value` / `set_fpsr_value` | `u32` accessors |
| `nzcv_bits` / `set_nzcv_bits` | `u8` accessors |
| `tpidr_el0` / `set_tpidr_el0`, `tpidrro_el0` / `set_tpidrro_el0` | TLS pointers |
| `set_generic_counter`, `counter_frequency`, `set_counter_frequency` | guest system counter |
| `clear_exclusive_monitor`, `clear_wait`, `clear_halt`, `clear_jit_cache` | run-loop state resets |
| `config` | `fn config(&self) -> &AArch64Config` |
| `get_sp` / `set_current_sp` / `get_pc` / `set_pc` | from `ArmCpu` (`rax::isa::arm::common::cpu::ArmCpu`), plus the inherent `set_current_sp` |

## AArch32 core — `rax::isa::arm::aarch32` / `rax::isa::arm`

| Item | Signature |
|---|---|
| `Armv7Cpu::new` | `fn new() -> Self`; public fields `regs: [u32; 16]`, `cpsr: Psr`, `vfp: VfpState`, `cp15: Cp15State`, `is_halted`, banked registers |
| `Armv7Cpu::change_mode` | `fn change_mode(&mut self, mode: ProcessorMode)` |
| `Psr` | `from_u32` / `to_u32`, public fields `t`, `mode`, `it_state`; `in_it_block()`, `advance_it_state()` |
| `ProcessorMode` | `User`, ... |
| `Cp15State` | public fields `sctlr`, `cntkctl`, `cntfrq`, `cntpct`, `tpidrurw`, `tpidruro`, `cpacr` |
| `Cpacr` / `Fpscr` | `from_bits(u32)` / `bits() -> u32` |
| `VfpState` | public fields `dregs: [u64; 32]`, `fpscr`, `fpexc` |
| `Executor::new` | `fn new(cpu: &'a mut Armv7Cpu, mem: &'a mut M) -> Self` where `M: ArmMemory` |
| `Executor::execute` | `fn execute(&mut self, insn: &DecodedInsn) -> ExecResult`; public field `exclusive_monitor` |
| `ExecResult` | `Continue`, `Branch(u32)`, `Exception(ExceptionType)`, `Halt`, `Undefined`, `MemoryFault(MemoryError)` |
| `ExceptionType` | `SupervisorCall(u32)`, `UndefinedInstruction`, `Breakpoint(u16)`, ... |
| `Decoder` | `new(ExecutionState)`, `set_state`, `decode(&[u8]) -> Result<DecodedInsn, DecodeError>` |
| `DecodedInsn` | fields `mnemonic`, `cond`, `operands`, `raw`, `size`, `state` |
| `ThumbDecoder::is_32bit_instruction` | `fn is_32bit_instruction(hw1: u16) -> bool` |
| `ExclusiveMonitor` | `new`, `clear`, `mark_exclusive`, `check_and_clear` |
| `ArmMemory` (A32-local, `aarch32::cpu`) | `read_word`, `write_word`, `read_halfword`, `write_halfword`, `read_byte`, `write_byte`, `allows_unaligned` |
| `MemoryError` (A32) | `Unaligned(u32)`, `OutOfBounds(u32)`, `PermissionDenied(u32)`, `BusError(u32)` |
| `Sctlr::from_bits`, `CNTKCTL_PL0VCTEN` | construction constants |

## Memory interface — `rax::isa::arm::common::memory`

| Item | Signature |
|---|---|
| `ArmMemory` | required: `read(&self, u64, &mut [u8])`, `write(&mut self, u64, &[u8])`, `mark_exclusive`, `check_exclusive`, `clear_exclusive`, `register_mmio`, `unregister_mmio`; overridden: `fetch`, `requires_alignment`, `is_big_endian` |
| `MemoryError` | `Unmapped { addr, size, access }`, `OutOfBounds { addr, size }`, `Alignment { addr, required }`, `Permission { addr, access, reason }`, `BusError { addr }`, ... |
| `MmioHandler` | trait; user address spaces register none |

## Events, faults and exits

| Item | Notes |
|---|---|
| `CpuExit` | `Continue`, `Svc(imm)`, `Breakpoint(imm)`, `Hvc`, `Smc`, `Halt`, `Undefined(insn)`, `Wfi`, `Wfe` |
| `ArmError` | `MemoryError(MemoryFaultInfo)`, `UndefinedInstruction(insn)`, `InvalidExceptionLevel(el)`, `Unimplemented(&str)`, ... |
| `MemoryFaultInfo` | fields `address`, `access: AccessType`, `fault_type: MemoryFaultType` |
| `AccessType` | `InstructionFetch`, `Read`, `Write`, `Atomic` |
| `A64Exit` / `A32Exit` | rax's own exit enums; the adapters reuse them so the differential tests compare like with like |
| `AccessFault` / `AccessFaultKind` | `{ addr, access, kind, pc }` / `Unmapped`, `Permission`, `Alignment`, `Bus`; `AccessFault::from_memory` |
| `GuestMemoryFault` | `rax::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind}` |
| `Isa` | `rax::user::cpu::Isa::{Aarch64, Arm, ...}` |

## What raxdbg deliberately does not use

* `rax::user::cpu::{aarch64::A64UserCpu, arm::A32UserCpu}` — used only by
  `tests/diff_rax_adapters.rs`. Their memory bridge is private and they expose
  only `run(budget)`, so unidbg's per-access hooks, stop conditions and trap
  dispatch cannot be built on them (plan D2).
* `rax-capi` — the C ABI rejects `AArch32 + RAX_MODE_USER` (plan D1).
* `rax::user::{linux, darwin, windows}` personalities — raxdbg implements
  unidbg's syscall layer itself.
* `rax::user::image` — raxdbg implements unidbg's `AndroidElfLoader` itself.
