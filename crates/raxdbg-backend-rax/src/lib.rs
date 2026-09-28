//! rax CPU backend for raxdbg.
//!
//! Port of unidbg's `backend/unicorn2` module, replacing unicorn with the rax
//! engine: user-mode CPU adapters for AArch64 and AArch32, the memory bridge,
//! the shared run loop, hook dispatch and CPU context snapshots.
//!
//! See `RAX_API.md` for every rax item this crate depends on, and
//! `../../vendor/rax/PATCHES.md` for the two accessors raxdbg adds to rax.

pub mod backend;
pub mod context;
pub mod cpu;
pub mod hooks;
pub mod memory;
pub mod run;
pub mod time;

pub use backend::{PAGE_SIZE, RaxBackend};
pub use context::{Arm32Context, Arm64Context, CpuContext};
pub use cpu::{Cpu, CpuEvent, RaxArm32Cpu, RaxArm64Cpu};
pub use hooks::{HookRange, HookTable, MemShared};
pub use memory::{FaultSlot, RaxArm32Memory, RaxMemory};
