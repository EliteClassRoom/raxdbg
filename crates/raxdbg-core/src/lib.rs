//! Core abstractions shared by every raxdbg crate.
//!
//! Port of unidbg's `unidbg-api` module: the backend contract, register model,
//! guest memory facade, pointer helpers, module/symbol registry, the syscall
//! framework, the cooperative thread dispatcher and the debugger API.

pub mod backend;
pub mod reg;
