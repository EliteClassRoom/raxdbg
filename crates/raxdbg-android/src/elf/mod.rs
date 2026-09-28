//! The Android ELF loader.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidElfLoader.java`
//! and its helpers — `LinuxModule`, `ModuleSymbol`, `LinuxSymbol`,
//! `AbsoluteInitFunction`, `LinuxInitFunction` — at 7f5da98e.
//!
//! [`AndroidElfLoader`] maps a shared object's segments, resolves its
//! relocations against its dependencies and every loaded module, collects its
//! initialisers, and registers it so `dlopen`/`dlsym` can find it. The Java
//! class is also the `Memory` implementation; here the memory facade is
//! [`raxdbg_core::memory::loader::Loader`], which the loader owns and exposes
//! through [`AndroidElfLoader::memory`].

pub mod init;
pub mod loader;
pub mod module;
pub mod symbol;

pub use init::InitFunction;
pub use loader::{AndroidElfLoader, ElfError, InitCaller, ModuleInfo};
pub use module::{MemRegion, Module};
pub use symbol::{ElfSymbol, ModuleSymbol, Symbol, WEAK_BASE};
