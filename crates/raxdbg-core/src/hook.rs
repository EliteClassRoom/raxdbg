//! Symbol-resolution interception.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/hook/HookListener.java`
//! @7f5da98e. A listener sees every symbol the loader resolves — relocation,
//! `dlsym`, and a module's own exports — and may replace the address with a
//! host-provided one (a stub in the SVC page, for example).

use crate::svc::SvcMemory;

/// Consulted whenever the loader resolves a symbol.
pub trait HookListener {
    /// Returns the address to use for `symbol_name`, or `0` to leave the
    /// loader's own resolution in place.
    ///
    /// `library_name` is the module the symbol was found in, or `None` when
    /// nothing defined it.
    fn hook(
        &self,
        svc_memory: &SvcMemory,
        library_name: Option<&str>,
        symbol_name: &str,
        address: u64,
    ) -> u64;
}

/// A listener that replaces nothing, for tests and defaults.
pub struct NoHookListener;

impl HookListener for NoHookListener {
    fn hook(
        &self,
        _svc_memory: &SvcMemory,
        _library_name: Option<&str>,
        _symbol_name: &str,
        _address: u64,
    ) -> u64 {
        0
    }
}
