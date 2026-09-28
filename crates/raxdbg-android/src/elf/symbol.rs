//! ELF symbols and pending relocations.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/{LinuxSymbol,ModuleSymbol}.java`
//! and `unidbg-api/src/main/java/com/github/unidbg/Symbol.java`@7f5da98e.

use std::fmt;

/// `SHN_UNDEF`: the symbol is imported.
pub const SHN_UNDEF: u16 = 0;

/// `STB_GLOBAL`.
pub const BINDING_GLOBAL: u8 = 1;
/// `STB_WEAK`.
pub const BINDING_WEAK: u8 = 2;

/// A symbol from an ELF dynamic symbol table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfSymbol {
    /// The symbol's name.
    pub name: String,
    /// `st_value`, relative to the module's load base for a shared object.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_info` (binding in the high nibble, type in the low nibble).
    pub info: u8,
    /// `st_shndx`; [`SHN_UNDEF`] marks an import.
    pub shndx: u16,
}

impl ElfSymbol {
    /// Whether the symbol is imported from another module.
    pub fn is_undefined(&self) -> bool {
        self.shndx == SHN_UNDEF
    }

    /// `ST_BIND(info)`.
    pub fn binding(&self) -> u8 {
        self.info >> 4
    }

    /// Whether the symbol has weak binding.
    pub fn is_weak(&self) -> bool {
        self.binding() == BINDING_WEAK
    }
}

/// A symbol as the guest sees it: a name, an absolute address and the module
/// it came from.
///
/// Port of unidbg: `Symbol`/`LinuxSymbol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// The symbol's name.
    pub name: String,
    /// The symbol's absolute address.
    pub address: u64,
    /// `st_size`.
    pub size: u64,
    /// The module the symbol belongs to, by name; `None` for a host-provided
    /// symbol (unidbg's `VirtualSymbol`).
    pub module: Option<String>,
}

impl Symbol {
    /// A symbol belonging to a module.
    pub fn new(name: impl Into<String>, address: u64, size: u64, module: Option<String>) -> Self {
        Symbol {
            name: name.into(),
            address,
            size,
            module,
        }
    }

    /// A symbol whose address the host supplied (a hook, a virtual module).
    pub fn virtual_symbol(name: impl Into<String>, address: u64) -> Self {
        Symbol::new(name, address, 0, None)
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@0x{:x}", self.name, self.address)
    }
}

/// [`ModuleSymbol::load_base`] for a symbol whose value the host decided.
///
/// Port of unidbg: `ModuleSymbol.WEAK_BASE`.
pub const WEAK_BASE: u64 = u64::MAX;

/// A relocation that has not been resolved yet.
///
/// Port of unidbg: `ModuleSymbol`. `so_name`/`load_base` describe the module
/// the relocation lives in, `to_so_name` the module it resolved against, and
/// `offset` the addend to fold in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSymbol {
    /// The module the relocation belongs to.
    pub so_name: String,
    /// That module's load base, or [`WEAK_BASE`] when the value is decided by
    /// `offset` alone.
    pub load_base: u64,
    /// The symbol being resolved, if the relocation names one.
    pub symbol: Option<ElfSymbol>,
    /// Where the relocated value is written.
    pub relocation_addr: u64,
    /// The module the symbol was found in, by name.
    pub to_so_name: Option<String>,
    /// The addend (or, for a weak resolution, the value itself).
    pub offset: i64,
}

impl ModuleSymbol {
    /// A relocation against `symbol`, not yet resolved.
    pub fn new(
        so_name: impl Into<String>,
        load_base: u64,
        symbol: Option<ElfSymbol>,
        relocation_addr: u64,
        to_so_name: Option<String>,
        offset: i64,
    ) -> Self {
        ModuleSymbol {
            so_name: so_name.into(),
            load_base,
            symbol,
            relocation_addr,
            to_so_name,
            offset,
        }
    }

    /// The symbol's name, or `""` when the relocation is against section 0.
    pub fn symbol_name(&self) -> &str {
        self.symbol.as_ref().map(|s| s.name.as_str()).unwrap_or("")
    }

    /// The value to store.
    ///
    /// Port of unidbg: `ModuleSymbol.relocation`, where `symbol` is already the
    /// symbol found in the module `load_base` belongs to.
    pub fn value(&self) -> u64 {
        if self.load_base == WEAK_BASE {
            self.offset as u64
        } else {
            let symbol_value = self.symbol.as_ref().map(|s| s.value).unwrap_or(0);
            self.load_base
                .wrapping_add(symbol_value)
                .wrapping_add(self.offset as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_binding_is_split_out_of_st_info() {
        let symbol = ElfSymbol {
            name: "f".into(),
            value: 0,
            size: 0,
            info: (BINDING_WEAK << 4) | 2,
            shndx: 1,
        };
        assert_eq!(symbol.binding(), BINDING_WEAK);
        assert!(symbol.is_weak());
        assert!(!symbol.is_undefined());
    }

    #[test]
    fn weak_resolutions_use_the_offset_as_the_value() {
        let symbol = ModuleSymbol::new("a.so", WEAK_BASE, None, 0x1000, Some("libc.so".into()), 0x77);
        assert_eq!(symbol.value(), 0x77);
    }

    #[test]
    fn normal_resolutions_fold_base_symbol_and_addend() {
        let target = ElfSymbol {
            name: "f".into(),
            value: 0x400,
            size: 0,
            info: BINDING_GLOBAL << 4,
            shndx: 1,
        };
        let symbol = ModuleSymbol::new("a.so", 0x1000_0000, Some(target), 0x2000, None, 0x10);
        assert_eq!(symbol.value(), 0x1000_0410);
    }
}
