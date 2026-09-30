//! Loaded modules.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/LinuxModule.java`
//! and `unidbg-api/src/main/java/com/github/unidbg/Module.java`@7f5da98e.
//!
//! Unlike unidbg, a module does not hold strong references to its
//! dependencies: dependency names are resolved through the loader's module
//! table, which keeps the ownership graph acyclic.

use std::collections::BTreeMap;

use super::symbol::{ElfSymbol, Symbol};

/// One mapped region of a module.
///
/// Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/memory/MemRegion.java`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemRegion {
    /// The region's virtual address in the file (unidbg's `begin`).
    pub begin: u64,
    /// Where it was mapped.
    pub address: u64,
    /// One past the last mapped byte.
    pub end: u64,
    /// The permissions it was mapped with.
    pub perms: u8,
    /// The file it came from.
    pub file: String,
    /// Its `p_vaddr`.
    pub virtual_address: u64,
}

impl MemRegion {
    /// The region's length.
    pub fn size(&self) -> u64 {
        self.end - self.address
    }
}

/// A loaded shared object.
#[derive(Debug)]
pub struct Module {
    /// The load base the guest sees (`load_virtual_address` in unidbg, the
    /// lowest `PT_LOAD` address including the base).
    pub base: u64,
    /// The load base relocations are computed against.
    pub load_base: u64,
    /// The span of the module's `PT_LOAD` segments.
    pub size: u64,
    /// The module's name, which is its `DT_SONAME` or its file name.
    pub name: String,
    /// The ELF entry point.
    pub entry_point: u64,
    /// The module's dynamic symbol table.
    pub symbols: Vec<ElfSymbol>,
    /// Symbol name to index into [`Module::symbols`].
    by_name: BTreeMap<String, usize>,
    /// Indices into [`Module::symbols`] ordered by `st_value`, for
    /// address-to-symbol lookup.
    by_address: Vec<usize>,
    /// Relocations that still need a symbol.
    pub unresolved: Vec<super::symbol::ModuleSymbol>,
    /// Relocations that resolved, keyed by symbol name; a later module that
    /// defines the symbol re-relocates them (unidbg's `resolvedSymbols`).
    pub resolved_symbols: BTreeMap<String, super::symbol::ModuleSymbol>,
    /// The initialisers to run, in order.
    pub init_functions: Vec<super::init::InitFunction>,
    /// Dependency basenames, resolved through the loader's module table.
    pub needed_libraries: Vec<String>,
    /// The regions this module occupies.
    pub regions: Vec<MemRegion>,
    /// Symbol name to host-provided address (unidbg's `hookMap`).
    pub hook_map: BTreeMap<String, u64>,
    /// How many `dlopen`s hold this module.
    pub reference_count: u32,
    /// Whether this module has no file behind it (unidbg's virtual modules).
    pub is_virtual: bool,
}

impl Module {
    /// A module with the given symbol table.
    pub fn new(
        base: u64,
        load_base: u64,
        size: u64,
        name: impl Into<String>,
        symbols: Vec<ElfSymbol>,
    ) -> Self {
        let mut by_name = BTreeMap::new();
        for (index, symbol) in symbols.iter().enumerate() {
            // The first definition of a name wins, as in a dynamic symbol
            // table lookup.
            by_name.entry(symbol.name.clone()).or_insert(index);
        }
        let mut by_address: Vec<usize> = (0..symbols.len())
            .filter(|index| !symbols[*index].is_undefined() && symbols[*index].value != 0)
            .collect();
        by_address.sort_by_key(|index| symbols[*index].value);
        Module {
            base,
            load_base,
            size,
            name: name.into(),
            entry_point: 0,
            symbols,
            by_name,
            by_address,
            unresolved: Vec::new(),
            resolved_symbols: BTreeMap::new(),
            init_functions: Vec::new(),
            needed_libraries: Vec::new(),
            regions: Vec::new(),
            hook_map: BTreeMap::new(),
            reference_count: 0,
            is_virtual: false,
        }
    }

    /// A module with no file behind it, whose symbols are host addresses.
    ///
    /// Port of unidbg: `LinuxModule.createVirtualModule`.
    pub fn virtual_module(
        base: u64,
        size: u64,
        name: impl Into<String>,
        symbols: BTreeMap<String, u64>,
    ) -> Self {
        let mut module = Module::new(base, base, size, name, Vec::new());
        module.hook_map = symbols;
        module.is_virtual = true;
        module
    }

    /// The ELF symbol with this name, defined or not.
    pub fn elf_symbol_by_name(&self, name: &str) -> Option<&ElfSymbol> {
        self.by_name.get(name).map(|index| &self.symbols[*index])
    }

    /// The symbol this module exports under `name`.
    ///
    /// Port of unidbg: `Module.findSymbolByName(name, withDependencies)`; the
    /// dependency half is [`super::loader::AndroidElfLoader::find_symbol`],
    /// which owns the module table.
    pub fn find_symbol(&self, name: &str) -> Option<Symbol> {
        if let Some(address) = self.hook_map.get(name) {
            return Some(Symbol::new(name, *address, 0, Some(self.name.clone())));
        }
        let symbol = self.elf_symbol_by_name(name)?;
        if symbol.is_undefined() {
            return None;
        }
        Some(Symbol::new(
            name,
            self.base.wrapping_add(symbol.value),
            symbol.size,
            Some(self.name.clone()),
        ))
    }

    /// The symbol whose range contains `address`.
    ///
    /// Port of unidbg: `Module.findClosestSymbolByAddress`.
    pub fn find_closest_symbol(&self, address: u64) -> Option<Symbol> {
        let offset = address.checked_sub(self.base)?;
        if offset == 0 {
            return None;
        }
        let position = self.by_address.partition_point(|index| {
            self.symbols[*index].value <= offset
        });
        let mut best = position.checked_sub(1).map(|index| self.by_address[index]);
        // A module with no entry point sits at `entry_point == 0`, so the
        // synthetic "start" symbol would land exactly on its base and hide
        // every real symbol below it. Only consider an entry point the module
        // actually has.
        if self.entry_point != 0 {
            let entry = self.base + self.entry_point;
            if address >= entry {
                let current = best.map(|index| self.base + self.symbols[index].value);
                if current.is_none_or(|current| entry > current) {
                    return Some(Symbol::new("start", entry, 0, Some(self.name.clone())));
                }
                best = None;
            }
        }
        let index = best?;
        let symbol = &self.symbols[index];
        Some(Symbol::new(
            symbol.name.clone(),
            self.base.wrapping_add(symbol.value),
            symbol.size,
            Some(self.name.clone()),
        ))
    }

    /// Every defined symbol this module exports.
    pub fn exported_symbols(&self) -> impl Iterator<Item = &ElfSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| !symbol.is_undefined() && !symbol.name.is_empty())
    }

    /// The module's `init_array` and `DT_INIT` entry points, in call order.
    pub fn init_functions(&self) -> &[super::init::InitFunction] {
        &self.init_functions
    }

    /// The symbol a relocation wrote to `address`, when `address` is a GOT
    /// slot.
    ///
    /// unidbg has no such lookup: `Module.findClosestSymbolByAddress` cannot
    /// name a PLT stub, because a stub is not a symbol. raxdbg needs it to
    /// name the imported function a `bl <stub>` reaches. The returned symbol's
    /// `address` is the slot itself; only `name` and `module` are meaningful.
    pub fn relocation_symbol(&self, address: u64) -> Option<Symbol> {
        let pending = self
            .resolved_symbols
            .values()
            .chain(self.unresolved.iter())
            .find(|pending| {
                pending.relocation_addr == address && !pending.symbol_name().is_empty()
            })?;
        Some(Symbol::new(
            pending.symbol_name(),
            address,
            0,
            pending
                .to_so_name
                .clone()
                .or_else(|| Some(self.name.clone())),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::symbol::{ElfSymbol, ModuleSymbol};
    use super::*;

    #[test]
    fn a_relocation_slot_names_the_symbol_it_writes() {
        let mut module = Module::new(0x1000, 0x1000, 0x1000, "a.so", vec![]);
        module.resolved_symbols.insert(
            "printf".into(),
            ModuleSymbol::new(
                "a.so",
                0x1000,
                Some(ElfSymbol {
                    name: "printf".into(),
                    value: 0,
                    size: 0,
                    info: 0,
                    shndx: 0,
                }),
                0x2000,
                Some("libc.so".into()),
                0,
            ),
        );

        let symbol = module.relocation_symbol(0x2000).expect("the slot names printf");
        assert_eq!(symbol.name, "printf");
        assert_eq!(symbol.module.as_deref(), Some("libc.so"));
        // The address is the slot, not the callee: only the name and the
        // module carry meaning.
        assert_eq!(symbol.address, 0x2000);

        assert!(module.relocation_symbol(0x2001).is_none());
    }
}
