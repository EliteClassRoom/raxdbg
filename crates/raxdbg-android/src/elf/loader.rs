//! The Android ELF loader.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidElfLoader.java`
//! @7f5da98e, plus the allocation half of
//! `unidbg-api/src/main/java/com/github/unidbg/spi/AbstractLoader.java`, which
//! lives in [`raxdbg_core::memory::loader::Loader`].
//!
//! The loader maps a shared object's `PT_LOAD` segments, resolves its
//! relocations against its dependencies and every loaded module, collects its
//! initialisers, and registers it so `dlopen`/`dlsym` can find it. The Java
//! class doubles as the `Memory` implementation; here the memory facade is the
//! core [`Loader`], which this type delegates to through [`AndroidElfLoader::memory`].

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::{Elf, dynamic, header};

use raxdbg_core::backend::{Backend, Prot};
use raxdbg_core::hook::HookListener;
use raxdbg_core::memory::loader::{Loader, align, align_size};
use raxdbg_core::memory::{
    MAP_ANONYMOUS, MAP_FIXED, Memory, MemoryError, PAGE_SIZE, STACK_BASE, STACK_SIZE_OF_PAGE,
};
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::SvcMemory;

use crate::android_file::{LibraryFile, LibraryResolver};
use crate::elf::init::InitFunction;
use crate::elf::module::{MemRegion, Module};
use crate::elf::symbol::{ElfSymbol, ModuleSymbol, Symbol, WEAK_BASE};

/// The environment `AndroidElfLoader`'s constructor installs.
pub const DEFAULT_ENVIRON: &[&str] = &[
    "ANDROID_DATA=/data",
    "ANDROID_ROOT=/system",
    "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
    "NO_ADDR_COMPAT_LAYOUT_FIXUP=1",
];

/// A relocation type this loader implements.
///
/// Port of unidbg: the `switch (type)` in `AndroidElfLoader.loadInternal`.
pub mod reloc_type {
    /// `R_ARM_ABS32`.
    pub const R_ARM_ABS32: u32 = 2;
    /// `R_ARM_COPY`.
    pub const R_ARM_COPY: u32 = 20;
    /// `R_ARM_GLOB_DAT`.
    pub const R_ARM_GLOB_DAT: u32 = 21;
    /// `R_ARM_JUMP_SLOT`.
    pub const R_ARM_JUMP_SLOT: u32 = 22;
    /// `R_ARM_RELATIVE`.
    pub const R_ARM_RELATIVE: u32 = 23;
    /// `R_AARCH64_COPY`.
    pub const R_AARCH64_COPY: u32 = 1024;
    /// `R_AARCH64_GLOB_DAT`.
    pub const R_AARCH64_GLOB_DAT: u32 = 1025;
    /// `R_AARCH64_JUMP_SLOT`.
    pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
    /// `R_AARCH64_RELATIVE`.
    pub const R_AARCH64_RELATIVE: u32 = 1027;
    /// `R_AARCH64_ABS64`.
    pub const R_AARCH64_ABS64: u32 = 257;
}

/// An ELF loading failure.
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    /// The file is not an ELF this loader can map.
    #[error("{0}")]
    Message(String),
    /// The guest memory facade failed.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// Reading the library failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<raxdbg_core::backend::BackendError> for ElfError {
    fn from(error: raxdbg_core::backend::BackendError) -> Self {
        ElfError::Memory(MemoryError::Backend(error))
    }
}

impl From<goblin::error::Error> for ElfError {
    fn from(error: goblin::error::Error) -> Self {
        ElfError::Message(format!("cannot parse the ELF file: {error}"))
    }
}

/// A small deterministic random source, so `--seed` makes a run reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// The placement of one mapped segment.
#[derive(Clone, Copy, Debug)]
struct Alignment {
    address: u64,
    size: u64,
    begin: u64,
    data_size: u64,
}

/// A loaded shared object's identity, for callers that only need a summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInfo {
    /// The module's name.
    pub name: String,
    /// Its base address.
    pub base: u64,
    /// Its span.
    pub size: u64,
    /// Its entry point.
    pub entry_point: u64,
    /// Its dependencies, by name.
    pub needed_libraries: Vec<String>,
    /// The initialisers it carries.
    pub init_functions: usize,
    /// How many `dlopen`s hold it.
    pub reference_count: u32,
}

/// The Android ELF loader.
pub struct AndroidElfLoader {
    memory: Rc<Loader>,
    backend: Rc<RefCell<dyn Backend>>,
    is_64bit: bool,
    pointer_size: usize,
    modules: RefCell<BTreeMap<String, Module>>,
    library_resolver: RefCell<Option<Rc<dyn LibraryResolver>>>,
    hook_listeners: RefCell<Vec<Rc<dyn HookListener>>>,
    svc_memory: RefCell<Option<Rc<SvcMemory>>>,
    call_init_function: Cell<bool>,
    environ: Cell<u64>,
    max_so_name: RefCell<Option<String>>,
    max_size_of_so: Cell<u64>,
    init_caller: RefCell<Option<Rc<dyn InitCaller>>>,
    rng: RefCell<Rng>,
}

impl std::fmt::Debug for AndroidElfLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidElfLoader")
            .field("is_64bit", &self.is_64bit)
            .field("modules", &self.modules.borrow().len())
            .field("mmap_base", &format_args!("{:#x}", self.memory.mmap_base_address()))
            .finish()
    }
}

impl AndroidElfLoader {
    /// Creates a loader with the stack mapped and TLS installed, as unidbg's
    /// `AndroidElfLoader` constructor does.
    pub fn new(
        backend: Rc<RefCell<dyn Backend>>,
        is_64bit: bool,
        process_name: &str,
        seed: u64,
    ) -> Result<Rc<Self>, ElfError> {
        let pointer_size = if is_64bit { 8 } else { 4 };
        let memory = Loader::new(Rc::clone(&backend), pointer_size);
        let loader = Rc::new(AndroidElfLoader {
            memory,
            backend,
            is_64bit,
            pointer_size,
            modules: RefCell::new(BTreeMap::new()),
            library_resolver: RefCell::new(None),
            hook_listeners: RefCell::new(Vec::new()),
            svc_memory: RefCell::new(None),
            call_init_function: Cell::new(true),
            environ: Cell::new(0),
            max_so_name: RefCell::new(None),
            max_size_of_so: Cell::new(0),
            init_caller: RefCell::new(None),
            rng: RefCell::new(Rng::new(seed)),
        });
        loader.setup_stack(process_name)?;
        Ok(loader)
    }

    /// Maps the stack area, sets the stack pointer, and installs TLS.
    fn setup_stack(&self, process_name: &str) -> Result<(), ElfError> {
        let stack_size = STACK_SIZE_OF_PAGE * PAGE_SIZE;
        self.memory.mmap2(
            STACK_BASE - stack_size,
            stack_size as usize,
            Prot::READ.union(Prot::WRITE),
            MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        )?;
        self.memory.set_stack_point(STACK_BASE);
        let environ = self.initialize_tls(DEFAULT_ENVIRON, process_name)?;
        self.environ.set(environ);
        self.memory.set_errno(0);
        Ok(())
    }

    /// Builds the initial thread's stack frame and TLS block.
    ///
    /// Port of unidbg: `AndroidElfLoader.initializeTLS`.
    pub fn initialize_tls(&self, envs: &[&str], process_name: &str) -> Result<u64, ElfError> {
        let memory = self.memory.as_ref();
        let pointer_size = self.pointer_size;

        // pthread_internal_t: next, prev, tid.
        let thread = memory.allocate_stack(0x400)?;
        thread.write_pointer(0, 0)?;
        thread.write_pointer(pointer_size as u64, 0)?;
        thread.write_u32(pointer_size as u64 * 2, 1)?;

        let stack_chk_guard = memory.allocate_stack(pointer_size)?;
        let guard = self.rng.borrow_mut().next_u64();
        stack_chk_guard.write_pointer(0, if self.is_64bit { guard } else { guard & 0xffff_ffff })?;

        let program_name = memory.write_stack_string(process_name)?;
        let program_name_pointer = memory.allocate_stack(pointer_size)?;
        program_name_pointer.write_pointer(0, program_name.peer())?;

        let auxv = memory.allocate_stack(0x100)?;
        // AT_RANDOM is a pointer to 16 bytes of randomness on the stack.
        const AT_RANDOM: u64 = 25;
        const AT_PAGESZ: u64 = 6;
        auxv.write_pointer(0, AT_RANDOM)?;
        auxv.write_pointer(pointer_size as u64, guard)?;
        auxv.write_pointer(pointer_size as u64 * 2, AT_PAGESZ)?;
        auxv.write_pointer(pointer_size as u64 * 3, PAGE_SIZE)?;

        let env_list: Vec<&str> = envs
            .iter()
            .copied()
            .filter(|env| env.contains('='))
            .collect();
        let environ = memory.allocate_stack(pointer_size * (env_list.len() + 1))?;
        for (index, env) in env_list.iter().enumerate() {
            let string = memory.write_stack_string(env)?;
            environ.write_pointer(pointer_size as u64 * index as u64, string.peer())?;
        }
        environ.write_pointer(pointer_size as u64 * env_list.len() as u64, 0)?;

        let argv = memory.allocate_stack(0x100)?;
        argv.write_pointer(pointer_size as u64, program_name_pointer.peer())?;
        argv.write_pointer(pointer_size as u64 * 2, environ.peer())?;
        argv.write_pointer(pointer_size as u64 * 3, auxv.peer())?;

        // The Android ABI requires a 16-byte-aligned thread pointer; unidbg
        // leaves it wherever the stack pointer happens to be, which is not
        // always aligned once the environment strings are pushed.
        let tls_raw = memory.allocate_stack(0x80 * 4 + 16)?;
        let tls = memory.pointer(tls_raw.peer() & !0xf);
        tls.write_pointer(pointer_size as u64, thread.peer())?;
        let errno = tls.share(pointer_size as u64 * 2, 4);
        self.memory.set_errno_address(errno.peer());
        tls.write_pointer(pointer_size as u64 * 3, argv.peer())?;

        let mut backend = self.backend.borrow_mut();
        if self.is_64bit {
            backend.reg_write(RegId::TpidrEl0, tls.peer())?;
        } else {
            backend.reg_write(RegId::C13C0_3, tls.peer())?;
        }
        drop(backend);

        let mut sp = memory.get_stack_point();
        sp &= !if self.is_64bit { 15 } else { 7 };
        memory.set_stack_point(sp);

        Ok(environ.peer())
    }

    /// The memory facade: allocation, the stack, `errno` and the region tree.
    pub fn memory(&self) -> &Rc<Loader> {
        &self.memory
    }

    /// The CPU backend.
    pub fn backend(&self) -> &Rc<RefCell<dyn Backend>> {
        &self.backend
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The guest pointer width in bytes.
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// The `environ` array's address.
    pub fn environ(&self) -> u64 {
        self.environ.get()
    }

    /// Installs the resolver used for `DT_NEEDED` and `dlopen`.
    pub fn set_library_resolver(&self, resolver: Rc<dyn LibraryResolver>) {
        *self.library_resolver.borrow_mut() = Some(resolver);
    }

    /// Installs the SVC page, so hook listeners can allocate stubs in it.
    pub fn set_svc_memory(&self, svc_memory: Rc<SvcMemory>) {
        *self.svc_memory.borrow_mut() = Some(svc_memory);
    }

    /// The SVC page, if one is installed.
    pub fn svc_memory(&self) -> Option<Rc<SvcMemory>> {
        self.svc_memory.borrow().clone()
    }

    /// Registers a symbol-resolution listener.
    pub fn add_hook_listener(&self, listener: Rc<dyn HookListener>) {
        self.hook_listeners.borrow_mut().push(listener);
    }

    /// Whether module initialisers run after loading.
    pub fn call_init_function(&self) -> bool {
        self.call_init_function.get()
    }

    /// Turns module initialisers off (unidbg's `disableCallInitFunction`).
    pub fn set_call_init_function(&self, call_init: bool) {
        self.call_init_function.set(call_init);
    }

    /// The name of the longest module loaded, for diagnostic buffers.
    pub fn max_library_name(&self) -> Option<String> {
        self.max_so_name.borrow().clone()
    }

    /// The largest module span seen.
    pub fn max_library_size(&self) -> u64 {
        self.max_size_of_so.get()
    }

    /// Loads `file`, resolving dependencies and running initialisers.
    ///
    /// Port of unidbg: `AbstractLoader.load(LibraryFile, forceCallInit)`.
    pub fn load(
        &self,
        file: Box<dyn LibraryFile>,
        force_call_init: bool,
    ) -> Result<String, ElfError> {
        let name = self.load_internal(file.as_ref())?;
        self.resolve_symbols(!force_call_init);

        if self.call_init_function.get() || force_call_init {
            let names: Vec<String> = self.modules.borrow().keys().cloned().collect();
            let ran = self.init_caller.borrow().is_some();
            for module_name in names {
                let force = force_call_init && module_name == name;
                if self.call_init_function.get() || force {
                    self.call_init_functions(&module_name)?;
                }
                // unidbg always clears the list here because it always runs
                // the initialisers. raxdbg keeps them when nothing ran them
                // (no emulator is attached yet), so the loader still reports
                // what a module wanted to run.
                if ran {
                    if let Some(module) = self.modules.borrow_mut().get_mut(&module_name) {
                        module.init_functions.clear();
                    }
                }
            }
        }
        if let Some(module) = self.modules.borrow_mut().get_mut(&name) {
            module.reference_count += 1;
        }
        Ok(name)
    }

    /// Runs a module's initialisers through the emulator's function call.
    ///
    /// The emulator installs this in P5; until then loading a library with
    /// initialisers reports them instead of running them.
    pub fn set_init_caller(&self, caller: Rc<dyn InitCaller>) {
        *self.init_caller.borrow_mut() = Some(caller);
    }

    fn call_init_functions(&self, name: &str) -> Result<(), ElfError> {
        let functions = match self.modules.borrow().get(name) {
            Some(module) => module.init_functions.clone(),
            None => return Ok(()),
        };
        let caller = self.init_caller.borrow().clone();
        for function in functions {
            let address = function.address(self.memory.as_ref())?;
            if address == 0 || address == u64::MAX {
                continue;
            }
            if let Some(caller) = &caller {
                caller.call_init(address)?;
            }
        }
        Ok(())
    }

    /// Resolves every pending relocation across every loaded module.
    ///
    /// Port of unidbg: `AndroidElfLoader.resolveSymbols`.
    pub fn resolve_symbols(&self, show_warning: bool) {
        let names: Vec<String> = self.modules.borrow().keys().cloned().collect();
        for name in names {
            let unresolved = match self.modules.borrow_mut().get_mut(&name) {
                Some(module) => std::mem::take(&mut module.unresolved),
                None => continue,
            };
            let mut still_unresolved = Vec::new();
            for pending in unresolved {
                match self.resolve_pending(&pending, true) {
                    Some(resolved) => self.apply_relocation(&resolved, &name),
                    None => {
                        if show_warning {
                            log::info!(
                                "[{}] symbol {} is missing, relocation address {:#x}",
                                pending.so_name,
                                pending.symbol_name(),
                                pending.relocation_addr
                            );
                        }
                        still_unresolved.push(pending);
                    }
                }
            }
            if let Some(module) = self.modules.borrow_mut().get_mut(&name) {
                module.unresolved = still_unresolved;
            }
        }
    }

    /// `dlopen`: loads `filename` unless it is already loaded.
    ///
    /// Port of unidbg: `AndroidElfLoader.dlopen`.
    pub fn dlopen(&self, filename: &str, call_init: bool) -> Option<String> {
        let base_name = basename(filename);
        if self.modules.borrow().contains_key(&base_name) {
            let mut modules = self.modules.borrow_mut();
            let module = modules.get_mut(&base_name)?;
            module.reference_count += 1;
            return Some(base_name);
        }

        let file = {
            let resolver = self.library_resolver.borrow();
            resolver.as_ref()?.resolve_library(filename)?
        };
        if call_init {
            return self.load(file, false).ok();
        }
        match self.load_internal(file.as_ref()) {
            Ok(name) => {
                self.resolve_symbols(false);
                if !self.call_init_function.get() {
                    for module in self.modules.borrow_mut().values_mut() {
                        module.init_functions.clear();
                    }
                }
                if let Some(module) = self.modules.borrow_mut().get_mut(&name) {
                    module.reference_count += 1;
                }
                Some(name)
            }
            Err(_) => None,
        }
    }

    /// `dlsym`: the address of `symbol_name` in `handle`, or in any module
    /// when `handle` is `RTLD_DEFAULT`/0.
    ///
    /// Port of unidbg: `AndroidElfLoader.dlsym`.
    pub fn dlsym(&self, handle: u64, symbol_name: &str) -> Option<Symbol> {
        if symbol_name == "environ" {
            return Some(Symbol::virtual_symbol(symbol_name, self.environ.get()));
        }
        let mut found = None;
        for module in self.modules.borrow().values() {
            if module.base == handle {
                if let Some(symbol) = module.find_symbol(symbol_name) {
                    found = Some(symbol);
                    break;
                }
            }
        }
        if found.is_none() && (handle == 0 || handle as i64 == -1) {
            for module in self.modules.borrow().values() {
                if let Some(symbol) = module.find_symbol(symbol_name) {
                    found = Some(symbol);
                    break;
                }
            }
        }

        if let Some(svc_memory) = self.svc_memory.borrow().as_ref() {
            let library = found.as_ref().and_then(|symbol| symbol.module.clone());
            let address = found.as_ref().map(|symbol| symbol.address).unwrap_or(0);
            for listener in self.hook_listeners.borrow().iter() {
                let hook = listener.hook(svc_memory, library.as_deref(), symbol_name, address);
                if hook != 0 {
                    return Some(Symbol::virtual_symbol(symbol_name, hook));
                }
            }
        }
        found
    }

    /// `dlclose`: drops a reference and unloads the module when it reaches
    /// zero.
    ///
    /// Port of unidbg: `AndroidElfLoader.dlclose`.
    pub fn dlclose(&self, handle: u64) -> bool {
        let name = self
            .modules
            .borrow()
            .values()
            .find(|module| module.base == handle)
            .map(|module| module.name.clone());
        let Some(name) = name else {
            return false;
        };
        let mut modules = self.modules.borrow_mut();
        let Some(module) = modules.get_mut(&name) else {
            return false;
        };
        module.reference_count = module.reference_count.saturating_sub(1);
        if module.reference_count == 0 {
            let module = modules.remove(&name).expect("just looked up");
            self.unload(&module);
        }
        true
    }

    /// Unmaps every region a module occupied.
    ///
    /// Port of unidbg: `Module.unload`.
    fn unload(&self, module: &Module) {
        for region in &module.regions {
            let _ = self.memory.munmap(region.address, region.size() as usize);
        }
    }

    /// Registers a module with no file behind it.
    ///
    /// Port of unidbg: `AndroidElfLoader.loadVirtualModule`.
    pub fn load_virtual_module(
        &self,
        name: &str,
        symbols: BTreeMap<String, u64>,
    ) -> Result<(), ElfError> {
        if symbols.is_empty() {
            return Err(ElfError::Message(
                "a virtual module needs at least one symbol".into(),
            ));
        }
        let first = *symbols.values().min().expect("non-empty");
        let last = *symbols.values().max().expect("non-empty");
        let (base, size) = align(first, last - first, PAGE_SIZE);
        let module = Module::virtual_module(base, size, name, symbols);
        self.modules.borrow_mut().insert(name.to_string(), module);
        self.note_module_name(name);
        Ok(())
    }

    /// Every loaded module's summary, ordered by name.
    pub fn module_infos(&self) -> Vec<ModuleInfo> {
        self.modules
            .borrow()
            .values()
            .map(|module| ModuleInfo {
                name: module.name.clone(),
                base: module.base,
                size: module.size,
                entry_point: module.entry_point,
                needed_libraries: module.needed_libraries.clone(),
                init_functions: module.init_functions.len(),
                reference_count: module.reference_count,
            })
            .collect()
    }

    /// The module with this name, if it is loaded.
    pub fn module(&self, name: &str) -> Option<ModuleInfo> {
        self.module_infos().into_iter().find(|info| info.name == name)
    }

    /// How many relocations the module still has nowhere to resolve, with the
    /// symbols that are missing. Part of the failure diagnostics the plan asks
    /// for, and what `P5` prints when bionic does not boot.
    pub fn unresolved_relocations(&self, name: &str) -> Vec<String> {
        self.modules
            .borrow()
            .get(name)
            .map(|module| {
                module
                    .unresolved
                    .iter()
                    .map(|pending| pending.symbol_name().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The initialisers a module carries, in call order.
    pub fn module_init_functions(&self, name: &str) -> Vec<u64> {
        self.modules
            .borrow()
            .get(name)
            .map(|module| {
                module
                    .init_functions
                    .iter()
                    .map(|function| {
                        // The slot is re-read, as `AbsoluteInitFunction.call`
                        // does: relocation has rewritten it since the module
                        // was mapped.
                        function
                            .address(self.memory.as_ref())
                            .unwrap_or_else(|_| function.declared_address())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many relocations the module still has nowhere to resolve.
    pub fn unresolved_relocation_count(&self, name: &str) -> usize {
        self.modules
            .borrow()
            .get(name)
            .map(|module| module.unresolved.len())
            .unwrap_or(0)
    }

    /// The module containing `address`.
    pub fn find_module_by_address(&self, address: u64) -> Option<ModuleInfo> {
        self.module_infos()
            .into_iter()
            .find(|info| address >= info.base && address < info.base + info.size)
    }

    /// The symbol nearest below `address`, in the module containing it.
    pub fn find_closest_symbol(&self, address: u64) -> Option<Symbol> {
        let modules = self.modules.borrow();
        let module = modules
            .values()
            .find(|module| address >= module.base && address < module.base + module.size)?;
        module.find_closest_symbol(address)
    }

    /// Every symbol exported by every loaded module.
    pub fn exported_symbols(&self) -> Vec<Symbol> {
        let mut out = Vec::new();
        for module in self.modules.borrow().values() {
            for symbol in module.exported_symbols() {
                out.push(Symbol::new(
                    symbol.name.clone(),
                    module.base.wrapping_add(symbol.value),
                    symbol.size,
                    Some(module.name.clone()),
                ));
            }
        }
        out
    }

    /// Finds a symbol in one module, then in its dependencies.
    ///
    /// Port of unidbg: `Module.findSymbolByName(name, withDependencies)`.
    pub fn find_symbol(&self, module_name: &str, name: &str) -> Option<Symbol> {
        let modules = self.modules.borrow();
        let module = modules.get(module_name)?;
        if let Some(symbol) = module.find_symbol(name) {
            return Some(symbol);
        }
        for needed in &module.needed_libraries {
            if let Some(dependency) = modules.get(needed) {
                if let Some(symbol) = dependency.find_symbol(name) {
                    return Some(symbol);
                }
            }
        }
        None
    }

    // ---- loading --------------------------------------------------------

    fn note_module_name(&self, name: &str) {
        let mut max = self.max_so_name.borrow_mut();
        if max.as_ref().is_none_or(|current| name.len() > current.len()) {
            *max = Some(name.to_string());
        }
    }

    /// Parses, maps, relocates and registers one library.
    ///
    /// Port of unidbg: `AndroidElfLoader.loadInternal(LibraryFile)`.
    fn load_internal(&self, file: &dyn LibraryFile) -> Result<String, ElfError> {
        let data = file.data();
        let elf = Elf::parse(data)?;
        self.check_header(&elf)?;

        let mut bound_high = 0u64;
        let mut segment_align = 0u64;
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD && ph.p_memsz > 0 {
                bound_high = bound_high.max(ph.p_vaddr + ph.p_memsz);
                segment_align = segment_align.max(ph.p_align);
            }
        }

        let base_align = PAGE_SIZE.max(segment_align);
        let load_base = align_size(self.memory.mmap_base_address(), base_align);
        let size = align_size(bound_high, base_align);
        self.memory.set_mmap_base_address(load_base + size);

        let mut regions: Vec<MemRegion> = Vec::new();
        let mut load_virtual_address = 0u64;
        let mut last_alignment: Option<Alignment> = None;

        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let mut prot = prot_of_flags(ph.p_flags);
            if prot.is_empty() {
                prot = Prot::READ.union(Prot::WRITE).union(Prot::EXEC);
            }
            let begin = load_base + ph.p_vaddr;
            if load_virtual_address == 0 {
                load_virtual_address = begin;
            }
            let segment_align = PAGE_SIZE.max(ph.p_align);
            let (check_address, _check_size) = align(begin, ph.p_memsz, segment_align);

            let overlapping = regions
                .last()
                .filter(|last| check_address >= last.begin && check_address < last.end)
                .cloned();
            let alignment = match overlapping {
                Some(last) => {
                    let overall_size = last.end - check_address;
                    let perms = Prot::from_bits(last.perms | prot.bits());
                    self.memory.mprotect_impl(check_address, overall_size as usize, perms)?;
                    if let Some(region) = regions.last_mut() {
                        region.perms = perms.bits();
                    }
                    let alignment = Alignment {
                        address: last.address,
                        size: last.end - last.address,
                        begin,
                        data_size: 0,
                    };
                    if ph.p_memsz > overall_size {
                        let mapped = self.mem_map(
                            begin + overall_size,
                            ph.p_memsz - overall_size,
                            prot,
                            segment_align,
                        )?;
                        regions.push(MemRegion {
                            begin,
                            address: mapped.address,
                            end: mapped.address + mapped.size,
                            perms: prot.bits(),
                            file: file.name().to_string(),
                            virtual_address: ph.p_vaddr,
                        });
                        mapped
                    } else {
                        alignment
                    }
                }
                None => {
                    let mapped = self.mem_map(begin, ph.p_memsz, prot, segment_align)?;
                    regions.push(MemRegion {
                        begin,
                        address: mapped.address,
                        end: mapped.address + mapped.size,
                        perms: prot.bits(),
                        file: file.name().to_string(),
                        virtual_address: ph.p_vaddr,
                    });
                    if let Some(previous) = last_alignment {
                        let base = previous.address + previous.size;
                        let gap = mapped.address.saturating_sub(base);
                        if gap > 0 {
                            self.memory
                                .mmap2(base, gap as usize, Prot::NONE, MAP_FIXED | MAP_ANONYMOUS, -1, 0)?;
                        }
                    }
                    mapped
                }
            };
            let mut alignment = alignment;
            alignment.begin = begin;

            // Write the file contents, clipped to the segment's in-memory size.
            let file_size = ph.p_filesz.min(ph.p_memsz) as usize;
            let start = ph.p_offset as usize;
            if file_size > 0 {
                let bytes = data
                    .get(start..start + file_size)
                    .ok_or_else(|| ElfError::Message("segment extends past end of file".into()))?;
                self.memory.write_bytes(begin, bytes)?;
            }
            alignment.data_size = file_size as u64;
            last_alignment = Some(alignment);
        }

        let dynamic = elf
            .dynamic
            .as_ref()
            .ok_or_else(|| ElfError::Message("the ELF file has no PT_DYNAMIC segment".into()))?;
        let so_name = dynamic_soname(&elf, dynamic).unwrap_or_else(|| file.name().to_string());

        // Dependencies, depth-first.
        let mut needed_libraries = Vec::new();
        for needed in dynamic_needed(&elf, dynamic) {
            let base_name = basename(&needed);
            if self.modules.borrow().contains_key(&base_name) {
                let mut modules = self.modules.borrow_mut();
                if let Some(module) = modules.get_mut(&base_name) {
                    module.reference_count += 1;
                }
                needed_libraries.push(base_name);
                continue;
            }
            let mut resolved = file.resolve_library(&needed);
            if resolved.is_none() {
                if let Some(resolver) = self.library_resolver.borrow().as_ref() {
                    resolved = resolver.resolve_library(&needed);
                }
            }
            match resolved {
                Some(needed_file) => match self.load_internal(needed_file.as_ref()) {
                    Ok(loaded) => {
                        if let Some(module) = self.modules.borrow_mut().get_mut(&loaded) {
                            module.reference_count += 1;
                        }
                        needed_libraries.push(basename(&loaded));
                    }
                    Err(error) => {
                        log::info!("{so_name} could not load its dependency {needed}: {error}");
                    }
                },
                None => log::info!("{so_name} could not resolve its dependency {needed}"),
            }
        }

        // Give every module's pending relocations another chance now that this
        // module's symbols exist.
        self.resolve_symbols(false);

        let mut unresolved = Vec::new();
        let mut resolved = Vec::new();
        for relocation in elf.dynrelas.iter().chain(elf.dynrels.iter()).chain(elf.pltrelocs.iter()) {
            let r_type = relocation.r_type;
            if r_type == 0 {
                log::warn!("unhandled relocation type 0");
                continue;
            }
            let symbol = if relocation.r_sym == 0 {
                None
            } else {
                elf.dynsyms.get(relocation.r_sym).map(|sym| ElfSymbol {
                    name: elf
                        .dynstrtab
                        .get_at(sym.st_name)
                        .unwrap_or("")
                        .to_string(),
                    value: sym.st_value,
                    size: sym.st_size,
                    info: sym.st_info,
                    shndx: sym.st_shndx as u16,
                })
            };
            let sym_value = symbol.as_ref().map(|symbol| symbol.value).unwrap_or(0);
            let relocation_addr = load_base + relocation.r_offset;
            let addend = relocation.r_addend.unwrap_or(0);

            match r_type {
                reloc_type::R_ARM_ABS32 => {
                    let offset = i64::from(self.memory.pointer(relocation_addr).read_u32(0)?);
                    self.push_relocation(
                        &mut unresolved,
                        &mut resolved,
                        load_base,
                        symbol,
                        relocation_addr,
                        &so_name,
                        offset,
                    );
                }
                reloc_type::R_AARCH64_ABS64 => {
                    let offset = self
                        .memory
                        .pointer(relocation_addr)
                        .read_u64(0)? as i64
                        + addend;
                    self.push_relocation(
                        &mut unresolved,
                        &mut resolved,
                        load_base,
                        symbol,
                        relocation_addr,
                        &so_name,
                        offset,
                    );
                }
                reloc_type::R_ARM_RELATIVE => {
                    if sym_value != 0 {
                        return Err(ElfError::Message(format!(
                            "R_ARM_RELATIVE with a symbol value of {sym_value:#x}"
                        )));
                    }
                    let offset = self.memory.pointer(relocation_addr).read_u32(0)?;
                    self.memory
                        .pointer(relocation_addr)
                        .write_u32(0, (load_base as u32).wrapping_add(offset))?;
                }
                reloc_type::R_AARCH64_RELATIVE => {
                    if sym_value != 0 {
                        return Err(ElfError::Message(format!(
                            "R_AARCH64_RELATIVE with a symbol value of {sym_value:#x}"
                        )));
                    }
                    self.memory
                        .pointer(relocation_addr)
                        .write_u64(0, load_base.wrapping_add(addend as u64))?;
                }
                reloc_type::R_ARM_GLOB_DAT | reloc_type::R_ARM_JUMP_SLOT => {
                    self.push_relocation(
                        &mut unresolved,
                        &mut resolved,
                        load_base,
                        symbol,
                        relocation_addr,
                        &so_name,
                        0,
                    );
                }
                reloc_type::R_AARCH64_GLOB_DAT | reloc_type::R_AARCH64_JUMP_SLOT => {
                    self.push_relocation(
                        &mut unresolved,
                        &mut resolved,
                        load_base,
                        symbol,
                        relocation_addr,
                        &so_name,
                        addend,
                    );
                }
                reloc_type::R_ARM_COPY | reloc_type::R_AARCH64_COPY => {
                    return Err(ElfError::Message(format!(
                        "R_*_COPY relocations are not supported (symbol {})",
                        symbol.as_ref().map(|s| s.name.as_str()).unwrap_or("")
                    )));
                }
                other => {
                    log::warn!(
                        "[{so_name}] unhandled relocation type {other}, symbol {}, offset {:#x}",
                        symbol.as_ref().map(|s| s.name.as_str()).unwrap_or(""),
                        relocation.r_offset
                    );
                }
            }
        }

        // Initialisers.
        let mut init_functions = Vec::new();
        let preinit_size = dynamic_value(dynamic, dynamic::DT_PREINIT_ARRAYSZ).unwrap_or(0);
        let executable = elf.header.e_type == header::ET_EXEC || preinit_size > 0;
        if executable {
            let count = preinit_size / self.pointer_size as u64;
            if count > 0 {
                let array = load_base
                    + dynamic_value(dynamic, dynamic::DT_PREINIT_ARRAY).ok_or_else(|| {
                        ElfError::Message("DT_PREINIT_ARRAY is missing".into())
                    })?;
                for index in 0..count {
                    let ptr = array + index * self.pointer_size as u64;
                    let address = self.read_pointer(ptr)?;
                    init_functions.push(InitFunction::Absolute {
                        load_base,
                        lib_name: so_name.clone(),
                        ptr,
                        address,
                    });
                }
            }
        }
        if elf.header.e_type == header::ET_DYN {
            if let Some(init) = dynamic_value(dynamic, dynamic::DT_INIT) {
                if init != 0 {
                    init_functions.push(InitFunction::Linux {
                        load_base,
                        lib_name: so_name.clone(),
                        address: init,
                    });
                }
            }
            let init_array_size = dynamic_value(dynamic, dynamic::DT_INIT_ARRAYSZ).unwrap_or(0);
            let count = init_array_size / self.pointer_size as u64;
            if count > 0 {
                let array = load_base
                    + dynamic_value(dynamic, dynamic::DT_INIT_ARRAY)
                        .ok_or_else(|| ElfError::Message("DT_INIT_ARRAY is missing".into()))?;
                for index in 0..count {
                    let ptr = array + index * self.pointer_size as u64;
                    let address = self.read_pointer(ptr)?;
                    init_functions.push(InitFunction::Absolute {
                        load_base,
                        lib_name: so_name.clone(),
                        ptr,
                        address,
                    });
                }
            }
        }

        if load_virtual_address == 0 {
            return Err(ElfError::Message("the module has no loadable segment".into()));
        }

        let symbols = elf
            .dynsyms
            .iter()
            .map(|sym| ElfSymbol {
                name: elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string(),
                value: sym.st_value,
                size: sym.st_size,
                info: sym.st_info,
                shndx: sym.st_shndx as u16,
            })
            .collect();

        let mut module = Module::new(
            load_virtual_address,
            load_base,
            size,
            so_name.clone(),
            symbols,
        );
        module.entry_point = elf.entry;
        module.unresolved = unresolved;
        module.init_functions = init_functions;
        module.needed_libraries = needed_libraries;
        module.regions = regions;

        // Apply the relocations that resolved, and remember them so a module
        // loaded later can re-relocate against its own definitions.
        for pending in &resolved {
            self.apply_relocation(pending, &so_name);
        }
        for pending in resolved {
            module
                .resolved_symbols
                .insert(pending.symbol_name().to_string(), pending);
        }

        // A newly loaded module may define symbols other modules imported.
        if executable {
            self.relocate_against(&module);
        }

        if so_name == "libc.so" {
            if let (Some(malloc), Some(free)) = (
                module.find_symbol("malloc"),
                module.find_symbol("free"),
            ) {
                log::debug!("libc.so provides malloc={:#x} free={:#x}", malloc.address, free.address);
            }
        }

        self.modules.borrow_mut().insert(so_name.clone(), module);
        self.note_module_name(&so_name);
        if bound_high > self.max_size_of_so.get() {
            self.max_size_of_so.set(bound_high);
        }
        Ok(so_name)
    }

    /// Re-relocates every module's remembered resolutions against this module's
    /// definitions.
    ///
    /// Port of unidbg: the `if (executable)` block in `loadInternal`.
    fn relocate_against(&self, module: &Module) {
        let names: Vec<String> = self.modules.borrow().keys().cloned().collect();
        for name in names {
            let remembered = match self.modules.borrow_mut().get_mut(&name) {
                Some(other) => std::mem::take(&mut other.resolved_symbols),
                None => continue,
            };
            for (symbol_name, pending) in remembered {
                match module.find_symbol(&symbol_name) {
                    Some(_symbol) => self.apply_relocation(
                        &ModuleSymbol {
                            to_so_name: Some(module.name.clone()),
                            ..pending
                        },
                        &name,
                    ),
                    None => {
                        if let Some(other) = self.modules.borrow_mut().get_mut(&name) {
                            other.resolved_symbols.insert(symbol_name, pending);
                        }
                    }
                }
            }
        }
    }

    fn push_relocation(
        &self,
        unresolved: &mut Vec<ModuleSymbol>,
        resolved: &mut Vec<ModuleSymbol>,
        load_base: u64,
        symbol: Option<ElfSymbol>,
        relocation_addr: u64,
        so_name: &str,
        offset: i64,
    ) {
        match self.resolve_symbol(load_base, symbol.clone(), relocation_addr, so_name, offset) {
            Some(pending) => resolved.push(pending),
            None => unresolved.push(ModuleSymbol::new(
                so_name,
                load_base,
                symbol,
                relocation_addr,
                None,
                offset,
            )),
        }
    }

    /// Resolves one relocation's symbol.
    ///
    /// Port of unidbg: `AndroidElfLoader.resolveSymbol`, which first gives
    /// hook listeners a chance, then searches the dependency modules.
    fn resolve_symbol(
        &self,
        load_base: u64,
        symbol: Option<ElfSymbol>,
        relocation_addr: u64,
        so_name: &str,
        offset: i64,
    ) -> Option<ModuleSymbol> {
        let Some(symbol) = symbol else {
            return Some(ModuleSymbol::new(
                so_name,
                load_base,
                None,
                relocation_addr,
                Some(so_name.to_string()),
                offset,
            ));
        };

        if !symbol.is_undefined() {
            if let Some(svc_memory) = self.svc_memory.borrow().as_ref() {
                let address = load_base + symbol.value + offset as u64;
                for listener in self.hook_listeners.borrow().iter() {
                    let hook = listener.hook(svc_memory, Some(so_name), &symbol.name, address);
                    if hook > 0 {
                        return Some(ModuleSymbol::new(
                            so_name,
                            WEAK_BASE,
                            Some(symbol),
                            relocation_addr,
                            Some(so_name.to_string()),
                            hook as i64,
                        ));
                    }
                }
            }
            return Some(ModuleSymbol::new(
                so_name,
                load_base,
                Some(symbol),
                relocation_addr,
                Some(so_name.to_string()),
                offset,
            ));
        }

        let pending = ModuleSymbol::new(
            so_name,
            load_base,
            Some(symbol),
            relocation_addr,
            None,
            offset,
        );
        self.resolve_pending(&pending, false)
    }

    /// Searches every loaded module for a pending relocation's symbol.
    ///
    /// Port of unidbg: `ModuleSymbol.resolve`.
    fn resolve_pending(&self, pending: &ModuleSymbol, resolve_weak: bool) -> Option<ModuleSymbol> {
        let symbol = pending.symbol.as_ref()?;
        let symbol_name = symbol.name.clone();
        let modules = self.modules.borrow();
        for module in modules.values() {
            if let Some(address) = module.hook_map.get(&symbol_name) {
                return Some(ModuleSymbol {
                    load_base: WEAK_BASE,
                    to_so_name: Some(module.name.clone()),
                    offset: *address as i64,
                    ..pending.clone()
                });
            }
            let Some(elf_symbol) = module.elf_symbol_by_name(&symbol_name) else {
                continue;
            };
            if elf_symbol.is_undefined() {
                continue;
            }
            // Only global and weak definitions are eligible, as in ELF.
            let binding = elf_symbol.binding();
            if binding != super::symbol::BINDING_GLOBAL && binding != super::symbol::BINDING_WEAK {
                continue;
            }
            if let Some(svc_memory) = self.svc_memory.borrow().as_ref() {
                let address = module
                    .base
                    .wrapping_add(elf_symbol.value)
                    .wrapping_add(pending.offset as u64);
                for listener in self.hook_listeners.borrow().iter() {
                    let hook = listener.hook(svc_memory, Some(&module.name), &symbol_name, address);
                    if hook > 0 {
                        return Some(ModuleSymbol {
                            load_base: WEAK_BASE,
                            to_so_name: Some(module.name.clone()),
                            offset: hook as i64,
                            ..pending.clone()
                        });
                    }
                }
            }
            return Some(ModuleSymbol {
                load_base: module.base,
                symbol: Some(elf_symbol.clone()),
                to_so_name: Some(module.name.clone()),
                ..pending.clone()
            });
        }

        if resolve_weak && symbol.is_weak() {
            return Some(ModuleSymbol {
                load_base: WEAK_BASE,
                to_so_name: Some("0".into()),
                offset: 0,
                ..pending.clone()
            });
        }

        if is_dl_symbol(&symbol_name) && resolve_weak {
            if let Some(svc_memory) = self.svc_memory.borrow().as_ref() {
                for listener in self.hook_listeners.borrow().iter() {
                    let hook = listener.hook(svc_memory, Some("libdl.so"), &symbol_name, pending.offset as u64);
                    if hook > 0 {
                        return Some(ModuleSymbol {
                            load_base: WEAK_BASE,
                            to_so_name: Some("libdl.so".into()),
                            offset: hook as i64,
                            ..pending.clone()
                        });
                    }
                }
            }
        }
        None
    }

    /// Writes a resolved relocation and records it for later re-relocation.
    ///
    /// Port of unidbg: `ModuleSymbol.relocation(emulator, module)`.
    fn apply_relocation(&self, pending: &ModuleSymbol, owner: &str) {
        let value = pending.value();
        let pointer = self.memory.pointer(pending.relocation_addr);
        let write = if self.is_64bit {
            pointer.write_u64(0, value)
        } else {
            pointer.write_u32(0, value as u32)
        };
        if let Err(error) = write {
            log::warn!(
                "cannot apply relocation for {} at {:#x}: {error}",
                pending.symbol_name(),
                pending.relocation_addr
            );
            return;
        }
        if let Some(module) = self.modules.borrow_mut().get_mut(owner) {
            if let Some(symbol) = pending.symbol.as_ref() {
                module
                    .resolved_symbols
                    .insert(symbol.name.clone(), pending.clone());
            }
        }
    }

    fn read_pointer(&self, address: u64) -> Result<u64, ElfError> {
        let pointer = self.memory.pointer(address);
        Ok(if self.is_64bit {
            pointer.read_u64(0)?
        } else {
            u64::from(pointer.read_u32(0)?)
        })
    }

    fn mem_map(
        &self,
        address: u64,
        size: u64,
        prot: Prot,
        align_to: u64,
    ) -> Result<Alignment, ElfError> {
        let (aligned_address, aligned_size) = align(address, size, align_to);
        self.memory.mmap2(
            aligned_address,
            aligned_size as usize,
            prot,
            MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        )?;
        Ok(Alignment {
            address: aligned_address,
            size: aligned_size,
            begin: address,
            data_size: 0,
        })
    }

    fn check_header(&self, elf: &Elf<'_>) -> Result<(), ElfError> {
        let class = elf.header.e_ident[header::EI_CLASS];
        if self.is_64bit && class != header::ELFCLASS64 {
            return Err(ElfError::Message("the library must be 64-bit".into()));
        }
        if !self.is_64bit && class != header::ELFCLASS32 {
            return Err(ElfError::Message("the library must be 32-bit".into()));
        }
        if elf.header.e_ident[header::EI_DATA] != header::ELFDATA2LSB {
            return Err(ElfError::Message("the library must be little-endian".into()));
        }
        if self.is_64bit && elf.header.e_machine != header::EM_AARCH64 {
            return Err(ElfError::Message("the library must be AArch64".into()));
        }
        if !self.is_64bit && elf.header.e_machine != header::EM_ARM {
            return Err(ElfError::Message("the library must be ARM".into()));
        }
        Ok(())
    }
}

/// Calls a guest initialiser.
///
/// unidbg calls `emulator.eFunc(address)`; the emulator installs this in P5.
pub trait InitCaller {
    /// Runs the function at `address` to completion.
    fn call_init(&self, address: u64) -> Result<(), ElfError>;
}

/// The `DT_SONAME` of a parsed file, if it has one.
fn dynamic_soname(elf: &Elf<'_>, dynamic: &goblin::elf::Dynamic) -> Option<String> {
    let value = dynamic_value(dynamic, dynamic::DT_SONAME)?;
    elf.dynstrtab.get_at(value as usize).map(str::to_string)
}

/// The `DT_NEEDED` names of a parsed file.
fn dynamic_needed(elf: &Elf<'_>, dynamic: &goblin::elf::Dynamic) -> Vec<String> {
    dynamic
        .dyns
        .iter()
        .filter(|entry| entry.d_tag == dynamic::DT_NEEDED)
        .filter_map(|entry| elf.dynstrtab.get_at(entry.d_val as usize))
        .map(str::to_string)
        .collect()
}

/// The value of the first `tag` entry.
fn dynamic_value(dynamic: &goblin::elf::Dynamic, tag: u64) -> Option<u64> {
    dynamic
        .dyns
        .iter()
        .find(|entry| entry.d_tag == tag)
        .map(|entry| entry.d_val)
}

/// The protection a segment's flags ask for; `PROT_NONE` when it has none,
/// which the caller turns into full access as unidbg does.
fn prot_of_flags(flags: u32) -> Prot {
    let mut prot = Prot::NONE;
    if flags & PF_R != 0 {
        prot = prot.union(Prot::READ);
    }
    if flags & PF_W != 0 {
        prot = prot.union(Prot::WRITE);
    }
    if flags & PF_X != 0 {
        prot = prot.union(Prot::EXEC);
    }
    prot
}

/// The file name part of a path.
fn basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// The `libdl` symbols a hook listener may supply, as unidbg's
/// `ModuleSymbol.resolve` lists them.
fn is_dl_symbol(name: &str) -> bool {
    matches!(
        name,
        "dlopen"
            | "dlclose"
            | "dlsym"
            | "dlerror"
            | "dladdr"
            | "android_update_LD_LIBRARY_PATH"
            | "android_get_LD_LIBRARY_PATH"
            | "dl_iterate_phdr"
            | "android_dlopen_ext"
            | "android_set_application_target_sdk_version"
            | "android_get_application_target_sdk_version"
            | "android_init_namespaces"
            | "android_create_namespace"
            | "dlvsym"
            | "android_dlwarning"
            | "dl_unwind_find_exidx"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_protection_follows_the_flags() {
        assert_eq!(prot_of_flags(PF_R), Prot::READ);
        assert_eq!(prot_of_flags(PF_R | PF_W), Prot::READ.union(Prot::WRITE));
        assert_eq!(
            prot_of_flags(PF_R | PF_X),
            Prot::READ.union(Prot::EXEC)
        );
        assert_eq!(prot_of_flags(0), Prot::NONE);
    }

    #[test]
    fn basenames_strip_directories() {
        assert_eq!(basename("/system/lib64/libc.so"), "libc.so");
        assert_eq!(basename("libm.so"), "libm.so");
        assert_eq!(basename("lib/x86/libz.so"), "libz.so");
    }

    #[test]
    fn dl_symbols_are_recognised() {
        assert!(is_dl_symbol("dlopen"));
        assert!(is_dl_symbol("dl_unwind_find_exidx"));
        assert!(!is_dl_symbol("malloc"));
    }
}
