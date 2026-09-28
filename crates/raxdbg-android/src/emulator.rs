//! The Android emulator: the loader, the syscall layer and the backend wired
//! together.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidARM64Emulator.java`,
//! `AndroidARMEmulator.java`, `AndroidEmulator.java`,
//! `unidbg-api/src/main/java/com/github/unidbg/arm/AbstractARM64Emulator.java`
//! and `AbstractARMEmulator.java`@7f5da98e.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use raxdbg_core::alloc::GuestCall;
use raxdbg_core::backend::{
    Backend, BackendError, EventMemHook, Prot, RunError, UnmappedKind,
};
use raxdbg_core::memory::loader::Loader;
use raxdbg_core::memory::{Memory, MemoryError};
use raxdbg_core::reg::RegId;
use raxdbg_backend_rax::RaxBackend;

use crate::android_file::LibraryFile;
use crate::elf::loader::{AndroidElfLoader, ElfError, InitCaller};
use crate::linux::android::arm_ld::ArmLd64;
use crate::linux::android::resolver::AndroidResolver;
use crate::linux::android::system_property::{SystemPropertyHook, SystemPropertyProvider};
use crate::linux::android::virtual_module::{
    AndroidModule, JniGraphics, MediaNdkModule, SystemProperties,
};
use crate::syscall::android::{AndroidSyscallHandler, SyscallHook};

/// The `LR` trap page's address on arm64.
///
/// Port of unidbg: `AbstractARM64Emulator.LR`. A function call returns by
/// branching here; the page is filled with `svc #0`, and the run loop stops
/// *before* executing the instruction at `until`, so the call ends.
pub const ARM64_TRAP_ADDRESS: u64 = 0x7ffff_0000;

/// The `LR` trap page's address on arm32.
pub const ARM32_TRAP_ADDRESS: u64 = 0xffff_0000;

/// The default process name.
pub const DEFAULT_PROCESS_NAME: &str = "unidbg-android";

/// Why an emulator could not be built.
#[derive(Debug, thiserror::Error)]
pub enum EmulatorError {
    /// The loader could not be created.
    #[error(transparent)]
    Elf(#[from] ElfError),
    /// The syscall layer could not be created.
    #[error(transparent)]
    Syscall(#[from] crate::syscall::AndroidSyscallError),
    /// A guest function call failed.
    #[error(transparent)]
    Run(#[from] RunError),
    /// The backend rejected an operation.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// The bundled libraries are missing.
    #[error(transparent)]
    Resolver(#[from] crate::linux::android::ResolverError),
    /// A host service could not register its stubs.
    #[error(transparent)]
    Stub(#[from] crate::linux::android::system_property::RegisterError),
    /// The `libdl` trampolines could not be registered.
    #[error(transparent)]
    Dlfcn(#[from] crate::linux::android::arm_ld::RegisterError),
    /// The library could not be loaded.
    #[error("{0}")]
    Message(String),
    /// Guest memory rejected an operation.
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

/// An Android emulator: a rax backend, an ELF loader, the syscall layer and
/// the Android host services.
pub struct AndroidEmulator {
    backend: Rc<RefCell<dyn Backend>>,
    loader: Rc<AndroidElfLoader>,
    syscall: Rc<RefCell<AndroidSyscallHandler>>,
    resolver: Rc<AndroidResolver>,
    is_64bit: bool,
    process_name: String,
    trap_address: u64,
    stdout: std::sync::Arc<crate::syscall::SharedSink>,
}

impl std::fmt::Debug for AndroidEmulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidEmulator")
            .field("is_64bit", &self.is_64bit)
            .field("process_name", &self.process_name)
            .field("modules", &self.loader.module_infos().len())
            .finish()
    }
}

impl AndroidEmulator {
    /// Builds an emulator, wiring the loader, the syscall layer, the trap page
    /// and the Android host services in unidbg's constructor order.
    pub fn new(
        is_64bit: bool,
        process_name: &str,
        root_dir: Option<PathBuf>,
        libs_dir: Option<PathBuf>,
        sdk: u32,
        seed: u64,
    ) -> Result<Rc<Self>, EmulatorError> {
        let backend = if is_64bit {
            RaxBackend::new_arm64(RaxBackend::default_space())
        } else {
            RaxBackend::new_arm32(RaxBackend::default_space())
        };
        let guest = backend.guest_memory();
        let backend: Rc<RefCell<dyn Backend>> = Rc::new(RefCell::new(backend));

        let loader = AndroidElfLoader::new(
            Rc::clone(&backend),
            guest,
            is_64bit,
            process_name,
            seed,
        )?;

        {
            let mut backend = backend.borrow_mut();
            backend.switch_user_mode();
            backend.enable_vfp();
            // unidbg's framework hook: an unmapped access is reported, and the
            // run loop turns it into `RunError::UnmappedMemory`.
            backend.hook_add_event_mem(Box::new(UnmappedMemoryHook), UnmappedKind::Read);
            backend.hook_add_event_mem(Box::new(UnmappedMemoryHook), UnmappedKind::Write);
            backend.hook_add_event_mem(Box::new(UnmappedMemoryHook), UnmappedKind::Fetch);
        }

        let syscall = AndroidSyscallHandler::new(Rc::clone(&loader), is_64bit, None)?;
        let stdout = syscall.borrow().stdout_sink();

        let mut resolver = match libs_dir {
            Some(dir) => AndroidResolver::with_libs_dir(sdk, is_64bit, dir),
            None => AndroidResolver::new(sdk, is_64bit)?,
        };
        if let Some(root) = root_dir {
            resolver.set_root_dir(root);
        }
        let resolver = Rc::new(resolver);
        let resolver_trait: Rc<dyn crate::android_file::LibraryResolver> =
            Rc::clone(&resolver) as Rc<dyn crate::android_file::LibraryResolver>;
        loader.set_library_resolver(resolver_trait);
        // The same resolver serves guest paths: without this the syscall
        // handler's I/O chain is empty and every `open` of a bundled resource
        // -- `/dev/__properties__` above all -- answers ENOENT. arm64 hid it
        // because `__system_property_get` is answered by a hook, but arm32's
        // `__system_property_area_init` opens the file for real.
        syscall
            .borrow()
            .unix_handler()
            .add_io_resolver(Box::new(crate::linux::android::resolver::SharedResolver(
                Rc::clone(&resolver),
            )));

        let emulator = Rc::new(AndroidEmulator {
            backend: Rc::clone(&backend),
            loader: Rc::clone(&loader),
            syscall: Rc::clone(&syscall),
            resolver: Rc::clone(&resolver),
            is_64bit,
            process_name: process_name.to_string(),
            trap_address: if is_64bit {
                ARM64_TRAP_ADDRESS
            } else {
                ARM32_TRAP_ADDRESS
            },
            stdout,
        });

        emulator.setup_traps()?;
        emulator.install_host_services()?;
        emulator.install_init_caller();

        {
            let mut backend = backend.borrow_mut();
            backend.hook_add_interrupt(Box::new(SyscallHook::new(Rc::clone(&syscall))));
        }
        Ok(emulator)
    }

    /// Maps the `LR` trap page, filled with `svc #0`.
    ///
    /// Port of unidbg: `AbstractARM64Emulator.setupTraps`.
    fn setup_traps(&self) -> Result<(), EmulatorError> {
        let memory = self.loader.memory();
        memory.mmap2(
            self.trap_address,
            0x1000,
            Prot::READ.union(Prot::EXEC),
            raxdbg_core::memory::MAP_FIXED | raxdbg_core::memory::MAP_ANONYMOUS,
            -1,
            0,
        )?;
        let word: [u8; 4] = if self.is_64bit {
            0xd400_0001u32.to_le_bytes()
        } else {
            0xef00_0000u32.to_le_bytes()
        };
        let mut page = Vec::with_capacity(0x1000);
        for _ in 0..0x400 {
            page.extend_from_slice(&word);
        }
        memory.write_bytes(self.trap_address, &page)?;
        Ok(())
    }

    /// Registers the `libdl` trampolines, the virtual modules and the system
    /// property hook, in unidbg's order.
    fn install_host_services(&self) -> Result<(), EmulatorError> {
        let svc_memory = self.loader.svc_memory().expect("the syscall layer built one");
        if self.is_64bit {
            let arm_ld = ArmLd64::register(
                svc_memory.as_ref(),
                self.loader.memory().as_ref(),
                Rc::new(crate::linux::android::system_property::StubDispatch::new()),
                Rc::clone(&self.loader),
            )?;
            self.loader
                .add_hook_listener(Rc::new(arm_ld) as Rc<dyn raxdbg_core::hook::HookListener>);
        }

        let provider = SystemPropertyProvider::with_defaults(
            self.resolver.sdk(),
            self.is_64bit,
        );
        let dispatch = Rc::new(crate::linux::android::system_property::StubDispatch::new());
        let property_hook = SystemPropertyHook::register(
            svc_memory.as_ref(),
            self.loader.memory().as_ref(),
            dispatch,
            self.is_64bit,
            self.loader.pointer_size(),
            provider,
        )?;
        self.loader
            .add_hook_listener(Rc::new(property_hook) as Rc<dyn raxdbg_core::hook::HookListener>);

        AndroidModule::register(&self.loader)?;
        SystemProperties::register(&self.loader)?;
        JniGraphics::register(&self.loader)?;
        MediaNdkModule::register(&self.loader)?;
        Ok(())
    }

    /// Lets the loader run a module's initialisers through [`Self::call_function`].
    fn install_init_caller(self: &Rc<Self>) {
        self.loader.set_init_caller(Rc::new(InitCallerAdapter {
            backend: Rc::clone(&self.backend),
            memory: Rc::clone(self.loader.memory()),
            trap: self.trap_address,
            is_64bit: self.is_64bit,
        }));
    }

    /// The CPU backend.
    pub fn backend(&self) -> &Rc<RefCell<dyn Backend>> {
        &self.backend
    }

    /// The memory facade.
    pub fn memory(&self) -> &Rc<Loader> {
        self.loader.memory()
    }

    /// The ELF loader.
    pub fn loader(&self) -> &Rc<AndroidElfLoader> {
        &self.loader
    }

    /// The syscall layer.
    pub fn syscall(&self) -> &Rc<RefCell<AndroidSyscallHandler>> {
        &self.syscall
    }

    /// The library resolver over `libs/`.
    pub fn resolver(&self) -> &Rc<AndroidResolver> {
        &self.resolver
    }

    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The process name the guest sees.
    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    /// The `LR` trap page's address.
    pub fn trap_address(&self) -> u64 {
        self.trap_address
    }

    /// The captured `stdout`/`stderr` sink.
    pub fn stdout(&self) -> std::sync::Arc<crate::syscall::SharedSink> {
        std::sync::Arc::clone(&self.stdout)
    }

    /// Loads a library from the resolver, running its initialisers.
    pub fn load_library(&self, name: &str) -> Result<String, EmulatorError> {
        let file = crate::android_file::LibraryResolver::resolve_library(&*self.resolver, name)
            .ok_or_else(|| EmulatorError::Message(format!("cannot resolve {name}")))?;
        self.loader
            .load(file, false)
            .map_err(EmulatorError::from)
    }

    /// Loads a library file, running its initialisers.
    pub fn load(
        &self,
        file: Box<dyn LibraryFile>,
        force_call_init: bool,
    ) -> Result<String, EmulatorError> {
        self.loader
            .load(file, force_call_init)
            .map_err(EmulatorError::from)
    }

    /// Calls a guest function and returns its result.
    ///
    /// Port of unidbg: `AbstractARM64Emulator.eFunc` / `AbstractARMEmulator.eEntry`:
    /// the link register is set to the trap page and the run stops there, so
    /// the callee's `ret` ends the call.
    pub fn call_function(&self, address: u64, args: &[u64]) -> Result<u64, EmulatorError> {
        AndroidEmulator::call_function_on(
            &self.backend,
            self.loader.memory(),
            self.trap_address,
            self.is_64bit,
            address,
            args,
        )
    }

    pub(crate) fn call_function_on(
        backend: &Rc<RefCell<dyn Backend>>,
        memory: &Rc<Loader>,
        trap: u64,
        is_64bit: bool,
        address: u64,
        args: &[u64],
    ) -> Result<u64, EmulatorError> {
        // The ABI requires a 16-byte-aligned stack at a call boundary, and
        // `write_stack_string` (which a caller uses to build arguments) aligns
        // its own allocation to four bytes. bionic's `ldp`/`stp` take an
        // alignment fault otherwise, which is what made `printf` fail.
        let align = if is_64bit { 16 } else { 8 };
        let sp = (memory.get_stack_point() - align) & !(align - 1);
        memory.set_stack_point(sp);
        let result = {
            let mut backend = backend.borrow_mut();
            for (index, arg) in args.iter().enumerate() {
                let reg = if is_64bit {
                    RegId::X(index as u8)
                } else {
                    RegId::R(index as u8)
                };
                backend.reg_write(reg, *arg)?;
            }
            backend.reg_write(RegId::Lr, trap)?;
            backend.emu_start(address, trap, 0, 0)?;
            let value = if is_64bit {
                backend.reg_read(RegId::X(0))?
            } else {
                backend.reg_read(RegId::R(0))?
            };
            Ok::<u64, EmulatorError>(value)
        };
        memory.set_stack_point(sp + align);
        result
    }

    /// Registers the guest's `malloc`/`free` with the memory facade once
    /// `libc.so` is loaded, so `Memory::malloc(len, false)` routes through them.
    pub fn register_libc_allocator(self: &Rc<Self>) -> bool {
        let (Some(malloc), Some(free)) = (
            self.loader.find_symbol("libc.so", "malloc"),
            self.loader.find_symbol("libc.so", "free"),
        ) else {
            return false;
        };
        self.loader.memory().set_libc_allocator(
            malloc.address,
            free.address,
            Rc::new(GuestCallAdapter {
                backend: Rc::clone(&self.backend),
                memory: Rc::clone(self.loader.memory()),
                trap: self.trap_address,
                is_64bit: self.is_64bit,
            }),
        );
        true
    }

    /// Runs `address` with no arguments, as a module initialiser.
    pub fn call_init(&self, address: u64) -> Result<u64, EmulatorError> {
        self.call_function(address, &[])
    }
}

/// Calls guest functions from host code that only has the backend and memory.
struct GuestCallAdapter {
    backend: Rc<RefCell<dyn Backend>>,
    memory: Rc<Loader>,
    trap: u64,
    is_64bit: bool,
}

impl GuestCall for GuestCallAdapter {
    fn call(&self, address: u64, args: &[u64]) -> Result<u64, MemoryError> {
        AndroidEmulator::call_function_on(
            &self.backend,
            &self.memory,
            self.trap,
            self.is_64bit,
            address,
            args,
        )
        .map_err(|error| MemoryError::Message(format!("calling {address:#x}: {error}")))
    }
}

/// The loader's initialiser hook.
struct InitCallerAdapter {
    backend: Rc<RefCell<dyn Backend>>,
    memory: Rc<Loader>,
    trap: u64,
    is_64bit: bool,
}

impl InitCaller for InitCallerAdapter {
    fn call_init(&self, address: u64) -> Result<(), ElfError> {
        AndroidEmulator::call_function_on(
            &self.backend,
            &self.memory,
            self.trap,
            self.is_64bit,
            address,
            &[],
        )
        .map(|_| ())
        .map_err(|error| ElfError::Message(format!("initialiser {address:#x}: {error}")))
    }
}

/// unidbg's framework hook: report an unmapped access and let the run loop
/// turn it into `RunError::UnmappedMemory`.
struct UnmappedMemoryHook;

impl EventMemHook for UnmappedMemoryHook {
    fn hook(
        &mut self,
        _backend: &mut dyn Backend,
        address: u64,
        size: usize,
        _value: u64,
        kind: UnmappedKind,
    ) -> bool {
        log::warn!("unmapped {kind} access at {address:#x} (size {size})");
        false
    }
}

/// Builds an emulator the way unidbg's `AndroidEmulatorBuilder` does.
#[derive(Debug, Clone)]
pub struct AndroidEmulatorBuilder {
    is_64bit: bool,
    process_name: String,
    root_dir: Option<PathBuf>,
    sdk: u32,
    seed: u64,
    libs_dir: Option<PathBuf>,
}

impl Default for AndroidEmulatorBuilder {
    fn default() -> Self {
        AndroidEmulatorBuilder {
            is_64bit: true,
            process_name: DEFAULT_PROCESS_NAME.to_string(),
            root_dir: None,
            sdk: 23,
            seed: 0,
            libs_dir: None,
        }
    }
}

impl AndroidEmulatorBuilder {
    /// A builder for a 64-bit guest.
    pub fn for_64bit() -> Self {
        AndroidEmulatorBuilder {
            is_64bit: true,
            sdk: 23,
            ..Default::default()
        }
    }

    /// A builder for a 32-bit guest.
    pub fn for_32bit() -> Self {
        AndroidEmulatorBuilder {
            is_64bit: false,
            sdk: 19,
            ..Default::default()
        }
    }

    /// Sets the process name the guest sees.
    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = name.into();
        self
    }

    /// Sets the root directory guest paths resolve under.
    pub fn root_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(dir.into());
        self
    }

    /// Sets the SDK level whose bundled libraries are used.
    pub fn sdk(mut self, sdk: u32) -> Self {
        self.sdk = sdk;
        self
    }

    /// Reads the bundled libraries from `dir` instead of the default tree.
    pub fn libs_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.libs_dir = Some(dir.into());
        self
    }

    /// Seeds the random source, so a run is reproducible.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Builds the emulator.
    pub fn build(self) -> Result<Rc<AndroidEmulator>, EmulatorError> {
        AndroidEmulator::new(
            self.is_64bit,
            &self.process_name,
            self.root_dir,
            self.libs_dir,
            self.sdk,
            self.seed,
        )
    }
}
