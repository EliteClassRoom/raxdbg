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
    /// The thread entry point and the `clone`/`pthread_join` replacements.
    thread_start: std::cell::RefCell<Option<Rc<crate::thread::join::ThreadStart>>>,
    /// The threads `clone` has been asked for.
    thread_join: std::cell::RefCell<Option<Rc<crate::thread::join::ThreadJoin>>>,
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
            thread_start: std::cell::RefCell::new(None),
            thread_join: std::cell::RefCell::new(None),
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

        // bionic's atexit family, so a library initialiser that registers a
        // destructor does not walk a list the emulator never built.
        crate::linux::android::atexit::AtExitModule::register(&self.loader)?;
        // libc++'s initialiser is genuine, and unidbg runs it too -- it just
        // never gets there, because unidbg does not decode the packed
        // relocations that give libc++'s init_array a value. Decoding them is
        // the more correct behaviour, and it makes the initialiser run into
        // `pthread_mutex_lock`, which walks a bionic pthread structure this
        // port does not model. The filter says exactly that, so the skip is a
        // decision rather than a fault. See docs/known-gaps.md.
        self.loader
            .set_init_function_filter(Rc::new(SkipCxxInit));

        // `clone` and `pthread_join`, the two libc functions unidbg replaces to
        // make threads (plan P7). The entry code is precomputed (plan D9).
        let start = crate::thread::join::install_entry(self)
            .map_err(EmulatorError::Memory)?;
        let joint = crate::thread::join::install(self, &start).map_err(EmulatorError::Memory)?;
        *self.thread_start.borrow_mut() = Some(Rc::new(start));
        joint.set_memory(Rc::clone(self.loader.memory()));
        *self.thread_join.borrow_mut() = Some(joint);
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
    /// The thread entry point and the `clone`/`pthread_join` replacements.
    ///
    /// Installed during boot, so it is the one a thread actually runs; a test
    /// that installs its own would be testing a second copy.
    pub fn thread_start(&self) -> Option<Rc<crate::thread::join::ThreadStart>> {
        self.thread_start.borrow().clone()
    }

    /// The threads `clone` has been asked for, and which of them may be joined.
    pub fn thread_join(&self) -> Option<Rc<crate::thread::join::ThreadJoin>> {
        self.thread_join.borrow().clone()
    }

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
    /// Calls a guest function, running the threads it creates.
    ///
    /// A `pthread_join` (or a futex wait) parks its caller: the syscall cannot
    /// make progress, so it asks for a `ThreadSwitch` and something else has to
    /// run. That "something" is the thread the guest just created.
    ///
    /// The caller therefore has to be a task of the dispatcher's own, which is
    /// how unidbg does it: there a `ThreadContextSwitchException` unwinds to a
    /// dispatcher that is already running the caller as a task, so a wake puts
    /// the caller's saved context back and the `svc` returns the value it owes.
    /// Running the caller on a stack of its own and handing its context to the
    /// dispatcher makes the same thing true here.
    pub fn call_function_driven(self: &Rc<Self>, address: u64, args: &[u64]) -> Result<u64, EmulatorError> {
        const MAX_SWITCHES: usize = 4096;
        let Some(start) = self.thread_start.borrow().clone() else {
            // Nothing installed the thread machinery, so nothing can park.
            return self.call_function(address, args);
        };
        let Some(join) = self.thread_join.borrow().clone() else {
            return self.call_function(address, args);
        };
        let runtime = crate::thread::ThreadRuntime::install(self).map_err(EmulatorError::Memory)?;
        let waiters = self
            .syscall
            .borrow()
            .unix_handler()
            .waiters()
            .clone();
        let mut dispatcher = runtime.dispatcher(self);
        dispatcher.set_waiters(Rc::clone(&waiters));

        // The caller, as a task, on a stack of its own.
        let caller_stack = runtime.allocate_stack(self).map_err(EmulatorError::Memory)?;
        let caller = dispatcher.create(address, args, caller_stack);
        let mut passes = 0usize;
        for _ in 0..MAX_SWITCHES {
            passes += 1;
            if dispatcher.pending() == 0 && join.pending_count() == 0 {
                // The caller has finished and nothing new was created.
                break;
            }
            // Every thread the guest created and has not run yet goes on the
            // ready queue alongside the caller: which of them runs is the
            // dispatcher's business, and the caller's parked task is woken by a
            // join exactly like any other. A thread can be created by another
            // thread, so this happens every pass, not just the first.
            for thread in join.take_pending() {
                let stack = runtime.allocate_stack(self).map_err(EmulatorError::Memory)?;
                self.loader
                    .memory()
                    .pointer(stack)
                    .write_pointer(0, thread.start_routine)
                    .map_err(EmulatorError::Memory)?;
                self.loader
                    .memory()
                    .pointer(stack + runtime.word_size())
                    .write_pointer(0, thread.arg)
                    .map_err(EmulatorError::Memory)?;
                dispatcher.create(start.entry, &[], stack);
            }
            // A pass can end with every task parked -- which is what a join
            // looks like between the two halves of the exchange. That is not a
            // failure: the results it collected are what the caller is waiting
            // for, and the loop decides whether there is anything more to do.
            // A thread is created by the running code, so the queue is topped
            // up both before and after a pass: a thread the caller makes while
            // it runs is not there when the pass it is in starts.
            for thread in join.take_pending() {
                let stack = runtime.allocate_stack(self).map_err(EmulatorError::Memory)?;
                // The clone replacement put the routine and its argument at the
                // top of the child's stack, which is where the entry code reads
                // them.
                self.loader
                    .memory()
                    .pointer(stack)
                    .write_pointer(0, thread.start_routine)
                    .map_err(EmulatorError::Memory)?;
                self.loader
                    .memory()
                    .pointer(stack + runtime.word_size())
                    .write_pointer(0, thread.arg)
                    .map_err(EmulatorError::Memory)?;
                dispatcher.create(start.entry, &[], stack);
            }
            // The dispatcher asks for more work between its passes, because a
            // thread is only known once the code that created it has stopped
            // running.
            let results = {
                let mut backend = self.backend.borrow_mut();
                let mut refill = |dispatcher: &mut raxdbg_core::thread::ThreadDispatcher,
                                   _backend: &mut dyn Backend| {
                    // A thread is created by the running code, so the dispatcher
                    // only learns about one when a pass ends.
                    for thread in join.take_pending() {
                        let Ok(stack) = runtime.allocate_stack(self) else {
                            return;
                        };
                        if self
                            .loader
                            .memory()
                            .pointer(stack)
                            .write_pointer(0, thread.start_routine)
                            .is_err()
                        {
                            return;
                        }
                        let _ = self
                            .loader
                            .memory()
                            .pointer(stack + runtime.word_size())
                            .write_pointer(0, thread.arg);
                        dispatcher.create(start.entry, &[], stack);
                    }
                };
                dispatcher.run_until_refilling(&mut *backend, caller, &mut refill)
            };
            let results = results?;
            // Whatever the pass created, and whatever it woke, is next.
            for thread in join.take_pending() {
                let stack = runtime.allocate_stack(self).map_err(EmulatorError::Memory)?;
                self.loader
                    .memory()
                    .pointer(stack)
                    .write_pointer(0, thread.start_routine)
                    .map_err(EmulatorError::Memory)?;
                self.loader
                    .memory()
                    .pointer(stack + runtime.word_size())
                    .write_pointer(0, thread.arg)
                    .map_err(EmulatorError::Memory)?;
                dispatcher.create(start.entry, &[], stack);
            }
            if results.is_empty() {
                // Nothing ran, so nothing can change: a join that is never woken
                // is a deadlock, and saying so beats hanging.
                break;
            }
            for (_, value) in results {
                join.complete_one(value);
            }
            // A thread that finished in this pass hands its result to whoever
            // joined it: the value goes into that joiner's `retval`, its waiter
            // is woken, and the woken task resumes with the value in `x0`. This
            // is the step that turns a parked joiner back into a running one,
            // so it has to happen before the queue is inspected.
            for (_, value) in join.take_finished() {
                for (waiter, _) in join.joins() {
                    if waiters.is_woken(waiter) {
                        continue;
                    }
                    waiters.wake(waiter as u64, 1);
                    // `wake_task` sets the value and clears the parking in one
                    // step, in that order: the value is looked up as the task
                    // comes back, which is what clearing the waiter enables.
                    if let Some(task) = dispatcher.task_waiting_on(waiter) {
                        dispatcher.wake_task(task, value);
                    }
                }
                join.deliver_result(&waiters, value);
            }
        }
        eprintln!("DBG end: {} tasks, {} finished, caller state {:?}", dispatcher.task_count(), dispatcher.finished_count(), dispatcher.task(caller).map(|t| t.state()));
        runtime.free_all_stacks();
        match dispatcher.task(caller).and_then(|task| task.result()) {
            Some(value) => Ok(value),
            None => Err(EmulatorError::Run(RunError::ThreadSwitch)),
        }
    }

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
        // `x18` is the thread pointer on AAPCS64 and bionic's own startup leaves
        // it holding a scratch value, so a module initialised after it would
        // read a mutex through garbage. A real kernel has it right on every
        // thread entry; this is the equivalent for an initialiser call.
        if self.is_64bit {
            let pointer = self.backend.borrow().reg_read(RegId::TpidrEl0)?;
            if pointer != 0 {
                self.backend.borrow_mut().reg_write(RegId::X(18), pointer)?;
            }
        }
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

/// Holds libc++'s initialiser back until the pthread internals are modelled.
///
/// Port of unidbg: `InitFunctionFilter`, which exists for exactly this kind of
/// decision. libc++ reaches `pthread_mutex_lock` from its initialiser, and
/// `__libc_init` -- which is what builds the structures it walks -- is a
/// separate initialiser this port does not run in the same order a device
/// would. Skipping is honest about that; faulting is not.
struct SkipCxxInit;

impl crate::elf::init::InitFunctionFilter for SkipCxxInit {
    fn accept(&self, lib_name: &str, _address: u64) -> bool {
        // Only libc++ is held back. Every other module's initialisers run, and
        // the fixture's own C constructors are what the tests depend on.
        !lib_name.contains("libc++")
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
    ///
    /// The SDK defaults to 23, as it does for 64-bit. Both bundled trees have
    /// an `sdk23`, and 23 is what the fixtures (NDK 26) and most unidbg users
    /// target; `sdk(19)` selects the older tree explicitly. See
    /// `docs/known-gaps.md` for why 19 does not boot arm32 yet.
    pub fn for_32bit() -> Self {
        AndroidEmulatorBuilder {
            is_64bit: false,
            sdk: 23,
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
