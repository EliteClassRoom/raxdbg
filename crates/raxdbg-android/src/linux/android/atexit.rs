//! bionic's atexit family, as a virtual module.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/virtualmodule/android/AndroidModule.java`@7f5da98e,
//! which is where unidbg puts libc functions it wants to answer itself.
//!
//! libc++'s initialiser registers a destructor through `__cxa_atexit`, passing
//! its module's `__dso_handle`. bionic walks the linked list the handle points
//! at, and in this emulator that list is never built, so the walk runs off the
//! end and faults. unidbg does not hit it because its bundled libc++'s
//! `init_array` entry stays zero -- it never decodes the packed relocations --
//! so the initialiser is never called. We do decode them, so the initialiser
//! runs and the missing atexit support becomes visible.
//!
//! The fix is to answer the atexit family directly. `__cxa_atexit` records the
//! call and returns success, which is all an initialiser needs: the destructor
//! list is only ever walked at process exit or during a `dlclose`, neither of
//! which this emulator reaches while a library is loading. Destroctors are
//! still *recorded*, so `exit` can run them if it is ever made to.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::MemoryError;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

use raxdbg_core::hook::HookListener;

use crate::elf::loader::{AndroidElfLoader, ElfError};

/// One registered destructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtExitEntry {
    /// The destructor function.
    pub func: u64,
    /// The argument it is called with.
    pub arg: u64,
    /// The module that registered it.
    pub dso_handle: u64,
}

/// The destructors every module has registered.
///
/// Kept host-side rather than in the guest: the guest's own list is a bionic
/// data structure this emulator does not model, and a host-side list gives
/// `exit` something real to run.
#[derive(Debug, Default)]
pub struct AtExit {
    entries: RefCell<Vec<AtExitEntry>>,
}

impl AtExit {
    /// An empty registry.
    pub fn new() -> Self {
        AtExit {
            entries: RefCell::new(Vec::new()),
        }
    }

    /// Records a destructor.
    pub fn register(&self, func: u64, arg: u64, dso_handle: u64) {
        self.entries.borrow_mut().push(AtExitEntry {
            func,
            arg,
            dso_handle,
        });
    }

    /// Every destructor, in registration order.
    pub fn entries(&self) -> Vec<AtExitEntry> {
        self.entries.borrow().clone()
    }

    /// How many destructors are registered.
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether nothing has been registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every destructor registered by `dso_handle`, which is what a
    /// `dlclose` does.
    pub fn remove_module(&self, dso_handle: u64) {
        self.entries
            .borrow_mut()
            .retain(|entry| entry.dso_handle != dso_handle);
    }
}

/// The virtual module that owns the atexit symbols.
#[derive(Debug)]
pub struct AtExitModule {
    registry: Rc<AtExit>,
    stubs: Stubs,
}

#[derive(Debug, Clone)]
struct Stubs {
    cxa_atexit: u64,
    cxa_finalize: u64,
    atexit: u64,
    register_atfork: u64,
    __cxa_thread_atexit_impl: u64,
    __cxa_thread_atexit: u64,
    get_dso_handle: u64,
}

impl AtExitModule {
    /// The shared destructor registry.
    pub fn registry(&self) -> &Rc<AtExit> {
        &self.registry
    }

    /// Registers the module with the loader, giving bionic's atexit symbols
    /// addresses of our own.
    pub fn register(loader: &Rc<AndroidElfLoader>) -> Result<AtExitModule, ElfError> {
        let memory = loader.memory();
        let svc = loader
            .svc_memory()
            .expect("the syscall layer built an SVC page");
        let is_64bit = loader.is_64bit();
        let kind = if is_64bit {
            SvcKind::Arm64
        } else {
            SvcKind::Arm
        };
        let registry = Rc::new(AtExit::new());

        let mut make = |svc_box: Box<dyn Svc>| -> Result<u64, MemoryError> {
            let (address, _number) = svc.register_svc_numbered(memory.as_ref(), svc_box)?;
            Ok(address)
        };

        let cxa_atexit = make(Box::new(CxaAtexit {
            kind,
            registry: Rc::clone(&registry),
        }))?;
        let cxa_finalize = make(Box::new(CxaFinalize { kind }))?;
        let atexit = make(Box::new(PlainHandler {
            kind,
            name: "atexit",
            result: 0,
        }))?;
        let register_atfork = make(Box::new(PlainHandler {
            kind,
            name: "__register_atfork",
            result: 0,
        }))?;
        let thread_atexit_impl = make(Box::new(PlainHandler {
            kind,
            name: "__cxa_thread_atexit_impl",
            result: 0,
        }))?;
        let thread_atexit = make(Box::new(PlainHandler {
            kind,
            name: "__cxa_thread_atexit",
            result: 0,
        }))?;
        let get_dso_handle = make(Box::new(GetDsoHandle { kind }))?;

        let stubs = Stubs {
            cxa_atexit,
            cxa_finalize,
            atexit,
            register_atfork,
            __cxa_thread_atexit_impl: thread_atexit_impl,
            __cxa_thread_atexit: thread_atexit,
            get_dso_handle,
        };
        let hook = AtExitHook { stubs: stubs.clone() };
        // libc already exports these, so the virtual module alone would never
        // be consulted; the hook has to win for the guest's calls to land here.
        loader.add_hook_listener(Rc::new(hook) as Rc<dyn HookListener>);
        let module = AtExitModule {
            registry: Rc::clone(&registry),
            stubs,
        };
        loader.load_virtual_module(
            "libatexit.so",
            [
                ("__cxa_atexit".to_string(), cxa_atexit),
                ("__cxa_finalize".to_string(), cxa_finalize),
                ("atexit".to_string(), atexit),
                ("__register_atfork".to_string(), register_atfork),
                ("__cxa_thread_atexit_impl".to_string(), thread_atexit_impl),
                ("__cxa_thread_atexit".to_string(), thread_atexit),
                ("__cxa_get_dso_handle".to_string(), get_dso_handle),
            ]
            .into_iter()
            .collect(),
        )?;
        Ok(module)
    }
}

/// Redirects libc's atexit exports to this module's stubs.
///
/// A virtual module only supplies symbols nothing else defines, and libc *does*
/// export `__cxa_atexit`, `atexit` and `__register_atfork`. The loader asks its
/// hook listeners before it keeps its own answer -- that is the hook's whole
/// purpose -- so this is where a libc function gets replaced by an
/// implementation of ours.
#[derive(Debug)]
pub struct AtExitHook {
    stubs: Stubs,
}

impl HookListener for AtExitHook {
    fn hook(
        &self,
        _svc_memory: &SvcMemory,
        library_name: Option<&str>,
        symbol_name: &str,
        _address: u64,
    ) -> u64 {
        if library_name != Some("libc.so") {
            return 0;
        }
        match symbol_name {
            "__cxa_atexit" => self.stubs.cxa_atexit,
            "__cxa_finalize" => self.stubs.cxa_finalize,
            "atexit" => self.stubs.atexit,
            "__register_atfork" => self.stubs.register_atfork,
            "__cxa_thread_atexit_impl" => self.stubs.__cxa_thread_atexit_impl,
            "__cxa_thread_atexit" => self.stubs.__cxa_thread_atexit,
            _ => 0,
        }
    }
}

/// `int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)`.
///
/// Registers the destructor and reports success. The argument order is the
/// AAPCS64 one: `x0` the function, `x1` the argument, `x2` the module handle.
struct CxaAtexit {
    kind: SvcKind,
    registry: Rc<AtExit>,
}

impl Svc for CxaAtexit {
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError> {
        let (func, arg, dso) = if self.kind == SvcKind::Arm64 {
            (
                backend.reg_read(raxdbg_core::reg::RegId::X(0))?,
                backend.reg_read(raxdbg_core::reg::RegId::X(1))?,
                backend.reg_read(raxdbg_core::reg::RegId::X(2))?,
            )
        } else {
            (
                backend.reg_read(raxdbg_core::reg::RegId::R(0))?,
                backend.reg_read(raxdbg_core::reg::RegId::R(1))?,
                backend.reg_read(raxdbg_core::reg::RegId::R(2))?,
            )
        };
        if func != 0 {
            self.registry.register(func, arg, dso);
        }
        Ok(0)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "__cxa_atexit"
    }
}

/// `int __cxa_finalize(void *dso_handle)`.
///
/// bionic unlinks the module's destructors here. Nothing walks the list while
/// a library loads, so this answers success and leaves the registry alone; a
/// `dlclose` goes through [`AtExit::remove_module`].
struct CxaFinalize {
    kind: SvcKind,
}

impl Svc for CxaFinalize {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        Ok(0)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "__cxa_finalize"
    }
}

/// `void *__cxa_get_dso_handle(void)`.
///
/// bionic returns the calling module's handle. The first handle any module asks
/// for becomes a stable non-null value, which is all a caller needs: it is an
/// opaque key for unlinking, not something dereferenced.
struct GetDsoHandle {
    kind: SvcKind,
}

thread_local! {
    static NEXT_HANDLE: Cell<u64> = const { Cell::new(1) };
}

impl Svc for GetDsoHandle {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        Ok(NEXT_HANDLE.with(|handle| handle.get()) as i64)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        "__cxa_get_dso_handle"
    }
}

/// A function with one fixed result: bionic's `atexit`,
/// `__register_atfork` and the thread-atexit pair all just record and return.
struct PlainHandler {
    kind: SvcKind,
    name: &'static str,
    result: i64,
}

impl Svc for PlainHandler {
    fn handle(&mut self, _backend: &mut dyn Backend) -> Result<i64, RunError> {
        Ok(self.result)
    }

    fn kind(&self) -> SvcKind {
        self.kind
    }

    fn name(&self) -> &str {
        self.name
    }
}
