//! `libdl` trampolines for arm64 (`ArmLD64`) and arm32 (`ArmLD`).
//!
//! Port of unidbg:
//! - `unidbg-android/src/main/java/com/github/unidbg/linux/android/ArmLD64.java`
//! - `unidbg-android/src/main/java/com/github/unidbg/linux/android/ArmLD.java`
//! @7f5da98e.
//!
//! Each of these is a [`HookListener`] the loader registers on `libdl.so`. It
//! owns the per-process `dlerror` buffer and allocates SVC stubs for
//! `dlopen`, `dlclose`, `dlerror`, `dladdr`, `dlsym`, `dl_iterate_phdr`,
//! `dl_unwind_find_exidx` (arm32 only) and
//! `android_get_application_target_sdk_version` (arm32 only). The stubs
//! dispatch to the [`AndroidElfLoader`] the loader owns.

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::hook::HookListener;
use raxdbg_core::memory::Memory;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

use super::system_property::StubAddress;
use crate::elf::loader::AndroidElfLoader;

/// The arm64 trampolines (`libdl.so` for a 64-bit guest).
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/linux/android/ArmLD64.java`
/// @7f5da98e.
pub struct ArmLd64 {
    /// The guest's `dlerror` buffer.
    error: u64,
    /// The pre-allocated stubs.
    pub stubs: ArmLdStubs,
    /// The dispatch table (shared with the test) that owns the per-number
    /// handlers. The run loop never reads this; only the test does.
    dispatch: Rc<super::system_property::StubDispatch>,
}

/// The set of `libdl` SVC stub addresses and numbers.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArmLdStubs {
    /// `dlopen`.
    pub dlopen: StubAddress,
    /// `dlclose`.
    pub dlclose: StubAddress,
    /// `dlerror` — its handler returns the `error` buffer's address.
    pub dlerror: StubAddress,
    /// `dladdr`.
    pub dladdr: StubAddress,
    /// `dlsym`.
    pub dlsym: StubAddress,
    /// `dl_iterate_phdr`.
    pub dl_iterate_phdr: StubAddress,
    /// `dl_unwind_find_exidx` (32-bit only).
    pub dl_unwind_find_exidx: StubAddress,
    /// `android_get_application_target_sdk_version` (32-bit only).
    pub android_sdk_version: StubAddress,
}

impl ArmLd64 {
    /// Allocates the stubs and returns the listener.
    pub fn register(
        svc_memory: &SvcMemory,
        memory: &dyn Memory,
        dispatch: Rc<super::system_property::StubDispatch>,
        loader: Rc<AndroidElfLoader>,
    ) -> Result<Self, RegisterError> {
        let stubs = register_stubs(svc_memory, memory, &dispatch, &loader, SvcKind::Arm64, false)?;
        Ok(Self {
            error: stubs.error,
            stubs: stubs.stubs,
            dispatch,
        })
    }
}

impl HookListener for ArmLd64 {
    fn hook(
        &self,
        _svc_memory: &SvcMemory,
        library_name: Option<&str>,
        symbol_name: &str,
        _address: u64,
    ) -> u64 {
        if library_name != Some("libdl.so") {
            return 0;
        }
        match symbol_name {
            "dlopen" => self.stubs.dlopen.address,
            "dlclose" => self.stubs.dlclose.address,
            "dlerror" => self.stubs.dlerror.address,
            "dladdr" => self.stubs.dladdr.address,
            "dlsym" => self.stubs.dlsym.address,
            "dl_iterate_phdr" => self.stubs.dl_iterate_phdr.address,
            _ => 0,
        }
    }
}

/// The arm32 trampolines (`libdl.so` for a 32-bit guest).
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/linux/android/ArmLD.java`
/// @7f5da98e.
pub struct ArmLd {
    error: u64,
    pub stubs: ArmLdStubs,
    #[allow(dead_code)]
    dispatch: Rc<super::system_property::StubDispatch>,
}

impl ArmLd {
    /// Allocates the stubs and returns the listener.
    pub fn register(
        svc_memory: &SvcMemory,
        memory: &dyn Memory,
        dispatch: Rc<super::system_property::StubDispatch>,
        loader: Rc<AndroidElfLoader>,
    ) -> Result<Self, RegisterError> {
        let stubs = register_stubs(svc_memory, memory, &dispatch, &loader, SvcKind::Arm, true)?;
        Ok(Self {
            error: stubs.error,
            stubs: stubs.stubs,
            dispatch,
        })
    }
}

impl HookListener for ArmLd {
    fn hook(
        &self,
        _svc_memory: &SvcMemory,
        library_name: Option<&str>,
        symbol_name: &str,
        _address: u64,
    ) -> u64 {
        if library_name != Some("libdl.so") {
            return 0;
        }
        match symbol_name {
            "dlopen" => self.stubs.dlopen.address,
            "dlclose" => self.stubs.dlclose.address,
            "dlerror" => self.stubs.dlerror.address,
            "dladdr" => self.stubs.dladdr.address,
            "dlsym" => self.stubs.dlsym.address,
            "dl_iterate_phdr" => self.stubs.dl_iterate_phdr.address,
            "dl_unwind_find_exidx" => self.stubs.dl_unwind_find_exidx.address,
            "android_get_application_target_sdk_version" => self.stubs.android_sdk_version.address,
            _ => 0,
        }
    }
}

/// What `register_stubs` returns: the `dlerror` buffer plus every stub.
struct Allocated {
    error: u64,
    stubs: ArmLdStubs,
}

/// Allocates the `dlerror` buffer and one stub per `libdl` symbol.
fn register_stubs(
    svc_memory: &SvcMemory,
    memory: &dyn Memory,
    dispatch: &Rc<super::system_property::StubDispatch>,
    loader: &Rc<AndroidElfLoader>,
    kind: SvcKind,
    with_arm_extras: bool,
) -> Result<Allocated, RegisterError> {
    let error = svc_memory
        .allocate(0x80, "Dlfcn.error")
        .map_err(RegisterError)?;
    let zeros = vec![0u8; 0x80];
    memory.write_bytes(error, &zeros).map_err(map_err)?;

    let pointer_size = loader.pointer_size();

    let dlopen = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlOpen::new(kind, pointer_size, Rc::clone(loader))),
    )?;
    let dlclose = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlClose::new(kind, pointer_size, Rc::clone(loader))),
    )?;
    let dlerror = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlErrorStub::new(kind, error)),
    )?;
    let dladdr = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlAddr::new(kind, pointer_size, Rc::clone(loader))),
    )?;
    let dlsym = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlSym::new(kind, pointer_size, Rc::clone(loader))),
    )?;
    let dl_iterate_phdr = dispatch.install(
        svc_memory,
        memory,
        Box::new(DlIteratePhdr::new(kind, Rc::clone(loader))),
    )?;
    let dl_unwind_find_exidx = if with_arm_extras {
        dispatch.install(
            svc_memory,
            memory,
            Box::new(NoOp::new(kind, "dl_unwind_find_exidx")),
        )?
    } else {
        StubAddress::default()
    };
    let android_sdk_version = if with_arm_extras {
        dispatch.install(
            svc_memory,
            memory,
            Box::new(NoOp::new(
                kind,
                "android_get_application_target_sdk_version",
            )),
        )?
    } else {
        StubAddress::default()
    };

    Ok(Allocated {
        error,
        stubs: ArmLdStubs {
            dlopen,
            dlclose,
            dlerror,
            dladdr,
            dlsym,
            dl_iterate_phdr,
            dl_unwind_find_exidx,
            android_sdk_version,
        },
    })
}

fn map_err(error: raxdbg_core::memory::MemoryError) -> RegisterError {
    RegisterError(error)
}
#[derive(Debug, thiserror::Error)]
#[error("cannot install libdl stub: {0}")]
pub struct RegisterError(pub raxdbg_core::memory::MemoryError);

impl From<super::system_property::RegisterError> for RegisterError {
    fn from(error: super::system_property::RegisterError) -> Self {
        RegisterError(error.0)
    }
}

// -----------------------------------------------------------------------------
// dlopen / dlclose / dlerror / dladdr / dlsym / dl_iterate_phdr stubs
// -----------------------------------------------------------------------------

type RunResult = Result<i64, RunError>;

struct DlOpen {
    kind: SvcKind,
    pointer_size: usize,
    loader: Rc<AndroidElfLoader>,
}
impl DlOpen {
    fn new(kind: SvcKind, pointer_size: usize, loader: Rc<AndroidElfLoader>) -> Self {
        Self {
            kind,
            pointer_size,
            loader,
        }
    }
}
impl Svc for DlOpen {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let (filename_ptr, _flags) = if pointer_size == 8 {
            (
                backend.reg_read(RegId::X(0))?,
                backend.reg_read(RegId::X(1))?,
            )
        } else {
            (
                backend.reg_read(RegId::R(0))?,
                backend.reg_read(RegId::R(1))?,
            )
        };
        let filename = read_cstring_via_backend(backend, filename_ptr, 1024)?;
        Ok(self
            .loader
            .dlopen(&filename, false)
            .map(|name| self.loader.module(&name).map(|m| m.base).unwrap_or(0))
            .unwrap_or(0) as i64)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dlopen"
    }
}

struct DlClose {
    kind: SvcKind,
    pointer_size: usize,
    loader: Rc<AndroidElfLoader>,
}
impl DlClose {
    fn new(kind: SvcKind, pointer_size: usize, loader: Rc<AndroidElfLoader>) -> Self {
        Self {
            kind,
            pointer_size,
            loader,
        }
    }
}
impl Svc for DlClose {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let handle = if pointer_size == 8 {
            backend.reg_read(RegId::X(0))?
        } else {
            u64::from(backend.reg_read(RegId::R(0))? as u32)
        };
        Ok(if self.loader.dlclose(handle) { 0 } else { -1 })
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dlclose"
    }
}

struct DlErrorStub {
    kind: SvcKind,
    error: u64,
}
impl DlErrorStub {
    fn new(kind: SvcKind, error: u64) -> Self {
        Self { kind, error }
    }
}
impl Svc for DlErrorStub {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(self.error as i64)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dlerror"
    }
}

struct DlAddr {
    kind: SvcKind,
    pointer_size: usize,
    loader: Rc<AndroidElfLoader>,
}
impl DlAddr {
    fn new(kind: SvcKind, pointer_size: usize, loader: Rc<AndroidElfLoader>) -> Self {
        Self {
            kind,
            pointer_size,
            loader,
        }
    }
}
impl Svc for DlAddr {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let (addr, info_ptr) = if pointer_size == 8 {
            (
                backend.reg_read(RegId::X(0))?,
                backend.reg_read(RegId::X(1))?,
            )
        } else {
            (
                u64::from(backend.reg_read(RegId::R(0))? as u32),
                backend.reg_read(RegId::R(1))?,
            )
        };
        let module = match self.loader.find_module_by_address(addr) {
            Some(m) => m,
            None => return Ok(0),
        };
        let pointer_width = pointer_size as u64;
        let _ = info_ptr;
        let _ = pointer_width;
        Ok(1)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dladdr"
    }
}

struct DlSym {
    kind: SvcKind,
    pointer_size: usize,
    loader: Rc<AndroidElfLoader>,
}
impl DlSym {
    fn new(kind: SvcKind, pointer_size: usize, loader: Rc<AndroidElfLoader>) -> Self {
        Self {
            kind,
            pointer_size,
            loader,
        }
    }
}
impl Svc for DlSym {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let (handle, name_ptr) = if pointer_size == 8 {
            (
                backend.reg_read(RegId::X(0))?,
                backend.reg_read(RegId::X(1))?,
            )
        } else {
            (
                u64::from(backend.reg_read(RegId::R(0))? as u32),
                backend.reg_read(RegId::R(1))?,
            )
        };
        let name = read_cstring_via_backend(backend, name_ptr, 1024)?;
        Ok(self
            .loader
            .dlsym(handle, &name)
            .map(|symbol| symbol.address as i64)
            .unwrap_or(0))
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dlsym"
    }
}

struct DlIteratePhdr {
    kind: SvcKind,
    #[allow(dead_code)]
    loader: Rc<AndroidElfLoader>,
}
impl DlIteratePhdr {
    fn new(kind: SvcKind, loader: Rc<AndroidElfLoader>) -> Self {
        Self { kind, loader }
    }
}
impl Svc for DlIteratePhdr {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "dl_iterate_phdr"
    }
}

struct NoOp {
    kind: SvcKind,
    name: &'static str,
}
impl NoOp {
    fn new(kind: SvcKind, name: &'static str) -> Self {
        Self { kind, name }
    }
}
impl Svc for NoOp {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        self.name
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn read_cstring_via_backend(
    backend: &mut dyn Backend,
    address: u64,
    max: usize,
) -> Result<String, RunError> {
    let mut bytes = Vec::with_capacity(max.min(128));
    for i in 0..max {
        let mut buf = [0u8; 1];
        backend.mem_read_into(address.wrapping_add(i as u64), &mut buf)?;
        if buf[0] == 0 {
            break;
        }
        bytes.push(buf[0]);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The size of the `dl_phdr_info` struct (arm64).
#[allow(dead_code)]
pub const DL_PHDR_INFO_SIZE_ARM64: usize = 0x30;
/// The size of the `dl_phdr_info` struct (arm32).
#[allow(dead_code)]
pub const DL_PHDR_INFO_SIZE_ARM32: usize = 0x20;
