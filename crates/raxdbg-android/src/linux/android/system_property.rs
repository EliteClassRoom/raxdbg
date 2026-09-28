//! Android system-property hook and default property table.
//!
//! Port of unidbg:
//! - `unidbg-android/src/main/java/com/github/unidbg/linux/android/{SystemPropertyHook,SystemPropertyProvider}.java`
//! @7f5da98e.
//!
//! Bionic looks up `ro.*` values through `__system_property_get` (and a few
//! sibling symbols in `libc.so`). We install a [`HookListener`] on `libc.so`
//! that, for every call to one of those names, returns the address of an SVC
//! stub the loader has already allocated; the stub's handler reads the key
//! out of the guest's registers, looks it up in a [`SystemPropertyProvider`],
//! and writes the value into the guest buffer.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::hook::HookListener;
use raxdbg_core::reg::RegId;
use raxdbg_core::svc::{Svc, SvcKind, SvcMemory};

/// The bionic `PROP_VALUE_MAX` constant: the maximum number of bytes (not
/// counting the trailing NUL) that a property value may occupy.
///
/// Port of unidbg: `SystemPropertyHook.PROP_VALUE_MAX` and bionic's
/// `<sys/system_properties.h>`.
pub const PROP_VALUE_MAX: usize = 92;

/// The first SVC number the SVC page hands out for an arm64 stub. The
/// run loop reserves `0`, `0xffff` (`SVC_MAX`), and `0xfffe` (`SVC_MAX - 1`)
/// — the first usable number for an arm64 guest is therefore `1`.
const ARM64_FIRST_SVC: i32 = 1;
/// The first SVC number for an ARM-state AArch32 stub.
const ARM_FIRST_SVC: i32 = 0x100;

/// A stub's guest address paired with its SVC number, the way the run loop
/// dispatches a stub call.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubAddress {
    /// The guest address the stub was written at.
    pub address: u64,
    /// The SVC number (`svc #N`) the run loop looks up.
    pub number: i32,
}

/// The three stubs the property hook may substitute.
#[derive(Clone, Copy, Debug, Default)]
pub struct PropertyStubs {
    /// `__system_property_get`.
    pub get: StubAddress,
    /// `__system_property_read`.
    pub read: StubAddress,
    /// `__system_property_find`.
    pub find: StubAddress,
}

/// A side-table that pairs each SVC number the hook listener allocates with
/// the [`Svc`] handler that should run when the guest calls into the stub.
///
/// unidbg's `SvcMemory` keeps the same table internally and the run loop
/// looks it up by number; here we keep our own copy because we allocate the
/// stubs by hand instead of through `SvcMemory::register_svc`, so we can
/// also expose the number alongside the guest address to test fixtures.
#[derive(Default)]
pub struct StubDispatch {
    /// `(svc_number, Svc)` pairs.
    pub handlers: RefCell<BTreeMap<i32, Box<dyn Svc>>>,
    /// A simple counter that hands out the next free arm64 SVC number.
    arm64_next: Cell<i32>,
    /// A simple counter that hands out the next free ARM-state SVC number.
    arm_next: Cell<i32>,
}

impl StubDispatch {
    /// Creates an empty dispatch table seeded at the first usable numbers.
    pub fn new() -> Self {
        Self {
            handlers: RefCell::new(BTreeMap::new()),
            arm64_next: Cell::new(ARM64_FIRST_SVC),
            arm_next: Cell::new(ARM_FIRST_SVC),
        }
    }

    /// Allocates a stub word (`svc #N` + `ret`) for `kind`, writes it
    /// through `memory` at the address returned by `svc_memory.allocate`,
    /// records the handler, and returns the (address, number) pair.
    ///
    /// This mirrors `SvcMemory::register_svc` but, instead of bumping the
    /// `SvcMemory`'s own number counters, we hand out numbers from this
    /// table so callers can recover them.
    pub fn install(
        &self,
        svc_memory: &SvcMemory,
        memory: &dyn raxdbg_core::memory::Memory,
        svc: Box<dyn Svc>,
    ) -> Result<StubAddress, RegisterError> {
        // The stub numbers belong to the SVC page, not to this table: the run
        // loop's dispatch looks them up there, so a stub numbered here would
        // never be reached.
        let (address, number) = svc_memory
            .register_svc_numbered(memory, svc)
            .map_err(RegisterError)?;
        Ok(StubAddress { address, number })
    }
}

/// The `HookListener` that intercepts `__system_property_*` symbol
/// resolutions on `libc.so` and returns the address of an SVC stub that
/// answers the call.
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/linux/android/SystemPropertyHook.java`
/// @7f5da98e. unidbg only hooks three names — `__system_property_get`,
/// `__system_property_read`, and `__system_property_find`. We do the same.
pub struct SystemPropertyHook {
    is_64bit: bool,
    provider: Rc<RefCell<SystemPropertyProvider>>,
    /// The pre-allocated stubs, populated by [`SystemPropertyHook::register`].
    stubs: PropertyStubs,
    /// The shared dispatch table (kept here so a caller can take a handler
    /// out of `take_svc(number)` even though we installed the stubs by hand).
    dispatch: Rc<StubDispatch>,
}

impl SystemPropertyHook {
    /// Allocates one stub per property name and returns a `HookListener` that
    /// substitutes them on `libc.so`. The `dispatch` is shared with the caller
    /// so it can drive the stubs through `take_svc(number)` the way the run
    /// loop does.
    pub fn register(
        svc_memory: &SvcMemory,
        memory: &dyn raxdbg_core::memory::Memory,
        dispatch: Rc<StubDispatch>,
        is_64bit: bool,
        pointer_size: usize,
        provider: Rc<RefCell<SystemPropertyProvider>>,
    ) -> Result<Self, RegisterError> {
        let kind = if is_64bit { SvcKind::Arm64 } else { SvcKind::Arm };
        let get_stub: Box<dyn Svc> = Box::new(GetHandler {
            kind,
            pointer_size,
            provider: Rc::clone(&provider),
        });
        let read_stub: Box<dyn Svc> = Box::new(ReadHandler {
            kind,
            pointer_size,
            provider: Rc::clone(&provider),
        });
        let find_stub: Box<dyn Svc> = Box::new(FindHandler { kind });

        let get = dispatch.install(svc_memory, memory, get_stub)?;
        let read = dispatch.install(svc_memory, memory, read_stub)?;
        let find = dispatch.install(svc_memory, memory, find_stub)?;

        Ok(Self {
            is_64bit,
            provider,
            stubs: PropertyStubs { get, read, find },
            dispatch,
        })
    }

    /// The arm64 bit of the guest.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// The property table backing this hook.
    pub fn provider(&self) -> &Rc<RefCell<SystemPropertyProvider>> {
        &self.provider
    }

    /// The pre-allocated stubs.
    pub fn stubs(&self) -> &PropertyStubs {
        &self.stubs
    }

    /// The dispatch table that owns the per-number handlers. The test uses
    /// this to drive the stub calls without the run loop.
    pub fn dispatch(&self) -> &Rc<StubDispatch> {
        &self.dispatch
    }
}

impl HookListener for SystemPropertyHook {
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
            "__system_property_get" => self.stubs.get.address,
            "__system_property_read" => self.stubs.read.address,
            "__system_property_find" => self.stubs.find.address,
            _ => 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("cannot install system-property stub: {0}")]
pub struct RegisterError(pub raxdbg_core::memory::MemoryError);

// -----------------------------------------------------------------------------
// Stub handlers
// -----------------------------------------------------------------------------

/// The return type every `Svc::handle` implementation below produces.
type RunResult = Result<i64, RunError>;

struct GetHandler {
    kind: SvcKind,
    pointer_size: usize,
    provider: Rc<RefCell<SystemPropertyProvider>>,
}
impl Svc for GetHandler {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        // x0 = name, x1 = value buffer (the libc convention).
        let (name_ptr, value_ptr) = if pointer_size == 8 {
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
        let name = read_guest_c_string(backend, name_ptr, 1024)?;
        let provider = self.provider.borrow();
        let length = match provider.get_property(&name) {
            Some(value) => {
                write_guest_c_string(backend, value_ptr, &value)?;
                value.as_bytes().len()
            }
            None => 0,
        };
        Ok(length as i64)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "__system_property_get"
    }
}

struct ReadHandler {
    kind: SvcKind,
    pointer_size: usize,
    provider: Rc<RefCell<SystemPropertyProvider>>,
}
impl Svc for ReadHandler {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let pi = if pointer_size == 8 {
            backend.reg_read(RegId::X(0))?
        } else {
            backend.reg_read(RegId::R(0))?
        };
        // pi layout (Linux libc): first 4 bytes = serial, next PROP_VALUE_MAX
        // bytes = value, then the NUL-terminated key.
        let key_ptr = pi.wrapping_add(4 + PROP_VALUE_MAX as u64 + 4);
        let value_ptr = pi.wrapping_add(4);
        let key = read_guest_c_string(backend, key_ptr, 1024)?;
        let provider = self.provider.borrow();
        let length = match provider.get_property(&key) {
            Some(value) => {
                write_guest_c_string(backend, value_ptr, &value)?;
                let len = value.as_bytes().len() as u32;
                let serial = (len << 24) | 0x01;
                backend.mem_write(pi, &serial.to_le_bytes())?;
                value.as_bytes().len()
            }
            None => 0,
        };
        Ok(length as i64)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "__system_property_read"
    }
}

struct FindHandler {
    kind: SvcKind,
}
impl Svc for FindHandler {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "__system_property_find"
    }
}

// -----------------------------------------------------------------------------
// Guest <-> host string helpers that go through the backend.
// -----------------------------------------------------------------------------

fn read_guest_c_string(
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
        if bytes.len() >= max {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn write_guest_c_string(
    backend: &mut dyn Backend,
    address: u64,
    value: &str,
) -> Result<(), RunError> {
    let bytes = value.as_bytes();
    let limit = bytes.len().min(PROP_VALUE_MAX);
    backend.mem_write(address, &bytes[..limit])?;
    backend.mem_write(address.wrapping_add(limit as u64), &[0u8; 1])?;
    Ok(())
}

// -----------------------------------------------------------------------------
// SystemPropertyProvider — the table lookup
// -----------------------------------------------------------------------------

/// Answers property lookups.
pub struct SystemPropertyProvider {
    table: BTreeMap<String, String>,
}

impl SystemPropertyProvider {
    /// An empty provider — every lookup returns `None`.
    pub fn empty() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            table: BTreeMap::new(),
        }))
    }

    /// A provider seeded with the keys unidbg's `AndroidResolver` and tests
    /// rely on (the ones the bundled `__properties__` file does not carry).
    pub fn with_defaults(sdk: u32, is_64bit: bool) -> Rc<RefCell<Self>> {
        let provider = Rc::new(RefCell::new(Self {
            table: BTreeMap::new(),
        }));
        let abi = if is_64bit { "arm64-v8a" } else { "armeabi-v7a" };
        let mut p = provider.borrow_mut();
        p.insert("ro.build.version.sdk".into(), sdk.to_string());
        p.insert("ro.product.cpu.abi".into(), abi.into());
        p.insert(
            "ro.product.cpu.abilist".into(),
            format!("{abi},armeabi-v7a,armeabi"),
        );
        p.insert("ro.product.model".into(), "raxdbg".into());
        p.insert("ro.build.version.release".into(), "9".into());
        p.insert("ro.debuggable".into(), "1".into());
        p.insert(
            "ro.build.fingerprint".into(),
            "raxdbg/dev/raxdbg:9/raxdbg/raxdbg".into(),
        );
        drop(p);
        provider
    }

    /// A provider built from the bundled `__properties__` file at `path`,
    /// with `defaults` filling in the keys that file does not carry.
    pub fn from_properties_file(
        path: impl AsRef<Path>,
        defaults: Rc<RefCell<Self>>,
    ) -> Result<Rc<RefCell<Self>>, PropertyFileError> {
        let bytes = std::fs::read(path.as_ref()).map_err(PropertyFileError::Io)?;
        let mut table = parse_properties_blob(&bytes)?;
        for (key, value) in defaults.borrow().table.iter() {
            table.entry(key.clone()).or_insert(value.clone());
        }
        Ok(Rc::new(RefCell::new(Self { table })))
    }

    /// A direct constructor for callers that already have a table.
    pub fn from_table(table: BTreeMap<String, String>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self { table }))
    }

    /// The value for `key`, if any.
    pub fn get_property(&self, key: &str) -> Option<String> {
        self.table.get(key).cloned()
    }

    /// Adds or replaces a `(key, value)` pair.
    pub fn insert(&mut self, key: String, value: String) {
        self.table.insert(key, value);
    }

    /// Every entry, alphabetically.
    pub fn entries(&self) -> Vec<(String, String)> {
        self.table
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// What can go wrong while parsing a `__properties__` file.
#[derive(Debug, thiserror::Error)]
pub enum PropertyFileError {
    /// The file could not be read.
    #[error("cannot read __properties__: {0}")]
    Io(#[from] std::io::Error),
    /// The file's magic or version header is wrong.
    #[error("__properties__ has the wrong magic or version")]
    BadHeader,
    /// A trie node offset points outside the file.
    #[error("__properties__ has an out-of-range offset at {0:#x}")]
    OutOfRange(u64),
}

/// Parses the Android `__properties__` binary format.
///
/// Port of unidbg:
/// `unidbg-android/src/test/java/com/github/unidbg/PropertiesTest.java#findProperty`
/// @7f5da98e. The file's header is 8 bytes (the file's own length and the
/// data file's mtime), then the magic (`0x504f5250`) and version
/// (`0xfc6ed0ab`), then 28 reserved `u32`s, then the trie root. Each trie
/// node is 20 bytes of header plus a NUL-terminated name; each `prop` offset
/// points at a 4-byte serial followed by the value bytes (the high byte of
/// the serial holds the value's length).
pub fn parse_properties_blob(data: &[u8]) -> Result<BTreeMap<String, String>, PropertyFileError> {
    if data.len() < 128 {
        return Err(PropertyFileError::BadHeader);
    }
    let magic = read_u32(data, 8);
    let version = read_u32(data, 12);
    if magic != 0x504f_5250 || version != 0xfc6e_d0ab {
        return Err(PropertyFileError::BadHeader);
    }
    let start = 8 + 4 + 4 + 28 * 4;
    let mut out = BTreeMap::new();
    walk(data, start, start, "", &mut out)?;
    Ok(out)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    u32::from_le_bytes(bytes)
}

fn walk(
    data: &[u8],
    base: usize,
    offset: usize,
    prefix: &str,
    out: &mut BTreeMap<String, String>,
) -> Result<(), PropertyFileError> {
    let node = PropBt::parse(data, offset, base)?;
    // The trie stores one segment per node, so a child's key is its parent's
    // key plus a dot and the child's segment; the root's name is empty and
    // contributes nothing.
    let full_key = if prefix.is_empty() {
        node.name.clone()
    } else {
        format!("{prefix}.{}", node.name)
    };
    if node.prop != 0 {
        let prop_offset = base + node.prop as usize;
        if prop_offset + 4 > data.len() {
            return Err(PropertyFileError::OutOfRange(prop_offset as u64));
        }
        let serial = read_u32(data, prop_offset);
        let length = (serial >> 24) as usize;
        let value_offset = prop_offset + 4;
        if value_offset + length > data.len() {
            return Err(PropertyFileError::OutOfRange(value_offset as u64));
        }
        let value = std::str::from_utf8(&data[value_offset..value_offset + length])
            .map_err(|_| PropertyFileError::BadHeader)?
            .to_string();
        out.insert(full_key.clone(), value);
    }
    if node.left != 0 {
        walk(data, base, base + node.left as usize, prefix, out)?;
    }
    if node.right != 0 {
        walk(data, base, base + node.right as usize, prefix, out)?;
    }
    if node.children != 0 {
        walk(data, base, base + node.children as usize, &full_key, out)?;
    }
    Ok(())
}

struct PropBt {
    name: String,
    prop: u32,
    left: u32,
    right: u32,
    children: u32,
}
impl PropBt {
    fn parse(data: &[u8], offset: usize, base: usize) -> Result<Self, PropertyFileError> {
        if offset + 20 > data.len() {
            return Err(PropertyFileError::OutOfRange(offset as u64));
        }
        let name_len = data[offset] as usize;
        let prop = read_u32(data, offset + 4);
        let left = read_u32(data, offset + 8);
        let right = read_u32(data, offset + 12);
        let children = read_u32(data, offset + 16);
        let name_start = offset + 20;
        let name_end = name_start + name_len;
        if name_end > data.len() {
            return Err(PropertyFileError::OutOfRange(offset as u64));
        }
        let name = std::str::from_utf8(&data[name_start..name_end])
            .map_err(|_| PropertyFileError::BadHeader)?
            .to_string();
        let _ = base;
        Ok(Self {
            name,
            prop,
            left,
            right,
            children,
        })
    }
}
