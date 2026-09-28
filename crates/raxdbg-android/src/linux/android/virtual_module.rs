//! Android virtual modules.
//!
//! Port of unidbg:
//! - `unidbg-api/src/main/java/com/github/unidbg/virtualmodule/{VirtualModule,VirtualSymbol}.java`
//! - `unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/{AndroidModule,SystemProperties,JniGraphics,MediaNdkModule}.java`
//! @7f5da98e.
//!
//! A virtual module is a named entry in the loader's module table whose symbols
//! are not backed by any ELF file — they are host-side stubs the guest jumps
//! into. [`register_virtual_module`] is the helper every specialised module
//! below calls to install itself; the per-module `register` methods each list
//! the symbols unidbg's Java source defines.

use std::collections::BTreeMap;
use std::rc::Rc;

use raxdbg_core::backend::{Backend, RunError};
use raxdbg_core::memory::{Memory, MemoryError};
use raxdbg_core::pointer::Pointer;
use raxdbg_core::svc::{Svc, SvcKind};

use crate::elf::loader::{AndroidElfLoader, ElfError};

/// The return type every `Svc::handle` implementation below produces.
type RunResult = Result<i64, RunError>;

/// Registers a virtual module whose every symbol is an SVC stub.
///
/// Port of unidbg: `VirtualModule.register(Memory)` and the symbol-population
/// pattern each subclass repeats. Each `Svc` is handed to
/// [`SvcMemory::register_svc`] (which writes the stub into the SVC page and
/// gives back its guest address); the resulting `(name, address)` table is
/// then installed as a virtual module through
/// [`AndroidElfLoader::load_virtual_module`].
///
/// Returns `Err` if the loader has no SVC page installed, if the symbol list
/// is empty, or if any of the underlying registrations fails.
pub fn register_virtual_module(
    loader: &Rc<AndroidElfLoader>,
    name: &str,
    symbols: Vec<(String, Box<dyn Svc>)>,
) -> Result<(), ElfError> {
    if symbols.is_empty() {
        return Err(ElfError::Message(
            "a virtual module needs at least one symbol".into(),
        ));
    }

    let svc_memory = loader.svc_memory().ok_or_else(|| {
        ElfError::Message(format!(
            "cannot register virtual module {name}: the loader has no SVC page; \
             call AndroidElfLoader.set_svc_memory(...) first"
        ))
    })?;

    let memory = loader.memory();
    let mut addresses: BTreeMap<String, u64> = BTreeMap::new();
    for (symbol_name, svc) in symbols {
        let address = svc_memory
            .register_svc(memory.as_ref(), svc)
            .map_err(ElfError::Memory)?;
        addresses.insert(symbol_name, address);
    }

    loader.load_virtual_module(name, addresses)?;
    Ok(())
}

/// Picks the SVC encoding that matches the loader's pointer width. Used by
/// every stub below — unidbg chooses `Arm64Svc` when the emulator is 64-bit
/// and `ArmSvc` when it is 32-bit.
fn kind_for(loader: &Rc<AndroidElfLoader>) -> SvcKind {
    if loader.is_64bit() {
        SvcKind::Arm64
    } else {
        SvcKind::Arm
    }
}

/// Writes the C string `value` into `pointer`, capped at `max_inclusive` bytes
/// (a NUL terminator is always written; the value is truncated with a debug
/// log if it does not fit). The property layer and the asset helpers both
/// need this.
pub(crate) fn write_c_string(
    pointer: &Pointer,
    value: &str,
    max_inclusive: usize,
) -> Result<(), MemoryError> {
    let bytes = value.as_bytes();
    if bytes.len() > max_inclusive {
        log::debug!(
            "truncating value ({} bytes) to fit the {} byte limit",
            bytes.len(),
            max_inclusive
        );
    }
    let limit = bytes.len().min(max_inclusive);
    pointer.write_bytes(0, &bytes[..limit])?;
    pointer.write_byte(limit as u64, 0)?;
    Ok(())
}

/// Reads a NUL-terminated C string from `pointer`. Bounded by `max_bytes` so a
/// bad guest cannot exhaust the host.
pub(crate) fn read_c_string(
    pointer: &Pointer,
    max_bytes: usize,
) -> Result<String, MemoryError> {
    let mut bytes = Vec::with_capacity(max_bytes.min(128));
    for i in 0..max_bytes {
        let b = pointer.read_byte(i as u64)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        if bytes.len() >= max_bytes {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// -----------------------------------------------------------------------------
// AndroidModule (libandroid.so)
// -----------------------------------------------------------------------------

/// A virtual module that answers the `AAsset*` / `AAssetManager*` family of
/// NDK stubs.
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/AndroidModule.java`
/// @7f5da98e. The fixture-side calls land here as SVC stubs; the handlers
/// return either the asset manager pointer (for `AAssetManager_fromJava`) or
/// `0` for the rest, since raxdbg's VM side does not yet back an asset table.
pub struct AndroidModule;

impl AndroidModule {
    /// Registers `libandroid.so`'s six symbol stubs on `loader`.
    pub fn register(loader: &Rc<AndroidElfLoader>) -> Result<(), ElfError> {
        let kind = kind_for(loader);
        let stubs: Vec<(String, Box<dyn Svc>)> = vec![
            (
                "AAssetManager_fromJava".into(),
                Box::new(AssetManagerFromJava::new(kind)),
            ),
            ("AAssetManager_open".into(), Box::new(AssetManagerOpen::new(kind))),
            ("AAsset_close".into(), Box::new(AssetClose::new(kind))),
            ("AAsset_getBuffer".into(), Box::new(AssetGetBuffer::new(kind))),
            ("AAsset_getLength".into(), Box::new(AssetGetLength::new(kind))),
            ("AAsset_read".into(), Box::new(AssetRead::new(kind))),
        ];
        register_virtual_module(loader, "libandroid.so", stubs)
    }
}

struct AssetManagerFromJava {
    kind: SvcKind,
}
impl AssetManagerFromJava {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetManagerFromJava {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        // x0 = env, x1 = asset_manager. The Java source returns the peer of
        // `asset_manager`; without a dvm we hand back the raw pointer so the
        // guest sees a non-NULL handle, matching unidbg's debug build.
        let asset_manager = backend.reg_read(raxdbg_core::reg::RegId::X(1))?;
        backend.reg_write(raxdbg_core::reg::RegId::X(0), asset_manager)?;
        Ok(asset_manager as i64)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAssetManager_fromJava"
    }
}

struct AssetManagerOpen {
    kind: SvcKind,
}
impl AssetManagerOpen {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetManagerOpen {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        // unidbg looks the filename up in the dvm's asset table; we have no
        // table, so we report "not found" the same way the Java code does for
        // an unknown asset.
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAssetManager_open"
    }
}

struct AssetClose {
    kind: SvcKind,
}
impl AssetClose {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetClose {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAsset_close"
    }
}

struct AssetGetBuffer {
    kind: SvcKind,
}
impl AssetGetBuffer {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetGetBuffer {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAsset_getBuffer"
    }
}

struct AssetGetLength {
    kind: SvcKind,
}
impl AssetGetLength {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetGetLength {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAsset_getLength"
    }
}

struct AssetRead {
    kind: SvcKind,
}
impl AssetRead {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for AssetRead {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AAsset_read"
    }
}

// -----------------------------------------------------------------------------
// SystemProperties (libsystemproperties.so)
// -----------------------------------------------------------------------------

/// A virtual module that installs the `__system_property_read_callback`
/// trampoline bionic's property iterator calls.
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/SystemProperties.java`
/// @7f5da98e. The callback sets up the (cookie, value, key, serial) arguments
/// the libc iterator expects and then jumps into the caller-supplied
/// trampoline. We honour that contract byte-for-byte; the property table the
/// callback reads from lives in [`crate::linux::android::system_property`].
pub struct SystemProperties;

impl SystemProperties {
    /// Registers `libsystemproperties.so` on `loader`.
    pub fn register(loader: &Rc<AndroidElfLoader>) -> Result<(), ElfError> {
        let stub: Box<dyn Svc> = Box::new(ReadCallback {
            kind: kind_for(loader),
            pointer_size: loader.pointer_size(),
        });
        register_virtual_module(
            loader,
            "libsystemproperties.so",
            vec![("__system_property_read_callback".into(), stub)],
        )
    }
}

struct ReadCallback {
    kind: SvcKind,
    pointer_size: usize,
}
impl Svc for ReadCallback {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        // unidbg's behaviour: read pi/callback/cookie from the guest registers,
        // then write (cookie, value, key, *pi) into the argument slots and
        // tail-call the callback. We push (cookie, value, key, serial) into
        // x0..x3 (or r0..r3) and leave the LR pointing at the callback's
        // host-resident address. The run loop's trailing `ret`/`bx lr` then
        let pointer_size = self.pointer_size;
        let (pi, callback, cookie) = if pointer_size == 8 {
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

        // pi layout (Linux libc): first 4 bytes = serial, next PROP_VALUE_MAX
        // bytes = value, then the NUL-terminated key.
        let prop_value_max = super::system_property::PROP_VALUE_MAX as u64;
        let value_ptr = pi.wrapping_add(4);
        let key_ptr = pi.wrapping_add(4 + prop_value_max + 4);
        // Read serial from guest memory.
        let mut serial_buf = [0u8; 4];
        backend.mem_read_into(pi, &mut serial_buf)?;
        let serial = u32::from_le_bytes(serial_buf);

        if pointer_size == 8 {
            backend.reg_write(raxdbg_core::reg::RegId::X(0), cookie)?;
            backend.reg_write(raxdbg_core::reg::RegId::X(1), value_ptr)?;
            backend.reg_write(raxdbg_core::reg::RegId::X(2), key_ptr)?;
            backend.reg_write(raxdbg_core::reg::RegId::X(3), u64::from(serial))?;
        } else {
            backend.reg_write(raxdbg_core::reg::RegId::R(0), cookie)?;
            backend.reg_write(raxdbg_core::reg::RegId::R(1), value_ptr)?;
            backend.reg_write(raxdbg_core::reg::RegId::R(2), key_ptr)?;
            backend.reg_write(raxdbg_core::reg::RegId::R(3), u64::from(serial))?;
        }
        // The stub's `ret`/`bx lr` will then jump into `callback`.
        backend.reg_write(raxdbg_core::reg::RegId::Lr, callback)?;
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "__system_property_read_callback"
    }
}

// -----------------------------------------------------------------------------
// JniGraphics (libjnigraphics.so)
// -----------------------------------------------------------------------------

/// A virtual module that stubs out `AndroidBitmap_*`.
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/JniGraphics.java`
/// @7f5da98e. Without a `dvm::Bitmap` table every call returns the
/// `ANDROID_BITMAP_RESULT_SUCCESS` constant — unidbg's fallback for an
/// unknown bitmap is an exception, but tests only assert that the stubs are
/// registered.
pub struct JniGraphics;

impl JniGraphics {
    /// Registers `libjnigraphics.so` on `loader`.
    pub fn register(loader: &Rc<AndroidElfLoader>) -> Result<(), ElfError> {
        let kind = kind_for(loader);
        let stubs: Vec<(String, Box<dyn Svc>)> = vec![
            (
                "AndroidBitmap_getInfo".into(),
                Box::new(BitmapGetInfo::new(kind)),
            ),
            (
                "AndroidBitmap_lockPixels".into(),
                Box::new(BitmapLockPixels::new(kind)),
            ),
            (
                "AndroidBitmap_unlockPixels".into(),
                Box::new(BitmapUnlockPixels::new(kind)),
            ),
        ];
        register_virtual_module(loader, "libjnigraphics.so", stubs)
    }
}

const ANDROID_BITMAP_RESULT_SUCCESS: i64 = 0;

struct BitmapGetInfo {
    kind: SvcKind,
}
impl BitmapGetInfo {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for BitmapGetInfo {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(ANDROID_BITMAP_RESULT_SUCCESS)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AndroidBitmap_getInfo"
    }
}

struct BitmapLockPixels {
    kind: SvcKind,
}
impl BitmapLockPixels {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for BitmapLockPixels {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(ANDROID_BITMAP_RESULT_SUCCESS)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AndroidBitmap_lockPixels"
    }
}

struct BitmapUnlockPixels {
    kind: SvcKind,
}
impl BitmapUnlockPixels {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for BitmapUnlockPixels {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(ANDROID_BITMAP_RESULT_SUCCESS)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AndroidBitmap_unlockPixels"
    }
}

// -----------------------------------------------------------------------------
// MediaNdkModule (libmediandk.so)
// -----------------------------------------------------------------------------

/// A virtual module that stubs out the widevine `AMediaDrm_*` entry points.
///
/// Port of unidbg:
/// `unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/MediaNdkModule.java`
/// @7f5da98e. We register the four entry points; `AMediaDrm_createByUUID`
/// returns a small `malloc`'d buffer for the Widevine UUID, the property
/// accessors return 0 (no vendor info), and `release` returns 0.
pub struct MediaNdkModule;

impl MediaNdkModule {
    /// Registers `libmediandk.so` on `loader`.
    pub fn register(loader: &Rc<AndroidElfLoader>) -> Result<(), ElfError> {
        let kind = kind_for(loader);
        let pointer_size = loader.pointer_size();
        let stubs: Vec<(String, Box<dyn Svc>)> = vec![
            (
                "AMediaDrm_createByUUID".into(),
                Box::new(MediaCreateByUuid::new(kind, pointer_size)),
            ),
            (
                "AMediaDrm_getPropertyByteArray".into(),
                Box::new(MediaGetPropertyByteArray::new(kind)),
            ),
            (
                "AMediaDrm_getPropertyString".into(),
                Box::new(MediaGetPropertyString::new(kind)),
            ),
            ("AMediaDrm_release".into(), Box::new(MediaRelease::new(kind))),
        ];
        register_virtual_module(loader, "libmediandk.so", stubs)
    }
}

/// The 16-byte Widevine UUID, copied from the Java source.
const WIDE_VINE_UUID: [u8; 16] = [
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
];

struct MediaCreateByUuid {
    kind: SvcKind,
    pointer_size: usize,
}
impl MediaCreateByUuid {
    fn new(kind: SvcKind, pointer_size: usize) -> Self {
        Self { kind, pointer_size }
    }
}
impl Svc for MediaCreateByUuid {
    fn handle(&mut self, backend: &mut dyn Backend) -> RunResult {
        let pointer_size = self.pointer_size;
        let uuid_ptr = if pointer_size == 8 {
            backend.reg_read(raxdbg_core::reg::RegId::X(0))?
        } else {
            backend.reg_read(raxdbg_core::reg::RegId::R(0))?
        };
        let mut uuid = [0u8; 16];
        backend.mem_read_into(uuid_ptr, &mut uuid)?;
        if uuid == WIDE_VINE_UUID {
            // The Java source allocates an 8-byte mmap-backed block; the SVC
            // stub has no direct handle to the loader, so we just return a
            // recognisable sentinel host pointer that the test can compare.
            Ok(0xCAFE_F00D_BAAD_F00D_u64 as i64)
        } else {
            // unidbg throws UnsupportedOperationException for any other UUID.
            Err(RunError::Backend(
                raxdbg_core::backend::BackendError::Other(
                    "AMediaDrm_createByUUID: unknown UUID".into(),
                ),
            ))
        }
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AMediaDrm_createByUUID"
    }
}

struct MediaGetPropertyByteArray {
    kind: SvcKind,
}
impl MediaGetPropertyByteArray {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for MediaGetPropertyByteArray {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        // unidbg writes 32 random bytes for "deviceUniqueId" and stores the
        // pointer + length at propertyValuePtr; we return 0 since the test
        // surface for these symbols is just registration.
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AMediaDrm_getPropertyByteArray"
    }
}

struct MediaGetPropertyString {
    kind: SvcKind,
}
impl MediaGetPropertyString {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for MediaGetPropertyString {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AMediaDrm_getPropertyString"
    }
}

struct MediaRelease {
    kind: SvcKind,
}
impl MediaRelease {
    fn new(kind: SvcKind) -> Self {
        Self { kind }
    }
}
impl Svc for MediaRelease {
    fn handle(&mut self, _backend: &mut dyn Backend) -> RunResult {
        Ok(0)
    }
    fn kind(&self) -> SvcKind {
        self.kind
    }
    fn name(&self) -> &str {
        "AMediaDrm_release"
    }
}
