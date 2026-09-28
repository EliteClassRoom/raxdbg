//! SVC stubs: the trampolines unidbg installs for host-implemented calls.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/{ARMSvcMemory,Arm64Svc,ArmSvc,ThumbSvc,Svc}.java`
//! and `unidbg-api/src/main/java/com/github/unidbg/memory/SvcMemory.java`@7f5da98e.
//!
//! A stub is two instructions — the `SVC` itself and a return — because the
//! run loop's interrupt hook answers the call *without* touching the PC: the
//! trailing `ret`/`bx lr` is what returns to the caller.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use crate::backend::{Backend, RunError};
use crate::memory::{Memory, MemoryError};

/// Where the stub page is mapped.
///
/// Port of unidbg: `AbstractEmulator`'s `svcBase`/`svcSize` arguments.
pub const SVC_BASE: u64 = 0xfffe_0000;
/// The stub page's size.
pub const SVC_SIZE: u64 = 0x1_0000;

/// arm64 `SVC_MAX`: the largest `SVC` immediate, and the reserved number
/// below it.
pub const ARM64_SVC_MAX: i32 = 0xffff;
/// AArch32 `SVC_MAX` in ARM state.
pub const ARM_SVC_MAX: i32 = 0xff_ffff;
/// AArch32 `SVC_MAX` in Thumb state.
pub const THUMB_SVC_MAX: i32 = 0xff;

/// `SyscallHandler.DARWIN_SWI_SYSCALL`, skipped when numbering stubs.
pub const DARWIN_SWI_SYSCALL: i32 = 0x80;

/// Which instruction set a stub is encoded for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvcKind {
    /// AArch64: `svc #N` (32-bit) then `ret`.
    Arm64,
    /// AArch32 ARM state: `svc #N` (24-bit) then `bx lr`.
    Arm,
    /// AArch32 Thumb state: `svc #N` (8-bit, 16-bit encoding) then `bx lr`.
    Thumb,
}

impl SvcKind {
    /// The largest immediate this encoding can carry, less the one reserved
    /// number (unidbg's `assembleSvc` bound).
    pub const fn max_number(self) -> i32 {
        match self {
            SvcKind::Arm64 => ARM64_SVC_MAX - 1,
            SvcKind::Arm => ARM_SVC_MAX - 1,
            SvcKind::Thumb => THUMB_SVC_MAX - 1,
        }
    }

    /// The `svc` instruction word.
    pub const fn assemble(self, number: i32) -> u32 {
        match self {
            SvcKind::Arm64 => 0xd400_0001 | ((number as u32) << 5),
            SvcKind::Arm => 0xef00_0000 | number as u32,
            SvcKind::Thumb => 0xdf00 | number as u32,
        }
    }

    /// The stub's bytes: the `svc` followed by the return.
    pub fn stub(self, number: i32) -> Vec<u8> {
        match self {
            SvcKind::Arm64 => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&self.assemble(number).to_le_bytes());
                bytes.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
                bytes
            }
            SvcKind::Arm => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&self.assemble(number).to_le_bytes());
                bytes.extend_from_slice(&0xe12f_ff1eu32.to_le_bytes());
                bytes
            }
            SvcKind::Thumb => {
                let mut bytes = Vec::with_capacity(4);
                bytes.extend_from_slice(&(self.assemble(number) as u16).to_le_bytes());
                bytes.extend_from_slice(&0x4770u16.to_le_bytes());
                bytes
            }
        }
    }
}

/// A host-implemented call reachable from the guest through a stub.
///
/// Port of unidbg: `Svc`.
pub trait Svc {
    /// Answers the call; the value becomes `x0`/`r0`.
    ///
    /// Returning an error is how a handler raises what unidbg throws as
    /// `ThreadContextSwitchException` and friends (plan D5).
    fn handle(&mut self, backend: &mut dyn Backend) -> Result<i64, RunError>;

    /// The stub encoding this call needs.
    fn kind(&self) -> SvcKind;

    /// A label for the stub, for diagnostics.
    fn name(&self) -> &str {
        "Svc"
    }

    /// Runs just before the call is dispatched.
    fn handle_pre_callback(&mut self, _backend: &mut dyn Backend) {}

    /// Runs just after the call returned.
    fn handle_post_callback(&mut self, _backend: &mut dyn Backend) {}
}

/// One stub region inside the SVC page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvcRegion {
    /// First byte.
    pub begin: u64,
    /// One past the last byte.
    pub end: u64,
    /// The label the stub was allocated with.
    pub label: String,
}

/// The stub page: a bump allocator over `[SVC_BASE, SVC_BASE + SVC_SIZE)` and
/// the registry of the calls its stubs dispatch to.
pub struct SvcMemory {
    base: u64,
    size: u64,
    cursor: Cell<u64>,
    symbols: RefCell<BTreeMap<String, u64>>,
    svc_map: RefCell<BTreeMap<i32, Box<dyn Svc>>>,
    regions: RefCell<Vec<SvcRegion>>,
    thumb_svc_number: Cell<i32>,
    arm_svc_number: Cell<i32>,
    is_64bit: bool,
}

impl std::fmt::Debug for SvcMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvcMemory")
            .field("base", &format_args!("{:#x}", self.base))
            .field("cursor", &format_args!("{:#x}", self.cursor.get()))
            .field("stubs", &self.svc_map.borrow().len())
            .finish()
    }
}

impl SvcMemory {
    /// Creates the stub page and maps it `READ | EXEC`.
    pub fn new(memory: &dyn Memory, is_64bit: bool) -> Result<Self, MemoryError> {
        memory.mmap2(
            SVC_BASE,
            SVC_SIZE as usize,
            crate::backend::Prot::READ.union(crate::backend::Prot::EXEC),
            crate::memory::MAP_FIXED | crate::memory::MAP_ANONYMOUS,
            -1,
            0,
        )?;
        Ok(SvcMemory {
            base: SVC_BASE,
            size: SVC_SIZE,
            cursor: Cell::new(SVC_BASE),
            symbols: RefCell::new(BTreeMap::new()),
            svc_map: RefCell::new(BTreeMap::new()),
            regions: RefCell::new(Vec::new()),
            thumb_svc_number: Cell::new(0),
            arm_svc_number: Cell::new(0xff),
            is_64bit,
        })
    }

    /// The page's base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The page's size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reserves `size` bytes of stub space.
    ///
    /// Port of unidbg: `ARMSvcMemory.allocate`, which rounds up to four bytes.
    pub fn allocate(&self, size: usize, label: impl Into<String>) -> Result<u64, MemoryError> {
        let size = crate::memory::loader::align_size(size as u64, 4);
        let begin = self.cursor.get();
        let end = begin + size;
        if end > self.base + self.size {
            return Err(MemoryError::Message(format!(
                "the SVC page is full: {end:#x} is past {:#x}",
                self.base + self.size
            )));
        }
        self.cursor.set(end);
        self.regions.borrow_mut().push(SvcRegion {
            begin,
            end,
            label: label.into(),
        });
        Ok(begin)
    }

    /// The stub space holding `name`, allocated once per name.
    ///
    /// Port of unidbg: `ARMSvcMemory.allocateSymbolName`.
    pub fn allocate_symbol_name(
        &self,
        memory: &dyn Memory,
        name: &str,
    ) -> Result<u64, MemoryError> {
        if let Some(address) = self.symbols.borrow().get(name) {
            return Ok(*address);
        }
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        let address = self.allocate(bytes.len(), format!("Symbol.{name}"))?;
        memory.write_bytes(address, &bytes)?;
        self.symbols.borrow_mut().insert(name.to_string(), address);
        Ok(address)
    }

    /// The region containing `address`, if any.
    pub fn find_region(&self, address: u64) -> Option<SvcRegion> {
        if address < self.base || address >= self.base + self.size {
            return None;
        }
        self.regions
            .borrow()
            .iter()
            .find(|region| address >= region.begin && address < region.end)
            .cloned()
    }

    /// Every allocated region.
    pub fn regions(&self) -> Vec<SvcRegion> {
        self.regions.borrow().clone()
    }

    /// Whether a stub number is registered.
    pub fn contains_svc(&self, number: i32) -> bool {
        self.svc_map.borrow().contains_key(&number)
    }

    /// Takes the call a stub number dispatches to, leaving the slot empty.
    ///
    /// The run loop owns the dispatch, so taking the handler out for the
    /// duration of the call is what keeps the borrow of the stub page from
    /// aliasing the backend the handler is handed.
    pub fn take_svc(&self, number: i32) -> Option<Box<dyn Svc>> {
        self.svc_map.borrow_mut().remove(&number)
    }

    /// Puts a call back after [`SvcMemory::take_svc`].
    pub fn put_svc(&self, number: i32, svc: Box<dyn Svc>) {
        self.svc_map.borrow_mut().insert(number, svc);
    }

    /// Registers a call, allocating and writing its stub.
    ///
    /// Port of unidbg: `ARMSvcMemory.registerSvc`.
    pub fn register_svc(&self, memory: &dyn Memory, svc: Box<dyn Svc>) -> Result<u64, MemoryError> {
        self.register_svc_numbered(memory, svc).map(|(address, _)| address)
    }

    /// Registers a call, returning the stub's address and its number.
    ///
    /// The number is what the stub's `svc #N` carries and what the run loop's
    /// dispatch looks up, so a caller that needs to drive the stub itself (a
    /// test, or the debugger) must use this rather than guessing.
    pub fn register_svc_numbered(
        &self,
        memory: &dyn Memory,
        svc: Box<dyn Svc>,
    ) -> Result<(u64, i32), MemoryError> {
        let kind = svc.kind();
        let number = match kind {
            SvcKind::Thumb => {
                if self.is_64bit {
                    return Err(MemoryError::Message("a Thumb stub in a 64-bit guest".into()));
                }
                let next = self.thumb_svc_number.get() + 1;
                let next = if next == DARWIN_SWI_SYSCALL {
                    next + 1
                } else {
                    next
                };
                self.thumb_svc_number.set(next);
                next
            }
            SvcKind::Arm => {
                if self.is_64bit {
                    return Err(MemoryError::Message("an ARM stub in a 64-bit guest".into()));
                }
                let next = self.arm_svc_number.get() + 1;
                let next = if next == DARWIN_SWI_SYSCALL {
                    next + 1
                } else {
                    next
                };
                self.arm_svc_number.set(next);
                next
            }
            SvcKind::Arm64 => {
                if !self.is_64bit {
                    return Err(MemoryError::Message("an arm64 stub in a 32-bit guest".into()));
                }
                let next = self.arm_svc_number.get() + 1;
                let next = if next == DARWIN_SWI_SYSCALL {
                    next + 1
                } else {
                    next
                };
                self.arm_svc_number.set(next);
                next
            }
        };
        if number >= kind.max_number() {
            return Err(MemoryError::Message(format!(
                "the {kind:?} stub number space is exhausted at {number:#x}"
            )));
        }
        if self.svc_map.borrow().contains_key(&number) {
            return Err(MemoryError::Message(format!(
                "stub number {number:#x} is already registered"
            )));
        }
        let code = kind.stub(number);
        let label = format!("{}.{}", svc.name(), number);
        let address = self.allocate(code.len(), label)?;
        memory.write_bytes(address, &code)?;
        self.svc_map.borrow_mut().insert(number, svc);
        Ok((address, number))
    }

    /// Writes a NUL-terminated string into stub space.
    ///
    /// Port of unidbg: `ARMSvcMemory.writeStackString`.
    pub fn write_string(&self, memory: &dyn Memory, value: &str) -> Result<u64, MemoryError> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let address = self.allocate(bytes.len(), format!("writeString: {value}"))?;
        memory.write_bytes(address, &bytes)?;
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_stub_is_svc_then_ret() {
        let stub = SvcKind::Arm64.stub(0x1234);
        assert_eq!(
            u32::from_le_bytes(stub[..4].try_into().unwrap()),
            0xd400_0001 | (0x1234 << 5)
        );
        assert_eq!(u32::from_le_bytes(stub[4..].try_into().unwrap()), 0xd65f_03c0);
    }

    #[test]
    fn arm_stub_is_svc_then_bx_lr() {
        let stub = SvcKind::Arm.stub(0x100);
        assert_eq!(u32::from_le_bytes(stub[..4].try_into().unwrap()), 0xef00_0100);
        assert_eq!(u32::from_le_bytes(stub[4..].try_into().unwrap()), 0xe12f_ff1e);
    }

    #[test]
    fn thumb_stub_is_svc_then_bx_lr() {
        let stub = SvcKind::Thumb.stub(1);
        assert_eq!(u16::from_le_bytes(stub[..2].try_into().unwrap()), 0xdf01);
        assert_eq!(u16::from_le_bytes(stub[2..].try_into().unwrap()), 0x4770);
    }

    #[test]
    fn number_spaces_match_unidbg() {
        assert_eq!(SvcKind::Arm.max_number(), 0xff_fffe);
        assert_eq!(SvcKind::Thumb.max_number(), 0xfe);
        assert_eq!(SvcKind::Arm64.max_number(), 0xfffe);
    }
}
