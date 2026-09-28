//! The memory bridge: rax's `ArmMemory` over the guest address space, with
//! per-access hook dispatch.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/arm/backend/UnicornBackend.java`
//! memory-hook dispatch@7f5da98e. Read and write hooks fire after the access,
//! like unicorn's `UC_HOOK_MEM_READ`/`UC_HOOK_MEM_WRITE`; a faulting access
//! dispatches nothing and is reported to the run loop instead, which offers it
//! to the event-memory hooks.

use std::sync::Arc;

use parking_lot::Mutex;
use rax::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
use rax::isa::arm::aarch32::cpu::{ArmMemory as Arm32Memory, MemoryError as Arm32MemoryError};
use rax::isa::arm::common::cpu::AccessType;
use rax::isa::arm::common::memory::{
    ArmMemory as Arm64Memory, MemResult, MemoryError as Arm64MemoryError, MmioHandler,
};

use crate::hooks::MemShared;

/// Converts a rax address-space fault into the AArch64 core's memory error.
///
/// Mirrors `UserArmMemory::to_memory_error` in rax's `src/user/cpu/aarch64.rs`.
fn to_arm64_error(fault: GuestMemoryFault, size: usize) -> Arm64MemoryError {
    let access = match fault.access {
        MemoryAccessKind::Read => AccessType::Read,
        MemoryAccessKind::Write => AccessType::Write,
        MemoryAccessKind::Fetch => AccessType::InstructionFetch,
    };
    match fault.kind {
        MemoryFaultKind::Unmapped => Arm64MemoryError::Unmapped {
            addr: fault.address,
            size,
            access,
        },
        MemoryFaultKind::Permission => Arm64MemoryError::Permission {
            addr: fault.address,
            access,
            reason: String::new(),
        },
        MemoryFaultKind::Other => Arm64MemoryError::BusError {
            addr: fault.address,
        },
    }
}

/// Converts a rax address-space fault into the AArch32 core's memory error.
///
/// Mirrors `UserA32Memory::failed` in rax's `src/user/cpu/arm.rs`; the address
/// space truncates guest addresses to 32 bits.
fn to_arm32_error(fault: GuestMemoryFault) -> Arm32MemoryError {
    let addr = fault.address as u32;
    match fault.kind {
        MemoryFaultKind::Unmapped => Arm32MemoryError::OutOfBounds(addr),
        MemoryFaultKind::Permission => Arm32MemoryError::PermissionDenied(addr),
        MemoryFaultKind::Other => Arm32MemoryError::BusError(addr),
    }
}

/// The fault of the last failed AArch32 access.
///
/// The AArch32 memory interface reports failures by address only, so the
/// translation fault behind it is kept here for the adapter to report with its
/// access direction. Only touched on the failure path.
#[derive(Debug, Default)]
pub struct FaultSlot(Mutex<Option<GuestMemoryFault>>);

impl FaultSlot {
    /// Records a fault.
    pub fn set(&self, fault: GuestMemoryFault) {
        *self.0.lock() = Some(fault);
    }

    /// Clears the slot, so a stale fault is never reported for a later access.
    pub fn clear(&self) {
        *self.0.lock() = None;
    }

    /// Takes the recorded fault, clearing the slot.
    pub fn take(&self) -> Option<GuestMemoryFault> {
        self.0.lock().take()
    }
}

/// The AArch64 core's memory interface over the shared guest address space.
#[derive(Debug)]
pub struct RaxMemory {
    shared: Arc<MemShared>,
    exclusive: Option<(u64, u8)>,
}

impl RaxMemory {
    /// Creates a memory view over `shared`.
    pub fn new(shared: Arc<MemShared>) -> Self {
        RaxMemory {
            shared,
            exclusive: None,
        }
    }

    /// The shared bridge.
    pub fn shared(&self) -> &Arc<MemShared> {
        &self.shared
    }
}

impl Arm64Memory for RaxMemory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.shared
            .space()
            .read(addr, buf)
            .map_err(|fault| to_arm64_error(fault, buf.len()))?;
        self.shared.dispatch_read(addr, buf.len());
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        self.shared
            .space()
            .write(addr, data)
            .map_err(|fault| to_arm64_error(fault, data.len()))?;
        self.shared.dispatch_write(addr, data.len(), stored_value(data));
        Ok(())
    }

    fn fetch(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.shared
            .space()
            .fetch(addr, buf)
            .map_err(|fault| to_arm64_error(fault, buf.len()))
    }

    fn mark_exclusive(&mut self, addr: u64, size: u8) {
        self.exclusive = Some((addr, size));
    }

    fn check_exclusive(&mut self, addr: u64, size: u8) -> bool {
        self.exclusive.take() == Some((addr, size))
    }

    fn clear_exclusive(&mut self) {
        self.exclusive = None;
    }

    /// User address spaces enforce no alignment (Linux runs EL0 with
    /// `SCTLR_EL1.A` clear).
    fn requires_alignment(&self) -> bool {
        false
    }

    /// User address spaces contain no device memory.
    fn register_mmio(&mut self, _base: u64, _size: u64, _handler: Box<dyn MmioHandler>) {}

    fn unregister_mmio(&mut self, _base: u64) {}
}

/// The little-endian value a store leaves behind, for the write hook.
fn stored_value(data: &[u8]) -> u64 {
    let mut value = 0u64;
    for (i, byte) in data.iter().take(8).enumerate() {
        value |= u64::from(*byte) << (8 * i);
    }
    value
}

/// The AArch32 core's memory interface over the shared guest address space.
#[derive(Debug)]
pub struct RaxArm32Memory {
    shared: Arc<MemShared>,
    fault: FaultSlot,
}

impl RaxArm32Memory {
    /// Creates a memory view over `shared`.
    pub fn new(shared: Arc<MemShared>) -> Self {
        RaxArm32Memory {
            shared,
            fault: FaultSlot::default(),
        }
    }

    /// The shared bridge.
    pub fn shared(&self) -> &Arc<MemShared> {
        &self.shared
    }

    /// The fault of the last failed access, which it clears.
    pub fn take_fault(&self) -> Option<GuestMemoryFault> {
        self.fault.take()
    }

    /// Clears the recorded fault before an instruction executes.
    pub fn clear_fault(&self) {
        self.fault.clear();
    }

    fn failed(&self, fault: GuestMemoryFault) -> Arm32MemoryError {
        self.fault.set(fault);
        to_arm32_error(fault)
    }

    fn load<const N: usize>(&self, addr: u32) -> Result<[u8; N], Arm32MemoryError> {
        let mut buf = [0u8; N];
        let addr = u64::from(addr);
        self.shared
            .space()
            .read(addr, &mut buf)
            .map_err(|fault| self.failed(fault))?;
        self.shared.dispatch_read(addr, N);
        Ok(buf)
    }

    fn store(&self, addr: u32, data: &[u8]) -> Result<(), Arm32MemoryError> {
        let addr64 = u64::from(addr);
        self.shared
            .space()
            .write(addr64, data)
            .map_err(|fault| self.failed(fault))?;
        self.shared.dispatch_write(addr64, data.len(), stored_value(data));
        Ok(())
    }
}

impl Arm32Memory for RaxArm32Memory {
    fn read_word(&self, addr: u32) -> Result<u32, Arm32MemoryError> {
        self.load::<4>(addr).map(u32::from_le_bytes)
    }

    fn write_word(&mut self, addr: u32, value: u32) -> Result<(), Arm32MemoryError> {
        self.store(addr, &value.to_le_bytes())
    }

    fn read_halfword(&self, addr: u32) -> Result<u16, Arm32MemoryError> {
        self.load::<2>(addr).map(u16::from_le_bytes)
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> Result<(), Arm32MemoryError> {
        self.store(addr, &value.to_le_bytes())
    }

    fn read_byte(&self, addr: u32) -> Result<u8, Arm32MemoryError> {
        self.load::<1>(addr).map(|b| b[0])
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> Result<(), Arm32MemoryError> {
        self.store(addr, &[value])
    }

    /// Linux runs EL0 with `SCTLR_1.A` clear.
    fn allows_unaligned(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_value_is_little_endian() {
        assert_eq!(stored_value(&[0x2a]), 0x2a);
        assert_eq!(stored_value(&[0x34, 0x12]), 0x1234);
        assert_eq!(stored_value(&[0, 0, 0, 0, 1]), 0x1_0000_0000);
        assert_eq!(
            stored_value(&[0xff; 16]),
            u64::MAX,
            "only the first eight bytes are reported"
        );
    }

    #[test]
    fn arm32_fault_mapping_matches_rax() {
        let fault = |kind| GuestMemoryFault {
            address: 0x1000,
            size: 4,
            access: MemoryAccessKind::Read,
            kind,
        };
        assert_eq!(
            to_arm32_error(fault(MemoryFaultKind::Unmapped)),
            Arm32MemoryError::OutOfBounds(0x1000)
        );
        assert_eq!(
            to_arm32_error(fault(MemoryFaultKind::Permission)),
            Arm32MemoryError::PermissionDenied(0x1000)
        );
        assert_eq!(
            to_arm32_error(fault(MemoryFaultKind::Other)),
            Arm32MemoryError::BusError(0x1000)
        );
    }
}
