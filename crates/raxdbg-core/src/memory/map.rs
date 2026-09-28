//! Guest memory maps.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/memory/MemoryMap.java`@7f5da98e.

use crate::backend::Prot;

/// One region of the guest address space, as unidbg's `memoryMap` tree records
/// it: a base, a length and the protection it was mapped with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMap {
    /// First byte of the region.
    pub base: u64,
    /// Length in bytes.
    pub size: u64,
    /// Current protection.
    pub prot: Prot,
}

impl MemoryMap {
    /// A region.
    pub const fn new(base: u64, size: u64, prot: Prot) -> Self {
        MemoryMap { base, size, prot }
    }

    /// One past the last byte.
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Whether `[start, start + len)` overlaps this region.
    pub const fn overlaps(&self, start: u64, len: u64) -> bool {
        start < self.end() && start + len > self.base
    }

    /// Whether `addr` falls inside this region.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}
