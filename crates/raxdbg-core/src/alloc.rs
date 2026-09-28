//! Guest memory blocks and allocation tracking.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/memory/MemoryBlockImpl.java`,
//! `MemoryAllocBlock.java` and `MemoryTracker.java`@7f5da98e.

use std::collections::BTreeMap;

use parking_lot::Mutex;

use crate::backend::Prot;
use crate::memory::{Memory, MemoryError, MMapListener};
use crate::pointer::Pointer;

/// Calls a guest function from host code.
///
/// unidbg's `Symbol.call(emulator, args)`; the emulator implements this in
/// raxdbg (plan P5), so the memory facade can route `malloc` through the
/// guest's libc without depending on the emulator.
pub trait GuestCall {
    /// Calls the function at `address` with `args`, returning its result.
    fn call(&self, address: u64, args: &[u64]) -> Result<u64, MemoryError>;
}

/// A block of guest memory.
///
/// Port of unidbg: `MemoryBlock`, with both implementations in one enum
/// because the only difference is how the block is released.
pub enum MemoryBlock {
    /// Allocated with `mmap`, released with `munmap`
    /// (`MemoryBlockImpl.alloc`).
    Mmap {
        /// The memory that owns the block.
        memory: std::rc::Rc<dyn Memory>,
        /// The block.
        pointer: Pointer,
    },
    /// Allocated by the guest libc's `malloc`, released with `free`
    /// (`MemoryAllocBlock.malloc`).
    Libc {
        /// How to call the guest.
        call: std::rc::Rc<dyn GuestCall>,
        /// Address of the guest `free`.
        free: u64,
        /// The block.
        pointer: Pointer,
    },
}

impl std::fmt::Debug for MemoryBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryBlock::Mmap { pointer, .. } => f
                .debug_struct("MemoryBlock::Mmap")
                .field("pointer", pointer)
                .finish(),
            MemoryBlock::Libc { pointer, free, .. } => f
                .debug_struct("MemoryBlock::Libc")
                .field("pointer", pointer)
                .field("free", &format_args!("{free:#x}"))
                .finish(),
        }
    }
}

impl MemoryBlock {
    /// The block's first byte.
    pub fn pointer(&self) -> &Pointer {
        match self {
            MemoryBlock::Mmap { pointer, .. } | MemoryBlock::Libc { pointer, .. } => pointer,
        }
    }

    /// Whether `pointer` addresses the same block.
    pub fn is_same(&self, pointer: &Pointer) -> bool {
        self.pointer().peer() == pointer.peer()
    }

    /// Releases the block the way it was allocated.
    pub fn free(self) -> Result<(), MemoryError> {
        match self {
            MemoryBlock::Mmap { memory, pointer } => {
                memory.munmap(pointer.peer(), pointer.get_size() as usize)?;
                Ok(())
            }
            MemoryBlock::Libc {
                call,
                free,
                pointer,
            } => {
                call.call(free, &[pointer.peer()])?;
                Ok(())
            }
        }
    }
}

/// One live allocation, as `MemoryTracker` records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationRecord {
    /// The block's first byte.
    pub address: u64,
    /// The block's length.
    pub size: u64,
    /// The protection it was mapped with.
    pub prot: Prot,
    /// The guest stack, innermost frame first.
    pub guest_backtrace: Vec<u64>,
    /// The host stack, innermost frame first.
    pub host_backtrace: Vec<String>,
}

/// The guest stack of an allocation.
///
/// unidbg walks the guest with its unwinder; raxdbg's unwinder arrives in P12,
/// so the tracker takes whatever provider the emulator installs and records the
/// program counter alone until then.
pub trait BacktraceProvider {
    /// Captures up to `max` guest frames.
    fn capture(&self, max: usize) -> Vec<u64>;
}

/// Records every mapping and unmapping of the guest address space.
///
/// Port of unidbg: `MemoryTracker`, which is an `MMapListener` that chains to
/// the listener it replaced.
pub struct MemoryTracker {
    allocations: Mutex<BTreeMap<u64, AllocationRecord>>,
    previous: Mutex<Option<Box<dyn MMapListener>>>,
    provider: Mutex<Option<Box<dyn BacktraceProvider>>>,
    host_backtrace: std::sync::atomic::AtomicBool,
    total_allocations: Mutex<u64>,
    total_deallocations: Mutex<u64>,
}

impl std::fmt::Debug for MemoryTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTracker")
            .field("live", &self.allocations.lock().len())
            .field("total_allocations", &self.total_allocations.lock())
            .field("total_deallocations", &self.total_deallocations.lock())
            .finish()
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTracker {
    /// A tracker with no previous listener and no guest unwinder.
    pub fn new() -> Self {
        MemoryTracker {
            allocations: Mutex::new(BTreeMap::new()),
            previous: Mutex::new(None),
            provider: Mutex::new(None),
            host_backtrace: std::sync::atomic::AtomicBool::new(false),
            total_allocations: Mutex::new(0),
            total_deallocations: Mutex::new(0),
        }
    }

    /// Installs `provider` for guest backtraces (the P12 unwinder).
    pub fn set_backtrace_provider(&self, provider: Box<dyn BacktraceProvider>) {
        *self.provider.lock() = Some(provider);
    }

    /// Records the host stack as well; off by default because it is slow.
    pub fn set_host_backtrace(&self, enabled: bool) {
        self.host_backtrace
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Takes the listener `memory` currently has and installs this tracker in
    /// its place, remembering the old one to chain to (unidbg's constructor).
    pub fn install(self: &std::rc::Rc<Self>, memory: &dyn Memory) {
        *self.previous.lock() = memory.take_mmap_listener();
        memory.set_mmap_listener(Box::new(ChainedTracker(std::rc::Rc::clone(self))));
    }

    /// Every live allocation, ordered by address.
    pub fn allocations(&self) -> Vec<AllocationRecord> {
        self.allocations.lock().values().cloned().collect()
    }

    /// Total mappings seen.
    pub fn total_allocations(&self) -> u64 {
        *self.total_allocations.lock()
    }

    /// Total unmappings seen.
    pub fn total_deallocations(&self) -> u64 {
        *self.total_deallocations.lock()
    }

    /// Writes the live allocations to `out`, innermost frame first
    /// (unidbg's `MemoryTracker.traceMemoryLeaks`).
    pub fn write_leaks(&self, out: &mut impl std::io::Write) -> std::io::Result<usize> {
        let allocations = self.allocations();
        for record in &allocations {
            writeln!(
                out,
                "Allocation {{ address=0x{:x}, size=0x{:x}, prot={} }}",
                record.address, record.size, record.prot
            )?;
            for (index, pc) in record.guest_backtrace.iter().enumerate() {
                writeln!(out, "  #{index} guest 0x{pc:x}")?;
            }
            for (index, frame) in record.host_backtrace.iter().enumerate() {
                writeln!(out, "  #{index} host {frame}")?;
            }
        }
        Ok(allocations.len())
    }

    fn record(&self, address: u64, size: u64, prot: Prot) {
        let guest_backtrace = self
            .provider
            .lock()
            .as_ref()
            .map(|provider| provider.capture(20))
            .unwrap_or_default();
        let host_backtrace = if self
            .host_backtrace
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            host_frames(20)
        } else {
            Vec::new()
        };
        self.allocations.lock().insert(
            address,
            AllocationRecord {
                address,
                size,
                prot,
                guest_backtrace,
                host_backtrace,
            },
        );
        *self.total_allocations.lock() += 1;
    }

    /// Removes every record that overlaps `[address, address + size)`.
    fn forget(&self, address: u64, size: u64) {
        let end = address.saturating_add(size);
        self.allocations
            .lock()
            .retain(|_, record| !(record.address < end && record.address + record.size > address));
    }
}

/// The listener `MemoryTracker` installs, so the tracker can chain to whatever
/// listener it replaced without holding a borrow of the memory.
struct ChainedTracker(std::rc::Rc<MemoryTracker>);

impl MMapListener for ChainedTracker {
    fn on_map(&self, address: u64, size: u64, prot: Prot) {
        self.0.record(address, size, prot);
        if let Some(previous) = self.0.previous.lock().as_ref() {
            previous.on_map(address, size, prot);
        }
    }

    fn on_protect(&self, address: u64, size: u64, prot: Prot) -> Prot {
        match self.0.previous.lock().as_ref() {
            Some(previous) => previous.on_protect(address, size, prot),
            None => prot,
        }
    }

    fn on_unmap(&self, address: u64, size: u64) {
        self.0.forget(address, size);
        *self.0.total_deallocations.lock() += 1;
        if let Some(previous) = self.0.previous.lock().as_ref() {
            previous.on_unmap(address, size);
        }
    }
}

/// Captures up to `max` host frames, innermost first.
fn host_frames(max: usize) -> Vec<String> {
    let mut frames = Vec::new();
    let mut skip = 0usize;
    for line in std::backtrace::Backtrace::force_capture().to_string().lines() {
        // The first lines are the "stack backtrace:" banner and this function.
        if skip < 2 {
            skip += 1;
            continue;
        }
        frames.push(line.trim().to_string());
        if frames.len() == max {
            break;
        }
    }
    frames
}
