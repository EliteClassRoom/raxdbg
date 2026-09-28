//! The guest memory facade.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/memory/Memory.java`,
//! `unidbg-api/src/main/java/com/github/unidbg/spi/AbstractLoader.java` and
//! `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidElfLoader.java`
//! @7f5da98e.
//!
//! The trait is the whole host-side view of guest memory: allocation
//! (`mmap2`, `brk`, `malloc`), the stack, thread stacks, `errno`, and the
//! region bookkeeping unidbg's `memoryMap` keeps. Module loading lives in
//! `raxdbg-android`'s ELF loader, which delegates here.
//!
//! Every method takes `&self`: the loader owns its state behind cells so a
//! `Pointer` can hold an `Rc<dyn Memory>` without borrowing rules getting in
//! the way (plan P2.6).

pub mod loader;
pub mod map;
pub mod stack;

use crate::backend::{BackendError, Prot};
use crate::pointer::Pointer;

pub use map::MemoryMap;

/// Guest page size.
pub const PAGE_SIZE: u64 = 4096;

/// Base of the main thread's stack region.
///
/// Port of unidbg: `Memory.STACK_BASE`.
pub const STACK_BASE: u64 = 0xe500_0000;

/// Base of the `mmap` region.
///
/// Port of unidbg: `Memory.MMAP_BASE`.
pub const MMAP_BASE: u64 = 0x1200_0000;

/// Base of the program break (`brk`).
///
/// Port of unidbg: `AndroidElfLoader.HEAP_BASE`.
pub const HEAP_BASE: u64 = 0x0804_8000;

/// Maximum number of guest threads.
///
/// Port of unidbg: `Memory.MAX_THREADS`.
pub const MAX_THREADS: usize = 16;

/// Pages reserved for one thread's stack.
///
/// Port of unidbg: `BaseTask.THREAD_STACK_PAGE`.
pub const THREAD_STACK_PAGE: u64 = 64;

/// Pages reserved for the main thread's stack.
///
/// Port of unidbg: `Memory.STACK_SIZE_OF_MAIN_PAGE`.
pub const STACK_SIZE_OF_MAIN_PAGE: u64 = 256;

/// Pages reserved for every thread stack together.
///
/// Port of unidbg: `Memory.STACK_SIZE_OF_THREAD_PAGE`.
pub const STACK_SIZE_OF_THREAD_PAGE: u64 = MAX_THREADS as u64 * THREAD_STACK_PAGE;

/// Pages reserved for the stack area as a whole.
///
/// Port of unidbg: `Memory.STACK_SIZE_OF_PAGE`.
pub const STACK_SIZE_OF_PAGE: u64 = STACK_SIZE_OF_THREAD_PAGE + STACK_SIZE_OF_MAIN_PAGE;

/// `MAP_SHARED`.
pub const MAP_SHARED: i32 = 0x01;
/// `MAP_PRIVATE`.
pub const MAP_PRIVATE: i32 = 0x02;
/// `MAP_FIXED`.
pub const MAP_FIXED: i32 = 0x10;
/// `MAP_ANONYMOUS`.
pub const MAP_ANONYMOUS: i32 = 0x20;

/// The value `mmap2` returns when it fails, as Linux's `MAP_FAILED`.
pub const MAP_FAILED: u64 = u64::MAX;

/// A guest memory operation that failed.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    /// The CPU backend rejected the operation.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// The address is not mapped.
    #[error("address {addr:#x} is not mapped")]
    NotMapped {
        /// The offending address.
        addr: u64,
    },
    /// The request is invalid.
    #[error("{0}")]
    Message(String),
}

/// Notified when the guest address space changes.
///
/// Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/memory/MMapListener.java`.
pub trait MMapListener {
    /// A new region was mapped.
    fn on_map(&self, address: u64, size: u64, prot: Prot);
    /// A region's protection is about to change; returns the protection to use.
    fn on_protect(&self, address: u64, size: u64, prot: Prot) -> Prot;
    /// A region was unmapped.
    fn on_unmap(&self, address: u64, size: u64);
}

/// Guest memory.
pub trait Memory {
    /// The guest page size.
    fn page_size(&self) -> u64;

    /// The guest pointer width in bytes (4 or 8).
    fn pointer_size(&self) -> usize;

    /// A pointer into guest memory. Never fails: an unmapped address is only
    /// discovered on access, as with unidbg's `UnidbgPointer`.
    fn pointer(&self, address: u64) -> Pointer;

    /// Reads `buf.len()` bytes.
    fn read_bytes(&self, address: u64, buf: &mut [u8]) -> Result<(), MemoryError>;

    /// Writes `data`.
    fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), MemoryError>;

    /// Maps `length` bytes anywhere, as unidbg's `Memory.mmap`.
    fn mmap(&self, length: usize, prot: Prot) -> Result<Pointer, MemoryError>;

    /// Maps `length` bytes, as Linux's `mmap2`.
    fn mmap2(
        &self,
        start: u64,
        length: usize,
        prot: Prot,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<u64, MemoryError>;

    /// Changes the protection of `[address, address + length)`.
    fn mprotect(&self, address: u64, length: usize, prot: Prot) -> Result<i32, MemoryError>;

    /// Unmaps `[start, start + length)`.
    fn munmap(&self, start: u64, length: usize) -> Result<i32, MemoryError>;

    /// Grows or shrinks the program break; `0` returns the current break.
    fn brk(&self, address: u64) -> Result<u64, MemoryError>;

    /// Allocates `length` bytes. `runtime` selects the mmap-backed block
    /// (freed with `munmap`) over the guest libc's `malloc` (freed with
    /// `free`), as unidbg's `Memory.malloc` documents.
    fn malloc(&self, length: usize, runtime: bool) -> Result<crate::alloc::MemoryBlock, MemoryError>;

    /// Reserves `size` bytes below the stack pointer.
    fn allocate_stack(&self, size: usize) -> Result<Pointer, MemoryError>;

    /// Pushes a NUL-terminated UTF-8 string onto the stack.
    fn write_stack_string(&self, value: &str) -> Result<Pointer, MemoryError>;

    /// Pushes bytes onto the stack, page-aligned.
    fn write_stack_bytes(&self, data: &[u8]) -> Result<Pointer, MemoryError>;

    /// Reserves a thread index, or fails when all [`MAX_THREADS`] are taken.
    fn allocate_thread_index(&self) -> Result<usize, MemoryError>;

    /// Releases a thread index.
    fn free_thread_index(&self, index: usize);

    /// The stack a thread index's thread runs on.
    fn allocate_thread_stack(&self, index: usize) -> Result<Pointer, MemoryError>;

    /// The current stack pointer.
    fn get_stack_point(&self) -> u64;

    /// Sets the stack pointer (and records the stack base on the first call).
    fn set_stack_point(&self, sp: u64);

    /// The stack base recorded by the first [`Memory::set_stack_point`].
    fn get_stack_base(&self) -> u64;

    /// The stack size recorded by the first [`Memory::set_stack_point`].
    fn get_stack_size(&self) -> usize;

    /// Sets the guest's `errno` slot.
    fn set_errno(&self, errno: i32);

    /// The last `errno` written.
    fn get_last_errno(&self) -> i32;

    /// A snapshot of the region tree, ordered by address.
    fn get_memory_map(&self) -> Vec<MemoryMap>;

    /// Installs the listener notified of address-space changes.
    fn set_mmap_listener(&self, listener: Box<dyn MMapListener>);

    /// Removes and returns the installed listener, so a new one can chain to
    /// it (unidbg's `MemoryTracker` does exactly that).
    fn take_mmap_listener(&self) -> Option<Box<dyn MMapListener>>;
}
