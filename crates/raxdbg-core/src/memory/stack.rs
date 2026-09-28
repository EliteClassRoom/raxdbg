//! Stack and thread-stack allocation.
//!
//! Port of unidbg: `AbstractLoader.allocateStack`/`allocateThreadIndex`/
//! `allocateThreadStack`/`setStackPoint` and `Memory.STACK_*`@7f5da98e.
//!
//! The stack is *not* mapped here: unidbg's `initializeTLS` maps the whole
//! stack area once, and these methods only move the stack pointer inside it.

use crate::memory::Memory;
use crate::memory::{
    MAX_THREADS, MemoryError, STACK_BASE, STACK_SIZE_OF_MAIN_PAGE, THREAD_STACK_PAGE,
};
use crate::pointer::Pointer;
use crate::reg::RegId;

use super::loader::{Loader, align_size};

impl Loader {
    /// Reserves `size` bytes below the stack pointer.
    ///
    /// Port of unidbg: `AbstractLoader.allocateStack`.
    pub fn allocate_stack_impl(&self, size: usize) -> Result<Pointer, MemoryError> {
        let new_addr = self.sp.get().wrapping_sub(size as u64);
        let thread_stack_base = STACK_BASE - STACK_SIZE_OF_MAIN_PAGE * self.page_size;
        if new_addr <= thread_stack_base {
            return Err(MemoryError::Message(format!(
                "main thread stack exhausted: sp={:#x}, limit={thread_stack_base:#x}",
                self.sp.get()
            )));
        }
        self.set_stack_point(new_addr);
        Ok(self.pointer(self.sp.get()).set_size(size as u64))
    }

    /// Pushes a NUL-terminated UTF-8 string onto the stack.
    ///
    /// Port of unidbg: `AbstractLoader.writeStackString`.
    pub fn write_stack_string_impl(&self, value: &str) -> Result<Pointer, MemoryError> {
        let mut data = value.as_bytes().to_vec();
        data.push(0);
        self.write_stack_bytes_impl(&data)
    }

    /// Pushes bytes onto the stack, aligned to four bytes.
    ///
    /// Port of unidbg: `AbstractLoader.writeStackBytes`.
    pub fn write_stack_bytes_impl(&self, data: &[u8]) -> Result<Pointer, MemoryError> {
        let size = align_size(data.len() as u64, 4);
        let pointer = self.allocate_stack_impl(size as usize)?;
        pointer.write_bytes(0, data)?;
        Ok(pointer)
    }

    /// Reserves a thread index, or fails when all are taken.
    ///
    /// Port of unidbg: `AbstractLoader.allocateThreadIndex`.
    pub fn allocate_thread_index_impl(&self) -> Result<usize, MemoryError> {
        let mut map = self.thread_stack_map.borrow_mut();
        for (index, taken) in map.iter_mut().enumerate() {
            if !*taken {
                *taken = true;
                return Ok(index);
            }
        }
        Err(MemoryError::Message(format!(
            "too many threads: the maximum is {MAX_THREADS}"
        )))
    }

    /// Releases a thread index.
    ///
    /// Port of unidbg: `AbstractLoader.freeThreadIndex`.
    pub fn free_thread_index_impl(&self, index: usize) {
        if let Some(slot) = self.thread_stack_map.borrow_mut().get_mut(index) {
            *slot = false;
        }
    }

    /// The stack a thread index's thread runs on.
    ///
    /// Port of unidbg: `AbstractLoader.allocateThreadStack`.
    pub fn allocate_thread_stack_impl(&self, index: usize) -> Result<Pointer, MemoryError> {
        if !self
            .thread_stack_map
            .borrow()
            .get(index)
            .copied()
            .unwrap_or(false)
        {
            return Err(MemoryError::Message(format!(
                "thread index {index} was not allocated by allocate_thread_index"
            )));
        }
        let thread_stack_base = STACK_BASE - STACK_SIZE_OF_MAIN_PAGE * self.page_size;
        let address = thread_stack_base - THREAD_STACK_PAGE * index as u64 * self.page_size;
        Ok(self.pointer(address))
    }

    /// Sets the stack pointer, recording the stack base on the first call, and
    /// writes it to the guest's `SP`.
    ///
    /// Port of unidbg: `AbstractLoader.setStackPoint`.
    pub fn set_stack_point_impl(&self, sp: u64) {
        if self.sp.get() == 0 {
            self.stack_base.set(sp);
            // unidbg's `stackSize` field is never assigned; raxdbg records the
            // distance down to the thread-stack area, which is the only useful
            // meaning it can have.
            self.stack_size.set(
                sp.saturating_sub(STACK_BASE - STACK_SIZE_OF_MAIN_PAGE * self.page_size) as usize,
            );
        }
        self.sp.set(sp);
        let _ = self.backend.borrow_mut().reg_write(RegId::Sp, sp);
    }
}
