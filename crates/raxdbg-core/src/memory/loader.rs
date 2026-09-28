//! The loader: unidbg's address-space bookkeeping.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/spi/AbstractLoader.java`
//! and the memory half of `unidbg-android/src/main/java/com/github/unidbg/linux/AndroidElfLoader.java`
//! @7f5da98e. The ELF half lives in `raxdbg-android`'s loader, which owns a
//! [`Loader`] and delegates the `Memory` contract to it.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use std::rc::Weak;

use crate::alloc::{GuestCall, MemoryBlock, MemoryTracker};
use crate::backend::{Backend, Prot};
use crate::memory::{
    HEAP_BASE, MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAX_THREADS, MMAP_BASE, MMapListener, Memory,
    MemoryError, MemoryMap, PAGE_SIZE,
};
use crate::pointer::Pointer;

/// Rounds `size` up to a multiple of `align`.
pub const fn align_size(size: u64, align: u64) -> u64 {
    if align == 0 {
        return size;
    }
    size.div_ceil(align) * align
}

/// Rounds `address` down and `size` up for `align`, as unidbg's `ARM.align`.
pub const fn align(address: u64, size: u64, align: u64) -> (u64, u64) {
    let start = address / align * align;
    let end = align_size(address + size, align);
    (start, end - start)
}

/// A file-backed `mmap`, implemented by the syscall layer (plan P4) because it
/// needs the file-descriptor table.
pub trait FileMapper {
    /// Maps `length` bytes of `fd` at `offset` into `addr`.
    fn mmap_file(
        &self,
        fd: i32,
        addr: u64,
        length: u64,
        prot: Prot,
        offset: i64,
    ) -> Result<u64, MemoryError>;
}

/// The guest libc allocator, once `libc.so` is loaded.
pub(crate) struct LibcAllocator {
    malloc: u64,
    free: u64,
    call: Rc<dyn GuestCall>,
}

/// Guest address-space state: regions, `mmap` cursor, `brk`, the stack, thread
/// indices and `errno`.
pub struct Loader {
    pub(crate) backend: Rc<RefCell<dyn Backend>>,
    pub(crate) pointer_size: usize,
    pub(crate) page_size: u64,
    pub(crate) memory_map: RefCell<BTreeMap<u64, MemoryMap>>,
    pub(crate) mmap_base_address: Cell<u64>,
    pub(crate) brk: Cell<u64>,
    pub(crate) sp: Cell<u64>,
    pub(crate) stack_base: Cell<u64>,
    pub(crate) stack_size: Cell<usize>,
    pub(crate) thread_stack_map: RefCell<[bool; MAX_THREADS]>,
    pub(crate) errno_address: Cell<u64>,
    pub(crate) last_errno: Cell<i32>,
    pub(crate) listener: RefCell<Option<Box<dyn MMapListener>>>,
    pub(crate) libc: RefCell<Option<LibcAllocator>>,
    pub(crate) file_mapper: RefCell<Option<Box<dyn FileMapper>>>,
    pub(crate) tracker: RefCell<Option<Rc<MemoryTracker>>>,
    /// A weak handle to this loader, so a [`Pointer`] can own an
    /// `Rc<dyn Memory>` without the loader owning itself.
    pub(crate) self_ref: Weak<Loader>,
}

impl std::fmt::Debug for Loader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loader")
            .field("pointer_size", &self.pointer_size)
            .field("mmap_base", &format_args!("{:#x}", self.mmap_base_address.get()))
            .field("brk", &format_args!("{:#x}", self.brk.get()))
            .field("sp", &format_args!("{:#x}", self.sp.get()))
            .field("regions", &self.memory_map.borrow().len())
            .finish()
    }
}

impl Loader {
    /// A loader over `backend`, for a guest whose pointers are `pointer_size`
    /// bytes wide.
    ///
    /// The loader is returned inside an `Rc` because every [`Pointer`] it hands
    /// out keeps a strong handle to it.
    pub fn new(backend: Rc<RefCell<dyn Backend>>, pointer_size: usize) -> Rc<Self> {
        Rc::new_cyclic(|self_ref| Loader {
            backend,
            pointer_size,
            page_size: PAGE_SIZE,
            memory_map: RefCell::new(BTreeMap::new()),
            mmap_base_address: Cell::new(MMAP_BASE),
            brk: Cell::new(HEAP_BASE),
            sp: Cell::new(0),
            stack_base: Cell::new(0),
            stack_size: Cell::new(0),
            thread_stack_map: RefCell::new([false; MAX_THREADS]),
            errno_address: Cell::new(0),
            last_errno: Cell::new(0),
            listener: RefCell::new(None),
            libc: RefCell::new(None),
            file_mapper: RefCell::new(None),
            tracker: RefCell::new(None),
            self_ref: self_ref.clone(),
        })
    }

    /// A strong handle to this loader, for building pointers and blocks.
    fn handle(&self) -> Rc<dyn Memory> {
        self.self_ref
            .upgrade()
            .expect("a loader is kept alive by the Rc it was created in")
    }

    /// The backend this loader maps through.
    pub fn backend(&self) -> &Rc<RefCell<dyn Backend>> {
        &self.backend
    }

    /// Registers the guest libc's `malloc`/`free` so `Memory::malloc(len,
    /// false)` routes through them (unidbg's `MemoryAllocBlock`).
    pub fn set_libc_allocator(&self, malloc: u64, free: u64, call: Rc<dyn GuestCall>) {
        *self.libc.borrow_mut() = Some(LibcAllocator { malloc, free, call });
    }

    /// Registers the file mapper used by file-backed `mmap2`.
    pub fn set_file_mapper(&self, mapper: Box<dyn FileMapper>) {
        *self.file_mapper.borrow_mut() = Some(mapper);
    }

    /// Installs an allocation tracker (plan P2.5).
    pub fn set_tracker(&self, tracker: Rc<MemoryTracker>) {
        *self.tracker.borrow_mut() = Some(tracker);
    }

    /// The installed allocation tracker.
    pub fn tracker(&self) -> Option<Rc<MemoryTracker>> {
        self.tracker.borrow().clone()
    }

    /// The guest address of the `errno` slot.
    pub fn errno_address(&self) -> u64 {
        self.errno_address.get()
    }

    /// Sets the guest address `errno` is stored at (unidbg's `initializeTLS`
    /// does this once the TLS block exists).
    pub fn set_errno_address(&self, address: u64) {
        self.errno_address.set(address);
    }

    /// The current `mmap` cursor.
    pub fn mmap_base_address(&self) -> u64 {
        self.mmap_base_address.get()
    }

    /// Sets the `mmap` cursor.
    pub fn set_mmap_base_address(&self, address: u64) {
        self.mmap_base_address.set(address);
    }

    /// The region tree, ordered by address.
    pub fn regions(&self) -> Vec<MemoryMap> {
        self.memory_map.borrow().values().copied().collect()
    }

    /// The region containing `address`, if any.
    pub fn region_at(&self, address: u64) -> Option<MemoryMap> {
        self.memory_map
            .borrow()
            .values()
            .find(|map| map.contains(address))
            .copied()
    }

    /// The first free gap that fits `length` and is aligned to `mask`, else
    /// the `mmap` cursor.
    ///
    /// Port of unidbg: `AbstractLoader.allocateMapAddress`.
    pub fn allocate_map_address(&self, mask: u64, length: u64) -> u64 {
        let memory_map = self.memory_map.borrow();
        let mut last_entry: Option<MemoryMap> = None;
        for map in memory_map.values() {
            match last_entry {
                None => last_entry = Some(*map),
                Some(last) => {
                    let mmap_address = last.end();
                    if mmap_address + length < map.base && (mmap_address & mask) == 0 {
                        return mmap_address;
                    }
                    last_entry = Some(*map);
                }
            }
        }
        if let Some(last) = last_entry {
            let mmap_address = last.end();
            if mmap_address < self.mmap_base_address.get() {
                self.set_mmap_base_address(mmap_address);
            }
        }
        let mut addr = self.mmap_base_address.get();
        while (addr & mask) != 0 {
            addr += self.page_size;
        }
        self.set_mmap_base_address(addr + length);
        addr
    }

    /// Records and maps a region, notifying the listener.
    pub(crate) fn map_region(
        &self,
        address: u64,
        size: u64,
        prot: Prot,
    ) -> Result<(), MemoryError> {
        self.backend.borrow_mut().mem_map(address, size, prot)?;
        if let Some(listener) = self.listener.borrow().as_ref() {
            listener.on_map(address, size, prot);
        }
        self.memory_map
            .borrow_mut()
            .insert(address, MemoryMap::new(address, size, prot));
        Ok(())
    }

    /// Port of unidbg: `AndroidElfLoader.mmap2`.
    pub fn mmap2_impl(
        &self,
        start: u64,
        length: usize,
        prot: Prot,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<u64, MemoryError> {
        let aligned = align_size(length as u64, self.page_size);
        let is_anonymous = (flags & MAP_ANONYMOUS) != 0 || (start == 0 && fd <= 0 && offset == 0);

        if (flags & MAP_FIXED) != 0 && is_anonymous {
            let overlaps = self
                .memory_map
                .borrow()
                .values()
                .any(|map| map.overlaps(start, aligned));
            if overlaps {
                self.munmap_impl(start, length)?;
            }
            self.map_region(start, aligned, prot)?;
            return Ok(start);
        }

        if is_anonymous {
            let addr = self.allocate_map_address(0, aligned);
            self.map_region(addr, aligned, prot)?;
            return Ok(addr);
        }

        let mapper = self.file_mapper.borrow();
        let Some(mapper) = mapper.as_ref() else {
            return Err(MemoryError::Message(format!(
                "mmap2 needs the syscall layer for fd {fd} (start={start:#x}, length={length:#x})"
            )));
        };
        if start == 0 && fd > 0 {
            let addr = self.allocate_map_address(0, aligned);
            let ret = mapper.mmap_file(fd, addr, aligned, prot, offset)?;
            if let Some(listener) = self.listener.borrow().as_ref() {
                listener.on_map(addr, aligned, prot);
            }
            self.memory_map
                .borrow_mut()
                .insert(addr, MemoryMap::new(addr, aligned, prot));
            return Ok(ret);
        }
        if fd > 0 {
            if start % self.page_size != 0 {
                return Ok(MAP_FAILED);
            }
            let end = start + length as u64;
            let overlaps = self
                .memory_map
                .borrow()
                .values()
                .any(|map| map.base.max(start) <= map.end().min(end));
            if overlaps {
                return Ok(MAP_FAILED);
            }
            let ret = mapper.mmap_file(fd, start, aligned, prot, offset)?;
            if let Some(listener) = self.listener.borrow().as_ref() {
                listener.on_map(start, aligned, prot);
            }
            self.memory_map
                .borrow_mut()
                .insert(start, MemoryMap::new(start, aligned, prot));
            return Ok(ret);
        }
        Ok(MAP_FAILED)
    }

    /// Port of unidbg: `AbstractLoader.munmap`.
    pub fn munmap_impl(&self, start: u64, length: usize) -> Result<i32, MemoryError> {
        let aligned = align_size(length as u64, self.page_size);
        self.backend.borrow_mut().mem_unmap(start, aligned)?;
        if let Some(listener) = self.listener.borrow().as_ref() {
            listener.on_unmap(start, aligned);
        }

        let removed = self.memory_map.borrow_mut().remove(&start);
        let Some(removed) = removed else {
            // The range starts inside an existing region: split it in two.
            let segment = self
                .memory_map
                .borrow()
                .values()
                .find(|map| start > map.base && start < map.end())
                .copied()
                .ok_or_else(|| {
                    MemoryError::Message(format!("munmap of unmapped range at {start:#x}"))
                })?;
            let mut memory_map = self.memory_map.borrow_mut();
            if start + aligned < segment.end() {
                memory_map.insert(
                    start + aligned,
                    MemoryMap::new(start + aligned, segment.end() - start - aligned, segment.prot),
                );
            }
            memory_map.insert(
                segment.base,
                MemoryMap::new(segment.base, start - segment.base, segment.prot),
            );
            return Ok(segment.prot.bits() as i32);
        };

        if removed.size != aligned {
            if aligned >= removed.size {
                // The request covers this region and possibly its neighbours.
                let mut address = start + removed.size;
                let mut size = aligned - removed.size;
                while size != 0 {
                    let Some(next) = self.memory_map.borrow_mut().remove(&address) else {
                        break;
                    };
                    if next.size > size {
                        return Err(MemoryError::Message(format!(
                            "munmap adjacent region size={:#x} exceeds remaining={size:#x} at {address:#x}",
                            next.size
                        )));
                    }
                    address += next.size;
                    size -= next.size;
                }
                return Ok(removed.prot.bits() as i32);
            }
            // The request covers only the front of the region.
            self.memory_map.borrow_mut().insert(
                start + aligned,
                MemoryMap::new(start + aligned, removed.size - aligned, removed.prot),
            );
            return Ok(removed.prot.bits() as i32);
        }

        if self.memory_map.borrow().is_empty() {
            self.set_mmap_base_address(MMAP_BASE);
        }
        Ok(removed.prot.bits() as i32)
    }

    /// Port of unidbg: `AbstractLoader.mprotect`, including its region
    /// splitting.
    pub fn mprotect_impl(
        &self,
        address: u64,
        length: usize,
        prot: Prot,
    ) -> Result<i32, MemoryError> {
        if address % self.page_size != 0 {
            self.set_errno(crate::errno::EINVAL);
            return Ok(-1);
        }
        let aligned = align_size(length as u64, self.page_size);
        let prot = match self.listener.borrow().as_ref() {
            Some(listener) => listener.on_protect(address, aligned, prot),
            None => prot,
        };
        self.backend.borrow_mut().mem_protect(address, aligned, prot)?;

        let prot_end = address + aligned;
        let affected: Vec<MemoryMap> = self
            .memory_map
            .borrow()
            .values()
            .filter(|map| address < map.end() && prot_end > map.base)
            .copied()
            .collect();
        let mut memory_map = self.memory_map.borrow_mut();
        for map in affected {
            let map_end = map.end();
            memory_map.remove(&map.base);
            if address <= map.base && prot_end >= map_end {
                memory_map.insert(map.base, MemoryMap::new(map.base, map.size, prot));
            } else if address <= map.base {
                memory_map.insert(map.base, MemoryMap::new(map.base, prot_end - map.base, prot));
                memory_map.insert(
                    prot_end,
                    MemoryMap::new(prot_end, map_end - prot_end, map.prot),
                );
            } else if prot_end >= map_end {
                memory_map.insert(
                    map.base,
                    MemoryMap::new(map.base, address - map.base, map.prot),
                );
                memory_map.insert(address, MemoryMap::new(address, map_end - address, prot));
            } else {
                memory_map.insert(
                    map.base,
                    MemoryMap::new(map.base, address - map.base, map.prot),
                );
                memory_map.insert(address, MemoryMap::new(address, aligned, prot));
                memory_map.insert(
                    prot_end,
                    MemoryMap::new(prot_end, map_end - prot_end, map.prot),
                );
            }
        }
        Ok(0)
    }

    /// Port of unidbg: `AndroidElfLoader.brk`. The break starts at
    /// [`HEAP_BASE`] rather than at zero, so a guest that grows the heap
    /// without asking for the current break first cannot map `[0, brk)`.
    pub fn brk_impl(&self, address: u64) -> Result<u64, MemoryError> {
        if address == 0 {
            self.brk.set(HEAP_BASE);
            return Ok(HEAP_BASE);
        }
        if address % self.page_size != 0 {
            return Err(MemoryError::Message(format!(
                "brk address {address:#x} is not page-aligned"
            )));
        }
        let current = self.brk.get();
        if address > current {
            self.map_region(current, address - current, Prot::READ.union(Prot::WRITE))?;
        } else if address < current {
            self.backend
                .borrow_mut()
                .mem_unmap(address, current - address)?;
            if let Some(listener) = self.listener.borrow().as_ref() {
                listener.on_unmap(address, current - address);
            }
            // unidbg leaves the region tree alone here, which leaves a stale
            // region behind; shrink the heap's region instead, so the address
            // it gave back can be mapped again.
            let heap = self
                .memory_map
                .borrow()
                .values()
                .find(|map| map.contains(address))
                .copied();
            if let Some(heap) = heap {
                let mut memory_map = self.memory_map.borrow_mut();
                memory_map.remove(&heap.base);
                if address > heap.base {
                    memory_map.insert(
                        heap.base,
                        MemoryMap::new(heap.base, address - heap.base, heap.prot),
                    );
                }
            }
        }
        self.brk.set(address);
        Ok(address)
    }

    /// Port of unidbg: `AndroidElfLoader.malloc`.
    pub fn malloc_impl(&self, length: usize, runtime: bool) -> Result<MemoryBlock, MemoryError> {
        if runtime {
            return self.mmap_block(length);
        }
        let libc = self.libc.borrow();
        match libc.as_ref() {
            Some(allocator) => {
                let address = allocator.call.call(allocator.malloc, &[length as u64])?;
                let pointer = self.pointer(address).set_size(length as u64);
                Ok(MemoryBlock::Libc {
                    call: Rc::clone(&allocator.call),
                    free: allocator.free,
                    pointer,
                })
            }
            // Before `libc.so` is loaded there is no guest allocator to route
            // through, so the mmap-backed block is the only option.
            None => self.mmap_block(length),
        }
    }

    fn mmap_block(&self, length: usize) -> Result<MemoryBlock, MemoryError> {
        let pointer = self
            .mmap(length, Prot::READ.union(Prot::WRITE))?
            .set_size(align_size(length as u64, self.page_size));
        Ok(MemoryBlock::Mmap {
            memory: self.handle(),
            pointer,
        })
    }

}

impl Memory for Loader {
    fn page_size(&self) -> u64 {
        self.page_size
    }

    fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    fn pointer(&self, address: u64) -> Pointer {
        Pointer::new(self.handle(), address)
    }

    fn read_bytes(&self, address: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.backend
            .borrow()
            .mem_read_into(address, buf)
            .map_err(MemoryError::from)
    }

    fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        self.backend
            .borrow_mut()
            .mem_write(address, data)
            .map_err(MemoryError::from)
    }

    fn mmap(&self, length: usize, prot: Prot) -> Result<Pointer, MemoryError> {
        let aligned = align_size(length as u64, self.page_size);
        let address = self.mmap2(0, aligned as usize, prot, 0, -1, 0)?;
        Ok(self.pointer(address).set_size(aligned))
    }

    fn mmap2(
        &self,
        start: u64,
        length: usize,
        prot: Prot,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<u64, MemoryError> {
        self.mmap2_impl(start, length, prot, flags, fd, offset)
    }

    fn mprotect(&self, address: u64, length: usize, prot: Prot) -> Result<i32, MemoryError> {
        self.mprotect_impl(address, length, prot)
    }

    fn munmap(&self, start: u64, length: usize) -> Result<i32, MemoryError> {
        self.munmap_impl(start, length)
    }

    fn brk(&self, address: u64) -> Result<u64, MemoryError> {
        self.brk_impl(address)
    }

    fn malloc(&self, length: usize, runtime: bool) -> Result<MemoryBlock, MemoryError> {
        self.malloc_impl(length, runtime)
    }

    fn allocate_stack(&self, size: usize) -> Result<Pointer, MemoryError> {
        self.allocate_stack_impl(size)
    }

    fn write_stack_string(&self, value: &str) -> Result<Pointer, MemoryError> {
        self.write_stack_string_impl(value)
    }

    fn write_stack_bytes(&self, data: &[u8]) -> Result<Pointer, MemoryError> {
        self.write_stack_bytes_impl(data)
    }

    fn allocate_thread_index(&self) -> Result<usize, MemoryError> {
        self.allocate_thread_index_impl()
    }

    fn free_thread_index(&self, index: usize) {
        self.free_thread_index_impl(index)
    }

    fn allocate_thread_stack(&self, index: usize) -> Result<Pointer, MemoryError> {
        self.allocate_thread_stack_impl(index)
    }

    fn get_stack_point(&self) -> u64 {
        self.sp.get()
    }

    fn set_stack_point(&self, sp: u64) {
        self.set_stack_point_impl(sp)
    }

    fn get_stack_base(&self) -> u64 {
        self.stack_base.get()
    }

    fn get_stack_size(&self) -> usize {
        self.stack_size.get()
    }

    fn set_errno(&self, errno: i32) {
        self.last_errno.set(errno);
        let address = self.errno_address.get();
        if address != 0 {
            let _ = self.write_bytes(address, &errno.to_le_bytes());
        }
    }

    fn get_last_errno(&self) -> i32 {
        self.last_errno.get()
    }

    fn get_memory_map(&self) -> Vec<MemoryMap> {
        self.regions()
    }

    fn set_mmap_listener(&self, listener: Box<dyn MMapListener>) {
        *self.listener.borrow_mut() = Some(listener);
    }

    fn take_mmap_listener(&self) -> Option<Box<dyn MMapListener>> {
        self.listener.borrow_mut().take()
    }
}
