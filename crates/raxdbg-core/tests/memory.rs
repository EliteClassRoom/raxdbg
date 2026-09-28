//! Memory facade tests (plan P2).
//!
//! The loader is driven through a stand-in backend that keeps a real byte map,
//! so these tests cover unidbg's allocation algorithms and the `Pointer`
//! accessors without dragging the CPU engine in.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use raxdbg_core::alloc::MemoryBlock;
use raxdbg_core::backend::{
    Backend, BackendError, BlockHook, CodeHook, ContextId, EventMemHook, GuestMemory, HookId,
    InterruptHook, MemoryFault, MemoryFaultKind, Prot, ReadHook, RunError, RunOutcome,
    UnmappedKind, WriteHook,
};
use raxdbg_core::memory::{
    HEAP_BASE, MAP_ANONYMOUS, MAP_FIXED, MMAP_BASE, Memory, PAGE_SIZE, STACK_BASE,
    STACK_SIZE_OF_MAIN_PAGE, THREAD_STACK_PAGE, loader::Loader,
};
use raxdbg_core::reg::RegId;

/// A backend that keeps the address space in a `BTreeMap` of byte vectors.
#[derive(Default)]
struct TestBackend {
    regions: BTreeMap<u64, Region>,
    sp: u64,
}

struct Region {
    prot: Prot,
    data: Vec<u8>,
}

impl Region {
    fn end(&self) -> u64 {
        self.data.len() as u64
    }
}

impl TestBackend {
    /// Reads `buf`, ignoring guest permissions (raxdbg's host-side view).
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        for (index, slot) in buf.iter_mut().enumerate() {
            let address = addr + index as u64;
            let Some((base, region)) = self.region_at(address) else {
                return Err(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                });
            };
            *slot = region.data[(address - base) as usize];
        }
        Ok(())
    }

    /// Writes `data`, ignoring guest permissions.
    fn write_raw(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        for (index, byte) in data.iter().enumerate() {
            let address = addr + index as u64;
            let offset = self
                .region_at(address)
                .map(|(base, _)| (base, (address - base) as usize));
            let Some((base, offset)) = offset else {
                return Err(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                });
            };
            self.regions
                .get_mut(&base)
                .expect("just found")
                .data[offset] = *byte;
        }
        Ok(())
    }

    fn map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        if addr % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 || size == 0 {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "misaligned or empty".into(),
            });
        }
        if self
            .regions
            .iter()
            .any(|(base, region)| addr < base + region.end() && addr + size > *base)
        {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "overlaps an existing mapping".into(),
            });
        }
        self.regions.insert(
            addr,
            Region {
                prot: perms,
                data: vec![0u8; size as usize],
            },
        );
        Ok(())
    }

    fn protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        for (base, region) in self.regions.iter_mut() {
            if addr < *base + region.end() && addr + size > *base {
                region.prot = perms;
            }
        }
        Ok(())
    }

    fn unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.regions
            .retain(|base, region| !(addr < base + region.end() && addr + size > *base));
        Ok(())
    }

    fn region_at(&self, addr: u64) -> Option<(u64, &Region)> {
        self.regions
            .iter()
            .find(|(base, region)| addr >= **base && addr < **base + region.end())
            .map(|(base, region)| (*base, region))
    }
}

impl Backend for TestBackend {
    fn on_initialize(&mut self) {}
    fn switch_user_mode(&mut self) {}
    fn enable_vfp(&mut self) {}

    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError> {
        match reg {
            RegId::Sp => Ok(self.sp),
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match reg {
            RegId::Sp => {
                self.sp = value;
                Ok(())
            }
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }

    fn reg_write_vector(&mut self, reg: RegId, _v: [u8; 16]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }

    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; size];
        self.mem_read_into(addr, &mut buf)?;
        Ok(buf)
    }

    fn mem_read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), BackendError> {
        self.read_raw(addr, buf).map_err(BackendError::Memory)
    }

    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError> {
        self.write_raw(addr, bytes).map_err(BackendError::Memory)
    }

    fn mem_map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::map(self, addr, size, perms)
    }

    fn mem_protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::protect(self, addr, size, perms)
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        TestBackend::unmap(self, addr, size)
    }

    fn hook_add_code(&mut self, _cb: Box<dyn CodeHook>, _begin: u64, _end: u64) -> HookId {
        0
    }
    fn hook_add_block(&mut self, _cb: Box<dyn BlockHook>, _begin: u64, _end: u64) -> HookId {
        0
    }
    fn hook_add_read(&mut self, _cb: Box<dyn ReadHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_write(&mut self, _cb: Box<dyn WriteHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_event_mem(&mut self, _cb: Box<dyn EventMemHook>, _kind: UnmappedKind) -> HookId {
        0
    }
    fn hook_add_interrupt(&mut self, _cb: Box<dyn InterruptHook>) -> HookId {
        0
    }
    fn hook_del(&mut self, _id: HookId) {}

    fn emu_start(
        &mut self,
        _begin: u64,
        _until: u64,
        _timeout_us: u64,
        _count: u64,
    ) -> Result<RunOutcome, RunError> {
        Ok(RunOutcome::Stopped)
    }
    fn emu_stop(&mut self) {}
    fn set_pending_error(&mut self, _error: RunError) {}
    fn take_pending_error(&mut self) -> Option<RunError> {
        None
    }
    fn is_running(&self) -> bool {
        false
    }
    fn context_save(&mut self) -> ContextId {
        0
    }
    fn context_restore(&mut self, _id: ContextId) {}
    fn context_free(&mut self, _id: ContextId) {}
    fn page_size(&self) -> usize {
        PAGE_SIZE as usize
    }
    fn remove_jit_code_cache(&mut self, _begin: u64, _end: u64) {}
}

/// A loader over a stand-in backend, plus the backend for assertions.
///
/// The backend is a `Backend` for the loader's register access and an
/// `Arc<Mutex<..>>` shared with the `GuestMemory` handle, exactly the split
/// `RaxBackend` uses.
fn loader() -> (Rc<Loader>, Arc<parking_lot::Mutex<TestBackend>>) {
    let space = Arc::new(parking_lot::Mutex::new(TestBackend::default()));
    let guest: Arc<dyn GuestMemory> = Arc::new(TestMemory(Arc::clone(&space)));
    let backend: Rc<RefCell<dyn Backend>> = Rc::new(RefCell::new(SharedBackend(Arc::clone(&space))));
    (Loader::new(backend, guest, 8), space)
}

/// The `Backend` half: every memory call goes to the shared space.
struct SharedBackend(Arc<parking_lot::Mutex<TestBackend>>);

impl Backend for SharedBackend {
    fn on_initialize(&mut self) {}
    fn switch_user_mode(&mut self) {}
    fn enable_vfp(&mut self) {}
    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError> {
        self.0.lock().reg_read(reg)
    }
    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        self.0.lock().reg_write(reg, value)
    }
    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }
    fn reg_write_vector(&mut self, reg: RegId, _v: [u8; 16]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }
    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; size];
        self.mem_read_into(addr, &mut buf)?;
        Ok(buf)
    }
    fn mem_read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), BackendError> {
        self.0.lock().read_raw(addr, buf).map_err(BackendError::Memory)
    }
    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError> {
        self.0.lock().write_raw(addr, bytes).map_err(BackendError::Memory)
    }
    fn mem_map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::map(&mut self.0.lock(), addr, size, perms)
    }
    fn mem_protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::protect(&mut self.0.lock(), addr, size, perms)
    }
    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        TestBackend::unmap(&mut self.0.lock(), addr, size)
    }
    fn hook_add_code(&mut self, _cb: Box<dyn CodeHook>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_block(&mut self, _cb: Box<dyn BlockHook>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_read(&mut self, _cb: Box<dyn ReadHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_write(&mut self, _cb: Box<dyn WriteHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_event_mem(&mut self, _cb: Box<dyn EventMemHook>, _k: UnmappedKind) -> HookId {
        0
    }
    fn hook_add_interrupt(&mut self, _cb: Box<dyn InterruptHook>) -> HookId {
        0
    }
    fn hook_del(&mut self, _id: HookId) {}
    fn emu_start(
        &mut self,
        _b: u64,
        _u: u64,
        _t: u64,
        _c: u64,
    ) -> Result<RunOutcome, RunError> {
        Ok(RunOutcome::Stopped)
    }
    fn emu_stop(&mut self) {}
    fn set_pending_error(&mut self, _error: RunError) {}
    fn take_pending_error(&mut self) -> Option<RunError> {
        None
    }
    fn is_running(&self) -> bool {
        false
    }
    fn context_save(&mut self) -> ContextId {
        0
    }
    fn context_restore(&mut self, _id: ContextId) {}
    fn context_free(&mut self, _id: ContextId) {}
    fn page_size(&self) -> usize {
        PAGE_SIZE as usize
    }
    fn remove_jit_code_cache(&mut self, _b: u64, _e: u64) {}
}

/// The address-space half of the test backend, shared with the loader the way
/// `RaxBackend::guest_memory` shares rax's.
struct TestMemory(Arc<parking_lot::Mutex<TestBackend>>);

impl GuestMemory for TestMemory {
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        self.0.lock().read_raw(addr, buf)
    }
    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        self.0.lock().write_raw(addr, data)
    }
    fn map(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::map(&mut self.0.lock(), addr, size, perms)
    }
    fn protect(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        TestBackend::protect(&mut self.0.lock(), addr, size, perms)
    }
    fn unmap(&self, addr: u64, size: u64) -> Result<(), BackendError> {
        TestBackend::unmap(&mut self.0.lock(), addr, size)
    }
}

#[test]
fn mmap_starts_at_the_mmap_base() {
    let (loader, _) = loader();
    let pointer = loader.mmap(0x1000, Prot::READ.union(Prot::WRITE)).unwrap();
    assert_eq!(pointer.peer(), MMAP_BASE);
    assert_eq!(pointer.get_size(), 0x1000);
}

#[test]
fn allocate_map_address_fills_the_first_gap() {
    let (loader, _) = loader();
    loader
        .mmap2(0x1000_0000, 0x1000, Prot::READ, MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        .unwrap();
    loader
        .mmap2(0x1000_4000, 0x1000, Prot::READ, MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        .unwrap();
    // The gap between the two regions holds one more page.
    assert_eq!(loader.allocate_map_address(0, 0x1000), 0x1000_1000);
    // A larger request cannot fit in the gap, so the cursor is pulled down to
    // just past the last region (unidbg's `allocateMapAddress` does the same)
    // and the request is served there.
    assert_eq!(loader.allocate_map_address(0, 0x8000), 0x1000_5000);
}

#[test]
fn mmap2_bumps_the_cursor_and_records_regions() {
    let (loader, _) = loader();
    let first = loader.mmap2(0, 0x2000, Prot::READ, 0, -1, 0).unwrap();
    let second = loader.mmap2(0, 0x1000, Prot::READ, 0, -1, 0).unwrap();
    assert_eq!(first, MMAP_BASE);
    assert_eq!(second, MMAP_BASE + 0x2000);
    let regions = loader.get_memory_map();
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].base, MMAP_BASE);
    assert_eq!(regions[0].size, 0x2000);
}

#[test]
fn munmap_from_the_middle_splits_the_region() {
    let (loader, _) = loader();
    let base = 0x3000_0000;
    loader
        .mmap2(base, 0x3000, Prot::READ, MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        .unwrap();
    loader.munmap(base + 0x1000, 0x1000).unwrap();
    let regions = loader.get_memory_map();
    assert_eq!(regions.len(), 2);
    assert_eq!((regions[0].base, regions[0].size), (base, 0x1000));
    assert_eq!((regions[1].base, regions[1].size), (base + 0x2000, 0x1000));
}

#[test]
fn munmap_of_the_whole_region_drops_it_and_resets_the_cursor() {
    let (loader, _) = loader();
    loader.mmap(0x1000, Prot::READ).unwrap();
    assert!(loader.mmap_base_address() > MMAP_BASE);
    loader.munmap(MMAP_BASE, 0x1000).unwrap();
    assert!(loader.get_memory_map().is_empty());
    assert_eq!(loader.mmap_base_address(), MMAP_BASE);
}

#[test]
fn mprotect_splits_the_region_tree() {
    let (loader, backend) = loader();
    let base = 0x4000_0000;
    loader
        .mmap2(base, 0x3000, Prot::READ, MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        .unwrap();
    loader.mprotect(base + 0x1000, 0x1000, Prot::READ).unwrap();
    let regions = loader.get_memory_map();
    assert_eq!(regions.len(), 3);
    assert_eq!(regions[0].prot, Prot::READ);
    assert_eq!(regions[2].prot, Prot::READ);
    // A host write still reaches the page, as it does through unidbg's unicorn
    // host API; the guest's own store is what the protection stops, which the
    // backend suite covers.
    assert_eq!(regions[1].prot, Prot::READ);
    loader
        .write_bytes(base + 0x1000, &[1])
        .expect("a host write ignores guest permissions");
}

#[test]
fn mprotect_rejects_a_misaligned_address() {
    let (loader, _) = loader();
    loader.mmap(0x1000, Prot::READ).unwrap();
    assert_eq!(loader.mprotect(MMAP_BASE + 1, 0x1000, Prot::READ).unwrap(), -1);
    assert_eq!(loader.get_last_errno(), raxdbg_core::errno::EINVAL);
}

#[test]
fn mmap_fixed_over_an_existing_mapping_replaces_it() {
    let (loader, _) = loader();
    let base = 0x5000_0000;
    loader
        .mmap2(base, 0x2000, Prot::READ, MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        .unwrap();
    loader
        .mmap2(
            base,
            0x1000,
            Prot::READ.union(Prot::WRITE),
            MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let regions = loader.get_memory_map();
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].prot, Prot::READ.union(Prot::WRITE));
    assert_eq!(regions[0].size, 0x1000);
}

#[test]
fn brk_grows_and_shrinks_the_heap() {
    let (loader, _) = loader();
    assert_eq!(loader.brk(0).unwrap(), HEAP_BASE);
    assert_eq!(loader.brk(HEAP_BASE + 0x2000).unwrap(), HEAP_BASE + 0x2000);
    assert_eq!(loader.region_at(HEAP_BASE).map(|map| map.size), Some(0x2000));
    assert_eq!(loader.brk(HEAP_BASE + 0x1000).unwrap(), HEAP_BASE + 0x1000);
    assert_eq!(loader.region_at(HEAP_BASE).map(|map| map.size), Some(0x1000));
    assert_eq!(loader.brk(HEAP_BASE).unwrap(), HEAP_BASE);
    assert!(loader.region_at(HEAP_BASE).is_none());
}

#[test]
fn brk_rejects_a_misaligned_address() {
    let (loader, _) = loader();
    assert!(loader.brk(HEAP_BASE + 1).is_err());
}

#[test]
fn pointer_round_trips_every_typed_access() {
    let (loader, _) = loader();
    let pointer = loader.mmap(0x10_0000, Prot::READ.union(Prot::WRITE)).unwrap();

    pointer.write_byte(0, 0xab).unwrap();
    assert_eq!(pointer.read_byte(0).unwrap(), 0xab);
    pointer.write_u16(2, 0x1234).unwrap();
    assert_eq!(pointer.read_u16(2).unwrap(), 0x1234);
    pointer.write_u32(4, 0xdead_beef).unwrap();
    assert_eq!(pointer.read_u32(4).unwrap(), 0xdead_beef);
    pointer.write_u64(8, 0x0102_0304_0506_0708).unwrap();
    assert_eq!(pointer.read_u64(8).unwrap(), 0x0102_0304_0506_0708);

    pointer.write_pointer(16, 0x1234_5678_9abc).unwrap();
    assert_eq!(pointer.read_pointer(16).unwrap(), 0x1234_5678_9abc);

    pointer.set_string(32, "hello").unwrap();
    assert_eq!(pointer.get_string(32).unwrap(), "hello");
    assert_eq!(pointer.get_c_string(32).unwrap(), b"hello");

    pointer.set_wide_string(64, "wide").unwrap();
    assert_eq!(pointer.get_wide_string(64).unwrap(), "wide");

    pointer.write_int_array(96, &[1, 2, 3]).unwrap();
    assert_eq!(pointer.get_int_array(96, 3).unwrap(), vec![1, 2, 3]);
    pointer.write_long_array(128, &[4, 5]).unwrap();
    assert_eq!(pointer.get_long_array(128, 2).unwrap(), vec![4, 5]);

    pointer.set_memory(160, 4, 0x7f).unwrap();
    assert_eq!(pointer.get_bytes(160, 4).unwrap(), vec![0x7f; 4]);

    let shared = pointer.share(0x1000, 0x10);
    assert_eq!(shared.peer(), pointer.peer() + 0x1000);
    assert_eq!(shared.get_size(), 0x10);
}

#[test]
fn pointer_reads_outside_the_mapping_fail() {
    let (loader, _) = loader();
    let pointer = loader.mmap(0x1000, Prot::READ).unwrap();
    let beyond = pointer.share(0x1000, 1);
    assert!(beyond.read_byte(0).is_err());
}

#[test]
fn stack_allocation_moves_the_stack_pointer_and_the_guest_register() {
    let (loader, backend) = loader();
    // unidbg maps the stack area in `initializeTLS`; the loader only moves SP.
    loader
        .mmap2(
            STACK_BASE - 0x10000,
            0x10000,
            Prot::READ.union(Prot::WRITE),
            MAP_FIXED | MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    loader.set_stack_point(STACK_BASE);
    assert_eq!(loader.get_stack_base(), STACK_BASE);
    assert_eq!(backend.lock().sp, STACK_BASE);

    let pointer = loader.allocate_stack(0x100).unwrap();
    assert_eq!(pointer.peer(), STACK_BASE - 0x100);
    assert_eq!(loader.get_stack_point(), STACK_BASE - 0x100);
    assert_eq!(backend.lock().sp, STACK_BASE - 0x100);

    let string = loader.write_stack_string("abc").unwrap();
    assert_eq!(string.peer(), STACK_BASE - 0x100 - 4);
    assert_eq!(string.get_size(), 4);
}

#[test]
fn stack_allocation_fails_before_it_reaches_the_thread_area() {
    let (loader, _) = loader();
    let limit = STACK_BASE - STACK_SIZE_OF_MAIN_PAGE * PAGE_SIZE;
    loader.set_stack_point(limit + 0x10);
    assert!(loader.allocate_stack(0x20).is_err());
}

#[test]
fn thread_indices_are_recycled() {
    let (loader, _) = loader();
    let first = loader.allocate_thread_index().unwrap();
    let second = loader.allocate_thread_index().unwrap();
    assert_ne!(first, second);
    loader.free_thread_index(first);
    assert_eq!(loader.allocate_thread_index().unwrap(), first);

    // A stack is only handed out for a live index.
    assert!(loader.allocate_thread_stack(second).is_ok());
    loader.free_thread_index(second);
    assert!(loader.allocate_thread_stack(second).is_err());
}

#[test]
fn thread_stacks_sit_below_the_main_stack() {
    let (loader, _) = loader();
    let index = loader.allocate_thread_index().unwrap();
    let stack = loader.allocate_thread_stack(index).unwrap();
    let base = STACK_BASE - STACK_SIZE_OF_MAIN_PAGE * PAGE_SIZE;
    assert_eq!(stack.peer(), base - THREAD_STACK_PAGE * index as u64 * PAGE_SIZE);
}

#[test]
fn runtime_malloc_returns_an_mmap_block_that_frees() {
    let (loader, _) = loader();
    let block = loader.malloc(1024, true).unwrap();
    let address = block.pointer().peer();
    assert_eq!(block.pointer().get_size(), PAGE_SIZE);
    assert!(loader.region_at(address).is_some());
    block.free().unwrap();
    assert!(loader.region_at(address).is_none());
}

#[test]
fn malloc_without_a_libc_allocator_falls_back_to_mmap() {
    let (loader, _) = loader();
    let block = loader.malloc(64, false).unwrap();
    assert!(matches!(block, MemoryBlock::Mmap { .. }));
    block.free().unwrap();
}

#[test]
fn errno_is_written_to_the_guest_slot() {
    let (loader, _) = loader();
    let pointer = loader.mmap(0x1000, Prot::READ.union(Prot::WRITE)).unwrap();
    loader.set_errno_address(pointer.peer());
    loader.set_errno(raxdbg_core::errno::ENOENT);
    assert_eq!(loader.get_last_errno(), raxdbg_core::errno::ENOENT);
    assert_eq!(pointer.read_u32(0).unwrap(), raxdbg_core::errno::ENOENT as u32);
}

#[test]
fn aligned_sizes_round_up() {
    use raxdbg_core::memory::loader::align_size;
    assert_eq!(align_size(0, 0x1000), 0);
    assert_eq!(align_size(1, 0x1000), 0x1000);
    assert_eq!(align_size(0x1000, 0x1000), 0x1000);
    assert_eq!(align_size(0x1001, 0x1000), 0x2000);
}

// ---------------------------------------------------------------------------
// Allocation tracking
// ---------------------------------------------------------------------------

#[test]
fn tracker_records_mappings_and_forgets_unmappings() {
    use raxdbg_core::alloc::MemoryTracker;

    let (loader, _) = loader();
    let tracker = Rc::new(MemoryTracker::new());
    MemoryTracker::install(&tracker, &*loader);

    let block = loader.malloc(0x2000, true).unwrap();
    let address = block.pointer().peer();
    let records = tracker.allocations();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].address, address);
    assert_eq!(records[0].size, 0x2000);
    assert_eq!(tracker.total_allocations(), 1);

    block.free().unwrap();
    assert!(tracker.allocations().is_empty());
    assert_eq!(tracker.total_deallocations(), 1);

    let mut out = Vec::new();
    loader.malloc(0x1000, true).unwrap();
    assert_eq!(tracker.write_leaks(&mut out).unwrap(), 1);
    assert!(String::from_utf8(out).unwrap().contains("size=0x1000"));
}

#[test]
fn tracker_chains_to_the_listener_it_replaced() {
    use std::cell::Cell;
    use raxdbg_core::memory::MMapListener;

    struct Counter(Rc<Cell<u32>>);
    impl MMapListener for Counter {
        fn on_map(&self, _address: u64, _size: u64, _prot: Prot) {
            self.0.set(self.0.get() + 1);
        }
        fn on_protect(&self, _address: u64, _size: u64, prot: Prot) -> Prot {
            prot
        }
        fn on_unmap(&self, _address: u64, _size: u64) {}
    }

    let (loader, _) = loader();
    let seen = Rc::new(Cell::new(0));
    loader.set_mmap_listener(Box::new(Counter(seen.clone())));
    let tracker = Rc::new(raxdbg_core::alloc::MemoryTracker::new());
    raxdbg_core::alloc::MemoryTracker::install(&tracker, &*loader);

    loader.malloc(0x1000, true).unwrap();
    assert_eq!(seen.get(), 1, "the replaced listener still sees the mapping");
    assert_eq!(tracker.allocations().len(), 1);
}
