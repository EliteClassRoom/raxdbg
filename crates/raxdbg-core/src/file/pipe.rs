//! A bounded pipe pair — `pipe(2)` over a shared ring buffer.
//!
//! Port of unidbg:
//!
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/PipedReadFileIO.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/PipedWriteFileIO.java`
//! @7f5da98e.
//!
//! unidbg pipes the bytes between a `PipedInputStream` and a `PipedOutputStream`.
//! raxdbg's syscall layer drives waiting, so reads on an empty pipe return
//! `-EAGAIN` instead of blocking. We use a single ring buffer wrapped behind
//! two `FileIO`s; the `default capacity` (64 KiB) matches the typical Linux
//! pipe default of 16 pages.

use std::any::Any;
use std::collections::VecDeque;

use std::sync::Arc;

use parking_lot::Mutex;

use crate::errno::{EAGAIN, EBADF, EINVAL, EPIPE};
use crate::file::structs::{IOConstants, Stat};
use crate::file::FileIO;
use crate::memory::Memory;
/// The default capacity for a pipe (16 pages of 4 KiB).
pub const DEFAULT_PIPE_CAPACITY: usize = 64 * 1024;

/// The shared state between a pipe's read and write ends.
#[derive(Debug)]
struct PipeShared {
    /// Bytes that have been written and not yet consumed.
    buffer: VecDeque<u8>,
    /// The pipe's capacity; writes past this length fail with `-EAGAIN`.
    capacity: usize,
    /// The write end is closed (read returns 0 once drained).
    write_closed: bool,
    /// The read end is closed (write returns `-EPIPE`).
    read_closed: bool,
}

impl PipeShared {
    fn new(capacity: usize) -> Self {
        PipeShared {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            write_closed: false,
            read_closed: false,
        }
    }
}

/// One end of a pipe. The two halves share a `PipeShared` and a flag set
/// describing whether they expose the read or write side of the pipe.
struct PipeEnd {
    shared: Arc<Mutex<PipeShared>>,
    is_read: bool,
    path: String,
}

impl std::fmt::Debug for PipeEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeEnd")
            .field("path", &self.path)
            .field("is_read", &self.is_read)
            .finish()
    }
}

/// Returns `(read_end, write_end)` over a single shared buffer with the
/// default capacity.
pub fn pipe_pair() -> (Box<dyn FileIO>, Box<dyn FileIO>) {
    pipe_pair_with_capacity(DEFAULT_PIPE_CAPACITY)
}

/// Same as [`pipe_pair`] but with a custom capacity.
pub fn pipe_pair_with_capacity(capacity: usize) -> (Box<dyn FileIO>, Box<dyn FileIO>) {
    let shared = Arc::new(Mutex::new(PipeShared::new(capacity)));
    let read = Box::new(PipeEnd {
        shared: shared.clone(),
        is_read: true,
        path: "pipe[r]".to_string(),
    });
    let write = Box::new(PipeEnd {
        shared,
        is_read: false,
        path: "pipe[w]".to_string(),
    });
    (read, write)
}

impl FileIO for PipeEnd {
    fn close(&mut self) {
        let mut shared = self.shared.lock();
        if self.is_read {
            shared.read_closed = true;
        } else {
            shared.write_closed = true;
        }
    }

    fn write(&mut self, data: &[u8]) -> i32 {
        if self.is_read {
            return -EBADF;
        }
        let mut shared = self.shared.lock();
        if shared.read_closed {
            return -EPIPE;
        }
        let available = shared.capacity.saturating_sub(shared.buffer.len());
        if available == 0 {
            // raxdbg's syscall layer drives waiting, so a full pipe returns
            // `-EAGAIN` instead of blocking; callers can retry later.
            return -EAGAIN;
        }
        let n = data.len().min(available);
        shared.buffer.extend(&data[..n]);
        n as i32
    }

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        if !self.is_read {
            return -EBADF;
        }
        let mut shared = self.shared.lock();
        if shared.buffer.is_empty() {
            // The write end may still be open; we always return `-EAGAIN` so
            // the syscall layer can park the task when blocking is requested.
            return -EAGAIN;
        }
        let n = count.min(shared.buffer.len());
        let chunk: Vec<u8> = shared.buffer.drain(..n).collect();
        if memory.write_bytes(buffer, &chunk).is_err() {
            return -EINVAL;
        }
        n as i32
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        // Pipes are not seekable; returning `-EINVAL` matches what the Linux
        // kernel hands back for `lseek` on a FIFO.
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFIFO | 0o600;
        stat.st_nlink = 1;
        stat.st_size = 0;
        stat.st_blksize = 4096;
        0
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small in-memory `Memory` implementation good enough for the pipe
    /// tests. It just collects the bytes the descriptor writes into a `Vec`
    /// so the test can assert on them.
    #[derive(Default)]
    struct SinkMemory {
        bytes: Mutex<Vec<u8>>,
    }

    impl crate::memory::Memory for SinkMemory {
        fn page_size(&self) -> u64 {
            4096
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn pointer(&self, _address: u64) -> crate::pointer::Pointer {
            unimplemented!("pipe tests do not need pointers")
        }
        fn read_bytes(&self, _address: u64, _buf: &mut [u8]) -> Result<(), crate::memory::MemoryError> {
            Ok(())
        }
        fn write_bytes(&self, _address: u64, data: &[u8]) -> Result<(), crate::memory::MemoryError> {
            self.bytes.lock().extend_from_slice(data);
            Ok(())
        }
        fn mmap(&self, _length: usize, _prot: crate::backend::Prot) -> Result<crate::pointer::Pointer, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn mmap2(
            &self,
            _start: u64,
            _length: usize,
            _prot: crate::backend::Prot,
            _flags: i32,
            _fd: i32,
            _offset: i64,
        ) -> Result<u64, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn mprotect(&self, _address: u64, _length: usize, _prot: crate::backend::Prot) -> Result<i32, crate::memory::MemoryError> {
            Ok(0)
        }
        fn munmap(&self, _start: u64, _length: usize) -> Result<i32, crate::memory::MemoryError> {
            Ok(0)
        }
        fn brk(&self, _address: u64) -> Result<u64, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn malloc(
            &self,
            _length: usize,
            _runtime: bool,
        ) -> Result<crate::alloc::MemoryBlock, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn allocate_stack(&self, _size: usize) -> Result<crate::pointer::Pointer, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn write_stack_string(&self, _value: &str) -> Result<crate::pointer::Pointer, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn write_stack_bytes(&self, _data: &[u8]) -> Result<crate::pointer::Pointer, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn allocate_thread_index(&self) -> Result<usize, crate::memory::MemoryError> {
            Ok(0)
        }
        fn free_thread_index(&self, _index: usize) {}
        fn allocate_thread_stack(&self, _index: usize) -> Result<crate::pointer::Pointer, crate::memory::MemoryError> {
            unimplemented!()
        }
        fn get_stack_point(&self) -> u64 {
            0
        }
        fn set_stack_point(&self, _sp: u64) {}
        fn get_stack_base(&self) -> u64 {
            0
        }
        fn get_stack_size(&self) -> usize {
            0
        }
        fn set_errno(&self, _errno: i32) {}
        fn get_last_errno(&self) -> i32 {
            0
        }
        fn get_memory_map(&self) -> Vec<crate::memory::MemoryMap> {
            Vec::new()
        }
        fn set_mmap_listener(&self, _listener: Box<dyn crate::memory::MMapListener>) {}
        fn take_mmap_listener(&self) -> Option<Box<dyn crate::memory::MMapListener>> {
            None
        }
    }

    #[test]
    fn pipe_write_then_read_returns_bytes() {
        let (mut reader, mut writer) = pipe_pair();
        assert_eq!(writer.write(b"hello"), 5);
        let memory = SinkMemory::default();
        assert_eq!(reader.read(&memory, 0, 5), 5);
        assert_eq!(&memory.bytes.lock()[..], b"hello");
    }

    #[test]
    fn empty_pipe_read_returns_again() {
        let (mut reader, _writer) = pipe_pair();
        let memory = SinkMemory::default();
        assert_eq!(reader.read(&memory, 0, 4), -EAGAIN);
    }

    #[test]
    fn full_pipe_write_returns_again() {
        let (_reader, mut writer) = pipe_pair_with_capacity(4);
        assert_eq!(writer.write(b"abcd"), 4);
        // The pipe is now full; the next write must surface `-EAGAIN`.
        assert_eq!(writer.write(b"e"), -EAGAIN);
    }

    #[test]
    fn write_after_read_end_closed_returns_pipe() {
        let (mut reader, mut writer) = pipe_pair();
        reader.close();
        assert_eq!(writer.write(b"data"), -EPIPE);
    }
}
