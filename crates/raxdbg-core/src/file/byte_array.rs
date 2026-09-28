//! An in-memory guest file descriptor over a `Vec<u8>`.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/file/ByteArrayFileIO.java`
//! @7f5da98e. unidbg's class is the workhorse for paths that come straight out
//! of a resource (the bundled `__properties__` blob, `/proc/self/maps`,
//! in-memory `lib*.so` snapshots, ...); the cursor is implicit in the position
//! field and the host bytes are owned by the descriptor.

use std::any::Any;

use crate::backend::Prot;
use crate::errno::EINVAL;
use crate::file::structs::{IOConstants, Stat};
use crate::file::FileIO;
use crate::memory::Memory;

/// An in-memory `Vec<u8>` file, exactly the shape unidbg's `ByteArrayFileIO` takes.
#[derive(Debug)]
pub struct ByteArrayFileIO {
    /// The flags the descriptor was opened with. Kept for parity with
    /// unidbg's constructor; a `ByteArrayFileIO` does not currently use them
    /// because it is always read-only (a writable variant would route
    /// through a different descriptor type).
    #[allow(dead_code)]
    oflags: i32,
    path: String,
    bytes: Vec<u8>,
    pos: usize,
}

impl ByteArrayFileIO {
    /// Builds an in-memory file at `path` from `bytes`.
    pub fn new(oflags: i32, path: impl Into<String>, bytes: Vec<u8>) -> Self {
        ByteArrayFileIO {
            oflags,
            path: path.into(),
            bytes,
            pos: 0,
        }
    }

    /// Borrows the buffer the descriptor owns.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl FileIO for ByteArrayFileIO {
    fn close(&mut self) {
        self.pos = 0;
    }

    fn write(&mut self, _data: &[u8]) -> i32 {
        // Mirrors `ByteArrayFileIO.write` throwing `UnsupportedOperationException`.
        -EINVAL
    }

    fn pread(
        &mut self,
        memory: &dyn Memory,
        buffer: u64,
        count: usize,
        offset: u64,
    ) -> i32 {
        // unidbg's `ByteArrayFileIO.pread` saves and restores `pos` so a
        // concurrent `read` does not move the cursor.
        let saved = self.pos;
        self.pos = offset as usize;
        let ret = self.read(memory, buffer, count);
        self.pos = saved;
        ret
    }

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        if self.pos >= self.bytes.len() {
            return 0;
        }
        let remaining = self.bytes.len() - self.pos;
        let n = count.min(remaining);
        if memory
            .write_bytes(buffer, &self.bytes[self.pos..self.pos + n])
            .is_err()
        {
            return -EINVAL;
        }
        self.pos += n;
        n as i32
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> i64 {
        let len = self.bytes.len() as i64;
        // unidbg returns the absolute `pos`; bad `whence` falls back to
        // `EINVAL`. `SEEK_SET`/`SEEK_CUR`/`SEEK_END` match the values the
        // kernel uses (and that `IOConstants` exposes).
        match whence {
            IOConstants::SEEK_SET => {
                self.pos = offset as usize;
                self.pos as i64
            }
            IOConstants::SEEK_CUR => {
                self.pos = (self.pos as i64 + offset) as usize;
                self.pos as i64
            }
            IOConstants::SEEK_END => {
                self.pos = (len + offset) as usize;
                self.pos as i64
            }
            _ => -EINVAL as i64,
        }
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        let page_size = 4096u64;
        let size = self.bytes.len() as i64;
        stat.st_dev = 1;
        stat.st_mode = IOConstants::S_IFREG | 0o644;
        stat.st_nlink = 1;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = size;
        stat.st_blksize = page_size as u32;
        stat.st_blocks = (size + page_size as i64 - 1) / page_size as i64;
        stat.st_ino = 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        stat.st_atim.tv_sec = now;
        stat.st_mtim.tv_sec = now;
        stat.st_ctim.tv_sec = now;
        0
    }

    fn mmap2(
        &mut self,
        memory: &dyn Memory,
        addr: u64,
        aligned: u64,
        _prot: Prot,
        offset: i64,
        length: usize,
    ) -> Result<u64, crate::memory::MemoryError> {
        // unidbg's `BaseAndroidFileIO.mmap2` asks the descriptor for the bytes
        // to copy at `[addr, addr + length)`; for an offset/length match we
        // hand back the original slice, otherwise a copy.
        let offset = offset.max(0) as usize;
        let upper = (offset + length).min(self.bytes.len());
        let slice = &self.bytes[offset..upper];
        let _ = aligned;
        memory.write_bytes(addr, slice)?;
        Ok(addr)
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

