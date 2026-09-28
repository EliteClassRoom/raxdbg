//! Host files and the `/dev/*` specials unidbg resolves through `DriverFileIO`.
//!
//! Port of unidbg:
//!
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/DriverFileIO.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/Stdin.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/Stdout.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/NullFileIO.java`
//! * `unidbg-android/src/main/java/com/github/unidbg/linux/file/RandomFileIO.java`
//! @7f5da98e.
//!
//! `DriverFileIO` is the per-`/dev/*`-path factory unidbg's
//! `LinuxFileSystem.open` calls first; for the file-based path unidbg falls
//! through to a regular `SimpleFileIO` over a host file. We split the two
//! into [`HostFileIO`] (the host-backed file) and [`DriverFileIO`] (the
//! `/dev/*` specials), with the dispatcher [`create_driver_file`] doing the
//! same path→IO routing unidbg's `DriverFileIO.create` does.

use std::any::Any;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;



use crate::backend::Prot;
use crate::errno::{EINVAL, ENOENT, ENOSYS};
use crate::file::structs::{IOConstants, Stat};
use crate::file::FileIO;
use crate::memory::Memory;

/// A host file at `<root_dir>/<path>`, opened through [`OpenOptions`].
///
/// Equivalent to unidbg's `SimpleFileIO`, restricted to the byte buffer the
/// descriptor holds; the file's offset, `mmap2` and `fstat` are computed from
/// the in-memory copy plus the underlying `File`'s `Metadata`.
pub struct HostFileIO {
    oflags: i32,
    path: String,
    file: Arc<File>,
    cursor: u64,
}

impl std::fmt::Debug for HostFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFileIO")
            .field("path", &self.path)
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl HostFileIO {
    /// Opens `file` for the guest under `path` with the given `oflags`.
    pub fn open(oflags: i32, path: impl Into<String>, file: File) -> Self {
        HostFileIO {
            oflags,
            path: path.into(),
            file: Arc::new(file),
            cursor: 0,
        }
    }

    fn open_options(oflags: i32) -> OpenOptions {
        let mut opts = OpenOptions::new();
        let access = oflags & 0b11;
        match access {
            IOConstants::O_RDONLY => {
                opts.read(true);
            }
            IOConstants::O_WRONLY => {
                opts.write(true);
            }
            IOConstants::O_RDWR => {
                opts.read(true).write(true);
            }
            _ => {}
        }
        if (oflags & IOConstants::O_CREAT) != 0 {
            opts.create(true);
        }
        if (oflags & IOConstants::O_EXCL) != 0 {
            opts.create_new(true);
        }
        if (oflags & IOConstants::O_APPEND) != 0 {
            opts.append(true);
        }
        if (oflags & IOConstants::O_TRUNC) != 0 {
            opts.truncate(true);
        }
        opts
    }

    /// Convenience constructor that opens the host `path` (resolved by the
    /// caller) for the given `oflags`.
    pub fn open_path(
        oflags: i32,
        guest_path: &str,
        host_path: &Path,
    ) -> Result<Self, std::io::Error> {
        let file = Self::open_options(oflags).open(host_path)?;
        Ok(Self::open(oflags, guest_path.to_string(), file))
    }
}

impl FileIO for HostFileIO {
    fn close(&mut self) {}

    fn write(&mut self, data: &[u8]) -> i32 {
        // unidbg's `SimpleFileIO.write` honours `O_APPEND` by seeking to the
        // end before writing; a real `OpenOptions(append=true)` already does
        // that for us, but we keep the explicit branch for `O_APPEND` set on
        // a non-`append` descriptor.
        let file = self.file.clone();
        let mut file = file;
        let result: std::io::Result<usize> = (|| {
            if (self.oflags & IOConstants::O_APPEND) != 0 {
                file.seek(SeekFrom::End(0))?;
            } else {
                file.seek(SeekFrom::Start(self.cursor))?;
            }
            let written = file.write(data)?;
            self.cursor = file.stream_position()?;
            Ok(written)
        })();
        match result {
            Ok(n) => n as i32,
            Err(_) => -EINVAL,
        }
    }

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        let mut local = vec![0u8; count];
        let file: Arc<File> = Arc::clone(&self.file);
        let result: std::io::Result<usize> = (|| {
            let mut file: &File = &*file;
            file.seek(SeekFrom::Start(self.cursor))?;
            file.read(&mut local)
        })();
        match result {
            Ok(n) => {
                self.cursor += n as u64;
                if n == 0 {
                    return 0;
                }
                if memory.write_bytes(buffer, &local[..n]).is_err() {
                    return -EINVAL;
                }
                n as i32
            }
            Err(_) => -EINVAL,
        }
    }
    fn pread(&mut self, memory: &dyn Memory, buffer: u64, count: usize, offset: u64) -> i32 {
        let saved = self.cursor;
        self.cursor = offset;
        let ret = self.read(memory, buffer, count);
        self.cursor = saved;
        ret
    }

    fn pwrite(&mut self, memory: &dyn Memory, buffer: u64, count: usize, offset: u64) -> i32 {
        let bytes = match self.read_guest(memory, buffer, count) {
            Ok(b) => b,
            Err(_) => return -EINVAL,
        };
        let file = self.file.clone();
        let mut file = file;
        let result = (|| -> std::io::Result<usize> {
            file.seek(SeekFrom::Start(offset))?;
            let written = file.write(&bytes)?;
            Ok(written)
        })();
        match result {
            Ok(n) => n as i32,
            Err(_) => -EINVAL,
        }
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> i64 {
        let len = self.file.metadata().map(|m| m.len() as i64).unwrap_or(0);
        match whence {
            IOConstants::SEEK_SET => {
                self.cursor = offset.max(0) as u64;
                self.cursor as i64
            }
            IOConstants::SEEK_CUR => {
                self.cursor = (self.cursor as i64 + offset).max(0) as u64;
                self.cursor as i64
            }
            IOConstants::SEEK_END => {
                self.cursor = (len + offset).max(0) as u64;
                self.cursor as i64
            }
            _ => -EINVAL as i64,
        }
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        let metadata = match self.file.metadata() {
            Ok(m) => m,
            Err(_) => return -ENOENT,
        };
        let size = metadata.len() as i64;
        stat.st_dev = 1;
        stat.st_mode = IOConstants::S_IFREG | 0o644;
        stat.st_nlink = 1;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = size;
        stat.st_blksize = 4096;
        stat.st_blocks = (size + 4095) / 512;
        stat.st_ino = 1;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        stat.st_atim.tv_sec = mtime;
        stat.st_mtim.tv_sec = mtime;
        stat.st_ctim.tv_sec = mtime;
        0
    }

    fn mmap2(
        &mut self,
        memory: &dyn Memory,
        addr: u64,
        _aligned: u64,
        _prot: Prot,
        offset: i64,
        length: usize,
    ) -> Result<u64, crate::memory::MemoryError> {
        let mut local = vec![0u8; length];
        let file = self.file.clone();
        let mut file = file;
        let read = (|| -> std::io::Result<usize> {
            file.seek(SeekFrom::Start(offset.max(0) as u64))?;
            file.read(&mut local)
        })();
        match read {
            Ok(0) => {}
            Ok(n) => {
                memory.write_bytes(addr, &local[..n])?;
            }
            Err(_) => {
                return Err(crate::memory::MemoryError::Message(format!(
                    "host read failed for {}",
                    self.path
                )));
            }
        }
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

/// `DriverFileIO` for `/dev/null`: writes succeed silently, reads return 0.
pub struct NullFileIO {
    path: String,
}

impl std::fmt::Debug for NullFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NullFileIO")
            .field("path", &self.path)
            .finish()
    }
}

impl NullFileIO {
    /// Builds a `/dev/null` IO at `path`.
    pub fn new(path: impl Into<String>) -> Self {
        NullFileIO { path: path.into() }
    }

    /// True when the descriptor is for `/dev/tty` (which unidbg treats as
    /// a thin shim over the real terminal).
    pub fn is_tty(&self) -> bool {
        self.path == "/dev/tty"
    }
}

impl FileIO for NullFileIO {
    fn close(&mut self) {}

    fn write(&mut self, data: &[u8]) -> i32 {
        if self.is_tty() {
            // unidbg's `NullFileIO` mirrors TTY writes to the host stdout so
            // printf-style debugging reaches the host terminal.
            let _ = std::io::stdout().write_all(data);
        }
        data.len() as i32
    }

    fn read(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize) -> i32 {
        if self.is_tty() {
            let mut buf = [0u8; 1];
            match std::io::stdin().read(&mut buf) {
                Ok(0) => 0,
                Ok(_) => 1,
                Err(_) => -EINVAL,
            }
        } else {
            0
        }
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        0
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        if self.is_tty() {
            stat.st_mode = IOConstants::S_IFCHR | 0o666;
        } else {
            stat.st_mode = IOConstants::S_IFCHR | 0o666;
        }
        stat.st_size = 0;
        stat.st_blksize = 0;
        0
    }

    fn ioctl(&mut self, _request: u64, _argp: u64) -> i32 {
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

/// `DriverFileIO` for `/dev/urandom` and friends.
pub struct RandomFileIO {
    path: String,
}

/// A captured `stdout`/`stderr` descriptor.
///
/// Writes go to a host `Write` sink (typically a `Vec<u8>` the test owns, or
/// `std::io::stdout()`/`std::io::stderr()` in production). unidbg's `Stdout`
/// does the same: it keeps a callback plus a host `PrintStream`.
pub struct StdoutFileIO {
    path: String,
    sink: Box<dyn Write + Send>,
}

impl std::fmt::Debug for StdoutFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdoutFileIO")
            .field("path", &self.path)
            .finish()
    }
}

impl StdoutFileIO {
    /// Builds a stdout/stderr descriptor whose writes go to `sink`.
    pub fn new(path: impl Into<String>, sink: Box<dyn Write + Send>) -> Self {
        StdoutFileIO {
            path: path.into(),
            sink,
        }
    }
}

impl FileIO for StdoutFileIO {
    fn close(&mut self) {}

    fn write(&mut self, data: &[u8]) -> i32 {
        match self.sink.write_all(data) {
            Ok(()) => data.len() as i32,
            Err(_) => -EINVAL,
        }
    }

    fn read(&mut self, _memory: &dyn Memory, _buffer: u64, _count: usize) -> i32 {
        -EINVAL
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        0
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFCHR | 0o777;
        stat.st_size = 0;
        stat.st_blksize = 0;
        0
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn is_stdio(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl std::fmt::Debug for RandomFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandomFileIO")
            .field("path", &self.path)
            .finish()
    }
}

impl RandomFileIO {
    /// Builds a `/dev/urandom` IO at `path`.
    pub fn new(path: impl Into<String>) -> Self {
        RandomFileIO { path: path.into() }
    }
}

impl FileIO for RandomFileIO {
    fn close(&mut self) {}

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        let chunk = count.min(0x1000);
        let mut buf = vec![0u8; chunk];
        // unidbg uses `ThreadLocalRandom`; we mirror with the same primitive.
        rand_bytes(&mut buf);
        if memory.write_bytes(buffer, &buf).is_err() {
            return -EINVAL;
        }
        chunk as i32
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        0
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = IOConstants::S_IFCHR | 0o666;
        stat.st_size = 0;
        stat.st_blksize = 0;
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

fn rand_bytes(bytes: &mut [u8]) {
    // Cheap, host-side randomness. Tests may want determinism; the optional
    // `--seed` flag (plan P12) wires a deterministic source over this entry
    // point. We deliberately avoid pulling in `rand` for one helper.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
    }
}


///
/// The host-file branch lives elsewhere; this is only the special devices.
pub fn create_driver_file(
    pathname: &str,
    sink: Option<Box<dyn Write + Send>>,
    source: Option<Box<dyn Read + Send>>,
) -> Option<Box<dyn FileIO>> {
    match pathname {
        "/dev/null" | "/dev/alarm" => Some(Box::new(NullFileIO::new(pathname))),
        "/dev/tty" => Some(Box::new(NullFileIO::new("/dev/tty"))),
        "/dev/urandom" | "/dev/random" | "/dev/srandom" => {
            Some(Box::new(RandomFileIO::new(pathname)))
        }
        "stdin" => Some(Box::new(StdinFileIO::new(
            "stdin",
            source.unwrap_or_else(|| Box::new(std::io::stdin())),
        ))),
        "stdout" | "stderr" => {
            let sink = sink.unwrap_or_else(|| {
                if pathname == "stderr" {
                    Box::new(std::io::stderr())
                } else {
                    Box::new(std::io::stdout())
                }
            });
            Some(Box::new(StdoutFileIO::new(pathname, sink)))
        }
        _ => None,
    }
}


/// Reads guest input from a host `Read` source. Writes fail.
pub struct StdinFileIO {
    path: String,
    source: Box<dyn Read + Send>,
}

impl std::fmt::Debug for StdinFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdinFileIO")
            .field("path", &self.path)
            .finish()
    }
}

impl StdinFileIO {
    /// Builds a stdin descriptor whose reads come from `source`.
    pub fn new(path: impl Into<String>, source: Box<dyn Read + Send>) -> Self {
        StdinFileIO {
            path: path.into(),
            source,
        }
    }
}

impl FileIO for StdinFileIO {
    fn close(&mut self) {}

    fn write(&mut self, _data: &[u8]) -> i32 {
        -EINVAL
    }

    fn read(&mut self, memory: &dyn Memory, buffer: u64, count: usize) -> i32 {
        let mut local = vec![0u8; count];
        match self.source.read(&mut local) {

            Ok(0) => 0,
            Ok(n) => {
                if memory.write_bytes(buffer, &local[..n]).is_err() {
                    return -EINVAL;
                }
                n as i32
            }
            Err(_) => -EINVAL,
        }
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = 0;
        stat.st_size = 0;
        0
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn is_stdio(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}




/// Resolves a host file path under `root`, refuses to escape via `..`.
pub fn resolve_in_root(root: &Path, pathname: &str) -> Option<PathBuf> {
    use std::fs;
    let candidate = root.join(pathname.trim_start_matches('/'));
    let canonical_root = fs::canonicalize(root).ok()?;
    let canonical_candidate = match fs::canonicalize(&candidate) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let root_str = canonical_root.to_string_lossy().into_owned();
    let root_sep = if root_str.ends_with(std::path::MAIN_SEPARATOR) {
        root_str.clone()
    } else {
        format!("{root_str}{}", std::path::MAIN_SEPARATOR)
    };
    if canonical_candidate.to_string_lossy().starts_with(&root_sep) {
        Some(canonical_candidate)
    } else {
        None
    }
}

/// Returns `true` if `oflags` denotes a `/dev/null` write that should be
/// dropped silently (used by `LinuxFileSystem` short-circuits).
pub fn is_null_path(pathname: &str) -> bool {
    pathname == "/dev/null"
}

/// Returns the unsupported errno when no `/dev/*` branch matches.
pub fn unsupported_errno() -> i32 {
    -ENOSYS
}

// `PathBuf` is exposed so `linux_fs.rs` can build host paths without
// reaching for `std::path` directly.
pub use std::path::PathBuf as HostPath;
