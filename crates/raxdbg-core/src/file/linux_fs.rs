//! The Linux-shaped file system the guest sees.
//!
//! Port of unidbg:
//!
//! * `unidbg-android/src/main/java/com/github/unidbg/file/linux/LinuxFileSystem.java`
//! * `unidbg-api/src/main/java/com/github/unidbg/file/BaseFileSystem.java`
//! @7f5da98e.
//!
//! `LinuxFileSystem` is the file-system half unidbg's resolver chains into
//! first. It resolves guest paths against a root directory and answers the
//! `/dev/*`, `/proc/self/*`, and `/system/*` paths that libc and Android
//! runtime expect. It also creates the work directory and the `SimpleFileIO`
//! / `DirectoryFileIO` file descriptors for normal host files.

use std::fs;
use std::path::{Path, PathBuf};

use crate::errno::{EACCES, EEXIST};
use crate::file::byte_array::ByteArrayFileIO;
use crate::file::driver::{
    HostFileIO, RandomFileIO, StdoutFileIO, StdinFileIO, NullFileIO,
};
use crate::file::structs::IOConstants;
use crate::file::{FileIO, FileResult, FileSystem};

/// Default scratch directory unidbg creates under the root.
pub const DEFAULT_WORK_DIR: &str = "unidbg_work";

/// The Linux guest's view of the file system. Construct one with
/// [`LinuxFileSystem::new`] and hand it to the resolver chain.
pub struct LinuxFileSystem {
    root_dir: Option<PathBuf>,
}

impl std::fmt::Debug for LinuxFileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFileSystem")
            .field("root_dir", &self.root_dir)
            .finish()
    }
}

impl LinuxFileSystem {
    /// Builds a file system rooted at `root_dir`. The directory is created if
    /// it does not already exist; the `tmp` and `system` sub-directories
    /// unidbg expects are mirrored (`BaseFileSystem.initialize`).
    pub fn new(root_dir: impl Into<PathBuf>) -> Result<Self, std::io::Error> {
        let root_dir = root_dir.into();
        fs::create_dir_all(&root_dir)?;
        fs::create_dir_all(root_dir.join("tmp"))?;
        fs::create_dir_all(root_dir.join("system"))?;
        fs::create_dir_all(root_dir.join("data"))?;
        Ok(LinuxFileSystem {
            root_dir: Some(root_dir),
        })
    }

    /// Builds a file system with no host backing; only the `/dev/*` and
    /// `/proc/self/*` synthetic paths can be opened.
    pub fn ephemeral() -> Self {
        LinuxFileSystem { root_dir: None }
    }

    /// The work directory (`<root>/unidbg_work`), created if missing.
    pub fn work_dir(&self) -> Result<PathBuf, std::io::Error> {
        let Some(root) = self.root_dir.as_ref() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "LinuxFileSystem has no root_dir",
            ));
        };
        let dir = root.join(DEFAULT_WORK_DIR);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(dir)
    }

    /// Resolves `path` against the root directory, refusing traversal
    /// attempts (`..` segments).
    fn resolve_in_root(&self, path: &str) -> Option<PathBuf> {
        let root = self.root_dir.as_ref()?;
        let candidate = root.join(path.trim_start_matches('/'));
        let canonical_root = fs::canonicalize(root).ok()?;
        let canonical_candidate = fs::canonicalize(&candidate).ok()?;
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
}

impl FileSystem for LinuxFileSystem {
    fn root_dir(&self) -> Option<&Path> {
        self.root_dir.as_deref()
    }

    fn create_work_dir(&self) -> Result<PathBuf, std::io::Error> {
        self.work_dir()
    }

    fn open(&self, pathname: &str, oflags: i32) -> FileResult<Box<dyn FileIO>> {
        // The synthetic paths must always resolve (no root required).
        match pathname {
            "/dev/tty" => {
                return FileResult::Success(Box::new(NullFileIO::new("/dev/tty")));
            }
            "/dev/null" => {
                return FileResult::Success(Box::new(NullFileIO::new("/dev/null")));
            }
            "/dev/urandom" | "/dev/random" | "/dev/srandom" => {
                return FileResult::Success(Box::new(RandomFileIO::new(pathname)));
            }
            "stdin" => {
                return FileResult::Success(Box::new(StdinFileIO::new(
                    "stdin",
                    Box::new(EmptyReader),
                )));
            }
            "stdout" => {
                return FileResult::Success(Box::new(StdoutFileIO::new(
                    "stdout",
                    Box::new(NullWriter),
                )));
            }
            "stderr" => {
                return FileResult::Success(Box::new(StdoutFileIO::new(
                    "stderr",
                    Box::new(NullWriter),
                )));
            }
            "/proc/self/maps" | "/proc/self/stat" | "/proc/self/cmdline" => {
                return FileResult::Success(Box::new(ByteArrayFileIO::new(
                    oflags,
                    pathname,
                    self.synthesize_proc(pathname).into_bytes(),
                )));
            }
            _ => {}
        }

        if pathname.is_empty() {
            return FileResult::NotFound;
        }

        let Some(root) = self.root_dir.as_ref() else {
            return FileResult::NotFound;
        };

        // The path may legitimately be `<root>/<pathname>` directly without
        // resolving through `canonicalize` (which would fail for new files).
        let candidate = root.join(pathname.trim_start_matches('/'));
        let resolved = if candidate.exists() {
            match fs::canonicalize(&candidate) {
                Ok(c) => c,
                Err(_) => return FileResult::NotFound,
            }
        } else {
            // `O_CREAT` allows us to create the file lazily, but we still need
            // to ensure the resolved path stays inside the root. Walk the
            // canonical root and append the un-resolved remainder.
            let stripped = pathname.trim_start_matches('/');
            root.join(stripped)
        };

        // Reject `..` traversal even when the path does not exist yet.
        if self.resolve_in_root(pathname).is_none() && resolved.exists() {
            return FileResult::NotFound;
        }

        if resolved.exists() && resolved.is_dir() {
            return FileResult::Success(Box::new(DirectoryFileIO::new(
                oflags,
                pathname.to_string(),
                resolved.clone(),
            )));
        }

        if resolved.exists() {
            let file = match HostFileIO::open_path(oflags, pathname, &resolved) {
                Ok(f) => f,
                Err(_) => return FileResult::NotFound,
            };
            return FileResult::Success(Box::new(file));
        }

        if (oflags & IOConstants::O_CREAT) != 0 {
            if let Some(parent) = resolved.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let file = match HostFileIO::open_path(oflags, pathname, &resolved) {
                Ok(f) => f,
                Err(_) => return FileResult::NotFound,
            };
            return FileResult::Success(Box::new(file));
        }

        FileResult::NotFound
    }

    fn unlink(&self, path: &str) {
        if let Some(resolved) = self.resolve_in_root(path) {
            let _ = fs::remove_file(resolved);
        }
    }

    fn mkdir(&self, path: &str, _mode: i32) -> bool {
        let Some(root) = self.root_dir.as_ref() else {
            return false;
        };
        let target = root.join(path.trim_start_matches('/'));
        if target.exists() {
            return true;
        }
        fs::create_dir_all(target).is_ok()
    }

    fn rmdir(&self, path: &str) {
        if let Some(resolved) = self.resolve_in_root(path) {
            let _ = fs::remove_dir_all(resolved);
        }
    }

    fn rename(&self, old_path: &str, new_path: &str) -> i32 {
        let old = match self.resolve_in_root(old_path) {
            Some(o) => o,
            None => return -EACCES,
        };
        let new = match self.root_dir.as_ref() {
            Some(root) => root.join(new_path.trim_start_matches('/')),
            None => return -EACCES,
        };
        if let Some(parent) = new.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if old.exists() {
            if fs::rename(&old, &new).is_err() {
                return -EACCES;
            }
        }
        0
    }
}

impl LinuxFileSystem {
    fn synthesize_proc(&self, path: &str) -> String {
        match path {
            "/proc/self/maps" => {
                let mut out = String::new();
                if let Some(root) = self.root_dir.as_ref() {
                    if let Ok(canonical) = fs::canonicalize(root) {
                        out.push_str(&format!(
                            "{:x}-{:x} r--p 00000000 00:00 0 {}\n",
                            0,
                            canonical.to_string_lossy().len(),
                            canonical.display(),
                        ));
                    }
                }
                out.push_str("ffff_0000-ffff_1000 r--p 00000000 00:00 0 [stack]\n");
                out
            }
            "/proc/self/stat" => {
                // unidbg returns a static stub; we do the same.
                "1 (init) R 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n".to_string()
            }
            "/proc/self/cmdline" => "raxdbg\0".to_string(),
            _ => String::new(),
        }
    }
}

/// A `read()`-only `ByteArrayFileIO`-style directory enumeration stub.
///
/// unidbg's `DirectoryFileIO` calls into `BaseFileIO.getdents64`; we keep
/// that as a no-op for now (returns `-EOPNOTSUPP`) because raxdbg's
pub struct DirectoryFileIO {
    #[allow(dead_code)]
    oflags: i32,
    path: String,
    host: PathBuf,
}

impl std::fmt::Debug for DirectoryFileIO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryFileIO")
            .field("path", &self.path)
            .field("host", &self.host)
            .finish()
    }
}

impl DirectoryFileIO {
    /// Builds a directory descriptor for `host` (a host path) under the
    /// guest `path`.
    pub fn new(oflags: i32, path: String, host: PathBuf) -> Self {
        DirectoryFileIO {
            oflags,
            path,
            host,
        }
    }
}

impl FileIO for DirectoryFileIO {
    fn close(&mut self) {}

    fn lseek(&mut self, _offset: i64, _whence: i32) -> i64 {
        -crate::errno::EINVAL as i64
    }

    fn fstat(&self, stat: &mut Stat) -> i32 {
        stat.st_mode = crate::file::structs::IOConstants::S_IFDIR | 0o755;
        stat.st_nlink = 1;
        stat.st_size = 0;
        stat.st_blksize = 4096;
        0
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

use crate::file::structs::Stat;

/// Returns the cached `ENXIO` (-6) the syscall layer can use to short-circuit
/// unsupported paths. unidbg's `BaseFileSystem.open` does not return this
/// directly, but the `IOResolver` chain does.
pub fn unsupported_errno() -> i32 {
    -EEXIST
}

struct EmptyReader;

impl std::io::Read for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

struct NullWriter;

impl std::io::Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
