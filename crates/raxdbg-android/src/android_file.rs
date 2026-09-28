//! Library files and their resolution.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/spi/{LibraryFile,LibraryResolver}.java`
//! and `unidbg-android/src/main/java/com/github/unidbg/linux/android/{ElfLibraryFile,ElfLibraryRawFile}.java`
//! @7f5da98e.

use std::path::{Path, PathBuf};

/// A shared library the loader can map.
pub trait LibraryFile: std::fmt::Debug {
    /// The library's name, which is its basename (`libc.so`).
    fn name(&self) -> &str;

    /// The file's bytes.
    fn data(&self) -> &[u8];

    /// The file's path, when it came from the host file system.
    fn path(&self) -> Option<&Path>;

    /// Resolves a dependency of this file, as unidbg's
    /// `LibraryFile.resolveLibrary` does: a sibling in the same directory.
    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>>;

    /// The `DT_NEEDED` names this file declares, for diagnostics.
    fn needed_libraries(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Resolves a library name to a file.
///
/// Port of unidbg: `LibraryResolver`.
pub trait LibraryResolver {
    /// Resolves `name`, or `None` when the resolver does not know it.
    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>>;
}

/// A shared library on the host file system.
#[derive(Debug)]
pub struct ElfLibraryFile {
    path: PathBuf,
    name: String,
    data: Vec<u8>,
}

impl ElfLibraryFile {
    /// Opens `path`, reading it whole.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let data = std::fs::read(&path)?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        Ok(ElfLibraryFile { path, name, data })
    }

    /// The host path.
    pub fn file_path(&self) -> &Path {
        &self.path
    }
}

impl LibraryFile for ElfLibraryFile {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn path(&self) -> Option<&Path> {
        Some(&self.path)
    }

    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        let sibling = self.path.parent()?.join(name);
        if sibling.is_file() {
            ElfLibraryFile::open(sibling).ok().map(|file| Box::new(file) as Box<dyn LibraryFile>)
        } else {
            None
        }
    }
}

/// A shared library that only exists in memory, as an APK's `lib/<abi>/*.so`
/// entries do.
#[derive(Debug)]
pub struct ElfLibraryRawFile {
    name: String,
    data: Vec<u8>,
    /// The directory the file "came from", for sibling lookups.
    parent: Option<PathBuf>,
}

impl ElfLibraryRawFile {
    /// A file named `name` with `data`.
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        ElfLibraryRawFile {
            name: name.into(),
            data,
            parent: None,
        }
    }

    /// A file that claims to live in `parent`, so dependency lookups resolve
    /// against it.
    pub fn with_parent(name: impl Into<String>, data: Vec<u8>, parent: impl Into<PathBuf>) -> Self {
        ElfLibraryRawFile {
            name: name.into(),
            data,
            parent: Some(parent.into()),
        }
    }
}

impl LibraryFile for ElfLibraryRawFile {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn path(&self) -> Option<&Path> {
        self.parent.as_deref()
    }

    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        let parent = self.parent.as_ref()?;
        let sibling = parent.join(name);
        if sibling.is_file() {
            ElfLibraryFile::open(sibling).ok().map(|file| Box::new(file) as Box<dyn LibraryFile>)
        } else {
            None
        }
    }
}

/// Resolves library names from a directory tree.
#[derive(Debug)]
pub struct DirectoryResolver {
    root: PathBuf,
}

impl DirectoryResolver {
    /// Resolves names under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DirectoryResolver { root: root.into() }
    }
}

impl LibraryResolver for DirectoryResolver {
    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        let candidate = self.root.join(name);
        if candidate.is_file() {
            ElfLibraryFile::open(candidate)
                .ok()
                .map(|file| Box::new(file) as Box<dyn LibraryFile>)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_file_reports_its_name_and_bytes() {
        let file = ElfLibraryRawFile::new("libx.so", vec![1, 2, 3]);
        assert_eq!(file.name(), "libx.so");
        assert_eq!(file.data(), &[1, 2, 3]);
        assert!(file.path().is_none());
        assert!(file.resolve_library("liby.so").is_none());
    }
}
