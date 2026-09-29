//! The Android library and file resolver.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/AndroidResolver.java`
//! @7f5da98e, with one substitution: unidbg reads its bundled bionic libraries
//! out of its own jar resources, raxdbg reads the same tree from `libs/` on
//! disk (`tools/fetch-libs.ps1` populates it).

use std::rc::Rc;
use std::path::{Path, PathBuf};

use raxdbg_core::file::driver::{create_driver_file, is_null_path};
use raxdbg_core::file::linux_fs::LinuxFileSystem;
use raxdbg_core::file::{FileIO, FileResult, IOResolver};
use raxdbg_core::file::IOConstants;

use crate::android_file::{ElfLibraryFile, LibraryFile, LibraryResolver};

/// `LogCatFileIO.LOG_PATH_PREFIX`: paths under it become a log file in the
/// root directory.
pub const LOG_PATH_PREFIX: &str = "/dev/log/";

/// Where a resolver failed to find its libraries.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// The bundled libraries are missing.
    #[error(
        "the bundled Android libraries are not at {path}: run `pwsh tools/fetch-libs.ps1` \
         to populate `libs/` from the unidbg submodule, or point RAXDBG_LIBS_DIR at an \
         existing tree"
    )]
    LibsMissing {
        /// The directory that was tried.
        path: PathBuf,
    },
}

/// Resolves library names and guest paths to the bundled Android resources.
pub struct AndroidResolver {
    sdk: u32,
    libs_dir: PathBuf,
    root_dir: PathBuf,
    is_64bit: bool,
    /// When non-empty, only these library names are resolved (unidbg's
    /// `AndroidResolver(sdk, needed...)` constructor).
    needed: Vec<String>,
}

impl std::fmt::Debug for AndroidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidResolver")
            .field("sdk", &self.sdk)
            .field("libs_dir", &self.libs_dir)
            .field("is_64bit", &self.is_64bit)
            .finish()
    }
}

impl AndroidResolver {
    /// A resolver for `sdk`, reading `libs/` from the environment
    /// (`RAXDBG_LIBS_DIR`), the workspace, or next to the executable.
    pub fn new(sdk: u32, is_64bit: bool) -> Result<Self, ResolverError> {
        let libs_dir = default_libs_dir().ok_or_else(|| ResolverError::LibsMissing {
            path: PathBuf::from("libs"),
        })?;
        Ok(Self::with_libs_dir(sdk, is_64bit, libs_dir))
    }

    /// A resolver reading a specific `libs` tree.
    pub fn with_libs_dir(sdk: u32, is_64bit: bool, libs_dir: impl Into<PathBuf>) -> Self {
        let libs_dir = libs_dir.into();
        AndroidResolver {
            sdk,
            libs_dir,
            root_dir: std::env::temp_dir().join("raxdbg-root"),
            is_64bit,
            needed: Vec::new(),
        }
    }

    /// Restricts resolution to these library names.
    pub fn set_needed(&mut self, needed: Vec<String>) {
        self.needed = needed;
    }

    /// The SDK level whose libraries are used.
    pub fn sdk(&self) -> u32 {
        self.sdk
    }

    /// The tree the resources are read from.
    pub fn libs_dir(&self) -> &Path {
        &self.libs_dir
    }

    /// The directory guest paths are resolved under.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Sets the directory guest paths are resolved under.
    pub fn set_root_dir(&mut self, dir: impl Into<PathBuf>) {
        self.root_dir = dir.into();
    }

    /// `/android/sdk<sdk>/<path>` under the libs tree, as unidbg builds it.
    fn resource(&self, path: &str) -> PathBuf {
        let relative = path.trim_start_matches('/');
        self.libs_dir
            .join(format!("android/sdk{}", self.sdk))
            .join(relative)
    }

    /// The library resource path: unidbg replaces `+` with `p`, which is why
    /// `libc++_shared.so` is bundled as `libcpp_shared.so`.
    fn library_resource(&self, name: &str) -> PathBuf {
        let directory = if self.is_64bit { "lib64" } else { "lib" };
        self.libs_dir
            .join(format!("android/sdk{}", self.sdk))
            .join(directory)
            .join(name.replace('+', "p"))
    }

    /// A hook engine library (`libdobby.so`, `libhookzz.so`, `libxhook.so`),
    /// which unidbg keeps under `android/lib/<abi>/` (plan P8).
    pub fn hook_library(&self, name: &str) -> Option<ElfLibraryFile> {
        let abi = if self.is_64bit {
            "arm64-v8a"
        } else {
            "armeabi-v7a"
        };
        let path = self.libs_dir.join("android/lib").join(abi).join(name);
        if path.is_file() {
            ElfLibraryFile::open(path).ok()
        } else {
            None
        }
    }

    /// A `FileIO` for a host path, as unidbg's `createFileIO(File, ...)`.
    fn file_io(&self, path: &Path, guest_path: &str, oflags: i32) -> Option<Box<dyn FileIO>> {
        if !path.exists() {
            return None;
        }
        if path.is_dir() {
            return Some(Box::new(
                raxdbg_core::file::linux_fs::DirectoryFileIO::new(
                    oflags,
                    guest_path.to_string(),
                    path.to_path_buf(),
                ),
            ));
        }
        if is_null_path(guest_path) || guest_path.starts_with("/dev/") {
            if let Some(io) = create_driver_file(guest_path, None, None) {
                return Some(io);
            }
        }
        ElfLibraryFile::open(path).ok().map(|file| {
            Box::new(raxdbg_core::file::byte_array::ByteArrayFileIO::new(
                oflags,
                guest_path.to_string(),
                file.data().to_vec(),
            )) as Box<dyn FileIO>
        })
    }
}

impl LibraryResolver for AndroidResolver {
    fn resolve_library(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        if !self.needed.is_empty() && !self.needed.iter().any(|needed| needed == name) {
            return None;
        }

        // A file the caller put next to the root directory wins, so a test or
        // an application can override a bundled library.
        let override_path = self.root_dir.join(name);
        if override_path.is_file() {
            if let Ok(file) = ElfLibraryFile::open(override_path) {
                return Some(Box::new(file));
            }
        }

        let path = self.library_resource(name);
        if path.is_file() {
            return ElfLibraryFile::open(path)
                .ok()
                .map(|file| Box::new(file) as Box<dyn LibraryFile>);
        }

        // The hook engines live outside the SDK tree: unidbg keeps them under
        // `android/lib/<abi>/` rather than `android/sdk<N>/lib*/`, because they
        // are not part of any platform release. Without this a guest
        // `dlopen("libdobby.so")` -- which is exactly what an application doing
        // inline hooking does -- finds nothing.
        self.hook_library(name)
            .map(|file| Box::new(file) as Box<dyn LibraryFile>)
    }
}

impl IOResolver for AndroidResolver {
    fn resolve(&self, pathname: &str, oflags: i32) -> FileResult<Box<dyn FileIO>> {
        if let Some(rest) = pathname.strip_prefix(LOG_PATH_PREFIX) {
            let file = self.root_dir.join("dev/log").join(rest);
            if let Some(parent) = file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if !file.exists() {
                let _ = std::fs::File::create(&file);
            }
            return match raxdbg_core::file::driver::HostFileIO::open_path(
                oflags,
                pathname,
                &file,
            ) {
                Ok(io) => FileResult::Success(Box::new(io)),
                Err(_) => FileResult::NotFound,
            };
        }

        if pathname == "." {
            let work = LinuxFileSystem::new(&self.root_dir)
                .ok()
                .and_then(|fs| fs.work_dir().ok());
            return match work {
                Some(dir) => match self.file_io(&dir, pathname, oflags) {
                    Some(io) => FileResult::Success(io),
                    None => FileResult::NotFound,
                },
                None => FileResult::NotFound,
            };
        }

        let resource = self.resource(pathname);
        match self.file_io(&resource, pathname, oflags) {
            // unidbg answers resources as a fallback: a later resolver, or the
            // host file system, may still have a better answer.
            Some(io) => FileResult::Fallback(io),
            None => FileResult::NotFound,
        }
    }
}

/// The emulator's resolver, as the syscall handler's I/O chain sees it.
///
/// unidbg's `AndroidResolver` implements both `LibraryResolver` and
/// `IOResolver`, and the emulator hands the *same* object to both: the library
/// side loads `.so`s out of `libs/`, and the I/O side serves guest paths such as
/// `/dev/__properties__`, `/proc/stat` and
/// `/system/usr/share/zoneinfo/tzdata` out of the same tree. This wrapper shares
/// the `Rc` rather than cloning the resolver, so a later `set_root_dir` is seen
/// by both.
pub struct SharedResolver(pub Rc<AndroidResolver>);

impl IOResolver for SharedResolver {
    fn resolve(
        &self,
        pathname: &str,
        oflags: i32,
    ) -> raxdbg_core::file::FileResult<Box<dyn raxdbg_core::file::FileIO>> {
        self.0.resolve(pathname, oflags)
    }
}

/// `O_RDONLY`, re-exported for callers that open the standard descriptors.
pub const O_RDONLY: i32 = IOConstants::O_RDONLY;

/// The bundled library tree: `RAXDBG_LIBS_DIR`, then the workspace's `libs/`,
/// then `libs/` next to the executable.
pub fn default_libs_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("RAXDBG_LIBS_DIR") {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            return Some(path);
        }
    }
    // The workspace root, known at compile time; this is what the test suites
    // use, since they run from `target/`.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("libs"));
    if let Some(path) = workspace {
        if path.is_dir() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let path = exe.parent()?.join("libs");
        if path.is_dir() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_resource_names_replace_plus_with_p() {
        let resolver = AndroidResolver::with_libs_dir(23, true, "libs");
        assert!(resolver
            .library_resource("libc.so")
            .ends_with("android/sdk23/lib64/libc.so"));
        assert!(resolver
            .library_resource("libc++_shared.so")
            .ends_with("android/sdk23/lib64/libcpp_shared.so"));
        assert!(resolver
            .library_resource("libstdc++.so")
            .ends_with("android/sdk23/lib64/libstdcpp.so"));
        let resolver = AndroidResolver::with_libs_dir(19, false, "libs");
        assert!(resolver
            .library_resource("libc.so")
            .ends_with("android/sdk19/lib/libc.so"));
    }

    #[test]
    fn resources_are_looked_up_under_the_sdk_tree() {
        let resolver = AndroidResolver::with_libs_dir(23, true, "libs");
        assert!(resolver
            .resource("/system/usr/share/zoneinfo/tzdata")
            .ends_with("android/sdk23/system/usr/share/zoneinfo/tzdata"));
        assert!(resolver
            .resource("/dev/__properties__")
            .ends_with("android/sdk23/dev/__properties__"));
    }
}
