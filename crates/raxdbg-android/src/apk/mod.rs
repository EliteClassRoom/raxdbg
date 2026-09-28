//! APK loading (`ApkFile` / `ApkDir`) and binary-manifest parsing.
//!
//! Port of unidbg's
//! `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/apk/`:
//! `Apk.java`, `ApkFactory.java`, `ApkFile.java`, `ApkDir.java`. Only the
//! `Apk` trait shape we depend on from `BaseVM` (`findLibrary` -- see
//! `BaseVM.java::loadLibraryData` which reads `lib/<abi>/<name>.so`) is
//! ported; the `getSignatures()` method returns the raw PKCS#7 / X.509 DER
//! bytes from the `META-INF/*.RSA|DSA|EC` entry without parsing the
//! certificate (calling code is expected to feed them to a verifier if it
//! cares about identity), matching what unidbg's `ApkFile` exposes once
//! `apk-parser` has extracted the certificate meta.

use std::path::Path;

use thiserror::Error;

mod axml;
mod dir;
mod file;

pub use axml::{parse_manifest, AxmlError, ManifestMeta};

#[derive(Debug, Error)]
pub enum ApkError {
    /// The host path is neither a file nor a directory.
    #[error("apk path {path:?} is neither a file nor a directory")]
    NotADirectoryOrFile { path: Box<Path> },
    /// An I/O error happened while opening the underlying zip / directory.
    #[error("apk io error: {0}")]
    Io(#[from] std::io::Error),
    /// The zip file is malformed.
    #[error("apk zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The AndroidManifest.xml could not be parsed.
    #[error("apk manifest parse error: {0}")]
    Axml(#[from] AxmlError),
}

/// An Android APK: a `.apk` zip on disk or an unzipped directory tree.
///
/// Mirrors unidbg's `Apk` interface, narrowed to the call sites the port
/// actually uses. All accessors are infallible reads: callers that need to
/// distinguish "absent" from "malformed" should call the corresponding
/// `open` constructor and observe its `Result`.
pub trait Apk {
    fn package_name(&self) -> &str;
    fn version_code(&self) -> i64;
    fn version_name(&self) -> &str;
    /// Raw bytes of the manifest. For `ApkFile` this is the binary AXML
    /// payload (matching `apk-parser`'s `getManifestXml()` output only when
    /// the caller is willing to decode binary XML to text on its own); for
    /// `ApkDir` this is the plain-text `AndroidManifest.xml` file as-is.
    fn manifest_xml(&self) -> &[u8];

    fn get_file_data(&self, path: &str) -> Option<Vec<u8>>;

    /// Look up `assets/<name>`.
    fn open_asset(&self, name: &str) -> Option<Vec<u8>>;

    /// Signature entry bytes (one `Vec<u8>` per `META-INF/*.RSA|DSA|EC`
    /// file). Decoding them into certificates is left to the caller.
    fn get_signatures(&self) -> Vec<Vec<u8>>;

    fn parent_file(&self) -> Option<&Path>;
}

/// Open the given path as an `Apk`, dispatching on whether it is a
/// directory (`ApkDir`) or a file (`ApkFile`). Mirrors unidbg's
/// `ApkFactory.createApk(File)`.
pub fn open(path: &Path) -> Result<Box<dyn Apk>, ApkError> {
    let meta = std::fs::metadata(path)?;
    if meta.is_dir() {
        Ok(Box::new(dir::ApkDir::open(path)?))
    } else if meta.is_file() {
        Ok(Box::new(file::ApkFile::open(path)?))
    } else {
        Err(ApkError::NotADirectoryOrFile { path: path.to_path_buf().into_boxed_path() })
    }
}