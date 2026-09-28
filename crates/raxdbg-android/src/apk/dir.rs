//! Unzipped-APK directory implementation.
//!
//! Port of unidbg `ApkDir.java`. Differences vs. `ApkFile`:
//!
//! * Files are read on demand from the host FS (no in-memory mirror).
//! * `AndroidManifest.xml` is **plain text** in an unzipped APK (the
//!   AXML encoding only exists inside the zip); we therefore detect
//!   the `<?xml` / `<manifest` prefix and fall back to a minimal text
//!   scan for `package=`, `android:versionCode=`, `android:versionName=`.
//! * `getSignatures()` walks the directory tree recursively, picking up
//!   any file matching `*.RSA|DSA|EC`.

use std::path::{Path, PathBuf};

use super::{Apk, ApkError, ManifestMeta};
use crate::apk::axml;

pub(crate) struct ApkDir {
    root: PathBuf,
    meta: ManifestMeta,
    manifest_bytes: Vec<u8>,
}

impl ApkDir {
    pub(crate) fn open(path: &Path) -> Result<Self, ApkError> {
        if !path.is_dir() {
            return Err(ApkError::NotADirectoryOrFile {
                path: path.to_path_buf().into_boxed_path(),
            });
        }
        let manifest_path = path.join("AndroidManifest.xml");
        let manifest_bytes = std::fs::read(&manifest_path).map_err(|_| {
            ApkError::Axml(axml::AxmlError::MissingManifest)
        })?;
        let meta = if is_binary_axml(&manifest_bytes) {
            axml::parse_manifest(&manifest_bytes)?
        } else {
            parse_text_manifest(&manifest_bytes)?
        };
        Ok(ApkDir {
            root: path.to_path_buf(),
            meta,
            manifest_bytes,
        })
    }

    fn collect_signatures(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        collect_signatures_recursive(&self.root, &mut out);
        out
    }
}

impl Apk for ApkDir {
    fn package_name(&self) -> &str {
        &self.meta.package
    }
    fn version_code(&self) -> i64 {
        self.meta.version_code
    }
    fn version_name(&self) -> &str {
        &self.meta.version_name
    }
    fn manifest_xml(&self) -> &[u8] {
        &self.manifest_bytes
    }
    fn get_file_data(&self, path: &str) -> Option<Vec<u8>> {
        let stripped = path.strip_prefix('/').unwrap_or(path);
        let joined = self.root.join(stripped);
        std::fs::read(&joined).ok()
    }
    fn open_asset(&self, name: &str) -> Option<Vec<u8>> {
        self.get_file_data(&format!("assets/{name}"))
    }
    fn get_signatures(&self) -> Vec<Vec<u8>> {
        self.collect_signatures()
    }
    fn parent_file(&self) -> Option<&Path> {
        self.root.parent()
    }
}

fn is_binary_axml(bytes: &[u8]) -> bool {
    // The binary AXML format begins with chunk type 0x0003 (string pool)
    // in big-endian, i.e. the first two bytes are 0x00 0x03. Anything that
    // starts with `<?xml` or `<manifest` is plain text.
    bytes.len() >= 2 && bytes[0] == 0x00 && bytes[1] == 0x03
}

/// Minimal text-only manifest parser for unzipped APKs.
///
/// Real `apkanalyzer`-style parsing of plain-text `AndroidManifest.xml`
/// would be a multi-day project; for the only three attributes the trait
/// exposes we lift them with a stateful single-pass scanner. Quoted values
/// may use single or double quotes; namespace prefixes are preserved as-is
/// (we look for `android:versionCode` literally).
fn parse_text_manifest(bytes: &[u8]) -> Result<ManifestMeta, ApkError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ApkError::Axml(axml::AxmlError::BadStringEntry("manifest not utf-8")))?;
    let mut package: Option<String> = None;
    let mut version_code: Option<i64> = None;
    let mut version_name: Option<String> = None;
    let mut i = 0usize;
    let bytes_str = text;
    while let Some(rel) = find_attr_start(bytes_str, i) {
        let name_start = rel;
        let name_end = match bytes_str[name_start..].find(|c: char| c.is_whitespace() || c == '=') {
            Some(o) => name_start + o,
            None => break,
        };
        let name = &bytes_str[name_start..name_end];
        // Skip whitespace + '=' + optional quote
        let mut j = name_end;
        while j < bytes_str.len() && bytes_str.as_bytes()[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes_str.len() || bytes_str.as_bytes()[j] != b'=' {
            i = name_end + 1;
            continue;
        }
        j += 1;
        while j < bytes_str.len() && bytes_str.as_bytes()[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes_str.len() {
            break;
        }
        let quote = bytes_str.as_bytes()[j];
        if quote != b'"' && quote != b'\'' {
            i = j;
            continue;
        }
        j += 1;
        let value_start = j;
        let value_end = match bytes_str[value_start..].find(quote as char) {
            Some(o) => value_start + o,
            None => break,
        };
        let value = &bytes_str[value_start..value_end];
        match name {
            "package" => package = Some(value.to_string()),
            "android:versionCode" => {
                version_code = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| ApkError::Axml(axml::AxmlError::BadVersionCode(value.to_string())))?,
                );
            }
            "android:versionName" => version_name = Some(value.to_string()),
            _ => {}
        }
        i = value_end + 1;
    }
    let package = package.ok_or(ApkError::Axml(axml::AxmlError::MissingManifest))?;
    Ok(ManifestMeta {
        package,
        version_code: version_code.unwrap_or(0),
        version_name: version_name.unwrap_or_default(),
    })
}

fn find_attr_start(s: &str, from: usize) -> Option<usize> {
    // Skip whitespace, then expect an identifier character or namespace-prefix
    // colon. Returns the index of the first attribute name character.
    let mut i = from;
    while i < s.len() {
        let c = s.as_bytes()[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' || c == b':' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn collect_signatures_recursive(dir: &Path, out: &mut Vec<Vec<u8>>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            collect_signatures_recursive(&path, out);
        } else if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            if matches!(ext.to_ascii_uppercase().as_str(), "RSA" | "DSA" | "EC") {
                if let Ok(bytes) = std::fs::read(&path) {
                    out.push(bytes);
                }
            }
        }
    }
}