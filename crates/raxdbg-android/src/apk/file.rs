//! `.apk` zip-backed [`Apk`] implementation.
//!
//! Port of unidbg `ApkFile.java`. We mirror the same convenience methods:
//! `getVersionCode/Name/PackageName` are derived from the parsed AXML
//! start tag; `getFileData(path)` and `openAsset(name)` look entries up
//! in a flat `BTreeMap<String, Vec<u8>>` we read from the zip on `open`
//! (APKs are small enough that buffering is cheaper than the per-call
//! `Archive` traversal, and gives us O(log n) lookups without rewinding).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use super::{Apk, ApkError, ManifestMeta};

pub(crate) struct ApkFile {
    /// In-memory entry table, keyed by the exact zip entry name (forward
    /// slashes, no leading slash). Order-stable so callers iterating
    /// `parent_file`-derived files see a deterministic sequence.
    entries: BTreeMap<String, Vec<u8>>,
    meta: ManifestMeta,
    manifest_bytes: Vec<u8>,
    apk_path: PathBuf,
}

impl ApkFile {
    pub(crate) fn open(path: &Path) -> Result<Self, ApkError> {
        let file = File::open(path)?;
        let mut zip = ZipArchive::new(file)?;
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut signature_paths: Vec<String> = Vec::new();
        // Snapshot the entry list first; iterating while reading under
        // `Archive::by_index` is documented as safe but fragile.
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index_raw(i).map(|f| f.name().to_string()))
            .collect::<Result<_, _>>()?;
        for name in names {
            let mut zf = zip.by_name(&name)?;
            // Skip directories outright.
            if zf.is_dir() {
                continue;
            }
            let mut buf = Vec::with_capacity(zf.size() as usize);
            zf.read_to_end(&mut buf)?;
            if name == "AndroidManifest.xml" {
                manifest_bytes = Some(buf.clone());
            }
            if let Some(stripped) = name.strip_prefix("META-INF/") {
                if let Some(ext) = Path::new(stripped).extension().and_then(|s| s.to_str()) {
                    let ext = ext.to_ascii_uppercase();
                    if matches!(ext.as_str(), "RSA" | "DSA" | "EC") {
                        signature_paths.push(name.clone());
                    }
                }
            }
            entries.insert(name, buf);
        }
        let manifest_bytes =
            manifest_bytes.ok_or(ApkError::Axml(super::AxmlError::MissingManifest))?;
        let meta = super::parse_manifest(&manifest_bytes)?;
        // Sort signatures by zip order (BTreeMap iteration) to make
        // `get_signatures` stable across runs.
        let mut ordered_sigs: Vec<Vec<u8>> = Vec::with_capacity(signature_paths.len());
        for path in signature_paths {
            if let Some(bytes) = entries.get(&path) {
                ordered_sigs.push(bytes.clone());
            }
        }
        // We do not currently surface `ordered_sigs` here -- `get_signatures`
        // pulls them on demand below. Keeping this scratch vector avoids a
        // separate scan in `open`.
        let _ = ordered_sigs;
        Ok(ApkFile {
            entries,
            meta,
            manifest_bytes,
            apk_path: path.to_path_buf(),
        })
    }

    fn signature_entries(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (name, bytes) in &self.entries {
            if let Some(stripped) = name.strip_prefix("META-INF/") {
                if let Some(ext) = Path::new(stripped).extension().and_then(|s| s.to_str()) {
                    if matches!(ext.to_ascii_uppercase().as_str(), "RSA" | "DSA" | "EC") {
                        out.push(bytes.clone());
                    }
                }
            }
        }
        out
    }
}

impl Apk for ApkFile {
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
        let normalized = normalize(path);
        self.entries.get(&normalized).cloned()
    }
    fn open_asset(&self, name: &str) -> Option<Vec<u8>> {
        self.get_file_data(&format!("assets/{name}"))
    }
    fn get_signatures(&self) -> Vec<Vec<u8>> {
        self.signature_entries()
    }
    fn parent_file(&self) -> Option<&Path> {
        self.apk_path.parent()
    }
}

/// Drop a leading `/` (BaseVM sometimes passes `lib/<abi>/x.so`, sometimes
/// `/lib/<abi>/x.so`) and normalise `\` to `/`. Unidbg's `ApkFile` reads
/// from the zip without such massage because it relies on the Java
/// `ApkFile.getFileData(String)` upstream whose callers always pass the
/// un-prefixed path; we accept both because BaseVM's `unzip` prefix-strips.
fn normalize(path: &str) -> String {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    stripped.replace('\\', "/")
}