//! Integration tests for the `apk` module.
//!
//! We build a synthetic APK from scratch: a real binary AXML manifest
//! (hand-rolled string-pool + resource-map + start-tag chunks, encoded
//! exactly the way `aapt` produces them), a `lib/arm64-v8a/libjnitest.so`
//! placeholder, an `assets/foo.bin` blob, and a `META-INF/CERT.RSA`
//! signature entry. `ApkFile` is then driven end-to-end via the public
//! `Apk` trait, including a separate `ApkDir` test over a tempdir with a
//! plain-text `AndroidManifest.xml`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
// `Apk` is in scope for trait method dispatch through `Box<dyn Apk>`.
#[allow(unused_imports)]
use raxdbg_android::apk::{open, Apk, ApkError};
// ---------------------------------------------------------------------------
// Synthetic AXML builders (round-trippable through the real parser)
// ---------------------------------------------------------------------------

const ATTR_VERSION_CODE: u32 = 0x0101_021b;
const ATTR_VERSION_NAME: u32 = 0x0101_021c;

const RES_STRING_POOL_TYPE: u16 = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;

/// Build a UTF-16 string-pool chunk with `strings` in order.
fn build_string_pool(strings: &[&str]) -> Vec<u8> {
    let mut strings_buf: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    for s in strings {
        offsets.push(strings_buf.len() as u32);
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let len = utf16.len() as u16;
        strings_buf.extend_from_slice(&len.to_be_bytes());
        for u in utf16 {
            strings_buf.extend_from_slice(&u.to_be_bytes());
        }
        // 4-byte align within chunk (length bytes count toward alignment).
        let pad = (4 - (strings_buf.len() % 4)) % 4;
        strings_buf.resize(strings_buf.len() + pad, 0);
    }
    let header_size: u16 = 28;
    let string_count = strings.len() as u32;
    let offsets_bytes = (string_count as usize) * 4;
    let strings_start = header_size as u32 + offsets_bytes as u32;
    let chunk_size = strings_start + strings_buf.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&RES_STRING_POOL_TYPE.to_be_bytes());
    out.extend_from_slice(&header_size.to_be_bytes());
    out.extend_from_slice(&chunk_size.to_be_bytes());
    out.extend_from_slice(&string_count.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // styleCount
    out.extend_from_slice(&0u32.to_be_bytes()); // flags: UTF-16
    out.extend_from_slice(&strings_start.to_be_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // stylesStart
    for o in offsets {
        out.extend_from_slice(&o.to_be_bytes());
    }
    out.extend_from_slice(&strings_buf);
    out
}

fn build_resource_map(ids: &[u32]) -> Vec<u8> {
    let header_size: u16 = 8;
    let chunk_size = header_size as u32 + (ids.len() as u32) * 4;
    let mut out = Vec::new();
    out.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_be_bytes());
    out.extend_from_slice(&header_size.to_be_bytes());
    out.extend_from_slice(&chunk_size.to_be_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

fn build_start_tag(name_idx: u32, attrs: &[(u32, u32, u32)]) -> Vec<u8> {
    let header_size: u16 = 36;
    let attr_size: u16 = 20;
    let attr_count = attrs.len() as u16;
    let chunk_size = header_size as u32 + attr_count as u32 * attr_size as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_be_bytes());
    out.extend_from_slice(&header_size.to_be_bytes());
    out.extend_from_slice(&chunk_size.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // lineNumber
    out.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // comment
    out.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // ns
    out.extend_from_slice(&name_idx.to_be_bytes());
    out.extend_from_slice(&20u16.to_be_bytes()); // attributeStart
    out.extend_from_slice(&attr_size.to_be_bytes());
    out.extend_from_slice(&attr_count.to_be_bytes());
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // idIndex
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // classIndex
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // styleIndex
    for (ns, name, raw_value) in attrs {
        out.extend_from_slice(&ns.to_be_bytes());
        out.extend_from_slice(&name.to_be_bytes());
        out.extend_from_slice(&raw_value.to_be_bytes());
        out.extend_from_slice(&8u16.to_be_bytes()); // typedValueSize
        out.push(0); // typedValueRes0
        out.push(0); // typedValueDataType (unused)
        out.extend_from_slice(&0u32.to_be_bytes()); // typedValueData
    }
    out
}

fn build_synthetic_axml(
    package: &str,
    version_code: i64,
    version_name: &str,
) -> Vec<u8> {
    // Pool layout:
    //     0 = ""            1 = "manifest"           2 = "package"
    //     3 = package str   4 = "versionCode"        5 = version_code str
    //     6 = "versionName" 7 = version_name str
    let vcode_str = version_code.to_string();
    let pool_strings = [
        "",
        "manifest",
        "package",
        package,
        "versionCode",
        vcode_str.as_str(),
        "versionName",
        version_name,
    ];
    let mut blob = build_string_pool(&pool_strings);
    let mut resmap = vec![0u32; pool_strings.len()];
    resmap[4] = ATTR_VERSION_CODE;
    resmap[6] = ATTR_VERSION_NAME;
    blob.extend_from_slice(&build_resource_map(&resmap));
    let attrs = [
        (0xFFFF_FFFFu32, 2u32, 3u32), // package="..."
        (0xFFFF_FFFFu32, 4u32, 5u32), // android:versionCode="..."
        (0xFFFF_FFFFu32, 6u32, 7u32), // android:versionName="..."
    ];
    blob.extend_from_slice(&build_start_tag(1, &attrs));
    blob
}

// ---------------------------------------------------------------------------
// Tempdir + zip helpers
// ---------------------------------------------------------------------------

fn unique_tmp(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("raxdbg-android-apk-{nanos}-{name}"));
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

fn write_synthetic_apk(path: &Path, manifest_axml: &[u8]) {
    let file = File::create(path).expect("create apk file");
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    zip.start_file("AndroidManifest.xml", opts).expect("start manifest");
    zip.write_all(manifest_axml).expect("write manifest");

    let libso = b"\x7fELF placeholder for libjnitest.so\x00";
    zip.start_file("lib/arm64-v8a/libjnitest.so", opts)
        .expect("start libso");
    zip.write_all(libso).expect("write libso");

    let asset = b"\xCA\xFE\xBA\xBEbinary-asset-content\x00";
    zip.start_file("assets/foo.bin", opts).expect("start asset");
    zip.write_all(asset).expect("write asset");

    let cert = b"\x30\x82\x01\x00this-is-not-a-real-cert\x00";
    zip.start_file("META-INF/CERT.RSA", opts).expect("start sig");
    zip.write_all(cert).expect("write sig");

    // Add a sibling EC entry to make sure get_signatures pulls multiple.
    zip.start_file("META-INF/IGNORED.TXT", opts).expect("start ignored");
    zip.write_all(b"not a signature").expect("write ignored");
    zip.start_file("META-INF/CERT.EC", opts).expect("start ec");
    zip.write_all(b"\x30\xec-cert\x00").expect("write ec");

    zip.finish().expect("finish zip");
}

// ---------------------------------------------------------------------------
// ApkFile
// ---------------------------------------------------------------------------

#[test]
fn apk_file_parses_every_trait_method() {
    let dir = unique_tmp("file");
    let apk_path = dir.join("synthetic.apk");
    let manifest = build_synthetic_axml("com.raxdbg.test", 42, "1.2");
    write_synthetic_apk(&apk_path, &manifest);

    let apk = open(&apk_path).expect("open apk");
    assert_eq!(apk.package_name(), "com.raxdbg.test");
    assert_eq!(apk.version_code(), 42);
    assert_eq!(apk.version_name(), "1.2");

    // manifest_xml returns the binary AXML bytes verbatim.
    assert_eq!(apk.manifest_xml(), manifest.as_slice());

    // lib/<abi>/ lookup (BaseVM::loadLibraryData rule).
    let libso = apk
        .get_file_data("lib/arm64-v8a/libjnitest.so")
        .expect("libso entry");
    assert!(libso.starts_with(b"\x7fELF"));

    // Leading slash is normalised away.
    assert_eq!(
        apk.get_file_data("/lib/arm64-v8a/libjnitest.so").as_deref(),
        Some(libso.as_slice())
    );

    // open_asset goes through `assets/<name>`.
    let asset = apk.open_asset("foo.bin").expect("asset");
    assert_eq!(asset, b"\xCA\xFE\xBA\xBEbinary-asset-content\x00");

    // Missing entry is None, not an error.
    assert!(apk.open_asset("missing.bin").is_none());
    assert!(apk.get_file_data("lib/arm64-v8a/nope.so").is_none());

    // Signatures: BTreeMap iteration is lexicographic on the entry name,
    // so `CERT.EC` precedes `CERT.RSA`. The IGNORED.TXT entry is filtered.
    let sigs = apk.get_signatures();
    assert_eq!(sigs.len(), 2, "signatures: {sigs:?}");
    assert_eq!(sigs[0], b"\x30\xec-cert\x00");
    assert_eq!(sigs[1], b"\x30\x82\x01\x00this-is-not-a-real-cert\x00");

    // parent_file is the directory we wrote the apk into.
    assert_eq!(apk.parent_file(), Some(dir.as_path()));

    cleanup(&dir);
}

#[test]
fn apk_factory_dispatches_dir() {
    // Directory path -> ApkDir (text manifest).
    let dir = unique_tmp("dispatch-dir");
    let manifest_text = br#"<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.raxdbg.dispatchdir"
          android:versionCode="7"
          android:versionName="0.9.0">
</manifest>
"#;
    fs::write(dir.join("AndroidManifest.xml"), manifest_text).expect("write manifest");

    let apk = open(&dir).expect("open dir");
    assert_eq!(apk.package_name(), "com.raxdbg.dispatchdir");
    assert_eq!(apk.version_code(), 7);
    assert_eq!(apk.version_name(), "0.9.0");
    assert_eq!(apk.manifest_xml(), manifest_text);
    assert_eq!(apk.parent_file(), Some(dir.parent().unwrap()));

    cleanup(&dir);
}

#[test]
fn apk_factory_rejects_neither() {
    // Neither a file nor a directory.
    let bogus = std::env::temp_dir().join("raxdbg-android-apk-does-not-exist-xyz");
    let _ = fs::remove_file(&bogus);
    assert!(matches!(open(&bogus), Err(ApkError::Io(_))));
}
// ApkDir
// ---------------------------------------------------------------------------

#[test]
fn apk_dir_text_manifest() {
    let dir = unique_tmp("dir");
    let manifest_text = br#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.raxdbg.textdir"
          android:versionCode="13"
          android:versionName="text-1.0">
  <application/>
</manifest>
"#;
    fs::create_dir_all(dir.join("lib/arm64-v8a")).unwrap();
    fs::create_dir_all(dir.join("assets")).unwrap();
    fs::create_dir_all(dir.join("META-INF")).unwrap();
    fs::write(dir.join("AndroidManifest.xml"), manifest_text).unwrap();
    fs::write(
        dir.join("lib/arm64-v8a/libjnitest.so"),
        b"\x7fELF-text-dir\x00",
    )
    .unwrap();
    fs::write(dir.join("assets/bar.bin"), b"text-dir-asset").unwrap();
    fs::write(dir.join("META-INF/CERT.DSA"), b"\x30\x82\xd0\x01\x00\x00cert").unwrap();

    let apk = open(&dir).expect("open dir");
    assert_eq!(apk.package_name(), "com.raxdbg.textdir");
    assert_eq!(apk.version_code(), 13);
    assert_eq!(apk.version_name(), "text-1.0");
    assert_eq!(apk.manifest_xml(), manifest_text);

    let libso = apk
        .get_file_data("lib/arm64-v8a/libjnitest.so")
        .expect("libso");
    assert_eq!(libso, b"\x7fELF-text-dir\x00");

    let asset = apk.open_asset("bar.bin").expect("asset");
    assert_eq!(asset, b"text-dir-asset");

    let sigs = apk.get_signatures();
    assert_eq!(sigs, vec![b"\x30\x82\xd0\x01\x00\x00cert".to_vec()]);

    assert_eq!(apk.parent_file(), Some(dir.parent().unwrap()));

    cleanup(&dir);
}

#[test]
fn apk_dir_unzipped_binary_axml() {
    // When an unzipped directory happens to contain a binary AXML
    // (e.g. an apktool-rebuilt tree), the parser must still recognise it.
    let dir = unique_tmp("dir-binary");
    let axml = build_synthetic_axml("com.raxdbg.binaaa", 99, "binary-0.1");
    fs::write(dir.join("AndroidManifest.xml"), &axml).unwrap();

    let apk = open(&dir).expect("open dir");
    assert_eq!(apk.package_name(), "com.raxdbg.binaaa");
    assert_eq!(apk.version_code(), 99);
    assert_eq!(apk.version_name(), "binary-0.1");
    assert_eq!(apk.manifest_xml(), axml.as_slice());

    cleanup(&dir);
}