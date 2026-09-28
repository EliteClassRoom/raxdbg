//! Binary Android manifest (AXML) parser.
//!
//! Port of unidbg's `apk-parser` `BinaryXmlParser` invocation as called from
//! `ApkFile` / `ApkDir` (unidbg delegates to `net.dongliu.apk.parser`, which is
//! itself a port of AOSP `frameworks/base/include/androidfw/ResourceTypes.h`).
//! We only need three attributes off the `<manifest>` start tag: `package`,
//! `android:versionCode` (resource id `0x0101021b`), `android:versionName`
//! (resource id `0x0101021c`). Parsing is strict: malformed chunks become
//! `AxmlError`, never silent fallbacks.
//!
//! Layout per `frameworks/base/libs/androidfw/ResourceTypes.cpp`:
//!
//! ```text
//! ResChunk_header   { u16 type, u16 header_size, u32 size }
//! StringPool        type 0x0003
//! ResourceMap       type 0x0180  (parallel to string pool: name_idx -> attr)
//! StartNamespace    type 0x0100  (optional)
//! EndNamespace      type 0x0101
//! StartElement      type 0x0102  (manifest start tag carries the metadata)
//! EndElement        type 0x0103
//! Cdata             type 0x0104  (skipped)
//! ```
//!
//! String encoding inside the pool: `flags & 0x100` selects UTF-8 (with a
//! varint-length prefix) versus UTF-16 (two-byte length, big-endian).

use std::fmt;

/// The three attributes pulled from the binary manifest start tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestMeta {
    pub package: String,
    pub version_code: i64,
    pub version_name: String,
}

/// Errors raised by the AXML parser.
#[derive(Debug)]
pub enum AxmlError {
    /// Chunk header reports a size larger than the input.
    Truncated { chunk_type: u16, declared: u32, available: usize },
    /// A chunk's `header_size` is smaller than the chunk header itself.
    BadHeaderSize { chunk_type: u16, header_size: u16 },
    /// An attribute referenced a string-pool index out of range.
    StringIndexOutOfRange { index: u32, count: u32 },
    /// The string-pool header is malformed (negative offsets, missing data).
    BadStringPool(&'static str),
    /// String entry length or encoding was corrupt.
    BadStringEntry(&'static str),
    /// A start tag referenced more attributes than its chunk could hold.
    AttributeOverflow { declared: u16, chunk_size: u32, header_size: u16 },
    /// Required top-level `<manifest>` element was not seen.
    MissingManifest,
    /// `android:versionCode` was present but not a parseable integer.
    BadVersionCode(String),
}

impl fmt::Display for AxmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AxmlError::Truncated { chunk_type, declared, available } => write!(
                f,
                "AXML chunk 0x{chunk_type:04x} declares size {declared} but only {available} bytes remain"
            ),
            AxmlError::BadHeaderSize { chunk_type, header_size } => write!(
                f,
                "AXML chunk 0x{chunk_type:04x} has headerSize {header_size} < 8"
            ),
            AxmlError::StringIndexOutOfRange { index, count } => write!(
                f,
                "AXML string-pool index {index} out of range (pool has {count} entries)"
            ),
            AxmlError::BadStringPool(msg) => write!(f, "AXML string pool: {msg}"),
            AxmlError::BadStringEntry(msg) => write!(f, "AXML string entry: {msg}"),
            AxmlError::AttributeOverflow { declared, chunk_size, header_size } => write!(
                f,
                "AXML start tag declares {declared} attributes but chunk size {chunk_size} and headerSize {header_size} cannot contain them"
            ),
            AxmlError::MissingManifest => write!(f, "AXML did not contain a <manifest> start tag"),
            AxmlError::BadVersionCode(s) => write!(f, "AXML android:versionCode={s:?} is not an integer"),
        }
    }
}

impl std::error::Error for AxmlError {}

/// Android system attribute resource ids (`R.attr.*`). See
/// `frameworks/base/core/res/res/values/attrs_manifest.xml`.
const ATTR_VERSION_CODE: u32 = 0x0101_021b;
const ATTR_VERSION_NAME: u32 = 0x0101_021c;
/// A plain (non-namespaced) attribute: the resource map leaves it as 0.
const ATTR_NONE: u32 = 0;

/// Parse an AXML blob and return the metadata fields the rest of the port
/// consumes.
pub fn parse_manifest(data: &[u8]) -> Result<ManifestMeta, AxmlError> {
    let mut cursor = Cursor::new(data);
    let mut strings: Option<StringPool> = None;
    let mut resource_map: Vec<u32> = Vec::new();
    // We hold the *first* manifest start tag we see. Real AXML puts manifest
    // as the outermost element; if there is no `<manifest>` we surface an
    // error rather than guessing from some inner element.
    let mut meta: Option<ManifestMeta> = None;

    while cursor.remaining() >= 8 {
        let chunk_start = cursor.pos;
        let chunk_type = cursor.u16()?;
        let header_size = cursor.u16()?;
        let chunk_size = cursor.u32()?;
        if header_size < 8 {
            return Err(AxmlError::BadHeaderSize { chunk_type, header_size });
        }
        let declared = chunk_size as usize;
        let available = data.len().saturating_sub(chunk_start);
        if declared < header_size as usize || declared > available {
            return Err(AxmlError::Truncated {
                chunk_type,
                declared: chunk_size,
                available,
            });
        }
        let chunk_end = chunk_start + declared;
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                let pool = StringPool::parse(&data[chunk_start..chunk_end])?;
                strings = Some(pool);
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                resource_map.clear();
                let count = (chunk_size as usize - header_size as usize) / 4;
                for _ in 0..count {
                    let id = cursor.u32()?;
                    resource_map.push(id);
                }
            }
            RES_XML_START_NAMESPACE_TYPE
            | RES_XML_END_NAMESPACE_TYPE
            | RES_XML_CDATA_TYPE => {
                // No fields of interest; skip the entire chunk body.
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool = strings
                    .as_ref()
                    .ok_or(AxmlError::BadStringPool("start tag before string pool"))?;
                let _line_number = cursor.u32()?;
                let _comment = cursor.u32()?;
                let _ns = cursor.u32()?;
                let name_idx = cursor.u32()?;
                let _attribute_start = cursor.u16()?;
                let attribute_size = cursor.u16()?;
                let attribute_count = cursor.u16()?;
                let _id_index = cursor.u16()?;
                let _class_index = cursor.u16()?;
                let _style_index = cursor.u16()?;
                let element_name = pool.get(name_idx)?;
                if element_name == "manifest" && meta.is_none() {
                    let after_header = chunk_start + header_size as usize;
                    let attr_bytes_total = chunk_size as usize - header_size as usize;
                    if attr_bytes_total
                        < (attribute_count as usize) * (attribute_size as usize)
                    {
                        return Err(AxmlError::AttributeOverflow {
                            declared: attribute_count,
                            chunk_size,
                            header_size,
                        });
                    }
                    let mut package: Option<String> = None;
                    let mut version_code: Option<i64> = None;
                    let mut version_name: Option<String> = None;
                    for i in 0..attribute_count as usize {
                        let attr_off = after_header + i * attribute_size as usize;
                        let attr_end = attr_off + attribute_size as usize;
                        let bytes = &data[attr_off..attr_end];
                        match Attribute::parse(bytes, pool, &resource_map)? {
                            Attribute::Package(value) => package = Some(value),
                            Attribute::VersionCode(value) => version_code = Some(value),
                            Attribute::VersionName(value) => version_name = Some(value),
                            Attribute::Other => {}
                        }
                    }
                    meta = Some(ManifestMeta {
                        package: package.ok_or(AxmlError::MissingManifest)?,
                        version_code: version_code.unwrap_or(0),
                        version_name: version_name.unwrap_or_default(),
                    });
                }
            }
            RES_XML_END_ELEMENT_TYPE => {
                // body: line, comment, ns, name (4 * u32)
            }
            _ => {
                // Unknown chunk type: ignore but still advance to chunk_end.
            }
        }
        cursor.jump_to(chunk_end)?;
    }

    meta.ok_or(AxmlError::MissingManifest)
}

enum Attribute {
    Package(String),
    VersionCode(i64),
    VersionName(String),
    Other,
}

impl Attribute {
    fn parse(
        bytes: &[u8],
        pool: &StringPool,
        resource_map: &[u32],
    ) -> Result<Attribute, AxmlError> {
        if bytes.len() < 20 {
            return Err(AxmlError::BadStringPool("attribute slice < 20 bytes"));
        }
        let mut c = Cursor::new(bytes);
        let _ns = c.u32()?;
        let name_idx = c.u32()?;
        let raw_value_idx = c.u32()?;
        let _typed_value_size = c.u16()?;
        let _typed_value_res0 = c.u8()?;
        let _typed_value_data_type = c.u8()?;
        let _typed_value_data = c.u32()?;

        let resource_id = resource_map
            .get(name_idx as usize)
            .copied()
            .unwrap_or(ATTR_NONE);
        let raw_value = if raw_value_idx == 0xFFFF_FFFF {
            String::new()
        } else {
            pool.get(raw_value_idx)?
        };

        match resource_id {
            ATTR_VERSION_CODE => {
                let v: i64 = raw_value
                    .parse()
                    .map_err(|_| AxmlError::BadVersionCode(raw_value))?;
                Ok(Attribute::VersionCode(v))
            }
            ATTR_VERSION_NAME => Ok(Attribute::VersionName(raw_value)),
            _ => {
                // The `<manifest>` element's `package` attribute is a plain
                // (non-namespaced) attribute with resource id 0.
                // Its name index points to the literal string "package".
                let name = pool.get(name_idx)?;
                if name == "package" && resource_id == ATTR_NONE {
                    Ok(Attribute::Package(raw_value))
                } else {
                    Ok(Attribute::Other)
                }
            }
        }
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn jump_to(&mut self, new_pos: usize) -> Result<(), AxmlError> {
        if new_pos > self.data.len() {
            return Err(AxmlError::BadStringPool("cursor past end of input"));
        }
        self.pos = new_pos;
        Ok(())
    }
    fn read(&mut self, n: usize) -> Result<&'a [u8], AxmlError> {
        if self.remaining() < n {
            return Err(AxmlError::BadStringPool("short read"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, AxmlError> {
        Ok(self.read(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AxmlError> {
        let bytes = self.read(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, AxmlError> {
        let bytes = self.read(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    fn parse(chunk: &[u8]) -> Result<StringPool, AxmlError> {
        if chunk.len() < 8 {
            return Err(AxmlError::BadStringPool("chunk shorter than header"));
        }
        let mut c = Cursor::new(&chunk[8..]);
        let string_count = c.u32()? as usize;
        let style_count = c.u32()? as usize;
        let flags = c.u32()?;
        let strings_start = c.u32()? as usize;
        let _styles_start = c.u32()?;
        let is_utf8 = (flags & UTF8_FLAG) != 0;
        let mut offsets = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            offsets.push(c.u32()? as usize);
        }
        for _ in 0..style_count {
            let _ = c.u32()?;
        }
        let strings_base = strings_start;
        if strings_base > chunk.len() {
            return Err(AxmlError::BadStringPool("stringsStart past chunk"));
        }
        let mut out = Vec::with_capacity(string_count);
        for &off in &offsets {
            let abs = strings_base + off;
            if abs > chunk.len() {
                return Err(AxmlError::BadStringPool("string offset past chunk"));
            }
            let s = if is_utf8 {
                decode_utf8_at(&chunk[abs..])?
            } else {
                decode_utf16_at(&chunk[abs..])?
            };
            out.push(s);
        }
        Ok(StringPool { strings: out })
    }
    fn get(&self, idx: u32) -> Result<String, AxmlError> {
        if idx == 0xFFFF_FFFF {
            return Err(AxmlError::StringIndexOutOfRange {
                index: idx,
                count: self.strings.len() as u32,
            });
        }
        if (idx as usize) >= self.strings.len() {
            return Err(AxmlError::StringIndexOutOfRange {
                index: idx,
                count: self.strings.len() as u32,
            });
        }
        Ok(self.strings[idx as usize].clone())
    }
}

fn decode_utf16_at(data: &[u8]) -> Result<String, AxmlError> {
    if data.len() < 2 {
        return Err(AxmlError::BadStringEntry("utf16 length truncated"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let bytes = &data[2..];
    let need = len.checked_mul(2).ok_or(AxmlError::BadStringEntry("utf16 length overflow"))?;
    if bytes.len() < need {
        return Err(AxmlError::BadStringEntry("utf16 payload truncated"));
    }
    let mut units = Vec::with_capacity(len);
    for i in 0..len {
        let off = i * 2;
        units.push(u16::from_be_bytes([bytes[off], bytes[off + 1]]));
    }
    String::from_utf16(&units).map_err(|_| AxmlError::BadStringEntry("utf16 decode failed"))
}

fn decode_utf8_at(data: &[u8]) -> Result<String, AxmlError> {
    if data.is_empty() {
        return Err(AxmlError::BadStringEntry("utf8 length truncated"));
    }
    let first = data[0];
    let (len, header_skip) = if first & 0x80 != 0 {
        if data.len() < 2 {
            return Err(AxmlError::BadStringEntry("utf8 two-byte length truncated"));
        }
        let high = (first & 0x7f) as usize;
        let low = data[1] as usize;
        (high.checked_shl(8).ok_or(AxmlError::BadStringEntry("utf8 length overflow"))? | low, 2)
    } else {
        (first as usize, 1)
    };
    let bytes = &data[header_skip..];
    if bytes.len() < len {
        return Err(AxmlError::BadStringEntry("utf8 payload truncated"));
    }
    std::str::from_utf8(&bytes[..len])
        .map(|s| s.to_string())
        .map_err(|_| AxmlError::BadStringEntry("utf8 decode failed"))
}

const UTF8_FLAG: u32 = 0x0100;
const RES_STRING_POOL_TYPE: u16 = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny UTF-16 string-pool chunk with N strings.
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

    fn build_start_tag(
        name_idx: u32,
        attrs: &[(u32, u32, u32)],
    ) -> Vec<u8> {
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
        out.extend_from_slice(&20u16.to_be_bytes()); // attributeStart (size of one attribute)
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
            out.push(0); // typedValueDataType (TYPE_NULL but unused)
            out.extend_from_slice(&0u32.to_be_bytes()); // typedValueData
        }
        out
    }

    #[test]
    fn parse_minimal_manifest() {
        // String-pool indices:
        //   0 = ""          1 = "manifest"      2 = "package"       3 = "com.raxdbg.test"
        //   4 = "versionCode" 5 = "42"           6 = "versionName"   7 = "1.2"
        let strings = [
            "",
            "manifest",
            "package",
            "com.raxdbg.test",
            "versionCode",
            "42",
            "versionName",
            "1.2",
        ];
        let mut blob = build_string_pool(&strings);
        // The resource map is parallel to the *entire* string pool (one u32
        // per pool entry). Empty strings have no resource id, so they are 0.
        let mut full_resmap = vec![0u32; strings.len()];
        full_resmap[4] = ATTR_VERSION_CODE;
        full_resmap[6] = ATTR_VERSION_NAME;
        blob.extend_from_slice(&build_resource_map(&full_resmap));
        // Attributes on <manifest>:
        //   (ns, name, rawValue)
        let attrs = [
            (0xFFFF_FFFFu32, 2u32, 3u32), // package="com.raxdbg.test"
            (0xFFFF_FFFFu32, 4u32, 5u32), // android:versionCode="42"
            (0xFFFF_FFFFu32, 6u32, 7u32), // android:versionName="1.2"
        ];
        blob.extend_from_slice(&build_start_tag(1, &attrs));

        let parsed = parse_manifest(&blob).expect("parse succeeds");
        assert_eq!(parsed.package, "com.raxdbg.test");
        assert_eq!(parsed.version_code, 42);
        assert_eq!(parsed.version_name, "1.2");
    }

    #[test]
    fn truncated_chunk_is_an_error() {
        // StringPool header with size much larger than the blob.
        let mut bad = Vec::new();
        bad.extend_from_slice(&RES_STRING_POOL_TYPE.to_be_bytes());
        bad.extend_from_slice(&28u16.to_be_bytes());
        bad.extend_from_slice(&1024u32.to_be_bytes());
        match parse_manifest(&bad) {
            Err(AxmlError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn missing_manifest_is_an_error() {
        // Only a resource map; no <manifest> element.
        let blob = build_resource_map(&[]);
        match parse_manifest(&blob) {
            Err(AxmlError::MissingManifest) => {}
            other => panic!("expected MissingManifest, got {other:?}"),
        }
    }
}