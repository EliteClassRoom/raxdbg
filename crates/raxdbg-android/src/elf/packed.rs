//! Android packed relocations, the `APS2` format.
//!
//! Port of unidbg: `unidbg-android/src/main/java/net/fornwall/jelf/{AndroidRelocation,AndroidRelocationIterator}.java`
//! and the `DT_ANDROID_REL`/`DT_ANDROID_RELA` handling in `ElfDynamicStructure`@7f5da98e.
//!
//! Since NDK r12 the Android linker packs a library's relative relocations into
//! a single `DT_ANDROID_REL` (`APS2`) blob, so `DT_REL`/`DT_RELSZ` are **zero**
//! for such a library and a loader that only reads the classic tables applies
//! none of them. `libcpp.so` is exactly that library: on both ABIs it has
//! `DT_ANDROID_REL(A)` and nothing else, which is why `libc++`'s `.init_array`
//! slot still held a raw virtual address.
//!
//! The encoding is a delta stream: a relocation count, a starting offset, then
//! groups that each fix the values their members share (the type, the offset
//! step, the addend) and store the rest as signed LEB128.

use goblin::elf::reloc::Reloc;

/// Why the packed table could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PackedError {
    /// The table does not begin with the `APS2` magic.
    #[error("packed relocations do not start with APS2 (found {found:?})")]
    BadMagic {
        /// The first four bytes.
        found: Vec<u8>,
    },
    /// The stream ended in the middle of a value.
    #[error("packed relocations ended after {read} bytes with {count} relocations still to read")]
    Truncated {
        /// How many bytes were read.
        read: usize,
        /// How many relocations were still outstanding.
        count: u64,
    },
    /// A group announced more relocations than the count allows.
    #[error("a group of {size} relocations overruns the remaining {remaining}")]
    GroupOverrun {
        /// The group's size.
        size: u64,
        /// How many relocations were left.
        remaining: u64,
    },
    /// An addend appeared in a `DT_ANDROID_REL` table, which has none.
    #[error("an addend was encoded in a table that has no addends")]
    UnexpectedAddend,
}

/// `RELOCATION_GROUPED_BY_INFO_FLAG`: every member shares one type.
const GROUPED_BY_INFO: u64 = 1;
/// `RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG`: every member steps the offset by
/// the same amount.
const GROUPED_BY_OFFSET_DELTA: u64 = 2;
/// `RELOCATION_GROUPED_BY_ADDEND_FLAG`: every member shares one addend step.
const GROUPED_BY_ADDEND: u64 = 4;
/// `RELOCATION_GROUP_HAS_ADDEND_FLAG`: the group carries addends at all.
const GROUP_HAS_ADDEND: u64 = 8;

/// A cursor over the packed stream.
struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    /// How many bits a value may use, so an over-long encoding is caught.
    bits: u32,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], bits: u32) -> Self {
        Reader {
            data,
            offset: 0,
            bits,
        }
    }

    /// A signed LEB128 value, sign-extended to `i64`.
    fn sleb128(&mut self) -> Result<i64, PackedError> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let Some(byte) = self.data.get(self.offset).copied() else {
                return Err(PackedError::Truncated {
                    read: self.offset,
                    count: 0,
                });
            };
            self.offset += 1;
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign-extend when the value is narrower than the target.
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                // unidbg reads these through `Utils.readSignedLeb128` with the
                // object size, which truncates to 32 bits on a 32-bit guest.
                if self.bits == 32 {
                    result = i64::from(result as i32);
                }
                return Ok(result);
            }
            if shift > 64 {
                return Err(PackedError::Truncated {
                    read: self.offset,
                    count: 0,
                });
            }
        }
    }
}

/// Decodes an `APS2` table into the relocations it stands for.
///
/// `rela` says whether the table carries addends, which is `DT_ANDROID_RELA`
/// rather than `DT_ANDROID_REL`. `bits` is the guest's word size: the offsets
/// and values in the stream are truncated to it, as unidbg's
/// `Utils.readSignedLeb128(buffer, 32 | 64)` does.
///
/// `data` starts *after* the four-byte `APS2` magic, which the caller has
/// already checked with [`has_magic`].
pub fn decode(data: &[u8], rela: bool, bits: u32) -> Result<Vec<Reloc>, PackedError> {
    let mut reader = Reader::new(data, bits);
    let mut remaining = reader.sleb128()? as u64;
    let mut offset = reader.sleb128()?;
    let mut info: u64 = 0;
    let mut addend: i64 = 0;

    let mut relocations = Vec::new();
    let mut group_size = 0u64;
    let mut group_index = 0u64;
    let mut group_flags = 0u64;
    let mut group_offset_delta = 0i64;

    while remaining > 0 {
        if group_index == group_size {
            // A new group: the values its members share come first.
            group_size = reader.sleb128()? as u64;
            group_flags = reader.sleb128()? as u64;
            if group_size > remaining {
                return Err(PackedError::GroupOverrun {
                    size: group_size,
                    remaining,
                });
            }
            group_offset_delta = if group_flags & GROUPED_BY_OFFSET_DELTA != 0 {
                reader.sleb128()?
            } else {
                0
            };
            if group_flags & GROUPED_BY_INFO != 0 {
                info = reader.sleb128()? as u64;
            }
            if group_flags & GROUP_HAS_ADDEND != 0 && group_flags & GROUPED_BY_ADDEND != 0 {
                if !rela {
                    return Err(PackedError::UnexpectedAddend);
                }
                addend += reader.sleb128()?;
            } else if group_flags & GROUP_HAS_ADDEND == 0 && rela {
                addend = 0;
            }
            group_index = 0;
        }

        if group_flags & GROUPED_BY_OFFSET_DELTA != 0 {
            offset += group_offset_delta;
        } else {
            offset += reader.sleb128()?;
        }
        if group_flags & GROUPED_BY_INFO == 0 {
            info = reader.sleb128()? as u64;
        }
        if group_flags & GROUP_HAS_ADDEND != 0 && group_flags & GROUPED_BY_ADDEND == 0 {
            if !rela {
                return Err(PackedError::UnexpectedAddend);
            }
            addend += reader.sleb128()?;
        }

        remaining -= 1;
        group_index += 1;
        // `r_info` is packed the same way the classic tables pack it, so the
        // split follows the guest's word size: a 32-bit guest keeps the symbol
        // above the low byte, a 64-bit one above the low word. unidbg does this
        // in `ElfRelocation.sym()`/`type()`, and getting it wrong turns an
        // AArch64 `R_AARCH64_RELATIVE` (1027) into a nonsense type.
        let (symbol_shift, type_mask) = if bits == 32 {
            (8u32, 0xffu64)
        } else {
            (32u32, 0xffff_ffffu64)
        };
        relocations.push(Reloc {
            r_offset: offset as u64,
            r_addend: rela.then_some(addend),
            r_sym: (info >> symbol_shift) as usize,
            r_type: (info & type_mask) as u32,
        });
    }
    Ok(relocations)
}

/// How many relocations the stream declares, without decoding it.
///
/// The count is the first value in the stream, so a decoder that stops early
/// shows up as a mismatch rather than as a short list nobody notices.
pub fn count(data: &[u8], bits: u32) -> Result<u64, PackedError> {
    let mut reader = Reader::new(data, bits);
    Ok(reader.sleb128()? as u64)
}

/// Whether `data` begins with the `APS2` magic.
pub fn has_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"APS2"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes `value` as signed LEB128, for building test streams.
    fn sleb(value: i64) -> Vec<u8> {
        let mut value = value;
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
            out.push(if done { byte } else { byte | 0x80 });
            if done {
                return out;
            }
        }
    }

    #[test]
    fn signed_leb128_round_trips() {
        for value in [0i64, 1, -1, 63, 64, -64, -65, 127, 128, 1000, -1000, i32::MIN as i64] {
            let encoded = sleb(value);
            let mut reader = Reader::new(&encoded, 64);
            assert_eq!(reader.sleb128().unwrap(), value, "value {value}");
        }
    }

    #[test]
    fn a_32_bit_reader_truncates_as_unidbg_does() {
        // unidbg reads these with the object size, so a 32-bit guest sees the
        // low half sign-extended.
        let encoded = sleb(0x1_0000_0000);
        let mut reader = Reader::new(&encoded, 32);
        assert_eq!(reader.sleb128().unwrap(), 0);
    }

    #[test]
    fn a_single_grouped_relocation_decodes() {
        // count = 1, offset = 0x100, group of 1 with all three flags set.
        let mut data = sleb(1);
        data.extend(sleb(0x100));
        data.extend(sleb(1)); // group size
        data.extend(sleb((GROUPED_BY_INFO | GROUPED_BY_OFFSET_DELTA) as i64));
        data.extend(sleb(0)); // offset delta
        data.extend(sleb(23)); // info: R_ARM_RELATIVE with no symbol
        let relocations = decode(&data, false, 32).unwrap();
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].r_offset, 0x100);
        assert_eq!(relocations[0].r_type, 23);
        assert_eq!(relocations[0].r_sym, 0);
        assert_eq!(relocations[0].r_addend, None);
    }

    #[test]
    fn an_ungrouped_group_steps_its_offsets() {
        // Two relocations, offsets 0x10 then 0x18, types given per member.
        let mut data = sleb(2);
        data.extend(sleb(0x10));
        data.extend(sleb(2)); // group size
        data.extend(sleb(0)); // no flags
        data.extend(sleb(0)); // offset delta 0 -> 0x10
        data.extend(sleb(23)); // type
        data.extend(sleb(8)); // offset delta +8 -> 0x18
        data.extend(sleb(23));
        let relocations = decode(&data, false, 32).unwrap();
        assert_eq!(relocations.len(), 2);
        assert_eq!(relocations[0].r_offset, 0x10);
        assert_eq!(relocations[1].r_offset, 0x18);
        assert!(relocations.iter().all(|r| r.r_type == 23));
    }

    #[test]
    fn a_rela_table_carries_addends() {
        let mut data = sleb(1);
        data.extend(sleb(0x20));
        data.extend(sleb(1));
        data.extend(sleb(GROUP_HAS_ADDEND as i64));
        data.extend(sleb(0)); // offset delta
        data.extend(sleb(1027)); // R_AARCH64_RELATIVE
        data.extend(sleb(0x40)); // addend
        let relocations = decode(&data, true, 64).unwrap();
        assert_eq!(relocations[0].r_addend, Some(0x40));
    }

    #[test]
    fn the_info_split_follows_the_word_size() {
        // The same encoded value means different things on the two ABIs, which
        // is how an AArch64 relocation type came out as 3.
        let mut data = sleb(1);
        data.extend(sleb(0));
        data.extend(sleb(1));
        data.extend(sleb(0));
        data.extend(sleb(0));
        data.extend(sleb(0x403)); // 1027: R_AARCH64_RELATIVE, and sym 0
        let wide = decode(&data, false, 64).unwrap();
        assert_eq!(wide[0].r_type, 1027);
        assert_eq!(wide[0].r_sym, 0);

        // A symbol index above the low byte, as a 64-bit table would pack it.
        let mut data = sleb(1);
        data.extend(sleb(0));
        data.extend(sleb(1));
        data.extend(sleb(0));
        data.extend(sleb(0));
        data.extend(sleb((5i64 << 32) | 1027));
        let wide = decode(&data, false, 64).unwrap();
        assert_eq!(wide[0].r_sym, 5, "the symbol sits above the low word");
        assert_eq!(wide[0].r_type, 1027);
    }

    #[test]
    fn an_addend_in_a_rel_table_is_refused() {
        let mut data = sleb(1);
        data.extend(sleb(0));
        data.extend(sleb(1));
        data.extend(sleb(GROUP_HAS_ADDEND as i64));
        data.extend(sleb(0));
        data.extend(sleb(23));
        data.extend(sleb(4));
        assert!(matches!(
            decode(&data, false, 32),
            Err(PackedError::UnexpectedAddend)
        ));
    }

    #[test]
    fn a_group_larger_than_the_count_is_refused() {
        let mut data = sleb(1);
        data.extend(sleb(0));
        data.extend(sleb(99)); // a group of 99 with only 1 to read
        data.extend(sleb(0));
        assert!(matches!(
            decode(&data, false, 32),
            Err(PackedError::GroupOverrun { size: 99, remaining: 1 })
        ));
    }

    #[test]
    fn a_truncated_stream_is_an_error_not_a_short_list() {
        let data = sleb(3); // three relocations, then nothing
        assert!(decode(&data, false, 32).is_err());
    }

    #[test]
    fn the_declared_count_matches_what_decoding_produces() {
        let mut data = sleb(2);
        data.extend(sleb(0x10));
        data.extend(sleb(2));
        data.extend(sleb(0));
        data.extend(sleb(0));
        data.extend(sleb(23));
        data.extend(sleb(8));
        data.extend(sleb(23));
        assert_eq!(count(&data, 32).unwrap(), 2);
        assert_eq!(decode(&data, false, 32).unwrap().len(), 2);
    }

    #[test]
    fn the_magic_is_checked() {
        assert!(has_magic(b"APS2\0\0\0\0"));
        assert!(!has_magic(b"APS1\0\0\0\0"));
        assert!(!has_magic(b"AP"));
    }
}

#[cfg(test)]
mod real_library {
    //! What the decoder makes of libc++'s real `init_array` entry.
    use super::*;

    fn libcxx(rela: bool) -> (u64, u64, Vec<Reloc>) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .to_path_buf();
        let path = root.join(if rela {
            "libs/android/sdk23/lib64/libcpp.so"
        } else {
            "libs/android/sdk23/lib/libcpp.so"
        });
        let bytes = std::fs::read(&path).expect("read libcpp");
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse libcpp");
        let dynamic = elf.dynamic.as_ref().expect("dynamic");
        let tag = |want: u64| dynamic.dyns.iter().find(|e| e.d_tag == want).map(|e| e.d_val);
        let (offset, size) = if rela {
            (tag(0x6000_0011).expect("DT_ANDROID_RELA"), tag(0x6000_0012).expect("DT_ANDROID_RELASZ"))
        } else {
            (tag(0x6000_000f).expect("DT_ANDROID_REL"), tag(0x6000_0010).expect("DT_ANDROID_RELSZ"))
        };
        let file_offset = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
            .find(|header| offset >= header.p_vaddr && offset < header.p_vaddr + header.p_filesz)
            .map(|header| header.p_offset + (offset - header.p_vaddr))
            .expect("the table is mapped");
        let table = &bytes[file_offset as usize..(file_offset + size) as usize];
        assert!(has_magic(table), "the table starts with APS2");
        let bits = if rela { 64 } else { 32 };
        let relocations = decode(&table[4..], rela, bits).expect("decode");
        (tag(goblin::elf::dynamic::DT_INIT_ARRAY).expect("DT_INIT_ARRAY"), offset, relocations)
    }

    #[test]
    fn the_init_array_entry_is_a_relative_relocation_into_code() {
        for rela in [true, false] {
            let (init_array, table, relocations) = libcxx(rela);
            let entry = relocations
                .iter()
                .find(|relocation| relocation.r_offset == init_array)
                .unwrap_or_else(|| panic!("no relocation for the init_array entry at {init_array:#x}"));
            let relative = if rela { 1027 } else { 23 };
            assert_eq!(entry.r_type, relative, "the entry is a relative relocation");
            let addend = if rela {
                entry.r_addend.expect("a RELA entry has an addend")
            } else {
                // A REL entry keeps the value in the slot; the decoder reports
                // no addend, so read it from the file.
                let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .ancestors()
                    .nth(2)
                    .unwrap()
                    .to_path_buf();
                let path = root.join(if rela {
                    "libs/android/sdk23/lib64/libcpp.so"
                } else {
                    "libs/android/sdk23/lib/libcpp.so"
                });
                let bytes = std::fs::read(path).unwrap();
                let elf = goblin::elf::Elf::parse(&bytes).unwrap();
                let off: u64 = elf
                    .program_headers
                    .iter()
                    .filter(|h| h.p_type == goblin::elf::program_header::PT_LOAD)
                    .find(|h| init_array >= h.p_vaddr && init_array < h.p_vaddr + h.p_filesz)
                    .map(|h| h.p_offset + (init_array - h.p_vaddr))
                    .unwrap();
                if rela {
                    i64::from_le_bytes(bytes[off as usize..off as usize + 8].try_into().unwrap())
                } else {
                    i64::from(i32::from_le_bytes(bytes[off as usize..off as usize + 4].try_into().unwrap()))
                }
            };
            assert_ne!(addend, 0, "the initialiser's link-time address is in the table");
            // It must be code: the executable segment, not a data one.
            assert!(
                addend < 0x90000,
                "the initialiser {addend:#x} should be in libc++'s text, and the table is at {table:#x}"
            );
        }
    }
}
