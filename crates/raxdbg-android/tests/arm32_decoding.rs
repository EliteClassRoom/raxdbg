//! Does the CPU and the disassembler agree on where Thumb instructions start?
//!
//! The arm32 bionic initialiser faulted at a PC whose linear disassembly did not
//! match the instruction boundaries the CPU actually executed, so this walks a
//! real Thumb code stream with both rules and reports every place they differ.
//! rax decides with `ThumbDecoder::is_32bit_instruction` (2 bytes or 4);
//! yaxpeax decides from the encoding's own top bits.

use rax::isa::arm::decoder::ThumbDecoder;
use raxdbg_android::android_file::ElfLibraryFile;
use raxdbg_android::emulator::AndroidEmulatorBuilder;
use raxdbg_core::memory::Memory;

/// yaxpeax's rule: a Thumb halfword in `11101`/`11110`/`11111` starts a 32-bit
/// instruction.
fn yaxpeax_size(halfword: u16) -> usize {
    if matches!(halfword >> 11, 0b11101 | 0b11110 | 0b11111) {
        4
    } else {
        2
    }
}

#[test]
fn the_two_decoders_agree_on_instruction_boundaries() {
    let emulator = AndroidEmulatorBuilder::for_32bit()
        .process_name("raxdbg-decoding")
        .build()
        .expect("emulator");
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("libs/android/sdk23/lib/libc.so");
    let file = ElfLibraryFile::open(&path).expect("open libc");
    emulator.load(Box::new(file), false).expect("load libc");
    let base = emulator
        .loader()
        .module_infos()
        .into_iter()
        .find(|module| module.name.contains("libc"))
        .expect("libc module")
        .base;

    // Walk the whole of libc's code, not just the window the fault was seen in:
    // this is a guard on the disassembler as much as a diagnosis.
    let start = base;
    let bytes = emulator
        .memory()
        .pointer(start)
        .get_bytes(0, 0x84000)
        .expect("read libc");

    let mut offset = 0usize;
    let mut disagreements = Vec::new();
    while offset + 4 <= bytes.len() {
        let half = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let rax_size = if ThumbDecoder::is_32bit_instruction(half) { 4 } else { 2 };
        let yax_size = yaxpeax_size(half);
        if rax_size != yax_size {
            disagreements.push((start + offset as u64, half, rax_size, yax_size));
            // Re-synchronise on the CPU's view, which is what actually ran.
            offset += rax_size;
            continue;
        }
        offset += rax_size;
    }

    for (address, half, rax_size, yax_size) in &disagreements {
        println!("DISAGREE {address:#x}: half={half:#06x} rax={rax_size} yaxpeax={yax_size}");
    }
    println!(
        "walked {:#x} bytes from {start:#x}: {} disagreements",
        bytes.len(),
        disagreements.len()
    );
    assert!(
        disagreements.is_empty(),
        "the CPU and the disassembler disagree about instruction boundaries: {:?}",
        &disagreements[..disagreements.len().min(8)]
    );
}
