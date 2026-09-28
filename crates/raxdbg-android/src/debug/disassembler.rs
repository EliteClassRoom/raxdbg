//! Disassembly through `yaxpeax-arm`.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/debugger/AssemblyCodeDumper.java`'s
//! decoding half@7f5da98e. unidbg reaches for capstone; raxdbg uses a pure Rust
//! decoder so the build has no C dependency (plan D9).

use raxdbg_core::debug::Disassembler;
use yaxpeax_arch::Decoder;

/// A disassembler for both supported instruction sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArmDisassembler {
    /// Decode as AArch32 (Thumb) rather than AArch64.
    pub thumb: bool,
}

impl ArmDisassembler {
    /// An AArch64 disassembler.
    pub fn arm64() -> Self {
        ArmDisassembler { thumb: false }
    }

    /// An AArch32 disassembler.
    pub fn arm32() -> Self {
        ArmDisassembler { thumb: false }
    }
}

impl Disassembler for ArmDisassembler {
    fn disassemble(&self, address: u64, bytes: &[u8], thumb: bool) -> Option<String> {
        if thumb || self.thumb {
            // The AArch32 decoder needs to know which state the instruction is
            // in; the ARM-state default cannot decode a Thumb encoding.
            let decoder = yaxpeax_arm::armv7::InstDecoder::default().with_thumb_mode(true);
            let mut reader = yaxpeax_arch::U8Reader::new(bytes);
            let instruction = decoder.decode(&mut reader).ok()?;
            Some(format!("{instruction}"))
        } else {
            let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
            let mut reader = yaxpeax_arch::U8Reader::new(bytes);
            let instruction = decoder.decode(&mut reader).ok()?;
            let _ = address;
            Some(format!("{instruction}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aarch64_decodes_a_move_and_a_return() {
        let disassembler = ArmDisassembler::arm64();
        let mov = 0xd280_0540u32.to_le_bytes();
        let text = disassembler.disassemble(0, &mov, false).expect("decode");
        assert!(text.contains("x0"), "{text}");
        let ret = 0xd65f_03c0u32.to_le_bytes();
        assert!(disassembler
            .disassemble(0, &ret, false)
            .expect("decode")
            .contains("ret"));
    }

    #[test]
    fn aarch32_decodes_a_thumb_move() {
        let disassembler = ArmDisassembler::arm32();
        let movs = 0x2001u16.to_le_bytes();
        let text = disassembler.disassemble(0, &movs, true).expect("decode");
        assert!(text.contains("r0"), "{text}");
    }
}
