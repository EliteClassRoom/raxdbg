//! Shared helpers for the backend integration tests.
#![allow(dead_code)]

use std::sync::Arc;

use rax::isa::arm::aarch64::AArch64Config;
use rax::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};
use raxdbg_backend_rax::{MemShared, RaxArm32Cpu, RaxArm64Cpu, RaxBackend};
use raxdbg_core::backend::{Backend, Prot};

/// Address the test code is mapped at.
pub const CODE: u64 = 0x1000;
/// Address the test data page is mapped at.
pub const DATA: u64 = 0x2000;

/// A 16 MiB arena address space, as rax's own user tests build.
pub fn new_space() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        va_limit: 1 << 48,
        arena_bytes: 16 * 1024 * 1024,
        reserved_phys: Vec::new(),
    })
    .expect("address space")
}

/// Maps one page at `addr` with `perms`.
pub fn map_page(space: &AddressSpace, addr: u64, perms: Perms) {
    space
        .map(addr, 0x1000, Mapping::anonymous(perms))
        .expect("map page");
}

/// Maps an RWX page at [`CODE`] holding `words`, little-endian.
pub fn map_code(space: &AddressSpace, words: &[u32]) {
    map_page(space, CODE, Perms::READ | Perms::WRITE | Perms::EXEC);
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    space.write(CODE, &bytes).expect("write code");
}

/// Maps an RWX page at [`CODE`] holding raw bytes (for Thumb code).
pub fn map_code_bytes(space: &AddressSpace, bytes: &[u8]) {
    map_page(space, CODE, Perms::READ | Perms::WRITE | Perms::EXEC);
    space.write(CODE, bytes).expect("write code");
}

/// Maps an RW data page at [`DATA`].
pub fn map_data(space: &AddressSpace) {
    map_page(space, DATA, Perms::READ | Perms::WRITE);
}

/// An AArch64 backend with `words` at [`CODE`].
pub fn arm64_backend(words: &[u32]) -> RaxBackend {
    let space = new_space();
    map_code(&space, words);
    RaxBackend::new_arm64(space)
}

/// An AArch32 backend with `bytes` at [`CODE`].
pub fn arm32_backend(bytes: &[u8]) -> RaxBackend {
    let space = new_space();
    map_code_bytes(&space, bytes);
    RaxBackend::new_arm32(space)
}

/// The rax address space behind a backend, for tests that also drive rax's own
/// adapters over the same memory.
pub fn space_of(backend: &RaxBackend) -> AddressSpace {
    backend.address_space().clone()
}

/// An AArch64 adapter over `space` with the configuration the backend uses.
pub fn rax_arm64_adapter(space: &AddressSpace) -> RaxArm64Cpu {
    RaxArm64Cpu::new(AArch64Config::v8_2(), Arc::new(MemShared::new(space.clone())))
}

/// An AArch32 adapter over `space`.
pub fn rax_arm32_adapter(space: &AddressSpace) -> RaxArm32Cpu {
    RaxArm32Cpu::new(Arc::new(MemShared::new(space.clone())))
}

/// Maps `size` bytes of RW memory through the backend.
pub fn map_rw(backend: &mut RaxBackend, addr: u64, size: u64) {
    backend
        .mem_map(addr, size, Prot::READ.union(Prot::WRITE))
        .expect("map");
}

/// AArch64 instruction encodings used by the tests.
pub mod a64 {
    /// `mov x0, #imm16`.
    pub const fn mov_x0(imm: u16) -> u32 {
        0xd280_0000 | ((imm as u32) << 5)
    }

    /// `mov x1, #imm16`.
    pub const fn mov_x1(imm: u16) -> u32 {
        0xd280_0000 | ((imm as u32) << 5) | 1
    }

    /// `add x0, x0, #1`.
    pub const fn add_x0_1() -> u32 {
        0x9100_0400
    }

    /// `svc #imm16`.
    pub const fn svc(imm: u16) -> u32 {
        0xd400_0001 | ((imm as u32) << 5)
    }

    /// `brk #imm16`.
    pub const fn brk(imm: u16) -> u32 {
        0xd420_0000 | ((imm as u32) << 5)
    }

    /// `ret`.
    pub const fn ret() -> u32 {
        0xd65f_03c0
    }

    /// `nop`.
    pub const fn nop() -> u32 {
        0xd503_201f
    }

    /// `ldr x1, [x0]`.
    pub const fn ldr_x1_x0() -> u32 {
        0xf940_0001
    }

    /// `ldr x2, [x0]`.
    pub const fn ldr_x2_x0() -> u32 {
        0xf940_0002
    }

    /// `str x1, [x0]`.
    pub const fn str_x1_x0() -> u32 {
        0xf900_0001
    }

    /// `fadd d0, d1, d2`.
    pub const fn fadd_d0_d1_d2() -> u32 {
        0x1e62_2820
    }

    /// `add v0.16b, v1.16b, v2.16b`.
    pub const fn add_v0_v1_v2() -> u32 {
        0x4e22_8420
    }

    /// `undef` (an unallocated encoding).
    pub const fn undefined() -> u32 {
        0x0000_0000
    }
}

/// AArch32 instruction encodings used by the tests.
pub mod a32 {
    /// `mov r0, #imm8` (ARM state).
    pub const fn mov_r0(imm: u8) -> u32 {
        0xe3a0_0000 | imm as u32
    }

    /// `add r0, r0, #1` (ARM state).
    pub const fn add_r0_1() -> u32 {
        0xe280_0001
    }

    /// `bx lr` (ARM state).
    pub const fn bx_lr() -> u32 {
        0xe12f_ff1e
    }

    /// `svc #0` (ARM state).
    pub const fn svc0() -> u32 {
        0xef00_0000
    }

    /// `movs r0, #imm8` (Thumb, T16).
    pub const fn t16_movs_r0(imm: u8) -> u16 {
        0x2000 | imm as u16
    }

    /// `adds r0, #1` (Thumb, T16).
    pub const fn t16_adds_r0_1() -> u16 {
        0x3001
    }

    /// `bx lr` (Thumb, T16).
    pub const fn t16_bx_lr() -> u16 {
        0x4770
    }

    /// `nop` (Thumb, T16).
    pub const fn t16_nop() -> u16 {
        0xbf00
    }

    /// Packs 32-bit ARM words into bytes.
    pub fn words(words: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(words.len() * 4);
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Packs 16-bit Thumb halfwords into bytes.
    pub fn halfwords(halfwords: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(halfwords.len() * 2);
        for halfword in halfwords {
            bytes.extend_from_slice(&halfword.to_le_bytes());
        }
        bytes
    }
}
