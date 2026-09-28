//! Spike: drive rax's own AArch64 user adapter directly (no raxdbg adapter yet).
//!
//! Guards the assumptions in the plan's P0.7: the engine crate builds on
//! Windows, `AddressSpace` maps demand-paged anonymous memory, and
//! `A64UserCpu::run` classifies `SVC` at EL0 while preserving the register
//! file. If this test fails, every later phase is built on sand.

use rax::isa::arm::common::cpu::ArmCpu;
use rax::user::cpu::aarch64::{A64Exit, A64UserCpu};
use rax::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};

const CODE: u64 = 0x1000;

fn new_space() -> AddressSpace {
    AddressSpace::new(SpaceConfig {
        va_limit: 1 << 48,
        arena_bytes: 16 * 1024 * 1024,
        reserved_phys: Vec::new(),
    })
    .expect("address space")
}

fn map_code(space: &AddressSpace, words: &[u32]) {
    space
        .map(
            CODE,
            0x1000,
            Mapping::anonymous(Perms::READ | Perms::WRITE | Perms::EXEC),
        )
        .expect("map");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    space.write(CODE, &bytes).expect("write code");
}

/// `mov x0, #imm16` (64-bit MOV wide immediate).
fn mov_x0(imm: u16) -> u32 {
    0xd280_0000 | (u32::from(imm) << 5)
}

/// `svc #imm16`.
fn svc(imm: u16) -> u32 {
    0xd400_0001 | (u32::from(imm) << 5)
}

#[test]
fn svc_reaches_el0_and_preserves_registers() {
    let space = new_space();
    map_code(&space, &[mov_x0(0x2a), svc(0)]);

    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(CODE);

    let exit = cpu.run(16);

    assert!(
        matches!(exit, A64Exit::Svc { imm: 0, pc } if pc == CODE + 4),
        "expected SVC #0 at {:#x}, got {exit:?}",
        CODE + 4
    );
    assert_eq!(cpu.core().get_x(0), 0x2a);
    assert_eq!(cpu.core().get_pc(), CODE + 8);
}

#[test]
fn budget_yields_without_an_event() {
    let space = new_space();
    // `add x0, x0, #1` repeated, so no SVC is ever reached.
    let add = 0x9100_0400u32;
    map_code(&space, &[add; 8]);

    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(CODE);

    let exit = cpu.run(4);
    assert_eq!(exit, A64Exit::Yield);
    assert_eq!(cpu.core().get_x(0), 4);
    assert_eq!(cpu.core().get_pc(), CODE + 16);
}

#[test]
fn unmapped_fetch_reports_a_fault_with_pc_preserved() {
    let space = new_space();
    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(CODE);

    match cpu.run(1) {
        A64Exit::Fault(fault) => {
            assert_eq!(fault.pc, CODE);
            assert_eq!(fault.addr, CODE);
        }
        other => panic!("expected a fetch fault, got {other:?}"),
    }
}
