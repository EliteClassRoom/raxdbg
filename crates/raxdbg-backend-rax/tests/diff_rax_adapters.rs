//! Differential tests: raxdbg's adapters against rax's own user-mode adapters.
//!
//! The plan's guard for plan decision D2 — our adapters copy rax's exit
//! classification and fetch/execute sequence, so the only way to keep the copy
//! faithful across rax updates is to run the same code through both and compare
//! the whole machine state.
//!
//! Both adapters run over separate address spaces holding identical contents,
//! so memory writes do not leak between them.

mod common;

use common::{a32, a64, new_space, CODE, DATA};
use rax::isa::arm::aarch64::AArch64Config;
use rax::isa::arm::aarch64::AArch64Cpu;
use rax::isa::arm::common::cpu::ArmCpu;
use rax::isa::arm::{Armv7Cpu, ProcessorMode, Psr};
use rax::user::cpu::aarch64::A64UserCpu;
use rax::user::cpu::arm::A32UserCpu;
use rax::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};
use raxdbg_backend_rax::RaxArm64Cpu;
use std::sync::Arc;

use raxdbg_backend_rax::{MemShared, RaxArm32Cpu};

fn space_with(code: &[u8], data: &[u8]) -> AddressSpace {
    let space = new_space();
    space
        .map(CODE, 0x1000, Mapping::anonymous(Perms::READ | Perms::WRITE | Perms::EXEC))
        .expect("map code");
    space
        .map(DATA, 0x1000, Mapping::anonymous(Perms::READ | Perms::WRITE))
        .expect("map data");
    space.write(CODE, code).expect("write code");
    space.write(DATA, data).expect("write data");
    space
}

fn read_page(space: &AddressSpace) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    space.read(DATA, &mut buf).expect("read data page");
    buf
}

fn words(code: &[u32]) -> Vec<u8> {
    a32::words(code)
}

/// Every AArch64 register both adapters must agree on.
fn snapshot64(core: &AArch64Cpu) -> Vec<u64> {
    let mut out = Vec::with_capacity(64);
    for reg in 0..31u8 {
        out.push(core.get_x(reg));
    }
    out.push(core.get_sp());
    out.push(core.get_pc());
    out.push(u64::from(core.nzcv_bits()));
    out.push(u64::from(core.fpcr_value()));
    out.push(u64::from(core.fpsr_value()));
    out.push(core.tpidr_el0());
    out.push(core.tpidrro_el0());
    for reg in 0..32u8 {
        let value = core.get_simd(reg);
        out.push(value as u64);
        out.push((value >> 64) as u64);
    }
    out
}

/// Every AArch32 register both adapters must agree on.
fn snapshot32(core: &Armv7Cpu) -> Vec<u64> {
    let mut out = Vec::with_capacity(64);
    out.extend(core.regs.iter().map(|r| u64::from(*r)));
    out.push(u64::from(core.cpsr.to_u32()));
    out.extend(core.vfp.dregs.iter().copied());
    out.push(u64::from(core.vfp.fpscr.bits()));
    out.push(u64::from(core.vfp.fpexc));
    out.push(u64::from(core.cp15.tpidrurw));
    out.push(u64::from(core.cp15.tpidruro));
    out
}

/// Runs `code` through both AArch64 adapters and asserts they agree.
fn assert_arm64_matches(label: &str, code: &[u32], budget: u64, setup: impl Fn(&mut AArch64Cpu)) {
    let ours_space = space_with(&words(code), &0x1234_5678_9abc_def0u64.to_le_bytes());
    let theirs_space = space_with(&words(code), &0x1234_5678_9abc_def0u64.to_le_bytes());

    let mut ours = RaxArm64Cpu::new(AArch64Config::v8_2(), Arc::new(MemShared::new(ours_space.clone())));
    let mut theirs = A64UserCpu::new(&theirs_space);

    setup(ours.core_mut());
    setup(theirs.core_mut());
    ours.core_mut().set_x(0, DATA);
    theirs.core_mut().set_x(0, DATA);

    ours.run(budget);
    theirs.run(budget);

    let ours_state = snapshot64(ours.core());
    let theirs_state = snapshot64(theirs.core());
    assert_eq!(ours_state, theirs_state, "{label}: register files diverged");

    assert_eq!(
        read_page(&ours_space),
        read_page(&theirs_space),
        "{label}: memory diverged"
    );
}

/// Runs `code` through both AArch32 adapters and asserts they agree.
fn assert_arm32_matches(label: &str, code: &[u8], budget: u64) {
    let ours_space = space_with(code, &0x1234_5678u32.to_le_bytes());
    let theirs_space = space_with(code, &0x1234_5678u32.to_le_bytes());

    let mut ours = RaxArm32Cpu::new(Arc::new(MemShared::new(ours_space.clone())));
    let mut theirs = A32UserCpu::new(&theirs_space);

    ours.core_mut().regs[0] = DATA as u32;
    theirs.core_mut().regs[0] = DATA as u32;

    ours.run(budget);
    theirs.run(budget);

    let ours_state = snapshot32(ours.core());
    let theirs_state = snapshot32(theirs.core());
    assert_eq!(ours_state, theirs_state, "{label}: register files diverged");

    assert_eq!(
        read_page(&ours_space),
        read_page(&theirs_space),
        "{label}: memory diverged"
    );
}

fn no_setup(_cpu: &mut AArch64Cpu) {}

#[test]
fn arm64_arithmetic_matches_rax() {
    // mov x1,#5; mov x2,#7; add x3,x1,x2; sub x4,x1,x2; mul x5,x1,x2
    let code = [0xd280_00a1, 0xd280_00e2, 0x8b02_0023, 0xcb02_0024, 0x9b02_7c25];
    assert_arm64_matches("arithmetic", &code, 5, no_setup);
}

#[test]
fn arm64_flag_setting_arithmetic_matches_rax() {
    // adds x1,x2,x3; subs x4,x5,x6; cmp x1,x2; adc x7,x1,x2
    let code = [0xab03_0041, 0xeb06_00a4, 0xeb02_003f, 0x1a02_0027];
    assert_arm64_matches("flags", &code, 4, |cpu| {
        cpu.set_x(2, 0xffff_ffff_ffff_ffff);
        cpu.set_x(3, 1);
        cpu.set_x(5, 5);
        cpu.set_x(6, 9);
    });
}

#[test]
fn arm64_load_store_matches_rax() {
    // ldr x1,[x0]; str x1,[x0,#8]; ldr x2,[x0,#8]; str x2,[x0,#16]
    let code = [0xf940_0001, 0xf900_0401, 0xf940_0402, 0xf900_0802];
    assert_arm64_matches("load/store", &code, 4, no_setup);
}

#[test]
fn arm64_branches_match_rax() {
    // b #8; mov x1,#1; mov x2,#2; b #-4 (self)
    let code = [0x1400_0002, 0xd280_0021, 0xd280_0042, 0x1400_0000];
    assert_arm64_matches("branches", &code, 6, no_setup);
}

#[test]
fn arm64_fp_and_neon_match_rax() {
    // fadd d0,d1,d2; fmul d3,d4,d5; add v0.16b,v1.16b,v2.16b; sub v3.16b,v4.16b,v5.16b
    let code = [0x1e62_2820, 0x1e62_0883, 0x4e22_8420, 0x6e25_8483];
    assert_arm64_matches("fp/neon", &code, 4, |cpu| {
        cpu.set_simd(1, 0x3ff0_0000_0000_0000);
        cpu.set_simd(2, 0x4000_0000_0000_0000);
        cpu.set_simd(4, 0x4008_0000_0000_0000);
        cpu.set_simd(5, 0x3ff0_0000_0000_0000);
    });
}

#[test]
fn arm64_svc_and_undefined_agree_on_pc() {
    // A `mov`, then an SVC: both adapters must leave the PC past the SVC.
    let code = [a64::mov_x0(1), a64::svc(3), a64::nop()];
    let ours_space = space_with(&words(&code), &[0u8; 8]);
    let theirs_space = space_with(&words(&code), &[0u8; 8]);
    let mut ours = RaxArm64Cpu::new(AArch64Config::v8_2(), Arc::new(MemShared::new(ours_space)));
    let mut theirs = A64UserCpu::new(&theirs_space);

    let our_exit = ours.run(8);
    let their_exit = theirs.run(8);
    assert_eq!(
        format!("{our_exit:?}"),
        format!("{their_exit:?}"),
        "the SVC exit must match rax's"
    );

    let undef = words(&[0x0000_0000u32]);
    let ours_space = space_with(&undef, &[0u8; 8]);
    let theirs_space = space_with(&undef, &[0u8; 8]);
    let mut ours = RaxArm64Cpu::new(AArch64Config::v8_2(), Arc::new(MemShared::new(ours_space)));
    let mut theirs = A64UserCpu::new(&theirs_space);
    assert_eq!(
        format!("{:?}", ours.run(1)),
        format!("{:?}", theirs.run(1)),
        "the undefined-instruction exit must match rax's"
    );
}

#[test]
fn arm64_unmapped_fetch_agrees_on_the_fault() {
    let ours_space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 48,
        arena_bytes: 4 * 1024 * 1024,
        reserved_phys: Vec::new(),
    })
    .expect("space");
    let theirs_space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 48,
        arena_bytes: 4 * 1024 * 1024,
        reserved_phys: Vec::new(),
    })
    .expect("space");
    let mut ours = RaxArm64Cpu::new(AArch64Config::v8_2(), Arc::new(MemShared::new(ours_space)));
    let mut theirs = A64UserCpu::new(&theirs_space);
    ours.core_mut().set_pc(0x9000_0000);
    theirs.core_mut().set_pc(0x9000_0000);
    assert_eq!(
        format!("{:?}", ours.run(1)),
        format!("{:?}", theirs.run(1)),
        "the fault must match rax's"
    );
}

#[test]
fn arm32_arm_state_arithmetic_matches_rax() {
    // mov r1,#5; mov r2,#7; add r3,r1,r2; sub r4,r1,r2; mul r5,r1,r2
    let code = words(&[0xe3a0_1005, 0xe3a0_2007, 0xe081_3002, 0xe041_4002, 0xe000_0592]);
    assert_arm32_matches("arm arithmetic", &code, 5);
}

#[test]
fn arm32_load_store_matches_rax() {
    // ldr r1,[r0]; str r1,[r0,#8]; ldr r2,[r0,#8]; strb r2,[r0,#4]
    let code = words(&[0xe590_1000, 0xe580_1008, 0xe590_2008, 0xe5c0_2004]);
    assert_arm32_matches("arm load/store", &code, 4);
}

#[test]
fn arm32_branches_match_rax() {
    // b #8; mov r1,#1; mov r2,#2; b . (self)
    let code = words(&[0xea00_0002, 0xe3a0_1001, 0xe3a0_2002, 0xeaff_fffe]);
    assert_arm32_matches("arm branches", &code, 6);
}

#[test]
fn arm32_thumb_matches_rax() {
    // movs r1,#5; adds r1,#1; adds r2,r1,#3; bx lr
    let thumb = [0x2105u16, 0x3101, 0x1cc8, 0x4770];
    let mut code = a32::halfwords(&thumb);
    code.extend_from_slice(&[0, 0]);
    assert_arm32_matches("thumb", &code, 4);
}

#[test]
fn arm32_thumb32_matches_rax() {
    // `mov.w r1, #0x1234` (T32), `add.w r2, r1, #7` (T32), `nop`
    let t32: [u16; 3] = [0xf241, 0x2134, 0xbf00];
    let mut code = a32::halfwords(&t32);
    code.extend_from_slice(&[0, 0]);
    assert_arm32_matches("thumb32", &code, 2);
}

#[test]
fn arm32_vfp_matches_rax() {
    // vadd.f64 d0, d1, d2 ; vmul.f64 d3, d4, d5
    let code = words(&[0xee31_0b02, 0xee24_3b05]);
    let ours_space = space_with(&code, &[0u8; 8]);
    let theirs_space = space_with(&code, &[0u8; 8]);
    let mut ours = RaxArm32Cpu::new(Arc::new(MemShared::new(ours_space)));
    let mut theirs = A32UserCpu::new(&theirs_space);
    for core in [ours.core_mut(), theirs.core_mut()] {
        core.vfp.fpexc = 1 << 30;
        core.vfp.dregs[1] = 0x3ff0_0000_0000_0000;
        core.vfp.dregs[2] = 0x4000_0000_0000_0000;
        core.vfp.dregs[4] = 0x4008_0000_0000_0000;
        core.vfp.dregs[5] = 0x3ff0_0000_0000_0000;
    }
    ours.run(2);
    theirs.run(2);
    assert_eq!(snapshot32(ours.core()), snapshot32(theirs.core()));
}

#[test]
fn arm32_processor_mode_matches_rax() {
    // Both adapters must construct the same user-mode state.
    let ours_space = space_with(&words(&[a32::bx_lr()]), &[0u8; 8]);
    let theirs_space = space_with(&words(&[a32::bx_lr()]), &[0u8; 8]);
    let ours = RaxArm32Cpu::new(Arc::new(MemShared::new(ours_space)));
    let theirs = A32UserCpu::new(&theirs_space);
    assert_eq!(snapshot32(ours.core()), snapshot32(theirs.core()));
    assert_eq!(ours.core().cpsr.mode, ProcessorMode::User as u8);
    assert_eq!(theirs.core().cpsr.mode, ProcessorMode::User as u8);
    assert_eq!(
        ours.core().cpsr.to_u32(),
        Psr::from_u32(ProcessorMode::User as u32).to_u32()
    );
}
