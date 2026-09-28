//! Guest register identifiers.
//!
//! Port of unidbg's register model: the set of `RegId`s is exactly the set of
//! unicorn register constants unidbg touches, enumerated from the reference
//! tree (`Arm64Const.UC_ARM64_REG_*` / `ArmConst.UC_ARM_REG_*`).
//!
//! Aliases are modelled once and resolved by the backend for the ISA it runs:
//! [`RegId::Lr`] is `X30` on AArch64 and `R14` on AArch32, [`RegId::Sp`] is
//! `SP_EL0` / `R13`, [`RegId::D`] is one of 32 AArch64 `D` registers or one of
//! 16 AArch32 `D` registers, and so on. A backend rejects a register that its
//! ISA does not have.

use std::fmt;

/// A guest register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RegId {
    // ---- AArch64 general purpose -------------------------------------
    /// `X0`-`X30`.
    X(u8),
    /// `W0`-`W30` (the low 32 bits of `X0`-`X30`).
    W(u8),
    /// `XZR` (reads 0, writes discarded).
    Xzr,
    /// `WZR` (reads 0, writes discarded).
    Wzr,
    /// `SP_EL0` on AArch64, `R13` on AArch32.
    Sp,
    /// `WSP` (the low 32 bits of `SP_EL0`).
    Wsp,
    /// The program counter.
    Pc,
    /// `X30` on AArch64, `R14` on AArch32.
    Lr,
    /// `X29` on AArch64, `R11` on AArch32.
    Fp,
    /// `X16` on AArch64, `R12` on AArch32.
    Ip,
    /// `X17` (AArch64 `IP1`).
    Ip1,

    // ---- AArch64 flags and system registers --------------------------
    /// `NZCV` as a 32-bit value (`N<<31 | Z<<30 | C<<29 | V<<28`).
    Nzcv,
    /// `CPACR_EL1`.
    CpacrEl1,
    /// `TPIDR_EL0` (thread pointer, the guest's TLS base).
    TpidrEl0,
    /// `TPIDRRO_EL0` (read-only thread pointer).
    TpidrroEl0,

    // ---- AArch32 general purpose -------------------------------------
    /// `R0`-`R15`.
    R(u8),
    /// `R9` (platform register).
    Sb,
    /// `R10` (stack limit).
    Sl,

    // ---- SIMD / VFP --------------------------------------------------
    /// `Q0`-`Q31` (AArch64 only).
    Q(u8),
    /// `D0`-`D31` on AArch64, `D0`-`D15` on AArch32.
    D(u8),
    /// `S0`-`S31` (AArch64 only).
    S(u8),
    /// `H0`-`H31` (AArch64 only).
    H(u8),
    /// `B0`-`B31` (AArch64 only).
    B(u8),

    // ---- AArch32 status / system registers ---------------------------
    /// `CPSR`.
    Cpsr,
    /// `FPEXC`.
    Fpexc,
    /// `FPSCR`.
    Fpscr,
    /// Coprocessor register `C1_C0_2` (AArch32 `CPACR`).
    C1C0_2,
    /// Coprocessor register `C13_C0_3` (AArch32 thread pointer, `TPIDRURO`).
    C13C0_3,
}

impl RegId {
    /// `X0`-`X30`.
    pub const fn x(n: u8) -> Self {
        RegId::X(n)
    }

    /// `W0`-`W30`.
    pub const fn w(n: u8) -> Self {
        RegId::W(n)
    }

    /// `R0`-`R15`.
    pub const fn r(n: u8) -> Self {
        RegId::R(n)
    }

    /// `D0`-`D31`.
    pub const fn d(n: u8) -> Self {
        RegId::D(n)
    }

    /// The `X` register a `W` register aliases, if any.
    pub const fn wide(self) -> Option<RegId> {
        match self {
            RegId::W(n) if n <= 30 => Some(RegId::X(n)),
            RegId::Wsp => Some(RegId::Sp),
            _ => None,
        }
    }

    /// Whether writing this register has no effect and reading yields 0.
    pub const fn is_zero(self) -> bool {
        matches!(self, RegId::Xzr | RegId::Wzr)
    }

    /// Whether this register is one of the 128-bit vector registers.
    pub const fn is_vector(self) -> bool {
        matches!(
            self,
            RegId::Q(_) | RegId::D(_) | RegId::S(_) | RegId::H(_) | RegId::B(_)
        )
    }
}

impl fmt::Display for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegId::X(n) => write!(f, "x{n}"),
            RegId::W(n) => write!(f, "w{n}"),
            RegId::Xzr => f.write_str("xzr"),
            RegId::Wzr => f.write_str("wzr"),
            RegId::Sp => f.write_str("sp"),
            RegId::Wsp => f.write_str("wsp"),
            RegId::Pc => f.write_str("pc"),
            RegId::Lr => f.write_str("lr"),
            RegId::Fp => f.write_str("fp"),
            RegId::Ip => f.write_str("ip"),
            RegId::Ip1 => f.write_str("ip1"),
            RegId::Nzcv => f.write_str("nzcv"),
            RegId::CpacrEl1 => f.write_str("cpacr_el1"),
            RegId::TpidrEl0 => f.write_str("tpidr_el0"),
            RegId::TpidrroEl0 => f.write_str("tpidrro_el0"),
            RegId::R(n) => write!(f, "r{n}"),
            RegId::Sb => f.write_str("sb"),
            RegId::Sl => f.write_str("sl"),
            RegId::Q(n) => write!(f, "q{n}"),
            RegId::D(n) => write!(f, "d{n}"),
            RegId::S(n) => write!(f, "s{n}"),
            RegId::H(n) => write!(f, "h{n}"),
            RegId::B(n) => write!(f, "b{n}"),
            RegId::Cpsr => f.write_str("cpsr"),
            RegId::Fpexc => f.write_str("fpexc"),
            RegId::Fpscr => f.write_str("fpscr"),
            RegId::C1C0_2 => f.write_str("c1_c0_2"),
            RegId::C13C0_3 => f.write_str("c13_c0_3"),
        }
    }
}

/// Every AArch64 register id, in the order unidbg's ARM64 tests touch them.
pub const ARM64_REGS: &[RegId] = &[
    RegId::X(0),
    RegId::X(1),
    RegId::X(2),
    RegId::X(3),
    RegId::X(4),
    RegId::X(5),
    RegId::X(6),
    RegId::X(7),
    RegId::X(8),
    RegId::X(9),
    RegId::X(10),
    RegId::X(11),
    RegId::X(12),
    RegId::X(13),
    RegId::X(14),
    RegId::X(15),
    RegId::X(16),
    RegId::X(17),
    RegId::X(18),
    RegId::X(19),
    RegId::X(20),
    RegId::X(21),
    RegId::X(22),
    RegId::X(23),
    RegId::X(24),
    RegId::X(25),
    RegId::X(26),
    RegId::X(27),
    RegId::X(28),
    RegId::X(29),
    RegId::X(30),
    RegId::W(0),
    RegId::W(1),
    RegId::W(2),
    RegId::W(3),
    RegId::W(4),
    RegId::W(5),
    RegId::W(6),
    RegId::W(7),
    RegId::W(8),
    RegId::W(9),
    RegId::W(10),
    RegId::W(11),
    RegId::W(12),
    RegId::W(13),
    RegId::W(14),
    RegId::W(15),
    RegId::W(16),
    RegId::W(17),
    RegId::W(18),
    RegId::W(19),
    RegId::W(20),
    RegId::W(21),
    RegId::W(22),
    RegId::W(23),
    RegId::W(24),
    RegId::W(25),
    RegId::W(26),
    RegId::W(27),
    RegId::W(28),
    RegId::W(29),
    RegId::W(30),
    RegId::Xzr,
    RegId::Wzr,
    RegId::Sp,
    RegId::Wsp,
    RegId::Pc,
    RegId::Lr,
    RegId::Fp,
    RegId::Ip,
    RegId::Ip1,
    RegId::Nzcv,
    RegId::CpacrEl1,
    RegId::TpidrEl0,
    RegId::TpidrroEl0,
];

/// Every AArch32 register id.
pub const ARM32_REGS: &[RegId] = &[
    RegId::R(0),
    RegId::R(1),
    RegId::R(2),
    RegId::R(3),
    RegId::R(4),
    RegId::R(5),
    RegId::R(6),
    RegId::R(7),
    RegId::R(8),
    RegId::R(9),
    RegId::R(10),
    RegId::R(11),
    RegId::R(12),
    RegId::R(13),
    RegId::R(14),
    RegId::R(15),
    RegId::Sb,
    RegId::Sl,
    RegId::Sp,
    RegId::Lr,
    RegId::Pc,
    RegId::Fp,
    RegId::Ip,
    RegId::Cpsr,
    RegId::Fpexc,
    RegId::C1C0_2,
    RegId::C13C0_3,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_resolve_per_isa() {
        assert_eq!(RegId::W(3).wide(), Some(RegId::X(3)));
        assert_eq!(RegId::Wsp.wide(), Some(RegId::Sp));
        assert_eq!(RegId::W(31), RegId::W(31));
        assert!(RegId::Xzr.is_zero());
        assert!(!RegId::X(0).is_zero());
        assert!(RegId::Q(31).is_vector());
        assert!(!RegId::Cpsr.is_vector());
    }

    #[test]
    fn register_lists_are_unique() {
        for list in [ARM64_REGS, ARM32_REGS] {
            let mut seen = list.to_vec();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), list.len(), "duplicate register id in {list:?}");
        }
    }
}
