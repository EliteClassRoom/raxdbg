# Vendored rax

Copy of [HexRaysSA/rax](https://github.com/HexRaysSA/rax) at commit
`c468ca32087553bb6c16aad10c17c08fee24ce95` (MIT AND BSD-3-Clause), vendored
because raxdbg needs two engine items that are not public upstream. See
`../crates/raxdbg-backend-rax/RAX_API.md` for the full list of rax items raxdbg
depends on.

## What was copied

* `src/**` (the crate's `include` list ships exactly these files)
* `Cargo.toml`, `Cargo.lock`, `LICENSE`, `LICENSES/`, `README.md`,
  `THIRD_PARTY_NOTICES.md`

`Cargo.toml` differs from upstream only in packaging:

* the `[workspace]` table no longer declares the `capi` member (not vendored),
  so the copy is its own workspace root and raxdbg's workspace does not absorb
  it;
* the `[[test]]` targets are dropped (the `tests/` tree is not vendored).

## Patch 1 — `CPACR_EL1` accessors

`src/isa/arm/aarch64/cpu/user_mode.rs`:

```rust
pub fn cpacr_el1(&self) -> u64;
pub fn set_cpacr_el1(&mut self, value: u64);
```

Why: rax's AArch64 core traps every FP/SIMD instruction at EL0 unless
`CPACR_EL1.FPEN == 0b11` (`src/isa/arm/aarch64/cpu/simd/fp.rs`,
`src/isa/arm/aarch64/cpu/memory.rs`), and `sysregs` is private with no
accessor. Real bionic code needs FP/SIMD — NEON string routines, floating-point
`printf`, `memcpy` on wide registers — so an EL0 embedder without this cannot
run it. Two accessors are the whole patch; no behaviour changes.

To re-vendor after a rax update: copy `src/**` and the manifest from the new
rev, re-apply the packaging changes and this patch, then run
`cargo test -p raxdbg-backend-rax` (the differential tests in
`crates/raxdbg-backend-rax/tests/diff_rax_adapters.rs` guard the engine
behaviour raxdbg copies).
