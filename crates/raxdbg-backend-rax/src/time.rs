//! Monotonic host clock.
//!
//! rax drives guest-visible counters (`CNTVCT_EL0`, `CNTPCT`) and timeouts
//! from `rax::vm::timing::elapsed_nanos`, which is crate-private; raxdbg keeps
//! its own epoch so the counter update in the adapters matches rax's formula
//! without depending on a private item.

use std::sync::LazyLock;
use std::time::Instant;

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Nanoseconds since the process's clock epoch.
pub fn host_nanos() -> u64 {
    EPOCH.elapsed().as_nanos() as u64
}

/// Microseconds since the process's clock epoch.
pub fn host_micros() -> u64 {
    EPOCH.elapsed().as_micros() as u64
}
