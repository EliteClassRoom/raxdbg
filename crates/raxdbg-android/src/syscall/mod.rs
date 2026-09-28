//! The Android syscall layer.
//!
//! Plan P4: SVC dispatch, the fd table, host-backed file IO, and the arm64
//! syscall table. The four files in this module split along the same
//! lines as unidbg's Java tree:
//!
//! | File | unidbg reference |
//! |------|------------------|
//! | [`handler`] | `unidbg-api/.../unix/UnixSyscallHandler.java`, `IO.java`, `spi/SyscallHandler.java` |
//! | [`arm64`] | `unidbg-android/.../linux/ARM64SyscallHandler.java` |
//! | [`android`] | `unidbg-android/.../linux/AndroidSyscallHandler.java` |
//! | [`mod` (this file) | `unidbg-android` namespace glue |
//!
//! The SVC dispatcher lives in [`AndroidSyscallHandler::dispatch`]
//! (the `android` module); it routes the interrupt-hook callback into
//! the right path (stub call, real syscall, control-flow unwind) per the
//! plan P4.2 contract.

pub mod android;
pub mod arm64;
pub mod handler;

pub use android::{
    install_standard_descriptors, AndroidSyscallError, AndroidSyscallHandler,
    RefCellAndroidSyscallHandler, SyscallHook,
};
pub use arm64::{Arm64SyscallTable, Arm64ThreadState};
pub use handler::{
    SharedSink, SyscallError, UnixSyscallHandler, AT_FDCWD, CLOCK_BOOTTIME,
    CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_REALTIME, CLOCK_THREAD_CPUTIME_ID, O_APPEND, O_CREAT, O_RDONLY,
    O_RDWR, O_TRUNC, O_WRONLY,
};