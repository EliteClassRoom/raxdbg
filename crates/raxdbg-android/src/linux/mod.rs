//! Linux-side host services for the Android emulator.
//!
//! Port of unidbg's `unidbg-android/src/main/java/com/github/unidbg/linux/`
//! package: the Android resource resolver, the virtual modules bionic expects
//! (`libandroid.so`, the system properties), the `libdl` trampolines, and the
//! thread glue.

pub mod android;
