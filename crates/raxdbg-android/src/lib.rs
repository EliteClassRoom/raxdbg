//! Android emulation on top of raxdbg-core.
//!
//! Port of unidbg's `unidbg-android` module: the Android ELF loader, Linux
//! syscall handlers, the `dvm` JNI runtime, hook engines, the Android resolver
//! with bundled bionic libraries, APK support and the console debugger.
pub mod android_file;
pub mod apk;
pub mod elf;
