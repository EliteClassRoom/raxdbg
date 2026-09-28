//! Guest structures the syscall layer reads and writes.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/struct/`
//! (`Stat32`, `Stat64`, `RLimit64`) and
//! `unidbg-android/src/main/java/com/github/unidbg/file/linux/IOConstants.java`
//! @7f5da98e.
//!
//! unidbg models each ABI's layout as a separate JNA structure; here one
//! [`Stat`] carries the fields and serialises to whichever layout the guest
//! uses, because the two differ only in field widths and padding.

use crate::errno::EINVAL;
use crate::memory::{Memory, MemoryError};

/// Linux `open(2)` flags and `stat` modes, as unidbg's `IOConstants`.
pub struct IOConstants;

impl IOConstants {
    /// `O_RDONLY`.
    pub const O_RDONLY: i32 = 0;
    /// `O_WRONLY`.
    pub const O_WRONLY: i32 = 1;
    /// `O_RDWR`.
    pub const O_RDWR: i32 = 2;
    /// `O_CREAT`.
    pub const O_CREAT: i32 = 0x40;
    /// `O_EXCL`.
    pub const O_EXCL: i32 = 0x80;
    /// `O_NOCTTY`.
    pub const O_NOCTTY: i32 = 0x100;
    /// `O_TRUNC`.
    pub const O_TRUNC: i32 = 0x200;
    /// `O_APPEND`.
    pub const O_APPEND: i32 = 0x400;
    /// `O_NONBLOCK`.
    pub const O_NONBLOCK: i32 = 0x800;
    /// `O_DIRECTORY`.
    pub const O_DIRECTORY: i32 = 0x10000;
    /// `O_NOFOLLOW`.
    pub const O_NOFOLLOW: i32 = 0x20000;
    /// `O_CLOEXEC`.
    pub const O_CLOEXEC: i32 = 0x80000;

    /// `SEEK_SET`.
    pub const SEEK_SET: i32 = 0;
    /// `SEEK_CUR`.
    pub const SEEK_CUR: i32 = 1;
    /// `SEEK_END`.
    pub const SEEK_END: i32 = 2;

    /// `AT_FDCWD`.
    pub const AT_FDCWD: i32 = -100;

    /// Regular file.
    pub const S_IFREG: u32 = 0x8000;
    /// Directory.
    pub const S_IFDIR: u32 = 0x4000;
    /// Character device.
    pub const S_IFCHR: u32 = 0x2000;
    /// Block device.
    pub const S_IFBLK: u32 = 0x6000;
    /// FIFO.
    pub const S_IFIFO: u32 = 0x1000;
    /// Symbolic link.
    pub const S_IFLNK: u32 = 0xa000;
    /// Socket.
    pub const S_IFSOCK: u32 = 0xc000;
    /// The file-type mask.
    pub const S_IFMT: u32 = 0xf000;

    /// `PROT_READ`.
    pub const PROT_READ: i32 = 1;
    /// `PROT_WRITE`.
    pub const PROT_WRITE: i32 = 2;
    /// `PROT_EXEC`.
    pub const PROT_EXEC: i32 = 4;

    /// `F_GETFD`.
    pub const F_GETFD: i32 = 1;
    /// `F_SETFD`.
    pub const F_SETFD: i32 = 2;
    /// `F_GETFL`.
    pub const F_GETFL: i32 = 3;
    /// `F_SETFL`.
    pub const F_SETFL: i32 = 4;
    /// `F_DUPFD`.
    pub const F_DUPFD: i32 = 0;
    /// `FD_CLOEXEC`.
    pub const FD_CLOEXEC: i32 = 1;
}

/// A `timespec` with 64-bit fields (the arm64 ABI).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeSpec64 {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl TimeSpec64 {
    /// A time.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        TimeSpec64 { tv_sec, tv_nsec }
    }
}

/// A guest `struct stat`, in whichever layout the guest's ABI uses.
///
/// Field names follow the kernel's: the arm64 ABI has a 128-byte `struct stat`
/// (`st_dev`, `st_ino`, `st_mode`, `st_nlink`, `st_uid`, `st_gid`, `st_rdev`,
/// `st_size`, `st_blksize`, `st_blocks`, three `timespec`s, then padding), the
/// arm32 ABI a 96-byte `struct stat64` with 32-bit `st_ino`/`st_mode` and
/// 32-bit `timespec`s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// Device.
    pub st_dev: u64,
    /// Inode.
    pub st_ino: u64,
    /// File type and permissions.
    pub st_mode: u32,
    /// Hard link count.
    pub st_nlink: u32,
    /// Owner.
    pub st_uid: u32,
    /// Group.
    pub st_gid: u32,
    /// Device, for special files.
    pub st_rdev: u64,
    /// Size in bytes.
    pub st_size: i64,
    /// Preferred I/O block size.
    pub st_blksize: u32,
    /// Blocks allocated, in 512-byte units.
    pub st_blocks: i64,
    /// Access time.
    pub st_atim: TimeSpec64,
    /// Modification time.
    pub st_mtim: TimeSpec64,
    /// Change time.
    pub st_ctim: TimeSpec64,
}

impl Stat {
    /// `sizeof(struct stat)` on arm64.
    pub const SIZE_ARM64: usize = 128;
    /// `sizeof(struct stat64)` on arm32.
    pub const SIZE_ARM32: usize = 96;

    /// A regular file of `size` bytes, mode `mode`.
    pub fn regular(size: i64, mode: u32) -> Self {
        Stat {
            st_mode: IOConstants::S_IFREG | (mode & 0o7777),
            st_nlink: 1,
            st_size: size,
            st_blksize: 4096,
            st_blocks: (size + 511) / 512,
            ..Stat::default()
        }
    }

    /// A character device with `mode` and device id `rdev`.
    pub fn character(rdev: u64, mode: u32) -> Self {
        Stat {
            st_mode: IOConstants::S_IFCHR | (mode & 0o7777),
            st_nlink: 1,
            st_rdev: rdev,
            st_blksize: 4096,
            ..Stat::default()
        }
    }

    /// A socket.
    pub fn socket() -> Self {
        Stat {
            st_mode: IOConstants::S_IFSOCK | 0o777,
            st_nlink: 1,
            st_blksize: 4096,
            ..Stat::default()
        }
    }

    /// A FIFO.
    pub fn fifo() -> Self {
        Stat {
            st_mode: IOConstants::S_IFIFO | 0o600,
            st_nlink: 1,
            st_blksize: 4096,
            ..Stat::default()
        }
    }

    /// The size this struct occupies in `is_64bit` guests.
    pub const fn size(is_64bit: bool) -> usize {
        if is_64bit {
            Self::SIZE_ARM64
        } else {
            Self::SIZE_ARM32
        }
    }

    /// Serialises the struct into guest memory at `address`.
    pub fn write_to(
        &self,
        memory: &dyn Memory,
        address: u64,
        is_64bit: bool,
    ) -> Result<(), MemoryError> {
        let mut buf = vec![0u8; Self::size(is_64bit)];
        if is_64bit {
            put_u64(&mut buf, 0, self.st_dev);
            put_u64(&mut buf, 8, self.st_ino);
            put_u32(&mut buf, 16, self.st_mode);
            put_u32(&mut buf, 20, self.st_nlink);
            put_u32(&mut buf, 24, self.st_uid);
            put_u32(&mut buf, 28, self.st_gid);
            put_u64(&mut buf, 32, self.st_rdev);
            put_i64(&mut buf, 48, self.st_size);
            put_u32(&mut buf, 56, self.st_blksize);
            put_i64(&mut buf, 64, self.st_blocks);
            put_timespec64(&mut buf, 72, self.st_atim);
            put_timespec64(&mut buf, 88, self.st_mtim);
            put_timespec64(&mut buf, 104, self.st_ctim);
        } else {
            put_u64(&mut buf, 0, self.st_dev);
            put_u32(&mut buf, 12, self.st_ino as u32);
            put_u32(&mut buf, 16, self.st_mode);
            put_u32(&mut buf, 20, self.st_nlink);
            put_u32(&mut buf, 24, self.st_uid);
            put_u32(&mut buf, 28, self.st_gid);
            put_u64(&mut buf, 32, self.st_rdev);
            put_i64(&mut buf, 44, self.st_size);
            put_u32(&mut buf, 52, self.st_blksize);
            put_i64(&mut buf, 56, self.st_blocks);
            put_timespec32(&mut buf, 64, self.st_atim);
            put_timespec32(&mut buf, 72, self.st_mtim);
            put_timespec32(&mut buf, 80, self.st_ctim);
            put_u64(&mut buf, 88, self.st_ino);
        }
        memory.write_bytes(address, &buf)
    }

    /// Reads the struct back out of guest memory (for tests and for the
    /// syscalls that take a `stat` the guest filled in).
    pub fn read_from(
        memory: &dyn Memory,
        address: u64,
        is_64bit: bool,
    ) -> Result<Self, MemoryError> {
        let mut buf = vec![0u8; Self::size(is_64bit)];
        memory.read_bytes(address, &mut buf)?;
        Ok(if is_64bit {
            Stat {
                st_dev: get_u64(&buf, 0),
                st_ino: get_u64(&buf, 8),
                st_mode: get_u32(&buf, 16),
                st_nlink: get_u32(&buf, 20),
                st_uid: get_u32(&buf, 24),
                st_gid: get_u32(&buf, 28),
                st_rdev: get_u64(&buf, 32),
                st_size: get_i64(&buf, 48),
                st_blksize: get_u32(&buf, 56),
                st_blocks: get_i64(&buf, 64),
                st_atim: get_timespec64(&buf, 72),
                st_mtim: get_timespec64(&buf, 88),
                st_ctim: get_timespec64(&buf, 104),
            }
        } else {
            Stat {
                st_dev: get_u64(&buf, 0),
                st_ino: get_u64(&buf, 88),
                st_mode: get_u32(&buf, 16),
                st_nlink: get_u32(&buf, 20),
                st_uid: get_u32(&buf, 24),
                st_gid: get_u32(&buf, 28),
                st_rdev: get_u64(&buf, 32),
                st_size: get_i64(&buf, 44),
                st_blksize: get_u32(&buf, 52),
                st_blocks: get_i64(&buf, 56),
                st_atim: get_timespec32(&buf, 64),
                st_mtim: get_timespec32(&buf, 72),
                st_ctim: get_timespec32(&buf, 80),
            }
        })
    }

    /// The `st_mode` bits that a `stat` of `path` should report, from the
    /// host's metadata.
    pub fn mode_of(metadata: &std::fs::Metadata) -> u32 {
        if metadata.is_dir() {
            IOConstants::S_IFDIR | 0o755
        } else {
            IOConstants::S_IFREG | 0o644
        }
    }
}

/// A guest `struct rlimit64`.
///
/// Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/struct/RLimit64.java`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RLimit64 {
    /// Soft limit.
    pub rlim_cur: u64,
    /// Hard limit.
    pub rlim_max: u64,
}

impl RLimit64 {
    /// Serialises into guest memory.
    pub fn write_to(&self, memory: &dyn Memory, address: u64) -> Result<(), MemoryError> {
        let mut buf = [0u8; 16];
        put_u64(&mut buf, 0, self.rlim_cur);
        put_u64(&mut buf, 8, self.rlim_max);
        memory.write_bytes(address, &buf)
    }
}

/// A guest `struct itimerval` (two `timeval`s).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ITimerVal {
    /// Interval between repeats.
    pub it_interval_sec: i64,
    /// Interval, microseconds.
    pub it_interval_usec: i64,
    /// Time to the next delivery.
    pub it_value_sec: i64,
    /// Time to the next delivery, microseconds.
    pub it_value_usec: i64,
}

impl ITimerVal {
    /// Serialises into guest memory, 64-bit fields for a 64-bit guest.
    pub fn write_to(
        &self,
        memory: &dyn Memory,
        address: u64,
        is_64bit: bool,
    ) -> Result<(), MemoryError> {
        let width = if is_64bit { 8 } else { 4 };
        let mut buf = vec![0u8; width * 4];
        put_long(&mut buf, 0, self.it_interval_sec, is_64bit);
        put_long(&mut buf, width, self.it_interval_usec, is_64bit);
        put_long(&mut buf, width * 2, self.it_value_sec, is_64bit);
        put_long(&mut buf, width * 3, self.it_value_usec, is_64bit);
        memory.write_bytes(address, &buf)
    }
}

/// A guest `struct sockaddr`: a 16-bit family followed by up to 14 bytes of
/// address data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddr {
    /// Address family.
    pub family: u16,
    /// Family-specific bytes.
    pub data: [u8; 14],
}

impl SockAddr {
    /// `sizeof(struct sockaddr)`.
    pub const SIZE: usize = 16;

    /// Reads the family and data from guest memory.
    pub fn read_from(memory: &dyn Memory, address: u64) -> Result<Self, MemoryError> {
        let mut buf = [0u8; Self::SIZE];
        memory.read_bytes(address, &mut buf)?;
        let mut data = [0u8; 14];
        data.copy_from_slice(&buf[2..]);
        Ok(SockAddr {
            family: u16::from_le_bytes([buf[0], buf[1]]),
            data,
        })
    }

    /// The port, for `AF_INET` addresses in network byte order.
    pub fn port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// The IPv4 address, for `AF_INET`.
    pub fn ipv4(&self) -> [u8; 4] {
        [self.data[2], self.data[3], self.data[4], self.data[5]]
    }
}

/// A Linux error code for a failed `stat`.
pub(crate) const _STAT_FAILED: i32 = -EINVAL;

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(buf: &mut [u8], offset: usize, value: i64) {
    put_u64(buf, offset, value as u64);
}

fn put_long(buf: &mut [u8], offset: usize, value: i64, is_64bit: bool) {
    if is_64bit {
        put_i64(buf, offset, value);
    } else {
        put_u32(buf, offset, value as u32);
    }
}

fn put_timespec64(buf: &mut [u8], offset: usize, value: TimeSpec64) {
    put_i64(buf, offset, value.tv_sec);
    put_i64(buf, offset + 8, value.tv_nsec);
}

fn put_timespec32(buf: &mut [u8], offset: usize, value: TimeSpec64) {
    put_u32(buf, offset, value.tv_sec as u32);
    put_u32(buf, offset + 4, value.tv_nsec as u32);
}

fn get_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("four bytes"))
}

fn get_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("eight bytes"))
}

fn get_i64(buf: &[u8], offset: usize) -> i64 {
    get_u64(buf, offset) as i64
}

fn get_timespec64(buf: &[u8], offset: usize) -> TimeSpec64 {
    TimeSpec64::new(get_i64(buf, offset), get_i64(buf, offset + 8))
}

fn get_timespec32(buf: &[u8], offset: usize) -> TimeSpec64 {
    TimeSpec64::new(i64::from(get_u32(buf, offset)), i64::from(get_u32(buf, offset + 4)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_layouts_match_the_kernels() {
        assert_eq!(Stat::size(true), 128);
        assert_eq!(Stat::size(false), 96);
    }

    #[test]
    fn regular_file_stat_fields_are_derived() {
        let stat = Stat::regular(1024, 0o644);
        assert_eq!(stat.st_mode, IOConstants::S_IFREG | 0o644);
        assert_eq!(stat.st_blocks, 2);
        assert_eq!(stat.st_nlink, 1);
    }
}
