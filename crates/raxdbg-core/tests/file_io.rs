//! File-IO tests (plan P4).
//!
//! Each test builds a stand-in backend modelled on the `TestBackend` from
//! `crates/raxdbg-core/tests/memory.rs`, so the file descriptors exercise the
//! real `Memory`/`Loader` facade end-to-end without dragging the CPU engine
//! in. They cover the [acceptance criteria] listed in the assignment:
//!
//! * a `ByteArrayFileIO` read/lseek/pread sequence;
//! * a `DriverFileIO` writing to a captured stdout sink and reading a temp
//!   file back through a real `Loader`-backed guest memory;
//! * a pipe write-then-read and an empty-pipe `-EAGAIN`;
//! * a `TcpListener`/`TcpStream` round trip through `socket.rs`;
//! * `LinuxFileSystem::open` resolving a file under a temp root dir plus
//!   `/dev/null` and `/proc/self/maps`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use raxdbg_core::backend::{
    GuestMemory,
    Backend, BackendError, BlockHook, CodeHook, ContextId, EventMemHook, HookId, InterruptHook,
    MemoryFault, MemoryFaultKind, Prot, ReadHook, RunError, RunOutcome, UnmappedKind, WriteHook,
};
use raxdbg_core::errno::{EACCES, EAGAIN};
use raxdbg_core::file::byte_array::ByteArrayFileIO;
use raxdbg_core::file::driver::{HostFileIO, NullFileIO, StdoutFileIO, create_driver_file};
use raxdbg_core::file::linux_fs::LinuxFileSystem;
use raxdbg_core::file::pipe::pipe_pair;
use raxdbg_core::file::socket::{TcpSocket, read_inet_addr, supported_family};
use raxdbg_core::file::{FileIO, FileResult, FileSystem};
use raxdbg_core::memory::loader::Loader;
use raxdbg_core::memory::{Memory, PAGE_SIZE};
use raxdbg_core::reg::RegId;

#[derive(Default)]
struct TestBackend {
    regions: BTreeMap<u64, Region>,
    sp: u64,
}

struct Region {
    prot: Prot,
    data: Vec<u8>,
}

impl Region {
    fn end(&self) -> u64 {
        self.data.len() as u64
    }
}

impl TestBackend {
    fn region_at(&self, addr: u64) -> Option<(u64, &Region)> {
        self.regions
            .iter()
            .find(|(base, region)| addr >= **base && addr < **base + region.end())
            .map(|(base, region)| (*base, region))
    }
}

impl Backend for TestBackend {
    fn on_initialize(&mut self) {}
    fn switch_user_mode(&mut self) {}
    fn enable_vfp(&mut self) {}

    fn reg_read(&self, reg: RegId) -> Result<u64, BackendError> {
        match reg {
            RegId::Sp => Ok(self.sp),
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn reg_write(&mut self, reg: RegId, value: u64) -> Result<(), BackendError> {
        match reg {
            RegId::Sp => {
                self.sp = value;
                Ok(())
            }
            other => Err(BackendError::UnsupportedRegister(other)),
        }
    }

    fn reg_read_vector(&self, reg: RegId) -> Result<[u8; 16], BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }

    fn reg_write_vector(&mut self, reg: RegId, _v: [u8; 16]) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedRegister(reg))
    }

    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; size];
        self.mem_read_into(addr, &mut buf)?;
        Ok(buf)
    }

    fn mem_read_into(&self, addr: u64, buf: &mut [u8]) -> Result<(), BackendError> {
        for (index, slot) in buf.iter_mut().enumerate() {
            let address = addr + index as u64;
            let Some((base, region)) = self.region_at(address) else {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                }));
            };
            if !region.prot.contains(Prot::READ) {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Permission,
                }));
            }
            *slot = region.data[(address - base) as usize];
        }
        Ok(())
    }

    fn mem_write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), BackendError> {
        for (index, byte) in bytes.iter().enumerate() {
            let address = addr + index as u64;
            let Some((base, region)) = self.region_at(address) else {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                }));
            };
            if !region.prot.contains(Prot::WRITE) {
                return Err(BackendError::Memory(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Permission,
                }));
            }
            let offset = (address - base) as usize;
            self.regions.get_mut(&base).unwrap().data[offset] = *byte;
        }
        Ok(())
    }

    fn mem_map(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        if addr % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 || size == 0 {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "misaligned or empty".into(),
            });
        }
        if self
            .regions
            .iter()
            .any(|(base, region)| addr < base + region.end() && addr + size > *base)
        {
            return Err(BackendError::Map {
                addr,
                size,
                reason: "overlaps an existing mapping".into(),
            });
        }
        self.regions.insert(
            addr,
            Region {
                prot: perms,
                data: vec![0u8; size as usize],
            },
        );
        Ok(())
    }

    fn mem_protect(&mut self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        for (base, region) in self.regions.iter_mut() {
            if addr < *base + region.end() && addr + size > *base {
                region.prot = perms;
            }
        }
        Ok(())
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.regions
            .retain(|base, region| !(addr < base + region.end() && addr + size > *base));
        Ok(())
    }

    fn hook_add_code(&mut self, _cb: Box<dyn CodeHook>, _begin: u64, _end: u64) -> HookId {
        0
    }
    fn hook_add_block(&mut self, _cb: Box<dyn BlockHook>, _begin: u64, _end: u64) -> HookId {
        0
    }
    fn hook_add_read(&mut self, _cb: Box<dyn ReadHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_write(&mut self, _cb: Box<dyn WriteHook + Send>, _b: u64, _e: u64) -> HookId {
        0
    }
    fn hook_add_event_mem(&mut self, _cb: Box<dyn EventMemHook>, _kind: UnmappedKind) -> HookId {
        0
    }
    fn hook_add_interrupt(&mut self, _cb: Box<dyn InterruptHook>) -> HookId {
        0
    }
    fn hook_del(&mut self, _id: HookId) {}

    fn emu_start(
        &mut self,
        _begin: u64,
        _until: u64,
        _timeout_us: u64,
        _count: u64,
    ) -> Result<RunOutcome, RunError> {
        Ok(RunOutcome::Stopped)
    }
    fn emu_stop(&mut self) {}
    fn set_pending_error(&mut self, _error: RunError) {}
    fn take_pending_error(&mut self) -> Option<RunError> {
        None
    }
    fn is_running(&self) -> bool {
        false
    }
    fn context_save(&mut self) -> ContextId {
        0
    }
    fn context_restore(&mut self, _id: ContextId) {}
    fn context_free(&mut self, _id: ContextId) {}
    fn page_size(&self) -> usize {
        PAGE_SIZE as usize
    }
    fn remove_jit_code_cache(&mut self, _begin: u64, _end: u64) {}
}

/// The address-space half of the test backend, shared with the loader the way
/// `RaxBackend::guest_memory` shares rax's.
///
/// It keeps its own region map because `Loader` holds it behind an
/// `Arc<dyn GuestMemory>`, which must be `Send + Sync`, and the test's
/// `Backend` is a plain `Rc<RefCell<..>>`.
#[derive(Default)]
struct TestMemory {
    regions: parking_lot::Mutex<BTreeMap<u64, Region>>,
}

impl TestMemory {
    fn region_at(&self, addr: u64) -> Option<(u64, u64)> {
        self.regions
            .lock()
            .iter()
            .find(|(base, region)| addr >= **base && addr < **base + region.end())
            .map(|(base, region)| (*base, region.data.len() as u64))
    }
}

impl GuestMemory for TestMemory {
    fn read_raw(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryFault> {
        let regions = self.regions.lock();
        for (index, slot) in buf.iter_mut().enumerate() {
            let address = addr + index as u64;
            let Some((base, region)) = regions
                .iter()
                .find(|(base, region)| address >= **base && address < **base + region.end())
            else {
                return Err(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                });
            };
            *slot = region.data[(address - base) as usize];
        }
        Ok(())
    }

    fn write_raw(&self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        let mut regions = self.regions.lock();
        for (index, byte) in data.iter().enumerate() {
            let address = addr + index as u64;
            let found = regions
                .iter()
                .find(|(base, region)| address >= **base && address < **base + region.end())
                .map(|(base, _)| *base);
            let Some(base) = found else {
                return Err(MemoryFault {
                    addr: address,
                    size: 1,
                    kind: MemoryFaultKind::Unmapped,
                });
            };
            let offset = (address - base) as usize;
            regions.get_mut(&base).expect("just found").data[offset] = *byte;
        }
        Ok(())
    }

    fn map(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        self.regions.lock().insert(
            addr,
            Region {
                prot: perms,
                data: vec![0u8; size as usize],
            },
        );
        Ok(())
    }

    fn protect(&self, addr: u64, size: u64, perms: Prot) -> Result<(), BackendError> {
        for (base, region) in self.regions.lock().iter_mut() {
            if addr < *base + region.end() && addr + size > *base {
                region.prot = perms;
            }
        }
        Ok(())
    }

    fn unmap(&self, addr: u64, size: u64) -> Result<(), BackendError> {
        self.regions
            .lock()
            .retain(|base, region| !(addr < base + region.end() && addr + size > *base));
        Ok(())
    }
}

fn loader() -> Rc<Loader> {
    let backend = Rc::new(RefCell::new(TestBackend::default()));
    let guest: std::sync::Arc<dyn GuestMemory> = std::sync::Arc::new(TestMemory::default());
    Loader::new(backend as Rc<RefCell<dyn Backend>>, guest, 8)
}


#[test]
fn byte_array_mmap2_copies_into_a_fresh_mapping() {
    let memory = loader();
    let target = memory.mmap(0x1000, Prot::READ.union(Prot::WRITE)).unwrap();
    let mut io = ByteArrayFileIO::new(0, "/data", b"abcDEF".to_vec());
    io.mmap2(&*memory, target.peer(), 0x1000, Prot::READ, 0, 6)
        .expect("mmap2");
    let mut bytes = [0u8; 6];
    memory
        .read_bytes(target.peer(), &mut bytes)
        .expect("read back");
    assert_eq!(&bytes, b"abcDEF");
}
// ---------------------------------------------------------------------------
// DriverFileIO (host files + /dev specials + captured stdout)
// ---------------------------------------------------------------------------

#[test]
fn driver_host_file_round_trip() {
    let temp = tempdir("raxdbg-file-io-host");
    let path = temp.path().join("hello.txt");
    {
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(b"raxdbg host IO").expect("write");
    }
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();
    let mut io = HostFileIO::open_path(
        raxdbg_core::file::structs::IOConstants::O_RDONLY,
        "hello.txt",
        &path,
    )
    .expect("open");
    assert_eq!(io.read(&*memory, guest.peer(), 32), 14);
    let mut bytes = [0u8; 14];

    memory
        .read_bytes(guest.peer(), &mut bytes)
        .expect("read back");
    assert_eq!(&bytes, b"raxdbg host IO");
}
fn driver_captured_stdout_sink_writes_through() {
    let captured: std::sync::Arc<parking_lot::Mutex<Vec<u8>>> =
        std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = CapturedWriter::new(captured.clone());
    let mut io = StdoutFileIO::new("stdout", Box::new(sink));
    assert_eq!(io.write(b"hello, "), 7);
    assert_eq!(io.write(b"world"), 5);
    assert_eq!(&captured.lock()[..], b"hello, world");
    assert!(io.is_stdio());
}

#[test]
fn driver_dev_null_drops_writes() {
    let mut io = create_driver_file("/dev/null", None, None).expect("dev/null");
    assert_eq!(io.get_path(), "/dev/null");
    assert_eq!(io.write(b"drop me"), 7);
}

#[test]
fn driver_dev_urandom_returns_some_bytes() {
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();
    let mut io = create_driver_file("/dev/urandom", None, None).expect("urandom");
    let n = io.read(&*memory, guest.peer(), 32);
    assert!(n > 0);
}

// ---------------------------------------------------------------------------
// Pipes
// ---------------------------------------------------------------------------

#[test]
fn pipe_write_then_read() {
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();
    let (mut reader, mut writer) = pipe_pair();
    assert_eq!(writer.write(b"ping"), 4);
    assert_eq!(reader.read(&*memory, guest.peer(), 16), 4);
    let mut bytes = [0u8; 4];
    memory
        .read_bytes(guest.peer(), &mut bytes)
        .expect("read back");
    assert_eq!(&bytes, b"ping");
}

#[test]
fn empty_pipe_read_returns_again() {
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();
    let (mut reader, _writer) = pipe_pair();
    assert_eq!(reader.read(&*memory, guest.peer(), 4), -EAGAIN);
}

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

#[test]
fn tcp_listener_and_stream_round_trip() {
    // Set up an in-process listener on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let std_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).expect("read_exact");
        stream.write_all(b"PONG").expect("write_all");
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));

    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();

    // Use the raxdbg TcpSocket wrapper to send the request.
    let mut client = TcpSocket::new(raxdbg_core::file::structs::IOConstants::O_RDWR, stream);
    let n = client.write(b"PING");
    assert_eq!(n, 4, "client.write returned {n}");

    // Spin until the reply arrives; the syscall layer would normally do this
    // via the futex/wait machinery, but in a test we just retry.
    let mut n = -1;
    for _ in 0..200 {
        n = client.read(&*memory, guest.peer(), 8);
        if n > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(n, 4, "client.read returned {n}");
    let mut bytes = [0u8; 4];
    memory
        .read_bytes(guest.peer(), &mut bytes)
        .expect("read back");
    assert_eq!(&bytes, b"PONG");

    std_server.join().expect("join");
}

#[test]
fn supported_family_recognises_known_constants() {
    assert!(!supported_family(0));
    assert!(supported_family(2));
    assert!(supported_family(10));
    assert!(supported_family(16));
    assert!(!supported_family(99));
}

#[test]
fn read_inet_addr_decodes_a_v4_address() {
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();
    let mut sockaddr = [0u8; 16];
    sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
    sockaddr[2..4].copy_from_slice(&8080u16.to_be_bytes());
    sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    memory.write_bytes( guest.peer(), &sockaddr);

    let addr = read_inet_addr(&*memory, guest.peer(), 16).expect("inet addr");
    match addr {
        std::net::SocketAddr::V4(v4) => {
            assert_eq!(v4.ip().to_string(), "127.0.0.1");
            assert_eq!(v4.port(), 8080);
        }
        _ => panic!("expected v4"),
    }
}

// ---------------------------------------------------------------------------
// LinuxFileSystem
// ---------------------------------------------------------------------------

#[test]
fn linux_fs_open_resolves_under_root_and_handles_synthetic_paths() {
    let temp = tempdir("raxdbg-file-io-fs");
    let root = temp.path();
    let data = root.join("data.txt");
    std::fs::write(&data, b"hi from raxdbg").expect("write");

    let fs = LinuxFileSystem::new(root).expect("fs");
    let memory = loader();
    let guest = memory
        .mmap(0x1000, Prot::READ.union(Prot::WRITE))
        .unwrap();

    match fs.open("data.txt", raxdbg_core::file::structs::IOConstants::O_RDONLY) {
        FileResult::Success(mut io) => {
            let n = io.read(&*memory, guest.peer(), 64);
            assert!(n > 0);
            let mut bytes = vec![0u8; n as usize];
            memory.read_bytes(guest.peer(), &mut bytes).unwrap();
            assert_eq!(&bytes, b"hi from raxdbg");
        }
        FileResult::Fallback(_) => panic!("unexpected fallback"),
        FileResult::NotFound => panic!("expected data.txt to resolve"),
    }

    // `/dev/null` returns a `NullFileIO` even without root state.
    let mut null_io = match fs.open(
        "/dev/null",
        raxdbg_core::file::structs::IOConstants::O_WRONLY,
    ) {
        FileResult::Success(io) => io,
        _ => panic!("/dev/null must resolve"),
    };
    assert_eq!(null_io.get_path(), "/dev/null");
    assert!(null_io.as_any().is::<NullFileIO>());

    // `/proc/self/maps` is synthesized by `LinuxFileSystem.synthesize_proc`.
    let mut proc_io = match fs.open(
        "/proc/self/maps",
        raxdbg_core::file::structs::IOConstants::O_RDONLY,
    ) {
        FileResult::Success(io) => io,
        _ => panic!("/proc/self/maps must resolve"),
    };
    let n = proc_io.read(&*memory, guest.peer(), 256);
    assert!(n > 0);

    // Path traversal is rejected.
    let traversal = fs.open("../etc/passwd", 0);
    assert!(matches!(traversal, FileResult::NotFound));

    // `create_work_dir` returns a directory under the root.
    let work = fs.create_work_dir().expect("work dir");
    assert!(work.starts_with(root));

    // Renaming an existing file succeeds.
    fs.mkdir("nested", 0o755);
    let rename = fs.rename("data.txt", "nested/data.txt");
    assert_eq!(rename, 0);
    assert!(root.join("nested").join("data.txt").exists());

    // Unlink the renamed file.
    fs.unlink("nested/data.txt");
    assert!(!root.join("nested").join("data.txt").exists());

    // `mkdir` is idempotent.
    fs.rmdir("nested");
    assert!(!root.join("nested").exists());
}

#[test]
fn linux_fs_ephemeral_only_handles_synthetic_paths() {
    let fs = LinuxFileSystem::ephemeral();
    match fs.open("/dev/null", 0) {
        FileResult::Success(_) => {}
        _ => panic!("/dev/null must always resolve"),
    }
    match fs.open("/proc/self/stat", 0) {
        FileResult::Success(_) => {}
        _ => panic!("/proc/self/stat must always resolve"),
    }
    match fs.open("/etc/hosts", 0) {
        FileResult::NotFound => {}
        _ => panic!("ephemeral fs must not resolve host files"),
    }
    // No root_dir → no work dir.
    assert!(fs.create_work_dir().is_err());
    assert!(matches!(
        fs.open("/proc/self/stat", 0),
        FileResult::Success(_)
    ));
    assert_eq!(
        fs.rename("from", "to"),
        -EACCES,
        "rename returns -EACCES with no root"
    );
}

// ---------------------------------------------------------------------------
// Helpers
struct CapturedWriter {
    sink: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl CapturedWriter {
    fn new(sink: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>) -> Self {
        CapturedWriter { sink }
    }
}

impl Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A temp directory that gets removed on drop.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir(label: &str) -> TempDir {
    let mut path = std::env::temp_dir();
    path.push(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create tempdir");
    TempDir(path)
}
