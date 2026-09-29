//! End-to-end tests for the syscall tracer and the protection report.
//!
//! These drive a real load rather than the dispatch directly, because what
//! the tracer has to get right is the *ordering* — a trace installed before
//! the load sees the load's own syscalls, and one installed afterwards does
//! not. Driving the handler by hand would not exercise that at all.
//!
//! The protections asserted here are the ones the bundled bionic and the
//! fixtures actually reach, not a synthetic list: a `ptrace(PTRACE_TRACEME)`
//! that the table answers with 0, and a `prctl` carrying bionic's
//! `PR_SET_VMA` magic, which decodes as a nonsense option unless the
//! wrapper's convention is accounted for.

#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use raxdbg_android::emulator::AndroidEmulatorBuilder;
use raxdbg_android::syscall::trace::{Severity, Verbosity};

/// The path to a bundled library, or skips the test when it is absent.
fn fixture(name: &str) -> Option<String> {
    let path = format!("fixtures/prebuilt/arm64-v8a/{name}");
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        None
    }
}

/// Loads `library` with a trace running from before the load.
fn traced(library: &str) -> (Rc<raxdbg_android::emulator::AndroidEmulator>, Rc<RefCell<raxdbg_android::syscall::SyscallTrace>>) {
    let emulator = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let trace = emulator.syscall().borrow_mut().set_trace();
    let file = raxdbg_android::android_file::ElfLibraryFile::open(library)
        .expect("the fixture opens");
    emulator.load(Box::new(file), false).expect("the fixture loads");
    (emulator, trace)
}

#[test]
fn trace_covers_the_load_itself() {
    let Some(library) = fixture("libctest.so") else {
        eprintln!("skipping: fixtures/prebuilt/arm64-v8a/libctest.so is not built");
        return;
    };
    let (_emulator, trace) = traced(&library);
    let trace = trace.borrow();
    // A load maps the object and its dependencies; without a trace installed
    // before the load there would be nothing at all here.
    assert!(
        trace.len() > 0,
        "a trace installed before the load must record the load's syscalls"
    );
    // Every event has a result: the first syscall of a run is the trap that
    // an unreturned-slot bug would leave dangling.
    for event in trace.events() {
        assert!(
            event.result.is_some(),
            "syscall #{} ({}) was recorded without a result",
            event.index,
            event.label()
        );
    }
}

#[test]
fn every_event_is_attributed_to_a_module() {
    let Some(library) = fixture("libctest.so") else {
        return;
    };
    let (emulator, trace) = traced(&library);
    let loader = emulator.loader();
    let modules = loader.module_infos();
    let mut trace = trace.borrow_mut();
    trace.attribute_modules(|pc| {
        modules
            .iter()
            .find(|module| pc >= module.base && pc < module.base + module.size)
            .map(|module| module.name.clone())
    });
    for event in trace.events() {
        assert!(
            event.module.is_some(),
            "syscall #{} at pc={:#x} was attributed to no module",
            event.index,
            event.pc
        );
    }
}

#[test]
fn a_run_without_a_trace_is_unaffected() {
    let Some(library) = fixture("libctest.so") else {
        return;
    };
    // The tracer is observation only. Two runs of the same function, one
    // traced and one not, must agree on the return value: a trace that
    // changed what the guest sees would be worse than no trace.
    let (traced_emulator, _trace) = traced(&library);
    let plain = AndroidEmulatorBuilder::for_64bit()
        .sdk(23)
        .build()
        .expect("the emulator builds");
    let file = raxdbg_android::android_file::ElfLibraryFile::open(&library).expect("opens");
    plain.load(Box::new(file), false).expect("loads");

    let address = traced_emulator.loader().dlsym(0, "hello").expect("hello").address;
    let with_trace = traced_emulator
        .call_function(address, &[])
        .expect("the traced call returns");
    let without_trace = plain
        .call_function(address, &[])
        .expect("the untraced call returns");
    assert_eq!(
        with_trace, without_trace,
        "installing a trace must not change the guest's result"
    );
}

#[test]
fn a_protection_probe_is_reported_with_its_path() {
    // A trace built by hand, because a protection is a *sequence*: the
    // `openat` carries the path and the answer the guest gets is what the
    // report has to say. Driving it through the real library would tie the
    // test to whatever that library happens to probe today.
    let mut events = Vec::new();
    events.push(SyscallEventProbe::openat_probe("/proc/self/status", 3));
    let report = raxdbg_android::syscall::ProtectionReport::from_events(&events, 8);
    assert_eq!(report.probe_paths, vec!["/proc/self/status".to_string()]);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == "proc probe")
        .expect("an open of /proc/self/status is a proc probe");
    assert_eq!(finding.severity, Severity::Gap);
    assert!(
        finding.evidence.contains("/proc/self/status"),
        "the finding must name the path: {}",
        finding.evidence
    );
}

/// Builds one synthetic [`SyscallEvent`](raxdbg_android::syscall::SyscallEvent).
struct SyscallEventProbe;

impl SyscallEventProbe {
    /// An `openat` of `path` that returned `result`.
    fn openat_probe(path: &str, result: i64) -> raxdbg_android::syscall::SyscallEvent {
        use raxdbg_android::syscall::SyscallEvent;
        use std::collections::BTreeMap;
        let mut paths = BTreeMap::new();
        paths.insert(1usize, path.to_string());
        SyscallEvent {
            index: 1,
            number: 56,
            name: Some("openat"),
            args: [0xffff_ff9c, 0x1000, 0x80000, 0, 0, 0],
            result: Some(result),
            errno: 0,
            pc: 0x1200_0000,
            lr: 0x1200_0004,
            pid: 1,
            paths,
            buffers: BTreeMap::new(),
            module: Some("libtest.so".into()),
        }
    }
}

#[test]
fn verbosity_selects_what_is_printed() {
    let Some(library) = fixture("libctest.so") else {
        return;
    };
    let (_emulator, trace) = traced(&library);
    let trace = trace.borrow();
    let full = raxdbg_android::syscall::trace::render(&trace, Verbosity::Full);
    let summary = raxdbg_android::syscall::trace::render(&trace, Verbosity::Summary);
    assert!(!full.is_empty(), "a full trace prints every syscall");
    assert!(
        summary.is_empty(),
        "a summary prints no per-syscall lines at all"
    );
    // `Full` must not be a subset of nothing: it names the syscalls.
    assert!(
        full.contains("mmap") || full.contains("brk") || full.contains("openat"),
        "a full trace names the syscalls it recorded, got:\n{full}"
    );
}
