//! CLI acceptance tests (plan P12).
//!
//! The binary is driven the way a user drives it, over the fixtures that are
//! committed, so these tests prove the whole stack — loader, bionic boot,
//! syscalls, unwinder, debugger core — from the outside.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn fixture(name: &str) -> PathBuf {
    workspace_root()
        .join("fixtures/prebuilt/arm64-v8a")
        .join(name)
}

fn raxdbg(args: &[&str]) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_raxdbg");
    Command::new(binary)
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("run raxdbg")
}

#[test]
fn run_calls_a_c_function_and_captures_its_stdout() {
    let output = raxdbg(&[
        "run",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "hello()V",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("hello 42"), "{stdout}");
}

#[test]
fn run_returns_a_value() {
    let output = raxdbg(&[
        "run",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "ctest_malloc_ok()V",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("0x1"), "{stdout}");
}

#[test]
fn info_lists_the_modules_and_their_dependencies() {
    let output = raxdbg(&["info", fixture("libctest.so").to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("libctest.so base="), "{stdout}");
    assert!(stdout.contains("libc.so"), "{stdout}");
    assert!(stdout.contains("needs:"), "{stdout}");
}

#[test]
fn trace_prints_the_instructions_it_ran() {
    let output = raxdbg(&[
        "trace",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "ctest_malloc_ok()V",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("instructions --"), "{stdout}");
    // `hello_value` returns a constant, so the trace must contain a `ret`.
    assert!(stdout.contains("ret"), "{stdout}");
}

#[test]
fn trace_functions_logs_the_calls_the_library_makes() {
    let output = raxdbg(&[
        "trace",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "hello()V",
        "--functions",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The branch is inside `hello`, and its target is a PLT stub, which only
    // the loader's relocation table can name. The count itself is left to the
    // core tests: a rebuilt fixture may reach `fflush` by a tail call.
    assert!(stdout.contains("libctest.so!hello+0x"), "{stdout}");
    // Addresses print module-relative, so the log can be read against the
    // binary itself rather than against one particular load base. The callee
    // is a PLT stub, so it belongs to the calling module even though the
    // function it reaches is libc's.
    assert!(stdout.contains("libctest.so+0x"), "{stdout}");
    assert!(stdout.contains("libc.so!printf"), "{stdout}");
    assert!(stdout.contains("calls --"), "{stdout}");
}

#[test]
fn trace_out_writes_the_instruction_log_to_a_file() {
    let log = std::env::temp_dir().join(format!("raxdbg-trace-{}.log", std::process::id()));
    let output = raxdbg(&[
        "trace",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "hello()V",
        "--code",
        "--out",
        log.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("instructions (written to"), "{stdout}");
    // With `--out` the instructions are streamed to the file, not the
    // terminal: only the summary line is left on stdout.
    assert!(!stdout.contains("[32]:"), "{stdout}");

    let text = std::fs::read_to_string(&log).expect("the trace file");
    assert!(text.contains("ret"), "the trace must contain a ret");
    let lines = text.lines().count();
    let reported: usize = stdout
        .split("-- ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("no instruction count in {stdout:?}"));
    assert_eq!(
        lines, reported,
        "the file must hold one line per instruction"
    );
    std::fs::remove_file(&log).ok();
}

#[test]
fn trace_runs_jni_on_load_and_logs_the_calls_it_makes() {
    // `JNI_OnLoad` takes a `JavaVM*`, so a bare `--call` would pass zeroes and
    // the guest would fault on the first dereference. With `--jni-on-load` the
    // VM supplies the pointer, and the function trace covers the whole call.
    let log = std::env::temp_dir().join(format!("raxdbg-jni-{}.log", std::process::id()));
    let output = raxdbg(&[
        "trace",
        fixture("libjnitest.so").to_str().unwrap(),
        "--jni-on-load",
        "--functions",
        "--out",
        log.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("calls (written to"), "{stdout}");

    let text = std::fs::read_to_string(&log).expect("the call log");
    assert!(
        text.contains("\ncall "),
        "the log must name the calls:\n{text}"
    );
    // A host service on the SVC page belongs to no ELF, so the loader cannot
    // name it -- but the stub page labels every allocation, and that label is
    // the function's name. Without it these come out as bare offsets.
    assert!(
        text.contains("JNIEnv!GetJavaVM") || text.contains("JNIEnv!FindClass"),
        "host services must be named, not shown as offsets:\n{text}"
    );
    // A stub whose name contains a dot must survive label parsing whole: the
    // dispatch number is a trailing `.<digits>`, and a name like
    // `JNIEnv!<unimplemented>` is not cut at its own punctuation.
    for line in text.lines() {
        if let Some(name) = line.rsplit("-> ").nth(1) {
            assert!(
                !name.contains("<unimplemented"),
                "a stub name was truncated at a dot: {line}"
            );
        }
    }
    // The log opens with the phases the run went through and reaches the
    // marker naming the entry point before the calls it makes. libc.so, which
    // the fixture needs, contributes the eleven `init_array` markers; the
    // fixture itself carries none.
    let marker = text
        .find("[libjnitest.so] JNI_OnLoad 0x")
        .expect("the log names the entry point");
    let first_call = text.find("\ncall ").expect("the log has calls");
    assert!(
        marker < first_call,
        "the marker comes before the calls:\n{text}"
    );
    assert!(
        text.lines()
            .next()
            .is_some_and(|line| line.starts_with("[libc.so] .init_array[1/11] 0x")),
        "and the phases come before that:\n{text}"
    );
    std::fs::remove_file(&log).ok();
}

#[test]
fn leak_check_reports_the_live_mappings() {
    // The tracker is an `MMapListener`, exactly as unidbg's `MemoryTracker` is,
    // so it reports the guest address space's live regions rather than every
    // `malloc`. `dlopen_sin` maps `libm.so` and never unloads it, so the report
    // must name it.
    let output = raxdbg(&[
        "run",
        fixture("libctest.so").to_str().unwrap(),
        "--call",
        "dlopen_sin()V",
        "--leak-check",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("live allocation(s)"), "{stdout}");
    let live = stdout
        .split("live allocation(s) --")
        .nth(1)
        .unwrap_or_default();
    assert!(
        live.contains("size 0x"),
        "the report lists the live regions: {stdout}"
    );
    assert!(live.lines().count() > 1, "at least one region: {stdout}");
}

#[test]
fn a_scripted_console_session_breaks_and_inspects() {
    let script = "r\nwhere\nq\n";
    let output = Command::new(env!("CARGO_BIN_EXE_raxdbg"))
        .args(["debug", fixture("libctest.so").to_str().unwrap()])
        .current_dir(workspace_root())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(script.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run the console");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("raxdbg console"), "{stdout}");
    assert!(stdout.contains("pc"), "{stdout}");
    assert!(stdout.contains("raxdbg>"), "{stdout}");
}

#[test]
fn an_unknown_option_is_reported() {
    let output = raxdbg(&["run", fixture("libctest.so").to_str().unwrap(), "--nope"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option"), "{stderr}");
    assert!(stderr.contains("usage:"), "{stderr}");
}

#[test]
fn a_jni_signature_reports_the_missing_runtime() {
    let output = raxdbg(&[
        "run",
        fixture("libjnitest.so").to_str().unwrap(),
        "--call",
        "echo(Ljava/lang/String;)Ljava/lang/String;",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dvm runtime"), "{stderr}");
}

#[test]
fn syscalls_prints_a_summary_and_a_report() {
    let output = raxdbg(&["syscalls", fixture("libctest.so").to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The default is the report alone: a summary is what makes the command
    // usable on a library that makes thousands of calls.
    assert!(stdout.contains("-- protection --"), "{stdout}");
    assert!(stdout.contains("syscalls inspected"), "{stdout}");
    assert!(
        !stdout.contains("-- syscalls --"),
        "the default must not print per-syscall lines, got:\n{stdout}"
    );
}

#[test]
fn syscalls_v_prints_the_calls_that_carry_a_path() {
    let output = raxdbg(&["syscalls", fixture("libctest.so").to_str().unwrap(), "-v"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("-- syscalls --"), "{stdout}");
    assert!(
        stdout.contains("openat"),
        "a path-carrying call is shown:\n{stdout}"
    );
}

#[test]
fn syscalls_vv_prints_every_call() {
    let output = raxdbg(&["syscalls", fixture("libctest.so").to_str().unwrap(), "-vv"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // `brk` carries neither a path nor a buffer, so only the full trace
    // shows it: that is the difference `-vv` makes.
    assert!(
        stdout.contains("brk@"),
        "the full trace shows every call:\n{stdout}"
    );
}

#[test]
fn syscalls_runs_jni_on_load_when_asked() {
    let output = raxdbg(&[
        "syscalls",
        fixture("libjnitest.so").to_str().unwrap(),
        "--jni-on-load",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(
        stdout.contains("JNI_OnLoad") && stdout.contains("0x10006"),
        "JNI_OnLoad must run and report the version it returned:\n{stdout}"
    );
}

/// The initialiser phases are marked, in order, before `JNI_OnLoad`.
///
/// `libc.so` is the module here for one reason: it is a bundled library that
/// carries initialisers (eleven `init_array` slots and no `DT_INIT`), and it
/// exports no `JNI_OnLoad` -- so the run reports that absence and the markers
/// are what is left to assert.
#[test]
fn syscalls_marks_the_initialiser_phases_before_jni_on_load() {
    let libc = workspace_root().join("libs/android/sdk23/lib64/libc.so");
    let output = raxdbg(&["syscalls", libc.to_str().unwrap(), "--jni-on-load"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let markers: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("[libc.so] .init_array["))
        .collect();
    assert_eq!(
        markers.len(),
        11,
        "every one of libc's initialisers is marked:\n{stdout}"
    );
    for (index, marker) in markers.iter().enumerate() {
        assert!(
            marker.starts_with(&format!("[libc.so] .init_array[{}/11] 0x", index + 1)),
            "the slots are marked in order: {marker}"
        );
    }

    let last = markers.last().expect("eleven markers");
    let on_load = stdout
        .find("does not export JNI_OnLoad")
        .expect("the run reports that libc has no entry point");
    assert!(
        stdout.find(last).expect("the marker is in the output") < on_load,
        "the constructors come before the entry point:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// The GDB remote serial protocol
// ---------------------------------------------------------------------------

/// A GDB remote-serial-protocol client, driven by hand.
///
/// The repository has no GDB binary to test against, so this speaks the wire
/// protocol itself: the server is driven exactly the way GDB drives it, which
/// is what makes this an acceptance test rather than a unit test.
struct RspClient {
    stream: std::net::TcpStream,
    buffered: Vec<u8>,
}

impl RspClient {
    fn connect(port: u16) -> Option<Self> {
        // The server is a child process, so the listener may not be up yet.
        for _ in 0..200 {
            if let Ok(stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                return Some(RspClient {
                    stream,
                    buffered: Vec::new(),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        None
    }

    /// One byte, refilled from the socket as needed.
    fn byte(&mut self) -> Option<u8> {
        if self.buffered.is_empty() {
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buffered.extend_from_slice(&chunk[..n]),
            }
        }
        Some(self.buffered.remove(0))
    }

    /// Sends one packet and returns the reply, which may be run-length
    /// encoded: a `c*<count>` run stands for that many copies of `c`.
    fn packet(&mut self, payload: &str) -> Option<String> {
        let raw = payload.as_bytes();
        let checksum = raw.iter().map(|b| *b as u32).sum::<u32>() & 0xff;
        let framed = format!("${payload}#{checksum:02x}");
        self.stream.write_all(framed.as_bytes()).ok()?;

        // The stub acknowledges the packet before it replies, so the first
        // byte back is the ack and the packet follows it.
        match self.byte()? {
            b'+' | b'-' => {}
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
        self.byte()?; // the leading '$'
        let mut body = Vec::new();
        loop {
            match self.byte()? {
                b'#' => break,
                byte => body.push(byte),
            }
        }
        // The two checksum digits every packet is framed with.
        self.byte()?;
        self.byte()?;
        Some(expand_rle(&body))
    }
}

/// Reverses the run-length encoding a stub may apply to its replies.
///
/// `c*<n>` stands for `c` repeated `n` times *in total*, with `n` biased by 28
/// so it never lands on a binary character: `0*<`,` is sixteen zeros.
fn expand_rle(body: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        let byte = body[index];
        index += 1;
        if byte != b'*' || out.is_empty() || index >= body.len() {
            out.push(byte);
            continue;
        }
        let total = body[index].wrapping_sub(28) as usize;
        index += 1;
        // The character before the marker is the first of the run, so it is
        // already in place; the count covers the repeats that follow it.
        let repeated = *out.last().expect("a run repeats what precedes it");
        for _ in 1..total {
            out.push(repeated);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A free loopback port, released before the server is asked to take it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let port = listener.local_addr().expect("a local address").port();
    drop(listener);
    port
}

#[test]
fn a_gdb_client_drives_the_guest_through_the_remote_protocol() {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_raxdbg"))
        .args([
            "debug",
            fixture("libctest.so").to_str().unwrap(),
            "--gdb",
            &port.to_string(),
            "--call",
            "ctest_malloc_ok()V",
        ])
        .current_dir(workspace_root())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the GDB server");

    let mut client = RspClient::connect(port).expect("the server listens on the loopback");
    assert!(
        client
            .packet("qSupported:multiprocess+")
            .is_some_and(|r| r.contains("PacketSize=")),
        "the server negotiates features"
    );
    let stop = client.packet("?").expect("the halt reason");
    assert!(
        stop.starts_with('T') || stop.starts_with('S'),
        "stopped: {stop}"
    );

    // The guest is parked at the callee's first instruction, before it ran.
    let regs = client.packet("g").expect("the register file");
    assert_eq!(regs.len() % 2, 0, "the register file is hex");
    // Register values travel as target-endian bytes, which is little-endian
    // here: 31 x-registers and `sp` (8 bytes each), then `pc`.
    let file = (0..regs.len() / 2)
        .map(|index| u8::from_str_radix(&regs[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect::<Vec<u8>>();
    let pc = u64::from_le_bytes(file[32 * 8..33 * 8].try_into().expect("eight bytes"));
    assert_ne!(pc, 0, "the program counter is at the callee");

    // A step runs exactly one real instruction, so it comes before any write
    // over the code at the entry.
    let stepped = client.packet("s").expect("the step completes");
    assert!(
        stepped.starts_with('S') || stepped.starts_with('T'),
        "a step stops: {stepped}"
    );
    let moved = {
        let after = client.packet("g").expect("the register file");
        let bytes: Vec<u8> = (0..after.len() / 2)
            .map(|i| u8::from_str_radix(&after[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect();
        u64::from_le_bytes(bytes[32 * 8..33 * 8].try_into().expect("eight bytes"))
    };
    assert_ne!(moved, pc, "one instruction moved the program counter");

    // A memory write is visible to the next read, in both directions.
    let write = client.packet(&format!("M{pc:x},4:aabbccdd"));
    assert_eq!(write.as_deref(), Some("OK"), "writing at {pc:x}");
    assert_eq!(
        client.packet(&format!("m{pc:x},4")).as_deref(),
        Some("aabbccdd")
    );
    // Unmapped memory is EFAULT rather than zeroes.
    assert_eq!(client.packet("m1,4").as_deref(), Some("E0e"));

    // Breakpoints are accepted, and removing one that is gone is refused.
    assert_eq!(
        client.packet(&format!("Z0,{pc:x},4")).as_deref(),
        Some("OK")
    );
    assert_eq!(
        client.packet(&format!("z0,{pc:x},4")).as_deref(),
        Some("OK")
    );
    assert_eq!(
        client.packet(&format!("z0,{pc:x},4")).as_deref(),
        Some("E16")
    );

    // Continuing runs the call to its return, and the session ends with the
    // exit reply a client reads as "the program finished".
    assert_eq!(client.packet("c").as_deref(), Some("W00"));
    drop(client);

    let output = child.wait_with_output().expect("the server exits");
    assert!(
        output.status.success(),
        "the server exits cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
