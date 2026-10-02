//! CLI acceptance tests (plan P12).
//!
//! The binary is driven the way a user drives it, over the fixtures that are
//! committed, so these tests prove the whole stack — loader, bionic boot,
//! syscalls, unwinder, debugger core — from the outside.

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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert_eq!(lines, reported, "the file must hold one line per instruction");
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("calls (written to"), "{stdout}");

    let text = std::fs::read_to_string(&log).expect("the call log");
    assert!(text.contains("\ncall "), "the log must name the calls:\n{text}");
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
        .args([
            "debug",
            fixture("libctest.so").to_str().unwrap(),
        ])
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
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
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("-- syscalls --"), "{stdout}");
    assert!(stdout.contains("openat"), "a path-carrying call is shown:\n{stdout}");
}

#[test]
fn syscalls_vv_prints_every_call() {
    let output = raxdbg(&["syscalls", fixture("libctest.so").to_str().unwrap(), "-vv"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    // `brk` carries neither a path nor a buffer, so only the full trace
    // shows it: that is the difference `-vv` makes.
    assert!(stdout.contains("brk@"), "the full trace shows every call:\n{stdout}");
}

#[test]
fn syscalls_runs_jni_on_load_when_asked() {
    let output = raxdbg(&[
        "syscalls",
        fixture("libjnitest.so").to_str().unwrap(),
        "--jni-on-load",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        stdout.contains("JNI_OnLoad") && stdout.contains("0x10006"),
        "JNI_OnLoad must run and report the version it returned:\n{stdout}"
    );
}
