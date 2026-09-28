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
