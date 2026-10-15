//! Command-line parsing.
//!
//! Port of unidbg's `AndroidEmulatorBuilder` configuration surface, as a CLI:
//! the ABI, the SDK level, the library tree, the root directory, the function
//! to call, the seed and the trace selection.

use std::path::PathBuf;

/// The address `--gdb` listens on unless `--gdb-bind` says otherwise.
///
/// Loopback, because the GDB remote protocol is unauthenticated and grants
/// full read/write access to guest memory and registers.
pub const DEFAULT_GDB_BIND: &str = "127.0.0.1";

/// What the user asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `run <lib.so>`
    Run {
        /// The library to load.
        library: String,
    },
    /// `info <lib.so>`
    Info {
        /// The library to inspect.
        library: String,
    },
    /// `trace <lib.so>`
    Trace {
        /// The library to load.
        library: String,
    },
    /// `debug <lib.so>`
    Debug {
        /// The library to load.
        library: String,
    },
    /// `syscalls <lib.so>`
    Syscalls {
        /// The library to load.
        library: String,
    },
}

/// Which trace `trace` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceKind {
    /// Instruction trace.
    Code,
    /// Memory access trace.
    Memory,
    /// Function calls.
    Functions,
}

/// A `--call` target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The function's name, without its argument list.
    pub name: String,
    /// The signature as written on the command line.
    pub signature: String,
}

/// The parsed command line.
#[derive(Clone, Debug)]
pub struct Options {
    /// The command and its library.
    pub command: Command,
    /// `--abi arm64|arm32`.
    pub abi: String,
    /// `--sdk <level>`.
    pub sdk: Option<u32>,
    /// `--libs-dir <dir>`.
    pub libs_dir: Option<PathBuf>,
    /// `--root <dir>`.
    pub root: Option<PathBuf>,
    /// `--call <name(args)>`.
    pub call: Option<Call>,
    /// The arguments following `--call`.
    pub call_arguments: Vec<u64>,
    /// `--seed <n>`.
    pub seed: u64,
    /// `--stdout <file>`.
    pub stdout_file: Option<PathBuf>,
    /// `--log <filter>`.
    pub log: Option<String>,
    /// `--leak-check`.
    pub leak_check: bool,
    /// `--code`.
    pub trace_code: bool,
    /// `--read`.
    pub trace_reads: bool,
    /// `--write`.
    pub trace_writes: bool,
    /// `--functions`.
    pub trace_functions: bool,
    /// `--jni-args`: also print the arguments of every `JNIEnv`/`JavaVM` call.
    ///
    /// Only meaningful with `--functions`, because that is the trace that names
    /// the callee; on any other trace there is no call to attach arguments to.
    pub jni_args: bool,
    /// `--out <file>`: where a trace's lines go instead of this terminal.
    pub out: Option<PathBuf>,
    /// `--syscall-detail <n>`: how much of a syscall trace to print.
    pub syscall_detail: SyscallDetail,
    /// `--gdb <port>`: serve the GDB remote serial protocol on this TCP port.
    ///
    /// Only meaningful with `debug`, which without it opens the console.
    pub gdb_port: Option<u16>,
    /// `--gdb-bind <ip>`: the address the GDB server listens on.
    ///
    /// Loopback by default: the protocol carries no authentication and grants
    /// full read/write access to guest memory and registers, so anything wider
    /// has to be asked for.
    pub gdb_bind: String,
    /// `--jni-on-load`: run the library's `JNI_OnLoad` before the `--call`.
    ///
    /// A packed JNI library exports nothing else, and `JNI_OnLoad` needs a
    /// real `JavaVM*`, so this runs it against a `dvm`-built VM instead of
    /// passing zeroes. With no `--call` it is the whole run.
    pub jni_on_load: bool,
}

/// How much of a syscall trace to print.
///
/// Ordered so `-v -v` accumulates, which is what the flag reads like.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyscallDetail {
    /// Only the summary and the protection report.
    #[default]
    Summary,
    /// The syscalls that carry a path or a captured buffer.
    Interesting,
    /// Every syscall.
    Full,
}

impl Options {
    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.abi != "arm32"
    }

    /// The SDK level, defaulting to 23 for both ABIs.
    ///
    /// `AndroidEmulatorBuilder::for_32bit` also defaults to 23, and so does
    /// this: the SDK 19 arm64 and arm32 trees are bundled, but 19's arm32 libc
    /// faults in `__system_property_area_init` because it dereferences a null
    /// `prop_area` when the properties file is not mapped. `--sdk 19` still
    /// selects it explicitly; the default is the one that boots.
    pub fn sdk(&self) -> u32 {
        self.sdk.unwrap_or(23)
    }

    /// Which trace to run.
    pub fn trace_kind(&self) -> TraceKind {
        if self.trace_reads || self.trace_writes {
            TraceKind::Memory
        } else if self.trace_functions {
            TraceKind::Functions
        } else {
            TraceKind::Code
        }
    }

    /// Parses the arguments.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut args = args.iter();
        let verb = match args.next().map(String::as_str) {
            Some(verb @ ("run" | "info" | "trace" | "debug" | "syscalls")) => verb.to_string(),
            Some(other) => return Err(format!("unknown command `{other}`")),
            None => return Err("a command is required".into()),
        };
        let library = args
            .next()
            .ok_or_else(|| "a library path is required".to_string())?;
        let mut options = Options {
            command: match verb.as_str() {
                "run" => Command::Run {
                    library: library.clone(),
                },
                "info" => Command::Info {
                    library: library.clone(),
                },
                "trace" => Command::Trace {
                    library: library.clone(),
                },
                "syscalls" => Command::Syscalls {
                    library: library.clone(),
                },
                _ => Command::Debug {
                    library: library.clone(),
                },
            },
            abi: "arm64".into(),
            sdk: None,
            libs_dir: None,
            root: None,
            call: None,
            call_arguments: Vec::new(),
            seed: 0,
            stdout_file: None,
            log: None,
            leak_check: false,
            trace_code: false,
            trace_reads: false,
            trace_writes: false,
            trace_functions: false,
            jni_args: false,
            out: None,
            syscall_detail: SyscallDetail::default(),
            gdb_port: None,
            gdb_bind: DEFAULT_GDB_BIND.to_string(),
            jni_on_load: false,
        };

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--abi" => {
                    options.abi = next_value(&mut args, "--abi")?;
                    if options.abi != "arm64" && options.abi != "arm32" {
                        return Err(format!("unknown ABI `{}`", options.abi));
                    }
                }
                "--sdk" => {
                    options.sdk = Some(
                        next_value(&mut args, "--sdk")?
                            .parse()
                            .map_err(|_| "--sdk needs a number".to_string())?,
                    );
                }
                "--libs-dir" => {
                    options.libs_dir = Some(PathBuf::from(next_value(&mut args, "--libs-dir")?))
                }
                "--root" => options.root = Some(PathBuf::from(next_value(&mut args, "--root")?)),
                "--seed" => {
                    options.seed = next_value(&mut args, "--seed")?
                        .parse()
                        .map_err(|_| "--seed needs a number".to_string())?;
                }
                "--stdout" => {
                    options.stdout_file = Some(PathBuf::from(next_value(&mut args, "--stdout")?))
                }
                "--log" => options.log = Some(next_value(&mut args, "--log")?),
                "--leak-check" => options.leak_check = true,
                "--code" => options.trace_code = true,
                "--read" => options.trace_reads = true,
                "--write" => options.trace_writes = true,
                "--functions" => options.trace_functions = true,
                "--jni-args" => options.jni_args = true,
                "--out" => options.out = Some(PathBuf::from(next_value(&mut args, "--out")?)),
                // Each flag turns one more level on, so `-vv` is cumulative
                // the way it reads at the command line.
                "-v" | "--syscalls" => {
                    options.syscall_detail = options.syscall_detail.max(SyscallDetail::Interesting)
                }
                "-vv" | "--syscalls=all" => options.syscall_detail = SyscallDetail::Full,
                "--jni-on-load" => options.jni_on_load = true,
                "--gdb" => {
                    options.gdb_port = Some(
                        next_value(&mut args, "--gdb")?
                            .parse()
                            .map_err(|_| "--gdb needs a port number".to_string())?,
                    )
                }
                "--gdb-bind" => {
                    let bind = next_value(&mut args, "--gdb-bind")?;
                    // Parsed here rather than at bind time so a typo is a
                    // command-line error with usage, not a later runtime one.
                    if bind.parse::<std::net::IpAddr>().is_err() {
                        return Err("--gdb-bind needs an IP address".into());
                    }
                    options.gdb_bind = bind;
                }
                "--call" => {
                    let signature = next_value(&mut args, "--call")?;
                    let name = signature
                        .split('(')
                        .next()
                        .unwrap_or(&signature)
                        .to_string();
                    options.call = Some(Call { name, signature });
                }
                other if other.starts_with("--") => {
                    return Err(format!("unknown option `{other}`"));
                }
                other => {
                    // Everything after `--call` is an argument to it.
                    let value = parse_number(other)?;
                    if options.call.is_none() {
                        return Err(format!("unexpected argument `{other}`"));
                    }
                    options.call_arguments.push(value);
                }
            }
        }
        // One trace per run: the three hooks have nothing to say to each
        // other, and picking one silently would hide a mistake in the command
        // line.
        if options.trace_functions && (options.trace_reads || options.trace_writes) {
            return Err("--functions cannot be combined with --read/--write".into());
        }
        if options.gdb_port.is_some() {
            if !matches!(options.command, Command::Debug { .. }) {
                return Err("--gdb requires debug".into());
            }
            // The server stops at the callee's first instruction, so without a
            // call there is no execution for the client to take part in.
            if options.call.is_none() {
                return Err("--gdb requires --call".into());
            }
        } else if options.gdb_bind != DEFAULT_GDB_BIND {
            return Err("--gdb-bind requires --gdb".into());
        }
        Ok(options)
    }
}

fn next_value(args: &mut std::slice::Iter<'_, String>, option: &str) -> Result<String, String> {
    args.next()
        .cloned()
        .ok_or_else(|| format!("{option} needs a value"))
}

/// A decimal or `0x`-prefixed argument.
pub fn parse_number(text: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| format!("`{text}` is not a number"))
    } else {
        text.parse()
            .map_err(|_| format!("`{text}` is not a number"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        Options::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn a_run_with_a_call_parses() {
        let options = parse(&["run", "lib.so", "--call", "add2(II)I", "2", "40"]).unwrap();
        assert!(options.is_64bit());
        assert_eq!(options.sdk(), 23);
        assert_eq!(options.call.as_ref().unwrap().name, "add2");
        assert_eq!(options.call_arguments, vec![2, 40]);
    }

    #[test]
    fn both_abis_default_to_the_sdk23_libraries() {
        // SDK 19's arm32 libc faults in `__system_property_area_init`, so a
        // 32-bit guest that defaulted to it could not load anything. `--sdk 19`
        // still selects it explicitly.
        let arm32 = parse(&["run", "lib.so", "--abi", "arm32"]).unwrap();
        assert!(!arm32.is_64bit());
        assert_eq!(arm32.sdk(), 23);
        let arm64 = parse(&["run", "lib.so"]).unwrap();
        assert_eq!(arm64.sdk(), 23);
        let explicit = parse(&["run", "lib.so", "--sdk", "19"]).unwrap();
        assert_eq!(explicit.sdk(), 19);
    }

    #[test]
    fn trace_flags_pick_the_trace() {
        let options = parse(&["trace", "lib.so", "--read", "--write"]).unwrap();
        assert_eq!(options.trace_kind(), TraceKind::Memory);
        let options = parse(&["trace", "lib.so"]).unwrap();
        assert_eq!(options.trace_kind(), TraceKind::Code);
    }

    #[test]
    fn functions_and_a_memory_trace_cannot_be_asked_for_at_once() {
        let options = parse(&["trace", "lib.so", "--functions"]).unwrap();
        assert_eq!(options.trace_kind(), TraceKind::Functions);

        let error = parse(&["trace", "lib.so", "--functions", "--read"]).unwrap_err();
        assert!(error.contains("cannot be combined"), "{error}");
        assert!(parse(&["trace", "lib.so", "--functions", "--write"]).is_err());
    }

    #[test]
    fn jni_args_is_off_by_default_and_parsed() {
        let options = parse(&["trace", "lib.so", "--functions"]).unwrap();
        assert!(
            !options.jni_args,
            "arguments are opt-in, not noise by default"
        );

        let options = parse(&["trace", "lib.so", "--functions", "--jni-args"]).unwrap();
        assert!(options.jni_args);
    }

    #[test]
    fn an_out_file_is_parsed() {
        let options = parse(&["trace", "lib.so", "--out", "trace.log"]).unwrap();
        assert_eq!(options.out, Some(PathBuf::from("trace.log")));
    }

    #[test]
    fn a_hex_argument_parses() {
        let options = parse(&["run", "lib.so", "--call", "f()V", "0x2a"]).unwrap();
        assert_eq!(options.call_arguments, vec![0x2a]);
    }

    #[test]
    fn an_unknown_option_is_rejected() {
        assert!(parse(&["run", "lib.so", "--nope"]).is_err());
        assert!(parse(&["nope", "lib.so"]).is_err());
        assert!(parse(&["run"]).is_err());
    }

    #[test]
    fn a_gdb_debug_session_takes_a_port_and_a_call() {
        let options = parse(&["debug", "lib.so", "--gdb", "23946", "--call", "hello()V"]).unwrap();
        assert_eq!(options.gdb_port, Some(23946));
        // Loopback unless asked otherwise: the protocol has no authentication.
        assert_eq!(options.gdb_bind, DEFAULT_GDB_BIND);

        let bound = parse(&[
            "debug",
            "lib.so",
            "--gdb",
            "23946",
            "--gdb-bind",
            "0.0.0.0",
            "--call",
            "hello()V",
        ])
        .unwrap();
        assert_eq!(bound.gdb_bind, "0.0.0.0");
    }

    #[test]
    fn a_gdb_session_needs_a_port_a_call_and_the_debug_command() {
        let error = parse(&["debug", "lib.so", "--gdb", "nope", "--call", "hello()V"]).unwrap_err();
        assert!(error.contains("--gdb needs a port number"), "{error}");

        let error =
            parse(&["debug", "lib.so", "--gdb", "99999", "--call", "hello()V"]).unwrap_err();
        assert!(error.contains("--gdb needs a port number"), "{error}");

        let error = parse(&[
            "debug",
            "lib.so",
            "--gdb",
            "23946",
            "--gdb-bind",
            "localhost",
            "--call",
            "hello()V",
        ])
        .unwrap_err();
        assert!(error.contains("--gdb-bind needs an IP address"), "{error}");

        // Without a call the client would attach to a guest that has nothing
        // to run, so it is refused rather than left idle.
        let error = parse(&["debug", "lib.so", "--gdb", "23946"]).unwrap_err();
        assert!(error.contains("--gdb requires --call"), "{error}");

        let error = parse(&["run", "lib.so", "--gdb", "23946", "--call", "hello()V"]).unwrap_err();
        assert!(error.contains("--gdb requires debug"), "{error}");

        let error = parse(&["debug", "lib.so", "--gdb-bind", "0.0.0.0"]).unwrap_err();
        assert!(error.contains("--gdb-bind requires --gdb"), "{error}");
    }
}
