//! Command-line parsing.
//!
//! Port of unidbg's `AndroidEmulatorBuilder` configuration surface, as a CLI:
//! the ABI, the SDK level, the library tree, the root directory, the function
//! to call, the seed and the trace selection.

use std::path::PathBuf;

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
}

/// Which trace `trace` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceKind {
    /// Instruction trace.
    Code,
    /// Memory access trace.
    Memory,
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
}

impl Options {
    /// Whether the guest is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.abi != "arm32"
    }

    /// The SDK level, defaulted per ABI as `AndroidEmulatorBuilder` does.
    pub fn sdk(&self) -> u32 {
        self.sdk
            .unwrap_or(if self.is_64bit() { 23 } else { 19 })
    }

    /// Which trace to run.
    pub fn trace_kind(&self) -> TraceKind {
        if self.trace_reads || self.trace_writes {
            TraceKind::Memory
        } else {
            TraceKind::Code
        }
    }

    /// Parses the arguments.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut args = args.iter();
        let verb = match args.next().map(String::as_str) {
            Some(verb @ ("run" | "info" | "trace" | "debug")) => verb.to_string(),
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
                "--libs-dir" => options.libs_dir = Some(PathBuf::from(next_value(&mut args, "--libs-dir")?)),
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
        Ok(options)
    }
}

fn next_value(args: &mut std::slice::Iter<'_, String>, option: &str) -> Result<String, String> {
    args.next()
        .cloned()
        .ok_or_else(|| format!("{option} needs a value"))
}

/// A decimal or `0x`-prefixed argument.
fn parse_number(text: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| format!("`{text}` is not a number"))
    } else {
        text.parse().map_err(|_| format!("`{text}` is not a number"))
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
    fn arm32_defaults_to_the_sdk19_libraries() {
        let options = parse(&["run", "lib.so", "--abi", "arm32"]).unwrap();
        assert!(!options.is_64bit());
        assert_eq!(options.sdk(), 19);
    }

    #[test]
    fn trace_flags_pick_the_trace() {
        let options = parse(&["trace", "lib.so", "--read", "--write"]).unwrap();
        assert_eq!(options.trace_kind(), TraceKind::Memory);
        let options = parse(&["trace", "lib.so"]).unwrap();
        assert_eq!(options.trace_kind(), TraceKind::Code);
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
}
