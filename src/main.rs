//! main.rs

use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

const PROGRAM: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    eprintln!("{PROGRAM} {VERSION} - IDA Pro vulnerability research assistant");
    eprintln!("Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>");
    eprintln!();

    // Force IDA Pro to stay quiet
    idalib::force_batch_mode();

    // Parse command line arguments
    let mut args = env::args_os();
    let argv0 = args.next().unwrap_or_else(|| OsString::from(PROGRAM));

    let prog = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(PROGRAM);

    let filename = match (args.next(), args.next()) {
        (Some(arg), None) if !arg.to_string_lossy().starts_with('-') => arg,
        _ => return usage(prog),
    };

    // Let's do it
    match rhabdomancer::run(Path::new(&filename)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[!] Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Print usage information and exit
fn usage(prog: &str) -> ExitCode {
    eprintln!("Usage:");
    eprintln!("{prog} <binary_file>");

    ExitCode::FAILURE
}
