//! main.rs

use std::env;
use std::path::Path;
use std::process::ExitCode;

const PROGRAM: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    eprintln!("{PROGRAM} {VERSION} - IDA Pro vulnerability research assistant");
    eprintln!("Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>");
    eprintln!();

    // Parse command line arguments
    let mut args = env::args();
    let argv0 = args.next().unwrap_or_else(|| PROGRAM.to_owned());

    let prog = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(PROGRAM);

    let filename = match (args.next(), args.next()) {
        (Some(arg), None) if !arg.starts_with('-') => arg,
        _ => return usage(prog),
    };

    // Force IDA Pro to stay quiet
    idalib::force_batch_mode();

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
