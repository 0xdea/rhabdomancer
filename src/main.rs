//! main.rs

use std::path::Path;
use std::{env, process};

const PROGRAM: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    println!("{PROGRAM} {VERSION} - IDA Pro vulnerability research assistant");
    println!("Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>");
    println!();

    // Force IDA Pro to stay quiet
    idalib::force_batch_mode();

    // Parse command line arguments
    let mut args = env::args();
    let argv0 = args.next().unwrap_or_else(|| PROGRAM.to_owned());

    let prog = Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(PROGRAM);

    let filename = match (args.next(), args.next()) {
        (Some(arg), None) if !arg.starts_with('-') => arg,
        _ => usage(prog),
    };

    // Let's do it
    match rhabdomancer::run(Path::new(&filename)) {
        Ok(_) => (),
        Err(err) => {
            eprintln!("[!] Error: {err:#}");
            process::exit(1);
        }
    }
}

/// Print usage information and exit
fn usage(prog: &str) -> ! {
    eprintln!("Usage:");
    eprintln!("{prog} <binary_file>");

    process::exit(1);
}
