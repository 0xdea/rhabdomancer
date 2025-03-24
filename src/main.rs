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
    let args = env::args().collect::<Vec<_>>();

    let prog = Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or(PROGRAM);

    let filename = match args.len() {
        2 => &args[1],
        _ => "-",
    };
    if filename.starts_with('-') {
        usage(prog);
    }

    // Let's do it
    match rhabdomancer::run(Path::new(filename)) {
        Ok(_) => (),
        Err(err) => {
            eprintln!("[!] Error: {err:#}");
            process::exit(1);
        }
    }
}

/// Print usage information and exit
fn usage(prog: &str) {
    println!("Usage:");
    println!("{prog} <binary_file>");

    process::exit(0);
}
