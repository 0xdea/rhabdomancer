//
// rhabdomancer - IDA Pro vulnerability research assistant
// Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//
// > "The road to exploitable bugs is paved with unexploitable bugs."
// >
// > -- Mark Dowd
//
// TODO
//

use std::env;
use std::path::Path;
use std::process;

// External crate imports
// use ...;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

const PROG: &str = "rhabdomancer";

fn main() {
    println!("rhabdomancer - IDA Pro vulnerability research assistant");
    println!("Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>");
    println!();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let prog = Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or(PROG);

    let filename = match args.len() {
        2 => &args[1],
        _ => "-",
    };
    if filename.starts_with('-') {
        usage(prog);
    }

    // Let's do it
    match rhabdomancer::run(Path::new(filename)) {
        Ok(()) => (),
        Err(err) => {
            eprintln!("[!] Error: {err}");
            process::exit(1);
        }
    }
}

/// Print usage information and exit
fn usage(prog: &str) {
    println!("Usage:");
    println!("./{prog} [binary file]");
    println!("\nExamples:");
    println!("./{prog} TODO");
    println!("./{prog} TODO");

    process::exit(1);
}
