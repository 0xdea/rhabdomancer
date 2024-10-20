//
// rhabdomancer - Vulnerability research assistant that locates calls to potentially insecure functions in a binary file.
// Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//
// > "It's important to be quotable."  
// >  
// > -- Halvar Flake  
//
// TODO
//

// Standard library imports
use std::env;
use std::path::Path;
use std::process;

// External crate imports
// use ...;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

const PROG: &str = "rhabdomancer.exe";

fn main() {
    println!("rhabdomancer - Vulnerability research assistant that locates calls to potentially insecure functions in a binary file.");
    println!("Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>");
    println!();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let prog = Path::new(&args[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap_or(PROG);

    let action = match args.len() {
        1 => "default",
        2 => &args[1].clone(),
        _ => {
            usage(prog);
            process::exit(1);
        }
    };
    if action.starts_with('-') {
        usage(prog);
        process::exit(1);
    }

    // Let's do it
    match rhabdomancer::run(action) {
        Ok(()) => (),
        Err(err) => {
            eprintln!("[!] Error: {err}");
            process::exit(1);
        }
    }
}

/// Print usage information
fn usage(prog: &str) {
    println!("Usage:");
    println!(".\\{prog} TODO");
    println!("\nExamples:");
    println!(".\\{prog}");
    println!(".\\{prog} TODO");
}
