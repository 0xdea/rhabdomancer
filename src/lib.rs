//!
//! rhabdomancer - IDA Pro vulnerability research assistant
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "The road to exploitable bugs is paved with unexploitable bugs."
//! >
//! > -- Mark Dowd
//!
//! TODO
//!
//! # See also
//! [TODO](TODO)
//!
//! # Cross-compiling
//! ```sh
//! [macOS example]
//! $ brew install mingw-w64
//! $ rustup target add x86_64-pc-windows-gnu
//! $ cargo build --release --target x86_64-pc-windows-gnu
//! ```
//!
//! # Usage
//! ```sh
//! TODO
//! ```
//!
//! # Examples
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! # Tested on
//! * TODO
//!
//! # TODO
//! * TODO
//!

use idalib::func::Function;
use idalib::idb::IDB;
use idalib::xref::XRefQuery;
use std::error::Error;
use std::path::Path;

// TODO: const NAME: type = ...;
// TODO: static NAME: type = ...;

/// Main program logic
pub fn run(filepath: &Path) -> anyhow::Result<()> {
    println!("[*] Trying to analyze binary file {}", filepath.display());

    // Check target file
    if !filepath.is_file() {
        return Err(anyhow::anyhow!(format!("{:?} is not a file", filepath)));

        /*
        Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            "not a file",
        ))); */
    }

    // Open target file, run auto-analysis, and keep results
    eprint!("[+] ");
    let idb = IDB::open_with(filepath, true)?;

    for (id, f) in idb.functions() {
        println!("{id} {}", f.name().unwrap());

        // TODO: move logic outside and handle errors, maybe use a suitable collection if needed
        get_xrefs(&idb, f);

        /*
        let xref = idb
            .first_xref_to(f.start_address(), XRefQuery::ALL)
            .map_or(0x0, |x| x.from());
        println!("{:x}", xref)
        */
    }

    Ok(())
}

/// TODO
fn get_xrefs(idb: &IDB, func: Function) -> anyhow::Result<()> {
    let mut current = idb
        .first_xref_to(func.start_address(), XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no XREFs to function {}", func.name().unwrap()))?;

    loop {
        println!("{:#x}", current.from());

        match current.next_to() {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(())
}

// TODO: grab config (insecure functions, tier, maybe message from external file); either use regular file, config (or more secure alternatives), or other serialization
// TODO: see also https://github.com/Accenture/VulFi
// TODO: reason on the output to make it usable/perhaps importable into IDA Pro and/or other tools; perhaps we can save an IDA db that can be opened in the tool
// TODO: add bookmark/comment (see also ghidra version), but collect also the calling function's name

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
