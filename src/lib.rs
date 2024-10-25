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
    // TODO: make sure a user can distinguish between an error (nothing is printed after opening because of non-ergonomic API) and success (messages are printed)
    eprint!("[+] ");
    let idb = IDB::open_with(filepath, true)?;

    // TODO: select interesting API functions, case-insensitive
    // TODO: consider using regex as well, check Ghidra plugin
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

// TODO: see my interesting function list, semgrep, https://github.com/Accenture/VulFi
// TODO: grab config (insecure functions, tier, maybe message from external file); either use regular file, config (or more secure alternatives), or other serialization

// TODO: collect/print the calling function's name and location -- see also ghidra version
// TODO: add comment, to be used with Text search (Find all occurrences) - see also ghidra version

// TODO: add bookmark (with a folder for each tier!); see idasdk90/include/moves.hpp | class bookmarks_t: mark(ea, index, title=0, desc, ud=0?); get() to check for duplicates?, get_desc()? others...? 1024 max bookmark limit?!
// TODO: see also https://gist.github.com/idiom/74114d745d6c427333ac237f91eee414

// TODO: running a new scan should not overwrite previous bookmarks/comments, also handle previous hand-made bookmarks/comments

// TODO: future feature: implement basic rules to rule out obvious false positive?! (see VulFi)

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
