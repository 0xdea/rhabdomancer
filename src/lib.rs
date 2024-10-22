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

use std::error::Error;
use std::io;
use std::path::Path;

use idalib::idb::IDB;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

/// Dispatch to function implementing the selected action
pub fn run(filepath: &Path) -> Result<(), Box<dyn Error>> {
    // Check target file
    if !filepath.is_file() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            "not a file",
        )));
    }

    let idb = IDB::open(filepath)?;

    Ok(())
}

// Other functions ...
// TODO: grab config (insecure functions, tier, maybe message from external file); either use regular file, config (or more secure alternatives), or other serialization
// TODO: reason on the output to make it usable/perhaps importable into IDA Pro and/or other tools; see also https://github.com/Accenture/VulFi
// TODO: perhaps we can save an IDA db that can be opened in the tool, looks like the best course of action to me

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
