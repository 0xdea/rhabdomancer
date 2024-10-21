//!
//! rhabdomancer - Vulnerability research assistant that locates calls to potentially insecure functions in a binary file.
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "It's important to be quotable."  
//! >  
//! > -- Halvar Flake  
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
