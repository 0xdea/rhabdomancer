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

// Standard library imports
use std::error::Error;

// External crate imports
// use ...;

// Internal imports
// use ...;

// const NAME: type = ...;

// static NAME: type = ...;

/// Dispatch to function implementing the selected action
pub fn run(action: &str) -> Result<(), Box<dyn Error>> {
    match action {
        "action1" => func1()?,
        _ => func2(action)?,
    }

    Ok(())
}

// Other functions ...

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
