//!
//! rhabdomancer - IDA Pro vulnerability research assistant
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "The road to exploitable bugs is paved with unexploitable bugs."
//! >
//! > -- Mark Dowd
//!
//! Rhabdomancer is a blazing fast IDA Pro headless plugin that locates all calls to potentially
//! insecure API functions in a binary file. Auditors can backtrace from these candidate points to
//! find pathways allowing access from untrusted input.
//!
//! ## Features
//! * Blazing fast, headless user experience courtesy of IDA Pro and Binarly's idalib Rust bindings.
//! * Support for C/C++ binary targets compiled for any architecture implemented by IDA Pro.
//! * Bad API function call locations are printed to stdout and marked with comments in the IDB.
//! * Known bad API functions are grouped in tiers of badness to help prioritize the audit work.
//!
//! ## Blog post
//! * <https://security.humanativaspa.it/doing-vulnerability-research-with-ida-pro-and-rust>
//!
//! ## See also
//! * <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
//! * <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
//! * <https://github.com/binarly-io/idalib/>
//! * <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>
//!
//! ## Compiling
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
//! 3. Compile rhabdomancer as follows:
//!     ```sh
//!     $ git clone https://github.com/0xdea/rhabdomancer
//!     $ cd rhabdomancer
//!     $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
//!     $ cargo build --release
//!     ```
//!
//! ## Usage
//! 1. Make sure IDA Pro is properly configured with a valid license.
//! 2. Run rhabdomancer as follows:
//!     ```sh
//!     $ ./target/release/rhabdomancer [binary file]
//!     ```
//! 3. Open the resulting `.i64` IDB file with IDA Pro.
//! 4. Select `Search` > `Text...`, flag `Find all occurrences`, and search for `[BAD `.
//! 5. Enjoy your results conveniently collected in an IDA Pro window.
//!
//! ## Tested with
//! * IDA Pro 9.0.240925 on macOS arm64.
//!
//! ## TODO
//! * Try the `bookmarks_t` API, despite it being cumbersome and having a `MAX_MARK_SLOT` of 1024.
//! * Enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
//! * Implement regex pattern matching, considering that `_func` in IDA Pro GUI is `.func` in idalib.
//! * Consider narrowing down marked cross-references (e.g, `is_code`, `is_data`, etc.).
//! * Implement a basic ruleset in the style of <https://github.com/Accenture/VulFi>.
//!

use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use config::{Config, ConfigError, File};
use idalib::ffi::BADADDR;
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::XRefQuery;
use idalib::{enable_console_messages, Address, IDAError};

// TODO: use the bookmarks API and make sure bookmarks and comments match (and text search includes everything...)

// TODO: test along with ghidra version on different types of binaries and compare output and performance
// TODO: what causes duplicate entries in stdout? Are they a problem?
// TODO: test with binaries with more than a function that matches a single bad pattern (e.g., case-insensitive)

// TODO: add test suite
// TODO: generate documentation and check that it makes sense;)

// TODO: clippy everything, use cargo udeps and deny
// TODO: push release(s) to crates.io

/// Priority of bad API functions
/// * High priority - These functions are generally considered insecure
/// * Medium priority - These functions are interesting and should be checked for insecure use cases
/// * Low priority - Code paths involving these functions should be carefully checked
enum Priority {
    High,
    Medium,
    Low,
}

/// List of known bad API function names organized by priority
#[derive(serde::Deserialize)]
struct KnownBadFunctions {
    high: Vec<String>,
    medium: Vec<String>,
    low: Vec<String>,
}

impl KnownBadFunctions {
    /// Populate the list of bad API function names from configuration file
    pub fn load() -> Result<Self, ConfigError> {
        let path =
            env::current_dir().expect("[!] Error: failed to determine the current directory");
        let conf_dir = path.join("conf");

        Config::builder()
            .add_source(File::from(conf_dir.join("rhabdomancer.toml")))
            .build()?
            .try_deserialize()
    }

    /// Check if a function is in the list of known bad API function names and return its priority
    fn check_function(&self, func: &Function) -> Option<Priority> {
        let func_matches = |x: &String| -> bool { x.eq_ignore_ascii_case(&func.name().unwrap()) };

        if self.high.iter().any(func_matches) {
            return Some(Priority::High);
        }

        if self.medium.iter().any(func_matches) {
            return Some(Priority::Medium);
        }

        if self.low.iter().any(func_matches) {
            return Some(Priority::Low);
        }

        None
    }
}

/// List of bad API functions found in target binary organized by priority
struct BadFunctions<'a> {
    high: BTreeMap<FunctionId, Function<'a>>,
    medium: BTreeMap<FunctionId, Function<'a>>,
    low: BTreeMap<FunctionId, Function<'a>>,
}

impl<'a> BadFunctions<'a> {
    /// Find all bad API functions in target binary
    fn find_all(idb: &'a IDB, bad: &KnownBadFunctions) -> Self {
        let mut found = Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
        };

        for (id, f) in idb.functions() {
            match bad.check_function(&f) {
                Some(Priority::High) => found.insert_function(id, f, &Priority::High),
                Some(Priority::Medium) => found.insert_function(id, f, &Priority::Medium),
                Some(Priority::Low) => found.insert_function(id, f, &Priority::Low),
                None => (),
            }
        }

        found
    }

    /// Insert a new bad API function in the list
    fn insert_function(&mut self, id: FunctionId, func: Function<'a>, priority: &Priority) {
        match priority {
            Priority::High => {
                self.high.insert(id, func);
            }
            Priority::Medium => {
                self.medium.insert(id, func);
            }
            Priority::Low => {
                self.low.insert(id, func);
            }
        }
    }

    /// Locate all calls to bad API functions and mark them
    fn locate_calls(&self, idb: &'a IDB) -> anyhow::Result<()> {
        for f in self.high.values() {
            Self::mark_calls(idb, f, &Priority::High)?;
        }
        for f in self.medium.values() {
            Self::mark_calls(idb, f, &Priority::Medium)?;
        }
        for f in self.low.values() {
            Self::mark_calls(idb, f, &Priority::Low)?;
        }

        Ok(())
    }

    /// Locate all calls to the specified function and mark them
    fn mark_calls(idb: &IDB, func: &Function, priority: &Priority) -> Result<(), IDAError> {
        // Prepare comment
        let comment = match priority {
            Priority::High => {
                format!("[BAD 0] {}", func.name().unwrap())
            }
            Priority::Medium => {
                format!("[BAD 1] {}", func.name().unwrap())
            }
            Priority::Low => {
                format!("[BAD 2] {}", func.name().unwrap())
            }
        };
        println!("\n{comment}");

        // Get first XREF if available, otherwise return immediately
        let Some(mut current) = idb.first_xref_to(func.start_address(), XRefQuery::ALL) else {
            return Ok(());
        };

        loop {
            // Handle .plt indirection in ELF binaries
            if is_in_plt(idb, current.from()) {
                if let Some(thunk) = idb.first_xref_to(
                    idb.function_at(current.from())
                        .map_or(BADADDR.into(), |f| f.start_address()),
                    XRefQuery::ALL,
                ) {
                    current = thunk;
                }
            }

            // Print address with caller function name if available
            let caller = idb
                .function_at(current.from())
                .map_or("<unknown>".to_string(), |f| f.name().unwrap());
            println!("{:#x} in {}", current.from(), caller);

            // Add comment if not already present to mark call location
            if !idb.get_cmt(current.from()).contains("[BAD ") {
                idb.append_cmt(current.from(), comment.clone())?;
            }

            // Get next XREF
            if let Some(next) = current.next_to() {
                current = next;
            } else {
                break;
            }
        }

        Ok(())
    }
}

/// Locate all calls to potentially insecure API functions in the binary file at `filepath`
pub fn run(filepath: &Path) -> anyhow::Result<()> {
    // Load known bad API function names from the configuration file
    println!("[*] Loading known bad API function names");
    let known_bad = KnownBadFunctions::load()?;

    // Enable console messages to report any license issues
    enable_console_messages(true);

    // Open target binary, run auto-analysis, and keep results
    println!("[*] Trying to analyze binary file {filepath:?}");
    if !filepath.is_file() {
        return Err(anyhow::anyhow!("invalid file path"));
    }
    let idb = IDB::open_with(filepath, true)?;
    println!("[+] Successfully analyzed binary file");

    // Disable console messages
    enable_console_messages(false);

    // Locate and mark bad API function calls in target binary
    println!();
    println!("[*] Finding bad API function calls...");
    BadFunctions::find_all(&idb, &known_bad).locate_calls(&idb)?;

    println!();
    println!("[+] Done processing binary file {filepath:?}");
    Ok(())
}

/// Check if an address is in the .plt segment
fn is_in_plt(idb: &IDB, addr: Address) -> bool {
    idb.segment_at(addr)
        .is_some_and(|s| s.name().unwrap().contains("plt"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
