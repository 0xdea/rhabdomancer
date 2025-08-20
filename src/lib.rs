//!
//! rhabdomancer - IDA Pro vulnerability research assistant
//! Copyright (c) 2024-2025 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "The road to exploitable bugs is paved with unexploitable bugs."
//! >
//! > -- Mark Dowd
//!
//! Rhabdomancer is a blazing fast IDA Pro headless plugin that locates calls to potentially
//! insecure API functions in a binary file. Auditors can backtrace from these candidate points to
//! find pathways allowing access to untrusted input.
//!
//! ## Features
//! * Blazing fast, headless user experience courtesy of IDA Pro 9 and Binarly's idalib Rust bindings.
//! * Support for C/C++ binary targets compiled for any architecture implemented by IDA Pro.
//! * Bad API function call locations are printed to stdout and marked in the IDB.
//! * Known bad API functions are grouped in tiers of badness to help prioritize the audit work.
//!     * [BAD 0] High priority - Functions that are generally considered insecure
//!     * [BAD 1] Medium priority - Interesting functions that should be checked for insecure use cases.
//!     * [BAD 2] Low priority - Code paths involving these functions should be carefully checked.
//! * The list of known bad API functions can be easily customized by editing `conf/rhabdomancer.toml`.
//!
//! ## Blog post
//! * <https://security.humanativaspa.it/streamlining-vulnerability-research-with-ida-pro-and-rust>
//!
//! ## See also
//! * <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
//! * <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
//! * <https://github.com/binarly-io/idalib>
//! * <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>
//!
//! ## Installing
//! The easiest way to get the latest release is via [crates.io](https://crates.io/crates/rhabdomancer):
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
//! 3. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
//! 4. On Linux/macOS, install as follows:
//!     ```sh
//!     export IDASDKDIR=/path/to/idasdk
//!     export IDADIR=/path/to/ida # if not set, the build script will check common locations
//!     cargo install rhabdomancer
//!     ```
//!    On Windows, instead, use the following commands:
//!     ```powershell
//!     $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
//!     $env:PATH="\path\to\ida;$env:PATH"
//!     $env:IDASDKDIR="\path\to\idasdk"
//!     $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
//!     cargo install rhabdomancer
//!     ```
//!
//! ## Compiling
//! Alternatively, you can build from [source](https://github.com/0xdea/rhabdomancer):
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
//! 3. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
//! 4. On Linux/macOS, compile as follows:
//!     ```sh
//!     git clone --depth 1 https://github.com/0xdea/rhabdomancer
//!     cd rhabdomancer
//!     export IDASDKDIR=/path/to/idasdk # or edit .cargo/config.toml
//!     export IDADIR=/path/to/ida # if not set, the build script will check common locations
//!     cargo build --release
//!     ```
//!    On Windows, instead, use the following commands:
//!     ```powershell
//!     git clone --depth 1 https://github.com/0xdea/rhabdomancer
//!     cd rhabdomancer
//!     $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
//!     $env:PATH="\path\to\ida;$env:PATH"
//!     $env:IDASDKDIR="\path\to\idasdk"
//!     $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
//!     cargo build --release
//!     ```
//!
//! ## Usage
//! 1. Make sure IDA Pro is properly configured with a valid license.
//! 2. Customize the list of known bad API functions in `conf/rhabdomancer.toml` if needed.
//! 3. Run as follows:
//!     ```sh
//!     rhabdomancer <binary_file>
//!     ```
//!    Any existing `.i64` IDB file will be updated; otherwise, a new IDB file will be created.
//! 4. Open the resulting `.i64` IDB file with IDA Pro.
//! 5. Select `View` > `Open subviews` > `Bookmarks`
//! 6. Enjoy your results conveniently collected in an IDA Pro window.
//!
//! *Note: rhabdomancer also adds comments at marked call locations.*
//!
//! ## Compatibility
//! * IDA Pro 9.0.240925 - Latest compatible: v0.2.4.
//! * IDA Pro 9.0.241217 - Latest compatible: v0.3.5.
//! * IDA Pro 9.1.250226 - Latest compatible: current version.
//!
//! *Note: check [idalib](https://github.com/binarly-io/idalib) documentation for additional information.*
//!
//! ## Changelog
//! * <https://github.com/0xdea/rhabdomancer/blob/master/CHANGELOG.md>
//!
//! ## TODO
//! * Enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
//! * Implement a basic ruleset in the style of [VulFi](https://github.com/Accenture/VulFi)
//!   and [VulnFanatic](https://github.com/Martyx00/VulnFanatic).
//!

#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::BTreeMap;
use std::env;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::Context;
use config::{Config, ConfigError, File};
use idalib::bookmarks::BookmarkIndex;
use idalib::ffi::BADADDR;
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};
use regex::Regex;

/// Number of marked call locations
static COUNTER: AtomicU32 = AtomicU32::new(0);

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
    /// Populate the list of bad API function names from the configuration file
    fn load() -> Result<Self, ConfigError> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/rhabdomancer.toml");

        println!("[*] Using configuration file `{}`", path.display());
        Config::builder()
            .add_source(File::from(path))
            .build()?
            .try_deserialize()
    }

    /// Check if a function is in the list of known bad API function names and return its priority
    fn check_function(&self, func: &Function) -> Option<Priority> {
        let re = Regex::new(&format!(r"^[._]?{}$", &func.name()?)).ok()?;

        if self.high.iter().any(|bad| re.is_match(bad)) {
            return Some(Priority::High);
        }
        if self.medium.iter().any(|bad| re.is_match(bad)) {
            return Some(Priority::Medium);
        }
        if self.low.iter().any(|bad| re.is_match(bad)) {
            return Some(Priority::Low);
        }

        None
    }
}

/// List of bad API functions found in the target binary organized by priority
struct BadFunctions<'a> {
    high: BTreeMap<FunctionId, Function<'a>>,
    medium: BTreeMap<FunctionId, Function<'a>>,
    low: BTreeMap<FunctionId, Function<'a>>,
}

impl<'a> BadFunctions<'a> {
    /// Find bad API functions in the target binary
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

    /// Locate calls to bad API functions and mark them
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

    /// Locate calls to the specified function and mark them
    fn mark_calls(idb: &IDB, func: &Function, priority: &Priority) -> Result<(), IDAError> {
        // Return an error if the function name is empty (shouldn't happen)
        let Some(func_name) = func.name() else {
            return Err(IDAError::ffi_with("empty function name"));
        };

        // Prepare description
        let desc = match priority {
            Priority::High => {
                format!("[BAD 0] {}", func_name.trim_start_matches('.'))
            }
            Priority::Medium => {
                format!("[BAD 1] {}", func_name.trim_start_matches('.'))
            }
            Priority::Low => {
                format!("[BAD 2] {}", func_name.trim_start_matches('.'))
            }
        };
        println!("\n{desc}");

        // Traverse XREFs and mark call locations
        idb.first_xref_to(func.start_address(), XRefQuery::ALL)
            .map_or(Ok(()), |cur| Self::traverse_xrefs(idb, &cur, &desc))
    }

    /// Recursively traverse XREFs and mark call locations
    fn traverse_xrefs(idb: &IDB, xref: &XRef, desc: &str) -> Result<(), IDAError> {
        // Handle .plt indirection in ELF binaries
        if is_in_plt(idb, xref.from()) {
            idb.first_xref_to(
                idb.function_at(xref.from())
                    .map_or_else(|| BADADDR.into(), |func| func.start_address()),
                XRefQuery::ALL,
            )
            .map(|thunk| Self::traverse_xrefs(idb, &thunk, desc));
        } else if xref.is_code() {
            // Print address with caller function name if available
            let caller = idb.function_at(xref.from()).map_or_else(
                || "<unknown>".into(),
                |func| func.name().unwrap_or_else(|| "<no name>".into()),
            );
            println!("{:#X} in {}", xref.from(), caller);

            // Add a bookmark if not already present to mark the call location
            if !idb
                .bookmarks()
                .get_description(xref.from())
                .unwrap_or_default()
                .contains("[BAD ")
            {
                idb.bookmarks().mark(xref.from(), desc)?;
                COUNTER.fetch_add(1, Ordering::Relaxed);
            }

            // Add a comment if not already present to mark the call location
            if !idb
                .get_cmt(xref.from())
                .unwrap_or_default()
                .contains("[BAD ")
            {
                idb.append_cmt(xref.from(), desc)?;
            }
        }

        // Process next XREF
        xref.next_to()
            .map_or(Ok(()), |next| Self::traverse_xrefs(idb, &next, desc))
    }
}

/// Locate calls to potentially insecure API functions in the binary file at `filepath`.
///
/// ## Errors
///
/// Returns how many call locations were marked or a generic error in case something goes wrong.
pub fn run(filepath: &Path) -> anyhow::Result<BookmarkIndex> {
    // Load known bad API function names from the configuration file
    println!("[*] Loading known bad API function names");
    let known_bad =
        KnownBadFunctions::load().context("Failed to load known bad API function names")?;

    // Open the target binary, run auto-analysis, and keep results
    println!("[*] Analyzing binary file `{}`", filepath.display());
    let idb = IDB::open_with(filepath, true, true)
        .with_context(|| format!("Failed to analyze binary file `{}`", filepath.display()))?;
    println!("[+] Successfully analyzed binary file");
    println!();

    // Print binary file information
    println!("[-] Processor: {}", idb.processor().long_name(),);
    println!("[-] Compiler: {:?}", idb.meta().cc_id());
    println!("[-] File type: {:?}", idb.meta().filetype());
    println!();

    // Locate and mark bad API function calls in the target binary
    println!("[*] Finding bad API function calls...");
    BadFunctions::find_all(&idb, &known_bad)
        .locate_calls(&idb)
        .context("Failed to find bad API function calls")?;

    println!();
    println!("[+] Marked {COUNTER:?} new call locations");
    println!("[+] Done processing binary file `{}`", filepath.display());
    Ok(COUNTER.load(Ordering::Relaxed))
}

/// Check if an address is in the .plt segment
fn is_in_plt(idb: &IDB, addr: Address) -> bool {
    idb.segment_at(addr)
        .is_some_and(|segm| segm.name().unwrap_or_default().contains("plt"))
}
