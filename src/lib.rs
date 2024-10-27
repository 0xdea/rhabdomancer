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
//! TODO description:
// * C/C++ target
// * Tiers of badness
// * Briefly cover pros/cons of candidate point strategy
// * Mention TAOSSA and other strategies
// * Rust, idalib, headless, performance
//!
//! # See also
//! * <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
//! * <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
//! * <https://github.com/binarly-io/idalib/>
//!
//! ## Compiling
//! 1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>)
//! 2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>)
//! 3. Compile rhabdomancer as follows (macOS example):
//! ```sh
//! $ git clone https://github.com/0xdea/rhabdomancer
//! $ cd rhabdomancer
//! $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
//! $ cargo build --release
//! ```
//!
//! # Usage
//! ```sh
//! TODO
//! ```
//!
//! # Example
//! TODO:
//! ```sh
//! TODO
//! ```
//!
//! # Tested with
//! * IDA Pro 9.0.240925 on macOS arm64
//!
//! # TODO
//! * Enrich known bad API function list (see <https://github.com/0xdea/semgrep-rules>)
//! * Implement regex pattern matching instead of ASCII case insensitive matching
//! * Implement a basic ruleset in the style of <https://github.com/Accenture/VulFi>
//!

use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use config::{Config, ConfigError, File};
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::XRefQuery;
use idalib::IDAError;

// TODO: mark calls locations with comment, to be used with Text search (Find all occurrences) - specify this in the comments/README and explain why bookmarks weren't used instead (cumbersome, limit)
// TODO: add bookmark (with a folder for each tier!); see idasdk90/include/moves.hpp | class bookmarks_t: mark(ea, index, title=0, desc, ud=0?); get() to check for duplicates?, get_desc()? others...? 1024 max bookmark limit?!
// TODO: see also https://gist.github.com/idiom/74114d745d6c427333ac237f91eee414

// TODO: test along with ghidra version and compare output and performance
// TODO: search only for code XREFs, not data XREFs (e.g., XRefQuery::FAR)? Pay attention to duplicate entries, what's the cause?
// TODO: should we also check for some tags/function attributes such as external or what we have so far is good enough? (KISS) -- see IDA book from p.478
// TODO: test performance with large files, e.g. zysh; optimize data structures to make them more performant/idiomatic if needed
// TODO: test with binaries with more than a function that matches a single bad pattern (e.g., case-insensitive)
// TODO: clippy everything, use cargo udeps and deny

// TODO: add test suite
// TODO: generate documentation and check that it makes sense;)

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
    pub fn populate() -> Result<Self, ConfigError> {
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
        if self
            .high
            .iter()
            .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
        {
            return Some(Priority::High);
        }

        if self
            .medium
            .iter()
            .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
        {
            return Some(Priority::Medium);
        }

        if self
            .low
            .iter()
            .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
        {
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
    /// Find bad API functions in target binary
    fn find(idb: &'a IDB, bad: &KnownBadFunctions) -> Self {
        let mut found = Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
        };

        for (id, f) in idb.functions() {
            match bad.check_function(&f) {
                Some(Priority::High) => found.insert(id, f, &Priority::High),
                Some(Priority::Medium) => found.insert(id, f, &Priority::Medium),
                Some(Priority::Low) => found.insert(id, f, &Priority::Low),
                None => (),
            }
        }

        found
    }

    /// Insert a new bad API function found in target binary
    fn insert(&mut self, id: FunctionId, function: Function<'a>, priority: &Priority) {
        match priority {
            Priority::High => {
                self.high.insert(id, function);
            }
            Priority::Medium => {
                self.medium.insert(id, function);
            }
            Priority::Low => {
                self.low.insert(id, function);
            }
        }
    }
}

/// Locate all calls to potentially insecure API functions in the binary file at `filepath`
pub fn run(filepath: &Path) -> anyhow::Result<()> {
    // Load known bad API function names from the configuration file
    println!("[*] Loading known bad API function names");
    let bad = KnownBadFunctions::populate()?;

    // Check target binary
    println!("[*] Trying to analyze binary file {filepath:?}");
    if !filepath.is_file() {
        return Err(anyhow::anyhow!("invalid file path"));
    }

    // Open target binary, run auto-analysis, and keep results
    let idb = IDB::open_with(filepath, true)?;
    println!("[+] Successfully analyzed binary file");

    // Find bad API functions in target binary
    println!();
    println!("[*] Finding bad API function calls...");
    let found = BadFunctions::find(&idb, &bad);

    // Find bad API function calls in target binary
    for (_, f) in found.high {
        mark_calls(&idb, &f, &Priority::High)?;
    }
    for (_, f) in found.medium {
        mark_calls(&idb, &f, &Priority::Medium)?;
    }
    for (_, f) in found.low {
        mark_calls(&idb, &f, &Priority::Low)?;
    }

    println!();
    println!("[+] Done processing binary file {filepath:?}");
    Ok(())
}

/// Locate all calls to the specified function and mark their locations
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

    // Get first XREF if available, otherwise return early
    let Some(mut current) = idb.first_xref_to(func.start_address(), XRefQuery::ALL) else {
        return Ok(());
    };

    loop {
        // Print address with caller function name if available
        let caller = idb
            .function_at(current.from())
            .map_or("<unknown>".to_string(), |f| f.name().unwrap());
        println!("{:#x} in {}", current.from(), caller);

        // Add or append comment if not already present
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
