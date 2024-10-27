//!
//! rhabdomancer - IDA Pro vulnerability research assistant
//! Copyright (c) 2024 Marco Ivaldi <raptor@0xdeadbeef.info>
//!
//! > "The road to exploitable bugs is paved with unexploitable bugs."
//! >
//! > -- Mark Dowd
//!
//! Rhabdomancer is a simple IDA Pro headless plugin that locates all calls to potentially insecure
//! API functions in a binary file. Auditors can backtrace from these candidate points to find
//! pathways allowing access from untrusted input.
//!
//! TODO description:
// * C/C++ target
// * Tiers of badness
// * Briefly cover pros/cons of candidate point strategy
// * Mention TAOSSA and other strategies
// * Rust, idalib, headless
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

// TODO: remove all unwraps and similar where possible, implement robust error handling
// TODO: test performance with large files, e.g. zysh; optimize data structures to make them more performant/idiomatic if needed
// TODO: test with binaries with more than a function that matches a single bad pattern (e.g., case-insensitive)
// TODO: clippy everything, use cargo udeps and deny

/// Priority of bad API functions
/// * High priority - These functions are generally considered insecure
/// * Medium priority - These functions are interesting and should be checked for insecure use cases
/// * Low priority - Code paths involving these functions should be carefully checked
enum Priority {
    High,
    Medium,
    Low,
}

/// List of known bad API function names, organized by their associated priority
#[derive(serde::Deserialize)]
struct BadFunctions {
    high: Vec<String>,
    medium: Vec<String>,
    low: Vec<String>,
}

impl BadFunctions {
    /// Get known bad API function names from configuration file
    pub fn get() -> Result<Self, ConfigError> {
        let path = env::current_dir().expect("[!] Failed to determine the current directory");
        let conf_dir = path.join("conf");

        Config::builder()
            .add_source(File::from(conf_dir.join("rhabdomancer.toml")))
            .build()?
            .try_deserialize()
    }
}

/// List of bad API functions found in the target binary, organized by their associated priority
struct FoundBadFunctions<'a> {
    high: BTreeMap<FunctionId, Function<'a>>,
    medium: BTreeMap<FunctionId, Function<'a>>,
    low: BTreeMap<FunctionId, Function<'a>>,
}

impl<'a> FoundBadFunctions<'a> {
    /// Initialize the list of bad API functions
    const fn new() -> Self {
        Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
        }
    }

    /// Insert a new bad API function found in the target binary
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
    let bad = BadFunctions::get()?;

    println!("[*] Trying to analyze binary file {}", filepath.display());

    // Check target binary
    // TODO: make sure a user can distinguish between an error (nothing is printed after opening because of non-ergonomic API) and success (messages are printed)
    // TODO: fix this: [*] Trying to analyze binary file /Users/raptor/Downloads/web-console-login [+] % when there's no license available
    if !filepath.is_file() {
        return Err(anyhow::anyhow!(format!("{:?} is not a file", filepath)));

        /*
        Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            "not a file",
        ))); */
    }

    // Open target binary, run auto-analysis, and keep results
    eprint!("[+] ");
    let idb = IDB::open_with(filepath, true)?;

    // Find bad API functions in the target binary
    let found = find_bad_functions(&idb, &bad);

    for (_id, f) in found.high {
        println!("[BAD 0] {}", f.name().unwrap());
        get_xrefs(&idb, f);
    }
    for (_id, f) in found.medium {
        println!("[BAD 1] {}", f.name().unwrap());
        get_xrefs(&idb, f);
    }
    for (_id, f) in found.low {
        println!("[BAD 2] {}", f.name().unwrap());
        get_xrefs(&idb, f);
    }

    Ok(())
}

/// Find bad API functions in the target binary
/// TODO: return an option?
/// TODO: should we also check for some tags/function attributes such as external or this is good enough? (KISS) -- see IDA book from p.478
fn find_bad_functions<'a>(idb: &'a IDB, bad: &'a BadFunctions) -> FoundBadFunctions<'a> {
    let mut found = FoundBadFunctions::new();

    for (id, f) in idb.functions() {
        match check_function(&f, bad) {
            Some(Priority::High) => found.insert(id, f, &Priority::High),
            Some(Priority::Medium) => found.insert(id, f, &Priority::Medium),
            Some(Priority::Low) => found.insert(id, f, &Priority::Low),
            None => (),
        }
    }

    found
}

/// Compare a function with a list of known bad API function names
fn check_function(func: &Function, bad: &BadFunctions) -> Option<Priority> {
    if bad
        .high
        .iter()
        .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
    {
        return Some(Priority::High);
    }

    if bad
        .medium
        .iter()
        .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
    {
        return Some(Priority::Medium);
    }

    if bad
        .low
        .iter()
        .any(|x| x.eq_ignore_ascii_case(&func.name().unwrap()))
    {
        return Some(Priority::Low);
    }

    None
}

/// TODO: this must be refactored
/// TODO: move logic outside and handle errors, maybe use a suitable collection if needed
fn get_xrefs(idb: &IDB, func: Function) -> anyhow::Result<()> {
    let mut current = idb
        .first_xref_to(func.start_address(), XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no XREFs to function {}", func.name().unwrap()))?;

    // TODO: refactor loop into a while let
    // TODO: calculate addresses before and do error handling
    loop {
        println!(
            "{:#x} in {}",
            current.from(),
            idb.function_at(current.from()).unwrap().name().unwrap()
        );

        match current.next_to() {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(())
}

// TODO: see my interesting function list, semgrep, https://github.com/Accenture/VulFi

// TODO: collect/print the calling function's name and location -- see also ghidra version
// TODO: add comment, to be used with Text search (Find all occurrences) - see also ghidra version; specify this in the comments/README and explain why bookmarks weren't used instead
// TODO: add bookmark (with a folder for each tier!); see idasdk90/include/moves.hpp | class bookmarks_t: mark(ea, index, title=0, desc, ud=0?); get() to check for duplicates?, get_desc()? others...? 1024 max bookmark limit?!
// TODO: see also https://gist.github.com/idiom/74114d745d6c427333ac237f91eee414

// TODO: running a new scan should not overwrite previous bookmarks/comments, also handle previous hand-made bookmarks/comments

// TODO: generate documentation and check that it makes sense;)

// TODO: add test suite
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
