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
/// * High: these functions are generally considered insecure
/// * Medium: these functions are interesting and should be checked for insecure use cases
/// * Low: code paths involving these functions should be carefully checked
enum Priority {
    High,
    Medium,
    Low,
}

/// List of names of bad API functions, organized by their associated priority
#[derive(serde::Deserialize)]
struct BadFunctions {
    high: Vec<String>,
    medium: Vec<String>,
    low: Vec<String>,
}

impl BadFunctions {
    /// Get bad API functions from configuration file
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
    /// Initialize the list of bad API functions found in the target binary
    const fn new() -> Self {
        Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
        }
    }

    /// Insert in the list a new bad API function found in the target binary
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

/// Main program logic
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
        println!("{}", f.name().unwrap());
    }
    for (_id, f) in found.medium {
        println!("{}", f.name().unwrap());
    }
    for (_id, f) in found.low {
        println!("{}", f.name().unwrap());
    }

    for (id, f) in idb.functions() {
        //println!("{id} {}", f.name().unwrap());

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

/// Find bad API functions in the target binary
/// TODO: return an option?
/// TODO: should we also check for some tags/function attributes such as external or this is good enough? (KISS)
fn find_bad_functions<'a>(idb: &'a IDB, bad: &'a BadFunctions) -> FoundBadFunctions<'a> {
    let mut found = FoundBadFunctions::new();

    for (id, f) in idb.functions() {
        match match_function(&f, bad) {
            Some(Priority::High) => found.insert(id, f, &Priority::High),
            Some(Priority::Medium) => found.insert(id, f, &Priority::Medium),
            Some(Priority::Low) => found.insert(id, f, &Priority::Low),
            None => (),
        }
    }

    found
}

/// Compare a function with a list of bad API function names
/// TODO: consider using regex instead, check Ghidra plugin and my semgrep rules
fn match_function(func: &Function, bad: &BadFunctions) -> Option<Priority> {
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
fn get_xrefs(idb: &IDB, func: Function) -> anyhow::Result<()> {
    let mut current = idb
        .first_xref_to(func.start_address(), XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no XREFs to function {}", func.name().unwrap()))?;

    loop {
        //println!("{:#x}", current.from());

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

// TODO: future feature: implement basic rules to rule out obvious false positive?! (see VulFi) -> TODO in comments/README

// TODO: generate documentation and check that it makes sense;)

// TODO: add test suite
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
