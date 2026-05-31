#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::{env, mem};

use anyhow::Context as _;
use config::{Config, ConfigError, File};
use idalib::bookmarks::BookmarkIndex;
use idalib::ffi::BADADDR;
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Prefix for bookmarks and comments
pub const PREFIX: &str = "[BAD ";

/// Priority of bad API functions
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum Priority {
    /// High priority - These functions are generally considered insecure
    High = 0,
    /// Medium priority - These functions are interesting and should be checked for insecure use cases
    Medium,
    /// Low priority - Code paths involving these functions should be carefully checked
    Low,
}

impl Priority {
    /// Return the priority code as a byte
    const fn code(self) -> u8 {
        self as u8
    }

    /// Return the tag prefix to use for bookmarks and comments
    fn tag_prefix(self) -> String {
        format!("{PREFIX}{}]", self.code())
    }

    /// Return a description for a bad API function with the specified name
    fn description(self, func_name: &str) -> String {
        format!("{} {}", self.tag_prefix(), func_name)
    }
}

/// Set of known bad API function names organized by priority
#[derive(serde::Deserialize)]
struct KnownBadFunctions {
    /// High-priority known bad functions
    high: HashSet<String>,
    /// Medium-priority known bad functions
    medium: HashSet<String>,
    /// Low-priority known bad functions
    low: HashSet<String>,
}

impl KnownBadFunctions {
    /// Populate the list of bad API function names from the configuration file
    fn load() -> Result<Self, ConfigError> {
        // Use configuration file path specified in the `RHABDOMANCER_CONFIG` environment variable
        // if set, otherwise fall back to the default file location
        let path = env::var_os("RHABDOMANCER_CONFIG").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/rhabdomancer.toml"),
            PathBuf::from,
        );

        println!("[*] Using configuration file `{}`", path.display());
        let mut this = Config::builder()
            .add_source(File::from(path))
            .build()?
            .try_deserialize::<Self>()?;

        // Return the list of normalized configuration entries
        this.normalize_sets();
        Ok(this)
    }

    /// Check if a function is in the list of known bad API function names and return its priority
    fn check_function(&self, func: &Function) -> Option<Priority> {
        let func_name = func.name()?;
        let func_name = normalize_name(&func_name);

        if self.high.contains(func_name) {
            return Some(Priority::High);
        }
        if self.medium.contains(func_name) {
            return Some(Priority::Medium);
        }
        if self.low.contains(func_name) {
            return Some(Priority::Low);
        }

        None
    }

    /// Normalize configuration entries so runtime lookups are trivial and consistent
    fn normalize_sets(&mut self) {
        for set in [&mut self.high, &mut self.medium, &mut self.low] {
            *set = mem::take(set)
                .into_iter()
                .map(|s| normalize_name(&s).to_owned())
                .collect();
        }
    }
}

/// Ordered list of bad API functions found in the target binary organized by
/// priority and number of marked call locations expressed as a [`BookmarkIndex`]
struct BadFunctions<'a> {
    /// High-priority found bad functions
    high: BTreeMap<FunctionId, Function<'a>>,
    /// Medium-priority found bad functions
    medium: BTreeMap<FunctionId, Function<'a>>,
    /// Low-priority found bad functions
    low: BTreeMap<FunctionId, Function<'a>>,
    /// Number of marked call locations
    marked: BookmarkIndex,
}

impl<'a> BadFunctions<'a> {
    /// Find bad API functions in the target binary
    fn find_all(idb: &'a IDB, bad: &KnownBadFunctions) -> Self {
        let mut found = Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
            marked: 0,
        };

        for (id, f) in idb.functions() {
            if let Some(p) = bad.check_function(&f) {
                found.insert_function(id, f, p);
            }
        }

        found
    }

    /// Insert a new bad API function in the list
    fn insert_function(&mut self, id: FunctionId, func: Function<'a>, priority: Priority) {
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
    fn locate_calls(&mut self, idb: &'a IDB) -> anyhow::Result<BookmarkIndex> {
        let mut marked = 0;

        for (priority, functions) in [
            (Priority::High, &self.high),
            (Priority::Medium, &self.medium),
            (Priority::Low, &self.low),
        ] {
            for f in functions.values() {
                Self::mark_calls(idb, f, priority, &mut marked)?;
            }
        }

        self.marked = marked;
        Ok(self.marked)
    }

    /// Locate calls to the specified function and mark them
    fn mark_calls(
        idb: &IDB,
        func: &Function,
        priority: Priority,
        marked: &mut BookmarkIndex,
    ) -> Result<(), IDAError> {
        // Return an error if the function name is empty (shouldn't happen)
        let Some(func_name) = func.name() else {
            return Err(IDAError::ffi_with("empty function name"));
        };

        // Prepare description
        let desc = priority.description(normalize_name(&func_name));

        // Print description
        if is_in_plt(idb, func.start_address()) {
            println!("\n{desc} (thunk)");
        } else {
            println!("\n{desc}");
        }

        // Traverse XREFs and mark call locations
        idb.first_xref_to(func.start_address(), XRefQuery::ALL)
            .map_or(Ok(()), |cur| Self::traverse_xrefs(idb, cur, &desc, marked))
    }

    /// Iteratively traverse XREFs and mark call locations
    ///
    /// An explicit work stack is used instead of recursion so that binaries with very long XREF chains or deep .plt
    /// indirection don't overflow the stack.
    fn traverse_xrefs(
        idb: &IDB,
        first_xref: XRef,
        desc: &str,
        marked: &mut BookmarkIndex,
    ) -> Result<(), IDAError> {
        // Each entry is the head of an XREF chain still to be processed
        let mut stack = vec![first_xref];

        while let Some(xref) = stack.pop() {
            let from = xref.from();
            let is_code = xref.is_code();

            // Queue the next xref in the chain before processing the current one
            if let Some(next) = xref.next_to() {
                stack.push(next);
            }

            if is_in_plt(idb, from) {
                // Handle .plt indirection in ELF binaries by queueing the thunk's own XREF chain for later processing
                let target = idb
                    .function_at(from)
                    .map_or_else(|| BADADDR.into(), |func| func.start_address());
                if let Some(thunk) = idb.first_xref_to(target, XRefQuery::ALL) {
                    stack.push(thunk);
                }
            } else if is_code {
                // Print address with caller function name if available
                let caller = idb.function_at(from).map_or_else(
                    || "[unknown]".into(),
                    |func| func.name().unwrap_or_else(|| "[no name]".into()),
                );
                println!("{from:#X} in {caller}");

                // Add a bookmark if not already present to mark the call location
                if !idb
                    .bookmarks()
                    .get_description(from)
                    .unwrap_or_default()
                    .contains(PREFIX)
                {
                    idb.bookmarks().mark(from, desc)?;
                    *marked += 1;
                }

                // Add a comment if not already present to mark the call location
                if !idb.get_cmt(from).unwrap_or_default().contains(PREFIX) {
                    idb.append_cmt(from, desc)?;
                }
            }
        }

        Ok(())
    }
}

/// Locate calls to potentially insecure API functions in the binary file at `filepath`.
///
/// ## Errors
///
/// Returns a [`BookmarkIndex`] that indicates how many call locations were marked, or an error in
/// case something goes wrong.
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
    println!("[-] Processor: {}", idb.processor().long_name());
    println!("[-] Compiler: {:?}", idb.meta().cc_id());
    println!("[-] File type: {:?}", idb.meta().filetype());
    println!();

    // Locate and mark bad API function calls in the target binary
    println!("[*] Finding bad API function calls...");
    let marked = BadFunctions::find_all(&idb, &known_bad)
        .locate_calls(&idb)
        .context("Failed to find bad API function calls")?;

    println!();
    println!("[+] Marked {marked} new call locations");
    println!("[+] Done processing binary file `{}`", filepath.display());
    Ok(marked)
}

/// Check if an address is in the .plt segment
fn is_in_plt(idb: &IDB, addr: Address) -> bool {
    idb.segment_at(addr)
        .is_some_and(|segm| segm.name().unwrap_or_default().starts_with(".plt"))
}

/// Normalize a function name for matching against configuration entries
fn normalize_name(name: &str) -> &str {
    name.trim_start_matches(['.', '_'])
}
