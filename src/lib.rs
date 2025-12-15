#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::{BTreeMap, HashSet};
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

/// Number of marked call locations
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Priority of bad API functions
/// * High priority - These functions are generally considered insecure
/// * Medium priority - These functions are interesting and should be checked for insecure use cases
/// * Low priority - Code paths involving these functions should be carefully checked
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Priority {
    High,
    Medium,
    Low,
}

/// List of known bad API function names organized by priority
#[derive(serde::Deserialize)]
struct KnownBadFunctions {
    high: HashSet<String>,
    medium: HashSet<String>,
    low: HashSet<String>,
}

impl KnownBadFunctions {
    /// Populate the list of bad API function names from the configuration file
    fn load() -> Result<Self, ConfigError> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/rhabdomancer.toml");

        println!("[*] Using configuration file `{}`", path.display());
        let mut this: Self = Config::builder()
            .add_source(File::from(path))
            .build()?
            .try_deserialize()?;

        // Return the list of normalized configuration entries
        this.normalize_sets();
        Ok(this)
    }

    /// Check if a function is in the list of known bad API function names and return its priority
    fn check_function(&self, func: &Function) -> Option<Priority> {
        let func_name = func.name()?;
        let pattern = Self::normalize_name(&func_name);

        if self.high.contains(pattern) {
            return Some(Priority::High);
        }
        if self.medium.contains(pattern) {
            return Some(Priority::Medium);
        }
        if self.low.contains(pattern) {
            return Some(Priority::Low);
        }

        None
    }

    /// Normalize configuration entries so runtime lookups are trivial and consistent
    fn normalize_sets(&mut self) {
        self.high = self
            .high
            .drain()
            .map(|s| Self::normalize_name(&s).to_owned())
            .collect();

        self.medium = self
            .medium
            .drain()
            .map(|s| Self::normalize_name(&s).to_owned())
            .collect();

        self.low = self
            .low
            .drain()
            .map(|s| Self::normalize_name(&s).to_owned())
            .collect();
    }

    /// Normalize a function name for matching against configuration entries
    fn normalize_name(name: &str) -> &str {
        name.trim_start_matches(['.', '_'])
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
    fn locate_calls(&self, idb: &'a IDB) -> anyhow::Result<()> {
        for f in self.high.values() {
            Self::mark_calls(idb, f, Priority::High)?;
        }
        for f in self.medium.values() {
            Self::mark_calls(idb, f, Priority::Medium)?;
        }
        for f in self.low.values() {
            Self::mark_calls(idb, f, Priority::Low)?;
        }

        Ok(())
    }

    /// Locate calls to the specified function and mark them
    fn mark_calls(idb: &IDB, func: &Function, priority: Priority) -> Result<(), IDAError> {
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
/// Returns a [`BookmarkIndex`] that indicates how many call locations were marked, or a generic
/// error in case something goes wrong.
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
