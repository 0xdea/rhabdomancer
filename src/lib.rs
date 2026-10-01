#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, iter};

use anyhow::Context as _;
use config::{Config, ConfigError, File};
use idalib::bookmarks::BookmarkIndex;
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Prefix of the tags in the bookmarks and comments added by rhabdomancer,
/// e.g., `[BAD 0]`.
///
/// This is part of the public API: search for it to find rhabdomancer's
/// annotations in an IDB. Changing it breaks compatibility with IDBs annotated
/// by previous versions.
pub const PREFIX: &str = "[BAD ";

/// Priority of bad API functions.
///
/// Variants are declared from highest to lowest priority: the derived [`Ord`]
/// follows this order, which determines the order in which found bad functions
/// are processed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Priority {
    /// High priority - These functions are generally considered insecure.
    High,
    /// Medium priority - These functions are interesting and should be checked for
    /// insecure use cases.
    Medium,
    /// Low priority - Code paths involving these functions should be carefully
    /// checked.
    Low,
}

impl Priority {
    /// Returns the numeric level shown in bookmark and comment tags (`[BAD 0]` for
    /// high priority, and so on).
    #[must_use]
    const fn level(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
        }
    }

    /// Returns a description for a bad API function with the specified name, e.g.,
    /// `[BAD 0] strcpy`.
    ///
    /// The tag is built from [`PREFIX`], so that it always stays in sync with it.
    #[must_use]
    fn description(self, func_name: &str) -> String {
        format!("{PREFIX}{}] {func_name}", self.level())
    }
}

/// Known bad API function names organized by priority, as listed in the
/// configuration file.
#[derive(serde::Deserialize)]
struct KnownBadFunctionsConfig {
    /// High-priority known bad functions.
    high: Vec<String>,
    /// Medium-priority known bad functions.
    medium: Vec<String>,
    /// Low-priority known bad functions.
    low: Vec<String>,
}

/// Known bad API function names, normalized for matching and mapped to their
/// priority.
///
/// Deserialized from a [`KnownBadFunctionsConfig`], which is rejected if any
/// name is empty or is listed under multiple priorities, once normalized.
#[derive(serde::Deserialize)]
#[serde(try_from = "KnownBadFunctionsConfig")]
struct KnownBadFunctions {
    /// Priority of each known bad function, keyed by normalized name.
    functions: HashMap<String, Priority>,
}

impl TryFrom<KnownBadFunctionsConfig> for KnownBadFunctions {
    type Error = String;

    /// Normalizes the names in `config` and maps each of them to its priority.
    ///
    /// # Errors
    ///
    /// Returns an error message if a name is empty or is listed under multiple
    /// priorities, once normalized.
    fn try_from(config: KnownBadFunctionsConfig) -> Result<Self, Self::Error> {
        let mut functions = HashMap::new();

        for (priority, names) in [
            (Priority::High, config.high),
            (Priority::Medium, config.medium),
            (Priority::Low, config.low),
        ] {
            for name in names {
                let normalized = normalize_name(&name);

                if normalized.is_empty() {
                    return Err(format!("`{name}` is not a valid function name"));
                }

                if *functions.entry(normalized.to_owned()).or_insert(priority) != priority {
                    return Err(format!(
                        "`{normalized}` is listed under multiple priorities"
                    ));
                }
            }
        }

        Ok(Self { functions })
    }
}

impl KnownBadFunctions {
    /// Populates the list of bad API function names from the configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the configuration file can't be read or parsed,
    /// or if a name is empty or is listed under multiple priorities, once
    /// normalized.
    fn load() -> Result<Self, ConfigError> {
        // Use configuration file path specified in the `RHABDOMANCER_CONFIG`
        // environment variable if set, otherwise fall back to the default file
        // location.
        let path = env::var_os("RHABDOMANCER_CONFIG").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/rhabdomancer.toml"),
            PathBuf::from,
        );

        eprintln!("[*] Using configuration file `{}`", path.display());
        Config::builder()
            .add_source(File::from(path))
            .build()?
            .try_deserialize()
    }

    /// Returns the normalized name and priority of the known bad API function with
    /// the specified name, if any.
    #[must_use]
    fn lookup(&self, func_name: &str) -> Option<(&str, Priority)> {
        self.functions
            .get_key_value(normalize_name(func_name))
            .map(|(name, &priority)| (name.as_str(), priority))
    }
}

/// Bad API functions found in the target binary with their normalized names,
/// ordered by priority and then by function ID.
struct BadFunctions<'a> {
    /// Found bad functions with their normalized names, keyed by priority and
    /// function ID.
    functions: BTreeMap<(Priority, FunctionId), (Function<'a>, &'a str)>,
}

impl<'a> BadFunctions<'a> {
    /// Finds bad API functions in the target binary.
    fn find_all(idb: &'a IDB, bad: &'a KnownBadFunctions) -> Self {
        Self {
            functions: idb
                .functions()
                .filter_map(|(id, func)| {
                    let (name, priority) = bad.lookup(&func.name()?)?;
                    Some(((priority, id), (func, name)))
                })
                .collect(),
        }
    }

    /// Returns an iterator over the found bad functions as
    /// `(priority, id, func, name)` tuples, ordered by priority and then by
    /// function ID.
    fn iter(&self) -> impl Iterator<Item = (Priority, FunctionId, &Function<'a>, &'a str)> {
        self.functions
            .iter()
            .map(|(&(priority, id), (func, name))| (priority, id, func, *name))
    }
}

/// Address ranges of the .plt segments of a binary.
struct PltSegments {
    /// Address ranges of the .plt segments.
    ///
    /// Half-open like IDA's `range_t`, which excludes `end_ea`.
    ranges: Vec<Range<Address>>,
}

impl PltSegments {
    /// Collects the address ranges of all .plt segments in `idb`.
    fn new(idb: &IDB) -> Self {
        Self {
            ranges: idb
                .segments()
                .filter(|(_, segm)| segm.name().is_some_and(|name| name.starts_with(".plt")))
                .map(|(_, segm)| segm.start_address()..segm.end_address())
                .collect(),
        }
    }

    /// Checks if an address is in a .plt segment.
    ///
    /// Equivalent to IDA's `range_t::contains`, i.e., `start_ea <= addr < end_ea`,
    /// without any FFI calls.
    #[must_use]
    fn contains(&self, addr: Address) -> bool {
        self.ranges.iter().any(|range| range.contains(&addr))
    }
}

/// Marks the call locations of bad API functions in an IDB with bookmarks and
/// comments.
struct CallMarker<'a> {
    /// IDB to annotate.
    idb: &'a IDB,
    /// Address ranges of the IDB's .plt segments, used to follow thunk indirection
    /// in ELF binaries.
    plt: PltSegments,
}

impl<'a> CallMarker<'a> {
    /// Creates a marker for `idb`, collecting the address ranges of its .plt
    /// segments.
    fn new(idb: &'a IDB) -> Self {
        Self {
            idb,
            plt: PltSegments::new(idb),
        }
    }

    /// Locates calls to the bad API functions in `found` and marks them.
    ///
    /// Returns the total number of newly marked call locations, stopping at the
    /// first error.
    fn mark_all(&self, found: &BadFunctions<'_>) -> Result<BookmarkIndex, IDAError> {
        found
            .iter()
            .map(|(priority, _, func, name)| self.mark_calls(func, priority, name))
            .sum()
    }

    /// Locates calls to the specified function and marks them with its priority and
    /// normalized name.
    ///
    /// Returns the number of newly marked call locations.
    fn mark_calls(
        &self,
        func: &Function<'_>,
        priority: Priority,
        name: &str,
    ) -> Result<BookmarkIndex, IDAError> {
        let desc = priority.description(name);
        if self.plt.contains(func.start_address()) {
            println!("\n{desc} (thunk)");
        } else {
            println!("\n{desc}");
        }

        // Traverse XREFs and mark call locations.
        self.traverse_xrefs(func.start_address(), &desc)
    }

    /// Iteratively traverses the XREFs to `target` and marks call locations.
    ///
    /// Each XREF chain is walked with [`iter::successors`]. The .plt thunks found
    /// along the way are queued on an explicit worklist and their chains walked
    /// afterwards, so that deep .plt indirection can't overflow the call stack.
    /// Each address is walked at most once, so that cyclic .plt references (in
    /// crafted or unusual binaries) can't make the traversal loop forever.
    ///
    /// Returns the number of newly marked call locations.
    fn traverse_xrefs(&self, target: Address, desc: &str) -> Result<BookmarkIndex, IDAError> {
        let bookmarks = self.idb.bookmarks();
        let mut marked = BookmarkIndex::default();

        // Addresses whose XREF chains are still to be walked: `target`, plus each .plt
        // thunk found, each queued only once.
        let mut visited = HashSet::from([target]);
        let mut targets = vec![target];

        while let Some(addr) = targets.pop() {
            let first_xref = self.idb.first_xref_to(addr, XRefQuery::ALL);
            for xref in iter::successors(first_xref, XRef::next_to) {
                let from = xref.from();

                if self.plt.contains(from) {
                    // Handle .plt indirection in ELF binaries by also walking the XREFs to the
                    // thunk, unless it was already queued.
                    if let Some(thunk) = self.idb.function_at(from).map(|func| func.start_address())
                        && visited.insert(thunk)
                    {
                        targets.push(thunk);
                    }
                    continue;
                }
                if !xref.is_code() {
                    continue;
                }

                // Print address with caller function name if available.
                let caller = self.idb.function_at(from).map_or_else(
                    || "[unknown]".into(),
                    |func| func.name().unwrap_or_else(|| "[no name]".into()),
                );
                println!("{from:#X} in {caller}");

                // Add a bookmark if not already present to mark the call location.
                if !bookmarks
                    .get_description(from)
                    .unwrap_or_default()
                    .contains(PREFIX)
                {
                    bookmarks.mark(from, desc)?;
                    marked = marked.saturating_add(1);
                }

                // Add a comment if not already present to mark the call location.
                if !self.idb.get_cmt(from).unwrap_or_default().contains(PREFIX) {
                    self.idb.append_cmt(from, desc)?;
                }
            }
        }

        Ok(marked)
    }
}

/// Locates calls to potentially insecure API functions in the binary file at
/// `filepath`.
///
/// Returns a [`BookmarkIndex`] that indicates how many call locations were
/// marked.
///
/// # Errors
///
/// Returns [`anyhow::Error`] in case something goes wrong with analyzing the
/// binary file or finding bad API calls.
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<BookmarkIndex> {
    let start = Instant::now();
    let filepath = filepath.as_ref();

    eprintln!("[*] Loading known bad API function names");
    let known_bad =
        KnownBadFunctions::load().context("failed to load known bad API function names")?;

    // Open the target binary, run auto-analysis, and keep results.
    eprintln!("[*] Analyzing binary file `{}`", filepath.display());
    let idb = IDB::open_with(filepath, true, true)
        .with_context(|| format!("failed to analyze binary file `{}`", filepath.display()))?;
    eprintln!("[+] Successfully analyzed binary file");
    eprintln!();

    eprintln!("[-] Processor: {}", idb.processor().long_name());
    eprintln!("[-] Compiler: {:?}", idb.meta().cc_id());
    eprintln!("[-] File type: {:?}", idb.meta().filetype());
    eprintln!();

    eprintln!("[*] Finding bad API function calls...");
    let found = BadFunctions::find_all(&idb, &known_bad);
    let marked = CallMarker::new(&idb)
        .mark_all(&found)
        .context("failed to find bad API function calls")?;

    eprintln!();
    eprintln!("[+] Marked {marked} new call locations");
    eprintln!(
        "[+] Done processing binary file `{}` in {:.1} seconds",
        filepath.display(),
        start.elapsed().as_secs_f64()
    );
    Ok(marked)
}

/// Normalizes a function name for matching against configuration entries.
#[must_use]
fn normalize_name(name: &str) -> &str {
    name.trim_start_matches(['.', '_'])
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
mod tests {
    use config::FileFormat;

    use super::*;

    /// Returns a [`KnownBadFunctionsConfig`] with the specified names for each
    /// priority.
    fn config(high: &[&str], medium: &[&str], low: &[&str]) -> KnownBadFunctionsConfig {
        let to_owned = |names: &[&str]| names.iter().copied().map(str::to_owned).collect();
        KnownBadFunctionsConfig {
            high: to_owned(high),
            medium: to_owned(medium),
            low: to_owned(low),
        }
    }

    /// Deserializes [`KnownBadFunctions`] from a TOML string, like
    /// [`KnownBadFunctions::load`] does from a file.
    fn deserialize(toml: &str) -> Result<KnownBadFunctions, ConfigError> {
        Config::builder()
            .add_source(File::from_str(toml, FileFormat::Toml))
            .build()?
            .try_deserialize()
    }

    /// Returns [`PltSegments`] with the specified `(start, end)` address ranges.
    fn plt(ranges: &[(Address, Address)]) -> PltSegments {
        PltSegments {
            ranges: ranges.iter().map(|&(start, end)| start..end).collect(),
        }
    }

    #[test]
    fn description_formats_tag_and_name() {
        assert_eq!(
            Priority::High.description("strcpy"),
            "[BAD 0] strcpy",
            "wrong high-priority description"
        );
        assert_eq!(
            Priority::Medium.description("memcpy"),
            "[BAD 1] memcpy",
            "wrong medium-priority description"
        );
        assert_eq!(
            Priority::Low.description("getenv"),
            "[BAD 2] getenv",
            "wrong low-priority description"
        );
    }

    #[test]
    fn plt_segments_contain_start_but_not_end() {
        let segments = plt(&[(0x1000, 0x1010)]);

        assert!(
            !segments.contains(0x0FFF),
            "address before the start should not match"
        );
        assert!(segments.contains(0x1000), "start address should match");
        assert!(segments.contains(0x100F), "last address should match");
        assert!(!segments.contains(0x1010), "end address should not match");
    }

    #[test]
    fn plt_segments_check_every_range() {
        let segments = plt(&[(0x1000, 0x1010), (0x2000, 0x2010)]);

        assert!(
            segments.contains(0x1008),
            "address in the first range should match"
        );
        assert!(
            segments.contains(0x2008),
            "address in the second range should match"
        );
        assert!(
            !segments.contains(0x1800),
            "address between ranges should not match"
        );
    }

    #[test]
    fn plt_segments_without_ranges_or_with_empty_ranges_contain_nothing() {
        let no_ranges = plt(&[]);
        let empty_range = plt(&[(0x1000, 0x1000)]);

        assert!(
            !no_ranges.contains(0x1000),
            "no ranges should match nothing"
        );
        assert!(
            !empty_range.contains(0x1000),
            "an empty range should match nothing"
        );
    }

    #[test]
    fn priority_order_is_high_medium_low() {
        assert!(
            Priority::High < Priority::Medium && Priority::Medium < Priority::Low,
            "priorities should be ordered from highest to lowest, which sets the processing order"
        );
    }

    #[test]
    fn try_from_maps_names_to_their_priority() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["memcpy"], &["getenv"]))?;

        assert_eq!(
            known_bad.lookup("strcpy"),
            Some(("strcpy", Priority::High)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("memcpy"),
            Some(("memcpy", Priority::Medium)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("getenv"),
            Some(("getenv", Priority::Low)),
            "wrong normalized name or priority"
        );
        Ok(())
    }

    #[test]
    fn try_from_normalizes_configuration_names() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&["_strcpy"], &[".memset"], &["__getenv"]))?;

        assert_eq!(
            known_bad.lookup("strcpy"),
            Some(("strcpy", Priority::High)),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.lookup("memset"),
            Some(("memset", Priority::Medium)),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.lookup("getenv"),
            Some(("getenv", Priority::Low)),
            "decorated name should match"
        );
        Ok(())
    }

    #[test]
    fn lookup_normalizes_function_names() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &[], &[]))?;

        for func_name in ["_strcpy", ".strcpy", "__strcpy", "._strcpy"] {
            assert_eq!(
                known_bad.lookup(func_name),
                Some(("strcpy", Priority::High)),
                "decorated function name `{func_name}` should match"
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_unknown_name_returns_none() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &[], &[]))?;

        assert_eq!(
            known_bad.lookup("strncpy"),
            None,
            "unknown name should not match"
        );
        assert_eq!(known_bad.lookup(""), None, "empty name should not match");
        Ok(())
    }

    #[test]
    fn try_from_accepts_duplicates_within_the_same_priority() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&[], &["fwrite", "_fwrite", "fwrite"], &[]))?;

        assert_eq!(
            known_bad.lookup("fwrite"),
            Some(("fwrite", Priority::Medium)),
            "wrong normalized name or priority"
        );
        assert_eq!(known_bad.functions.len(), 1, "duplicates should be merged");
        Ok(())
    }

    #[test]
    fn try_from_rejects_names_listed_under_multiple_priorities() {
        for (high, medium, low) in [
            (&["strtrns"][..], &["strtrns"][..], &[][..]),
            (&[], &["_memcpy"], &[".memcpy"]),
            (&["getenv"], &[], &["__getenv"]),
        ] {
            let result = KnownBadFunctions::try_from(config(high, medium, low));
            assert!(
                result.is_err_and(|err| err.contains("is listed under multiple priorities")),
                "names listed under multiple priorities should be rejected"
            );
        }
    }

    #[test]
    fn try_from_error_names_the_normalized_duplicate() {
        let result = KnownBadFunctions::try_from(config(&[], &["_memcpy"], &[".memcpy"]));
        assert!(
            result.is_err_and(|err| err == "`memcpy` is listed under multiple priorities"),
            "error should name the normalized duplicate"
        );
    }

    #[test]
    fn try_from_rejects_names_that_normalize_to_empty() {
        for name in ["", "_", ".", "._", "__"] {
            for (high, medium, low) in [
                (&[name][..], &[][..], &[][..]),
                (&[], &[name], &[]),
                (&[], &[], &[name]),
            ] {
                let result = KnownBadFunctions::try_from(config(high, medium, low));
                assert!(
                    result
                        .is_err_and(|err| err == format!("`{name}` is not a valid function name")),
                    "name `{name}` that normalizes to empty should be rejected"
                );
            }
        }
    }

    #[test]
    fn lookup_name_that_normalizes_to_empty_returns_none() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["memcpy"], &["getenv"]))?;

        for func_name in ["", "_", ".", "__"] {
            assert_eq!(
                known_bad.lookup(func_name),
                None,
                "function name `{func_name}` that normalizes to empty should not match"
            );
        }
        Ok(())
    }

    #[test]
    fn deserialize_uses_try_from() -> Result<(), ConfigError> {
        let known_bad = deserialize("high = [\"_strcpy\"]\nmedium = [\"memcpy\"]\nlow = []\n")?;

        assert_eq!(
            known_bad.lookup("strcpy"),
            Some(("strcpy", Priority::High)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("memcpy"),
            Some(("memcpy", Priority::Medium)),
            "wrong normalized name or priority"
        );
        Ok(())
    }

    #[test]
    fn deserialize_rejects_names_listed_under_multiple_priorities() {
        let result = deserialize("high = [\"strtrns\"]\nmedium = [\"strtrns\"]\nlow = []\n");
        assert!(
            result.is_err_and(|err| err
                .to_string()
                .contains("`strtrns` is listed under multiple priorities")),
            "configuration with names listed under multiple priorities should be rejected"
        );
    }

    #[test]
    fn default_configuration_is_valid() -> Result<(), ConfigError> {
        let toml = include_str!("../conf/rhabdomancer.toml");
        let known_bad = deserialize(toml)?;

        assert!(
            !known_bad.functions.is_empty(),
            "default configuration should not be empty"
        );
        Ok(())
    }
}
