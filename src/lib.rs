#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context as _;
use config::{Config, ConfigError, File};
use idalib::bookmarks::BookmarkIndex;
use idalib::ffi::BADADDR;
use idalib::func::{Function, FunctionId};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};

/// Prefix for bookmarks and comments.
pub const PREFIX: &str = "[BAD ";

/// Priority of bad API functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum Priority {
    /// High priority - These functions are generally considered insecure.
    High = 0,
    /// Medium priority - These functions are interesting and should be checked for insecure use cases.
    Medium,
    /// Low priority - Code paths involving these functions should be carefully checked.
    Low,
}

impl Priority {
    /// Returns the tag prefix to use for bookmarks and comments.
    ///
    /// The tag text must stay in sync with the `PREFIX` constant and each variant's discriminant.
    const fn tag_prefix(self) -> &'static str {
        match self {
            Self::High => "[BAD 0]",
            Self::Medium => "[BAD 1]",
            Self::Low => "[BAD 2]",
        }
    }

    /// Returns a description for a bad API function with the specified name.
    fn description(self, func_name: &str) -> String {
        format!("{} {}", self.tag_prefix(), func_name)
    }
}

/// Known bad API function names organized by priority, as listed in the configuration file.
#[derive(serde::Deserialize)]
struct KnownBadFunctionsConfig {
    /// High-priority known bad functions.
    high: Vec<String>,
    /// Medium-priority known bad functions.
    medium: Vec<String>,
    /// Low-priority known bad functions.
    low: Vec<String>,
}

/// Known bad API function names, normalized for matching and mapped to their priority.
///
/// Deserialized from a [`KnownBadFunctionsConfig`], which is rejected if any name is empty or is listed under
/// multiple priorities, once normalized.
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
    /// Returns an error message if a name is empty or is listed under multiple priorities, once normalized.
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
    /// Returns [`ConfigError`] if the configuration file can't be read or parsed, or if a name is empty or is listed
    /// under multiple priorities, once normalized.
    fn load() -> Result<Self, ConfigError> {
        // Use configuration file path specified in the `RHABDOMANCER_CONFIG` environment variable
        // if set, otherwise fall back to the default file location.
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

    /// Checks if a function is in the list of known bad API function names and returns its priority.
    fn check_function(&self, func: &Function<'_>) -> Option<Priority> {
        self.priority_of(&func.name()?)
    }

    /// Returns the priority of the known bad API function with the specified name, if any.
    fn priority_of(&self, func_name: &str) -> Option<Priority> {
        self.functions.get(normalize_name(func_name)).copied()
    }
}

/// Ordered list of bad API functions found in the target binary organized by
/// priority and number of marked call locations expressed as a [`BookmarkIndex`].
struct BadFunctions<'a> {
    /// High-priority found bad functions.
    high: BTreeMap<FunctionId, Function<'a>>,
    /// Medium-priority found bad functions.
    medium: BTreeMap<FunctionId, Function<'a>>,
    /// Low-priority found bad functions.
    low: BTreeMap<FunctionId, Function<'a>>,
    /// Number of marked call locations.
    marked: BookmarkIndex,
    /// Address ranges of .plt segments.
    ///
    /// Half-open like IDA's `range_t`, which excludes `end_ea`.
    plt: Vec<Range<Address>>,
}

impl<'a> BadFunctions<'a> {
    /// Finds bad API functions in the target binary.
    fn find_all(idb: &'a IDB, bad: &KnownBadFunctions) -> Self {
        let mut found = Self {
            high: BTreeMap::new(),
            medium: BTreeMap::new(),
            low: BTreeMap::new(),
            marked: 0,
            plt: idb
                .segments()
                .filter(|(_, segm)| segm.name().is_some_and(|name| name.starts_with(".plt")))
                .map(|(_, segm)| segm.start_address()..segm.end_address())
                .collect(),
        };

        for (id, func) in idb.functions() {
            if let Some(pri) = bad.check_function(&func) {
                found.insert_function(id, func, pri);
            }
        }

        found
    }

    /// Inserts a new bad API function in the list.
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

    /// Locates calls to bad API functions and marks them.
    fn locate_calls(&mut self, idb: &'a IDB) -> anyhow::Result<BookmarkIndex> {
        let mut marked = 0;

        for (priority, functions) in [
            (Priority::High, &self.high),
            (Priority::Medium, &self.medium),
            (Priority::Low, &self.low),
        ] {
            for func in functions.values() {
                self.mark_calls(idb, func, priority, &mut marked)?;
            }
        }

        self.marked = marked;
        Ok(self.marked)
    }

    /// Locates calls to the specified function and marks them.
    fn mark_calls(
        &self,
        idb: &IDB,
        func: &Function<'_>,
        priority: Priority,
        marked: &mut BookmarkIndex,
    ) -> Result<(), IDAError> {
        // Return an error if the function name is empty (shouldn't happen).
        let Some(func_name) = func.name() else {
            return Err(IDAError::ffi_with("empty function name"));
        };

        let desc = priority.description(normalize_name(&func_name));
        if self.is_in_plt(func.start_address()) {
            println!("\n{desc} (thunk)");
        } else {
            println!("\n{desc}");
        }

        // Traverse XREFs and mark call locations.
        idb.first_xref_to(func.start_address(), XRefQuery::ALL)
            .map_or(Ok(()), |cur| self.traverse_xrefs(idb, cur, &desc, marked))
    }

    /// Iteratively traverses XREFs and marks call locations.
    ///
    /// An explicit work stack is used instead of recursion so that binaries with very long XREF chains or deep .plt
    /// indirection don't overflow the stack.
    #[expect(clippy::else_if_without_else, reason = "else branch would be empty")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`usize` can hardly overflow here"
    )]
    fn traverse_xrefs(
        &self,
        idb: &IDB,
        first_xref: XRef<'_>,
        desc: &str,
        marked: &mut BookmarkIndex,
    ) -> Result<(), IDAError> {
        // Each entry in the stack is the head of an XREF chain still to be processed.
        let mut stack = vec![first_xref];

        while let Some(xref) = stack.pop() {
            let from = xref.from();
            let is_code = xref.is_code();

            // Queue the next XREF in the chain before processing the current one.
            if let Some(next) = xref.next_to() {
                stack.push(next);
            }

            if self.is_in_plt(from) {
                // Handle .plt indirection in ELF binaries by queueing the thunk's own XREF chain for later processing.
                let target = idb
                    .function_at(from)
                    .map_or_else(|| BADADDR.into(), |func| func.start_address());
                if let Some(thunk) = idb.first_xref_to(target, XRefQuery::ALL) {
                    stack.push(thunk);
                }
            } else if is_code {
                // Print address with caller function name if available.
                let caller = idb.function_at(from).map_or_else(
                    || "[unknown]".into(),
                    |func| func.name().unwrap_or_else(|| "[no name]".into()),
                );
                println!("{from:#X} in {caller}");

                // Add a bookmark if not already present to mark the call location.
                if !idb
                    .bookmarks()
                    .get_description(from)
                    .unwrap_or_default()
                    .contains(PREFIX)
                {
                    idb.bookmarks().mark(from, desc)?;
                    *marked += 1;
                }

                // Add a comment if not already present to mark the call location.
                if !idb.get_cmt(from).unwrap_or_default().contains(PREFIX) {
                    idb.append_cmt(from, desc)?;
                }
            }
        }

        Ok(())
    }

    /// Checks if an address is in a .plt segment.
    ///
    /// Equivalent to IDA's `range_t::contains`, i.e., `start_ea <= addr < end_ea`, without any FFI calls.
    fn is_in_plt(&self, addr: Address) -> bool {
        self.plt.iter().any(|range| range.contains(&addr))
    }
}

/// Locates calls to potentially insecure API functions in the binary file at `filepath`.
///
/// Returns a [`BookmarkIndex`] that indicates how many call locations were marked.
///
/// # Errors
///
/// Returns [`anyhow::Error`] in case something goes wrong with analyzing the binary file or finding bad API calls.
pub fn run(filepath: impl AsRef<Path>) -> anyhow::Result<BookmarkIndex> {
    let start = Instant::now();

    eprintln!("[*] Loading known bad API function names");
    let known_bad =
        KnownBadFunctions::load().context("Failed to load known bad API function names")?;

    // Open the target binary, run auto-analysis, and keep results.
    eprintln!(
        "[*] Analyzing binary file `{}`",
        filepath.as_ref().display()
    );
    let idb = IDB::open_with(&filepath, true, true).with_context(|| {
        format!(
            "Failed to analyze binary file `{}`",
            filepath.as_ref().display()
        )
    })?;
    eprintln!("[+] Successfully analyzed binary file");
    eprintln!();

    eprintln!("[-] Processor: {}", idb.processor().long_name());
    eprintln!("[-] Compiler: {:?}", idb.meta().cc_id());
    eprintln!("[-] File type: {:?}", idb.meta().filetype());
    eprintln!();

    eprintln!("[*] Finding bad API function calls...");
    let marked = BadFunctions::find_all(&idb, &known_bad)
        .locate_calls(&idb)
        .context("Failed to find bad API function calls")?;

    eprintln!();
    eprintln!("[+] Marked {marked} new call locations");
    eprintln!(
        "[+] Done processing binary file `{}` in {:.1} seconds",
        filepath.as_ref().display(),
        start.elapsed().as_secs_f64()
    );
    Ok(marked)
}

/// Normalizes a function name for matching against configuration entries.
fn normalize_name(name: &str) -> &str {
    name.trim_start_matches(['.', '_'])
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
mod tests {
    use config::FileFormat;

    use super::*;

    /// Returns a [`KnownBadFunctionsConfig`] with the specified names for each priority.
    fn config(high: &[&str], medium: &[&str], low: &[&str]) -> KnownBadFunctionsConfig {
        let to_owned = |names: &[&str]| names.iter().copied().map(str::to_owned).collect();
        KnownBadFunctionsConfig {
            high: to_owned(high),
            medium: to_owned(medium),
            low: to_owned(low),
        }
    }

    /// Deserializes [`KnownBadFunctions`] from a TOML string, like [`KnownBadFunctions::load`] does from a file.
    fn deserialize(toml: &str) -> Result<KnownBadFunctions, ConfigError> {
        Config::builder()
            .add_source(File::from_str(toml, FileFormat::Toml))
            .build()?
            .try_deserialize()
    }

    #[test]
    fn try_from_maps_names_to_their_priority() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["memcpy"], &["getenv"]))?;

        assert_eq!(
            known_bad.priority_of("strcpy"),
            Some(Priority::High),
            "wrong priority"
        );
        assert_eq!(
            known_bad.priority_of("memcpy"),
            Some(Priority::Medium),
            "wrong priority"
        );
        assert_eq!(
            known_bad.priority_of("getenv"),
            Some(Priority::Low),
            "wrong priority"
        );
        Ok(())
    }

    #[test]
    fn try_from_normalizes_configuration_names() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&["_strcpy"], &[".memset"], &["__getenv"]))?;

        assert_eq!(
            known_bad.priority_of("strcpy"),
            Some(Priority::High),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.priority_of("memset"),
            Some(Priority::Medium),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.priority_of("getenv"),
            Some(Priority::Low),
            "decorated name should match"
        );
        Ok(())
    }

    #[test]
    fn priority_of_normalizes_function_names() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &[], &[]))?;

        for func_name in ["_strcpy", ".strcpy", "__strcpy", "._strcpy"] {
            assert_eq!(
                known_bad.priority_of(func_name),
                Some(Priority::High),
                "decorated function name `{func_name}` should match"
            );
        }
        Ok(())
    }

    #[test]
    fn priority_of_unknown_name_returns_none() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &[], &[]))?;

        assert_eq!(
            known_bad.priority_of("strncpy"),
            None,
            "unknown name should not match"
        );
        assert_eq!(
            known_bad.priority_of(""),
            None,
            "empty name should not match"
        );
        Ok(())
    }

    #[test]
    fn try_from_accepts_duplicates_within_the_same_priority() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&[], &["fwrite", "_fwrite", "fwrite"], &[]))?;

        assert_eq!(
            known_bad.priority_of("fwrite"),
            Some(Priority::Medium),
            "wrong priority"
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
    fn priority_of_name_that_normalizes_to_empty_returns_none() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["memcpy"], &["getenv"]))?;

        for func_name in ["", "_", ".", "__"] {
            assert_eq!(
                known_bad.priority_of(func_name),
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
            known_bad.priority_of("strcpy"),
            Some(Priority::High),
            "wrong priority"
        );
        assert_eq!(
            known_bad.priority_of("memcpy"),
            Some(Priority::Medium),
            "wrong priority"
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
