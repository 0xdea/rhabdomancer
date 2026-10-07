#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/logo.png")]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs, iter};

use anyhow::Context as _;
use idalib::bookmarks::BookmarkIndex;
use idalib::func::{Function, FunctionFlags, FunctionId};
use idalib::idb::IDB;
use idalib::xref::{XRef, XRefQuery};
use idalib::{Address, IDAError};
use toml::de::Error as TomlError;

/// Prefix of the tags in the bookmarks and comments added by rhabdomancer,
/// e.g., `[BAD 0]`.
///
/// Users and scripts search IDBs for these tags (the annotation format is
/// documented in the README), and IDBs annotated by previous versions carry
/// the same prefix, so it must never change.
const PREFIX: &str = "[BAD ";

/// Default configuration, embedded from `conf/rhabdomancer.toml` at build time
/// so that the binary doesn't depend on the source tree.
const DEFAULT_CONFIG: &str = include_str!("../conf/rhabdomancer.toml");

/// Prefixes of the names of library aliases of functions: the Universal CRT's
/// wrappers (e.g., `__o_malloc`) and glibc's aliases (e.g., `__libc_system`,
/// `__GI___snprintf`), which IDA may pick over the plain name.
///
/// Matched on the raw name: the leading underscores tell an alias apart from a
/// function such as `o_write` or `libc_system`.
const ALIAS_PREFIXES: [&str; 4] = ["__o_", "_o_", "__libc_", "__GI_"];

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

    /// Returns a description for a bad API function named `func_name`, e.g.,
    /// `[BAD 0] strcpy`.
    ///
    /// The tag is built from [`PREFIX`], so that it always stays in sync with it.
    #[must_use]
    fn description(self, func_name: &str) -> String {
        format!("{PREFIX}{}] {func_name}", self.level())
    }
}

/// Kind of a function, which affects how it's matched and listed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionKind {
    /// An ordinary function.
    Plain,
    /// A stub that only forwards to another function (see [`is_stub`]).
    Stub,
}

/// Known bad API function names organized by priority, as listed in the
/// configuration file.
///
/// Unknown keys are rejected, so that a misspelled priority (e.g., `meduim`)
/// fails loudly instead of being silently ignored.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(try_from = "KnownBadFunctionsConfig")]
struct KnownBadFunctions {
    /// Priority of each known bad function, keyed by normalized name.
    functions: HashMap<String, Priority>,
}

impl KnownBadFunctions {
    /// Populates the list of bad API function names from the configuration file
    /// at the path in the `RHABDOMANCER_CONFIG` environment variable if set, or
    /// from the built-in [`DEFAULT_CONFIG`] otherwise. An empty value counts as
    /// unset, so that clearing the variable restores the built-in configuration.
    ///
    /// # Errors
    ///
    /// Returns [`anyhow::Error`] if the configuration file can't be read, or if
    /// the configuration can't be parsed (see [`KnownBadFunctions::parse`]).
    fn load() -> anyhow::Result<Self> {
        let Some(path) = env::var_os("RHABDOMANCER_CONFIG")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
        else {
            eprintln!(
                "[*] Using built-in configuration (set RHABDOMANCER_CONFIG to use a custom one)"
            );
            return Self::parse(DEFAULT_CONFIG).context("failed to parse built-in configuration");
        };

        eprintln!("[*] Using configuration file `{}`", path.display());
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read configuration file `{}`", path.display()))?;
        Self::parse(&text)
            .with_context(|| format!("failed to parse configuration file `{}`", path.display()))
    }

    /// Parses known bad API function names from `text`, a configuration in TOML
    /// format.
    ///
    /// # Errors
    ///
    /// Returns [`TomlError`] if `text` isn't a valid configuration, or if a
    /// name is empty or is listed under multiple priorities, once normalized.
    fn parse(text: &str) -> Result<Self, TomlError> {
        toml::from_str(text)
    }

    /// Returns the normalized name and priority of the known bad API function
    /// named `func_name`, if any, given the function's `kind`.
    ///
    /// Tries, in order, the normalized name, the name without the prefix of
    /// library aliases (see [`strip_alias_prefix`]), and then that name without
    /// the numeric suffix that IDA appends to names already in use (see
    /// [`strip_ida_suffix`]), so that, e.g., `__libc_system` and `memset_0`
    /// match `system` and `memset`. The suffix is only stripped from stubs and
    /// library aliases, so that an unrelated function such as `read_16` doesn't
    /// match `read`.
    #[must_use]
    fn lookup(&self, func_name: &str, kind: FunctionKind) -> Option<(&str, Priority)> {
        let normalized = normalize_name(func_name);
        let unprefixed = strip_alias_prefix(func_name);
        let may_have_suffix = kind == FunctionKind::Stub || unprefixed.is_some();
        let unsuffixed = may_have_suffix
            .then(|| strip_ida_suffix(unprefixed.unwrap_or(normalized)))
            .flatten();

        // Try the normalized name, then the name without the prefix of library
        // aliases, and finally that name without the numeric suffix that IDA
        // appends to names already in use.
        [Some(normalized), unprefixed, unsuffixed]
            .into_iter()
            .flatten()
            .find_map(|name| self.functions.get_key_value(name))
            .map(|(name, &priority)| (name.as_str(), priority))
    }
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

/// A bad API function found in the target binary.
struct FoundFunction<'a> {
    /// The function.
    func: Function<'a>,
    /// Its normalized name, as listed in the configuration.
    name: &'a str,
    /// Its kind.
    kind: FunctionKind,
}

/// Bad API functions found in the target binary, ordered by priority and then
/// by function ID.
struct BadFunctions<'a> {
    /// Found bad functions, keyed by priority and function ID.
    functions: BTreeMap<(Priority, FunctionId), FoundFunction<'a>>,
}

impl<'a> BadFunctions<'a> {
    /// Finds the functions in `idb` that are listed in `bad`.
    ///
    /// In ELF binaries, a bad API function usually matches twice: as its .plt
    /// stub (listed as a thunk) and as its import, whose traversal reaches the
    /// same callers through the stub, so their call sites are listed twice. This
    /// is deliberate: dropping the stub when its name matches the import's could
    /// lose marks whenever the import's traversal doesn't actually reach the
    /// stub's callers (e.g., an unrelated function that normalizes to the same
    /// name, or a stub that IDA doesn't link to the import). Marks aren't
    /// affected by the repetition, since each call site is bookmarked only once.
    ///
    /// `plt` holds the address ranges of the .plt segments of `idb`, used to
    /// tell stubs apart (see [`is_stub`]).
    #[must_use]
    fn find_all(idb: &'a IDB, bad: &'a KnownBadFunctions, plt: &PltSegments) -> Self {
        Self {
            functions: idb
                .functions()
                .filter_map(|(id, func)| {
                    let kind = if is_stub(&func, plt) {
                        FunctionKind::Stub
                    } else {
                        FunctionKind::Plain
                    };
                    let (name, priority) = bad.lookup(&func.name()?, kind)?;
                    Some(((priority, id), FoundFunction { func, name, kind }))
                })
                .collect(),
        }
    }

    /// Returns an iterator over the found bad functions as
    /// `(priority, id, func, name, kind)` tuples, ordered by priority and then
    /// by function ID.
    fn iter(
        &self,
    ) -> impl Iterator<Item = (Priority, FunctionId, &Function<'a>, &'a str, FunctionKind)> {
        self.functions
            .iter()
            .map(|(&(priority, id), found)| (priority, id, &found.func, found.name, found.kind))
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
    #[must_use]
    fn new(idb: &IDB) -> Self {
        Self {
            ranges: idb
                .segments()
                .filter(|(_, segm)| segm.name().is_some_and(|name| name.starts_with(".plt")))
                .map(|(_, segm)| segm.start_address()..segm.end_address())
                .collect(),
        }
    }

    /// Checks if `addr` is in a .plt segment.
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
    /// Addresses that already carry one of rhabdomancer's bookmarks, including
    /// the ones added during this run.
    bookmarked: HashSet<Address>,
}

impl<'a> CallMarker<'a> {
    /// Creates a marker for `idb`, whose .plt segments are in `plt`, collecting
    /// the addresses that already carry one of rhabdomancer's bookmarks.
    ///
    /// Every bookmark is checked, rather than looking one up by address: IDA
    /// overlays bookmarks added at an already bookmarked address, and a lookup by
    /// address returns only one of them, which may be a user's own.
    ///
    /// A bookmark is ours if its description contains [`PREFIX`] anywhere, not
    /// only at the start, so that one of our bookmarks that a user has edited by
    /// prepending text is still recognized and not marked again. The trade-off
    /// is that a user's own bookmark merely mentioning the prefix counts as ours.
    #[must_use]
    fn new(idb: &'a IDB, plt: PltSegments) -> Self {
        let bookmarks = idb.bookmarks();

        Self {
            idb,
            plt,
            bookmarked: (0..bookmarks.len())
                // Is it ours?
                .filter(|&idx| {
                    bookmarks
                        .get_description_by_index(idx)
                        .is_some_and(|desc| desc.contains(PREFIX))
                })
                // Where is it?
                .filter_map(|idx| bookmarks.get_address(idx))
                .collect(),
        }
    }

    /// Locates calls to the bad API functions in `found` and marks them.
    ///
    /// Returns the total number of newly marked call locations. The total can't
    /// overflow: each location counted is a new bookmark at a distinct address,
    /// and IDA indexes bookmarks with [`BookmarkIndex`] values, so their number
    /// always fits in one.
    ///
    /// # Errors
    ///
    /// Returns [`IDAError`] if a bookmark or comment can't be added, stopping at
    /// the first error.
    fn mark_all(&mut self, found: &BadFunctions<'_>) -> Result<BookmarkIndex, IDAError> {
        found
            .iter()
            .map(|(priority, _, func, name, kind)| self.mark_calls(func, priority, name, kind))
            .sum()
    }

    /// Locates calls to `func` and marks them with `priority` and `name`,
    /// listing `func` as a thunk if it's a stub, according to `kind`.
    ///
    /// Returns the number of newly marked call locations.
    ///
    /// # Errors
    ///
    /// Returns [`IDAError`] if a bookmark or comment can't be added.
    fn mark_calls(
        &mut self,
        func: &Function<'_>,
        priority: Priority,
        name: &str,
        kind: FunctionKind,
    ) -> Result<BookmarkIndex, IDAError> {
        let desc = priority.description(name);
        let label = match kind {
            FunctionKind::Stub => " (thunk)",
            FunctionKind::Plain => "",
        };
        println!("\n{desc}{label}");

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
    /// Ordinary-flow XREFs (fall-throughs) aren't call locations, so they are
    /// skipped. Call locations in functions that IDA recognizes as library code
    /// are listed with a `(lib)` label.
    ///
    /// Returns the number of newly marked call locations.
    ///
    /// # Errors
    ///
    /// Returns [`IDAError`] if a bookmark or comment can't be added.
    fn traverse_xrefs(&mut self, target: Address, desc: &str) -> Result<BookmarkIndex, IDAError> {
        let bookmarks = self.idb.bookmarks();
        let mut marked = BookmarkIndex::default();

        // Addresses whose XREF chains are still to be walked: `target`, plus each .plt
        // thunk found, each queued only once.
        let mut visited = HashSet::from([target]);
        let mut targets = vec![target];

        while let Some(addr) = targets.pop() {
            // Skip ordinary-flow XREFs, i.e., the previous instruction falling
            // through into `addr`: compilers reach another function with calls or
            // jumps (including tail calls), which are kept, while fall-throughs
            // into a function's start are padding or follow calls that never
            // return.
            let first_xref = self.idb.first_xref_to(addr, XRefQuery::FAR);
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

                // Print address with caller function name if available, labeled if
                // IDA recognizes the caller as library code. The name comes from the
                // analyzed binary, so escape it to keep terminal escape sequences and
                // other non-printable chars (e.g., bidi overrides) out of the output,
                // and print the label before it, so that no name can fake it.
                match self.idb.function_at(from) {
                    Some(func) => {
                        let label = if func.flags().contains(FunctionFlags::LIB) {
                            " (lib)"
                        } else {
                            ""
                        };
                        println!(
                            "{from:#X}{label} in {}",
                            function_name(&func).escape_debug()
                        );
                    }
                    None => println!("{from:#X} in [unknown]"),
                }

                // Add a bookmark if not already present to mark the call location.
                if self.bookmarked.insert(from) {
                    bookmarks.mark(from, desc)?;
                    marked = marked.saturating_add(1);
                }

                // Add a comment if not already present to mark the call location. The
                // check uses `contains` because `append_cmt` adds our tag after any
                // existing comment, so it isn't necessarily at the start.
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
/// Returns [`anyhow::Error`] if the configuration can't be loaded, the binary
/// file can't be analyzed, or a call location can't be marked.
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
    let plt = PltSegments::new(&idb);
    let found = BadFunctions::find_all(&idb, &known_bad, &plt);
    let marked = CallMarker::new(&idb, plt)
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

/// Returns the name of [`Function`] `func`, or `[no name]` if it has none.
///
/// The name comes from the analyzed binary, so it's untrusted: escape it with
/// [`str::escape_debug`] before printing it.
#[must_use]
fn function_name(func: &Function<'_>) -> String {
    func.name().unwrap_or_else(|| "[no name]".to_owned())
}

/// Checks if `func` is a stub, i.e., a function that only forwards to another
/// one: a thunk according to IDA, or a function in one of the .plt segments in
/// `plt` (which include ELF's lazy-binding stubs, which IDA doesn't flag as
/// thunks).
#[must_use]
fn is_stub(func: &Function<'_>, plt: &PltSegments) -> bool {
    func.flags().contains(FunctionFlags::THUNK) || plt.contains(func.start_address())
}

/// Normalizes a function name for matching against configuration entries.
#[must_use]
fn normalize_name(name: &str) -> &str {
    name.trim_start_matches(['.', '_'])
}

/// Returns the normalized name of the function aliased by the library alias
/// named `func_name` (e.g., `malloc` for `__o_malloc`, `system` for
/// `__libc_system`, `snprintf` for `__GI___snprintf`), or `None` if
/// `func_name` doesn't start with one of the [`ALIAS_PREFIXES`].
#[must_use]
fn strip_alias_prefix(func_name: &str) -> Option<&str> {
    ALIAS_PREFIXES
        .iter()
        .find_map(|prefix| func_name.strip_prefix(prefix))
        .map(normalize_name)
}

/// Returns the normalized name `name` without the numeric suffix that IDA
/// appends to names already in use (e.g., `memset` for `memset_0`), or `None`
/// if it has none. Only one suffix is stripped.
#[must_use]
fn strip_ida_suffix(name: &str) -> Option<&str> {
    if let Some((base, suffix)) = name.rsplit_once('_')
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        Some(base)
    } else {
        None
    }
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
mod tests {
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
            known_bad.lookup("strcpy", FunctionKind::Plain),
            Some(("strcpy", Priority::High)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("memcpy", FunctionKind::Plain),
            Some(("memcpy", Priority::Medium)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("getenv", FunctionKind::Plain),
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
            known_bad.lookup("strcpy", FunctionKind::Plain),
            Some(("strcpy", Priority::High)),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.lookup("memset", FunctionKind::Plain),
            Some(("memset", Priority::Medium)),
            "decorated name should match"
        );
        assert_eq!(
            known_bad.lookup("getenv", FunctionKind::Plain),
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
                known_bad.lookup(func_name, FunctionKind::Plain),
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
            known_bad.lookup("strncpy", FunctionKind::Plain),
            None,
            "unknown name should not match"
        );
        for func_name in ["", "_", ".", "__"] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Plain),
                None,
                "function name `{func_name}` that normalizes to empty should not match"
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_strips_ida_suffix_from_stubs() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["CreateProcessW"], &[]))?;

        for func_name in ["strcpy_0", "strcpy_12", "_strcpy_0"] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Stub),
                Some(("strcpy", Priority::High)),
                "stub name `{func_name}` with a numeric suffix should match"
            );
        }
        assert_eq!(
            known_bad.lookup("CreateProcessW_0", FunctionKind::Stub),
            Some(("CreateProcessW", Priority::Medium)),
            "stub name with a numeric suffix should match"
        );
        Ok(())
    }

    #[test]
    fn lookup_keeps_ida_suffix_of_other_functions() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&[], &["read"], &["write"]))?;

        for func_name in ["read_16", "write_32", "_read_8"] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Plain),
                None,
                "function name `{func_name}` that isn't a stub should not match"
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_strips_ucrt_prefix() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&[], &["_wpopen"], &["malloc", "rand"]))?;

        for (func_name, expected) in [
            ("__o_malloc", ("malloc", Priority::Low)),
            ("_o_malloc", ("malloc", Priority::Low)),
            ("__o__wpopen", ("wpopen", Priority::Medium)),
            ("_o_rand_0", ("rand", Priority::Low)),
        ] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Plain),
                Some(expected),
                "function name `{func_name}` with the UCRT prefix should match"
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_strips_glibc_prefixes() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(
            &["system"],
            &["snprintf", "strlen"],
            &["realloc"],
        ))?;

        for (func_name, expected) in [
            ("__libc_system", ("system", Priority::High)),
            ("__libc_realloc", ("realloc", Priority::Low)),
            ("__GI___snprintf", ("snprintf", Priority::Medium)),
            ("__GI_strlen", ("strlen", Priority::Medium)),
        ] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Plain),
                Some(expected),
                "function name `{func_name}` with a glibc prefix should match"
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_requires_underscores_before_alias_prefix() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&["system"], &["write", "snprintf"], &["malloc"]))?;

        for kind in [FunctionKind::Plain, FunctionKind::Stub] {
            for func_name in [
                "o_write",
                "o_malloc",
                ".o_malloc",
                "libc_system",
                "_libc_system",
                "GI_snprintf",
                "_GI_snprintf",
            ] {
                assert_eq!(
                    known_bad.lookup(func_name, kind),
                    None,
                    "function name `{func_name}` without an alias prefix should not match"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn lookup_tries_unprefixed_name_before_stripping_suffix() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["foo_2"], &[], &["foo"]))?;

        assert_eq!(
            known_bad.lookup("__o_foo_2", FunctionKind::Plain),
            Some(("foo_2", Priority::High)),
            "name without the alias prefix should be tried before stripping the suffix"
        );
        Ok(())
    }

    #[test]
    fn lookup_prefers_exact_match_over_stripped_name() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &["strcpy_1"], &[]))?;

        assert_eq!(
            known_bad.lookup("strcpy_1", FunctionKind::Stub),
            Some(("strcpy_1", Priority::Medium)),
            "exact match should take precedence"
        );
        assert_eq!(
            known_bad.lookup("strcpy_2", FunctionKind::Stub),
            Some(("strcpy", Priority::High)),
            "stub name without an exact match should match once stripped"
        );
        Ok(())
    }

    #[test]
    fn lookup_keeps_other_suffixes_and_prefixes() -> Result<(), String> {
        let known_bad = KnownBadFunctions::try_from(config(&["strcpy"], &[], &[]))?;

        // As a stub, where the most is stripped.
        for func_name in [
            "strcpy_s",
            "strcpy_",
            "strcpy_0x",
            "strcpy0",
            "strcpy_0_1",
            "foo_strcpy",
            "x_strcpy",
            "o_",
            "o_0",
            "__o_",
            "__libc_",
            "__GI_",
            "__libc_strcpy_s",
        ] {
            assert_eq!(
                known_bad.lookup(func_name, FunctionKind::Stub),
                None,
                "function name `{func_name}` should not match"
            );
        }
        Ok(())
    }

    #[test]
    fn try_from_accepts_duplicates_within_the_same_priority() -> Result<(), String> {
        let known_bad =
            KnownBadFunctions::try_from(config(&[], &["fwrite", "_fwrite", "fwrite"], &[]))?;

        assert_eq!(
            known_bad.lookup("fwrite", FunctionKind::Plain),
            Some(("fwrite", Priority::Medium)),
            "wrong normalized name or priority"
        );
        assert_eq!(known_bad.functions.len(), 1, "duplicates should be merged");
        Ok(())
    }

    #[test]
    fn try_from_rejects_names_listed_under_multiple_priorities() {
        for (high, medium, low, duplicate) in [
            (&["strtrns"][..], &["strtrns"][..], &[][..], "strtrns"),
            (&[], &["_memcpy"], &[".memcpy"], "memcpy"),
            (&["getenv"], &[], &["__getenv"], "getenv"),
        ] {
            let result = KnownBadFunctions::try_from(config(high, medium, low));
            assert!(
                result.is_err_and(
                    |err| err == format!("`{duplicate}` is listed under multiple priorities")
                ),
                "`{duplicate}` should be rejected, named once normalized"
            );
        }
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
    fn parse_uses_try_from() -> Result<(), TomlError> {
        let known_bad =
            KnownBadFunctions::parse("high = [\"_strcpy\"]\nmedium = [\"memcpy\"]\nlow = []\n")?;

        assert_eq!(
            known_bad.lookup("strcpy", FunctionKind::Plain),
            Some(("strcpy", Priority::High)),
            "wrong normalized name or priority"
        );
        assert_eq!(
            known_bad.lookup("memcpy", FunctionKind::Plain),
            Some(("memcpy", Priority::Medium)),
            "wrong normalized name or priority"
        );
        Ok(())
    }

    #[test]
    fn parse_rejects_names_listed_under_multiple_priorities() {
        let result =
            KnownBadFunctions::parse("high = [\"strtrns\"]\nmedium = [\"strtrns\"]\nlow = []\n");
        assert!(
            result.is_err_and(|err| err
                .to_string()
                .contains("`strtrns` is listed under multiple priorities")),
            "configuration with names listed under multiple priorities should be rejected"
        );
    }

    #[test]
    fn parse_rejects_unknown_keys() {
        let result =
            KnownBadFunctions::parse("high = []\nmedium = []\nlow = []\nmeduim = [\"memcpy\"]\n");
        assert!(
            result.is_err_and(|err| err.to_string().contains("unknown field `meduim`")),
            "configuration with unknown keys should be rejected"
        );
    }

    #[test]
    fn parse_rejects_missing_priorities() {
        let result = KnownBadFunctions::parse("high = [\"strcpy\"]\nmedium = []\n");
        assert!(
            result.is_err_and(|err| err.to_string().contains("missing field `low`")),
            "configuration with missing priorities should be rejected"
        );
    }

    #[test]
    fn parse_rejects_wrong_types() {
        let result = KnownBadFunctions::parse("high = \"strcpy\"\nmedium = []\nlow = []\n");
        assert!(
            result.is_err_and(|err| err.to_string().contains("invalid type")),
            "configuration with a string instead of an array should be rejected"
        );
    }

    #[test]
    fn parse_rejects_invalid_toml() {
        // The rest of the configuration is valid, so that only the syntax error
        // (the unclosed array) can make parsing fail.
        let result = KnownBadFunctions::parse("high = [\"strcpy\"\nmedium = []\nlow = []\n");
        assert!(result.is_err(), "invalid TOML should be rejected");
    }

    #[test]
    fn default_configuration_is_valid() -> Result<(), TomlError> {
        let known_bad = KnownBadFunctions::parse(DEFAULT_CONFIG)?;

        assert!(
            !known_bad.functions.is_empty(),
            "default configuration should not be empty"
        );
        Ok(())
    }
}
