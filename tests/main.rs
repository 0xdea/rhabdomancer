//! tests/main.rs.

#![expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]

use std::path::{Path, PathBuf};
use std::{env, fs, io, process};

use anyhow::Context as _;
use idalib::Address;
use idalib::bookmarks::BookmarkIndex;
use idalib::func::FunctionFlags;
use idalib::idb::IDB;

/// Prefix of the bookmarks and comments added by rhabdomancer.
///
/// Deliberately a literal: users and scripts search IDBs for this text, so an
/// accidental change to the tags that rhabdomancer writes must fail the tests.
const BAD_PREFIX: &str = "[BAD ";

/// Extensions of the files that make up an IDB, packed (`i64`) or unpacked.
const IDB_EXTENSIONS: [&str; 6] = ["i64", "id0", "id1", "id2", "nam", "til"];

/// Target binary with calls to known bad API functions.
const LS: &str = "./tests/data/ls";
/// Target binary without calls to known bad API functions.
const NO_CALLS: &str = "./tests/data/no_calls";
/// ARM64 target binary whose `main` calls `system` through a .plt stub that
/// IDA sees referencing the import more than once.
const DOUBLE_XREF: &str = "./tests/data/double_xref";
/// PE target binary whose import stubs IDA names with a numeric suffix (e.g.,
/// `strcpy_0`).
const IMPORT_STUBS: &str = "./tests/data/import_stubs";
/// Target binary that doesn't exist.
const MISSING: &str = "./tests/data/missing";

/// Expected number of marked call locations in `LS` with the default
/// configuration.
const N_MARKS: BookmarkIndex = 86;
/// Expected number of bad functions found in `LS` with the default
/// configuration, counting .plt stubs and imports separately, each printed on
/// stdout as a header after a blank line.
const N_BAD_FUNCTIONS: usize = 20;
/// Expected number of call-site lines printed on stdout for `LS` with the
/// default configuration (each of the `N_MARKS` call locations is listed under
/// both the .plt stub and the import).
const N_CALL_SITE_LINES: usize = 172;
/// Expected number of marked call locations in `LS` with `CUSTOM_CONFIG_TOML`.
const N_MARKS_CUSTOM: BookmarkIndex = 13;
/// Expected number of marked call locations in `DOUBLE_XREF`.
const N_MARKS_DOUBLE_XREF: BookmarkIndex = 1;
/// Expected stdout of rhabdomancer for `DOUBLE_XREF`, with the call site
/// listed once per bad function, even though the .plt stub references the
/// import more than once.
const DOUBLE_XREF_LISTING: &str = "
[BAD 0] system (thunk)
0x7F4 in main

[BAD 0] system
0x7F4 in main
";
/// Expected number of marked call locations in `IMPORT_STUBS`.
const N_MARKS_IMPORT_STUBS: BookmarkIndex = 22;

/// Call site in `DOUBLE_XREF` where the tests add a bookmark of their own,
/// as a user would.
const USER_BOOKMARK_ADDR: Address = 0x7F4;
/// Description of the bookmark that the tests add at `USER_BOOKMARK_ADDR`.
const USER_BOOKMARK_DESC: &str = "user note";
/// Call site in `DOUBLE_XREF` where the tests add a comment of their own, as a
/// user would.
const USER_COMMENT_ADDR: Address = 0x7F4;
/// Comment that the tests add at `USER_COMMENT_ADDR`.
const USER_COMMENT: &str = "user comment";
/// Expected comment at `USER_COMMENT_ADDR` after rhabdomancer runs, with its
/// tag appended to the user's comment exactly once (`append_cmt` separates
/// them with a newline).
const USER_COMMENT_MARKED: &str = "user comment\n[BAD 0] system";

/// Label of the custom configuration file written by the tests to a temporary
/// directory.
const CUSTOM_CONFIG: &str = "custom";
/// Custom configuration that marks only a subset of functions, including
/// decorated names to test normalization.
const CUSTOM_CONFIG_TOML: &str = r#"
high = ["sprintf", "strcpy"]
medium = ["snprintf", "_fwrite", "memcpy", ".memset", "strlen"]
low = []
"#;
/// Normalized names of the medium-priority functions in `CUSTOM_CONFIG_TOML`.
const CUSTOM_MEDIUM: &[&str] = &["snprintf", "fwrite", "memcpy", "memset", "strlen"];

/// Label of the invalid configuration file written by the tests to a temporary
/// directory.
const INVALID_CONFIG: &str = "invalid";
/// Invalid configuration that lists the same function under multiple
/// priorities, once normalized.
const INVALID_CONFIG_TOML: &str = r#"
high = ["strcpy"]
medium = ["_strcpy"]
low = []
"#;

/// Label of the configuration file that the tests never write, to test a
/// missing configuration.
const MISSING_CONFIG: &str = "missing";

/// Custom harness for integration tests.
fn main() -> anyhow::Result<()> {
    // Force IDA to stay quiet.
    idalib::force_batch_mode();

    // Make sure the scenarios that expect the built-in configuration don't pick
    // up a custom one from the environment.
    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::remove_var("RHABDOMANCER_CONFIG");
    };

    test_default_configuration()?;
    test_custom_configuration()?;
    test_binary_without_calls()?;
    test_thunk_with_repeated_xrefs()?;
    test_import_stubs_with_numeric_suffix()?;
    test_user_bookmark_at_call_site()?;
    test_user_comment_at_call_site()?;
    test_empty_configuration_variable()?;
    test_invalid_configuration()?;
    test_missing_configuration()?;
    test_missing_binary()?;
    test_invalid_arguments()?;

    eprintln!();
    Ok(())
}

/// Runs the rhabdomancer binary with the default configuration, checks what it
/// prints and its annotations, then runs rhabdomancer again on the same IDB and
/// checks that no new call locations are marked.
fn test_default_configuration() -> anyhow::Result<()> {
    reset_idb(LS)?;

    let output = run_binary(&[LS], None)?;
    eprintln!();
    check_binary_succeeded(&output);
    check_number_of_output_lines(&output);
    check_stdout_line(&output, "0x2C5F in sub_2C30");
    check_summary(&output, "[+] Marked 86 new call locations");
    check_priority_order(&output)?;

    let idb = open_idb(LS)?;
    check_number_of_bookmarks(&idb, N_MARKS);
    check_bookmark_descriptions(&idb);
    check_number_of_comments(&idb, N_MARKS)?;
    check_comments_match_bookmarks(&idb)?;
    // The IDB must be closed before rhabdomancer opens it again.
    drop(idb);

    eprintln!();
    let n_marks_new = rhabdomancer::run(LS)?;
    eprintln!();
    check_no_new_marks(n_marks_new);

    // Remove the IDB file at the end.
    reset_idb(LS)?;
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with a custom configuration set via `RHABDOMANCER_CONFIG`
/// and checks its annotations.
fn test_custom_configuration() -> anyhow::Result<()> {
    reset_idb(LS)?;

    let n_marks = run_with_config(LS, CUSTOM_CONFIG, CUSTOM_CONFIG_TOML)??;
    eprintln!();
    check_number_of_marks(n_marks, N_MARKS_CUSTOM);

    let idb = open_idb(LS)?;
    check_number_of_bookmarks(&idb, n_marks);
    check_custom_bookmark_descriptions(&idb);
    check_number_of_comments(&idb, n_marks)?;
    check_comments_match_bookmarks(&idb)?;
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(LS)?;
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer against a binary without calls to known bad API functions
/// and checks that it marks no call locations.
fn test_binary_without_calls() -> anyhow::Result<()> {
    reset_idb(NO_CALLS)?;

    let n_marks = rhabdomancer::run(NO_CALLS)?;
    eprintln!();
    check_number_of_marks(n_marks, 0);

    let idb = open_idb(NO_CALLS)?;
    check_number_of_bookmarks(&idb, n_marks);
    check_number_of_comments(&idb, n_marks)?;
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(NO_CALLS)?;
    eprintln!();
    Ok(())
}

/// Runs the rhabdomancer binary against a binary whose .plt stub references a
/// bad API function more than once, and checks that each call site is listed
/// only once (regression test for walking the stub's XREFs once per reference).
fn test_thunk_with_repeated_xrefs() -> anyhow::Result<()> {
    reset_idb(DOUBLE_XREF)?;

    let output = run_binary(&[DOUBLE_XREF], None)?;
    eprintln!();
    check_binary_succeeded(&output);
    check_listing(&output, DOUBLE_XREF_LISTING);

    let idb = open_idb(DOUBLE_XREF)?;
    check_number_of_bookmarks(&idb, N_MARKS_DOUBLE_XREF);
    check_number_of_comments(&idb, N_MARKS_DOUBLE_XREF)?;
    check_comments_match_bookmarks(&idb)?;
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(DOUBLE_XREF)?;
    eprintln!();
    Ok(())
}

/// Runs the rhabdomancer binary against a PE binary whose import stubs IDA
/// names with a numeric suffix (e.g., `strcpy_0`), and checks that their calls
/// are marked (regression test for missing such stubs).
fn test_import_stubs_with_numeric_suffix() -> anyhow::Result<()> {
    reset_idb(IMPORT_STUBS)?;

    let output = run_binary(&[IMPORT_STUBS], None)?;
    eprintln!();
    check_binary_succeeded(&output);
    check_stdout_line(&output, "[BAD 0] strcpy (thunk)");
    check_stdout_line(&output, "0x1400014AB in helper");
    check_summary(&output, "[+] Marked 22 new call locations");

    let idb = open_idb(IMPORT_STUBS)?;
    check_thunk_exists(&idb, "strcpy_0");
    check_number_of_bookmarks(&idb, N_MARKS_IMPORT_STUBS);
    check_number_of_comments(&idb, N_MARKS_IMPORT_STUBS)?;
    check_comments_match_bookmarks(&idb)?;
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(IMPORT_STUBS)?;
    eprintln!();
    Ok(())
}

/// Adds a bookmark of its own at a call site, as a user would, then runs
/// rhabdomancer twice and checks that the second run marks no new call
/// locations and that the user's bookmark is preserved (regression test for
/// overlaid bookmarks hiding rhabdomancer's own).
fn test_user_bookmark_at_call_site() -> anyhow::Result<()> {
    reset_idb(DOUBLE_XREF)?;
    add_user_bookmark(DOUBLE_XREF)?;

    let n_marks = rhabdomancer::run(DOUBLE_XREF)?;
    eprintln!();
    check_number_of_marks(n_marks, N_MARKS_DOUBLE_XREF);

    eprintln!();
    let n_marks_new = rhabdomancer::run(DOUBLE_XREF)?;
    eprintln!();
    check_no_new_marks(n_marks_new);

    let idb = open_idb(DOUBLE_XREF)?;
    check_number_of_bookmarks(&idb, N_MARKS_DOUBLE_XREF.saturating_add(1));
    check_user_bookmark_preserved(&idb);
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(DOUBLE_XREF)?;
    eprintln!();
    Ok(())
}

/// Adds a comment of its own at a call site, as a user would, then runs
/// rhabdomancer twice and checks that the tag is appended to the user's
/// comment exactly once (regression test for the comment check, which must
/// find the tag after any existing text).
fn test_user_comment_at_call_site() -> anyhow::Result<()> {
    reset_idb(DOUBLE_XREF)?;
    add_user_comment(DOUBLE_XREF)?;

    let n_marks = rhabdomancer::run(DOUBLE_XREF)?;
    eprintln!();
    check_number_of_marks(n_marks, N_MARKS_DOUBLE_XREF);

    eprintln!();
    let n_marks_new = rhabdomancer::run(DOUBLE_XREF)?;
    eprintln!();
    check_no_new_marks(n_marks_new);

    let idb = open_idb(DOUBLE_XREF)?;
    check_number_of_bookmarks(&idb, N_MARKS_DOUBLE_XREF);
    check_number_of_comments(&idb, N_MARKS_DOUBLE_XREF)?;
    check_user_comment_marked(&idb);
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(DOUBLE_XREF)?;
    eprintln!();
    Ok(())
}

/// Runs the rhabdomancer binary with `RHABDOMANCER_CONFIG` set to an empty
/// value and checks that it uses the built-in configuration, rather than
/// failing to read a configuration file with an empty path.
fn test_empty_configuration_variable() -> anyhow::Result<()> {
    reset_idb(NO_CALLS)?;

    eprintln!();
    let output = run_binary(&[NO_CALLS], Some(""))?;
    eprintln!();
    check_binary_succeeded(&output);

    // Remove the IDB file at the end.
    reset_idb(NO_CALLS)?;
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with an invalid configuration and checks that it fails
/// before analyzing the binary.
fn test_invalid_configuration() -> anyhow::Result<()> {
    reset_idb(LS)?;

    let result = run_with_config(LS, INVALID_CONFIG, INVALID_CONFIG_TOML)?;
    eprintln!();
    check_invalid_configuration_error(result)?;
    check_no_idb_created(LS);
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with a configuration file that doesn't exist and checks
/// that it fails before analyzing the binary.
fn test_missing_configuration() -> anyhow::Result<()> {
    reset_idb(LS)?;
    let missing_config = config_path(MISSING_CONFIG);
    if missing_config.is_file() {
        fs::remove_file(&missing_config)?;
    }

    let result = run_with_config_path(LS, &missing_config);
    eprintln!();
    check_missing_configuration_error(result)?;
    check_no_idb_created(LS);
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer against a binary that doesn't exist and checks that it
/// fails without creating an IDB.
fn test_missing_binary() -> anyhow::Result<()> {
    reset_idb(MISSING)?;

    let result = rhabdomancer::run(MISSING);
    eprintln!();
    check_missing_binary_error(result)?;
    check_no_idb_created(MISSING);
    Ok(())
}

/// Runs the rhabdomancer binary with invalid arguments and checks that each
/// time it prints usage information and fails without analyzing anything.
fn test_invalid_arguments() -> anyhow::Result<()> {
    reset_idb(NO_CALLS)?;

    for args in [&[][..], &[NO_CALLS, NO_CALLS], &["-h"], &["--help"]] {
        eprintln!();
        let output = run_binary(args, None)?;
        check_usage(&output, args);
    }
    check_no_idb_created(NO_CALLS);
    Ok(())
}

/// Removes the IDB files of the binary at `filename`, packed or unpacked, if
/// they exist.
fn reset_idb(filename: &str) -> anyhow::Result<()> {
    for extension in IDB_EXTENSIONS {
        let idb_path = Path::new(filename).with_extension(extension);
        if idb_path.is_file() {
            fs::remove_file(idb_path)?;
        }
    }
    Ok(())
}

/// Opens the IDB of the binary at `filename` and shows everything, so that
/// checks don't miss anything.
fn open_idb(filename: &str) -> anyhow::Result<IDB> {
    let mut idb = IDB::open(filename)?;
    idb.meta_mut().set_show_all_comments();
    idb.meta_mut().set_show_hidden_funcs();
    idb.meta_mut().set_show_hidden_insns();
    idb.meta_mut().set_show_hidden_segms();
    Ok(idb)
}

/// Creates the IDB of the binary at `filename` with a bookmark at
/// `USER_BOOKMARK_ADDR`, as a user would add it, and saves it.
fn add_user_bookmark(filename: &str) -> anyhow::Result<()> {
    let idb = IDB::open_with(filename, true, true)?;
    idb.bookmarks()
        .mark(USER_BOOKMARK_ADDR, USER_BOOKMARK_DESC)?;
    Ok(())
}

/// Creates the IDB of the binary at `filename` with a comment at
/// `USER_COMMENT_ADDR`, as a user would add it, and saves it.
fn add_user_comment(filename: &str) -> anyhow::Result<()> {
    let idb = IDB::open_with(filename, true, true)?;
    idb.set_cmt(USER_COMMENT_ADDR, USER_COMMENT)?;
    Ok(())
}

/// Returns the path of a configuration file in a temporary directory, scoped to
/// `label` and the current process.
fn config_path(label: &str) -> PathBuf {
    env::temp_dir().join(format!("rhabdomancer_{label}_{}.toml", process::id()))
}

/// Runs rhabdomancer against the binary at `filename` with the configuration
/// file at `config_path`, selected via the `RHABDOMANCER_CONFIG` environment
/// variable, then unsets the variable.
fn run_with_config_path(filename: &str, config_path: &Path) -> anyhow::Result<BookmarkIndex> {
    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::set_var("RHABDOMANCER_CONFIG", config_path);
    };

    eprintln!();
    let result = rhabdomancer::run(filename);

    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::remove_var("RHABDOMANCER_CONFIG");
    };
    result
}

/// Runs rhabdomancer against the binary at `filename` with `text` written to
/// the configuration file for `label` (see [`config_path`]), then removes the
/// configuration file.
///
/// Returns the result of the run, so that callers can check expected errors.
///
/// # Errors
///
/// Returns an error if the configuration file cannot be written or removed.
fn run_with_config(
    filename: &str,
    label: &str,
    text: &str,
) -> anyhow::Result<anyhow::Result<BookmarkIndex>> {
    let config_path = config_path(label);
    fs::write(&config_path, text)?;
    let result = run_with_config_path(filename, &config_path);
    fs::remove_file(&config_path)?;
    Ok(result)
}

/// Runs the rhabdomancer binary with `args`, with `RHABDOMANCER_CONFIG` set to
/// `config` if any, or removed otherwise, forwards its stderr, and returns its
/// output.
///
/// Unlike [`rhabdomancer::run`], this captures the listing of call sites that
/// rhabdomancer prints to stdout.
///
/// # Errors
///
/// Returns an error if the binary cannot be run.
fn run_binary(args: &[&str], config: Option<&str>) -> anyhow::Result<process::Output> {
    let mut command = process::Command::new(env!("CARGO_BIN_EXE_rhabdomancer"));
    command.args(args);
    if let Some(config) = config {
        command.env("RHABDOMANCER_CONFIG", config);
    } else {
        command.env_remove("RHABDOMANCER_CONFIG");
    }
    let output = command.output()?;
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(output)
}

/// Checks that the rhabdomancer binary exited successfully.
fn check_binary_succeeded(output: &process::Output) {
    eprint!("[*] Checking binary exits successfully... ");
    assert!(
        output.status.success(),
        "binary failed with {}",
        output.status
    );
    eprintln!("Ok.");
}

/// Checks that stdout has a header line (after a blank line) per bad function
/// found in `LS`, one line per call site, and nothing else.
fn check_number_of_output_lines(output: &process::Output) {
    eprint!("[*] Checking number of stdout lines by kind... ");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = |is_kind: fn(&str) -> bool| stdout.lines().filter(|line| is_kind(line)).count();

    assert_eq!(
        count(str::is_empty),
        N_BAD_FUNCTIONS,
        "wrong number of blank lines"
    );
    assert_eq!(
        count(|line| line.starts_with(BAD_PREFIX)),
        N_BAD_FUNCTIONS,
        "wrong number of bad function header lines"
    );
    assert_eq!(
        count(|line| line.starts_with("0x") && line.contains(" in ")),
        N_CALL_SITE_LINES,
        "wrong number of call-site lines"
    );
    assert_eq!(
        stdout.lines().count(),
        2 * N_BAD_FUNCTIONS + N_CALL_SITE_LINES,
        "unexpected stdout lines"
    );
    eprintln!("Ok.");
}

/// Checks that stdout contains the known `line`, which pins the output format.
fn check_stdout_line(output: &process::Output, line: &str) {
    eprint!("[*] Checking stdout contains `{line}`... ");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.lines().any(|stdout_line| stdout_line == line),
        "known stdout line missing from:\n{stdout}"
    );
    eprintln!("Ok.");
}

/// Checks that stderr contains the final `summary`, which reports the number of
/// newly marked call locations.
fn check_summary(output: &process::Output, summary: &str) {
    eprint!("[*] Checking summary reports marked call locations... ");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.lines().any(|line| line == summary),
        "summary missing or wrong in stderr"
    );
    eprintln!("Ok.");
}

/// Checks the number of marked call locations.
fn check_number_of_marks(n_marks: BookmarkIndex, expected: BookmarkIndex) {
    eprint!("[*] Checking number of marked call locations... ");
    assert_eq!(n_marks, expected, "wrong number of marked call locations");
    eprintln!("Ok.");
}

/// Checks the number of bookmarks in the IDB.
fn check_number_of_bookmarks(idb: &IDB, n_marks: BookmarkIndex) {
    eprint!("[*] Checking number of bookmarks... ");
    assert_eq!(idb.bookmarks().len(), n_marks, "wrong number of bookmarks");
    eprintln!("Ok.");
}

/// Checks that every bookmark description starts with `BAD_PREFIX`.
fn check_bookmark_descriptions(idb: &IDB) {
    eprint!("[*] Checking bookmark descriptions... ");
    for idx in 0..idb.bookmarks().len() {
        let desc = idb.bookmarks().get_description_by_index(idx);
        assert!(
            desc.as_deref()
                .is_some_and(|desc| desc.starts_with(BAD_PREFIX)),
            "wrong bookmark description: {desc:?}"
        );
    }
    eprintln!("Ok.");
}

/// Checks the number of comments that contain `BAD_PREFIX` in the IDB.
fn check_number_of_comments(idb: &IDB, n_marks: BookmarkIndex) -> anyhow::Result<()> {
    eprint!("[*] Checking number of comments... ");
    assert_eq!(
        idb.find_text_iter(BAD_PREFIX).count(),
        usize::try_from(n_marks)?,
        "wrong number of comments"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that the comment at every bookmarked address starts with the
/// bookmark's description.
fn check_comments_match_bookmarks(idb: &IDB) -> anyhow::Result<()> {
    eprint!("[*] Checking comments match bookmark descriptions... ");
    for idx in 0..idb.bookmarks().len() {
        let addr = idb
            .bookmarks()
            .get_address(idx)
            .context("invalid bookmark address")?;
        let desc = idb
            .bookmarks()
            .get_description_by_index(idx)
            .context("missing bookmark description")?;
        let cmt = idb.get_cmt(addr);
        assert!(
            cmt.as_deref().is_some_and(|cmt| cmt.starts_with(&desc)),
            "comment at {addr:#X} doesn't match bookmark description `{desc}`: {cmt:?}"
        );
    }
    eprintln!("Ok.");
    Ok(())
}

/// Checks that a second run on the same IDB marks no new call locations.
fn check_no_new_marks(n_marks_new: BookmarkIndex) {
    eprint!("[*] Checking idempotency (second run adds no new marks)... ");
    assert_eq!(
        n_marks_new, 0,
        "second run marked {n_marks_new} new locations (expected 0)"
    );
    eprintln!("Ok.");
}

/// Checks that every bookmark description is `[BAD 1] ` followed by a
/// normalized name from `CUSTOM_MEDIUM`.
fn check_custom_bookmark_descriptions(idb: &IDB) {
    eprint!("[*] Checking custom configuration bookmark descriptions... ");
    for idx in 0..idb.bookmarks().len() {
        let desc = idb.bookmarks().get_description_by_index(idx);
        assert!(
            desc.as_deref()
                .and_then(|desc| desc.strip_prefix("[BAD 1] "))
                .is_some_and(|name| CUSTOM_MEDIUM.contains(&name)),
            "custom configuration produced an unexpected bookmark description: {desc:?}"
        );
    }
    eprintln!("Ok.");
}

/// Checks that the IDB has a function named `name` flagged as a thunk, which a
/// scenario relies on, so that it can't pass without testing what it's meant
/// to (e.g., if a future IDA names the stub differently).
fn check_thunk_exists(idb: &IDB, name: &str) {
    eprint!("[*] Checking `{name}` is a thunk in the IDB... ");
    assert!(
        idb.functions().any(|(_, func)| {
            func.name().as_deref() == Some(name) && func.flags().contains(FunctionFlags::THUNK)
        }),
        "no thunk named `{name}`, the test binary no longer tests what it should"
    );
    eprintln!("Ok.");
}

/// Checks that the listing of call sites printed to stdout is `expected`.
fn check_listing(output: &process::Output, expected: &str) {
    eprint!("[*] Checking listing of call sites... ");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "wrong listing of call sites"
    );
    eprintln!("Ok.");
}

/// Checks that the bad function headers printed to stdout (`[BAD n] <name>`)
/// are ordered by priority level, from `0` (highest) to `2` (lowest), and that
/// there is more than one level, so that the check isn't vacuous.
fn check_priority_order(output: &process::Output) -> anyhow::Result<()> {
    eprint!("[*] Checking bad functions are listed by priority... ");
    let levels = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix(BAD_PREFIX))
        .map(|tag| tag.chars().next()?.to_digit(10))
        .collect::<Option<Vec<_>>>()
        .context("invalid priority level in listing")?;
    assert!(
        levels.is_sorted(),
        "bad functions not listed by priority: {levels:?}"
    );
    assert!(
        levels.first() != levels.last(),
        "listing should have more than one priority level: {levels:?}"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that the bookmark added at `USER_BOOKMARK_ADDR` is still there,
/// unchanged.
fn check_user_bookmark_preserved(idb: &IDB) {
    eprint!("[*] Checking user bookmark is preserved... ");
    let preserved = (0..idb.bookmarks().len()).any(|idx| {
        idb.bookmarks().get_address(idx) == Some(USER_BOOKMARK_ADDR)
            && idb.bookmarks().get_description_by_index(idx).as_deref() == Some(USER_BOOKMARK_DESC)
    });
    assert!(
        preserved,
        "user bookmark at {USER_BOOKMARK_ADDR:#X} was lost or changed"
    );
    eprintln!("Ok.");
}

/// Checks that the user's comment at `USER_COMMENT_ADDR` is preserved and
/// tagged exactly once.
fn check_user_comment_marked(idb: &IDB) {
    eprint!("[*] Checking user comment is preserved and tagged once... ");
    let cmt = idb.get_cmt(USER_COMMENT_ADDR);
    assert_eq!(
        cmt.as_deref(),
        Some(USER_COMMENT_MARKED),
        "wrong comment at {USER_COMMENT_ADDR:#X}"
    );
    eprintln!("Ok.");
}

/// Checks that the rhabdomancer binary failed and printed usage information to
/// stderr, and nothing to stdout, for the invalid `args`.
fn check_usage(output: &process::Output, args: &[&str]) {
    eprint!("[*] Checking usage is printed for arguments {args:?}... ");
    assert!(
        !output.status.success(),
        "invalid arguments {args:?} should fail"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Usage:"),
        "usage information should be printed for arguments {args:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing should be printed to stdout for arguments {args:?}"
    );
    eprintln!("Ok.");
}

/// Checks that `run` returns the expected error for an invalid configuration.
fn check_invalid_configuration_error(result: anyhow::Result<BookmarkIndex>) -> anyhow::Result<()> {
    eprint!("[*] Checking invalid configuration returns an error... ");
    let err = result
        .err()
        .context("expected an error for an invalid configuration")?;
    assert!(
        format!("{err:#}").contains("`strcpy` is listed under multiple priorities"),
        "wrong error returned: {err:#}"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that `run` returns the expected error for a missing configuration
/// file.
///
/// Checks the kind of the underlying [`io::Error`] rather than any message,
/// whose wording depends on the OS.
fn check_missing_configuration_error(result: anyhow::Result<BookmarkIndex>) -> anyhow::Result<()> {
    eprint!("[*] Checking missing configuration returns an error... ");
    let err = result
        .err()
        .context("expected an error for a missing configuration")?;
    assert!(
        err.chain()
            .filter_map(|cause| cause.downcast_ref::<io::Error>())
            .any(|io_err| io_err.kind() == io::ErrorKind::NotFound),
        "wrong error returned: {err:#}"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that `run` returns the expected error for a binary that doesn't
/// exist.
fn check_missing_binary_error(result: anyhow::Result<BookmarkIndex>) -> anyhow::Result<()> {
    eprint!("[*] Checking missing binary returns an error... ");
    let err = result
        .err()
        .context("expected an error for a missing binary")?;
    assert!(
        format!("{err:#}").contains("failed to analyze binary file"),
        "wrong error returned: {err:#}"
    );
    eprintln!("Ok.");
    Ok(())
}

/// Checks that no IDB file, packed or unpacked, was created for the binary at
/// `filename`.
fn check_no_idb_created(filename: &str) {
    eprint!("[*] Checking no IDB file is created... ");
    for extension in IDB_EXTENSIONS {
        let idb_path = Path::new(filename).with_extension(extension);
        assert!(
            !idb_path.exists(),
            "unexpected IDB file created: {}",
            idb_path.display()
        );
    }
    eprintln!("Ok.");
}
