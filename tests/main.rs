//! tests/main.rs.

#![expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]

use std::path::Path;
use std::{env, fs, process};

use anyhow::Context as _;
use idalib::bookmarks::BookmarkIndex;
use idalib::idb::IDB;

/// Prefix of the bookmarks and comments added by rhabdomancer.
///
/// Deliberately a literal rather than `rhabdomancer::PREFIX`: users and scripts
/// search IDBs for this text, so an accidental change to the production
/// constant must fail the tests.
const BAD_PREFIX: &str = "[BAD ";

/// Extensions of the files that make up an IDB, packed (`i64`) or unpacked.
const IDB_EXTENSIONS: [&str; 6] = ["i64", "id0", "id1", "id2", "nam", "til"];

/// Target binary.
const FILENAME: &str = "./tests/data/ls";
/// Target binary that doesn't exist.
const MISSING: &str = "./tests/data/missing";

/// Expected number of marked call locations in `FILENAME` with the default
/// configuration.
const N_MARKS: BookmarkIndex = 86;
/// Expected number of marked call locations in `FILENAME` with
/// `CUSTOM_CONFIG_TOML`.
const N_MARKS_CUSTOM: BookmarkIndex = 13;

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

/// Custom harness for integration tests.
fn main() -> anyhow::Result<()> {
    // Force IDA to stay quiet.
    idalib::force_batch_mode();

    test_default_configuration()?;
    test_custom_configuration()?;
    test_invalid_configuration()?;
    test_missing_binary()?;

    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with the default configuration, checks its annotations,
/// then runs it again on the same IDB and checks that no new call locations are
/// marked.
fn test_default_configuration() -> anyhow::Result<()> {
    reset_idb(FILENAME)?;

    let n_marks = rhabdomancer::run(FILENAME)?;
    eprintln!();
    check_number_of_marks(n_marks, N_MARKS);

    let idb = open_idb(FILENAME)?;
    check_number_of_bookmarks(&idb, n_marks);
    check_bookmark_descriptions(&idb);
    check_number_of_comments(&idb, n_marks)?;
    check_comments_match_bookmarks(&idb)?;
    // The IDB must be closed before rhabdomancer opens it again.
    drop(idb);

    eprintln!();
    let n_marks_new = rhabdomancer::run(FILENAME)?;
    eprintln!();
    check_no_new_marks(n_marks_new);

    // Remove the IDB file at the end.
    reset_idb(FILENAME)?;
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with a custom configuration set via `RHABDOMANCER_CONFIG`
/// and checks its annotations.
fn test_custom_configuration() -> anyhow::Result<()> {
    reset_idb(FILENAME)?;

    let n_marks = run_with_config(FILENAME, CUSTOM_CONFIG, CUSTOM_CONFIG_TOML)??;
    eprintln!();
    check_number_of_marks(n_marks, N_MARKS_CUSTOM);

    let idb = open_idb(FILENAME)?;
    check_number_of_bookmarks(&idb, n_marks);
    check_custom_bookmark_descriptions(&idb);
    check_number_of_comments(&idb, n_marks)?;
    check_comments_match_bookmarks(&idb)?;
    drop(idb);

    // Remove the IDB file at the end.
    reset_idb(FILENAME)?;
    eprintln!();
    Ok(())
}

/// Runs rhabdomancer with an invalid configuration and checks that it fails
/// before analyzing the binary.
fn test_invalid_configuration() -> anyhow::Result<()> {
    reset_idb(FILENAME)?;

    let result = run_with_config(FILENAME, INVALID_CONFIG, INVALID_CONFIG_TOML)?;
    eprintln!();
    check_invalid_configuration_error(result)?;
    check_no_idb_created(FILENAME);
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

/// Runs rhabdomancer against the binary at `filename` with `toml` written to a
/// configuration file in a temporary directory, scoped to `label` and the
/// current process, and selected via the `RHABDOMANCER_CONFIG` environment
/// variable, then removes the configuration file and unsets the variable.
///
/// Returns the result of the run, so that callers can check expected errors.
///
/// # Errors
///
/// Returns an error if the configuration file cannot be written or removed.
fn run_with_config(
    filename: &str,
    label: &str,
    toml: &str,
) -> anyhow::Result<anyhow::Result<BookmarkIndex>> {
    let config_path = env::temp_dir().join(format!("rhabdomancer_{label}_{}.toml", process::id()));
    fs::write(&config_path, toml)?;
    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::set_var("RHABDOMANCER_CONFIG", &config_path);
    };

    eprintln!();
    let result = rhabdomancer::run(filename);

    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::remove_var("RHABDOMANCER_CONFIG");
    };
    fs::remove_file(&config_path)?;
    Ok(result)
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

/// Checks that `run` returns the expected error for a binary that doesn't
/// exist.
fn check_missing_binary_error(result: anyhow::Result<BookmarkIndex>) -> anyhow::Result<()> {
    eprint!("[*] Checking missing binary returns an error... ");
    let err = result
        .err()
        .context("expected an error for a missing binary")?;
    assert!(
        format!("{err:#}").contains("Failed to analyze binary file"),
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
