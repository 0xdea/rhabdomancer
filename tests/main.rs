//! tests/main.rs

use std::path::Path;
use std::{env, fs};

use idalib::bookmarks::BookmarkIndex;
use idalib::idb::IDB;

/// Custom harness for integration tests.
///
/// ## Safety
///
/// [`env::set_var`] and [`env::remove_var`] are safe to call as this is a single-threaded test binary.
#[expect(clippy::expect_used, reason = "tests can use `expect`")]
fn main() -> anyhow::Result<()> {
    // Target binary path.
    const FILENAME: &str = "./tests/data/ls";
    // Expected number of marked call locations with default configuration.
    const N_MARKS: BookmarkIndex = 86;
    // Expected number of marked call locations with custom test configuration.
    const N_MARKS_CUSTOM: BookmarkIndex = 13;

    let idb_path = Path::new(FILENAME).with_extension("i64");

    // Remove the IDB file if it exists.
    if idb_path.is_file() {
        fs::remove_file(&idb_path)?;
    }

    // Run rhabdomancer and check the number of marked call locations with default configuration.
    let n_marks = rhabdomancer::run(Path::new(FILENAME))?;
    println!();
    print!("[*] Checking number of marked call locations (default configuration)... ");
    assert_eq!(n_marks, N_MARKS, "wrong number of marked call locations");
    println!("Ok.");

    {
        // Open the IDB and show everything to ensure the search doesn't miss anything.
        let mut idb = IDB::open(FILENAME)?;
        show_everything(&mut idb);

        // Check the number of bookmarks.
        print!("[*] Checking number of bookmarks... ");
        assert_eq!(idb.bookmarks().len(), n_marks, "wrong number of bookmarks");
        println!("Ok.");

        // Check bookmarks.
        print!("[*] Checking bookmarks... ");
        for i in 0..idb.bookmarks().len() {
            assert!(
                idb.bookmarks()
                    .get_description_by_index(i)
                    .is_some_and(|desc| desc.starts_with("[BAD ")),
                "wrong description in bookmark"
            );
        }
        println!("Ok.");

        // Check the number of comments.
        print!("[*] Checking number of comments... ");
        assert_eq!(
            idb.find_text_iter("[BAD ").count(),
            n_marks as usize,
            "wrong number of comments"
        );
        println!("Ok.");

        // Check comments.
        print!("[*] Checking comments... ");
        for i in 0..idb.bookmarks().len() {
            assert!(
                idb.get_cmt(
                    idb.bookmarks()
                        .get_address(i)
                        .expect("invalid bookmark address")
                )
                .is_some_and(|desc| desc.starts_with("[BAD ")),
                "wrong description in comment"
            );
        }
        println!("Ok.");

        // The IDB is dropped here before the idempotency test opens it again.
    }

    // Idempotency: a second run on the same IDB must not add any new marks.
    println!();
    let n_marks_new = rhabdomancer::run(Path::new(FILENAME))?;
    println!();
    print!("[*] Checking idempotency (second run adds no new marks)... ");
    assert_eq!(
        n_marks_new, 0,
        "second run marked {n_marks_new} new locations (expected 0)"
    );
    println!("Ok.");

    // Remove the IDB file after the default configuration and idempotency tests.
    fs::remove_file(&idb_path)?;

    // Custom configuration test: mark only a subset of functions via `RHABDOMANCER_CONFIG` override (function name
    // normalization is also tested here, as the custom configuration contains both decorated and undecorated names).
    let custom_config_path = Path::new("./tests/data/custom.toml");
    fs::write(
        custom_config_path,
        "high = [\"sprintf\", \"strcpy\"]\nmedium = [\"snprintf\", \"_fwrite\", \"memcpy\", \".memset\", \"strlen\"]\nlow = []\n",
    )?;
    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::set_var("RHABDOMANCER_CONFIG", custom_config_path);
    }
    println!();
    let n_marks_custom = rhabdomancer::run(Path::new(FILENAME))?;
    // Safety: safe to call as this is a single-threaded test binary.
    unsafe {
        env::remove_var("RHABDOMANCER_CONFIG");
    }
    fs::remove_file(custom_config_path)?;

    println!();
    print!("[*] Checking number of marked call locations (custom configuration)... ");
    assert_eq!(
        n_marks_custom, N_MARKS_CUSTOM,
        "wrong number of marked call locations"
    );
    println!("Ok.");

    {
        let mut idb = IDB::open(FILENAME)?;
        show_everything(&mut idb);

        print!("[*] Checking all custom configuration bookmarks are medium-priority... ");
        for i in 0..idb.bookmarks().len() {
            assert!(
                idb.bookmarks()
                    .get_description_by_index(i)
                    .is_some_and(|desc| desc.starts_with("[BAD 1]")),
                "custom configuration produced a non-medium-priority bookmark"
            );
        }
        println!("Ok.");
    }

    // Remove the IDB file at the end.
    fs::remove_file(idb_path)?;

    println!();
    Ok(())
}

/// Shows everything in IDB.
fn show_everything(idb: &mut IDB) {
    idb.meta_mut().set_show_all_comments();
    idb.meta_mut().set_show_hidden_funcs();
    idb.meta_mut().set_show_hidden_insns();
    idb.meta_mut().set_show_hidden_segms();
}
