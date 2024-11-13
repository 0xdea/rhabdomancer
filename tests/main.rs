use std::fs;
use std::path::Path;

use idalib::bookmarks::BookmarkIndex;
use idalib::idb::IDB;

/// Custom harness for integration tests
fn main() -> anyhow::Result<()> {
    // Target binary path
    const FILENAME: &str = "./tests/bin/ls";
    // Expected number of marked call locations with default configuration
    const N_MARKS: BookmarkIndex = 86;

    // Remove IDB file if it exists
    let idb_path = &format!("{FILENAME}.i64");
    let idb_path = Path::new(idb_path);
    if idb_path.is_file() {
        fs::remove_file(idb_path)?;
    }

    // Run rhabdomancer and check the number of marked call locations
    let n_marks = rhabdomancer::run(Path::new(FILENAME))?;
    assert_eq!(n_marks, N_MARKS);

    // Check all marked call locations
    let idb = IDB::open(FILENAME)?;
    assert_eq!(idb.bookmarks().len(), n_marks);
    for i in 0..idb.bookmarks().len() {
        assert!(idb
            .bookmarks()
            .get_description_by_index(i)
            .is_some_and(|desc| desc.starts_with("[BAD ")));
    }

    // TODO: check also comments, via either one of the following functionalities to be added to idalib:
    //  * text search
    //  * `bookmarks().find_address()`

    // Remove IDB file at the end
    fs::remove_file(idb_path)?;

    Ok(())
}
