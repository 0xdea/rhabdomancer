use std::fs;
use std::path::Path;

use idalib::idb::IDB;

/// Custom harness for integration tests
fn main() {
    // Target binary path
    const FILENAME: &str = "./tests/bin/ls";
    // Number of marked call locations with the default configuration
    const N_MARKS: usize = 86;

    // Remove IDB file if it exists
    let idb_path = &format!("{FILENAME}.i64");
    let idb_path = Path::new(idb_path);
    if idb_path.is_file() {
        fs::remove_file(idb_path).unwrap();
    }

    // Run rhabdomancer and check the number of marked call locations
    let n_marks = rhabdomancer::run(Path::new(FILENAME)).unwrap();
    assert_eq!(n_marks, N_MARKS);

    // Check all marked call locations
    let _idb = IDB::open(FILENAME).unwrap();
    // TODO: implement bookmarks first, which should allow for an easy check
    // TODO: for comments, we need to implement text search functionality in idalib

    // Remove IDB file at the end
    fs::remove_file(idb_path).unwrap();
}
