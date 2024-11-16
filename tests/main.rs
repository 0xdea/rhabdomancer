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
    println!();
    print!("[*] Checking number of marked call locations... ");
    assert_eq!(n_marks, N_MARKS);
    println!("Ok.");

    // Open IDB and show everything to ensure search doesn't miss anything
    let mut idb = IDB::open(FILENAME)?;
    show_everything(&mut idb);

    // Check the number of bookmarks
    print!("[*] Checking number of bookmarks... ");
    assert_eq!(idb.bookmarks().len(), n_marks);
    println!("Ok.");

    // Check bookmarks
    print!("[*] Checking bookmarks... ");
    for i in 0..idb.bookmarks().len() {
        assert!(idb
            .bookmarks()
            .get_description_by_index(i)
            .is_some_and(|desc| desc.starts_with("[BAD ")));
    }
    println!("Ok.");

    // Check the number of comments
    print!("[*] Checking number of comments... ");
    assert_eq!(idb.find_text_iter("[BAD ").count(), n_marks as usize);
    println!("Ok.");

    // Check comments
    print!("[*] Checking comments... ");
    for i in 0..idb.bookmarks().len() {
        assert!(idb
            .get_cmt(idb.bookmarks().get_address(i).unwrap())
            .is_some_and(|desc| desc.starts_with("[BAD ")));
    }
    println!("Ok.");

    // Remove IDB file at the end
    fs::remove_file(idb_path)?;

    println!();
    Ok(())
}

/// Show everything in IDB
fn show_everything(idb: &mut IDB) {
    idb.meta_mut().set_show_all_comments();
    idb.meta_mut().set_show_hidden_funcs();
    idb.meta_mut().set_show_hidden_insns();
    idb.meta_mut().set_show_hidden_segms();
}
