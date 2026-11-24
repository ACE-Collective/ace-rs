//! The crate's integration tests as one test program. Cargo would build each file here as a test
//! program of its own, each linking every dependency again, and those programs were most of the
//! coverage build's size. `Cargo.toml` turns that off (`autotests = false`) and builds this file
//! alone, so a test file runs only once it's declared below, which `every_test_file_is_declared`
//! checks.

mod common;
mod delays;
mod reference;

/// With `autotests = false`, Cargo builds only what this file declares, so a test file it doesn't
/// name would never run.
#[test]
fn every_test_file_is_declared() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let declared = include_str!("main.rs");
    for entry in std::fs::read_dir(&dir).expect("the tests directory reads") {
        let path = entry.expect("a directory entry").path();
        let module = if path.extension().is_some_and(|e| e == "rs") {
            path.file_stem()
        } else if path.join("mod.rs").is_file() {
            path.file_name()
        } else {
            continue;
        };
        let module = module.and_then(|m| m.to_str()).expect("a UTF-8 name");
        assert!(
            module == "main" || declared.contains(&format!("\nmod {module};")),
            "tests/main.rs doesn't declare tests/{module}"
        );
    }
}
