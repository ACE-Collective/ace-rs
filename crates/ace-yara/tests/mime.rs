//! PLAN.md 1.7: libmagic with the pinned database agrees with `file -b --mime-type`.
//!
//! The fixture set is fixtures/mime/ and every file in the repository's samples/ directory
//! (samples/local/ only where tools/samples/gather made it). Step 1.11 makes the same
//! comparison against ace3's own `file` over the sample set.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use ace_yara::mime::{DEFAULT_DATABASE, MimeTyper};

fn files_under(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn file_command(path: &Path) -> String {
    let output = Command::new("file")
        .args(["-b", "--mime-type"])
        .arg(path)
        .output()
        .expect("file runs");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn libmagic_agrees_with_file_on_the_fixture_set() {
    let mut files = Vec::new();
    files_under(&common::fixture("mime"), &mut files);
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    files_under(&samples, &mut files);
    files.sort();

    let typer = MimeTyper::open(Path::new(DEFAULT_DATABASE)).unwrap();
    let mut differences = Vec::new();
    let mut kinds = std::collections::BTreeSet::new();
    for path in &files {
        let ours = typer.mime_type(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            typer.mime_type_of_path(path).unwrap(),
            ours,
            "{}",
            path.display()
        );
        let theirs = file_command(path);
        if ours != theirs {
            differences.push(format!(
                "{}: libmagic {ours}, file {theirs}",
                path.display()
            ));
        }
        kinds.insert(ours);
    }

    println!("{} files, mime types: {kinds:?}", files.len());
    assert!(differences.is_empty(), "{differences:#?}");
    // The fixtures alone give ten files of eight or more kinds; the samples add the rest.
    assert!(files.len() >= 10, "{} files", files.len());
    assert!(kinds.len() >= 8, "{kinds:?}");
}

#[test]
fn no_bytes_is_inode_x_empty_as_file_says_of_an_empty_file() {
    let typer = MimeTyper::open(Path::new(DEFAULT_DATABASE)).unwrap();
    let empty = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(file_command(empty.path()), "inode/x-empty");
    assert_eq!(typer.mime_type(b"").unwrap(), "inode/x-empty");
}

#[test]
fn a_zip_is_found_by_its_end_of_central_directory() {
    // libmagic's buffer API can't read at offsets from the end, so it calls this
    // application/octet-stream; `file` on the path, and this crate, call it a zip.
    let zip = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/ace3/archive/evil.zip");
    let typer = MimeTyper::open(Path::new(DEFAULT_DATABASE)).unwrap();
    assert_eq!(
        typer.mime_type(&std::fs::read(&zip).unwrap()).unwrap(),
        "application/zip"
    );
}

#[test]
fn a_missing_database_is_an_error() {
    assert!(MimeTyper::open(Path::new("/nonexistent/magic.mgc")).is_err());
}
