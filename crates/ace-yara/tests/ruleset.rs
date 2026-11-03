//! PLAN.md 1.6: a serialized ruleset is keyed by its hash, and two builds of the same commit
//! give the same key.
//!
//! yara-x's serialization turned out deterministic, so the key is the sha256 of the bytes.
//! The builds compared here run in two processes and from two checkouts in different
//! directories, so neither per-process hash seeds nor paths can hide in the bytes.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ace_yara::ruleset::{Manifest, build};
use ace_yara::{LoadOptions, Ruleset, ScanRequest, Scanner};
use common::fixture;

/// Set to a signature directory to make `print_build_key` print that directory's build.
const KEY_DIR_VAR: &str = "ACE4_YARA_TEST_BUILD_DIR";

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=ace4 test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A git repository holding the fixture rules under `signatures/`, and its commit.
fn repository(root: &Path) -> String {
    copy_dir(&fixture("ruleset/signatures"), &root.join("signatures"));
    git(root, &["init", "-q"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "rules"]);
    git(root, &["rev-parse", "HEAD"])
}

/// The manifest of a build of `dir` in a new process: this test binary, running only
/// `print_build_key`.
fn manifest_in_another_process(dir: &Path) -> Manifest {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "print_build_key", "--ignored", "--nocapture"])
        .env(KEY_DIR_VAR, dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("MANIFEST "))
        .unwrap_or_else(|| panic!("no manifest in {stdout}"));
    serde_json::from_str(line).unwrap()
}

#[test]
#[ignore = "run by manifest_in_another_process"]
fn print_build_key() {
    let dir = std::env::var(KEY_DIR_VAR).expect("the directory to build");
    let built = build(Path::new(&dir), &LoadOptions::default()).unwrap();
    println!(
        "MANIFEST {}",
        serde_json::to_string(&built.manifest).unwrap()
    );
}

#[test]
fn two_builds_of_the_same_commit_give_the_same_key() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let commit = repository(&first);

    let here = build(&first.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(here.manifest.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(here.manifest.key.len(), 64);

    // Again in this process.
    let again = build(&first.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(again.manifest.key, here.manifest.key);
    assert_eq!(again.bytes, here.bytes);

    // In another process, from a clone of the commit in another directory.
    let second = temp.path().join("elsewhere/second");
    std::fs::create_dir_all(second.parent().unwrap()).unwrap();
    git(
        temp.path(),
        &[
            "clone",
            "-q",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
        ],
    );
    let there = manifest_in_another_process(&second.join("signatures"));
    assert_eq!(there.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(there.key, here.manifest.key);
    assert_eq!(there, here.manifest);
}

#[test]
fn the_manifest_lists_the_files_and_rules_included_and_the_files_left_out() {
    let built = build(&fixture("ruleset/signatures"), &LoadOptions::default()).unwrap();
    let manifest = &built.manifest;

    assert_eq!(manifest.yara_x_version, yara_x::VERSION);
    let included: Vec<_> = manifest
        .files
        .iter()
        .map(|f| (f.namespace.as_str(), f.path.as_str(), f.rules.clone()))
        .collect();
    assert_eq!(
        included,
        [
            ("one", "one/a.yar", vec!["one_a".to_string()]),
            ("two", "two/b.yar", vec!["two_b".into(), "two_c".into()]),
        ]
    );
    assert_eq!(manifest.left_out.len(), 1);
    assert_eq!(manifest.left_out[0].path, "one/broken.yar");
    assert!(manifest.left_out[0].error.contains("not_defined"));
}

#[test]
fn a_directory_outside_git_is_known_by_the_hash_of_its_sources() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    repository(&repo);
    let in_git = build(&repo.join("signatures"), &LoadOptions::default()).unwrap();

    // The same files outside git: no commit, the same sources hash and the same key.
    let plain = temp.path().join("plain");
    copy_dir(&fixture("ruleset/signatures"), &plain);
    let outside = build(&plain, &LoadOptions::default()).unwrap();
    assert_eq!(outside.manifest.commit, None);
    assert_eq!(
        outside.manifest.sources_sha256,
        in_git.manifest.sources_sha256
    );
    assert_eq!(outside.manifest.key, in_git.manifest.key);

    // A changed rule changes both.
    std::fs::write(plain.join("two/b.yar"), "rule two_b { condition: false }\n").unwrap();
    let changed = build(&plain, &LoadOptions::default()).unwrap();
    assert_ne!(
        changed.manifest.sources_sha256,
        outside.manifest.sources_sha256
    );
    assert_ne!(changed.manifest.key, outside.manifest.key);

    // So does a change to a file that is left out, which the key alone wouldn't show.
    std::fs::write(plain.join("one/broken.yar"), "rule one_broken {").unwrap();
    let broken_changed = build(&plain, &LoadOptions::default()).unwrap();
    assert_ne!(
        broken_changed.manifest.sources_sha256,
        changed.manifest.sources_sha256
    );
    assert_eq!(broken_changed.manifest.key, changed.manifest.key);
}

#[test]
fn a_checkout_with_uncommitted_changes_records_no_commit() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    repository(&repo);
    std::fs::write(
        repo.join("signatures/two/new.yar"),
        "rule untracked { condition: true }\n",
    )
    .unwrap();
    let built = build(&repo.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(built.manifest.commit, None);
}

#[test]
fn a_ruleset_loaded_from_its_bytes_scans_like_the_one_built() {
    let built = build(&fixture("ruleset/signatures"), &LoadOptions::default()).unwrap();
    let loaded = Ruleset::from_bytes(&built.bytes, &LoadOptions::default()).unwrap();

    let tags = vec!["type=email.attachment".to_string()];
    let request = ScanRequest {
        data: b"MZ\x90\x00\x01\x02PE needle haySTACKstack",
        path: "alert/sample.bin",
        mime_type: "application/octet-stream",
        meta_tags: &tags,
        timeout: Some(Duration::from_secs(5)),
    };
    let from_build = Scanner::new(&built.ruleset).scan(&request).unwrap();
    let from_bytes = Scanner::new(&loaded).scan(&request).unwrap();
    assert_eq!(from_bytes, from_build);
    assert!(!from_build.matches.is_empty());

    // The filters were compiled again: without the tag, one_a is dropped.
    let untagged = ScanRequest {
        meta_tags: &[],
        ..request
    };
    let outcome = Scanner::new(&loaded).scan(&untagged).unwrap();
    assert!(outcome.dropped.iter().any(|m| m.rule == "one_a"));
}
