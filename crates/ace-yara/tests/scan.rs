//! PLAN.md 1.5: a scan returns each match's namespace, rule, meta and pattern offsets, with
//! the externals and the filter set from the file, and a timeout is an error.

use crate::common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ace_yara::{
    LoadOptions, MetaValue, PatternMatch, ScanError, ScanOutcome, ScanRequest, Scanner, load_dir,
};
use common::fixture;

const DATA: &[u8] = b"xx needle yy ABC needle";

fn scan(options: &LoadOptions, path: &str, mime_type: &str, meta_tags: &[&str]) -> ScanOutcome {
    let loaded = load_dir(&fixture("scan/signatures"), options).unwrap();
    let tags: Vec<String> = meta_tags.iter().map(|t| t.to_string()).collect();
    Scanner::new(&loaded.ruleset)
        .scan(&ScanRequest {
            data: DATA,
            path,
            mime_type,
            meta_tags: &tags,
            timeout: Some(Duration::from_secs(5)),
        })
        .unwrap()
}

fn rules(matches: &[ace_yara::Match]) -> Vec<&str> {
    let mut names: Vec<_> = matches.iter().map(|m| m.rule.as_str()).collect();
    names.sort();
    names
}

fn pattern(identifier: &str, offset: usize, length: usize) -> PatternMatch {
    PatternMatch {
        identifier: identifier.into(),
        offset,
        length,
    }
}

#[test]
fn a_match_carries_its_namespace_rule_meta_and_pattern_offsets() {
    let outcome = scan(
        &LoadOptions::default(),
        "alert/files/run.txt",
        "text/plain",
        &[],
    );
    let found = outcome
        .matches
        .iter()
        .find(|m| m.rule == "two_patterns")
        .expect("two_patterns matches");

    assert_eq!(found.namespace, "scan");
    assert_eq!(
        found.meta.get("uuid"),
        Some(&MetaValue::Str(
            "7d1f1d6e-0000-4000-8000-000000000005".into()
        ))
    );
    assert_eq!(
        found.patterns,
        [
            pattern("$a", 3, 6),
            pattern("$a", 17, 6),
            pattern("$b", 13, 3)
        ]
    );
}

#[test]
fn the_path_sets_the_externals() {
    let outcome = scan(
        &LoadOptions::default(),
        "alert/files/run.ps1",
        "text/plain",
        &[],
    );
    assert!(rules(&outcome.matches).contains(&"path_externals"));

    let outcome = scan(
        &LoadOptions::default(),
        "alert/files/run.txt",
        "text/plain",
        &[],
    );
    assert!(!rules(&outcome.matches).contains(&"path_externals"));
}

#[test]
fn the_filter_uses_the_meta_tags_and_the_mime_type() {
    // No tags: the meta_tags rule is dropped. Not a PDF: the mime_type rule is dropped.
    let outcome = scan(&LoadOptions::default(), "alert/a.txt", "text/plain", &[]);
    assert_eq!(rules(&outcome.matches), ["two_patterns"]);
    assert_eq!(rules(&outcome.dropped), ["pdf_only", "tagged_attachment"]);

    let outcome = scan(
        &LoadOptions::default(),
        "alert/a.txt",
        "application/pdf",
        &["type=email.attachment"],
    );
    assert_eq!(
        rules(&outcome.matches),
        ["pdf_only", "tagged_attachment", "two_patterns"]
    );
    assert!(outcome.dropped.is_empty());
    let tagged = outcome
        .matches
        .iter()
        .find(|m| m.rule == "tagged_attachment")
        .unwrap();
    assert_eq!(tagged.tags, ["attachment"]);
}

#[test]
fn a_blacklisted_rule_is_dropped() {
    let options = LoadOptions {
        blacklist: BTreeSet::from(["two_patterns".to_string()]),
    };
    let outcome = scan(&options, "alert/a.txt", "text/plain", &[]);
    assert!(!rules(&outcome.matches).contains(&"two_patterns"));
    assert!(rules(&outcome.dropped).contains(&"two_patterns"));
}

#[test]
fn a_scan_past_its_timeout_is_a_timeout_error_not_an_empty_match_list() {
    let loaded = load_dir(&fixture("scan/slow"), &LoadOptions::default()).unwrap();
    let mut scanner = Scanner::new(&loaded.ruleset);
    let data = vec![0u8; 100_000];

    let started = Instant::now();
    let result = scanner.scan(&ScanRequest {
        data: &data,
        path: "alert/zeros.bin",
        mime_type: "application/octet-stream",
        meta_tags: &[],
        timeout: Some(Duration::from_secs(1)),
    });
    let elapsed = started.elapsed();

    match result {
        Err(ScanError::Timeout) => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
    // yara-x checks the timeout about once a second.
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
}
