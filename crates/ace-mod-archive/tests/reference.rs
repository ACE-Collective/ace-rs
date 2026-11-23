//! PLAN.md 1.29: the archive module against ace3's reference dumps for the archive samples,
//! nested, password-protected and zip-slip ones among them. Every difference is listed and
//! explained in differences.md, next to this file.

use std::collections::BTreeMap;
use std::path::Path;

use ace_mod_archive::ArchiveAnalyzer;
use ace_sdk::Outcome;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

/// The sample a dump analyzed, as the core would hand it over: with the mime type libmagic
/// finds, which is the one ace3's file_type module found (PLAN.md 1.7). None when the sample is
/// a git-ignored local one that isn't here.
fn sample(
    harness: &Harness<ArchiveAnalyzer>,
    dump: &Dump,
) -> Option<Result<ace_sdk::Observable, HarnessError>> {
    let path = dump.sample().expect("an archive dump analyzed a file");
    match harness.sample(path) {
        Ok(mut observable) => {
            if let Some(file) = observable.file.as_mut() {
                file.mime_type = dump.mime_type().map(str::to_owned);
            }
            Some(Ok(observable))
        }
        Err(e) if path.starts_with("local/") => {
            eprintln!("skipping {}: {e}", dump.name);
            None
        }
        Err(e) => Some(Err(e)),
    }
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
    let mut compared = Vec::new();
    let mut skipped = Vec::new();
    for dump in Dump::all("archive").expect("the dumps read") {
        let Some(observable) = sample(&harness, &dump) else {
            skipped.push(dump.short_name().to_owned());
            continue;
        };
        let observable = observable.unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if dump.short_name() == "ace3/archive/test.zip" {
            // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
            ace_testkit::check_view_fixture("archive_test_zip", &outcome);
        }
        let differences = diff(&dump.normal_form("ArchiveAnalysis"), &normal_form(&outcome));
        compared.push((dump.short_name().to_owned(), differences));
    }
    assert!(
        compared.len() >= 11,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &skipped) {
        panic!("{report}");
    }
}

/// Where ace3 hit the file limit, it picked files in the order its filesystem listed them, and
/// ace-rs picks them in archive order, so the two extract different files. With no limit, every
/// file ace3 extracted is among ace-rs's, with the same bytes, except the JAR entries whose CRC
/// doesn't match: ace3's zipfile raised at the end of each one and left it empty.
#[test]
fn without_a_limit_every_file_ace3_extracted_matches() {
    let harness = Harness::<ArchiveAnalyzer>::with_settings(json!({
        "max_file_count": 0,
        "max_jar_file_count": 0,
    }))
    .expect("harness")
    .with_typer(ace_mod_files::file_type::type_of);
    let mut checked = 0;
    let mut cut = 0;
    for dump in Dump::all("archive").expect("the dumps read") {
        let Some(analysis) = dump.analysis("ArchiveAnalysis") else {
            continue;
        };
        let Some(observable) = sample(&harness, &dump) else {
            continue;
        };
        let outcome = harness
            .run_parser(observable.expect("the sample loads"))
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let Outcome::Done(result) = outcome else {
            continue;
        };
        let ours: BTreeMap<&str, (String, u64)> = result
            .files
            .iter()
            .map(|f| (f.path.as_str(), (f.sha256.to_hex(), f.size)))
            .collect();
        for theirs in analysis["observables"].as_array().into_iter().flatten() {
            let path = theirs["file_path"].as_str().expect("a file path");
            let Some((sha256, size)) = ours.get(path) else {
                // the ACE archive is the one format ace-rs doesn't open
                assert!(dump.name.ends_with(".ace"), "{}: no {path}", dump.name);
                continue;
            };
            if theirs["size"].as_u64() == Some(0) && *size > 0 {
                assert!(
                    dump.name.ends_with("test.jar"),
                    "{}: {path} is empty in ace3",
                    dump.name
                );
                cut += 1;
                continue;
            }
            assert_eq!(
                Some(sha256.as_str()),
                theirs["value"].as_str(),
                "{}: {path}",
                dump.name
            );
            assert_eq!(
                Some(*size),
                theirs["size"].as_u64(),
                "{}: {path}",
                dump.name
            );
            checked += 1;
        }
    }
    println!(
        "{checked} files matched ace3's by path, size and sha256; {cut} were empty in ace3 for a bad CRC"
    );
    assert!(checked >= 80, "only {checked} files checked");
    assert_eq!(
        cut, 19,
        "test.jar's entries with a bad CRC that ace3 extracted"
    );
}
