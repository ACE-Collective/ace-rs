//! PLAN.md 1.25 and 1.26: the email module against ace3's reference dumps for its email
//! fixtures. Every difference is listed and explained in differences.md, next to this file.

use std::path::Path;

use ace_mod_email::EmailAnalyzer;
use ace_testkit::Harness;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let harness = Harness::<EmailAnalyzer>::new().expect("harness");
    let mut compared = Vec::new();
    let mut skipped = Vec::new();
    for dump in Dump::all("email_analyzer").expect("the dumps read") {
        let sample = dump.sample().expect("an email dump analyzed a file");
        let mut observable = match harness.sample(sample) {
            Ok(observable) => observable,
            // samples/local/ is git-ignored, so CI doesn't have it
            Err(e) if sample.starts_with("local/") => {
                eprintln!("skipping {}: {e}", dump.name);
                skipped.push(dump.name.clone());
                continue;
            }
            Err(e) => panic!("{}: {e}", dump.name),
        };
        // the core gives a file the mime type libmagic finds (PLAN.md 1.7 and 2.5); ace3's
        // file_type module found the same one
        if let Some(file) = observable.file.as_mut() {
            file.mime_type = dump.mime_type().map(str::to_owned);
        }
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let differences = diff(&dump.normal_form("EmailAnalysis"), &normal_form(&outcome));
        compared.push((dump.name.clone(), differences));
    }
    assert!(
        compared.len() >= 17,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &skipped) {
        panic!("{report}");
    }
}
