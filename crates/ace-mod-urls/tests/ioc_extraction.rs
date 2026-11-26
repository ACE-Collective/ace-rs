//! ioc_extraction loads libmagic only for a task that looks for URLs: urlfinderlib describes the
//! file's re-fanged text, which the type step never saw, as ace3's does.

use std::path::{Path, PathBuf};

use ace_mod_urls::IocExtraction;
use ace_mod_urls::ioc_extraction::IocExtractionSettings;
use ace_sdk::{Module, Outcome};
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

fn report() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/iocs/report.txt")
}

/// A run on report.txt with these settings, from module init to result, and the bytes it read.
fn run(
    settings: serde_json::Value,
    database: Option<&Path>,
) -> (
    Result<Outcome<ace_results::types::ioc_extraction::IocExtractionAnalysis>, HarnessError>,
    u64,
) {
    ace_testkit::bytes_read_by(|| {
        let mut harness =
            Harness::<IocExtraction>::with_settings(settings.clone()).expect("harness");
        if let Some(database) = database {
            let parsed: IocExtractionSettings = serde_json::from_value(settings).expect("settings");
            let module = IocExtraction::init(&parsed).expect("init");
            harness = harness.with_module(module.with_database(database));
        }
        let observable = harness
            .file("report.txt", report(), &[])
            .expect("the fixture")
            .with_directive("extract_iocs");
        harness.run_parser(observable)
    })
}

fn iocs(outcome: &Outcome<ace_results::types::ioc_extraction::IocExtractionAnalysis>) -> usize {
    match outcome {
        Outcome::Done(result) => result.details.iocs.values().map(Vec::len).sum(),
        other => panic!("not done: {other:?}"),
    }
}

/// A task that looks for URLs loads libmagic over the database's mapping, and one that doesn't
/// loads none: neither reads the database, and only the first fails without it.
#[test]
fn no_task_reads_libmagics_database_and_only_one_looking_for_urls_loads_it() {
    let database = std::fs::metadata(ace_urlfinder::magic::DATABASE)
        .expect("the database")
        .len();
    let (outcome, read) = run(json!({ "urls": null }), None);
    let outcome = outcome.expect("runs");
    assert!(iocs(&outcome) > 0);
    assert!(read < database / 10, "{read} bytes read without urls");

    let (outcome, read) = run(json!({}), None);
    assert!(iocs(&outcome.expect("runs")) > 0);
    assert!(read < database / 10, "{read} bytes read with urls");

    let missing = Path::new("/nonexistent/magic.mgc");
    let (outcome, _) = run(json!({ "urls": null }), Some(missing));
    assert!(iocs(&outcome.expect("runs")) > 0);
    match run(json!({}), Some(missing)).0 {
        Err(HarnessError::Module(e)) => {
            assert!(e.to_string().contains("/nonexistent/magic.mgc"), "{e}")
        }
        other => panic!("{other:?}"),
    }
}
