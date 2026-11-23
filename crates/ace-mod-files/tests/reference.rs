//! PLAN.md 7.5 batch 2: the file identity modules against ace3's reference dumps, made from
//! `tools/ace3/dumps/fixtures/files`. Every difference is listed and explained in
//! differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_files::file_type::as_ace3;
use ace_mod_files::{
    BinaryFileAnalyzer, DHashImageAnalyzer, FileHashAnalyzer, FileType, LnkParseAnalyzer,
    SsdeepAnalyzer, X509Analyzer,
};
use ace_sdk::{Outcome, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/files")
}

/// The file a dump analyzed and its alert path: a fixture, labelled
/// `fixtures/files/<name> as <alert path>`, or a sample, labelled by its path under `samples/`.
fn file_of(dump: &Dump) -> (PathBuf, String) {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    if let Some(rest) = label.strip_prefix("fixtures/ssdeep/") {
        let name = rest.split(' ').next().expect("a name");
        return (fixtures().join("../ssdeep").join(name), name.to_owned());
    }
    if let Some(rest) = label.strip_prefix("fixtures/dhash/images/") {
        let name = rest.split(' ').next().expect("a name");
        return (
            fixtures().join("../dhash/images").join(name),
            name.to_owned(),
        );
    }
    match label.strip_prefix("fixtures/files/") {
        Some(rest) => {
            let (name, alert_path) = rest.split_once(" as ").expect("its alert path");
            (fixtures().join(name), alert_path.to_owned())
        }
        None => {
            let alert_path = dump.value["input"]["observable"]["file_path"]
                .as_str()
                .expect("a file path");
            (
                ace_testkit::samples_dir().join(label),
                alert_path.to_owned(),
            )
        }
    }
}

/// Runs file_type, the type step, and turns what it found into ace3's result for the dump's path.
fn compare_file_type() -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all("file_type").expect("the dumps read") {
        let harness = Harness::<FileType>::new()
            .map(|h| h.with_typer(ace_mod_files::file_type::type_of))
            .expect("harness");
        let (fixture, alert_path) = file_of(&dump);
        let observable = harness
            .file(&alert_path, &fixture, &[])
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let Outcome::Done(facts) = outcome else {
            panic!("{}: the type step found nothing", dump.name);
        };
        let outcome = Outcome::Done(as_ace3(&facts.details, &alert_path));
        if dump.short_name() == "script.js" {
            // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
            ace_testkit::check_view_fixture("file_type_script_js", &outcome);
        }
        let differences = diff(
            &dump.normal_form("FileTypeAnalysis"),
            &normal_form(&outcome),
        );
        compared.push((format!("file_type/{}", dump.short_name()), differences));
    }
    compared
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    view: Option<(&str, &str)>,
) -> Vec<(String, Vec<Difference>)> {
    compare_with::<M>(module, class, view, serde_json::Value::Null)
}

fn compare_with<M: Parser>(
    module: &str,
    class: &str,
    view: Option<(&str, &str)>,
    settings: serde_json::Value,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let mut harness = if settings.is_null() {
            Harness::<M>::new().map(|h| h.with_typer(ace_mod_files::file_type::type_of))
        } else {
            Harness::<M>::with_settings(settings.clone())
                .map(|h| h.with_typer(ace_mod_files::file_type::type_of))
        }
        .expect("harness");
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        let (fixture, alert_path) = file_of(&dump);
        let tags: Vec<&str> = dump.value["input"]["meta_tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str())
            .collect();
        let mut observable = harness
            .file(&alert_path, &fixture, &tags)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        for directive in dump.value["input"]["directives"]
            .as_array()
            .into_iter()
            .flatten()
        {
            observable = observable.with_directive(directive.as_str().expect("a directive"));
        }
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let differences = diff(&dump.normal_form(class), &normal_form(&outcome));
        compared.push((format!("{module}/{}", dump.short_name()), differences));
    }
    compared
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = compare_file_type();
    compared.extend(compare::<FileHashAnalyzer>(
        "file_hash_analyzer",
        "FileHashAnalysis",
        Some(("notes.zip", "file_hash_notes_zip")),
    ));
    compared.extend(compare::<BinaryFileAnalyzer>(
        "binary_file_analyzer",
        "BinaryFileAnalysis",
        Some(("nul.rtf", "binary_nul_rtf")),
    ));
    compared.extend(compare::<LnkParseAnalyzer>(
        "lnk_parser",
        "LnkParseAnalysis",
        Some(("ace-rs/lnk/shortcut.lnk", "lnk_shortcut")),
    ));
    compared.extend(compare::<X509Analyzer>(
        "x509_analyzer",
        "X509Analysis",
        Some(("ace-rs/x509/cert.pem", "x509_cert_pem")),
    ));
    compared.extend(compare_with::<DHashImageAnalyzer>(
        "dhash",
        "DHashImageAnalysis",
        Some(("brand.jpg", "dhash_brand_jpg")),
        serde_json::json!({"source_dir": fixtures().join("../dhash/analyst_data/dhash")}),
    ));
    // ace3's threshold, and 1, which keeps every match ssdeep prints
    let hashes = fixtures().join("../ssdeep/known_hashes");
    for (threshold, suffix) in [(90, false), (1, true)] {
        let mut runs = compare_with::<SsdeepAnalyzer>(
            "ssdeep",
            "SsdeepAnalysis",
            (!suffix).then_some(("edited_little", "ssdeep_edited_little")),
            serde_json::json!({"ssdeep_hashes": hashes, "ssdeep_match_threshold": threshold}),
        );
        runs.retain(|(name, _)| name.ends_with(".threshold_1") == suffix);
        compared.extend(runs);
    }
    assert!(
        compared.len() >= 100,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
