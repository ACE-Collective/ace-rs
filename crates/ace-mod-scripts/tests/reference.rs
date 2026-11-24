//! PLAN.md 7.5 batch 6: the RTF and script modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps scripts` from `tools/ace3/dumps/fixtures/scripts`, which
//! `tools/samples/make-scripts` writes, and the samples the modules take. Every difference is
//! listed and explained in differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_scripts::{
    ExtractedRtfAnalyzer, MicrosoftScriptEncodingAnalyzer, NoWhiteSpaceAnalyzer, VbScriptAnalyzer,
};
use ace_sdk::{Observable, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/scripts")
}

/// The file a dump analyzed: a fixture, labelled `fixtures/scripts/<folder>/<name>...`, or a sample.
fn local_file(dump: &Dump) -> PathBuf {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    match label.strip_prefix("fixtures/scripts/") {
        Some(rest) => fixtures().join(rest.split(' ').next().expect("a name")),
        None => ace_testkit::samples_dir().join(label),
    }
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// The dump's file, with its directives and `yara_meta` types.
fn input<M: Parser>(harness: &Harness<M>, dump: &Dump) -> Observable {
    let input = &dump.value["input"];
    let mut observable = harness
        .file(
            input["observable"]["file_path"].as_str().expect("a path"),
            local_file(dump),
            &strings(&input["meta_tags"]),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
    for directive in strings(&input["directives"]) {
        observable = observable.with_directive(directive);
    }
    observable
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    view: Option<(&str, &str)>,
    skipped: &mut Vec<String>,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        // samples/local/ is git-ignored, so CI doesn't have it
        let local = local_file(&dump);
        if !local.exists() && dump.sample().is_some_and(|s| s.starts_with("local/")) {
            eprintln!("skipping {}: {} isn't here", dump.name, local.display());
            skipped.push(format!("{module}/{}", dump.short_name()));
            continue;
        }
        let mut harness = Harness::<M>::new()
            .expect("harness")
            .with_typer(ace_mod_files::file_type::type_of);
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        // rtfole's tag on what it writes: ace-rs's core says rtfole's result added the file
        if strings(&dump.value["input"]["tags"]).contains(&"extracted_rtf") {
            harness = harness.added_by(&["rtfole"]);
        }
        let observable = input(&harness, &dump);
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
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
    let mut skipped = Vec::new();
    let mut compared = compare::<MicrosoftScriptEncodingAnalyzer>(
        "microsoft_script_encoding_analysis",
        "MicrosoftScriptEncodingAnalysis",
        Some(("mse/invoice.vbe", "mse_invoice_vbe")),
        &mut skipped,
    );
    compared.extend(compare::<VbScriptAnalyzer>(
        "vbscript_analyzer",
        "VBScriptAnalysis",
        Some(("vbs/many_same.vbs", "vbscript_many_same")),
        &mut skipped,
    ));
    compared.extend(compare::<NoWhiteSpaceAnalyzer>(
        "nowhitespace_analyzer",
        "NoWhiteSpaceAnalysis",
        Some(("rtf/spaced.rtf", "nowhitespace_spaced")),
        &mut skipped,
    ));
    compared.extend(compare::<ExtractedRtfAnalyzer>(
        "extracted_rtf_analyzer",
        "ExtractedRTFAnalysis",
        Some(("extracted/payload.exe", "extracted_rtf_payload")),
        &mut skipped,
    ));
    // the dumps found, compared or skipped for a sample this checkout doesn't have
    assert!(
        compared.len() + skipped.len() >= 75,
        "only {} dumps compared and {} skipped",
        compared.len(),
        skipped.len()
    );
    if let Err(report) = listed.check(&compared, &skipped) {
        panic!("{report}");
    }
}

/// The decoder's output for each file in `ACE_RS_MSE_DIR`, one JSON line each: the file's name, and
/// the sha256 and length of what it printed or the message it died with, for a comparison with
/// `bin/jscript.decode.pl` itself (`docs/measurements/scripts.md`).
#[test]
#[ignore = "a comparison, with files a script writes"]
fn decoder_outputs() {
    let dir = std::env::var("ACE_RS_MSE_DIR").expect("ACE_RS_MSE_DIR");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    for name in names {
        let data = std::fs::read(format!("{dir}/{name}")).expect("the file");
        let line = match ace_mod_scripts::mse::decode(&data) {
            Ok(out) => serde_json::json!({"name": name, "stdout": hex_sha256(&out), "stderr": ""}),
            Err(e) => {
                serde_json::json!({"name": name, "stdout": hex_sha256(b""), "stderr": e.message()})
            }
        };
        println!("{line}");
    }
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
