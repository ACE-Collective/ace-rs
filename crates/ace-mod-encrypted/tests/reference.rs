//! PLAN.md 7.5 batch 7: the encrypted attachment modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps encrypted` from `tools/ace3/dumps/fixtures/encrypted`, which
//! `tools/samples/make-encrypted-files` writes, and the samples the modules take. A dump of a file
//! attached to an email holds the body parts ace3's email module wrote, which the test gives the
//! module as the carrying email's. Every difference is listed and explained in differences.md, next to this
//! file.

use std::path::{Path, PathBuf};

use ace_mod_encrypted::{PdfEncryptionAnalyzer, RarEncryptionAnalyzer, ZipEncryptionAnalyzer};
use ace_sdk::{CarryingEmail, EmailBodyPart, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/encrypted")
}

/// The file a dump analyzed: a fixture, labelled `fixtures/encrypted/<folder>/<name>...`, or a
/// sample.
fn local_file(dump: &Dump) -> PathBuf {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    match label.strip_prefix("fixtures/encrypted/") {
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

/// The email ace3 found from the file, as the core gives it to the module.
fn carrying_email(dump: &Dump, dir: &Path) -> CarryingEmail {
    let input = &dump.value["input"];
    let Some(carried) = input.get("carrying_email") else {
        return CarryingEmail::Absent;
    };
    if carried.is_null() {
        return CarryingEmail::Absent;
    }
    use base64::Engine;
    let mut parts = Vec::new();
    for (index, part) in carried["parts"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(part["body"].as_str().expect("a body"))
            .expect("base64");
        let path = dir.join(format!("email_body.{index}"));
        std::fs::write(&path, bytes).expect("written");
        parts.push(EmailBodyPart {
            path,
            html: part["html"].as_bool().expect("html or not"),
        });
    }
    if parts.is_empty() {
        CarryingEmail::NoBody
    } else {
        CarryingEmail::Parts(parts)
    }
}

/// pikepdf's copy of a PDF has a second `/ID` from the clock, the port's one from the content.
/// run_module.py keeps the sha256 the copy has with the port's `/ID`, after checking that nothing else
/// in it differs from `save(deterministic_id=True)`'s; that's the sha256 compared.
fn with_deterministic_id(mut form: Value, dump: &Dump, class: &str) -> Value {
    let Some(hashes) = dump
        .analysis(class)
        .and_then(|a| a.get("deterministic_id_sha256"))
        .and_then(Value::as_object)
    else {
        return form;
    };
    for (path, sha256) in hashes {
        if let Some(slot) = form.pointer_mut(&format!("/observables/file:{path}/sha256"))
            && sha256.is_string()
        {
            *slot = sha256.clone();
        }
    }
    form
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    view: Option<(&str, &str)>,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let dir = tempfile::tempdir().expect("a directory");
        let harness = Harness::<M>::new()
            .map(|h| h.with_typer(ace_mod_files::file_type::type_of))
            .expect("harness")
            .carrying_email(carrying_email(&dump, dir.path()));
        let input = &dump.value["input"];
        let observable = harness
            .file(
                input["observable"]["file_path"].as_str().expect("a path"),
                local_file(&dump),
                &strings(&input["meta_tags"]),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let ace3 = with_deterministic_id(dump.normal_form(class), &dump, class);
        let differences = diff(&ace3, &normal_form(&outcome));
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
    let mut compared = compare::<ZipEncryptionAnalyzer>(
        "zip_encryption_analyzer",
        "ZipEncryptionAnalysis",
        Some(("zip/aes256.zip.right", "zip_encryption_aes256")),
    );
    compared.extend(compare::<RarEncryptionAnalyzer>(
        "rar_encryption_analyzer",
        "RarEncryptionAnalysis",
        Some(("rar/rar5_headers.rar.right", "rar_encryption_rar5_headers")),
    ));
    compared.extend(compare::<PdfEncryptionAnalyzer>(
        "pdf_encryption_analyzer",
        "PDFEncryptionAnalysis",
        Some(("pdf/aes_256.pdf.right", "pdf_encryption_aes_256")),
    ));
    assert!(
        compared.len() >= 70,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
