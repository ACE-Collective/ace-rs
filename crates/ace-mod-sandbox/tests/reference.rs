//! PLAN.md 7.5 batch 10: the sandbox modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps pdftotext exif qrcode ocr` from the samples and from
//! `tools/ace3/dumps/fixtures/images`, which `tools/samples/make-image-files` writes. The tools run as
//! plain processes (`ace_sdk::tools::LocalRunner`), the dev image's, which are the sandbox image's at
//! ace3's versions. Every difference is listed and explained in differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_sandbox::qrcode::QRCODE_FILTER;
use ace_mod_sandbox::{ExifAnalyzer, OcrAnalyzer, PdfTextAnalyzer, QrCodeAnalyzer};
use ace_sdk::Parser;
use ace_sdk::lists::{Entry, MatchKind};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures")
}

/// The file a dump analyzed: a fixture, labelled `fixtures/images/<name>...`, or a sample.
fn local_file(dump: &Dump) -> PathBuf {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    match label.strip_prefix("fixtures/") {
        Some(rest) => fixtures().join(rest.split(' ').next().expect("a name")),
        None => ace_testkit::samples_dir().join(label),
    }
}

fn strings(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect()
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    view: Option<(&str, &str)>,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let mut harness = Harness::<M>::new().expect("harness");
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        // the qrcode dumps with ace3's qrcode.filter matching the code's URL
        if dump.short_name().ends_with(".filtered") {
            harness = harness.list(
                &QRCODE_FILTER,
                vec![Entry {
                    id: 1,
                    kind: MatchKind::Regex,
                    value: r"emmetcrcs\.org".to_owned(),
                    ignore_case: true,
                    observable_type: None,
                    expires_at: None,
                }],
            );
        }
        let input = &dump.value["input"];
        let mut observable = harness
            .file(
                input["observable"]["file_path"].as_str().expect("a path"),
                local_file(&dump),
                &strings(&input["meta_tags"]),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        for directive in strings(&input["directives"]) {
            observable = observable.with_directive(directive);
        }
        // the core doesn't queue a module for an observable without its required directives
        let ace4 = if M::REQUIRED_DIRECTIVES
            .iter()
            .all(|d| observable.has_directive(d))
        {
            let outcome = harness
                .run_parser(observable)
                .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
            if let Some((name, fixture)) = view
                && dump.short_name() == name
            {
                // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
                ace_testkit::check_view_fixture(fixture, &outcome);
            }
            normal_form(&outcome)
        } else {
            serde_json::Value::Null
        };
        let differences = diff(&dump.normal_form(class), &ace4);
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
    let qr = "ace3/pdf/sample_pdf_with_qr_code.pdf";
    let mut compared = compare::<PdfTextAnalyzer>(
        "pdftotext",
        "PDFTextAnalysis",
        Some((qr, "pdftotext_qr_code_pdf")),
    );
    // its view's fixture is written by hand: ExifTool's dates are the run's
    compared.extend(compare::<ExifAnalyzer>("exif", "ExifAnalysis", None));
    compared.extend(compare::<QrCodeAnalyzer>(
        "qrcode",
        "QRCodeAnalysis",
        Some((qr, "qrcode_qr_code_pdf")),
    ));
    compared.extend(compare::<OcrAnalyzer>(
        "ocr",
        "OCRAnalysis",
        Some(("images/text_plain.png", "ocr_text_plain")),
    ));
    assert!(
        compared.len() >= 400,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
