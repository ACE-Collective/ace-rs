//! PLAN.md 7.5 batches 10 to 12: the sandbox modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps pdftotext exif qrcode ocr` from the samples and from
//! `tools/ace3/dumps/fixtures/images`, which `tools/samples/make-image-files` writes, and by
//! `make-dumps java_class_decompiler upx autoit de4dot ilspy` from the executable samples, which
//! `tools/samples/make-executables` writes (those under `samples/local/` are git-ignored, and their
//! dumps are skipped where the sample isn't there), and by `make-dumps dmg_analyzer
//! cve_2021_30657_analyzer` from the DMGs `tools/samples/make-macos-images` writes. The tools run as
//! plain processes (`ace_sdk::tools::LocalRunner`), the dev image's, which are the sandbox image's at
//! ace3's versions. Every difference is listed and explained in differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_sandbox::qrcode::QRCODE_FILTER;
use ace_mod_sandbox::{
    AutoItAnalyzer, Cve202130657Analyzer, De4dotAnalyzer, DmgAnalyzer, ExifAnalyzer, IlspyAnalyzer,
    JavaClassDecompiler, OcrAnalyzer, PdfTextAnalyzer, QrCodeAnalyzer, UpxAnalyzer,
};
use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::lists::{Entry, MatchKind};
use ace_sdk::{Outcome, Parser};
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
        if !local_file(&dump).exists() {
            // a git-ignored sample this checkout doesn't have
            continue;
        }
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

/// The CVE module's dumps: each DMG through ace4's dmg_analyzer, and the image it adds, which
/// dmg_analyzer added and which redirects to the DMG, through the CVE module, as the core would
/// queue it.
fn compare_cve(view: (&str, &str)) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all("cve_2021_30657_analyzer").expect("the dumps read") {
        let dmg = Harness::<DmgAnalyzer>::new().expect("harness");
        let label = dump.value["input"]["label"].as_str().expect("a label");
        let observable = dmg.sample(label).expect("the sample");
        let image = match dmg
            .run_parser(observable.clone())
            .expect("dmg_analyzer runs")
        {
            Outcome::Done(result) => result.files.into_iter().next(),
            _ => None,
        };
        let ace4 = match image {
            Some(image) => {
                let harness = Harness::<Cve202130657Analyzer>::new()
                    .expect("harness")
                    .added_by(&["dmg_analyzer"]);
                let bytes = dmg.read_output(&image).expect("the image");
                let mut img = harness
                    .file_bytes(image.path.as_str(), &bytes, &["type=archive.dmg"])
                    .expect("the image");
                img.redirection = Some(ObservableRef::new(ObservableKind::File, &observable.value));
                let outcome = harness
                    .run_parser(img)
                    .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
                if dump.short_name() == view.0 {
                    ace_testkit::check_view_fixture(view.1, &outcome);
                }
                normal_form(&outcome)
            }
            None => serde_json::Value::Null,
        };
        let differences = diff(&dump.normal_form("CVE_2021_30657_Analysis"), &ace4);
        compared.push((
            format!("cve_2021_30657_analyzer/{}", dump.short_name()),
            differences,
        ));
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
    let qr_dumps = compared.len();
    // PLAN.md 7.5 batch 11
    let class = "ace3/executables/VxUGJsAplRNavewkjKujp.class";
    compared.extend(compare::<JavaClassDecompiler>(
        "java_class_decompiler",
        "JavaClassDecompilerAnalysis",
        Some((class, "java_class_decompiler_class")),
    ));
    compared.extend(compare::<UpxAnalyzer>(
        "upx",
        "UPXAnalysis",
        Some(("ace3/executables/cmd-upx.exe", "upx_cmd_upx")),
    ));
    compared.extend(compare::<AutoItAnalyzer>(
        "autoit",
        "AutoItAnalysis",
        Some(("ace3/executables/hello_autoit.exe", "autoit_hello_autoit")),
    ));
    // its view's fixture is written by hand: de4dot prints the path it was given, the harness's
    compared.extend(compare::<De4dotAnalyzer>("de4dot", "De4dotAnalysis", None));
    compared.extend(compare::<IlspyAnalyzer>(
        "ilspy",
        "IlspyAnalysis",
        Some(("ace4/executables/hello_dotnet.dll", "ilspy_hello_dotnet")),
    ));
    assert!(
        compared.len() - qr_dumps >= 5 * 10,
        "only {} executable dumps compared",
        compared.len() - qr_dumps
    );
    // PLAN.md 7.5 batch 12; dmg_analyzer's view fixture is written by hand, since dmg2img prints the
    // path it was given, the checkout's
    let before = compared.len();
    compared.extend(compare::<DmgAnalyzer>("dmg_analyzer", "DMGAnalysis", None));
    compared.extend(compare_cve((
        "ace4/macos/script_app.dmg",
        "cve_2021_30657_analyzer_script_app",
    )));
    assert!(
        compared.len() - before >= 2 * 10,
        "only {} DMG dumps compared",
        compared.len() - before
    );
    assert!(qr_dumps >= 400, "only {} dumps compared", qr_dumps);
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
