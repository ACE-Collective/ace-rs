//! What the reference dumps don't show: Office documents, gzip, files that aren't archives, and
//! settings.

use std::io::Write;

use ace_mod_archive::ArchiveAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::Outcome;
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

#[test]
fn an_office_document_is_extracted_whole_and_its_parts_redirect_to_it() {
    let harness = Harness::<ArchiveAnalyzer>::new().expect("harness");
    let docx = harness
        .sample("ace3/office/doc.docx")
        .expect("an ace3 sample");
    let sha256 = docx.value.clone();
    let Outcome::Done(result) = harness.run_parser(docx).expect("runs") else {
        panic!("expected a result");
    };
    // more than max_file_count, because an Office document isn't limited
    assert!(result.files.len() > 6, "{} files", result.files.len());
    assert_eq!(result.details.extracted_files.len(), result.files.len());
    for file in &result.files {
        let redirection = file.redirection.as_ref().expect("a redirection");
        assert_eq!(
            (redirection.kind, redirection.value.as_str()),
            (ObservableKind::File, sha256.as_str())
        );
        let xml = file.name().ends_with(".xml") || file.name().ends_with(".rels");
        assert_eq!(
            file.directives.contains(&"extract_urls".to_owned()),
            xml,
            "{}",
            file.path
        );
    }
    assert!(result.tags.is_empty());
}

#[test]
fn a_gzip_stream_is_one_file_under_its_original_name() {
    let mut encoder = flate2::GzBuilder::new()
        .filename("payload.js")
        .write(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"WScript.Echo(1)").expect("compresses");
    let gz = encoder.finish().expect("finishes");
    let harness = Harness::<ArchiveAnalyzer>::new().expect("harness");
    let file = harness
        .file_bytes("invoice.gz", &gz, &["type=email.attachment"])
        .expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("runs") else {
        panic!("expected a result");
    };
    let [file] = result.files.as_slice() else {
        panic!("expected one file, got {:?}", result.files);
    };
    assert_eq!(file.path.as_str(), "invoice.gz.extracted/payload.js");
    assert_eq!(
        harness.read_output(file).expect("reads"),
        b"WScript.Echo(1)"
    );
    assert_eq!(file.directives, ["sandbox"]);
    assert_eq!(
        file.detections[0].description,
        "An archive contained a single file that was a script"
    );
    assert_eq!(result.tags, ["single_file_zip", "script_in_zip"]);
    assert_eq!(
        result.summary.as_deref(),
        Some("Archive Analysis: extracted 1 of 1 files: (payload.js)")
    );
}

#[test]
fn files_that_arent_archives_are_skipped() {
    let harness = Harness::<ArchiveAnalyzer>::new().expect("harness");
    for (path, bytes) in [
        ("notes.txt", &b"just text"[..]),
        // an OLE document is the Office modules' business
        ("macro.doc", &b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest"[..]),
        // an email's parts are the email module's business
        (
            "email.rfc822.unknown_application_zip_000.zip",
            &b"PK\x03\x04"[..],
        ),
    ] {
        let file = harness.file_bytes(path, bytes, &[]).expect("fixture");
        let outcome = harness.run_parser(file).expect("runs");
        assert!(
            matches!(outcome, Outcome::Skipped(_)),
            "{path}: {outcome:?}"
        );
    }
}

#[test]
fn unknown_settings_keys_fail() {
    let err = Harness::<ArchiveAnalyzer>::with_settings(json!({"max_files": 3}))
        .err()
        .expect("an unknown key fails");
    assert!(matches!(err, HarnessError::Settings(_)), "{err}");
}
