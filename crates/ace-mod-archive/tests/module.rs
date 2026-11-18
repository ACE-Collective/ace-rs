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
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
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
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
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
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
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

/// A zip of one member, encrypted as `options` says, holding `b"the payload"`.
fn encrypted_zip(name: &str, options: zip::write::SimpleFileOptions) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer.start_file(name, options).expect("starts");
    writer.write_all(b"the payload").expect("writes");
    writer.finish().expect("finishes").into_inner()
}

/// A ZipCrypto member that the archive module's password, `infected`, doesn't open. ZipCrypto's
/// header is random and checks a password by one byte, so about one write in 256 takes a wrong
/// password too, which then decrypts to garbage; this writes again until `infected` is refused.
fn refusing_zipcrypto_zip(name: &str) -> Vec<u8> {
    for _ in 0..64 {
        let bytes = encrypted_zip(name, zipcrypto(b"Secr3tPw"));
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice())).expect("reads");
        if matches!(
            archive.by_index_decrypt(0, b"infected"),
            Err(zip::result::ZipError::InvalidPassword)
        ) {
            return bytes;
        }
    }
    panic!("64 ZipCrypto headers in a row took the wrong password");
}

fn zipcrypto(password: &'static [u8]) -> zip::write::SimpleFileOptions {
    use zip::unstable::write::FileOptionsExt as _;
    zip::write::SimpleFileOptions::default()
        .with_deprecated_encryption(password)
        .expect("a password")
}

fn aes(password: &'static str) -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, password)
}

/// ace3's `7z -pinfected` leaves an empty file for a zip member that password doesn't open, and
/// ace3 lists it as extracted. That file's name still decides the single-file tags and detections.
#[test]
fn a_zip_member_the_password_doesnt_open_is_written_empty_as_7z_leaves_it() {
    for bytes in [
        refusing_zipcrypto_zip("invoice.txt"),
        encrypted_zip("invoice.txt", aes("Secr3tPw")),
    ] {
        let harness = Harness::<ArchiveAnalyzer>::new()
            .expect("harness")
            .with_typer(ace_mod_files::file_type::type_of);
        let file = harness.file_bytes("a.zip", &bytes, &[]).expect("fixture");
        let Outcome::Done(result) = harness.run_parser(file).expect("runs") else {
            panic!("expected a result");
        };
        assert_eq!(result.details.extracted_files, ["invoice.txt"]);
        assert_eq!(result.tags, ["single_file_zip"]);
        let [file] = result.files.as_slice() else {
            panic!("expected one file, got {:?}", result.files);
        };
        assert_eq!(harness.read_output(file).expect("reads"), b"");
        assert_eq!(file.directives, ["sandbox"]);
        assert!(file.detections.is_empty(), "{:?}", file.detections);
    }

    let bytes = refusing_zipcrypto_zip("evil.exe");
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
    let file = harness.file_bytes("a.zip", &bytes, &[]).expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("runs") else {
        panic!("expected a result");
    };
    assert_eq!(result.tags, ["single_file_zip", "exe_in_zip"]);
    assert_eq!(
        result.files[0].detections[0].description,
        "An archive contained a single file that was an executable"
    );
}

#[test]
fn a_zip_member_the_password_opens_keeps_its_bytes() {
    for bytes in [
        encrypted_zip("invoice.txt", zipcrypto(b"infected")),
        encrypted_zip("invoice.txt", aes("infected")),
    ] {
        let harness = Harness::<ArchiveAnalyzer>::new()
            .expect("harness")
            .with_typer(ace_mod_files::file_type::type_of);
        let file = harness.file_bytes("a.zip", &bytes, &[]).expect("fixture");
        let Outcome::Done(result) = harness.run_parser(file).expect("runs") else {
            panic!("expected a result");
        };
        assert_eq!(
            harness.read_output(&result.files[0]).expect("reads"),
            b"the payload"
        );
    }
}

/// 7z leaves nothing for a 7z archive's member the password doesn't open (checked with 7-Zip 25.01,
/// ace3's), so here the member is counted and not extracted. This one's password is `Secr3t`.
#[test]
fn a_7z_member_the_password_doesnt_open_is_not_written() {
    let hex = "377abcaf271c0004641a7fdb100000000000000072000000000000009625bdcf46bef2e9eb630ff7160f7621d23d50a00104060001091000070b0100022406f1070112530f99994dced419c263c9fc0c40932166952121010001000c100c00080a017557db390000050119010011190069006e0076006f006900630065002e00740078007400000019020000140a01003978f3fc336edd01150601002080b6810000";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let harness = Harness::<ArchiveAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
    let file = harness.file_bytes("a.7z", &bytes, &[]).expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("runs") else {
        panic!("expected a result");
    };
    assert_eq!(result.details.file_count, 1);
    assert!(result.files.is_empty(), "{:?}", result.files);
}

#[test]
fn unknown_settings_keys_fail() {
    let err = Harness::<ArchiveAnalyzer>::with_settings(json!({"max_files": 3}))
        .err()
        .expect("an unknown key fails");
    assert!(matches!(err, HarnessError::Settings(_)), "{err}");
}
