//! PLAN.md 1.26 beyond the reference dumps: names from inside an email stay inside the alert,
//! and a part that can't be extracted is recorded while the rest still are.

use ace_mod_email::EmailAnalyzer;
use ace_sdk::Outcome;
use ace_testkit::Harness;

const HOSTILE_NAMES: &[u8] = b"From: a@example.com\n\
To: b@example.com\n\
Subject: names\n\
Message-ID: <names@example.com>\n\
MIME-Version: 1.0\n\
Content-Type: multipart/mixed; boundary=\"b\"\n\
\n\
--b\n\
Content-Type: text/plain\n\
\n\
body\n\
--b\n\
Content-Type: application/octet-stream\n\
Content-Disposition: attachment; filename=\"../../etc/passwd\"\n\
Content-Transfer-Encoding: base64\n\
\n\
cm9vdDp4OjA6MDo=\n\
--b\n\
Content-Type: application/octet-stream\n\
Content-Disposition: attachment; filename=\"email.rfc822\"\n\
\n\
same name as the email\n\
--b--\n";

#[test]
fn hostile_names_are_cleaned_and_taken_names_get_suffixes() {
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let email = harness
        .file_bytes("email.rfc822", HOSTILE_NAMES, &[])
        .expect("fixture");
    let Outcome::Done(result) = harness.run_parser(email).expect("runs") else {
        panic!("expected a result");
    };
    let paths: Vec<&str> = result.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "email.rfc822.unknown_text_plain_000.txt",
            "_/_/etc/passwd",
            "email_000.rfc822",
            "email.rfc822.headers",
            "email.rfc822.combined",
        ]
    );
    let passwd = &result.files[1];
    assert_eq!(harness.read_output(passwd).expect("reads"), b"root:x:0:0:");
    assert_eq!(passwd.yara_meta[0].as_str(), "type=email.attachment");
    assert_eq!(passwd.directives, ["extract_urls", "render"]);
    assert_eq!(result.files[0].directives, ["extract_urls", "preview"]);
    let headers = &result.files[3];
    assert_eq!(headers.exclude_modules, ["email_analyzer"]);
    assert_eq!(headers.yara_meta[0].as_str(), "type=email.headers");
    // the combined file is the headers, then each unnamed part
    let combined = harness.read_output(&result.files[4]).expect("reads");
    assert!(
        combined.ends_with(b"\n\nbody\n\n"),
        "{:?}",
        String::from_utf8_lossy(&combined)
    );
}
