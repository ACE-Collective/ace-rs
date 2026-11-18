//! What the reference dumps don't show: settings that change the email module's output, run by
//! the harness.

use ace_mod_email::EmailAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::Outcome;
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

fn has(
    outcome: &Outcome<ace_results::types::email::EmailAnalysis>,
    kind: ObservableKind,
    value: &str,
) -> bool {
    let Outcome::Done(result) = outcome else {
        return false;
    };
    result
        .observables
        .iter()
        .any(|o| o.kind == kind && o.value == value)
}

#[test]
fn a_spoof_of_a_local_domain_is_tagged_and_gets_deliveries() {
    let harness = Harness::<EmailAnalyzer>::with_settings(json!({
        "local_email_domains": ["company.com"],
    }))
    .expect("harness")
    .dependency_result(
        "file_type",
        ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
    );
    let email = harness
        .sample("ace3/email/direct_send_spoof.email.rfc822")
        .expect("sample");
    let outcome = harness.run_parser(email).expect("runs");
    let Outcome::Done(result) = &outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    let details = result.details.email.as_ref().expect("email details");
    assert!(details.mail_from_is_local);
    assert!(details.spoofed_internal);
    assert!(
        result
            .analyzed
            .tags
            .contains(&"spoofed_internal".to_owned())
    );
    let message_id = details.message_id.as_deref().expect("a message id").trim();
    assert!(has(
        &outcome,
        ObservableKind::EmailDelivery,
        &format!("{message_id}|user@company.com")
    ));
}

const OUTBOUND_JOURNAL_REPORT: &[u8] = b"From: journal@company.com\n\
To: archive@company.com\n\
Subject: journal report\n\
Message-ID: <report@company.com>\n\
X-MS-Exchange-Parent-Message-Id: <original@company.com>\n\
X-MS-Exchange-Organization-MessageDirectionality: Originating\n\
\n\
body\n";

/// ace3 8617ba8e: `scan_inbound_only` skips the email analysis of an outbound journaled message and
/// nothing else. The file gets its `outbound_email` tag, with no directive and nothing extracted; the
/// result has no details and no summary, and the modules that read it take it as no analysis.
#[test]
fn outbound_journaled_mail_skips_only_the_email_analysis_when_scanning_inbound_only() {
    let harness = Harness::<EmailAnalyzer>::with_settings(json!({"scan_inbound_only": true}))
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let email = harness
        .file_bytes("email.rfc822", OUTBOUND_JOURNAL_REPORT, &[])
        .expect("fixture")
        .with_directive("original_email");
    let outcome = harness.run_parser(email).expect("runs");
    let Outcome::Done(result) = &outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(result.analyzed.tags, ["outbound_email"]);
    assert!(result.analyzed.directives.is_empty());
    assert!(result.observables.is_empty() && result.files.is_empty());
    assert!(result.details.is_tag_only());
    assert_eq!(result.summary, None);
}

const PLAIN: &[u8] = b"From: Alice <Alice@Partner.Example>\n\
To: Bob <bob@company.com>, carol@company.com\n\
Subject: hello\n\
Message-ID: <plain@partner.example>\n\
\n\
body\n";

/// ace3 removed its brotex whitelist (8617ba8e): the module reads no list, and any sender or recipient
/// is analyzed.
#[test]
fn no_sender_or_recipient_stops_the_analysis() {
    assert!(ace_mod_email::MANIFEST.lists.is_empty());
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let email = harness
        .file_bytes("email.rfc822", PLAIN, &[])
        .expect("fixture");
    let outcome = harness.run_parser(email).expect("runs");
    let Outcome::Done(result) = &outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert!(result.details.email.is_some());
    assert!(result.analyzed.tags.is_empty() && result.analyzed.directives.is_empty());
    assert!(has(
        &outcome,
        ObservableKind::EmailFrom,
        "alice@partner.example"
    ));
}

#[test]
fn an_outbound_exception_is_scanned_and_tagged() {
    let harness = Harness::<EmailAnalyzer>::with_settings(json!({
        "scan_inbound_only": true,
        "outbound_exceptions": ["Archive@Company.com"],
    }))
    .expect("harness")
    .dependency_result(
        "file_type",
        ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
    );
    let email = harness
        .file_bytes("email.rfc822", OUTBOUND_JOURNAL_REPORT, &[])
        .expect("fixture")
        .with_directive("original_email");
    let Outcome::Done(result) = harness.run_parser(email).expect("runs") else {
        panic!("expected a result");
    };
    assert_eq!(
        result.analyzed.tags,
        ["outbound_email", "outbound_email_exception"]
    );
}

#[test]
fn a_file_that_isnt_an_email_is_skipped() {
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("ASCII text", "text/plain"),
        );
    let notes = harness
        .file_bytes("notes.txt", b"just some notes\n", &[])
        .expect("fixture");
    let outcome = harness.run_parser(notes).expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
}

#[test]
fn without_file_type_s_result_nothing_runs() {
    let harness = Harness::<EmailAnalyzer>::new().expect("harness");
    let email = harness
        .file_bytes("email.rfc822", PLAIN, &[])
        .expect("fixture");
    let outcome = harness.run_parser(email).expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
}

#[test]
fn unknown_settings_keys_fail() {
    let err = Harness::<EmailAnalyzer>::with_settings(json!({"scan_inbound": true}))
        .err()
        .expect("an unknown key fails");
    assert!(matches!(err, HarnessError::Settings(_)), "{err}");
}
