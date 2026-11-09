//! What the reference dumps don't show: settings that change the email module's output, run by
//! the harness.

use ace_mod_email::{EmailAnalyzer, RECIPIENT_WHITELIST, SENDER_WHITELIST};
use ace_results::ObservableKind;
use ace_results::types::email::EmailAnalysis;
use ace_sdk::Outcome;
use ace_sdk::lists::{Entry, ListSpec, MatchKind};
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

/// What ace3's `_file.whitelist()` leaves: the tag and the directive, nothing extracted, and no
/// details, under ace3's summary for a whitelisted email.
fn assert_whitelisted(outcome: &Outcome<EmailAnalysis>, tags: &[&str]) {
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(result.analyzed.tags, tags);
    assert_eq!(result.analyzed.directives, ["whitelisted"]);
    assert!(result.observables.is_empty() && result.files.is_empty());
    assert!(result.details.email.is_none());
    assert_eq!(
        result.summary.as_deref(),
        Some("Email Analysis: (whitelisted email)")
    );
}

#[test]
fn outbound_journaled_mail_is_whitelisted_when_scanning_inbound_only() {
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
    assert_whitelisted(&outcome, &["outbound_email", "whitelisted"]);
}

const PLAIN: &[u8] = b"From: Alice <Alice@Partner.Example>\n\
To: Bob <bob@company.com>, carol@company.com\n\
Subject: hello\n\
Message-ID: <plain@partner.example>\n\
\n\
body\n";

fn entry(id: i64, kind: MatchKind, value: &str, ignore_case: bool) -> Entry {
    Entry {
        id,
        kind,
        value: value.to_owned(),
        ignore_case,
        observable_type: None,
        expires_at: None,
    }
}

fn run_with(spec: &ListSpec, entries: Vec<Entry>) -> Outcome<EmailAnalysis> {
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        )
        .list(spec, entries);
    let email = harness
        .file_bytes("email.rfc822", PLAIN, &[])
        .expect("fixture");
    harness.run_parser(email).expect("runs")
}

/// ace3's `smtp_from` and `smtp_to` keys: an entry that matches the From address, or any To address,
/// whitelists the email. ace3's entries were case-blind substrings.
#[test]
fn a_whitelisted_sender_or_recipient_whitelists_the_email() {
    let ace3_style = |value| entry(1, MatchKind::Substring, value, true);
    assert_whitelisted(
        &run_with(&SENDER_WHITELIST, vec![ace3_style("@partner.example")]),
        &["whitelisted"],
    );
    assert_whitelisted(
        &run_with(&RECIPIENT_WHITELIST, vec![ace3_style("CAROL@")]),
        &["whitelisted"],
    );
    assert_whitelisted(
        &run_with(
            &SENDER_WHITELIST,
            vec![entry(
                2,
                MatchKind::Regex,
                r"^alice@partner\.example$",
                true,
            )],
        ),
        &["whitelisted"],
    );
    assert_whitelisted(
        &run_with(
            &RECIPIENT_WHITELIST,
            vec![entry(3, MatchKind::Exact, "bob@company.com", false)],
        ),
        &["whitelisted"],
    );
}

#[test]
fn an_entry_that_doesnt_match_leaves_the_email_alone() {
    for (spec, entries) in [
        // the sender list isn't read for recipients, nor the other way round
        (
            &SENDER_WHITELIST,
            vec![entry(1, MatchKind::Substring, "company.com", true)],
        ),
        (
            &RECIPIENT_WHITELIST,
            vec![entry(1, MatchKind::Substring, "partner", true)],
        ),
        // case kept
        (
            &SENDER_WHITELIST,
            vec![entry(1, MatchKind::Substring, "alice@partner", false)],
        ),
        (
            &SENDER_WHITELIST,
            vec![entry(1, MatchKind::Exact, "partner.example", true)],
        ),
    ] {
        let outcome = run_with(spec, entries);
        let Outcome::Done(result) = &outcome else {
            panic!("expected a result, got {outcome:?}");
        };
        assert!(result.details.email.is_some(), "{spec:?}");
        assert!(result.analyzed.directives.is_empty(), "{spec:?}");
    }
}

#[test]
fn an_expired_entry_whitelists_nothing() {
    let mut expired = entry(1, MatchKind::Substring, "partner.example", true);
    // the harness's clock is fixed at 2026-01-01
    expired.expires_at = Some("2025-12-31T23:59:59Z".parse().expect("a time"));
    let outcome = run_with(&SENDER_WHITELIST, vec![expired]);
    let Outcome::Done(result) = &outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert!(result.details.email.is_some());
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
