//! What the reference dumps don't show: modifiers, disabled rules, tags, redirection and the
//! files the module skips. The rules are written to a temporary signature directory.

use ace_mod_yara::{YARA_RULE_MATCH, YaraScanner};
use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::Outcome;
use ace_testkit::Harness;
use serde_json::json;

const RULES: &str = r#"
rule plain { strings: $a = "EVIL" condition: $a }
rule tagged : whitelisted { strings: $a = "EVIL" condition: $a }
rule tagged_directs : whitelisted { meta: modifiers = "directive=preview" strings: $a = "EVIL" condition: $a }
rule qa_only { meta: modifiers = "qa,directive=never" strings: $a = "EVIL" condition: $a }
rule directs { meta: modifiers = "no_alert, directive=extract_urls" uuid = "a8f0c1d2-0000-4000-8000-000000000001" strings: $a = "EVIL" condition: $a }
rule disabled { meta: enabled = "false" strings: $a = "EVIL" condition: $a }
rule SIP_feed { strings: $sip_42 = "EVIL" condition: $sip_42 }
"#;

fn harness(dir: &tempfile::TempDir) -> Harness<YaraScanner> {
    let namespace = dir.path().join("fixture");
    std::fs::create_dir_all(&namespace).expect("a namespace");
    std::fs::write(namespace.join("rules.yar"), RULES).expect("rules");
    Harness::with_settings(json!({"signature_dir": dir.path()})).expect("the rules load")
}

#[test]
fn modifiers_tags_and_disabled_rules_act_as_in_ace3() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let harness = harness(&dir);
    let file = harness
        .file_bytes("payload.bin", b"xxEVILxx", &[])
        .expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("scans") else {
        panic!("expected a result");
    };
    let rules: Vec<&str> = result
        .details
        .scan_results
        .iter()
        .map(|r| r.rule.as_str())
        .collect();
    assert_eq!(
        rules,
        [
            "plain",
            "tagged",
            "tagged_directs",
            "qa_only",
            "directs",
            "SIP_feed"
        ]
    );
    // a QA rule adds no directives; a no_alert or whitelisted rule still adds its own (ace3
    // 91211a66), and the whitelisted tag is an ordinary tag, with no directive of its own (8617ba8e)
    assert_eq!(
        result.analyzed.directives,
        ["preview", "extract_urls", "sandbox"]
    );
    assert_eq!(result.analyzed.tags, ["whitelisted"]);
    // detections only for rules that may alert, under the built-in signature without a uuid: a rule
    // tagged whitelisted makes none, as no_alert, and doesn't keep the others from alerting
    let detected: Vec<&str> = result
        .analyzed
        .detections
        .iter()
        .map(|d| d.description.as_str())
        .collect();
    assert_eq!(
        detected,
        [
            "payload.bin matched yara rule plain",
            "payload.bin matched yara rule SIP_feed",
        ]
    );
    assert_eq!(
        result.analyzed.detections[0].signature_uuid.as_deref(),
        Some(YARA_RULE_MATCH)
    );
    assert_eq!(result.analyzed.detections[0].signature_family, None);
    let has = |kind, value: &str| {
        result
            .observables
            .iter()
            .any(|o| o.kind == kind && o.value == value)
    };
    assert!(has(ObservableKind::YaraRule, "directs"));
    assert!(has(
        ObservableKind::SignatureId,
        "a8f0c1d2-0000-4000-8000-000000000001"
    ));
    assert!(has(ObservableKind::YaraString, "plain:$a"));
    assert!(has(ObservableKind::Indicator, "sip:42"));
    let first = &result.details.scan_results[0];
    assert_eq!(first.strings[0].0, 2);
    assert_eq!(first.match_context[0].match_offset, 2);
    assert_eq!(first.match_context[0].data.as_slice(), b"xxEVILxx");
}

#[test]
fn a_redirected_part_sandboxes_what_it_redirects_to() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let harness = harness(&dir);
    let mut part = harness
        .file_bytes("doc.docx.extracted/word/document.xml", b"EVIL", &[])
        .expect("fixture");
    part.redirection = Some(ObservableRef::new(ObservableKind::File, "ab".repeat(32)));
    let Outcome::Done(result) = harness.run_parser(part).expect("scans") else {
        panic!("expected a result");
    };
    assert_eq!(result.redirected.directives, ["sandbox"]);
    assert!(!result.analyzed.directives.contains(&"sandbox".to_owned()));
}

#[test]
fn empty_files_no_scan_and_no_match_give_no_result() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let harness = harness(&dir);
    let empty = harness.file_bytes("empty.bin", b"", &[]).expect("fixture");
    let no_scan = harness
        .file_bytes("x.bin", b"EVIL", &[])
        .expect("fixture")
        .with_directive("no_scan");
    let clean = harness
        .file_bytes("clean.bin", b"nothing here", &[])
        .expect("fixture");
    for file in [empty, no_scan, clean] {
        let outcome = harness.run_parser(file).expect("runs");
        assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    }
}

/// PLAN.md 7.16: a matched `$obsd_<id>` string names an observable enabled for detection, which the
/// module adds, tagged with the rule, as ace3's scanner does from the detection's row. The rules are
/// the export's own (`ace_yara::export`), written as the namespace they are in a ruleset.
#[test]
fn a_matched_detection_adds_its_observable_tagged_with_the_rule() {
    use ace_yara::export::{self, Detection, ExportConfig};
    let config = ExportConfig {
        export_list: ["fqdn", "email_address", "url", "no_such_type", "file"]
            .map(str::to_owned)
            .to_vec(),
        ..ExportConfig::default()
    };
    let detection = |id, observable_type: &str, value: &str| Detection {
        id,
        observable_type: observable_type.to_owned(),
        value: value.to_owned(),
    };
    let ancestors = |kind: &str| {
        kind.parse::<ObservableKind>()
            .map(|k| k.ancestors().map(|a| a.as_str().to_owned()).collect())
            .unwrap_or_default()
    };
    let list = export::export_list(
        &config,
        &[
            detection(11, "fqdn", "evil.example.com"),
            // exported under email_address, and added as the type it is
            detection(12, "email_reply_to", "reply@evil.example.com"),
            detection(13, "url", "http://evil.example.com/a\"b"),
            // a type this binary doesn't have, and a file, which is its bytes: neither is added
            detection(14, "no_such_type", "unknown-typed-value"),
            detection(15, "file", &"ab".repeat(32)),
            detection(16, "fqdn", "absent.example.com"),
        ],
        ancestors,
    );
    let generated = export::generate(&config, &list, "11/15/2026");
    assert_eq!(generated.report.skipped, []);
    assert_eq!(generated.report.exported(), 6);

    let dir = tempfile::tempdir().expect("a temp dir");
    let namespace = dir.path().join(export::NAMESPACE);
    std::fs::create_dir_all(&namespace).expect("a namespace");
    for file in &generated.files {
        std::fs::write(namespace.join(&file.name), &file.source).expect("a rule file");
    }
    // a rule of the repository's own with an $obsd_ string resolves the same way, as in ace3
    let other = dir.path().join("fixture");
    std::fs::create_dir_all(&other).expect("a namespace");
    std::fs::write(
        other.join("own.yar"),
        "rule own { strings: $obsd_11 = \"sign in\" $obsd_999 = \"sign in\" condition: all of them }",
    )
    .expect("a rule file");
    let harness: Harness<YaraScanner> =
        Harness::with_settings(json!({"signature_dir": dir.path()})).expect("the rules load");

    let content = format!(
        "<a href=\"http://evil.example.com/a\"b\">sign in</a> reply@evil.example.com {} unknown-typed-value",
        "ab".repeat(32)
    );
    let file = harness
        .file_bytes("email.rfc822.headers", content.as_bytes(), &[])
        .expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("scans") else {
        panic!("expected a result");
    };
    let mut rules: Vec<&str> = result
        .details
        .scan_results
        .iter()
        .map(|r| r.rule.as_str())
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            "detect_email_address",
            "detect_file",
            "detect_fqdn",
            "detect_no_such_type",
            "detect_url",
            "own"
        ]
    );
    let tags_of = |kind, value: &str| {
        result
            .observables
            .iter()
            .find(|o| o.kind == kind && o.value == value)
            .map(|o| o.tags.clone())
    };
    // the fqdn was named by its own rule and by the repository's: one observable, both tags
    let mut fqdn = tags_of(ObservableKind::Fqdn, "evil.example.com").expect("the fqdn");
    fqdn.sort();
    assert_eq!(fqdn, ["detect_fqdn", "own"]);
    assert_eq!(
        tags_of(ObservableKind::EmailReplyTo, "reply@evil.example.com"),
        Some(vec!["detect_email_address".to_owned()])
    );
    assert_eq!(
        tags_of(ObservableKind::Url, "http://evil.example.com/a\"b"),
        Some(vec!["detect_url".to_owned()])
    );
    // the string that matched is still a yara_string observable, with its id in its name
    assert_eq!(
        tags_of(ObservableKind::YaraString, "detect_fqdn:$obsd_11"),
        Some(vec![])
    );
    // what isn't added: a detection that didn't match, an id the ruleset doesn't hold, a type this
    // binary doesn't have and a file
    assert_eq!(tags_of(ObservableKind::Fqdn, "absent.example.com"), None);
    assert!(
        !result
            .observables
            .iter()
            .any(|o| o.kind == ObservableKind::File || o.value == "unknown-typed-value"),
        "{:?}",
        result.observables
    );
    // each generated rule's match is a detection on the file, under ace3's built-in signature
    assert!(result.analyzed.detections.iter().any(|d| {
        d.description == "email.rfc822.headers matched yara rule detect_fqdn"
            && d.signature_uuid.as_deref() == Some(YARA_RULE_MATCH)
    }));
    assert!(
        result
            .details
            .scan_results
            .iter()
            .all(|r| r.rule == "own" || r.namespace == export::NAMESPACE)
    );
}

/// A rule file yara-x would overflow its stack on (`ace_yara::guard`) is left out when the pool loads a
/// signature directory, and the rest scan.
#[test]
fn a_rule_file_past_the_guard_s_bounds_is_left_out_and_the_rest_scan() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let namespace = dir.path().join("fixture");
    std::fs::create_dir_all(&namespace).expect("a namespace");
    std::fs::write(
        namespace.join("escapes.yar"),
        format!(
            "rule hostile {{ strings: $a = \"{}\" condition: $a }}",
            "\\\\".repeat(20_000)
        ),
    )
    .expect("rules");
    std::fs::write(
        namespace.join("nested.yar"),
        format!(
            "rule nested {{ condition: {}true{} }}",
            "(".repeat(20_000),
            ")".repeat(20_000)
        ),
    )
    .expect("rules");
    let harness = harness(&dir);
    let file = harness
        .file_bytes("payload.bin", b"xxEVILxx", &[])
        .expect("fixture");
    let Outcome::Done(result) = harness.run_parser(file).expect("scans") else {
        panic!("expected a result");
    };
    let rules: Vec<&str> = result
        .details
        .scan_results
        .iter()
        .map(|r| r.rule.as_str())
        .collect();
    assert_eq!(
        rules,
        [
            "plain",
            "tagged",
            "tagged_directs",
            "qa_only",
            "directs",
            "SIP_feed"
        ]
    );
}

/// A file the type step typed: its mime type comes with the task, so libmagic's database, which the
/// module maps before containment, goes unread.
#[test]
fn a_typed_file_reads_none_of_libmagics_database() {
    let database = std::fs::metadata(ace_yara::mime::DEFAULT_DATABASE)
        .expect("the database")
        .len();
    let dir = tempfile::tempdir().expect("a temp dir");
    let (outcome, read) = ace_testkit::bytes_read_by(|| {
        let harness = harness(&dir).with_typer(|_, _| {
            Some(ace_results::types::file_type::TypeFacts {
                mime: "application/octet-stream".to_owned(),
                ..Default::default()
            })
        });
        let file = harness
            .file_bytes("payload.bin", b"xxEVILxx", &[])
            .expect("fixture");
        harness.run_parser(file).expect("scans")
    });
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    assert!(read < database / 10, "{read} bytes read");
}
