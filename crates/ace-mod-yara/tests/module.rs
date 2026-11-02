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
    assert_eq!(rules, ["plain", "tagged", "qa_only", "directs", "SIP_feed"]);
    // a QA rule adds no directives; a no_alert rule still adds its own
    assert_eq!(
        result.analyzed.directives,
        ["extract_urls", "sandbox", "whitelisted"]
    );
    assert_eq!(result.analyzed.tags, ["whitelisted"]);
    // detections only for rules that may alert, under the built-in signature without a uuid
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
            "payload.bin matched yara rule tagged",
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
