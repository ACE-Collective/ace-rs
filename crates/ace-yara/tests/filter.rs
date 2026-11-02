//! PLAN.md 1.2: the meta filter, on the table in fixtures/filter_cases.json.
//!
//! tools/ace3/yara/filter_cases.py runs the same table through yara_scanner_v2's
//! filter_scan_results in ace3's dev container, so the expected values are ace3's.

mod common;

use std::collections::BTreeSet;

use ace_yara::filter::{RuleFilter, Target, keeps};
use ace_yara::{Meta, MetaValue};
use serde_json::Value;

const RULE: &str = "table_rule";

fn meta_value(value: &Value) -> MetaValue {
    match value {
        Value::String(s) => MetaValue::Str(s.clone()),
        Value::Bool(b) => MetaValue::Bool(*b),
        Value::Number(n) if n.is_i64() => MetaValue::Int(n.as_i64().unwrap()),
        Value::Number(n) => MetaValue::Float(n.as_f64().unwrap()),
        other => panic!("not a meta value: {other}"),
    }
}

#[test]
fn every_case_in_the_table() {
    let table: Value =
        serde_json::from_slice(&std::fs::read(common::fixture("filter_cases.json")).unwrap())
            .unwrap();

    let cases = table["cases"].as_array().unwrap();
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let meta = Meta::from_pairs(
            case["meta"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), meta_value(v))),
        );
        let tags: Vec<String> = case["meta_tags"]
            .as_array()
            .map(|tags| {
                tags.iter()
                    .map(|t| t.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let target = Target {
            path: case["path"].as_str().unwrap(),
            mime_type: case["mime_type"].as_str().unwrap_or(""),
            meta_tags: &tags,
        };
        let blacklist: BTreeSet<String> = if case["blacklisted"].as_bool() == Some(true) {
            BTreeSet::from([RULE.to_string()])
        } else {
            BTreeSet::new()
        };

        let filter = RuleFilter::from_meta(&meta).unwrap();
        let kept = keeps(RULE, &filter, &blacklist, &target);
        if kept != case["keep"].as_bool().unwrap() {
            failures.push(format!("{name}: kept {kept}"));
        }
    }

    assert!(failures.is_empty(), "{failures:#?}");
    // Each of the five directives with no prefix, !, re:, sub:, !re: and !sub:.
    assert!(cases.len() >= 5 * 6, "{} cases", cases.len());
}
