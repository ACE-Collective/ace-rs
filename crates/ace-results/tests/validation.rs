//! PLAN.md 1.17: a JSON result is checked against its type's schema, and a failure names the
//! path of the field that failed.

mod common;

use ace_results::{
    AnalysisTypeInfo, FieldError, InvalidResult, Registry, ResultValidator, result_schema,
};
use common::SampleAnalysis;
use serde_json::{Value, json};

fn registry() -> Registry {
    Registry::new(&[AnalysisTypeInfo::of::<SampleAnalysis>()]).expect("one type is valid")
}

fn valid_result() -> Value {
    json!({
        "analysis_type": "sample_analysis",
        "schema_version": 1,
        "details": {
            "subject": "Invoice",
            "raw_subject": {"base64": "SW52b2ljZf8="},
            "attachment_count": 2,
            "headers": [{"name": "Subject", "value": {"base64": "SW52b2ljZQ=="}}],
            "verdict": "suspicious",
        },
        "observables": [{"type": "email_from", "value": "a@example.com"}],
        "files": [{
            "path": "email.rfc822.headers",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 0,
            "yara_meta": ["type=email.headers"],
        }],
    })
}

/// Validates `result` and returns the failed fields, printing the error as a failure shows it.
fn failures(result: &Value) -> Vec<FieldError> {
    let err = registry()
        .validate(result)
        .expect_err("the result should fail");
    println!("{err}");
    err.fields().to_vec()
}

fn paths(fields: &[FieldError]) -> Vec<&str> {
    fields.iter().map(|f| f.path.as_str()).collect()
}

#[test]
fn a_valid_result_passes() {
    registry()
        .validate(&valid_result())
        .expect("the sample result is valid");
}

#[test]
fn an_unknown_field_fails_with_its_path() {
    let mut result = valid_result();
    result["details"]["surprise"] = json!(1);
    let fields = failures(&result);
    assert_eq!(paths(&fields), ["/details/surprise"]);
    assert_eq!(fields[0].message, "unknown field");

    let mut result = valid_result();
    result["details"]["headers"][0]["raw"] = json!("x");
    result["files"][0]["mime/type"] = json!("text/plain");
    result["extra"] = json!(true);
    let mut found = paths(&failures(&result))
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    found.sort();
    assert_eq!(
        found,
        ["/details/headers/0/raw", "/extra", "/files/0/mime~1type"]
    );
}

#[test]
fn a_wrong_type_fails_with_its_path() {
    let mut result = valid_result();
    result["details"]["attachment_count"] = json!("two");
    let fields = failures(&result);
    assert_eq!(paths(&fields), ["/details/attachment_count"]);
    assert!(
        fields[0].message.contains("integer"),
        "{}",
        fields[0].message
    );

    let mut result = valid_result();
    result["details"]["headers"][0]["value"] = json!("Invoice");
    assert_eq!(paths(&failures(&result)), ["/details/headers/0/value"]);

    let mut result = valid_result();
    result["details"]["verdict"] = json!("evil");
    assert_eq!(paths(&failures(&result)), ["/details/verdict"]);

    let mut result = valid_result();
    result["observables"][0]["type"] = json!("not_a_type");
    assert_eq!(paths(&failures(&result)), ["/observables/0/type"]);

    let mut result = valid_result();
    result["files"][0]["sha256"] = json!("E3B0");
    assert_eq!(paths(&failures(&result)), ["/files/0/sha256"]);
}

#[test]
fn the_error_message_carries_the_path() {
    let mut result = valid_result();
    result["details"]["attachment_count"] = json!("two");
    result["details"]["surprise"] = json!(1);
    let message = registry().validate(&result).unwrap_err().to_string();
    assert!(message.contains("/details/attachment_count: "), "{message}");
    assert!(
        message.contains("/details/surprise: unknown field"),
        "{message}"
    );
}

#[test]
fn a_missing_required_field_fails() {
    let mut result = valid_result();
    result["details"]
        .as_object_mut()
        .expect("details is an object")
        .remove("subject");
    let fields = failures(&result);
    assert_eq!(paths(&fields), ["/details"]);
    assert!(
        fields[0].message.contains("subject"),
        "{}",
        fields[0].message
    );
}

#[test]
fn another_type_or_version_is_refused() {
    let mut result = valid_result();
    result["schema_version"] = json!(2);
    assert_eq!(
        registry().validate(&result).unwrap_err(),
        InvalidResult::UnknownType {
            name: "sample_analysis".to_owned(),
            version: 2
        }
    );
    assert_eq!(
        registry().validate(&json!({"details": {}})).unwrap_err(),
        InvalidResult::Untyped
    );
    // a validator for one type refuses another's name, because the schema pins it
    let validator =
        ResultValidator::new(&result_schema::<SampleAnalysis>()).expect("schema compiles");
    let mut result = valid_result();
    result["analysis_type"] = json!("other_analysis");
    let err = validator.validate(&result).unwrap_err();
    assert_eq!(paths(err.fields()), ["/analysis_type"]);
}
