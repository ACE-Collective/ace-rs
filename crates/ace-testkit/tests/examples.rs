//! PLAN.md 1.23: the example modules from 1.18, run by the harness on fixtures without the core,
//! checked against their schemas and snapshotted.

use std::time::Duration;

use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::example::{LineCounter, Resolver};
use ace_sdk::{Module, ModuleError, Outcome, Parser, TaskContext};
use ace_testkit::{Harness, HarnessError, assert_outcome_snapshot};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// The example's own file role, which a binary that runs it lists, installed before a harness of it.
fn install_first_line() {
    ace_results::install_roles(&[ace_sdk::example::FIRST_LINE]).expect("installs");
}

#[test]
fn line_counter_on_a_fixture_file() {
    install_first_line();
    let harness = Harness::<LineCounter>::new().expect("harness");
    let notes = harness
        .file(
            "notes.txt",
            fixture("notes.txt"),
            &["type=email.attachment"],
        )
        .expect("fixture");
    let outcome = harness
        .run_parser(notes)
        .expect("runs and passes its schema");
    if let Outcome::Done(result) = &outcome {
        let bytes = harness.read_output(&result.files[0]).expect("output reads");
        assert_eq!(bytes, b"Invoice \xa3120 attached");
    }
    assert_outcome_snapshot!(outcome);
}

#[test]
fn samples_carry_their_manifest_path_and_tags() {
    install_first_line();
    let harness = Harness::<LineCounter>::new().expect("harness");
    let zip = harness
        .sample("ace3/archive/test.zip")
        .expect("an ace3 sample");
    let file = zip.file.as_ref().expect("a file observable");
    assert_eq!(file.path.as_str(), "test.zip");
    assert_eq!(file.yara_meta[0].as_str(), "type=email.attachment");
    let email = harness
        .sample("ace3/email/smtp.email.rfc822")
        .expect("an ace3 sample");
    let file = email.file.as_ref().expect("a file observable");
    assert_eq!(file.path.as_str(), "email.rfc822");
    assert!(file.yara_meta.is_empty());
    assert!(harness.sample("ace3/nothing/here").is_err());
}

#[test]
fn line_counter_skips_an_empty_file() {
    install_first_line();
    let harness = Harness::<LineCounter>::with_settings(json!({"max_bytes": 64})).expect("harness");
    let empty = harness.file_bytes("empty.txt", b"", &[]).expect("fixture");
    assert_outcome_snapshot!(harness.run_parser(empty).expect("runs"));
}

#[test]
fn line_counter_settings_refuse_unknown_keys() {
    install_first_line();
    let err = Harness::<LineCounter>::with_settings(json!({"max_bytez": 64}))
        .err()
        .expect("an unknown key fails");
    assert!(matches!(err, HarnessError::Settings(_)), "{err}");
}

#[tokio::test]
async fn resolver_delays_then_answers() {
    let harness = Harness::<Resolver>::with_settings(json!({
        "hosts": {"example.com": ["192.0.2.1", "192.0.2.2"]},
        "delays": 1,
        "delay_seconds": 30,
        "delay_timeout_seconds": 600,
    }))
    .expect("harness")
    .secret("resolver_token", "test-token");
    let domain = harness.observable(ObservableKind::Fqdn, "Example.com");

    let first = harness.run_lookup(domain.clone()).await.expect("runs");
    assert_outcome_snapshot!("resolver_first_run", first);
    let Outcome::Delay(delay) = first else {
        panic!("expected a delay");
    };

    let delayed = harness.after_delay(&delay, 1, Duration::from_secs(30));
    let second = harness.rerun_lookup(domain, delayed).await.expect("runs");
    assert_outcome_snapshot!("resolver_after_delay", second);
}

#[tokio::test]
async fn resolver_without_its_secret_fails() {
    let harness = Harness::<Resolver>::new().expect("harness");
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.com"))
        .await
        .expect_err("the secret is missing");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::MissingSecret(_))),
        "{err}"
    );
}

/// A module whose details serialize differently from what their schema says, to show the
/// harness checks the schema.
struct Liar;

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct LiarDetails {
    #[schemars(with = "u32")]
    count: String,
}

impl AnalysisType for LiarDetails {
    const NAME: &'static str = "liar";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "liar";
}

impl Module for Liar {
    const NAME: &'static str = "liar";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Test];
    type Output = LiarDetails;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Liar)
    }
}

impl Parser for Liar {
    fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LiarDetails>, ModuleError> {
        Ok(Outcome::Done(ResultEnvelope::new(LiarDetails {
            count: "three".to_owned(),
        })))
    }
}

#[test]
fn a_result_that_fails_its_schema_fails_the_harness() {
    let harness = Harness::<Liar>::new().expect("harness");
    let err = harness
        .run_parser(harness.observable(ObservableKind::Test, "x"))
        .expect_err("the result breaks its schema");
    println!("{err}");
    let HarnessError::InvalidResult(invalid) = err else {
        panic!("expected a schema failure, got {err}");
    };
    assert_eq!(invalid.fields()[0].path, "/details/count");
}
