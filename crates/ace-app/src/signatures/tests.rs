//! PLAN.md 6.8's Done check: a rule yara-x rejects fails `ace signatures check`, which names the file.
//!
//! The checkouts are under `tests/fixtures/signatures/`, written for these tests; nothing in them
//! comes from the signatures repository. `passing/` checks clean: its rules compile, one of them with
//! yara-x's `deprecated_field` warning for `pe.number_of_signatures`, and its hunt loads with
//! templates that compile. `failing/` holds one of each failure: a rule file yara-x rejects
//! (`alpha/broken.yar`), two files that compile alone but not together (`beta/one.yar` and
//! `beta/two.yar` define one rule name), a hunt that doesn't validate (`broken.yaml`), a hunt whose
//! templates don't compile (`bad_templates.yaml`) and a hunt naming a correlation command type the
//! binary doesn't have (`unknown_command.yaml`).

use std::path::{Path, PathBuf};

use clap::Parser;

use super::*;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/signatures")
        .join(name)
}

fn app() -> App {
    App::new().hunt_type(ace_hunt::types::Splunk::default())
}

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    args: CheckArgs,
}

/// Runs `ace signatures check` with these words after it, returning its exit code and output.
fn run_check(words: &[&str]) -> (ExitCode, String) {
    let cli = Cli::try_parse_from(std::iter::once("check").chain(words.iter().copied()))
        .expect("the arguments parse");
    let mut out = Vec::new();
    let code = execute(&app(), &cli.args, &mut out).expect("the check runs");
    (code, String::from_utf8(out).expect("the output is UTF-8"))
}

fn args(checkout: &Path) -> CheckArgs {
    CheckArgs {
        checkout: checkout.to_path_buf(),
        yara_dir: PathBuf::from("yara"),
        rule_dirs: Vec::new(),
        deny_warnings: false,
        json: false,
    }
}

#[test]
fn a_clean_checkout_passes_with_its_warning_listed() {
    let dir = fixture("passing");
    let report = check(&app(), &args(&dir)).expect("the check runs");
    assert!(report.passed, "{}", text(&report));
    assert_eq!(
        report.counts,
        Counts {
            rule_files: 2,
            rule_files_failed: 0,
            rules: 2,
            warnings: 1,
            hunts: 1,
            hunts_failed: 0,
            failures: 0,
        }
    );
    assert!(report.yara.ruleset.is_some());
    let deprecated = &report.yara.files[0];
    assert_eq!(deprecated.path, "yara/alpha/deprecated.yar");
    assert_eq!(deprecated.warnings.len(), 1);
    assert_eq!(deprecated.warnings[0].code, "deprecated_field");
    assert!(
        deprecated.warnings[0].text.contains("number_of_signatures"),
        "{}",
        deprecated.warnings[0].text
    );
    assert_eq!(report.hunts[0].path, "hunts/splunk/ok.yaml");
    assert_eq!(
        report.hunts[0].name.as_deref(),
        Some("fixture ok for {{ user }}")
    );

    let (code, out) = run_check(&[dir.to_str().unwrap()]);
    assert_eq!(code, ExitCode::SUCCESS, "{out}");
    assert!(
        out.starts_with("WARN yara/alpha/deprecated.yar (deprecated_field)\n"),
        "{out}"
    );
    assert!(
        out.ends_with(
            "yara (yara): 2 rule files, 0 failed, 2 rules, 1 warning\n\
         hunts (splunk in hunts/splunk): 1 hunt, 0 failed\n\
         signatures check passed\n"
        ),
        "{out}"
    );
}

/// The warning fails the check only when asked.
#[test]
fn deny_warnings_fails_on_the_deprecated_field() {
    let dir = fixture("passing");
    let (code, out) = run_check(&[dir.to_str().unwrap(), "--deny-warnings"]);
    assert_eq!(code, ExitCode::FAILURE, "{out}");
    assert!(
        out.starts_with("FAIL yara/alpha/deprecated.yar (deprecated_field)\n"),
        "{out}"
    );
    assert!(
        out.ends_with("signatures check failed: 1 failure\n"),
        "{out}"
    );
}

#[test]
fn a_rule_yara_x_rejects_fails_the_check_and_is_named() {
    let dir = fixture("failing");
    let report = check(&app(), &args(&dir)).expect("the check runs");
    assert!(!report.passed);

    // Every rule file, in order, with what failed.
    let files: Vec<(&str, Option<&str>)> = report
        .yara
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.error.as_deref()))
        .collect();
    let paths: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        paths,
        [
            "yara/alpha/broken.yar",
            "yara/alpha/good.yar",
            "yara/beta/one.yar",
            "yara/beta/two.yar",
        ]
    );
    let broken = files[0].1.expect("broken.yar fails");
    assert!(broken.contains("fixture_no_such_identifier"), "{broken}");
    assert_eq!(files[1].1, None);
    assert_eq!(files[2].1, None);
    let two = files[3].1.expect("two.yar fails with one.yar before it");
    assert!(
        two.starts_with("it compiles alone but not with the files before it: ")
            && two.contains("fixture_same_name"),
        "{two}"
    );
    // nothing loads when the files don't compile together, so there's no ruleset
    assert_eq!(report.yara.ruleset, None);

    // Every hunt, in order, with its errors.
    let hunts: Vec<(&str, &[String])> = report
        .hunts
        .iter()
        .map(|h| (h.path.as_str(), h.errors.as_slice()))
        .collect();
    let paths: Vec<&str> = hunts.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        paths,
        [
            "hunts/splunk/bad_templates.yaml",
            "hunts/splunk/broken.yaml",
            "hunts/splunk/ok.yaml",
            "hunts/splunk/unknown_command.yaml",
        ]
    );
    let templates = hunts[0].1;
    assert_eq!(templates.len(), 2, "{templates:?}");
    assert!(
        templates[0].starts_with("template dedup_key: TemplateSyntaxError: "),
        "{templates:?}"
    );
    assert!(
        templates[1].starts_with("template summary_details/0/content: TemplateSyntaxError: ")
            && templates[1].contains("fixture_no_such_filter"),
        "{templates:?}"
    );
    let broken = hunts[1].1;
    assert_eq!(broken.len(), 1);
    assert!(
        broken[0].contains("validation errors for SplunkHuntConfig"),
        "{broken:?}"
    );
    assert!(hunts[2].1.is_empty(), "{:?}", hunts[2].1);
    let command = hunts[3].1;
    assert_eq!(command.len(), 1, "{command:?}");
    assert!(
        command[0].starts_with("command 'fixture_no_such_type': unknown command type"),
        "{command:?}"
    );

    assert_eq!(
        report.counts,
        Counts {
            rule_files: 4,
            rule_files_failed: 2,
            rules: 3,
            warnings: 0,
            hunts: 4,
            hunts_failed: 3,
            failures: 5,
        }
    );

    // The command fails, naming each file with its error, then the counts.
    let (code, out) = run_check(&[dir.to_str().unwrap()]);
    assert_eq!(code, ExitCode::FAILURE, "{out}");
    let heads: Vec<&str> = out.lines().filter(|l| l.starts_with("FAIL ")).collect();
    assert_eq!(
        heads,
        [
            "FAIL yara/alpha/broken.yar",
            "FAIL yara/beta/two.yar",
            "FAIL hunts/splunk/bad_templates.yaml",
            "FAIL hunts/splunk/broken.yaml",
            "FAIL hunts/splunk/unknown_command.yaml",
        ]
    );
    assert!(
        out.contains("    error[E009]: unknown identifier `fixture_no_such_identifier`"),
        "{out}"
    );
    assert!(
        out.ends_with(
            "yara (yara): 4 rule files, 2 failed, 3 rules, 0 warnings\n\
         hunts (splunk in hunts/splunk): 4 hunts, 3 failed\n\
         signatures check failed: 5 failures\n"
        ),
        "{out}"
    );

    // The JSON form holds the same report, for a CI to parse.
    let (code, out) = run_check(&[dir.to_str().unwrap(), "--json"]);
    assert_eq!(code, ExitCode::FAILURE);
    let json: serde_json::Value = serde_json::from_str(&out).expect("the output is JSON");
    assert_eq!(json["passed"], false);
    assert_eq!(json["counts"]["failures"], 5);
    assert_eq!(json["yara"]["files"][0]["path"], "yara/alpha/broken.yar");
    assert_eq!(json["hunts"][1]["type"], "splunk");
    assert_eq!(json["hunts"][1]["path"], "hunts/splunk/broken.yaml");
    assert_eq!(json["hunts"][1]["name"], serde_json::Value::Null);
    assert_eq!(json["hunts"][2]["errors"], serde_json::json!([]));
}

/// A rule directory given that isn't there fails; a hunt type the binary lacks is a usage error.
#[test]
fn rule_directories_given_must_exist_and_name_a_type() {
    let dir = fixture("passing");
    let (code, out) = run_check(&[dir.to_str().unwrap(), "--rule-dir", "splunk=hunts/nowhere"]);
    assert_eq!(code, ExitCode::FAILURE, "{out}");
    assert!(
        out.contains("FAIL hunts/nowhere\n    the splunk rule directory isn't a directory\n"),
        "{out}"
    );

    let mut bad = args(&dir);
    bad.rule_dirs = vec!["logscale=hunts/logscale".to_owned()];
    let error = check(&app(), &bad)
        .expect_err("no logscale type")
        .to_string();
    assert_eq!(
        error,
        "this binary has no hunt type \"logscale\"; it has splunk"
    );

    // a default directory that isn't there is skipped, and said so
    let mut yara_only = args(&dir);
    yara_only.checkout = dir.join("yara");
    yara_only.yara_dir = PathBuf::from(".");
    let report = check(&app(), &yara_only).expect("the check runs");
    assert!(report.passed, "{}", text(&report));
    assert!(
        text(&report).contains("hunts (splunk: no hunts/splunk): 0 hunts, 0 failed\n"),
        "{}",
        text(&report)
    );
}

/// A rule directory that can't be listed fails the check.
#[test]
fn a_missing_rule_directory_fails() {
    let mut missing = args(&fixture("passing"));
    missing.yara_dir = PathBuf::from("no-such-yara");
    let report = check(&app(), &missing).expect("the check runs");
    assert!(!report.passed);
    assert_eq!(report.counts.failures, 1);
    assert!(text(&report).starts_with("FAIL no-such-yara\n    unable to list signature directory"));
}
