//! PLAN.md 1.1: a signature directory loads the way yara_scanner_v2 3.0.0 loads it.

mod common;

use std::collections::BTreeSet;

use ace_yara::{FileOutcome, LoadError, LoadOptions, load_dir};
use common::{capture_logs, fixture};

fn names<'a>(iter: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut names: Vec<_> = iter.collect();
    names.sort();
    names
}

#[test]
fn a_broken_file_is_logged_and_left_out_and_every_other_rule_loads() {
    let dir = fixture("load/signatures");
    let (loaded, logs) = capture_logs(|| load_dir(&dir, &LoadOptions::default()));
    let loaded = loaded.expect("the other files load");

    // Every rule from the files that compile, and none from the broken one, the nested
    // directory or the signature directory itself.
    let loaded_rules: Vec<_> = loaded
        .rules()
        .map(|r| format!("{}:{}", r.namespace, r.name))
        .collect();
    assert_eq!(
        names(loaded_rules.iter().map(String::as_str)),
        [
            "alpha:alpha_good",
            "alpha:alpha_upper_case_extension",
            "beta:alpha_good",
            "beta:beta_uses_externals",
        ]
    );
    let compiled: Vec<_> = loaded
        .ruleset
        .rules()
        .iter()
        .map(|r| format!("{}:{}", r.namespace(), r.identifier()))
        .collect();
    assert_eq!(
        names(compiled.iter().map(String::as_str)),
        names(loaded_rules.iter().map(String::as_str))
    );

    // The broken file is reported as left out, with yara-x's reason.
    let left_out: Vec<_> = loaded.left_out().collect();
    assert_eq!(left_out.len(), 1);
    assert_eq!(left_out[0].path, dir.join("alpha/broken.yar"));
    match &left_out[0].outcome {
        FileOutcome::LeftOut { error } => assert!(error.contains("no_such_identifier"), "{error}"),
        FileOutcome::Included { .. } => unreachable!(),
    }

    // ... and logged at ERROR with its path.
    let broken = dir.join("alpha/broken.yar").display().to_string();
    let error_lines: Vec<_> = logs.lines().filter(|l| l.contains("ERROR")).collect();
    assert_eq!(error_lines.len(), 1, "{logs}");
    assert!(error_lines[0].contains(&broken), "{logs}");

    // The files read are the .yar and .yara files directly in each namespace, ignoring case.
    let files: Vec<_> = loaded
        .files
        .iter()
        .map(|f| f.path.strip_prefix(&dir).unwrap().display().to_string())
        .collect();
    assert_eq!(
        files,
        [
            "alpha/SHOUTED.YARA",
            "alpha/broken.yar",
            "alpha/good.yar",
            "beta/externals.yar"
        ]
    );
}

#[test]
fn the_default_externals_are_defined() {
    let loaded = load_dir(&fixture("load/signatures"), &LoadOptions::default()).unwrap();
    let report = loaded
        .files
        .iter()
        .find(|f| f.path.ends_with("beta/externals.yar"))
        .unwrap();
    assert!(report.is_included(), "{report:?}");
}

#[test]
fn files_that_compile_alone_but_not_together_load_nothing() {
    let result = load_dir(&fixture("load/duplicate"), &LoadOptions::default());
    match result {
        Err(LoadError::Combined { path, error }) => {
            assert!(path.ends_with("alpha/two.yar"), "{path:?}");
            assert!(error.contains("same_name"), "{error}");
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("a rule name defined twice in one namespace loaded"),
    }
}

#[test]
fn the_ruleset_keeps_the_blacklist() {
    let options = LoadOptions {
        blacklist: BTreeSet::from(["alpha_good".to_string()]),
    };
    let loaded = load_dir(&fixture("load/signatures"), &options).unwrap();
    assert!(loaded.ruleset.is_blacklisted("alpha_good"));
    assert!(!loaded.ruleset.is_blacklisted("beta_uses_externals"));
}
