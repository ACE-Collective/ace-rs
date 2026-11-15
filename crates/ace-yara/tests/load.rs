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
        Err(LoadError::Combined { path, error, files }) => {
            // What became of each file alone is still reported.
            assert_eq!(files.len(), 3);
            assert!(files.iter().all(|f| f.is_included()));
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

/// Rule files past each of `ace_yara::guard`'s bounds, by name: what yara-x would overflow its stack
/// on, far past where it does (`docs/measurements/yara-guard.md`), and what refuses each.
fn hostile_files() -> Vec<(&'static str, String, &'static str)> {
    const N: usize = 20_000;
    let deep = "(".repeat(N);
    vec![
        (
            "escapes.yar",
            format!(
                "rule h1 {{ strings: $a = \"{}\" condition: $a }}",
                "\\\\".repeat(N)
            ),
            "escape sequences",
        ),
        (
            "regex.yar",
            format!(
                "rule h2 {{ strings: $a = /a{}/ condition: $a }}",
                "\\.".repeat(N)
            ),
            "escape sequences",
        ),
        (
            "comment.yar",
            format!(
                "rule h3 {{ condition: /*\n{}*/ true }}",
                " * line\n".repeat(N)
            ),
            "runs of `*`",
        ),
        (
            "spaces.yar",
            format!("rule h4 {{ condition:{} true }}", "\u{a0}".repeat(N)),
            "spaces outside ASCII",
        ),
        (
            "parens.yar",
            format!("rule h5 {{ condition: {deep}true{} }}", ")".repeat(N)),
            "nests brackets",
        ),
        (
            "not.yar",
            format!("rule h6 {{ condition: {}true }}", "not ".repeat(N)),
            "nests brackets",
        ),
        (
            "hex.yar",
            format!(
                "rule h7 {{ strings: $a = {{ 01 02 03 04 {}05{} }} condition: $a }}",
                "( 06 | ".repeat(N),
                " )".repeat(N)
            ),
            "nests brackets",
        ),
        (
            "calls.yar",
            format!(
                "rule h8 {{ condition: {}0{} == 1 }}",
                "uint32(".repeat(40),
                ")".repeat(40)
            ),
            "nests calls",
        ),
        (
            "unclosed.yar",
            format!("rule h9 {{ condition: \"never closed\n{deep} }}"),
            "nests brackets",
        ),
        (
            "including.yar",
            "include \"parens.yar\"\nrule h10 { condition: true }".to_owned(),
            "the include \"parens.yar\" at line 1: line 1 nests brackets",
        ),
    ]
}

/// PLAN.md 7.16's follow-up: a rule file yara-x would overflow its stack on fails alone, with a reason
/// that names the line, and every other file loads. Without the bounds each of these aborts the
/// process. Runs on a thread of the smallest stack rule source is compiled on.
#[test]
fn a_file_yara_x_would_overflow_on_is_left_out_alone() {
    let root = tempfile::tempdir().unwrap();
    let namespace = root.path().join("hostile");
    std::fs::create_dir_all(&namespace).unwrap();
    std::fs::write(
        namespace.join("good.yar"),
        "rule good { meta: uuid = \"u-good\" strings: $a = \"EVIL\" condition: $a }",
    )
    .unwrap();
    let hostile = hostile_files();
    for (name, source, _) in &hostile {
        std::fs::write(namespace.join(name), source).unwrap();
    }
    let dir = root.path().to_path_buf();

    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            // the loader: the YARA pool, `ace signatures check` and SVS's replay load through it
            let loaded = load_dir(&dir, &LoadOptions::default()).expect("the good file loads");
            let rules: Vec<&str> = loaded.rules().map(|r| r.name.as_str()).collect();
            assert_eq!(rules, ["good"]);
            assert_eq!(loaded.left_out().count(), hostile.len());
            for (name, source, reason) in &hostile {
                let report = loaded
                    .files
                    .iter()
                    .find(|f| f.path.ends_with(name))
                    .unwrap();
                match &report.outcome {
                    FileOutcome::LeftOut { error } => {
                        assert!(error.contains(reason), "{name}: {error}");
                        assert!(
                            error.len() < 400,
                            "{name}: the reason holds none of the file"
                        );
                    }
                    FileOutcome::Included { .. } => panic!("{name} loaded"),
                }
                // the parser's use: no rules, as for a file it can't read. It follows no include,
                // so the including file's own rule is read
                let parsed = ace_yara::source::rules(source.as_bytes());
                assert_eq!(
                    parsed.len(),
                    usize::from(*name == "including.yar"),
                    "{name}"
                );
            }

            // the ruleset build, which the core's builder runs on a commit's export
            let built = ace_yara::ruleset::build(&dir, &LoadOptions::default()).expect("builds");
            assert_eq!(built.manifest.files.len(), 1);
            assert_eq!(built.manifest.left_out.len(), hostile.len());
            assert_eq!(built.manifest.signatures.len(), 1);

            // files given as already let through are checked again, since they're read again
            let namespaces = ace_yara::discover(&dir).unwrap();
            match ace_yara::load::compile_together(&namespaces, &LoadOptions::default()) {
                Err(LoadError::Combined { path, error, .. }) => {
                    assert!(path.ends_with("calls.yar"), "{path:?}");
                    assert!(error.contains("nests calls"), "{error}");
                }
                Err(e) => panic!("unexpected error: {e}"),
                Ok(_) => panic!("a file past the bounds compiled"),
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
