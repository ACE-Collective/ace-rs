//! PLAN.md 1.3: every `re:` item compiles with the regex crate while the rules load.

use crate::common;

use ace_yara::filter::{DirectiveKind, Target};
use ace_yara::{FileOutcome, LoadOptions, load_dir};
use common::{capture_logs, fixture};

#[test]
fn a_lookaround_in_a_re_item_leaves_its_file_out_with_an_error_naming_the_pattern() {
    let dir = fixture("regex/signatures");
    let (loaded, logs) = capture_logs(|| load_dir(&dir, &LoadOptions::default()));
    let loaded = loaded.expect("the other file loads");

    let left_out: Vec<_> = loaded.left_out().collect();
    assert_eq!(left_out.len(), 1);
    assert_eq!(left_out[0].path, dir.join("files/lookaround.yar"));
    let FileOutcome::LeftOut { error } = &left_out[0].outcome else {
        unreachable!()
    };
    assert!(error.contains(r"(?<=invoice)\d+"), "{error}");
    assert!(error.contains("lookaround_in_file_name"), "{error}");

    // The ERROR names the file and the pattern.
    let error_lines: Vec<_> = logs.lines().filter(|l| l.contains("ERROR")).collect();
    println!("{logs}");
    assert_eq!(error_lines.len(), 1, "{logs}");
    assert!(error_lines[0].contains("files/lookaround.yar"), "{logs}");
    assert!(error_lines[0].contains(r"(?<=invoice)\d+"), "{logs}");

    // Neither rule in the file is in the ruleset; the other file's rule is.
    let compiled: Vec<_> = loaded
        .ruleset
        .rules()
        .iter()
        .map(|r| r.identifier())
        .collect();
    assert_eq!(compiled, ["regex_that_compiles"]);
}

#[test]
fn the_ruleset_holds_each_rules_compiled_filter() {
    let loaded = load_dir(&fixture("regex/signatures"), &LoadOptions::default()).unwrap();
    let filter = loaded
        .ruleset
        .filter("files", "regex_that_compiles")
        .expect("a filter for every rule");
    let kinds: Vec<_> = filter.directives().iter().map(|d| d.kind()).collect();
    assert_eq!(kinds, [DirectiveKind::FileName, DirectiveKind::MimeType]);

    let target = |path| Target {
        path,
        mime_type: "application/msword",
        meta_tags: &[],
    };
    assert!(filter.keeps(&target("alert/Invoice.DOCX")));
    assert!(!filter.keeps(&target("alert/invoice.pdf")));
}
