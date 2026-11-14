//! The marker rule: ace3's `saq/svs/marker_rule.py`. A built-in `no_alert` YARA rule that finds run markers
//! inside file contents, so a marker in a dropped script or document is in the file's YARA result like any
//! other match, where attribution reads it (`attribution::analysis_sightings`, scan point
//! `file_contents`).
//!
//! ace3 writes the rule into its signature directory as a namespace of its own, when the YARA service
//! starts, and only when the file differs, since its scanner recompiles on a changed mtime. Here the
//! ruleset builder (PLAN.md 2.25, `crate::rulesets`) adds it to every ruleset it builds, as a file over the
//! commit's export (`ace_yara::ruleset::BuiltIn`): the repository never changes, and a ruleset built with
//! other built-ins than this build's is built again (`yara.rulesets.built_ins`), which is what "written
//! only when it changed" comes to.

use ace_yara::ruleset::BuiltIn;

/// The rule's namespace: a directory of the signature directory, ace3's `MARKER_RULE_DIR`.
pub const MARKER_RULE_DIR: &str = "svs_marker";
pub const MARKER_RULE_FILE: &str = "svs_marker.yar";
pub const MARKER_RULE_NAME: &str = "SVS_Marker";

/// The same matches as `markers::find_markers`. YARA has no lookbehind, so the boundary characters are
/// matched rather than asserted: a match's data can carry one on each side, and NULs when the text is
/// UTF-16 (`wide`), which `markers::find_markers_in_match` reads back. ace3's `MARKER_RULE`, byte for byte.
pub const MARKER_RULE: &str = r#"rule SVS_Marker
{
    meta:
        description = "An SVS test run marker (docs/SVS_RUNS.md). Written by ACE; do not edit."
        modifiers = "no_alert"
    strings:
        $marker = /(^|[^a-z0-9])svs-[a-z2-7]{26}([^a-z0-9]|$)/ nocase ascii wide
    condition:
        $marker
}
"#;

/// The rule as the ruleset builder adds it.
pub const BUILT_IN: BuiltIn = BuiltIn {
    namespace: MARKER_RULE_DIR,
    file: MARKER_RULE_FILE,
    source: MARKER_RULE,
};

/// ace3's tests/saq/svs/test_marker_rule.py. The cases of the file's writing are `ace_yara`'s
/// (`built_ins_join_the_commit_s_export`) and the builder's (`crates/ace-core/tests/rulesets.rs`).
#[cfg(test)]
mod tests {
    use std::path::Path;

    use ace_yara::load::{self, LoadOptions};
    use ace_yara::scan::ScanRequest;

    use super::*;
    use crate::svs::markers::{find_markers, find_markers_in_match};

    const MARKER: &str = "svs-abcdefghijklmnopqrstuvwxyz";

    /// The rule compiled alone, in its own namespace, as the builder lays it out.
    fn rules(dir: &Path) -> ace_yara::load::Loaded {
        let namespace = dir.join(MARKER_RULE_DIR);
        std::fs::create_dir_all(&namespace).expect("a directory");
        std::fs::write(namespace.join(MARKER_RULE_FILE), MARKER_RULE).expect("writes");
        let namespaces = load::discover(dir).expect("lists");
        load::compile(&namespaces, &LoadOptions::default()).expect("compiles")
    }

    /// Every marker the rule's matches carry, read back the way attribution reads them.
    fn rule_markers(loaded: &ace_yara::load::Loaded, data: &[u8]) -> Vec<String> {
        let mut scanner = ace_yara::scan::Scanner::new(&loaded.ruleset);
        let outcome = scanner
            .scan(&ScanRequest {
                data,
                path: "sample.txt",
                mime_type: "text/plain",
                meta_tags: &[],
                timeout: None,
            })
            .expect("scans");
        let mut found: Vec<String> = Vec::new();
        for matched in &outcome.matches {
            assert_eq!(matched.rule, MARKER_RULE_NAME);
            for pattern in &matched.patterns {
                let end = (pattern.offset + pattern.length).min(data.len());
                for marker in find_markers_in_match(&data[pattern.offset..end]) {
                    if !found.contains(&marker) {
                        found.push(marker);
                    }
                }
            }
        }
        found
    }

    /// `test_rule_is_no_alert`.
    #[test]
    fn the_rule_is_no_alert() {
        let dir = tempfile::tempdir().expect("a directory");
        let loaded = rules(dir.path());
        let [file] = loaded.files.as_slice() else {
            panic!("one file: {:?}", loaded.files)
        };
        let load::FileOutcome::Included { rules } = &file.outcome else {
            panic!("the rule compiles: {:?}", file.outcome)
        };
        let [rule] = rules.as_slice() else {
            panic!("one rule")
        };
        assert_eq!(rule.name, MARKER_RULE_NAME);
        assert_eq!(rule.namespace, MARKER_RULE_DIR);
        assert!(rule.meta.is_no_alert());
        // rule tags are copied onto the file that matched
        assert!(rule.tags.is_empty());
    }

    /// `test_rule_finds_what_the_regex_finds`, each text as UTF-8 and as UTF-16.
    #[test]
    fn the_rule_finds_what_the_regex_finds() {
        let dir = tempfile::tempdir().expect("a directory");
        let loaded = rules(dir.path());
        let texts = [
            MARKER.to_owned(),
            format!(" {MARKER} "),
            format!("_{MARKER}"),
            MARKER.to_uppercase(),
            format!("cmd.exe /c \"whoami & REM {MARKER}\"\r\n"),
            format!("sh -c \"id; # {MARKER}\"\n"),
            format!("powershell.exe \"& {{whoami}}\" <# {MARKER} #>"),
            format!("-OutputFile C:\\Temp\\{MARKER}.txt"),
            format!("x{MARKER}"),
            format!("{MARKER}2"),
            format!("svs-{}", "a".repeat(25)),
            format!("svs-{}", "a".repeat(27)),
            "no marker here".to_owned(),
        ];
        for text in &texts {
            let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            for (encoding, data) in [("utf-8", text.as_bytes().to_vec()), ("utf-16-le", wide)] {
                assert_eq!(
                    rule_markers(&loaded, &data),
                    find_markers(text),
                    "{text:?} as {encoding}"
                );
            }
        }
    }

    /// `test_rule_finds_every_marker`.
    #[test]
    fn the_rule_finds_every_marker() {
        let dir = tempfile::tempdir().expect("a directory");
        let loaded = rules(dir.path());
        let other = "svs-bbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(
            rule_markers(&loaded, format!("{MARKER} then {other}").as_bytes()),
            [MARKER, other]
        );
    }

    /// `test_find_markers_in_a_saved_match`: ace3 reads a saved match back as text with its NULs; ace4
    /// keeps a match's bytes (`ace_results::Bytes`), so both forms are the bytes.
    #[test]
    fn markers_in_a_saved_match() {
        let wide: Vec<u8> = format!(" {MARKER}\r")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(find_markers_in_match(&wide), [MARKER]);
        assert_eq!(
            find_markers_in_match(format!(" {}\r", MARKER.to_uppercase()).as_bytes()),
            [MARKER]
        );
    }

    /// `test_marker_regex_is_what_the_rule_mirrors`: the rule's pattern is written by hand, so if the
    /// marker format changes, both must change.
    #[test]
    fn the_rule_mirrors_the_marker_pattern() {
        assert!(MARKER_RULE.contains("svs-[a-z2-7]{26}"));
        assert!(MARKER_RULE.starts_with(&format!("rule {MARKER_RULE_NAME}\n")));
        assert_eq!(
            crate::svs::markers::MARKER_LENGTH,
            "svs-".len() + 26,
            "the marker's length is the rule's"
        );
        assert_eq!(
            (BUILT_IN.namespace, BUILT_IN.file, BUILT_IN.source),
            (MARKER_RULE_DIR, MARKER_RULE_FILE, MARKER_RULE)
        );
    }
}
