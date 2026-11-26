//! The pool's native copy of a ruleset (`ace_mod_yara::prepare_ruleset`): the core's rules
//! serialized again with yara-x's machine code, beside the core's file in the generation. The module
//! loads it when it is there and loads, and the core's file otherwise, and matches the same either
//! way. The rules are generated in the shapes signature repositories hold: text strings with
//! modifiers, hex strings with jumps and wildcards, regular expressions, the pe module and filter
//! metadata.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ace_mod_yara::{YaraScanner, native_copy_name, prepare_ruleset};
use ace_sdk::generation::{self, Generation, GenerationInfo};
use ace_testkit::Harness;
use serde_json::json;

/// splitmix64, so the rules and payloads are the same on every run.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn word(&mut self, len: u64) -> String {
        (0..len)
            .map(|_| char::from(b'a' + self.below(26) as u8))
            .collect()
    }

    fn pick<'a>(&mut self, choices: &[&'a str]) -> &'a str {
        choices[self.below(choices.len() as u64) as usize]
    }
}

/// `count` rules in five namespaces, and payloads that some of them match.
fn generate(dir: &Path, count: usize) -> Vec<Vec<u8>> {
    let mut random = Random(count as u64);
    let mut files: std::collections::BTreeMap<PathBuf, (bool, String)> = Default::default();
    let mut payloads = Vec::new();
    for i in 0..count {
        let file = dir
            .join(format!("ns{}", i % 5))
            .join(format!("rules_{}.yar", i / 100));
        let kind = random.below(100);
        let mut meta = format!(
            "        uuid = \"{:08x}-0000-4000-8000-{:012x}\"\n        description = \"generated rule {i}\"\n",
            random.next() as u32,
            random.next() & 0xffff_ffff_ffff
        );
        if kind < 10 {
            meta.push_str("        file_ext = \"exe\"\n");
        } else if kind < 15 {
            meta.push_str("        mime_type = \"text/plain\"\n");
        }
        let (strings, condition, payload) = if kind < 40 {
            let words: Vec<String> = (0..2 + random.below(4))
                .map(|_| {
                    let len = 8 + random.below(12);
                    random.word(len)
                })
                .collect();
            let strings: String = words
                .iter()
                .enumerate()
                .map(|(j, w)| {
                    let modifier = random.pick(&["", " ascii wide", " nocase", ""]);
                    format!("        $s{j} = \"{w}\"{modifier}\n")
                })
                .collect();
            let condition =
                random.pick(&["any of them", "2 of them", "filesize < 2MB and any of them"]);
            (strings, condition.to_owned(), words.join(" ").into_bytes())
        } else if kind < 70 {
            let head: Vec<u8> = (0..3 + random.below(4))
                .map(|_| random.next() as u8)
                .collect();
            let tail: Vec<u8> = (0..3).map(|_| random.next() as u8).collect();
            let hex = |bytes: &[u8]| {
                bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let strings = format!(
                "        $h0 = {{ {} ?? [1-4] {} }}\n",
                hex(&head),
                hex(&tail)
            );
            let mut payload = b"MZ".to_vec();
            payload.extend(&head);
            payload.extend(b"xyz");
            payload.extend(&tail);
            let condition = random.pick(&["uint16(0) == 0x5A4D and any of them", "any of them"]);
            (strings, condition.to_owned(), payload)
        } else if kind < 90 {
            let host = random.word(6);
            let marker = random.word(10);
            let strings = format!(
                "        $r0 = /https?:\\/\\/[a-z0-9]{{3,12}}\\.{host}\\.(com|net|org)\\/[a-z]{{2,8}}\\.php/\n        $t0 = \"{marker}\"\n"
            );
            let payload = format!("{marker} http://abc.{host}.net/gate.php").into_bytes();
            (strings, "$r0 and $t0".to_owned(), payload)
        } else {
            let word = random.word(12);
            let strings = format!("        $s0 = \"{word}\" wide\n");
            let condition = format!(
                "pe.is_pe and pe.number_of_sections > {} and $s0",
                3 + random.below(6)
            );
            (strings, condition, word.into_bytes())
        };
        if random.below(3) == 0 {
            payloads.push(payload);
        }
        let rule = format!(
            "rule gen_{i}\n{{\n    meta:\n{meta}    strings:\n{strings}    condition:\n        {condition}\n}}\n\n"
        );
        let entry = files.entry(file).or_default();
        entry.0 |= kind >= 90;
        entry.1.push_str(&rule);
    }
    for (path, (pe, rules)) in files {
        std::fs::create_dir_all(path.parent().expect("a namespace")).expect("a namespace");
        let import = if pe { "import \"pe\"\n\n" } else { "" };
        std::fs::write(path, format!("{import}{rules}")).expect("rules");
    }
    payloads
}

/// Builds the rules in `signatures` as the core does and publishes them as the generation `key` of
/// the pool's ruleset directory `rulesets`.
fn publish(signatures: &Path, rulesets: &Path, key: &str) -> Generation {
    let built = ace_yara::ruleset::build(signatures, &ace_yara::LoadOptions::default())
        .expect("the rules build");
    assert!(
        built.manifest.left_out.is_empty(),
        "{:?}",
        built.manifest.left_out
    );
    let download = rulesets.join(format!(".download-{key}"));
    std::fs::write(&download, &built.bytes).expect("the download");
    generation::publish(
        rulesets,
        &GenerationInfo {
            key: key.to_owned(),
            commit: "c0ffee".to_owned(),
        },
        &download,
    )
    .expect("published")
}

/// Collects what tracing writes while the module loads.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The module loaded from the pool's ruleset directory, with what it logged as it loaded.
fn harness(rulesets: &Path) -> (Harness<YaraScanner>, String) {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    let harness = tracing::subscriber::with_default(subscriber, || {
        Harness::<YaraScanner>::with_settings(json!({ "rulesets": rulesets }))
    })
    .expect("the module loads");
    let logs = String::from_utf8(logs.0.lock().expect("lock").clone()).expect("text");
    (harness, logs)
}

/// What the module made of each payload and each tracked sample.
fn outcomes(harness: &Harness<YaraScanner>, payloads: &[Vec<u8>]) -> Vec<String> {
    let mut outcomes = Vec::new();
    for (n, payload) in payloads.iter().enumerate() {
        let file = harness
            .file_bytes(&format!("payload{n}.exe"), payload, &[])
            .expect("a payload");
        outcomes.push(format!("{:?}", harness.run_parser(file).expect("scans")));
    }
    for sample in [
        "ace3/office/doc.docx",
        "ace3/pdf/ComplaintApril_424256637.pdf",
    ] {
        let file = harness.sample(sample).expect("a sample");
        outcomes.push(format!("{:?}", harness.run_parser(file).expect("scans")));
    }
    outcomes
}

#[test]
fn the_native_copy_matches_as_the_cores_file_does() {
    let signatures = tempfile::tempdir().expect("a directory");
    let rulesets = tempfile::tempdir().expect("a directory");
    let payloads = generate(signatures.path(), 300);
    let current = publish(signatures.path(), rulesets.path(), "aa");

    let built = prepare_ruleset(&current)
        .expect("the copy builds")
        .expect("a new copy");
    assert_eq!(built, current.dir.join(native_copy_name()));
    // a copy already there is kept
    assert_eq!(prepare_ruleset(&current).expect("nothing to do"), None);

    // every task loads the copy, so that is a DEBUG line, and the fallback to the core's file INFO
    let logged = |logs: &str, level: &str, wanted: &str| {
        logs.lines()
            .any(|line| line.contains(level) && line.contains(wanted) && line.contains("key=aa"))
    };
    let (with_copy, logs) = harness(rulesets.path());
    assert!(
        logged(&logs, "DEBUG", "loaded the pool's native copy"),
        "{logs}"
    );
    let native = outcomes(&with_copy, &payloads);

    std::fs::remove_file(&built).expect("removed");
    let (without, logs) = harness(rulesets.path());
    assert!(logged(&logs, "INFO", "no native copy"), "{logs}");
    let core = outcomes(&without, &payloads);

    let matched = core.iter().filter(|o| o.contains("scan_results")).count();
    assert!(matched > 50, "only {matched} matched");
    assert_eq!(native, core);
}

#[test]
fn a_native_copy_that_doesnt_load_falls_back_to_the_cores_file_and_warns() {
    let signatures = tempfile::tempdir().expect("a directory");
    let rulesets = tempfile::tempdir().expect("a directory");
    let payloads = generate(signatures.path(), 50);
    let current = publish(signatures.path(), rulesets.path(), "bb");
    let (harness_before, _) = harness(rulesets.path());
    let core = outcomes(&harness_before, &payloads);

    let copy = current.dir.join(native_copy_name());
    std::fs::write(&copy, b"not rules").expect("a corrupt copy");
    let (fallen_back, logs) = harness(rulesets.path());
    assert!(logs.contains("WARN"), "{logs}");
    assert!(logs.contains("key=bb"), "{logs}");
    assert!(logs.contains(&copy.display().to_string()), "{logs}");
    assert_eq!(outcomes(&fallen_back, &payloads), core);
}

#[test]
fn copies_from_other_builds_and_old_generations_go() {
    let signatures = tempfile::tempdir().expect("a directory");
    let rulesets = tempfile::tempdir().expect("a directory");
    generate(signatures.path(), 20);
    let first = publish(signatures.path(), rulesets.path(), "cc");
    prepare_ruleset(&first).expect("builds").expect("a copy");
    // another binary's copy, and a copy a stopped pool left half written
    let other = first.dir.join("native-0.0.0-elsewhere");
    let partial = first.dir.join(format!(".{}-123", native_copy_name()));
    std::fs::write(&other, b"x").expect("written");
    std::fs::write(&partial, b"x").expect("written");
    assert_eq!(prepare_ruleset(&first).expect("nothing to build"), None);
    assert!(!other.exists() && !partial.exists());

    for key in ["dd", "ee"] {
        let current = publish(signatures.path(), rulesets.path(), key);
        prepare_ruleset(&current).expect("builds").expect("a copy");
    }
    let mut names: Vec<String> = std::fs::read_dir(rulesets.path())
        .expect("reads")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, ["current", "dd-c0ffee", "ee-c0ffee"]);
    for dir in ["dd-c0ffee", "ee-c0ffee"] {
        let mut files: Vec<String> = std::fs::read_dir(rulesets.path().join(dir))
            .expect("reads")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        files.sort();
        assert_eq!(files, ["data", "generation.json", &native_copy_name()]);
    }
}
