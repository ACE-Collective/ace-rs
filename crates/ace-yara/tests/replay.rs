//! PLAN.md 1.10: the replay child reads replay.py's job.json and returns child.py's result,
//! with offsets.

mod common;

use std::path::Path;

use ace_yara::mime::{DEFAULT_DATABASE, MimeTyper};
use ace_yara::replay::{self, RESULT_FILE};
use serde_json::{Value, json};

/// A working directory with the job and each unit's file, as replay.py lays them out.
fn workdir(namespaces: Value, units: &[(&str, &[u8], &[&str])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut job_units = Vec::new();
    for (id, (file_path, data, tags)) in units.iter().enumerate() {
        let path = dir.path().join(format!("u/{id}/files/{file_path}"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        job_units.push(json!({"id": id, "path": path, "meta_tags": tags}));
    }
    let job = json!({
        "version": 1,
        "tree_root": common::fixture(""),
        "file_timeout": 10,
        "namespaces": namespaces,
        "units": job_units,
    });
    std::fs::write(dir.path().join("job.json"), job.to_string()).unwrap();
    dir
}

fn namespace(name: &str, dir: &str, files: &[&str]) -> Value {
    let dir = common::fixture(dir);
    let files: Vec<_> = files.iter().map(|f| dir.join(f)).collect();
    json!({"name": name, "directory": dir, "files": files})
}

fn run(dir: &Path) -> Value {
    let typer = MimeTyper::open(Path::new(DEFAULT_DATABASE)).unwrap();
    let result = replay::run(dir, &typer).unwrap();
    replay::write_json(dir, RESULT_FILE, &result).unwrap();
    serde_json::from_slice(&std::fs::read(dir.join(RESULT_FILE)).unwrap()).unwrap()
}

#[test]
fn matches_carry_offsets_and_the_filter_keeps_what_it_dropped() {
    let dir = workdir(
        json!([
            namespace("scan", "scan/signatures/scan", &["rules.yar"]),
            namespace(
                "alpha",
                "load/signatures/alpha",
                &["good.yar", "broken.yar"]
            ),
        ]),
        &[
            ("run.ps1", b"xx needle yy ABC needle", &[]),
            ("hello.txt", b"hello needle", &["type=email.attachment"]),
        ],
    );
    let result = run(dir.path());

    assert_eq!(result["version"], 1);
    assert_eq!(result["child"], "ace4");
    assert_eq!(result["ruleset_error"], Value::Null);

    // Each file alone: the broken one is reported with its error, the others with their rules.
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    let broken = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("broken.yar"));
    assert!(
        broken.unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("no_such_identifier")
    );
    let good = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("good.yar"))
        .unwrap();
    assert_eq!(good["rules"][0]["name"], "alpha_good");
    assert_eq!(
        good["rules"][0]["meta"]["uuid"],
        "2f0d2d7e-0000-4000-8000-000000000001"
    );

    // Each namespace is timed.
    assert_eq!(result["namespaces"]["scan"]["rules"], 5);
    assert_eq!(result["namespaces"]["alpha"]["rules"], 1);

    // Unit 0: two_patterns with its offsets; path_externals from the unit's path. The tagged
    // and PDF-only rules matched and were dropped by the filter.
    let unit = &result["units"]["0"];
    let two = unit["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["rule"] == "two_patterns")
        .unwrap();
    assert_eq!(two["namespace"], "scan");
    assert_eq!(
        two["strings"],
        json!([[3, "$a", 6], [17, "$a", 6], [13, "$b", 3]])
    );
    let kept: Vec<_> = unit["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["rule"].as_str().unwrap())
        .collect();
    // path_externals wants filepath "alert/files/run.ps1"; a unit's path is where it was
    // written in the working directory, as in ace3's replay.
    assert_eq!(kept, ["two_patterns"]);
    let dropped: Vec<_> = unit["dropped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["rule"].as_str().unwrap())
        .collect();
    assert_eq!(dropped, ["tagged_attachment", "pdf_only"]);
    assert_eq!(unit["errors"], json!([]));

    // Unit 1 has the tag, so tagged_attachment is kept; alpha_good matches "hello".
    let unit = &result["units"]["1"];
    let kept: Vec<_> = unit["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["rule"].as_str().unwrap())
        .collect();
    assert!(kept.contains(&"tagged_attachment"), "{kept:?}");
    assert!(kept.contains(&"alpha_good"), "{kept:?}");
}

#[test]
fn files_that_compile_alone_but_not_together_are_a_ruleset_error() {
    let dir = workdir(
        json!([namespace(
            "alpha",
            "load/duplicate/alpha",
            &["one.yar", "two.yar"]
        )]),
        &[("x.txt", b"x", &[])],
    );
    let result = run(dir.path());
    assert!(
        result["ruleset_error"]
            .as_str()
            .unwrap()
            .contains("same_name")
    );
    assert_eq!(result["files"].as_array().unwrap().len(), 2);
    assert_eq!(result["units"], json!({}));
}

#[test]
fn the_slowest_rules_are_reported_only_with_rules_profiling() {
    // yara-x reports only rules that took over 100 ms in all. The quadratic rule takes
    // about filesize squared steps, so 1,200 zero bytes keep it busy for longer than that,
    // and well under the timeout.
    let zeros = vec![0u8; 1_200];
    let dir = workdir(
        json!([
            namespace("scan", "scan/signatures/scan", &["rules.yar"]),
            namespace("loops", "scan/slow/loops", &["slow.yar"]),
        ]),
        &[("zeros.bin", &zeros, &[])],
    );
    let started = std::time::Instant::now();
    let result = run(dir.path());
    println!("replay took {:?}", started.elapsed());
    assert_eq!(result["units"]["0"]["errors"], json!([]));
    if cfg!(feature = "rules-profiling") {
        let slowest = result["slowest_rules"].as_array().unwrap();
        println!("{slowest:#?}");
        assert_eq!(slowest[0]["namespace"], "loops");
        assert_eq!(slowest[0]["rule"], "quadratic");
        assert!(slowest[0]["condition_seconds"].as_f64().unwrap() > 0.1);
    } else {
        assert_eq!(result.get("slowest_rules"), None);
    }
}

// ---- PLAN.md 7.10 batch 3: ace3's tests/saq/svs/yara/test_child.py ----
//
// The child is held to what the YARA pool does with the same rules: `load_dir`, which the ruleset build
// and the pool load with, and `Scanner`. Where ace4's loader differs from yara_scanner (a file that isn't
// UTF-8, an include that can't be read), the child does what the pool does, and the case says so.
// test_child.py's `test_the_sandboxed_scan_cannot_read_saq_home` is ace-site-example's
// `a_contained_replay_reads_only_its_validation`, which runs this binary's contained replay.

const PATH_RULES: &str = r#"
rule by_file_ext { meta: uuid = "u-ext" file_ext = "txt" strings: $a = "evil" condition: $a }
rule by_file_name { meta: uuid = "u-name" file_name = "re:^inv" strings: $a = "evil" condition: $a }
rule by_extension { meta: uuid = "u-extension" strings: $a = "evil" condition: $a and extension == "txt" }
rule by_filename { meta: uuid = "u-filename" strings: $a = "evil" condition: $a and filename == "invoice.txt" }
rule by_filepath { meta: uuid = "u-filepath" strings: $a = "evil" condition: $a and filepath contains "/files/" }
rule by_meta_tags { meta: uuid = "u-tags" meta_tags = "kind=email" strings: $a = "evil" condition: $a }
rule not_meta_tags { meta: uuid = "u-not-tags" meta_tags = "!kind=email" strings: $a = "evil" condition: $a }
rule by_mime_type { meta: uuid = "u-mime" mime_type = "text/plain" strings: $a = "evil" condition: $a }
rule plain { meta: uuid = "u-plain" strings: $a = "evil" condition: $a }
"#;

/// A namespace's name and its files' names and bytes.
type NamespaceFiles<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);

/// A signature directory under `root/tree/yara`, one subdirectory per namespace.
fn signature_dir(root: &Path, namespaces: &[NamespaceFiles<'_>]) -> std::path::PathBuf {
    let dir = root.join("tree").join("yara");
    for (namespace, files) in namespaces {
        std::fs::create_dir_all(dir.join(namespace)).unwrap();
        for (name, content) in *files {
            std::fs::write(dir.join(namespace).join(name), content).unwrap();
        }
    }
    dir
}

fn job_namespaces(signature_dir: &Path) -> Vec<Value> {
    ace_yara::discover(signature_dir)
        .unwrap()
        .into_iter()
        .map(|n| json!({"name": n.name, "directory": n.dir, "files": n.files}))
        .collect()
}

/// The child over `namespaces` and `units`, in this process.
fn child(root: &Path, signature_dir: &Path, namespaces: Vec<Value>, units: Vec<Value>) -> Value {
    let job = json!({
        "version": 1,
        "tree_root": signature_dir.parent().unwrap(),
        "file_timeout": 10,
        "namespaces": namespaces,
        "units": units,
    });
    std::fs::write(root.join("job.json"), job.to_string()).unwrap();
    run(root)
}

/// A unit's file at `root/u/<id>/files/<file_path>`.
fn sample(root: &Path, id: u64, file_path: &str, content: &[u8]) -> std::path::PathBuf {
    let path = root.join(format!("u/{id}/files/{file_path}"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path
}

fn rules_of(unit: &Value, key: &str) -> Vec<String> {
    let mut rules: Vec<String> = unit["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m[key].as_str().unwrap().to_owned())
        .collect();
    rules.sort();
    rules
}

/// test_child.py's `test_matches_agree_with_the_yara_service`, over its four cases: the path externals, the
/// meta filters and the mime type behave as the YARA pool's scan does.
#[test]
fn matches_agree_with_the_yara_pool() {
    let typer = MimeTyper::open(Path::new(DEFAULT_DATABASE)).unwrap();
    for (file_path, meta_tags) in [
        ("invoice.txt", vec!["kind=email"]),
        ("invoice.txt", vec![]),
        ("attachments/notes", vec!["kind=other"]),
        ("report.pdf.txt", vec![]),
    ] {
        let root = tempfile::tempdir().unwrap();
        let dir = signature_dir(
            root.path(),
            &[("acme", &[("paths.yar", PATH_RULES.as_bytes())])],
        );
        let path = sample(root.path(), 0, file_path, b"some evil text\n");
        let result = child(
            root.path(),
            &dir,
            job_namespaces(&dir),
            vec![json!({"id": 0, "path": path, "meta_tags": meta_tags})],
        );

        let loaded = ace_yara::load_dir(&dir, &ace_yara::LoadOptions::default()).unwrap();
        let mut scanner = ace_yara::Scanner::new(&loaded.ruleset);
        let data = std::fs::read(&path).unwrap();
        let tags: Vec<String> = meta_tags.iter().map(|t| (*t).to_owned()).collect();
        let pool = scanner
            .scan(&ace_yara::ScanRequest {
                data: &data,
                path: &path.to_string_lossy(),
                mime_type: &typer.mime_type(&data).unwrap(),
                meta_tags: &tags,
                timeout: None,
            })
            .unwrap();
        let mut expected: Vec<String> = pool.matches.iter().map(|m| m.rule.clone()).collect();
        expected.sort();

        let unit = &result["units"]["0"];
        assert_eq!(
            rules_of(unit, "rule"),
            expected,
            "{file_path} {meta_tags:?}"
        );
        assert!(rules_of(unit, "namespace").iter().all(|n| n == "acme"));
    }
}

/// test_child.py's `test_a_file_that_does_not_compile_drops_only_its_rules`.
#[test]
fn a_file_that_does_not_compile_drops_only_its_rules() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "good.yar",
                    b"rule good { meta: uuid = \"u-good\" strings: $a = \"evil\" condition: $a }\n",
                ),
                (
                    "broken.yar",
                    b"rule broken { meta: uuid = \"u-broken\" condition: nope }\n",
                ),
            ],
        )],
    );
    let path = sample(root.path(), 0, "x.bin", b"some evil text\n");
    let result = child(
        root.path(),
        &dir,
        job_namespaces(&dir),
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );

    let files: std::collections::BTreeMap<String, &Value> = result["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                Path::new(f["path"].as_str().unwrap())
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                f,
            )
        })
        .collect();
    assert!(
        files["broken.yar"]["error"]
            .as_str()
            .unwrap()
            .contains("nope")
    );
    assert_eq!(files["good.yar"]["rules"][0]["name"], "good");
    assert_eq!(result["ruleset_error"], Value::Null);
    assert_eq!(rules_of(&result["units"]["0"], "rule"), ["good"]);

    // as the pool loads it
    let loaded = ace_yara::load_dir(&dir, &ace_yara::LoadOptions::default()).unwrap();
    assert_eq!(loaded.left_out().count(), 1);
}

/// test_child.py's `test_a_ruleset_that_does_not_compile_together_would_not_load`.
#[test]
fn a_ruleset_that_does_not_compile_together_would_not_load() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "one.yar",
                    b"rule same { strings: $a = \"evil\" condition: $a }\n",
                ),
                (
                    "two.yar",
                    b"rule same { strings: $a = \"good\" condition: $a }\n",
                ),
            ],
        )],
    );
    let path = sample(root.path(), 0, "x.bin", b"some evil text\n");
    let result = child(
        root.path(),
        &dir,
        job_namespaces(&dir),
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );
    assert!(
        result["ruleset_error"]
            .as_str()
            .unwrap()
            .contains("duplicate"),
        "{}",
        result["ruleset_error"]
    );
    assert_eq!(result["units"], json!({}));
    assert!(ace_yara::load_dir(&dir, &ace_yara::LoadOptions::default()).is_err());

    // the same rule name in two namespaces is fine
    let ok = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        ok.path(),
        &[
            (
                "one",
                &[(
                    "one.yar",
                    b"rule same { strings: $a = \"evil\" condition: $a }\n",
                )],
            ),
            (
                "two",
                &[(
                    "two.yar",
                    b"rule same { strings: $a = \"evil\" condition: $a }\n",
                )],
            ),
        ],
    );
    let path = sample(ok.path(), 0, "x.bin", b"some evil text\n");
    let result = child(
        ok.path(),
        &dir,
        job_namespaces(&dir),
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );
    assert_eq!(result["ruleset_error"], Value::Null);
    assert_eq!(rules_of(&result["units"]["0"], "namespace"), ["one", "two"]);
}

/// test_child.py's `test_a_file_that_is_not_utf8_fails_the_whole_load`. ace4's loader leaves such a file out
/// alone (`ace_yara::load`'s docs), so the child does: the rest loads and scans.
#[test]
fn a_file_that_is_not_utf8_is_left_out_as_the_pool_leaves_it_out() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "good.yar",
                    b"rule good { strings: $a = \"evil\" condition: $a }\n",
                ),
                ("latin1.yar", b"rule caf\xe9 { condition: false }\n"),
            ],
        )],
    );
    let path = sample(root.path(), 0, "x.bin", b"some evil text\n");
    let result = child(
        root.path(),
        &dir,
        job_namespaces(&dir),
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );
    assert_eq!(result["ruleset_error"], Value::Null);
    let left_out: Vec<&Value> = result["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| !f["error"].is_null())
        .collect();
    assert_eq!(left_out.len(), 1);
    assert!(
        left_out[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("latin1.yar")
    );
    assert_eq!(rules_of(&result["units"]["0"], "rule"), ["good"]);
    assert_eq!(
        ace_yara::load_dir(&dir, &ace_yara::LoadOptions::default())
            .unwrap()
            .left_out()
            .count(),
        1
    );
}

/// test_child.py's `test_a_missing_include_compiles_and_is_reported`. yara_scanner compiles a missing include
/// as empty; ace4's loader leaves the file that includes it out, with the include's error, and the child
/// reports that. An include that resolves compiles.
#[test]
fn a_missing_include_leaves_its_file_out_and_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "inc.yar",
                    b"include \"common.yar\"\nrule uses { strings: $a = \"evil\" condition: $a }\n",
                ),
                (
                    "local.yar",
                    b"include \"../../shared/strings.yar\"\nrule shared { condition: false }\n",
                ),
            ],
        )],
    );
    std::fs::create_dir_all(root.path().join("tree/shared")).unwrap();
    std::fs::write(root.path().join("tree/shared/strings.yar"), "").unwrap();
    let result = child(root.path(), &dir, job_namespaces(&dir), vec![]);
    assert_eq!(result["ruleset_error"], Value::Null);
    let error_of = |name: &str| {
        result["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["path"].as_str().unwrap().ends_with(name))
            .unwrap()["error"]
            .clone()
    };
    assert!(
        error_of("inc.yar").as_str().unwrap().contains("common.yar"),
        "{}",
        error_of("inc.yar")
    );
    assert_eq!(error_of("local.yar"), Value::Null);
}

/// test_child.py's `test_compiler_warnings_and_rules_are_reported`.
#[test]
fn compiler_warnings_and_rules_are_reported() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[(
                "slow.yar",
                b"rule slow { meta: uuid = \"u-slow\" enabled = false strings: $a = { 00 ?? } condition: $a }\nprivate rule helper { condition: true }\n",
            )],
        )],
    );
    let result = child(root.path(), &dir, job_namespaces(&dir), vec![]);
    assert!(
        !result["warnings"].as_array().unwrap().is_empty(),
        "{result}"
    );
    assert_eq!(result["namespaces"]["acme"]["rules"], 2);
    let [entry] = &result["files"].as_array().unwrap()[..] else {
        panic!("one file")
    };
    let rules: std::collections::BTreeMap<&str, (bool, &Value)> = entry["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap(),
                (r["private"].as_bool().unwrap(), &r["meta"]),
            )
        })
        .collect();
    assert_eq!(
        rules["slow"],
        (false, &json!({"uuid": "u-slow", "enabled": false}))
    );
    assert_eq!(rules["helper"], (true, &json!({})));
}

/// test_child.py's `test_two_namespaces_of_one_directory_stay_apart`: two of a job's namespaces can share a
/// directory, and each still matches under its own name.
#[test]
fn two_namespaces_of_one_directory_stay_apart() {
    let root = tempfile::tempdir().unwrap();
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "rules.yar",
                    b"include \"common.yar\"\nrule same { strings: $a = \"evil\" condition: $a }\n",
                ),
                ("common.yar", b""),
            ],
        )],
    );
    let path = sample(root.path(), 0, "x.bin", b"some evil text\n");
    let directory = dir.join("acme");
    let namespace = |name: &str| json!({"name": name, "directory": directory, "files": [directory.join("rules.yar")]});
    let result = child(
        root.path(),
        &dir,
        vec![namespace("acme"), namespace("alias")],
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );
    assert_eq!(result["ruleset_error"], Value::Null);
    assert_eq!(result["include_warnings"], json!([]));
    assert_eq!(
        rules_of(&result["units"]["0"], "namespace"),
        ["acme", "alias"]
    );
}

/// A rule file yara-x would overflow its stack on (`ace_yara::guard`) is one more file with an error, and
/// the replay goes on with the rest: a base or head that holds one fails that file, not the child.
#[test]
fn a_file_past_the_guard_s_bounds_drops_only_its_rules() {
    let root = tempfile::tempdir().unwrap();
    let escapes = format!(
        "rule deep {{ meta: uuid = \"u-deep\" strings: $a = \"{}\" condition: $a }}\n",
        "\\\\".repeat(20_000)
    );
    let nested = format!(
        "rule nested {{ meta: uuid = \"u-nested\" condition: {}true{} }}\n",
        "(".repeat(20_000),
        ")".repeat(20_000)
    );
    let dir = signature_dir(
        root.path(),
        &[(
            "acme",
            &[
                (
                    "good.yar",
                    b"rule good { meta: uuid = \"u-good\" strings: $a = \"evil\" condition: $a }\n",
                ),
                ("escapes.yar", escapes.as_bytes()),
                ("nested.yar", nested.as_bytes()),
            ],
        )],
    );
    let path = sample(root.path(), 0, "x.bin", b"some evil text\n");
    let result = child(
        root.path(),
        &dir,
        job_namespaces(&dir),
        vec![json!({"id": 0, "path": path, "meta_tags": []})],
    );
    let error = |name: &str| {
        result["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["path"].as_str().unwrap().ends_with(name))
            .unwrap()["error"]
            .as_str()
            .map(str::to_owned)
    };
    assert_eq!(error("good.yar"), None);
    assert!(error("escapes.yar").unwrap().contains("escape sequences"));
    assert!(error("nested.yar").unwrap().contains("nests brackets"));
    assert_eq!(result["ruleset_error"], Value::Null);
    assert_eq!(rules_of(&result["units"]["0"], "rule"), ["good"]);
}
