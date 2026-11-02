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
