//! PLAN.md 2.25: the core builds the signatures repository at each new commit, puts the
//! serialized ruleset in the bucket under its key, and writes the manifest as a row. The
//! repository is one this test makes, with a commit added during the test that brings a file
//! that doesn't compile. Needs the stack's postgres and bucket services.

use std::path::Path;
use std::process::Command;

use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::rulesets::{self, RULESETS, SignatureRepo, build_new};
use ace_core::testing::TestDb;
use ace_store::{BucketConfig, NodeCache, Store};
use ace_yara::{LoadOptions, Ruleset};

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=ace4 test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn write(repo: &Path, path: &str, text: &str) {
    let path = repo.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn commit(repo: &Path, message: &str) -> String {
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

const GOOD: &str = r#"rule fixture_good { strings: $a = "EVIL" condition: $a }"#;
const BROKEN: &str = "rule fixture_broken { condition: nonsense( }";
const QA: &str =
    r#"rule fixture_qa { meta: uuid = "qa-rule-uuid" modifiers = "qa" condition: false }"#;

#[tokio::test]
async fn a_new_commit_gets_a_row_that_lists_the_files_left_out() {
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().unwrap();
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).unwrap(),
    );
    let db = test_db.db();
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());

    let checkout = tempfile::tempdir().unwrap();
    let repo = checkout.path();
    git(repo, &["init", "-q"]);
    write(repo, "yara/fixture/good.yar", GOOD);
    write(repo, "hunts/readme.txt", "not rules");
    let first = commit(repo, "a good rule");
    let signatures = SignatureRepo::new(repo);

    let row = build_new(db, &bucket, &signatures)
        .await
        .expect("builds")
        .expect("a row for the first commit");
    println!("first: {row:?}");
    assert_eq!(row.commit, first);
    assert!(row.left_out.is_empty());
    // the repository's file, and the marker rule the builder adds to every ruleset (PLAN.md 7.10 batch 6)
    assert_eq!(row.files.len(), 2);
    assert_eq!(row.files[0].path, "fixture/good.yar");
    assert_eq!(row.files[0].rules, ["fixture_good"]);
    assert_eq!(
        (
            row.files[1].namespace.as_str(),
            row.files[1].path.as_str(),
            row.files[1].rules.as_slice()
        ),
        (
            "svs_marker",
            "svs_marker/svs_marker.yar",
            ["SVS_Marker".to_owned()].as_slice()
        )
    );
    assert_eq!(row.yara_x_version, ace_yara::YARA_X_VERSION);
    // the bytes are in the bucket under the key, and load
    let mut object = bucket.get(RULESETS, &row.key).await.expect("in the bucket");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut object.file, &mut bytes).unwrap();
    assert_eq!(ace_yara::ruleset::key(&bytes), row.key.to_hex());
    Ruleset::from_bytes(&bytes, &LoadOptions::default()).expect("the ruleset loads");
    // nothing new, nothing built
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());

    // the commit added during the test brings a file that doesn't compile; a file that is only
    // in the working tree isn't part of any commit and stays out of the build
    write(repo, "yara/fixture/broken.yar", BROKEN);
    let second = commit(repo, "a broken rule");
    write(repo, "yara/fixture/untracked.yar", GOOD);
    let row2 = build_new(db, &bucket, &signatures)
        .await
        .expect("builds")
        .expect("a row for the new commit");
    println!("second: {row2:?}");
    assert_eq!(row2.commit, second);
    assert_eq!(row2.left_out.len(), 1, "{:?}", row2.left_out);
    assert_eq!(row2.left_out[0].namespace, "fixture");
    assert_eq!(row2.left_out[0].path, "fixture/broken.yar");
    assert!(!row2.left_out[0].error.is_empty());
    let paths: Vec<&str> = row2.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["fixture/good.yar", "svs_marker/svs_marker.yar"]);
    assert_ne!(row2.tree, row.tree);
    // the same rules compile to the same bytes
    assert_eq!(row2.key, row.key);
    let stored: (String, serde_json::Value) =
        sqlx::query_as("SELECT commit, left_out FROM yara.rulesets WHERE id = $1")
            .bind(row2.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(stored.0, second);
    assert_eq!(stored.1[0]["path"], "fixture/broken.yar");
    assert_eq!(
        rulesets::current(db).await.unwrap().map(|r| r.id),
        Some(row2.id)
    );

    // a commit outside the signature directory reuses the build of its unchanged tree
    std::fs::remove_file(repo.join("yara/fixture/untracked.yar")).unwrap();
    write(repo, "hunts/readme.txt", "still not rules");
    let third = commit(repo, "a hunt");
    let row3 = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("a row for the third commit");
    assert_eq!(row3.commit, third);
    assert_eq!((&row3.tree, &row3.key), (&row2.tree, &row2.key));
    assert_eq!(row3.left_out, row2.left_out);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM yara.rulesets")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 3);
    assert_eq!(row3.qa_rules, Some(vec![]));

    // a rule in QA mode is in the row's qa_rules (PLAN.md 5.6)
    write(repo, "yara/fixture/qa.yar", QA);
    let fourth = commit(repo, "a rule in QA mode");
    let row4 = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("a row for the fourth commit");
    assert_eq!(row4.commit, fourth);
    let qa = row4.qa_rules.clone().expect("recorded");
    assert_eq!(qa.len(), 1, "{qa:?}");
    assert_eq!(
        (
            qa[0].path.as_str(),
            qa[0].name.as_str(),
            qa[0].uuid.as_deref()
        ),
        ("fixture/qa.yar", "fixture_qa", Some("qa-rule-uuid"))
    );

    // a row built before qa_rules existed is filled in by the next run, keeping its id and key
    sqlx::query("UPDATE yara.rulesets SET qa_rules = NULL WHERE id = $1")
        .bind(row4.id)
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(rulesets::current(db).await.unwrap().unwrap().qa_rules, None);
    let filled = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("fills the row in");
    assert_eq!((filled.id, &filled.key), (row4.id, &row4.key));
    assert_eq!(filled.qa_rules, row4.qa_rules);
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());

    // what SVS reads of each rule with a uuid is in the row (PLAN.md 7.10 batch 5): the QA rule, whose
    // tags don't count, with the hash of its own text
    let signed = row4.signatures.clone().expect("recorded");
    let qa_rule = signed
        .iter()
        .find(|s| s.uuid == "qa-rule-uuid")
        .unwrap_or_else(|| panic!("the QA rule is a signature: {signed:?}"));
    assert_eq!(
        (qa_rule.name.as_str(), qa_rule.counts),
        ("fixture_qa", false)
    );
    assert_eq!(
        qa_rule.content_hash,
        ace_yara::source::rules(QA.as_bytes())[0].content_hash
    );
    // a row built before the signatures were recorded is filled in the same way, keeping its QA rules
    sqlx::query("UPDATE yara.rulesets SET signatures = NULL WHERE id = $1")
        .bind(row4.id)
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        rulesets::current(db).await.unwrap().unwrap().signatures,
        None
    );
    let filled = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("fills the row in");
    assert_eq!((filled.id, &filled.key), (row4.id, &row4.key));
    assert_eq!(
        (&filled.signatures, &filled.qa_rules),
        (&row4.signatures, &row4.qa_rules)
    );
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());

    // ace3's tests/saq/svs/test_marker_rule.py, the file's writing: the marker rule is in the ruleset
    // the pools scan with (test_install_writes_the_rule, test_default_path_is_under_the_configured_
    // signature_dir), and finds a marker in a file's bytes
    let current = rulesets::current(db).await.unwrap().expect("a ruleset");
    let mut object = bucket
        .get(RULESETS, &current.key)
        .await
        .expect("in the bucket");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut object.file, &mut bytes).unwrap();
    let loaded = Ruleset::from_bytes(&bytes, &LoadOptions::default()).expect("loads");
    let outcome = ace_yara::Scanner::new(&loaded)
        .scan(&ace_yara::ScanRequest {
            data: b"whoami & REM svs-abcdefghijklmnopqrstuvwxyz\r\n",
            path: "run.cmd",
            mime_type: "text/plain",
            meta_tags: &[],
            timeout: None,
        })
        .expect("scans");
    assert!(
        outcome
            .matches
            .iter()
            .any(|m| m.rule == "SVS_Marker" && m.namespace == "svs_marker"),
        "{:?}",
        outcome.matches
    );
    // nothing is built again while the built-ins are this build's (test_install_leaves_an_unchanged_
    // rule_alone), and a row built before the builder added any is built again, in place, with them
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT built_ins FROM yara.rulesets WHERE id = $1")
            .bind(current.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(recorded, Some(rulesets::built_ins()));
    sqlx::query("UPDATE yara.rulesets SET built_ins = NULL, key = repeat('0', 64), files = '[]'")
        .execute(db.pool())
        .await
        .unwrap();
    let rebuilt = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("builds it again");
    assert_eq!((rebuilt.id, &rebuilt.key), (current.id, &current.key));
    assert!(
        rebuilt
            .files
            .iter()
            .any(|f| f.path == "svs_marker/svs_marker.yar")
    );
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());

    // a file of the same namespace and name in the repository is replaced by ACE's
    // (test_install_replaces_a_changed_rule); another file of the namespace stays
    write(
        repo,
        "yara/svs_marker/svs_marker.yar",
        "rule old { condition: false }\n",
    );
    write(
        repo,
        "yara/svs_marker/other.yar",
        "rule beside { condition: false }\n",
    );
    commit(repo, "a marker rule of the repository's own");
    let replaced = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("a row for the commit");
    let marker: Vec<(&str, &[String])> = replaced
        .files
        .iter()
        .filter(|f| f.namespace == "svs_marker")
        .map(|f| (f.path.as_str(), f.rules.as_slice()))
        .collect();
    assert_eq!(
        marker,
        [
            ("svs_marker/other.yar", ["beside".to_owned()].as_slice()),
            (
                "svs_marker/svs_marker.yar",
                ["SVS_Marker".to_owned()].as_slice()
            ),
        ]
    );
}
