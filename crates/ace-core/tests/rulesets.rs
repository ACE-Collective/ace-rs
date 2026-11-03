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
    assert_eq!(row.files.len(), 1);
    assert_eq!(row.files[0].path, "fixture/good.yar");
    assert_eq!(row.files[0].rules, ["fixture_good"]);
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
    assert_eq!(paths, ["fixture/good.yar"]);
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
}
