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
            "user.name=ace-rs test",
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
        &BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).unwrap(),
    )
    .await;
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

    // a file yara-x would overflow its stack on is left out with why, and the build goes on: before
    // `ace_yara::guard` a literal of this many escapes aborted the core (PLAN.md 7.16)
    write(
        repo,
        "yara/fixture/hostile_escapes.yar",
        &format!(
            "rule hostile {{ strings: $a = \"{}\" condition: $a }}",
            "\\\\".repeat(20_000)
        ),
    );
    write(
        repo,
        "yara/fixture/hostile_nesting.yar",
        &format!(
            "rule hostile {{ condition: {}true{} }}",
            "(".repeat(20_000),
            ")".repeat(20_000)
        ),
    );
    let hostile = commit(repo, "two files past the guard's bounds");
    let guarded = build_new(db, &bucket, &signatures)
        .await
        .expect("the build survives")
        .expect("a row for the commit");
    assert_eq!(guarded.commit, hostile);
    let left_out: Vec<(&str, bool)> = guarded
        .left_out
        .iter()
        .map(|f| {
            (
                f.path.as_str(),
                f.error.contains("escape sequences") || f.error.contains("nests brackets"),
            )
        })
        .collect();
    assert_eq!(
        left_out,
        [
            ("fixture/broken.yar", false),
            ("fixture/hostile_escapes.yar", true),
            ("fixture/hostile_nesting.yar", true),
        ]
    );
    assert!(guarded.files.iter().any(|f| f.path == "fixture/good.yar"));
}

/// One of the observables enabled for detection, written as the service stores it.
async fn detect(db: &ace_core::Db, kind: &str, value: &str, matching: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO lists.entries
             (list, match, value, ignore_case, observable_type, created_by, updated_by)
         VALUES ('observable_detection', $3, $2, false, $1, $4::jsonb, $4::jsonb)
         RETURNING id",
    )
    .bind(kind)
    .bind(value)
    .bind(matching)
    .bind(serde_json::json!({"kind": "internal", "id": "test"}))
    .fetch_one(db.pool())
    .await
    .expect("adds the detection")
}

async fn loaded(bucket: &Bucket, key: &ace_results::Sha256) -> Ruleset {
    let mut object = bucket.get(RULESETS, key).await.expect("in the bucket");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut object.file, &mut bytes).unwrap();
    Ruleset::from_bytes(&bytes, &LoadOptions::default()).expect("loads")
}

fn export_files(row: &rulesets::RulesetRow) -> Vec<&str> {
    row.files
        .iter()
        .filter(|f| f.namespace == "observable_export")
        .map(|f| f.path.as_str())
        .collect()
}

/// PLAN.md 7.16: the observables enabled for detection are rules of the ruleset, built again in place
/// whenever what would be exported changes: a detection added, expired or removed, or the export's
/// settings. ace3's `test_export_skips_when_nothing_changed`,
/// `test_export_republishes_when_the_boundary_config_changes` and `test_export_prunes_stale_rule_files`,
/// where the fingerprint is the row's `built_ins` and the rule files are the ruleset's namespace.
#[tokio::test]
async fn the_detections_are_rules_of_the_ruleset_and_follow_the_list() {
    use ace_core::rulesets::{ExportConfig, build_new_with};
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().unwrap();
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).unwrap(),
    )
    .await;
    let db = test_db.db();
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
    let checkout = tempfile::tempdir().unwrap();
    let repo = checkout.path();
    git(repo, &["init", "-q"]);
    write(repo, "yara/fixture/good.yar", GOOD);
    // the repository's own rules under the export's name, an index among them: they never load
    write(
        repo,
        "yara/observable_export/planted.yar",
        "rule obsd_index { meta: e999999 = \"75726c:706c616e746564\" condition: false }\n\
         rule planted { strings: $a = \"PLANTED\" condition: $a }\n",
    );
    let head = commit(repo, "rules");
    let signatures = SignatureRepo::new(repo);

    // with no detection nothing is exported, and the row is as it was before 7.16
    let empty = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("a row");
    assert!(export_files(&empty).is_empty(), "{:?}", empty.files);
    assert_eq!(empty.detection_export, None);
    let recorded = |id: i64| async move {
        sqlx::query_scalar::<_, Option<String>>("SELECT built_ins FROM yara.rulesets WHERE id = $1")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap()
    };
    assert_eq!(recorded(empty.id).await, Some(rulesets::built_ins()));
    assert_eq!(loaded(&bucket, &empty.key).await.detection(999_999), None);

    // detections of an exported type, of a type that extends one, of a type that isn't exported, one
    // that matches by a pattern, one under the minimum length and one that expired
    let fqdn = detect(db, "fqdn", "evil.example.com", "exact").await;
    let reply_to = detect(db, "email_reply_to", "reply@evil.example.com", "exact").await;
    detect(db, "hostname", "not-an-exported-type", "exact").await;
    detect(db, "fqdn", "pattern\\.example\\.com", "regex").await;
    detect(db, "fqdn", "a.io", "exact").await;
    let expired = detect(db, "fqdn", "expired.example.com", "exact").await;
    sqlx::query("UPDATE lists.entries SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(expired)
        .execute(db.pool())
        .await
        .unwrap();
    let built = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("built again");
    assert_eq!(
        (built.id, &built.commit),
        (empty.id, &head),
        "the commit's row, in place"
    );
    assert_ne!(built.key, empty.key);
    assert_eq!(
        export_files(&built),
        [
            "observable_export/email_address.yar",
            "observable_export/fqdn.yar",
            "observable_export/obsd-index.yar"
        ]
    );
    let report = built.detection_export.clone().expect("a report");
    assert_eq!(report.exported(), 2);
    assert!(
        report.skipped.is_empty() && report.error.is_none(),
        "{report:?}"
    );
    assert_ne!(recorded(built.id).await, Some(rulesets::built_ins()));
    let ruleset = loaded(&bucket, &built.key).await;
    assert_eq!(ruleset.detection(fqdn), Some(("fqdn", "evil.example.com")));
    assert_eq!(
        ruleset.detection(reply_to),
        Some(("email_reply_to", "reply@evil.example.com"))
    );
    assert_eq!(ruleset.detection(expired), None);
    assert_eq!(
        ruleset.detection(999_999),
        None,
        "the repository's index isn't read"
    );
    let scan = |ruleset: &Ruleset, data: &[u8]| {
        ace_yara::Scanner::new(ruleset)
            .scan(&ace_yara::ScanRequest {
                data,
                path: "page.html",
                mime_type: "text/html",
                meta_tags: &[],
                timeout: None,
            })
            .expect("scans")
            .matches
            .into_iter()
            .map(|m| {
                let ids = m
                    .patterns
                    .iter()
                    .map(|p| p.identifier.clone())
                    .collect::<Vec<_>>();
                (m.rule, ids)
            })
            .collect::<Vec<_>>()
    };
    let content =
        b"visit evil.example.com. not acme-evil.example.com, expired.example.com or PLANTED";
    assert_eq!(
        scan(&ruleset, content),
        [("detect_fqdn".to_owned(), vec![format!("$obsd_{fqdn}")])]
    );

    // nothing changed, so nothing is built (test_export_skips_when_nothing_changed)
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());

    // the export's settings changed and the detections didn't: built again
    // (test_export_republishes_when_the_boundary_config_changes)
    let unbounded = ExportConfig {
        boundaries: Default::default(),
        ..ExportConfig::default()
    };
    let rebuilt = build_new_with(db, &bucket, &signatures, Some(&unbounded))
        .await
        .unwrap()
        .expect("built again");
    assert_eq!(rebuilt.id, built.id);
    assert_ne!(rebuilt.key, built.key);
    let text = loaded(&bucket, &rebuilt.key).await;
    // a text string with fullword still refuses the longer host; without a boundary it's a text string
    assert_eq!(
        scan(&text, b"evil.example.com"),
        [("detect_fqdn".to_owned(), vec![format!("$obsd_{fqdn}")])]
    );
    assert!(
        build_new_with(db, &bucket, &signatures, Some(&unbounded))
            .await
            .unwrap()
            .is_none()
    );

    // a new commit with the same signature directory and the same export takes the earlier build
    write(repo, "hunts/readme.txt", "not rules");
    let second = commit(repo, "outside the signature directory");
    let reused = build_new_with(db, &bucket, &signatures, Some(&unbounded))
        .await
        .unwrap()
        .expect("a row for the commit");
    assert_eq!((&reused.commit, &reused.key), (&second, &rebuilt.key));
    assert_eq!(reused.detection_export, rebuilt.detection_export);

    // a detection that expires leaves the next build, and the type with nothing left has no file
    // (test_export_prunes_stale_rule_files)
    sqlx::query("UPDATE lists.entries SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(fqdn)
        .execute(db.pool())
        .await
        .unwrap();
    let pruned = build_new(db, &bucket, &signatures)
        .await
        .unwrap()
        .expect("built again");
    assert_eq!(
        export_files(&pruned),
        [
            "observable_export/email_address.yar",
            "observable_export/obsd-index.yar"
        ]
    );
    assert!(scan(&loaded(&bucket, &pruned.key).await, content).is_empty());

    // turned off, the ruleset has no rule of the namespace, the repository's own included
    let off = build_new_with(db, &bucket, &signatures, None)
        .await
        .unwrap()
        .expect("built again");
    assert!(export_files(&off).is_empty());
    assert_eq!(off.detection_export, None);
    assert_eq!(recorded(off.id).await, Some(rulesets::built_ins()));
    assert!(
        build_new_with(db, &bucket, &signatures, None)
            .await
            .unwrap()
            .is_none()
    );

    // and with the list empty the default export is the same ruleset
    sqlx::query("DELETE FROM lists.entries")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(build_new(db, &bucket, &signatures).await.unwrap().is_none());
}

/// The overlay's `yara_export:` section over ace3's defaults: a key left out keeps the default,
/// `enabled: false` turns the export off, and a section the export can't use is refused when `ace serve`
/// starts.
#[test]
fn the_overlay_s_yara_export_section_is_checked() {
    use ace_core::rulesets::{ExportConfig, export_config};
    use ace_sdk::overlay::Overlay;
    let section = |yaml: &str| Overlay::from_yaml(yaml).expect("parses").yara_export;
    assert_eq!(
        export_config(&section("")),
        Ok(Some(ExportConfig::default()))
    );
    assert_eq!(
        export_config(&section("yara_export:\n  enabled: false\n")),
        Ok(None)
    );
    let set = export_config(&section(
        "yara_export:\n  export_list: [fqdn, url]\n  export_minimum_length: 8\n  \
         string_modifiers:\n    default: ascii nocase\n  string_boundaries:\n    url: hostname\n  \
         templates:\n    fqdn: |\n      rule detect_TEMPLATE_RULE_NAME {\n        strings:\n      \
         TEMPLATE_STRINGS\n        condition:\n          any of ($obsd_*)\n      }\n",
    ))
    .expect("a section the export takes")
    .expect("on");
    assert_eq!(set.export_list, ["fqdn", "url"]);
    assert_eq!(set.minimum_length, 8);
    assert_eq!(set.string_modifiers("fqdn"), "ascii nocase");
    assert_eq!(set.boundaries.len(), 1);
    assert!(set.templates["fqdn"].starts_with("rule detect_TEMPLATE_RULE_NAME {"));
    // ace3's other templates are still there
    assert!(set.templates.contains_key("default") && set.templates.contains_key("ip"));
    for (yaml, says) in [
        (
            "yara_export:\n  string_boundaries:\n    url: nonsense\n",
            "string_boundaries.url",
        ),
        (
            "yara_export:\n  string_modifiers:\n    fqdn: ascii xor\n",
            "string_modifiers.fqdn",
        ),
        ("yara_export:\n  export_list: ['../etc']\n", "export_list"),
        (
            "yara_export:\n  templates:\n    fqdn: rule broken\n",
            "TEMPLATE_STRINGS",
        ),
        // off, and still checked
        (
            "yara_export:\n  enabled: false\n  export_list: ['a b']\n",
            "export_list",
        ),
    ] {
        let error = export_config(&section(yaml)).unwrap_err();
        assert!(error.contains(says), "{yaml}: {error}");
    }
    assert!(Overlay::from_yaml("yara_export:\n  max_strings_per_rule: 5\n").is_err());
}
