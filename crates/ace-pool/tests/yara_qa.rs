//! PLAN.md 2.27's Done check: a match from a QA rule queues a task that records it, the match
//! appears in the QA table, and it raises no alert. The file is already in the bucket; the QA
//! match holds it there.
//!
//! The rules come from a git repository the test makes, which the core builds (2.25), and a YARA
//! pool scans with that ruleset (2.26). The core's QA recorder runs in the test. A second file,
//! which a rule that may alert matches, shows the same root mode does alert.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ace_core::rulesets::{SignatureRepo, build_new};
use ace_core::yara_qa::{QA_MODULE, recorder_worker, run_recorder};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{Core, PoolProcess, root_with_bytes, test_pool, wait_until_idle};

const MODULE: &str = "yara_scanner_v3_4";
const UUID: &str = "6a1d3b7e-2f4c-4e8a-9b0d-5c7e1f2a3b4c";

const RULES: &str = r#"
rule qa_candidate {
    meta:
        uuid = "6a1d3b7e-2f4c-4e8a-9b0d-5c7e1f2a3b4c"
        modifiers = "qa"
    strings:
        $a = "QA ONLY"
    condition:
        $a
}
rule alerting { strings: $a = "ALERT ME" condition: $a }
"#;

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

/// A QA row's uuid, version, rule, ruleset, sha256, file path and hit count.
type QaRow = (String, String, String, Option<String>, String, String, i32);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_qa_match_is_recorded_and_raises_no_alert() {
    let checkout = tempfile::tempdir().unwrap();
    let repo = checkout.path();
    git(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("yara/fixture")).unwrap();
    std::fs::write(repo.join("yara/fixture/rules.yar"), RULES).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", "a QA rule"]);
    let commit = git(repo, &["rev-parse", "HEAD"]);

    let core = Core::start(
        vec![ace_mod_yara::MANIFEST],
        &[MODULE],
        Duration::from_secs(30),
    )
    .await;
    let db = core.test_db.db();
    let ruleset = build_new(db, &core.bucket, &SignatureRepo::new(repo))
        .await
        .expect("builds")
        .expect("a ruleset");
    let stop = CancellationToken::new();
    let recorder = tokio::spawn(run_recorder(
        recorder_worker(db.clone()),
        core.bucket.clone(),
        Duration::from_secs(5),
        stop.clone(),
    ));

    let rulesets = tempfile::tempdir().unwrap();
    std::fs::set_permissions(rulesets.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = rulesets.path().to_str().unwrap();
    let settings = json!({MODULE: {"rulesets": dir}}).to_string();
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &[
            "parsers",
            "--task-user",
            "ace4-task",
            "--rulesets",
            dir,
            "--ruleset-poll-ms",
            "100",
            "--settings",
            &settings,
        ],
    ));

    let (qa_root, qa_sha256) =
        root_with_bytes(&core, "yara", b"xx QA ONLY xx", "invoice.pdf").await;
    let (alert_root, _) = root_with_bytes(&core, "yara", b"xx ALERT ME xx", "other.bin").await;
    wait_until_idle(&core, qa_root, Duration::from_secs(60)).await;
    wait_until_idle(&core, alert_root, Duration::from_secs(60)).await;
    let stderr = pool.terminate(Duration::from_secs(10));
    stop.cancel();
    recorder.await.expect("the recorder stops");

    // the scan's result queued a QA task, and the recorder ran it
    let tasks = core.tasks(qa_root).await;
    assert_eq!(
        tasks,
        [
            (MODULE.to_owned(), qa_sha256.to_hex(), "done".to_owned()),
            (QA_MODULE.to_owned(), qa_sha256.to_hex(), "done".to_owned()),
        ],
        "{stderr}"
    );

    // the QA table has the match, under the rule's uuid and its repository's commit
    let rows: Vec<QaRow> = sqlx::query_as(
        "SELECT signature_uuid, signature_version, rule, ruleset, sha256, file_path, hit_count
             FROM yara.qa_matches WHERE root_id = $1",
    )
    .bind(qa_root)
    .fetch_all(db.pool())
    .await
    .unwrap();
    println!("QA rows: {rows:?}");
    assert_eq!(
        rows,
        [(
            UUID.to_owned(),
            commit.clone(),
            "qa_candidate".to_owned(),
            Some(ruleset.key.to_hex()),
            qa_sha256.to_hex(),
            "invoice.pdf".to_owned(),
            1,
        )]
    );
    // it holds the file where it already is, for 30 days
    let held: Vec<(String, f64)> = sqlx::query_as(
        "SELECT h.pool, extract(epoch FROM h.expires_at - now())::float8 / 86400
         FROM store.holds h JOIN yara.qa_matches q ON h.holder_id = q.id::text
         WHERE h.holder_kind = 'yara_qa' AND h.sha256 = $1",
    )
    .bind(qa_sha256.to_hex())
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].0, "alert_files");
    assert!((29.9..=30.0).contains(&held[0].1), "{held:?}");

    // no alert: no detection, the root's mode unchanged, and its pass completed once
    let root: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT analysis_mode, alerted_at FROM analysis.roots WHERE id = $1")
            .bind(qa_root)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(root, ("yara".to_owned(), None));
    let detections: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.detections WHERE root_id = $1")
            .bind(qa_root)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(detections, 0);
    assert_eq!(
        ace_core::queue::completions(db, qa_root)
            .await
            .unwrap()
            .len(),
        1
    );

    // the same mode alerts on a rule that may alert, and queues no QA task for it
    let alerted: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT analysis_mode, alerted_at FROM analysis.roots WHERE id = $1")
            .bind(alert_root)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(alerted.0, "correlation");
    assert!(alerted.1.is_some());
    assert!(
        core.tasks(alert_root)
            .await
            .iter()
            .all(|(module, _, _)| module != QA_MODULE)
    );
}
