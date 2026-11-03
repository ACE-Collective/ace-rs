//! PLAN.md 2.26's Done check: a YARA pool loads the ruleset the core names by its hash, switches
//! to a new one only after it has loaded, and a switch during a stream of scans drops none.
//! Every match records its ruleset's key and commit.
//!
//! The signatures repository is one the test makes; a commit added during the stream changes the
//! rules, and the core builds it (2.25). The pool is the test pool binary in its parsers mode,
//! with task processes as the dev image's ace4-task user.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ace_core::rulesets::{SignatureRepo, build_new};
use serde_json::json;
use uuid::Uuid;

use common::{Core, PoolProcess, root_with_bytes, test_pool, wait_until_idle};

const MODULE: &str = "yara_scanner_v3_4";

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

fn commit_rules(repo: &Path, rules: &str, message: &str) -> String {
    let dir = repo.join("yara/fixture");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rules.yar"), rules).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

const FIRST: &str = r#"rule gen_one { strings: $a = "EVIL" condition: $a }"#;
const SECOND: &str = r#"
rule gen_one { strings: $a = "EVIL" condition: $a }
rule gen_two { strings: $a = "EVIL" condition: $a }
"#;

/// The YARA task's state and its result's (rules, ruleset, commit), for one root.
async fn scanned(core: &Core, root: Uuid) -> (String, Vec<String>, Option<String>, Option<String>) {
    let state: String = sqlx::query_scalar(
        "SELECT state::text FROM queue.tasks WHERE root_id = $1 AND module = $2",
    )
    .bind(root)
    .bind(MODULE)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task");
    let details: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM analysis.results WHERE root_id = $1 AND module = $2",
    )
    .bind(root)
    .bind(MODULE)
    .fetch_optional(core.test_db.db().pool())
    .await
    .expect("the result");
    let Some(details) = details else {
        return (state, Vec::new(), None, None);
    };
    let results = details["scan_results"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let rules = results
        .iter()
        .map(|r| r["rule"].as_str().unwrap_or_default().to_owned())
        .collect();
    let first = |field: &str| {
        results
            .first()
            .and_then(|r| r[field].as_str())
            .map(str::to_owned)
    };
    (state, rules, first("ruleset"), first("commit"))
}

/// A root with one file that every generation's rules match, queued for a scan.
async fn file(core: &Core, n: usize) -> Uuid {
    let bytes = format!("file {n}: EVIL");
    root_with_bytes(core, "yara", bytes.as_bytes(), &format!("payload{n}.bin"))
        .await
        .0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_during_a_stream_of_scans_drops_none() {
    let checkout = tempfile::tempdir().unwrap();
    let repo = checkout.path();
    git(repo, &["init", "-q"]);
    let first_commit = commit_rules(repo, FIRST, "one rule");
    let signatures = SignatureRepo::new(repo);

    let core = Core::start(
        vec![ace_mod_yara::MANIFEST],
        &[MODULE],
        Duration::from_secs(30),
    )
    .await;
    let db = core.test_db.db();
    let first = build_new(db, &core.bucket, &signatures)
        .await
        .expect("builds")
        .expect("the first ruleset");

    // the pool's ruleset directory, which task processes read as ace4-task
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
            "--concurrency",
            "2",
            "--rulesets",
            dir,
            "--ruleset-poll-ms",
            "100",
            "--settings",
            &settings,
        ],
    ));

    // a stream of files: half at once, so scans are queued and running when the rules change
    let mut roots = Vec::new();
    for n in 0..15 {
        roots.push(file(&core, n).await);
    }
    wait_until_idle(&core, roots[0], Duration::from_secs(60)).await;
    let second_commit = commit_rules(repo, SECOND, "two rules");
    let second = build_new(db, &core.bucket, &signatures)
        .await
        .expect("builds")
        .expect("the second ruleset");
    assert_eq!(second.commit, second_commit);
    let unfinished: i64 =
        sqlx::query_scalar("SELECT count(*) FROM queue.tasks WHERE state IN ('queued', 'running')")
            .fetch_one(db.pool())
            .await
            .unwrap();
    println!("{unfinished} scans unfinished when the second ruleset was built");
    assert!(unfinished > 0);
    // and the rest after it, spaced out
    for n in 15..30 {
        roots.push(file(&core, n).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_ne!(first.key, second.key);
    for root in &roots {
        wait_until_idle(&core, *root, Duration::from_secs(120)).await;
    }
    let stderr = pool.terminate(Duration::from_secs(10));

    let one = (
        vec!["gen_one".to_owned()],
        Some(first.key.to_hex()),
        Some(first_commit.clone()),
    );
    let two = (
        vec!["gen_one".to_owned(), "gen_two".to_owned()],
        Some(second.key.to_hex()),
        Some(second.commit.clone()),
    );
    let mut generations = Vec::new();
    for root in &roots {
        let (state, rules, ruleset, commit) = scanned(&core, *root).await;
        assert_eq!(state, "done", "a scan was dropped\n{stderr}");
        let seen = (rules, ruleset, commit);
        // each scan used one generation whole: its rules, its key and its commit agree
        if seen == one {
            generations.push(1);
        } else if seen == two {
            generations.push(2);
        } else {
            panic!("a scan matched {seen:?}\n{stderr}");
        }
    }
    println!("generations in stream order: {generations:?}");
    // the first file was scanned before the commit, the last well after the switch
    assert_eq!(generations.first(), Some(&1), "{generations:?}");
    assert_eq!(generations.last(), Some(&2), "{generations:?}");
    assert!(stderr.contains("switched to a new ruleset"), "{stderr}");
}
