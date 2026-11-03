//! PLAN.md 2.17's Done check: a panicking parser leaves a failed-task row and the supervisor
//! keeps leasing, a task process has no capabilities, and the archive module (on test.r07, a
//! RAR 5 file) and the YARA module each run contained. The supervisor is the test pool binary
//! in its parsers mode, running task processes as the dev image's ace4-task user.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use ace_pool::testing;
use serde_json::json;

use common::{
    Core, PoolProcess, root_with_bytes, root_with_tasks, task_of, test_pool, wait_until_idle,
};

/// The supervisor, running task processes as ace4-task.
fn supervisor(core: &Core, extra: &[&str]) -> PoolProcess {
    let mut args = vec!["parsers", "--task-user", "ace4-task", "--concurrency", "1"];
    args.extend_from_slice(extra);
    PoolProcess::start(test_pool(core, &args))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_parser_fails_its_task_and_the_supervisor_keeps_leasing() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_panicking_parser", "test_capabilities"],
        Duration::from_secs(30),
    )
    .await;
    let panics = root_with_tasks(
        &core,
        &["first.example.com".to_owned()],
        "test_panicking_parser",
    )
    .await;
    let reports = root_with_tasks(
        &core,
        &["second.example.com".to_owned()],
        "test_capabilities",
    )
    .await;

    let mut pool = supervisor(&core, &[]);
    wait_until_idle(&core, panics, Duration::from_secs(60)).await;
    wait_until_idle(&core, reports, Duration::from_secs(60)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();

    let (state, error) = task_of(&core, panics, "test_panicking_parser").await;
    assert_eq!(state, "failed", "{stderr}");
    assert_eq!(
        error.as_deref(),
        Some("the module panicked: test_panicking_parser was given first.example.com")
    );
    // the next task ran after the panic, and its process had no capabilities
    let (state, _) = task_of(&core, reports, "test_capabilities").await;
    assert_eq!(state, "done", "{stderr}");
    let note: String =
        sqlx::query_scalar("SELECT details->>'note' FROM analysis.results WHERE root_id = $1")
            .bind(reports)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the report");
    println!("{note}");
    for wanted in [
        "Uid: 10001 10001 10001 10001",
        "CapInh: 0000000000000000",
        "CapPrm: 0000000000000000",
        "CapEff: 0000000000000000",
        "CapAmb: 0000000000000000",
    ] {
        assert!(note.contains(wanted), "{wanted} in {note}");
    }
    assert!(
        note.contains("Groups:;") || note.ends_with("Groups:"),
        "no groups in {note}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archive_module_unpacks_rar_5_in_a_contained_task_process() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, rar) = core
        .root_with_file("file", "ace3/archive/test.r07", "test.r07")
        .await;
    let mut pool = supervisor(&core, &[]);
    let started = std::time::Instant::now();
    loop {
        let (state, _) = task_of(&core, root, "archive").await;
        if state != "queued" && state != "running" {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the archive task is still {state}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stderr = pool.stop();
    let rows = core.tasks(root).await;
    println!("{rows:?}");
    assert_eq!(
        rows[0],
        ("archive".to_owned(), rar.to_hex(), "done".to_owned()),
        "{stderr}"
    );
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let (count, paths): (i32, Vec<String>) = sqlx::query_as(
        "SELECT (r.details->>'file_count')::int,
                ARRAY(SELECT path FROM analysis.files f
                      WHERE f.root_id = r.root_id AND f.path <> 'test.r07' ORDER BY path)
         FROM analysis.results r WHERE r.root_id = $1 AND r.module = 'archive'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the archive's result");
    println!("{count} files: {paths:?}");
    assert!(count > 0);
    assert!(!paths.is_empty());
    assert!(
        paths.iter().all(|p| p.starts_with("test.r07.extracted/")),
        "{paths:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_yara_module_scans_in_a_contained_task_process() {
    let rules = tempfile::tempdir().expect("a rules directory");
    let namespace = rules.path().join("fixture");
    std::fs::create_dir(&namespace).expect("a namespace");
    std::fs::write(
        namespace.join("rules.yar"),
        r#"rule contained_evil { strings: $a = "EVIL" condition: $a }"#,
    )
    .expect("a rule");
    // the task processes' user reads the rules when it sets up
    for dir in [rules.path(), namespace.as_path()] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("opens it");
    }
    let settings = json!({"yara_scanner_v3_4": {"signature_dir": rules.path()}}).to_string();

    let core = Core::start(
        vec![ace_mod_yara::MANIFEST],
        &["yara_scanner_v3_4"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _) = root_with_bytes(&core, "yara", b"xxEVILxx", "payload.bin").await;
    let mut pool = supervisor(&core, &["--settings", &settings]);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let stderr = pool.stop();
    let (state, error) = task_of(&core, root, "yara_scanner_v3_4").await;
    assert_eq!(state, "done", "{error:?}\n{stderr}");
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let rule: String = sqlx::query_scalar(
        "SELECT details->'scan_results'->0->>'rule' FROM analysis.results WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the scan's result");
    assert_eq!(rule, "contained_evil");
}
