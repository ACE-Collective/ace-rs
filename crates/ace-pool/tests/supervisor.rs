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

// PLAN.md 4.1: the Python pool, with the checkout's worker on the dev image's Python, which has only
// the standard library, as the probe needs. tests/e2e/run does the same against the pool's image.

/// The Python pool's supervisor, running workers as ace4-task, one at a time.
fn python_pool(core: &Core, extra: &[&str]) -> PoolProcess {
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/../../python");
    let mut args = vec![
        "python",
        "--python",
        "/usr/bin/python3",
        "--source",
        source,
        "--task-user",
        "ace4-task",
        "--concurrency",
        "1",
    ];
    args.extend_from_slice(extra);
    PoolProcess::start(test_pool(core, &args))
}

async fn python_core() -> Core {
    Core::start(
        vec![ace_mod_python::PROBE_MANIFEST],
        &["python_probe"],
        Duration::from_secs(30),
    )
    .await
}

/// One probe task per value, in order, on one root.
async fn probe(core: &Core, actions: &[&str]) -> uuid::Uuid {
    let values: Vec<String> = actions
        .iter()
        .map(|action| format!("{action}.example.com"))
        .collect();
    root_with_tasks(core, &values, "python_probe").await
}

/// What the probe said for each action, in the order given, once they've all run.
async fn reports(core: &Core, root: uuid::Uuid, actions: &[&str]) -> Vec<serde_json::Value> {
    let mut reports = Vec::new();
    for action in actions {
        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT r.details FROM analysis.results r
             JOIN analysis.observables o ON o.id = r.observable_id
             WHERE r.root_id = $1 AND o.value = $2",
        )
        .bind(root)
        .bind(format!("{action}.example.com"))
        .fetch_one(core.test_db.db().pool())
        .await
        .unwrap_or_else(|e| panic!("the report on {action}: {e}"));
        reports.push(details);
    }
    reports
}

fn pid(report: &serde_json::Value) -> i64 {
    report["pid"].as_i64().expect("a pid")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_worker_is_recycled_at_its_task_count_and_the_next_task_runs_on_its_replacement() {
    let core = python_core().await;
    let actions = ["one", "print", "three", "four", "five"];
    let root = probe(&core, &actions).await;
    let mut pool = python_pool(&core, &["--max-tasks", "2"]);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let stderr = pool.stop();

    let reports = reports(&core, root, &actions).await;
    println!("{reports:?}");
    let pids: Vec<i64> = reports.iter().map(pid).collect();
    let counts: Vec<i64> = reports
        .iter()
        .map(|r| r["tasks_in_process"].as_i64().expect("a count"))
        .collect();
    // two tasks each, in three processes
    assert_eq!(counts, [1, 2, 1, 2, 1], "{stderr}");
    assert_eq!(pids[0], pids[1], "{stderr}");
    assert_eq!(pids[2], pids[3], "{stderr}");
    assert_ne!(pids[1], pids[2], "the third task ran on a new process");
    assert_ne!(pids[3], pids[4], "the fifth task ran on a new process");
    assert!(stderr.contains("\"task count\""), "{stderr}");
    // a module that prints doesn't break the protocol, and its text reaches the log
    assert_eq!(reports[1]["note"], "printed");
    assert!(stderr.contains("a module that prints"), "{stderr}");
    // the worker's own view: not root, and nothing in its environment, the token included
    for report in &reports {
        assert_eq!(report["uid"], 10001);
        assert_eq!(report["environment"], json!(["LC_CTYPE"]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_worker_is_recycled_past_its_memory_limit_and_one_under_it_is_kept() {
    let core = python_core().await;
    let actions = ["small", "hold-16", "hold-128", "after-1", "after-2"];
    let root = probe(&core, &actions).await;
    let mut pool = python_pool(&core, &["--max-memory-mb", "100"]);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let stderr = pool.stop();

    let reports = reports(&core, root, &actions).await;
    println!("{reports:?}");
    let pids: Vec<i64> = reports.iter().map(pid).collect();
    assert_eq!(pids[0], pids[1], "16 MB stays under the limit: {stderr}");
    assert_eq!(pids[1], pids[2], "{stderr}");
    assert_ne!(
        pids[2], pids[3],
        "the task after the limit ran on a new process"
    );
    assert_eq!(pids[3], pids[4], "the new process stayed: {stderr}");
    assert_eq!(reports[3]["tasks_in_process"], 1);
    assert!(stderr.contains("\"memory limit\""), "{stderr}");
    assert!(!stderr.contains("\"task count\""), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_task_that_fails_says_why_and_the_pool_keeps_running() {
    let core = python_core().await;
    // the port the API listens on, which the worker may not reach
    let connect = format!("connect-{}", core.port);
    let actions = [
        "raise",
        "fail",
        "crash",
        "fork",
        "thread",
        "hang",
        "read",
        connect.as_str(),
        "file",
    ];
    let root = root_with_tasks(
        &core,
        &actions
            .iter()
            .map(|a| format!("{a}.example.com"))
            .collect::<Vec<_>>(),
        "python_probe",
    )
    .await;
    let mut pool = python_pool(&core, &[]);
    wait_until_idle(&core, root, Duration::from_secs(90)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();

    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT o.value, t.state::text, t.error FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.id",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the tasks");
    println!("{rows:#?}");
    let error_of = |action: &str| {
        let row = rows
            .iter()
            .find(|(value, _, _)| value.starts_with(action))
            .unwrap_or_else(|| panic!("no task for {action}"));
        assert_eq!(row.1, "failed", "{action}: {stderr}");
        row.2.clone().unwrap_or_default()
    };
    assert!(error_of("raise.").contains("ValueError: the probe raised"));
    assert_eq!(error_of("fail."), "the probe failed on fail.example.com");
    assert!(error_of("crash.").contains("exited 7"));
    assert!(error_of("fork.").contains("SIGSYS"));
    assert!(error_of("thread.").contains("SIGSYS"));
    assert!(error_of("hang.").contains("deadline of 5s"));

    let details = reports(&core, root, &["read", connect.as_str(), "file"]).await;
    assert!(
        details[0]["note"]
            .as_str()
            .expect("a note")
            .starts_with("refused: PermissionError"),
        "{details:?}"
    );
    assert!(
        details[1]["note"]
            .as_str()
            .expect("a note")
            .starts_with("refused: PermissionError"),
        "{details:?}"
    );
    let paths: Vec<String> =
        sqlx::query_scalar("SELECT path FROM analysis.files WHERE root_id = $1")
            .bind(root)
            .fetch_all(core.test_db.db().pool())
            .await
            .expect("the files");
    assert_eq!(paths, ["probe.txt"], "the file reached the core");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_pool_gives_a_running_task_back_at_shutdown() {
    let core = python_core().await;
    let root = probe(&core, &["hang"]).await;
    let mut pool = python_pool(&core, &[]);
    let started = std::time::Instant::now();
    while task_of(&core, root, "python_probe").await.0 != "running" {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "it never started"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // let the lease's answer reach the pool: a pool that stops with the request in flight never
    // hears of the task, which then waits out its lease, as for any pool
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stderr = pool.terminate(Duration::from_secs(4));
    let (state, attempts): (String, i32) =
        sqlx::query_as("SELECT state::text, attempts FROM queue.tasks WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the task");
    assert_eq!((state.as_str(), attempts), ("queued", 0), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_pool_whose_workers_cant_start_leases_nothing() {
    let core = python_core().await;
    let root = probe(&core, &["one"]).await;
    let mut pool = python_pool(&core, &["--source", "/nonexistent"]);
    let started = std::time::Instant::now();
    while pool.running() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "it kept running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stderr = pool.stop();
    assert!(stderr.contains("the Python pool didn't start"), "{stderr}");
    assert_eq!(task_of(&core, root, "python_probe").await.0, "queued");
}
