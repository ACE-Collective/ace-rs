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
        "temp",
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

    let details = reports(&core, root, &["read", connect.as_str(), "file", "temp"]).await;
    // a library's temporary file works, in the task's own directory
    assert!(
        !details[3]["note"]
            .as_str()
            .expect("a note")
            .contains("refused"),
        "{details:?}"
    );
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

/// PLAN.md 4.2's Done check, on a real worker through the real API: the wrong fields come from
/// `python_probe.py` and only the core's check stops them reaching the tree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_result_with_a_wrong_field_is_rejected_and_a_correct_one_from_the_module_lands() {
    let core = python_core().await;
    let actions = ["wrong", "unknown", "envelope", "bytes", "right"];
    let root = probe(&core, &actions).await;
    let mut pool = python_pool(&core, &[]);
    // each is its first attempt's answer: the lease is 30 seconds and nothing here reaps one
    wait_until_idle(&core, root, Duration::from_secs(20)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();

    let db = core.test_db.db().pool();
    let rows: Vec<(String, i64, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT o.value, t.id, t.state::text, t.attempts, t.error FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.id",
    )
    .bind(root)
    .fetch_all(db)
    .await
    .expect("the tasks");
    println!("{rows:#?}");
    let row = |action: &str| {
        let row = rows
            .iter()
            .find(|row| row.0 == format!("{action}.example.com"))
            .unwrap_or_else(|| panic!("no task for {action}"));
        assert_eq!(row.2, "failed", "{action}: {stderr}");
        assert_eq!(row.3, 1, "{action} ran once: {stderr}");
        row.4.clone().unwrap_or_default()
    };
    // the core names the field's path, in the failed task's row
    let wrong = row("wrong");
    assert!(
        wrong.starts_with("invalid result: /details/pid: "),
        "{wrong}"
    );
    assert_eq!(
        row("unknown"),
        "invalid result: /details/extra: unknown field"
    );
    // these two stop in the supervisor, since they never read as a result: the same check, or
    // the worker's own error
    let envelope = row("envelope");
    assert!(
        envelope.starts_with("invalid result: /summary: "),
        "{envelope}"
    );
    let bytes = row("bytes");
    assert!(bytes.contains("TypeError: Object of type bytes"), "{bytes}");
    assert!(!stderr.contains("wasn't sent"), "{stderr}");

    // nothing from the rejected results landed, and only the correct one's report did
    let results: Vec<String> = sqlx::query_scalar(
        "SELECT o.value FROM analysis.results r
         JOIN analysis.observables o ON o.id = r.observable_id WHERE r.root_id = $1",
    )
    .bind(root)
    .fetch_all(db)
    .await
    .expect("the results");
    assert_eq!(results, ["right.example.com"], "{stderr}");
    let (observables, files, tasks): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM analysis.observables WHERE root_id = $1),
                (SELECT count(*) FROM analysis.files WHERE root_id = $1),
                (SELECT count(*) FROM queue.tasks WHERE root_id = $1)",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("the counts");
    assert_eq!((observables, files, tasks), (5, 0, 5));
    // the file the rejected result uploaded is gone, and never reached the pool
    let sha256: ace_results::Sha256 =
        "1e9b1e46c978519479871a402d21ac3175f1cbc5964e9040cd9e87030c05615e"
            .parse()
            .expect("a sha256");
    let wrong_task = rows
        .iter()
        .find(|row| row.0.starts_with("wrong."))
        .expect("its task");
    assert!(
        matches!(
            core.bucket.fetch_upload(wrong_task.1, &sha256).await,
            Err(ace_core::bucket::BucketError::Store(
                ace_store::StoreError::NotFound { .. }
            ))
        ),
        "the upload is gone"
    );
    assert!(
        core.bucket
            .object(ace_core::bucket::ALERT_FILES, &sha256)
            .await
            .expect("looks")
            .is_none()
    );

    // none of that cost the worker: the correct result came from the process they all ran in
    let right = reports(&core, root, &["right"]).await;
    assert_eq!(right[0]["tasks_in_process"], 5, "{right:?}");
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

// PLAN.md 4.3: a hung worker's stacks, from the real py-spy on a real contained worker, in the row.

/// Each probe action's state, error and stacks, once they've all ended.
async fn hung_rows(
    core: &Core,
    root: uuid::Uuid,
) -> std::collections::HashMap<String, (String, String, Option<String>)> {
    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT o.value, t.state::text, t.error, t.stacks FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id WHERE t.root_id = $1",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the tasks");
    rows.into_iter()
        .map(|(value, state, error, stacks)| {
            let action = value.trim_end_matches(".example.com").to_owned();
            (action, (state, error.unwrap_or_default(), stacks))
        })
        .collect()
}

/// The Done check. Each hung action names its own function in its row, and no other row does, so
/// the frame can only have come from that worker at that moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_python_task_leaves_its_stack_in_its_row() {
    let core = python_core().await;
    let hangs = [
        ("hang", "_hang_in_python"),
        ("hang-sleep", "_hang_in_sleep"),
        ("hang-select", "_hang_in_select"),
        ("hang-regex", "_hang_in_regex"),
        ("hang-hostile", "_hang_hostile"),
        // py-spy can't pause a stopped process, so this one comes from --nonblocking
        ("hang-stopped", "_hang_stopped"),
    ];
    let mut actions: Vec<&str> = hangs.iter().map(|(action, _)| *action).collect();
    actions.extend(["hang-closed", "after"]);
    let root = probe(&core, &actions).await;
    let mut pool = python_pool(&core, &["--concurrency", "4"]);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    assert!(pool.running(), "the supervisor kept running");
    let stderr = pool.stop();

    let rows = hung_rows(&core, root).await;
    for (action, function) in hangs {
        let (state, error, stacks) = &rows[action];
        let stacks = stacks.as_deref().unwrap_or_default();
        println!("--- {action}: {error}\n{stacks}");
        assert_eq!(state, "failed", "{action}: {stderr}");
        assert!(error.contains("deadline of 5s and was killed"), "{error}");
        assert!(!error.contains("no stack"), "{error}");
        assert!(stacks.contains(function), "{action}: {stacks}\n{stderr}");
        assert!(
            stacks.contains("python_probe.py"),
            "{action} names the file: {stacks}"
        );
        assert!(stacks.contains("worker.py"), "{action} has the whole stack");
        for (other, other_function) in hangs {
            assert!(
                other == action || !stacks.contains(other_function),
                "{action}'s row names {other_function}: {stacks}"
            );
        }
    }
    let stopped = rows["hang-stopped"].2.as_deref().unwrap_or_default();
    assert!(
        stopped.starts_with("(read while the process ran"),
        "{stopped}"
    );
    let hostile = rows["hang-hostile"].2.as_deref().unwrap_or_default();
    assert!(
        !hostile.contains(|c: char| c.is_control() && c != '\n' && c != '\t'),
        "{hostile:?}"
    );

    // a worker that refuses to be read still dies at its deadline, and the row says why
    let (state, error, stacks) = &rows["hang-closed"];
    println!("--- hang-closed: {error}");
    assert_eq!(state, "failed");
    assert!(error.contains("deadline of 5s and was killed"), "{error}");
    assert!(
        error.contains("no stack could be taken: py-spy exited 1"),
        "{error}"
    );
    assert_eq!(stacks, &None);
    assert_eq!(rows["after"].0, "done", "the pool went on: {stderr}");
}

/// A script in a directory ace4-task can read, in place of py-spy.
fn fake_tool(dir: &std::path::Path, name: &str, script: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, script).expect("the script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("its mode");
    path.display().to_string()
}

/// A hung task's row and how long its pool took over it, with `tool` as py-spy.
async fn hung_with(tool: &str, extra: &[&str]) -> ((String, String, Option<String>), Duration) {
    let core = python_core().await;
    let root = probe(&core, &["hang"]).await;
    let mut args = vec!["--py-spy", tool];
    args.extend_from_slice(extra);
    let mut pool = python_pool(&core, &args);
    let started = std::time::Instant::now();
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let elapsed = started.elapsed();
    assert!(pool.running(), "the supervisor kept running");
    let rows = hung_rows(&core, root).await;
    (rows["hang"].clone(), elapsed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_py_spy_that_fails_hangs_or_floods_still_leaves_a_row_at_the_deadline() {
    let dir = tempfile::tempdir().expect("a directory");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("mode");
    let hangs = fake_tool(dir.path(), "hangs", "#!/bin/sh\nexec sleep 1000\n");
    let floods = fake_tool(dir.path(), "floods", "#!/bin/sh\nexec yes frame\n");
    // a shell's builtins only, because the filter kills a fork
    let reports = fake_tool(
        dir.path(),
        "reports",
        "#!/bin/sh\n\
         while read -r line; do\n\
             case \"$line\" in Uid:*|NoNewPrivs:*|Seccomp:*) echo \"$line\" ;; esac\n\
         done < /proc/self/status\n\
         echo \"args: $*\"\n\
         set\n",
    );
    // -S, because the dev image's site directory makes a socket; the write shows it got this far
    let connects = fake_tool(
        dir.path(),
        "connects",
        "#!/usr/bin/python3 -IS\n\
         import socket, sys\n\
         print('about to make a socket', file=sys.stderr, flush=True)\n\
         socket.socket()\n",
    );

    let (hung, flooded, reported, connected, missing) = tokio::join!(
        hung_with(&hangs, &["--dump-timeout-ms", "1000"]),
        hung_with(&floods, &[]),
        hung_with(&reports, &[]),
        hung_with(&connects, &[]),
        hung_with("/nonexistent/py-spy", &[]),
    );

    // its own bound: both attempts, half each, and the task fails regardless
    let ((state, error, stacks), elapsed) = hung;
    println!("hangs, {elapsed:?}: {error}");
    assert_eq!(state, "failed");
    assert!(error.contains("no stack could be taken"), "{error}");
    assert!(
        error.contains("py-spy didn't finish within 500ms"),
        "{error}"
    );
    assert!(error.contains("with --nonblocking"), "{error}");
    assert_eq!(stacks, None);
    assert!(elapsed >= Duration::from_secs(6), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");

    // the row's text is capped, and says it was cut
    let ((state, error, stacks), _) = flooded;
    let stacks = stacks.expect("what it wrote");
    assert_eq!(state, "failed", "{error}");
    assert!(
        stacks.len() <= ace_pool::python::MAX_STACKS,
        "{}",
        stacks.len()
    );
    assert!(
        stacks.len() > ace_pool::python::MAX_STACKS / 2,
        "{}",
        stacks.len()
    );
    assert!(stacks.starts_with("frame\n"));
    assert!(stacks.contains("the stacks are longer than the row keeps"));

    // how narrowly it ran: the workers' user, nothing of the supervisor's environment, no new
    // privileges, and a seccomp filter
    let ((_, error, stacks), _) = reported;
    let stacks = stacks.unwrap_or_else(|| panic!("no report: {error}"));
    println!("reports: {stacks}");
    assert!(stacks.contains("Uid:\t10001\t10001"), "{stacks}");
    assert!(stacks.contains("NoNewPrivs:\t1"), "{stacks}");
    assert!(stacks.contains("Seccomp:\t2"), "{stacks}");
    assert!(
        stacks.contains("args: dump --full-filenames --pid "),
        "{stacks}"
    );
    assert!(!stacks.contains("ACE4_"), "{stacks}");

    // the filter refuses it a socket, which kills it
    let ((_, error, stacks), _) = connected;
    println!("connects: {error}");
    assert_eq!(stacks, None);
    assert!(error.contains("killed by SIGSYS"), "{error}");
    assert!(error.contains("about to make a socket"), "{error}");

    let ((state, error, stacks), _) = missing;
    println!("missing: {error}");
    assert_eq!(state, "failed");
    assert_eq!(stacks, None);
    assert!(
        error.contains("no stack could be taken: running /nonexistent/py-spy failed"),
        "{error}"
    );
}

/// A cancelled task isn't hung, so its worker goes at once, with no dump, well before its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_result_whose_uploads_outlast_the_lease_lands_on_its_first_attempt() {
    // a 3-second lease, and files enough that uploading them and landing them take longer
    let core = Core::start(
        vec![ace_mod_python::PROBE_MANIFEST],
        &["python_probe"],
        Duration::from_secs(3),
    )
    .await;
    let reaper_stop = tokio_util::sync::CancellationToken::new();
    let reaper = tokio::spawn(ace_core::queue::run_reaper(
        core.test_db.db().clone(),
        Duration::from_millis(200),
        reaper_stop.clone(),
    ));
    let root = probe(&core, &["files-1500"]).await;
    let mut pool = python_pool(&core, &[]);
    let started = std::time::Instant::now();
    wait_until_idle(&core, root, Duration::from_secs(240)).await;
    let took = started.elapsed();
    pool.stop();
    reaper_stop.cancel();
    reaper.await.expect("the reaper stops");
    assert!(
        took > Duration::from_secs(3),
        "this took {took:?}, inside one lease"
    );

    let db = core.test_db.db().pool();
    let (state, attempts): (String, i32) = sqlx::query_as(
        "SELECT state::text, attempts FROM queue.tasks WHERE root_id = $1 AND module = 'python_probe'",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("the task");
    assert_eq!((state.as_str(), attempts), ("done", 1));
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
        .bind(root)
        .fetch_one(db)
        .await
        .expect("the files");
    assert_eq!(files, 1500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_python_task_is_killed_without_a_dump() {
    // a 3-second lease renews each second, which is how the pool hears of the cancellation
    let core = Core::start(
        vec![ace_mod_python::PROBE_MANIFEST],
        &["python_probe"],
        Duration::from_secs(3),
    )
    .await;
    let root = probe(&core, &["hang-sleep"]).await;
    let mut pool = python_pool(&core, &[]);
    let started = std::time::Instant::now();
    while task_of(&core, root, "python_probe").await.0 != "running" {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "it never started"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let cancelled = std::time::Instant::now();
    let db = core.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, root)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    while task_of(&core, root, "python_probe").await.0 == "running" {
        assert!(
            cancelled.elapsed() < Duration::from_secs(4),
            "it never stopped"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stderr = pool.stop();
    let rows = hung_rows(&core, root).await;
    assert_eq!(rows["hang-sleep"].0, "cancelled", "{stderr}");
    assert_eq!(rows["hang-sleep"].2, None);
    assert!(!stderr.contains("ran past its deadline"), "{stderr}");
}

/// The processes `pool` started whose command line holds worker.py.
fn workers_of(pool: u32) -> Vec<u32> {
    let mut workers = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        let stat = std::fs::read_to_string(entry.path().join("stat")).unwrap_or_default();
        // the fields after the command's closing parenthesis: state, then parent
        let parent = stat
            .rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(1))
            .and_then(|parent| parent.parse().ok());
        let command = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        if parent == Some(pool) && String::from_utf8_lossy(&command).contains("worker.py") {
            workers.push(pid);
        }
    }
    workers
}

/// What py-spy may do to a worker, a worker may not do to another, or to the supervisor, though
/// they share a user and the supervisor's name for Yama; and it can't reach py-spy or forge a dump.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_python_worker_cant_read_another_or_reach_py_spy() {
    let core = python_core().await;
    let mut pool = python_pool(&core, &["--concurrency", "2"]);
    let started = std::time::Instant::now();
    let workers = loop {
        let workers = workers_of(pool.pid());
        if workers.len() == 2 {
            break workers;
        }
        assert!(started.elapsed() < Duration::from_secs(30), "{workers:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let targets = [workers[0], workers[1], pool.pid(), 1];
    let actions: Vec<String> = targets.iter().map(|pid| format!("ptrace-{pid}")).collect();
    let mut all: Vec<&str> = actions.iter().map(String::as_str).collect();
    all.extend(["tool", "forge"]);
    let root = probe(&core, &all).await;
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    let stderr = pool.stop();

    let names: Vec<&str> = all[..4].to_vec();
    let details = reports(&core, root, &names).await;
    let mut others = 0;
    for (report, target) in details.iter().zip(targets) {
        let note = report["note"].as_str().expect("a note");
        println!("{target}, from {}: {note}", pid(report));
        if pid(report) == i64::from(target) {
            continue; // the worker it ran on was its own target
        }
        others += 1;
        assert!(note.contains("ptrace: refused"), "{note}: {stderr}");
        assert!(note.contains("process_vm_readv: refused"), "{note}");
        assert!(note.contains("/proc mem: refused"), "{note}");
    }
    assert!(others >= 3, "{details:?}");

    let tool = reports(&core, root, &["tool"]).await;
    let note = tool[0]["note"].as_str().expect("a note");
    println!("tool: {note}");
    assert!(note.contains("import: None"), "{note}");
    assert!(note.contains("read: refused"), "{note}");
    assert!(note.contains("run: refused"), "{note}");

    let rows = hung_rows(&core, root).await;
    let (state, error, stacks) = &rows["forge"];
    assert_eq!(state, "failed");
    assert!(error.contains("which it can't know"), "{error}");
    assert_eq!(stacks, &None);
}
