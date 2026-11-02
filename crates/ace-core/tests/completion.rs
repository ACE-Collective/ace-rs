//! PLAN.md 2.11: a root is complete when it has no queued, delayed or running tasks, and each
//! analysis pass ends with exactly one completion event.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::queue::{self, Completion, Completions, Worker, reap_expired_leases};
use ace_core::testing::TestDb;
use ace_results::ObservableKind;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{result, root_with, worker};

/// Queues one task per observable and module, committed.
async fn queue_all(
    test_db: &TestDb,
    root: Uuid,
    ids: &[ace_core::tree::ObservableId],
    modules: &[&str],
) {
    let mut tx = test_db.db().begin().await.expect("begins");
    for id in ids {
        for module in modules {
            queue::enqueue(&mut tx, root, *id, module)
                .await
                .expect("queues")
                .expect("new");
        }
    }
    tx.commit().await.expect("commits");
}

/// Drains the worker's tasks, ending them three ways in turn: a result landed through the
/// orchestrator, a skip (completed with no result) and a failure.
async fn drain(worker: Arc<Worker>, orchestrator: Arc<Orchestrator>) {
    let empty: Value = json!({});
    while let Some(task) = worker.claim().await.expect("claims") {
        match task.id.0 % 3 {
            0 => {
                let mut tx = worker.db().begin().await.expect("begins");
                orchestrator
                    .land_result(
                        &mut tx,
                        &worker,
                        &task,
                        &result(json!({
                            "analysis_type": "test_stub",
                            "schema_version": 1,
                            "details": empty,
                        })),
                    )
                    .await
                    .expect("lands");
                tx.commit().await.expect("commits");
            }
            1 => worker.complete(task.id).await.expect("completes"),
            _ => worker.fail(task.id, "a test failure").await.expect("fails"),
        }
    }
}

/// Every completion notification about `root` until none comes for `quiet`.
async fn notifications(completions: &mut Completions, root: Uuid, quiet: Duration) -> Vec<i32> {
    let mut passes = Vec::new();
    while let Some(Completion { root: r, pass }) = completions.next(quiet).await.expect("listens") {
        if r == root {
            passes.push(pass);
        }
    }
    passes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn each_analysis_pass_ends_with_exactly_one_completion() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut completions = Completions::listen(db).await.expect("listens");
    // modules the catalog doesn't know, so results queue nothing more
    let orchestrator = Arc::new(Orchestrator::new(Catalog::default(), Modes::ace3()));
    let values: Vec<String> = (0..40).map(|i| format!("host{i}.example.com")).collect();
    let observables: Vec<(ObservableKind, &str)> = values
        .iter()
        .map(|v| (ObservableKind::Fqdn, v.as_str()))
        .collect();
    let (root, ids) = root_with(db, "analysis", &observables).await;

    for pass in 1..=2 {
        // each pass gets 200 new tasks, drained by four workers with four tasks in flight each,
        // so the last tasks of a pass end at nearly the same moment on different connections
        let names: Vec<String> = (0..5).map(|m| format!("pass{pass}_m{m}")).collect();
        let modules: Vec<&str> = names.iter().map(String::as_str).collect();
        queue_all(&test_db, root, &ids, &modules).await;
        let mut slots = tokio::task::JoinSet::new();
        for n in 0..4 {
            let worker = Arc::new(
                worker(
                    &test_db,
                    &format!("pass{pass}-worker{n}"),
                    &modules,
                    Duration::from_secs(60),
                )
                .await,
            );
            for _ in 0..4 {
                slots.spawn(drain(worker.clone(), orchestrator.clone()));
            }
        }
        slots.join_all().await;
        let seen = notifications(&mut completions, root, Duration::from_millis(500)).await;
        assert_eq!(seen, [pass], "pass {pass}'s notifications");
        let recorded: Vec<i32> = queue::completions(db, root)
            .await
            .expect("reads")
            .iter()
            .map(|c| c.pass)
            .collect();
        assert_eq!(recorded, (1..=pass).collect::<Vec<_>>());
    }
}

#[tokio::test]
async fn delayed_and_running_tasks_keep_a_root_open() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, root, &ids, &["slow"]).await;
    let worker = worker(&test_db, "w", &["slow"], Duration::from_secs(60)).await;

    let task = worker.claim().await.expect("claims").expect("a task");
    worker
        .delay(task.id, Duration::from_millis(200), &Value::Null)
        .await
        .expect("delays");
    assert!(
        queue::completions(db, root)
            .await
            .expect("reads")
            .is_empty()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let task = worker.claim().await.expect("claims").expect("due again");
    assert!(
        queue::completions(db, root)
            .await
            .expect("reads")
            .is_empty()
    );
    worker.complete(task.id).await.expect("completes");
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );
}

#[tokio::test]
async fn a_task_the_reaper_fails_can_end_the_pass_and_a_root_with_no_work_completes_at_start() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, root, &ids, &["crashing"]).await;
    sqlx::query("UPDATE queue.tasks SET max_attempts = 1 WHERE root_id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("sets the limit");
    let worker = worker(&test_db, "w", &["crashing"], Duration::from_millis(200)).await;
    let _claimed = worker.claim().await.expect("claims").expect("a task");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        reap_expired_leases(db).await.expect("reaps").failed.len(),
        1
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );

    // the orchestrator starting a root that no module takes: its first pass ends at once
    let orchestrator = Orchestrator::new(Catalog::new(common::manifests()), Modes::ace3());
    let (idle, _) = root_with(db, "event", &[(ObservableKind::Fqdn, "example.org")]).await;
    let mut tx = db.begin().await.expect("begins");
    assert!(
        orchestrator
            .start(&mut tx, idle)
            .await
            .expect("starts")
            .is_empty()
    );
    tx.commit().await.expect("commits");
    assert_eq!(
        queue::completions(db, idle).await.expect("reads"),
        [Completion {
            root: idle,
            pass: 1
        }]
    );
}
