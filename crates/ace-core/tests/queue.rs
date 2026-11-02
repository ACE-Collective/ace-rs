//! PLAN.md 2.6: tasks and claims. Two workers draining 1,000 tasks run each one exactly once.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ace_core::queue::{self, TaskId, TaskState};
use ace_core::testing::TestDb;
use ace_results::ObservableKind;

use common::{root_with, worker};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_workers_draining_1000_tasks_run_each_once() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let values: Vec<String> = (0..100).map(|i| format!("host{i}.example.com")).collect();
    let observables: Vec<(ObservableKind, &str)> = values
        .iter()
        .map(|v| (ObservableKind::Fqdn, v.as_str()))
        .collect();
    let (root, ids) = root_with(db, "analysis", &observables).await;
    let modules: Vec<String> = (0..10).map(|m| format!("module_{m}")).collect();
    let module_names: Vec<&str> = modules.iter().map(String::as_str).collect();

    let mut tx = db.begin().await.expect("begins");
    let mut queued = Vec::new();
    for id in &ids {
        for module in &modules {
            let task = queue::enqueue(&mut tx, root, *id, module)
                .await
                .expect("queues");
            queued.push(task.expect("a new task"));
        }
    }
    // queueing one again is a no-op
    assert_eq!(
        queue::enqueue(&mut tx, root, ids[0], &modules[0])
            .await
            .expect("queues"),
        None
    );
    tx.commit().await.expect("commits");
    assert_eq!(queued.len(), 1000);

    // two workers, each with its own pool and four claims in flight at a time
    let runs: Arc<Mutex<Vec<(TaskId, String)>>> = Arc::default();
    let mut slots = tokio::task::JoinSet::new();
    for name in ["worker-a", "worker-b"] {
        let worker = Arc::new(worker(&test_db, name, &module_names, Duration::from_secs(60)).await);
        for _ in 0..4 {
            let (worker, runs) = (worker.clone(), runs.clone());
            slots.spawn(async move {
                while let Some(task) = worker.claim().await.expect("claims") {
                    assert_eq!(task.attempts, 1);
                    runs.lock()
                        .expect("the run list")
                        .push((task.id, worker.name().to_owned()));
                    worker.complete(task.id).await.expect("completes");
                }
            });
        }
    }
    slots.join_all().await;

    let runs = runs.lock().expect("the run list").clone();
    let mut per_task: BTreeMap<TaskId, u32> = BTreeMap::new();
    let mut per_worker: BTreeMap<String, u32> = BTreeMap::new();
    for (task, name) in &runs {
        *per_task.entry(*task).or_default() += 1;
        *per_worker.entry(name.clone()).or_default() += 1;
    }
    println!("runs per worker: {per_worker:?}");
    assert_eq!(runs.len(), 1000);
    assert_eq!(per_task.len(), 1000);
    assert!(per_task.values().all(|&n| n == 1));
    assert_eq!(per_task.keys().copied().collect::<Vec<_>>(), {
        let mut sorted = queued.clone();
        sorted.sort();
        sorted
    });
    assert!(per_worker.values().all(|&n| n > 0), "{per_worker:?}");
    for task in queued {
        assert_eq!(
            queue::state(db, task).await.expect("reads"),
            Some(TaskState::Done)
        );
    }
}

#[tokio::test]
async fn a_worker_claims_only_its_own_modules_and_only_while_it_owns_a_task_can_it_end_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    let task = queue::enqueue(&mut tx, root, ids[0], "rdap_analyzer")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");

    let other = worker(
        &test_db,
        "other",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    assert!(other.claim().await.expect("claims").is_none());
    let owner = worker(
        &test_db,
        "owner",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let claimed = owner.claim().await.expect("claims").expect("a task");
    assert_eq!(claimed.id, task);
    assert_eq!(claimed.observable.kind, ObservableKind::Fqdn);
    assert_eq!(claimed.observable.value, "example.com");
    // the running task isn't claimable, and only its owner can end it
    assert!(owner.claim().await.expect("claims").is_none());
    assert!(other.fail(task, "not mine").await.is_err());
    owner.fail(task, "the module failed").await.expect("fails");
    assert_eq!(
        queue::state(db, task).await.expect("reads"),
        Some(TaskState::Failed)
    );
    assert!(owner.complete(task).await.is_err());
}
