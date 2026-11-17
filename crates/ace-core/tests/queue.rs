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
    drain_1000_tasks(1).await;
}

/// The same with each claim taking up to seven tasks, as a pool with seven free slots asks: the
/// claims of two workers never overlap, and no claim takes more than it asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_workers_draining_1000_tasks_seven_at_a_time_run_each_once() {
    drain_1000_tasks(7).await;
}

async fn drain_1000_tasks(most: usize) {
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
                loop {
                    let claimed = worker.claim_up_to(most).await.expect("claims");
                    if claimed.is_empty() {
                        break;
                    }
                    assert!(claimed.len() <= most, "{} claimed", claimed.len());
                    for task in claimed {
                        assert_eq!(task.attempts, 1);
                        runs.lock()
                            .expect("the run list")
                            .push((task.id, worker.name().to_owned()));
                        worker.complete(task.id).await.expect("completes");
                    }
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

/// A claim of several tasks takes what that many claims of one would: the oldest that are due, by
/// when each became due and then by id, whichever root they belong to, each with its own lease and
/// its attempt counted. So a pool that asks for its free slots at once takes the tasks in the order
/// it took them one request at a time, and a root with many tasks due gets no more of a turn.
#[tokio::test]
async fn a_claim_of_several_takes_the_oldest_due_in_the_order_single_claims_would() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hosts: Vec<String> = (0..6).map(|i| format!("host{i}.example.com")).collect();
    let observables: Vec<(ObservableKind, &str)> = hosts
        .iter()
        .map(|v| (ObservableKind::Fqdn, v.as_str()))
        .collect();
    // a large root, queued first, and a small one
    let (large, large_ids) = root_with(db, "analysis", &observables).await;
    let (small, small_ids) = root_with(db, "analysis", &observables[..2]).await;
    let mut tx = db.begin().await.expect("begins");
    let mut tasks = Vec::new();
    for id in &large_ids {
        tasks.push(
            queue::enqueue(&mut tx, large, *id, "mine")
                .await
                .expect("queues")
                .expect("new"),
        );
    }
    for id in &small_ids {
        tasks.push(
            queue::enqueue(&mut tx, small, *id, "mine")
                .await
                .expect("queues")
                .expect("new"),
        );
    }
    let theirs = queue::enqueue(&mut tx, small, small_ids[0], "theirs")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");
    // when each became due: the small root's two between the large root's, one of the large
    // root's not yet, and two at the same moment, which their ids order
    let due_in = [-50, -40, -40, -10, 3600, -5, -45, -20];
    for (task, seconds) in tasks.iter().zip(due_in) {
        sqlx::query(
            "UPDATE queue.tasks SET run_after = now() + make_interval(secs => $2) WHERE id = $1",
        )
        .bind(task.0)
        .bind(f64::from(seconds))
        .execute(db.pool())
        .await
        .expect("sets when it's due");
    }
    sqlx::query(
        "UPDATE queue.tasks SET run_after = (SELECT run_after FROM queue.tasks WHERE id = $1)
         WHERE id = $2",
    )
    .bind(tasks[1].0)
    .bind(tasks[2].0)
    .execute(db.pool())
    .await
    .expect("makes two due at the same moment");
    let oldest_first = [
        tasks[0], tasks[6], tasks[1], tasks[2], tasks[7], tasks[3], tasks[5],
    ];

    let worker = worker(&test_db, "several", &["mine"], Duration::from_secs(60)).await;
    let claimed = worker.claim_up_to(5).await.expect("claims");
    assert_eq!(
        claimed.iter().map(|task| task.id).collect::<Vec<_>>(),
        oldest_first[..5]
    );
    for task in &claimed {
        assert_eq!(task.attempts, 1);
        assert_eq!(
            queue::state(db, task.id).await.expect("reads"),
            Some(TaskState::Running)
        );
    }
    // what's left that is due, though it asked for more; the task that isn't due and the other
    // module's stay
    let rest = worker.claim_up_to(5).await.expect("claims");
    assert_eq!(
        rest.iter().map(|task| task.id).collect::<Vec<_>>(),
        oldest_first[5..]
    );
    assert!(worker.claim_up_to(5).await.expect("claims").is_empty());
    for task in [tasks[4], theirs] {
        assert_eq!(
            queue::state(db, task).await.expect("reads"),
            Some(TaskState::Queued)
        );
    }

    // given back, they are claimed one at a time in the same order
    for task in claimed.iter().chain(&rest) {
        worker.release(task.id).await.expect("gives it back");
    }
    let mut singly = Vec::new();
    while let Some(task) = worker.claim().await.expect("claims") {
        assert_eq!(task.attempts, 1, "a release doesn't count the claim");
        singly.push(task.id);
    }
    assert_eq!(singly, oldest_first);
}
