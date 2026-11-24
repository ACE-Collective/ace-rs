//! PLAN.md 2.7: leases. A worker renews its lease while it runs; the reaper takes back a task
//! whose lease expired and fails one at its attempt limit. The Done check kills a real worker
//! process mid-task.

use crate::common;

use std::process::Stdio;
use std::time::{Duration, Instant};

use ace_core::db::{Db, DbConfig};
use ace_core::queue::{self, QueueError, TaskState, Worker, reap_expired_leases, run_reaper};
use ace_core::testing::TestDb;
use ace_results::ObservableKind;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use common::{root_with, worker};

/// Set to a test database's name, it makes `worker_process` the killed worker.
const CHILD: &str = "ACE_RS_LEASE_TEST_CHILD";
const LEASE: Duration = Duration::from_secs(2);

/// Not a test of its own: the worker process the kill test starts and kills. It claims the task,
/// keeps its lease and never finishes. Without `ACE_RS_LEASE_TEST_CHILD` it returns at once.
#[tokio::test]
async fn worker_process() {
    let Ok(database) = std::env::var(CHILD) else {
        return;
    };
    let config = DbConfig::from_env("lease-test-child")
        .expect("ACE_RS_DATABASE_URL")
        .database(&database);
    let db = Db::connect(&config).await.expect("connects");
    let worker = Worker::new(db, "child", vec!["slow_module".to_owned()], LEASE);
    let task = worker.claim().await.expect("claims").expect("a task");
    let _keeper = worker.keep_lease(task.id);
    println!("claimed {}", task.id.0);
    // a module that never finishes
    tokio::time::sleep(Duration::from_secs(600)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_a_worker_mid_task_reruns_the_task_after_its_lease_expires() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    let task = queue::enqueue(&mut tx, root, ids[0], "slow_module")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");

    // libtest names a test by its path in the test program: this module's, less the crate's name
    let (_, module) = module_path!()
        .split_once("::")
        .expect("a module of tests/main.rs");
    let mut child = tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            &format!("{module}::worker_process"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, test_db.name())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("starts the worker process");
    let mut lines = BufReader::new(child.stdout.take().expect("its stdout")).lines();
    let claimed = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(line) = lines.next_line().await.expect("reads") {
            // libtest's "test worker_process ... " has no newline, so the marker can follow it
            if let Some((_, id)) = line.split_once("claimed ") {
                return id.trim().parse::<i64>().expect("a task id");
            }
        }
        panic!("the worker process exited without claiming");
    })
    .await
    .expect("the worker process claims within 30 seconds");
    assert_eq!(claimed, task.0);

    // while it lives, its renewals keep the task through two lease lengths
    tokio::time::sleep(LEASE * 2).await;
    assert_eq!(
        reap_expired_leases(db, None).await.expect("reaps"),
        Default::default()
    );
    assert_eq!(
        queue::state(db, task).await.expect("reads"),
        Some(TaskState::Running)
    );

    // the lease the kill leaves ends within a lease length, so the task comes back once it runs out;
    // checked here rather than by when the task is claimed again, which adds the reaper's and the
    // claims' own delays on a loaded machine
    let ends_within_a_lease: bool = sqlx::query_scalar(
        "SELECT lease_expires_at <= now() + make_interval(secs => $2) FROM queue.tasks WHERE id = $1",
    )
    .bind(task.0)
    .bind(LEASE.as_secs_f64())
    .fetch_one(db.pool())
    .await
    .expect("reads the lease");
    assert!(ends_within_a_lease, "the lease runs past a lease length");
    child.kill().await.expect("kills the worker process");
    let killed = Instant::now();
    let rescuer = worker(
        &test_db,
        "rescuer",
        &["slow_module"],
        Duration::from_secs(60),
    )
    .await;
    assert!(
        rescuer.claim().await.expect("claims").is_none(),
        "the task is still leased"
    );

    // the reaper runs on its own; the task comes back once the lease runs out
    let stop = CancellationToken::new();
    let reaper = tokio::spawn(run_reaper(
        db.clone(),
        Duration::from_millis(100),
        stop.clone(),
        None,
    ));
    let rerun = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(task) = rescuer.claim().await.expect("claims") {
                return task;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the task is claimable again within 10 seconds");
    let waited = killed.elapsed();
    stop.cancel();
    reaper.await.expect("the reaper stops");
    println!("claimed again {waited:?} after the kill");
    assert_eq!(rerun.id, task);
    assert_eq!(rerun.attempts, 2);
    // the last renewal was at most a third of a lease before the kill
    assert!(waited >= LEASE / 2, "{waited:?}");
    rescuer.complete(rerun.id).await.expect("completes");
    assert_eq!(
        queue::state(db, task).await.expect("reads"),
        Some(TaskState::Done)
    );
}

#[tokio::test]
async fn a_task_whose_lease_keeps_expiring_fails_at_its_attempt_limit() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    let task = queue::enqueue(&mut tx, root, ids[0], "crashing_module")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");

    let short = Duration::from_millis(300);
    let crasher = worker(&test_db, "crasher", &["crashing_module"], short).await;
    for attempt in 1..=queue::DEFAULT_MAX_ATTEMPTS {
        let claimed = crasher.claim().await.expect("claims").expect("a task");
        assert_eq!(claimed.attempts, attempt);
        // the worker dies without renewing; a renewal after the reaper is too late
        tokio::time::sleep(short + Duration::from_millis(200)).await;
        let reaped = reap_expired_leases(db, None).await.expect("reaps");
        if attempt < queue::DEFAULT_MAX_ATTEMPTS {
            assert_eq!(reaped.requeued, [task]);
        } else {
            assert_eq!(reaped.failed, [task]);
        }
        assert!(matches!(
            crasher.renew(task).await,
            Err(QueueError::LeaseLost(_))
        ));
    }
    assert_eq!(
        queue::state(db, task).await.expect("reads"),
        Some(TaskState::Failed)
    );
    let error: Option<String> = sqlx::query_scalar("SELECT error FROM queue.tasks WHERE id = $1")
        .bind(task.0)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(
        error.as_deref(),
        Some("the lease expired on all 3 attempts; the last owner was crasher")
    );
    assert!(crasher.claim().await.expect("claims").is_none());
}

#[tokio::test]
async fn renewing_extends_the_lease_and_the_keeper_fires_when_the_task_is_lost() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    let task = queue::enqueue(&mut tx, root, ids[0], "module")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");
    let lease = Duration::from_millis(600);
    let holder = worker(&test_db, "holder", &["module"], lease).await;
    let claimed = holder.claim().await.expect("claims").expect("a task");
    let renewed = holder.renew(task).await.expect("renews");
    assert!(renewed.expires_at >= claimed.lease_expires_at);
    assert!(!renewed.cancel_requested);

    // the keeper renews past several lease lengths
    let keeper = holder.keep_lease(task);
    tokio::time::sleep(lease * 3).await;
    assert!(
        reap_expired_leases(db, None)
            .await
            .expect("reaps")
            .requeued
            .is_empty()
    );
    assert!(!keeper.token().is_cancelled());

    // once the task is taken away, the keeper's next renewal fails and its token fires
    sqlx::query(
        "UPDATE queue.tasks SET state = 'queued', lease_owner = NULL, lease_expires_at = NULL
         WHERE id = $1",
    )
    .bind(task.0)
    .execute(db.pool())
    .await
    .expect("takes the task away");
    tokio::time::timeout(lease, keeper.token().cancelled())
        .await
        .expect("the token fires within a lease");
}
