//! PLAN.md 2.8: workers wait on LISTEN/NOTIFY, with a bounded timeout as the fallback.

mod common;

use std::time::{Duration, Instant};

use ace_core::queue::{self, Wakeups};
use ace_core::testing::TestDb;
use ace_results::ObservableKind;

use common::{root_with, worker};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_is_claimed_on_its_notification_without_the_fallback_firing() {
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let (root, ids) = root_with(
        &db,
        "analysis",
        &[
            (ObservableKind::Fqdn, "example.com"),
            (ObservableKind::Fqdn, "example.org"),
        ],
    )
    .await;
    let waiter = worker(
        &test_db,
        "waiter",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let mut wakeups = Wakeups::listen(waiter.db()).await.expect("listens");

    // first a task for a module the worker doesn't run, then one for its own
    let queued = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        for (id, module) in [(ids[0], "yara_scanner_v3_4"), (ids[1], "rdap_analyzer")] {
            let mut tx = db.begin().await.expect("begins");
            let task = queue::enqueue(&mut tx, root, id, module)
                .await
                .expect("queues")
                .expect("new");
            tx.commit().await.expect("commits");
            if module == "rdap_analyzer" {
                return (task, Instant::now());
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        unreachable!()
    });

    let (task, waits) = tokio::time::timeout(
        Duration::from_secs(10),
        // the fallback is a minute, far longer than the test waits
        waiter.next_task(&mut wakeups, Duration::from_secs(60)),
    )
    .await
    .expect("claims within 10 seconds")
    .expect("claims");
    let claimed_at = Instant::now();
    let (expected, queued_at) = queued.await.expect("queues");
    println!(
        "claimed {:?} after the task was queued, waits {waits:?}",
        claimed_at.saturating_duration_since(queued_at)
    );
    assert_eq!(task.id, expected);
    assert_eq!(task.module, "rdap_analyzer");
    assert_eq!(waits.timed_out, 0, "the fallback fired");
    assert_eq!(waits.notified, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_notification_the_fallback_still_finds_the_task() {
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let (root, ids) = root_with(&db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let waiter = worker(
        &test_db,
        "waiter",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let mut wakeups = Wakeups::listen(waiter.db()).await.expect("listens");
    // a lost notification, as when the listener's connection drops at the wrong moment
    sqlx::raw_sql("ALTER TABLE queue.tasks DISABLE TRIGGER tasks_notify")
        .execute(db.pool())
        .await
        .expect("disables the trigger");
    let queued = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut tx = db.begin().await.expect("begins");
        let task = queue::enqueue(&mut tx, root, ids[0], "rdap_analyzer")
            .await
            .expect("queues")
            .expect("new");
        tx.commit().await.expect("commits");
        task
    });

    let started = Instant::now();
    let (claimed, waits) = waiter
        .next_task(&mut wakeups, Duration::from_millis(600))
        .await
        .expect("claims");
    let waited = started.elapsed();
    assert_eq!(claimed.id, queued.await.expect("queues"));
    assert_eq!(waits.notified, 0);
    assert_eq!(waits.timed_out, 1);
    assert!(waited >= Duration::from_millis(600), "{waited:?}");
}
