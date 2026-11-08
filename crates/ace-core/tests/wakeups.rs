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

/// A task delayed while a worker already waits wakes it, so the worker waits only until the
/// delay ends, not until its own fallback. Before, the delay sent no notification, and a lease
/// request that started waiting before the delay slept out its whole wait: the Splunk task in
/// the Compose stack's end-to-end test took 10 seconds a delay instead of 1 (PLAN.md 2.30).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_delayed_while_a_worker_waits_is_claimed_when_its_delay_ends() {
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let (root, ids) = root_with(&db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let module = "clicker_detection_splunk";
    let mut tx = db.begin().await.expect("begins");
    let task = queue::enqueue(&mut tx, root, ids[0], module)
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");
    let first = worker(&test_db, "first", &[module], Duration::from_secs(60)).await;
    let claimed = first.claim().await.expect("claims").expect("a task");
    assert_eq!(claimed.id, task);

    let waiter = worker(&test_db, "waiter", &[module], Duration::from_secs(60)).await;
    let mut wakeups = Wakeups::listen(waiter.db()).await.expect("listens");
    let delayed = tokio::spawn(async move {
        // the waiter is waiting by now, with nothing due
        tokio::time::sleep(Duration::from_millis(500)).await;
        // before the call, because the core sets run_after to its own now() plus the delay
        // inside it: an instant taken after the call returns is late by the call's own time,
        // which under load was over 100 ms, and a claim on time then looked early
        let delayed_at = Instant::now();
        first
            .delay(task, Duration::from_secs(1), &serde_json::json!({}))
            .await
            .expect("delays");
        delayed_at
    });
    let (again, waits) = tokio::time::timeout(
        Duration::from_secs(10),
        waiter.next_task(&mut wakeups, Duration::from_secs(60)),
    )
    .await
    .expect("claims within 10 seconds")
    .expect("claims");
    let claimed_at = Instant::now();
    let delayed_at = delayed.await.expect("delays");
    let after = claimed_at.saturating_duration_since(delayed_at);
    println!("claimed {after:?} after the delay began, waits {waits:?}");
    assert_eq!(again.id, task);
    assert_eq!(waits.timed_out, 0, "the fallback fired");
    assert!(
        // run_after is no earlier than delayed_at plus the delay; 50 ms covers the two
        // containers' clocks, which aren't one clock
        after >= Duration::from_millis(950) && after < Duration::from_secs(3),
        "claimed {after:?} after a 1-second delay began"
    );
}
