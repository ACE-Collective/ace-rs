//! PLAN.md 2.19's Done check: the supervisor kills a task process at its deadline and writes a
//! failed-task row with the error and the input hashes.

mod common;

use std::time::{Duration, Instant};

use ace_pool::testing;

use common::{Core, PoolProcess, enqueue, root_with_bytes, test_pool, wait_until_idle};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_infinite_loop_is_killed_at_its_deadline_and_its_row_names_its_inputs() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_spin"],
        Duration::from_secs(30),
    )
    .await;
    // a root in event mode queues nothing by itself
    let (root, sha256) = root_with_bytes(&core, "event", b"spin on this", "spin.bin").await;
    enqueue(&core, root, &sha256.to_hex(), "test_spin").await;

    let started = Instant::now();
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "1"],
    ));
    wait_until_idle(&core, root, Duration::from_secs(30)).await;
    let took = started.elapsed();
    let stderr = pool.stop();
    println!("ended after {took:?}");

    let (state, error, inputs): (String, Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT state::text, error, input_hashes FROM queue.tasks WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task's row");
    assert_eq!(state, "failed", "{stderr}");
    assert_eq!(
        error.as_deref(),
        Some("the task process ran past its deadline of 2s and was killed")
    );
    assert_eq!(inputs, [sha256.to_hex()]);
    // it spun on its input before the deadline, and the kill came at the deadline, not later
    assert!(stderr.contains("test_spin: spinning on"), "{stderr}");
    assert!(took < Duration::from_secs(10), "{took:?}");
}
