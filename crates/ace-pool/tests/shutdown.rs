//! PLAN.md 2.21's Done check: shutdown with a hung upstream finishes within its deadline, and
//! the hung task's lease is released. Twice: with a lookup that awaits its upstream, which the
//! task's cancellation stops, and with one stuck in a blocking call, which nothing stops, so
//! the pool abandons it at the deadline and gives its lease back.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_pool::client::LeaseClient;
use ace_pool::pool::{AsyncPool, PoolDefinition};
use ace_pool::testing;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{Core, TOKEN, root_with_tasks, task_of};

/// An upstream that accepts connections and never answers, until it is dropped.
async fn hung_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("an address").to_string();
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (address, server)
}

async fn shut_down_with_a_hung_upstream(blocking: bool) {
    let core = Core::start(
        testing::test_manifests(),
        &["test_hung"],
        Duration::from_secs(30),
    )
    .await;
    let (address, upstream) = hung_upstream().await;
    let root = root_with_tasks(&core, &["slow.example.com".to_owned()], "test_hung").await;
    let modules =
        testing::modules(&json!({"test_hung": {"address": address, "blocking": blocking}}))
            .expect("the test modules");
    let definition = PoolDefinition {
        name: "test".to_owned(),
        modules: Arc::new(modules),
        concurrency: 4,
        sandbox: Default::default(),
        secrets: Vec::new(),
    };
    let grace = Duration::from_secs(2);
    let pool = AsyncPool::new(
        LeaseClient::new(&core.url, TOKEN, "pool").expect("a client"),
        &definition,
    )
    .lease_wait(Duration::from_secs(1))
    .shutdown_grace(grace);
    let stop = CancellationToken::new();
    let running = tokio::spawn({
        let stop = stop.clone();
        async move { pool.run(stop).await }
    });

    // the task is running and waiting on its upstream
    let started = Instant::now();
    while task_of(&core, root, "test_hung").await.0 != "running" {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the task never started"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    stop.cancel();
    let stopping = Instant::now();
    let stats = tokio::time::timeout(Duration::from_secs(30), running)
        .await
        .expect("shutdown ends")
        .expect("the pool's task");
    let took = stopping.elapsed();
    println!("blocking: {blocking}, shut down in {took:?}, {stats:?}");
    // the grace, plus the bounded calls that give leases back
    assert!(took < grace + Duration::from_secs(2), "{took:?}");
    assert_eq!(stats.released_at_deadline, u64::from(blocking));

    let (state, owner, attempts): (String, Option<String>, i32) = sqlx::query_as(
        "SELECT state::text, lease_owner, attempts FROM queue.tasks WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task");
    assert_eq!((state.as_str(), owner, attempts), ("queued", None, 0));
    // let a blocked thread go, so the test's runtime can stop
    upstream.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_with_an_upstream_that_never_answers_releases_the_lease_in_time() {
    shut_down_with_a_hung_upstream(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_with_a_module_stuck_in_a_blocking_call_releases_the_lease_in_time() {
    shut_down_with_a_hung_upstream(true).await;
}
