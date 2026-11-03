//! PLAN.md 2.16's Done check: a pool with a limit of 4 never runs a fifth task while 50 are
//! queued, a panicking task leaves a failed row while the others finish, and a lookup can't
//! connect to a port its manifest doesn't allow.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::pool::{AsyncPool, PoolDefinition};
use ace_pool::testing::{self, ALLOWED_PORT, MOST_AT_ONCE, OTHER_PORT};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{Core, TOKEN, root_with_tasks, test_pool, wait_until_idle};

fn definition(concurrency: usize) -> PoolDefinition {
    PoolDefinition {
        name: "test".to_owned(),
        modules: Arc::new(testing::modules(&json!({})).expect("the test modules")),
        concurrency,
        sandbox: Default::default(),
        secrets: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_with_a_limit_of_4_never_runs_a_fifth_task() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_counted"],
        Duration::from_secs(30),
    )
    .await;
    let values: Vec<String> = (0..50).map(|i| format!("host{i}.example.com")).collect();
    let root = root_with_tasks(&core, &values, "test_counted").await;

    let client = LeaseClient::new(&core.url, TOKEN, "pool").expect("a client");
    let pool = AsyncPool::new(client, &definition(4)).lease_wait(Duration::from_secs(1));
    let stop = CancellationToken::new();
    let running = tokio::spawn({
        let stop = stop.clone();
        async move { pool.run(stop).await }
    });
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    stop.cancel();
    let stats = running.await.expect("the pool stops");
    println!(
        "{stats:?}, at most {} at once",
        MOST_AT_ONCE.load(Ordering::SeqCst)
    );
    assert_eq!(stats.tasks, 50);
    assert_eq!(stats.errors, 0);
    assert_eq!(MOST_AT_ONCE.load(Ordering::SeqCst), 4);
    let done: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM queue.tasks WHERE root_id = $1 AND state = 'done'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("counts");
    assert_eq!(done, 50);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_task_leaves_a_failed_row_while_the_others_finish() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_panicky"],
        Duration::from_secs(30),
    )
    .await;
    let values: Vec<String> = (0..10)
        .map(|i| {
            if i % 5 == 0 {
                format!("panic{i}.example.com")
            } else {
                format!("fine{i}.example.com")
            }
        })
        .collect();
    let root = root_with_tasks(&core, &values, "test_panicky").await;
    let client = LeaseClient::new(&core.url, TOKEN, "pool").expect("a client");
    let pool = AsyncPool::new(client, &definition(4)).lease_wait(Duration::from_secs(1));
    let stop = CancellationToken::new();
    let running = tokio::spawn({
        let stop = stop.clone();
        async move { pool.run(stop).await }
    });
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    stop.cancel();
    running.await.expect("the pool stops");

    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT o.value, t.state::text, t.error FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id WHERE t.root_id = $1",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("reads");
    let mut states: BTreeMap<String, u32> = BTreeMap::new();
    for (value, state, error) in &rows {
        *states.entry(state.clone()).or_default() += 1;
        if value.starts_with("panic") {
            assert_eq!(state, "failed", "{value}");
            assert_eq!(
                error.as_deref(),
                Some(format!("the module panicked: test_panicky was given {value}").as_str())
            );
        } else {
            assert_eq!(state, "done", "{value}");
        }
    }
    assert_eq!(
        states,
        BTreeMap::from([("done".to_owned(), 8), ("failed".to_owned(), 2)])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contained_pools_lookup_cant_connect_to_a_port_its_manifest_doesnt_allow() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_connect"],
        Duration::from_secs(30),
    )
    .await;
    // something listens on both ports, so only containment can refuse one
    let _allowed = std::net::TcpListener::bind(("127.0.0.1", ALLOWED_PORT)).expect("binds");
    let _other = std::net::TcpListener::bind(("127.0.0.1", OTHER_PORT)).expect("binds");
    let root = root_with_tasks(&core, &["example.com".to_owned()], "test_connect").await;

    let mut pool = test_pool(&core, &["lookups", "--contained"])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the pool starts");
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    pool.kill().expect("stops the pool");
    let output = pool.wait_with_output().expect("the pool exits");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("contained: Contained"), "{stderr}");

    let note: String =
        sqlx::query_scalar("SELECT details->>'note' FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the lookup's result");
    println!("{note}");
    assert_eq!(
        note,
        format!("{ALLOWED_PORT}: connected; {OTHER_PORT}: Permission denied (os error 13)")
    );
}
