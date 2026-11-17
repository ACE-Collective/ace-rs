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

use common::{Core, PoolProcess, TOKEN, root_with_tasks, test_pool, wait_until_idle};

fn definition(concurrency: usize) -> PoolDefinition {
    PoolDefinition {
        name: "test".to_owned(),
        modules: Arc::new(testing::modules(&json!({})).expect("the test modules")),
        concurrency,
        sandbox: Default::default(),
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
    // the most tasks the queue ever shows leased to the pool, read every few milliseconds
    let most_leased = tokio::spawn({
        let (db, stop) = (core.test_db.db().clone(), stop.clone());
        async move {
            let mut most = 0i64;
            while !stop.is_cancelled() {
                let leased: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM queue.tasks
                     WHERE root_id = $1 AND state = 'running' AND lease_owner = 'test/pool'",
                )
                .bind(root)
                .fetch_one(db.pool())
                .await
                .expect("counts");
                most = most.max(leased);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            most
        }
    });
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    stop.cancel();
    let stats = running.await.expect("the pool stops");
    let most_leased = most_leased.await.expect("the reader stops");
    println!(
        "{stats:?}, at most {} at once, at most {most_leased} leased",
        MOST_AT_ONCE.load(Ordering::SeqCst)
    );
    assert_eq!(stats.tasks, 50);
    assert_eq!(stats.errors, 0);
    assert_eq!(MOST_AT_ONCE.load(Ordering::SeqCst), 4);
    // it asks for its free slots and no more: it never holds a lease it has no slot for
    assert_eq!(most_leased, 4);
    // and takes several tasks a request: its first, with four slots free, brought four
    assert!(
        stats.leases <= 47,
        "{} requests brought the 50 tasks",
        stats.leases
    );
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

fn signal(pool: &PoolProcess, signal: i32) {
    let pid = i32::try_from(pool.pid()).expect("a pid");
    // SAFETY: kill takes integers only; the pid is this test's child, not yet reaped
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "signals the pool");
}

/// What a frozen pool, and then a killed one, takes with it: as many tasks as it has slots and no
/// more. A pool with three slots, frozen while it waits for work, is answered with three of the
/// seven tasks that come due, and the other four stay in the queue for a pool that can run them.
/// It is killed holding the three. Their leases run out, the reaper queues them again, and another
/// pool runs all seven to their end, the three on their second attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_pool_takes_as_many_tasks_with_it_as_it_has_slots_and_they_come_back() {
    let lease = Duration::from_secs(3);
    let core = Core::start(testing::test_manifests(), &["test_counted"], lease).await;
    let db = core.test_db.db();
    let pool = PoolProcess::start(test_pool(&core, &["lookups", "--concurrency", "3"]));
    // it runs a task, so it is up. A request asks for the slots free when it is sent, and the
    // one sent while that task ran asked for two; the test pool asks again every two seconds, so
    // by now the request it waits on asked for all three
    let first = root_with_tasks(&core, &["first.example.com".to_owned()], "test_counted").await;
    wait_until_idle(&core, first, Duration::from_secs(60)).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    signal(&pool, libc::SIGSTOP);

    let values: Vec<String> = (0..7).map(|i| format!("host{i}.example.com")).collect();
    let root = root_with_tasks(&core, &values, "test_counted").await;
    let leased = || async {
        let leased: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM queue.tasks
             WHERE root_id = $1 AND state = 'running' AND lease_owner LIKE 'test/test-pool-%'",
        )
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("counts");
        leased
    };
    let started = std::time::Instant::now();
    while leased().await < 3 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the frozen pool was given {} tasks",
            leased().await
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // it is given no more while it holds them
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        leased().await,
        3,
        "a pool with three slots holds three leases"
    );
    signal(&pool, libc::SIGKILL);
    drop(pool);

    let stop = CancellationToken::new();
    let reaper = tokio::spawn(ace_core::queue::run_reaper(
        db.clone(),
        Duration::from_millis(200),
        stop.clone(),
    ));
    let killed = std::time::Instant::now();
    let mut second = PoolProcess::start(test_pool(&core, &["lookups", "--concurrency", "3"]));
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    println!("all seven ended {:?} after the kill", killed.elapsed());
    stop.cancel();
    reaper.await.expect("the reaper stops");
    second.terminate(Duration::from_secs(15));

    let rows: Vec<(String, i32)> = sqlx::query_as(
        "SELECT state::text, attempts FROM queue.tasks WHERE root_id = $1 ORDER BY attempts, id",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("the tasks");
    let done = |attempts: i32| ("done".to_owned(), attempts);
    assert_eq!(
        rows,
        [
            done(1),
            done(1),
            done(1),
            done(1),
            done(2),
            done(2),
            done(2)
        ],
        "the four it never held ran once, and the three it held ran again"
    );
    // the three waited for their leases to run out, and no longer than that and a reaper's pass
    assert!(
        killed.elapsed() >= lease - Duration::from_secs(1),
        "{:?}",
        killed.elapsed()
    );
}
