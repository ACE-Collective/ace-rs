//! PLAN.md 2.16's Done check: a pool with a limit of 4 never runs a fifth task while 50 are
//! queued, a panicking task leaves a failed row while the others finish, and a lookup can't
//! connect to a port its manifest doesn't allow. And decision 28's: a contained pool reaches the
//! bucket only when one of its modules adds files it fetched, and the core refuses an upload from a
//! lookup that doesn't declare it. And decision 45's: a lookup that reads its input file gets its
//! bytes, and its pool the bucket's port, and one that doesn't gets neither.

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

/// Runs `module`'s tasks for `values` in a contained test pool told where the bucket is, with
/// `settings`, until the root is idle, and returns the root.
async fn run_contained(
    core: &Core,
    settings: serde_json::Value,
    module: &str,
    values: &[&str],
) -> uuid::Uuid {
    let values: Vec<String> = values.iter().map(|v| (*v).to_owned()).collect();
    let root = root_with_tasks(core, &values, module).await;
    run_contained_root(core, settings, root).await
}

/// Runs a contained `lookups` pool with these settings until `root` has no task left to run.
async fn run_contained_root(
    core: &Core,
    settings: serde_json::Value,
    root: uuid::Uuid,
) -> uuid::Uuid {
    let endpoint = std::env::var(ace_pool::pool::BUCKET_ENDPOINT_VAR)
        .expect("the dev container's ACE4_BUCKET_ENDPOINT");
    let mut pool = test_pool(
        core,
        &[
            "lookups",
            "--contained",
            "--settings",
            &settings.to_string(),
        ],
    )
    .env(ace_pool::pool::BUCKET_ENDPOINT_VAR, &endpoint)
    .stderr(std::process::Stdio::piped())
    .spawn()
    .expect("the pool starts");
    // read while it runs, so its log never fills the pipe and stalls it
    let mut pipe = pool.stderr.take().expect("its stderr");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _read = std::io::Read::read_to_string(&mut pipe, &mut text);
        text
    });
    wait_until_idle(core, root, Duration::from_secs(60)).await;
    pool.kill().expect("stops the pool");
    pool.wait().expect("the pool exits");
    let stderr = reader.join().expect("the reader");
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    root
}

async fn connect_note(core: &Core, root: uuid::Uuid) -> String {
    sqlx::query_scalar(
        "SELECT details->>'note' FROM analysis.results WHERE root_id = $1 AND module = 'test_connect'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the lookup's result")
}

/// PLAN.md decision 28: a contained network pool may connect to the bucket's port, from
/// `ACE4_BUCKET_ENDPOINT`, only when one of its modules declares it adds files it fetched; then such
/// a module's file reaches the bucket and the tree. In the same pool, a lookup that writes a file
/// without declaring it gets no upload URL: the core fails its task, saying why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_reaches_the_bucket_only_when_a_module_adds_files_it_fetched() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_connect", "test_fetches", "test_lookup_writes"],
        Duration::from_secs(30),
    )
    .await;
    let db = core.test_db.db();

    // without a module that adds fetched files, the bucket's port is refused
    let root = run_contained(&core, json!({}), "test_connect", &["without.example.com"]).await;
    let note = connect_note(&core, root).await;
    assert!(
        note.ends_with("; bucket: Permission denied (os error 13)"),
        "{note}"
    );

    // with one, it connects, and its file lands
    let settings = json!({"test_fetches": null});
    let root = run_contained(
        &core,
        settings.clone(),
        "test_connect",
        &["with.example.com"],
    )
    .await;
    let note = connect_note(&core, root).await;
    assert!(note.ends_with("; bucket: connected"), "{note}");
    assert!(
        note.contains(&format!("{OTHER_PORT}: Permission denied")),
        "other ports stay refused: {note}"
    );
    let root = run_contained(
        &core,
        settings.clone(),
        "test_fetches",
        &["mail.example.com"],
    )
    .await;
    let files: Vec<(String, i64)> = sqlx::query_as(
        "SELECT f.path, s.size FROM analysis.files f
           JOIN analysis.observables o ON o.root_id = f.root_id AND o.id = f.observable_id
           JOIN store.objects s ON s.sha256 = o.value AND s.pool = 'alert_files'
         WHERE f.root_id = $1",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("the files");
    assert_eq!(files, [("mail.example.com.fetched".to_owned(), 16)]);

    // a lookup that doesn't declare it: no upload URL, and its task fails saying why, though its
    // pool could reach the bucket
    let root = run_contained(
        &core,
        settings,
        "test_lookup_writes",
        &["undeclared.example.com"],
    )
    .await;
    let (state, error): (String, Option<String>) = sqlx::query_as(
        "SELECT state::text, error FROM queue.tasks WHERE root_id = $1 AND module = 'test_lookup_writes'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the task");
    assert_eq!(state, "failed");
    let error = error.unwrap_or_default();
    assert!(error.contains("ADDS_FETCHED_FILES"), "{error}");
    let results: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("counts");
    assert_eq!(results, 0);
}

/// PLAN.md decision 45: a lookup that reads its input file (`Module::READS_INPUT_FILE`) gets the
/// file's bytes in a contained network pool, which reaches the bucket's port only because such a
/// module is in it; a lookup on the same file that doesn't declare it gets the file's path and no
/// bytes, and the core sends it no download.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lookup_reads_its_input_file_only_when_it_declares_it() {
    use ace_core::bucket::{ALERT_FILES, Hold};
    use ace_core::tree;
    let modules = ["test_connect", "test_reads_file", "test_file_record"];
    let core = Core::start(testing::test_manifests(), &modules, Duration::from_secs(30)).await;
    let db = core.test_db.db();

    // without a module that reads its file, the bucket's port is refused
    let root = run_contained(&core, json!({}), "test_connect", &["without.example.com"]).await;
    let note = connect_note(&core, root).await;
    assert!(
        note.ends_with("; bucket: Permission denied (os error 13)"),
        "{note}"
    );
    let settings = json!({"test_reads_file": null});
    let root = run_contained(
        &core,
        settings.clone(),
        "test_connect",
        &["with.example.com"],
    )
    .await;
    let note = connect_note(&core, root).await;
    assert!(note.ends_with("; bucket: connected"), "{note}");

    // a file for both lookups
    let bytes = b"a file a vendor's sandbox would take";
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_bytes(ALERT_FILES, bytes, Some(&Hold::root(root.id)))
        .await
        .expect("puts the bytes")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let id = tree::upsert_observable(
        &mut tx,
        root.id,
        &ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.to_hex()),
    )
    .await
    .expect("adds")
    .id;
    tree::add_file(&mut tx, root.id, id, "sample.bin", &[])
        .await
        .expect("records the file");
    for module in ["test_reads_file", "test_file_record"] {
        ace_core::queue::enqueue(&mut tx, root.id, id, module)
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    run_contained_root(&core, settings, root.id).await;
    let notes: Vec<(String, String)> = sqlx::query_as(
        "SELECT module, details->>'note' FROM analysis.results WHERE root_id = $1 ORDER BY module",
    )
    .bind(root.id)
    .fetch_all(db.pool())
    .await
    .expect("the results");
    let hex = sha256.to_hex();
    assert_eq!(
        notes,
        [
            (
                "test_file_record".to_owned(),
                "no bytes; sample.bin".to_owned()
            ),
            (
                "test_reads_file".to_owned(),
                format!(
                    "bytes {hex} {} (the record says {hex}); sample.bin",
                    bytes.len()
                )
            ),
        ]
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
        None,
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
