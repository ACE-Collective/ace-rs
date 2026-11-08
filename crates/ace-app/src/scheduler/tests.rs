//! PLAN.md 6.7's Done check: each scheduled task runs once through the scheduler, as the component it
//! acts as, and does what ace3's does: `bucket_gc` deletes the unheld objects and expired holds and keeps
//! a held one, `yara_qa_prune` removes the expired QA matches with their holds and an audit row and keeps
//! a live one, `bucket_orphans` deletes bytes no index row names, and `bucket_verify` records an intact
//! object and fails on a corrupt one, which it keeps. Then the scheduler's own rules: one run across
//! replicas, missed due times run once, a lease no run starts under, an abandoned run, a hung task
//! stopped at its timeout without holding up another, a bounded shutdown, and the overlay's section.
//!
//! The bucket is shared with the other tests, so each test's bucket has a pool of its own and only
//! that one, and the bytes it puts are its own.

use std::sync::atomic::{AtomicUsize, Ordering};

use ace_core::bucket::{Bucket, BucketSettings, Hold, PoolConfig, Retention};
use ace_core::testing::TestDb;
use ace_results::Sha256;
use ace_store::{BucketConfig, NodeCache, Store};
use sha2::Digest;

use super::*;

struct Fixture {
    test_db: TestDb,
    _cache: tempfile::TempDir,
    service: Service,
    bucket: Bucket,
    pool: String,
}

impl Fixture {
    async fn new() -> Fixture {
        let test_db = TestDb::new().await;
        let cache = tempfile::tempdir().expect("a cache directory");
        let store = Store::new(
            &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
            NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
        );
        let pool = format!("test-{}", uuid::Uuid::new_v4().simple());
        let settings = BucketSettings {
            orphan_grace: Duration::ZERO,
            gc_batch_pause: Duration::from_millis(10),
            pools: [(
                pool.clone(),
                PoolConfig {
                    retention: Retention::Held {
                        grace: Duration::ZERO,
                    },
                },
            )]
            .into(),
            ..BucketSettings::default()
        };
        let orchestrator = ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        );
        Fixture {
            service: Service::new(test_db.db().clone(), orchestrator),
            bucket: Bucket::new(test_db.db().clone(), store, settings),
            _cache: cache,
            test_db,
            pool,
        }
    }

    fn db(&self) -> &Db {
        self.test_db.db()
    }

    fn scheduler(&self, tasks: Vec<Configured>, node: &str) -> Scheduler {
        Scheduler {
            node: node.to_owned(),
            poll: Duration::from_millis(50),
            stop_wait: Duration::from_secs(2),
            ..Scheduler::new(
                self.db().clone(),
                self.service.clone(),
                self.bucket.clone(),
                tasks,
            )
        }
    }

    /// Bytes no other test puts.
    fn unique(&self, what: &str) -> Vec<u8> {
        format!("{what} {} {}", self.pool, uuid::Uuid::new_v4()).into_bytes()
    }

    async fn object_exists(&self, sha256: &Sha256) -> (bool, bool) {
        let indexed = self
            .bucket
            .object(&self.pool, sha256)
            .await
            .expect("reads the index")
            .is_some();
        let stored = self
            .bucket
            .store()
            .exists(&self.pool, sha256)
            .await
            .expect("asks the bucket");
        (indexed, stored)
    }

    async fn clean_up(&self) {
        let store = self.bucket.store();
        for key in store.list(&format!("{}/", self.pool)).await.expect("lists") {
            store.delete_key(&key).await.expect("deletes");
        }
    }
}

/// The core's task called `name`, configured with no overlay section.
fn builtin(name: &str) -> Configured {
    configure(&Task::builtin(), &BTreeMap::new())
        .expect("the defaults configure")
        .into_iter()
        .find(|t| t.task.name == name)
        .expect("a core task")
}

/// Makes the task due an hour ago.
async fn make_due(db: &Db, task: &Configured) {
    scheduler::ensure(db, &task.task.name, &task.schedule, &|now| task.next(now))
        .await
        .expect("records the task");
    sqlx::query("UPDATE scheduler.tasks SET due_at = now() - interval '1 hour' WHERE name = $1")
        .bind(&task.task.name)
        .execute(db.pool())
        .await
        .expect("makes it due");
}

/// Waits until `task` has `count` ended runs, and returns its runs, newest first.
async fn ended_runs(db: &Db, task: &str, count: usize) -> Vec<scheduler::Run> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let runs = scheduler::runs(db, task, 100)
            .await
            .expect("reads the runs");
        if runs.iter().filter(|r| r.ended_at.is_some()).count() >= count {
            return runs;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{task} didn't run: {runs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Runs the scheduler with these tasks until `task` has run once, and returns its run.
async fn run_once(fixture: &Fixture, tasks: Vec<Configured>, task: &str) -> scheduler::Run {
    let stop = CancellationToken::new();
    let running = tokio::spawn(fixture.scheduler(tasks, "test/1").run(stop.clone()));
    let runs = ended_runs(fixture.db(), task, 1).await;
    stop.cancel();
    running.await.expect("the scheduler stops");
    assert_eq!(runs.len(), 1, "{runs:?}");
    runs.into_iter().next().expect("a run")
}

fn sha256_of(bytes: &[u8]) -> Sha256 {
    Sha256(sha2::Sha256::digest(bytes).into())
}

#[tokio::test]
async fn bucket_gc_deletes_what_nothing_holds_and_keeps_what_something_does() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let held = fixture.unique("held");
    let unheld = fixture.unique("unheld");
    let lapsed = fixture.unique("lapsed");
    fixture
        .bucket
        .put_bytes(pool, &held, Some(&Hold::new("test", "keeps")))
        .await
        .expect("puts");
    // a hold that lapsed on an object another hold keeps: GC prunes its row
    fixture
        .bucket
        .hold(
            pool,
            &sha256_of(&held),
            &Hold::new("test", "old").until(Utc::now() - chrono::Duration::hours(1)),
        )
        .await
        .expect("holds");
    fixture
        .bucket
        .put_bytes(pool, &unheld, None)
        .await
        .expect("puts");
    fixture
        .bucket
        .put_bytes(
            pool,
            &lapsed,
            Some(&Hold::new("test", "lapsed").until(Utc::now() - chrono::Duration::hours(1))),
        )
        .await
        .expect("puts");
    let task = builtin("bucket_gc");
    make_due(fixture.db(), &task).await;

    let run = run_once(&fixture, vec![task], "bucket_gc").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(
        run.summary,
        Some(json!({pool.as_str(): {"deleted": 2, "holds_pruned": 1}}))
    );
    assert_eq!(fixture.object_exists(&sha256_of(&held)).await, (true, true));
    assert_eq!(
        fixture.object_exists(&sha256_of(&unheld)).await,
        (false, false)
    );
    assert_eq!(
        fixture.object_exists(&sha256_of(&lapsed)).await,
        (false, false)
    );
    let holds: i64 = sqlx::query_scalar("SELECT count(*) FROM store.holds WHERE pool = $1")
        .bind(pool)
        .fetch_one(fixture.db().pool())
        .await
        .expect("counts");
    assert_eq!(holds, 1, "the lapsed holds went, the live one stayed");
    // GC writes no audit row (ace_service's maintenance docs say why)
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM service.audit")
        .fetch_one(fixture.db().pool())
        .await
        .expect("counts");
    assert_eq!(audit, 0);
    fixture.clean_up().await;
}

#[tokio::test]
async fn yara_qa_prune_removes_the_expired_matches_with_their_holds_and_an_audit_row() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let expired_sha = sha256_of(&fixture.unique("expired")).to_hex();
    let live_sha = sha256_of(&fixture.unique("live")).to_hex();
    let root = uuid::Uuid::new_v4();
    let mut ids = BTreeMap::new();
    for (sha256, version, expires) in [(&expired_sha, "v1", -1), (&live_sha, "v1", 29)] {
        // the index rows and holds the recorder would have written, without the bytes
        sqlx::query(
            "INSERT INTO store.objects (pool, sha256, size, mime_type) VALUES ('alert_files', $1, 1, 'text/plain')",
        )
        .bind(sha256)
        .execute(db.pool())
        .await
        .expect("an object row");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO yara.qa_matches (signature_uuid, signature_version, rule, namespace, sha256,
                 file_path, root_id, observable_id, match, expires_at)
             VALUES ('rule-uuid', $1, 'qa_rule', 'ns', $2, 'a.txt', $3, 1, '{}',
                     now() + make_interval(days => $4))
             RETURNING id",
        )
        .bind(version)
        .bind(sha256)
        .bind(root)
        .bind(expires)
        .fetch_one(db.pool())
        .await
        .expect("a QA match");
        sqlx::query(
            "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id, expires_at)
             VALUES ('alert_files', $1, 'yara_qa', $2, now() + make_interval(days => $3))",
        )
        .bind(sha256)
        .bind(id.to_string())
        .bind(expires)
        .execute(db.pool())
        .await
        .expect("its hold");
        ids.insert(sha256.clone(), id);
    }
    let task = builtin("yara_qa_prune");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "yara_qa_prune").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(run.summary, Some(json!({"removed": 1, "batches": 1})));
    let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM yara.qa_matches ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads");
    assert_eq!(left, [ids[&live_sha]]);
    let holds: Vec<String> =
        sqlx::query_scalar("SELECT holder_id FROM store.holds WHERE holder_kind = 'yara_qa'")
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(holds, [ids[&live_sha].to_string()]);
    let audit: (serde_json::Value, String, String, String, serde_json::Value) = sqlx::query_as(
        "SELECT actor::jsonb, action, target_kind, target_id, before FROM service.audit",
    )
    .fetch_one(db.pool())
    .await
    .expect("one audit row");
    assert_eq!(
        audit,
        (
            json!({"kind": "internal", "id": "scheduler:yara_qa_prune"}),
            "prune_qa_matches".to_owned(),
            "yara_qa_matches".to_owned(),
            "expired".to_owned(),
            json!({"matches": [{"id": ids[&expired_sha], "signature_version": "v1",
                                "sha256": expired_sha, "root": root}]}),
        )
    );
}

#[tokio::test]
async fn bucket_orphans_deletes_bytes_no_index_row_names() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let store = fixture.bucket.store();
    let indexed = fixture.unique("indexed");
    fixture
        .bucket
        .put_bytes(pool, &indexed, Some(&Hold::new("test", "keeps")))
        .await
        .expect("puts");
    let orphan = fixture.unique("orphan");
    let orphan_key = Store::key(pool, &sha256_of(&orphan)).expect("a key");
    store
        .put_raw(&orphan_key, orphan.clone())
        .await
        .expect("writes");
    let stray = format!("{pool}/not-a-digest");
    store
        .put_raw(&stray, b"stray".to_vec())
        .await
        .expect("writes");
    // the grace is zero, and the bucket keeps a key's time to the second
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let task = builtin("bucket_orphans");
    make_due(fixture.db(), &task).await;

    let run = run_once(&fixture, vec![task], "bucket_orphans").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    let size = orphan.len();
    assert_eq!(
        run.summary,
        Some(
            json!({pool.as_str(): {"scanned": 3, "orphaned": 1, "within_grace": 0, "deleted": 1,
                                    "bytes_reclaimed": size, "unrecognized": 1}})
        )
    );
    let mut keys = store.list(&format!("{pool}/")).await.expect("lists");
    keys.sort();
    let mut expected = vec![
        Store::key(pool, &sha256_of(&indexed)).expect("a key"),
        stray,
    ];
    expected.sort();
    assert_eq!(
        keys, expected,
        "the orphan went; the object and the stray key stayed"
    );
    fixture.clean_up().await;
}

#[tokio::test]
async fn bucket_verify_records_an_intact_object_and_fails_on_a_corrupt_one() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let intact = fixture.unique("intact");
    let corrupt = fixture.unique("corrupt");
    for bytes in [&intact, &corrupt] {
        fixture
            .bucket
            .put_bytes(pool, bytes, Some(&Hold::new("test", "keeps")))
            .await
            .expect("puts");
    }
    let corrupt_sha = sha256_of(&corrupt);
    fixture
        .bucket
        .store()
        .put_raw(
            &Store::key(pool, &corrupt_sha).expect("a key"),
            b"other bytes".to_vec(),
        )
        .await
        .expect("overwrites");
    let task = builtin("bucket_verify");
    make_due(fixture.db(), &task).await;

    let run = run_once(&fixture, vec![task], "bucket_verify").await;

    assert_eq!(run.outcome.as_deref(), Some("failed"), "{run:?}");
    assert_eq!(
        run.error.as_deref(),
        Some(format!("{pool}: 0 missing, 1 corrupt").as_str())
    );
    assert_eq!(
        run.summary,
        Some(
            json!({pool.as_str(): {"checked": 2, "verified": 1, "removed": 0, "missing": [],
                                    "corrupt": [corrupt_sha.to_hex()]}})
        )
    );
    let verified: Vec<(String, bool)> = sqlx::query_as(
        "SELECT sha256, verified_at IS NOT NULL FROM store.objects WHERE pool = $1 ORDER BY sha256",
    )
    .bind(pool)
    .fetch_all(fixture.db().pool())
    .await
    .expect("reads");
    let mut expected = vec![
        (sha256_of(&intact).to_hex(), true),
        (corrupt_sha.to_hex(), false),
    ];
    expected.sort();
    assert_eq!(verified, expected, "the corrupt object is kept, unverified");
    fixture.clean_up().await;
}

/// Each task's component holds its own grant and nothing the others need.
#[tokio::test]
async fn each_task_acts_as_its_own_component_with_only_its_grant() {
    let fixture = Fixture::new().await;
    let names = [
        ace_service::BUCKET_GC,
        ace_service::BUCKET_VERIFY,
        ace_service::SIGNATURE_QA_PURGE,
        ace_service::ALERT_READ,
    ];
    for (task, holds) in [
        ("bucket_gc", ace_service::BUCKET_GC),
        ("bucket_orphans", ace_service::BUCKET_GC),
        ("bucket_verify", ace_service::BUCKET_VERIFY),
        ("yara_qa_prune", ace_service::SIGNATURE_QA_PURGE),
    ] {
        let actor = builtin(task).actor;
        for name in &names {
            let allowed = fixture.service.allowed(&actor, name).await.expect("checks");
            assert_eq!(allowed, *name == holds, "{task} and {name}");
        }
    }
    // a task acting as a component without the grant is refused, and its run fails
    let mut task = builtin("bucket_gc");
    task.actor = Actor::Internal {
        id: Component::new("scheduler:nobody").expect("valid"),
    };
    make_due(fixture.db(), &task).await;
    let run = run_once(&fixture, vec![task], "bucket_gc").await;
    assert_eq!(run.outcome.as_deref(), Some("failed"));
    assert_eq!(
        run.error.as_deref(),
        Some("internal:scheduler:nobody doesn't hold bucket:gc")
    );
}

/// A task that counts its runs and takes `takes` each.
fn counting(name: &str, takes: Duration, count: Arc<AtomicUsize>) -> Task {
    Task::new(name, "0 * * * *", Duration::from_secs(30), move |_| {
        let count = count.clone();
        Box::pin(async move {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(takes).await;
            Ok(Done::ok(json!({"ran": true})))
        })
    })
}

fn configured(tasks: &[Task], overlay: &str) -> Vec<Configured> {
    let overlay = ace_sdk::Overlay::from_yaml(overlay).expect("an overlay");
    configure(tasks, &overlay.scheduler).expect("configures")
}

/// Two replicas, a task due three hours ago on an hourly schedule: one run between them, and its
/// next due time an hour or less away, so the missed hours aren't run each.
#[tokio::test]
async fn two_replicas_run_a_task_once_for_its_missed_due_times() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    for round in 0..3 {
        let name = format!("counted_{round}");
        let count = Arc::new(AtomicUsize::new(0));
        let tasks = configured(
            &[counting(&name, Duration::from_millis(300), count.clone())],
            "",
        );
        scheduler::ensure(db, &name, &tasks[0].schedule, &|now| tasks[0].next(now))
            .await
            .expect("records");
        sqlx::query(
            "UPDATE scheduler.tasks SET due_at = now() - interval '3 hours' WHERE name = $1",
        )
        .bind(&name)
        .execute(db.pool())
        .await
        .expect("makes it due");
        let stop = CancellationToken::new();
        let a = tokio::spawn(fixture.scheduler(tasks.clone(), "a/1").run(stop.clone()));
        let b = tokio::spawn(fixture.scheduler(tasks.clone(), "b/2").run(stop.clone()));
        let runs = ended_runs(db, &name, 1).await;
        // both keep polling a while after the run ends
        tokio::time::sleep(Duration::from_millis(500)).await;
        stop.cancel();
        a.await.expect("stops");
        b.await.expect("stops");
        let runs_after = scheduler::runs(db, &name, 10).await.expect("reads");
        assert_eq!(runs_after.len(), 1, "{runs_after:?}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"));
        let due = scheduler::due_at(db, &name)
            .await
            .expect("reads")
            .expect("a row");
        let now = Utc::now();
        assert!(
            due > now && due <= now + chrono::Duration::hours(1),
            "next due {due}"
        );
    }
}

/// A claim takes the lease, so no run starts while one holds the task, even when it's due again; a
/// run whose lease ran out is abandoned by the next claim.
#[tokio::test]
async fn a_lease_keeps_a_second_run_out_and_an_expired_one_is_abandoned() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let next = |now: DateTime<Utc>| Some(now + chrono::Duration::hours(1));
    let due_now = || async {
        sqlx::query("UPDATE scheduler.tasks SET due_at = now() - interval '1 minute'")
            .execute(db.pool())
            .await
            .expect("makes it due");
    };
    scheduler::ensure(db, "leased", "0 * * * *", &next)
        .await
        .expect("records");
    due_now().await;
    let first = scheduler::claim(db, "leased", "a/1", Duration::from_secs(3600), &next)
        .await
        .expect("claims")
        .expect("due");
    due_now().await;
    assert_eq!(
        scheduler::claim(db, "leased", "b/2", Duration::from_secs(3600), &next)
            .await
            .expect("claims"),
        None,
        "the first run holds the lease"
    );
    // the first run's node goes away: its lease ends with it unrecorded
    sqlx::query("UPDATE scheduler.tasks SET lease_until = now() - interval '1 second'")
        .execute(db.pool())
        .await
        .expect("ends the lease");
    let second = scheduler::claim(db, "leased", "b/2", Duration::from_secs(3600), &next)
        .await
        .expect("claims")
        .expect("due");
    let runs = scheduler::runs(db, "leased", 10).await.expect("reads");
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[1].id, first.run);
    assert_eq!(runs[1].outcome.as_deref(), Some("abandoned"));
    assert!(runs[0].ended_at.is_none());
    // the abandoned run's late end doesn't touch the task the second run holds
    assert!(
        !scheduler::finish(db, "leased", first.run, Outcome::Succeeded, None, None)
            .await
            .expect("records")
    );
    assert!(
        scheduler::finish(db, "leased", second.run, Outcome::Succeeded, None, None)
            .await
            .expect("records")
    );
    let lease: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT lease_until FROM scheduler.tasks WHERE name = 'leased'")
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(lease, None);
}

/// A hung task is stopped at its timeout and recorded `timed_out`; a quick one due beside it runs
/// and ends long before that; a failing one and a panicking one are `failed` with why.
#[tokio::test]
async fn a_hung_task_times_out_without_holding_up_the_others() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let count = Arc::new(AtomicUsize::new(0));
    let tasks = configured(
        &[
            Task::new("hangs", "0 * * * *", Duration::from_secs(3600), |_| {
                Box::pin(std::future::pending())
            }),
            counting("quick", Duration::ZERO, count.clone()),
            Task::new("fails", "0 * * * *", Duration::from_secs(30), |_| {
                Box::pin(async { Err("the bucket said no".to_owned()) })
            }),
            Task::new("panics", "0 * * * *", Duration::from_secs(30), |_| {
                Box::pin(async { panic!("a bug") })
            }),
        ],
        "scheduler:\n  hangs:\n    timeout_seconds: 2\n",
    );
    for task in &tasks {
        make_due(db, task).await;
    }
    let stop = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let running = tokio::spawn(fixture.scheduler(tasks, "test/1").run(stop.clone()));
    let quick = ended_runs(db, "quick", 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the quick task waited for the hung one"
    );
    assert_eq!(quick[0].outcome.as_deref(), Some("succeeded"));
    let hung = ended_runs(db, "hangs", 1).await;
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(hung[0].outcome.as_deref(), Some("timed_out"));
    assert_eq!(
        hung[0].error.as_deref(),
        Some("it ran past its timeout of 2 s")
    );
    let failed = ended_runs(db, "fails", 1).await;
    assert_eq!(
        (failed[0].outcome.as_deref(), failed[0].error.as_deref()),
        (Some("failed"), Some("the bucket said no"))
    );
    let panicked = ended_runs(db, "panics", 1).await;
    assert_eq!(panicked[0].outcome.as_deref(), Some("failed"));
    assert!(
        panicked[0]
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("the task panicked")),
        "{panicked:?}"
    );
    stop.cancel();
    running.await.expect("stops");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// A shutdown stops a running task and records it `stopped` within the stop wait, and lets the task go,
/// so another replica can run it at its next due time.
#[tokio::test]
async fn shutdown_stops_a_running_task_within_its_bound() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let tasks = configured(
        &[Task::new(
            "hangs",
            "0 * * * *",
            Duration::from_secs(3600),
            |_| Box::pin(std::future::pending()),
        )],
        "",
    );
    make_due(db, &tasks[0]).await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(fixture.scheduler(tasks, "test/1").run(stop.clone()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while scheduler::runs(db, "hangs", 1)
        .await
        .expect("reads")
        .is_empty()
    {
        assert!(tokio::time::Instant::now() < deadline, "it never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stopping = tokio::time::Instant::now();
    stop.cancel();
    running.await.expect("stops");
    assert!(
        stopping.elapsed() < Duration::from_secs(3),
        "{:?}",
        stopping.elapsed()
    );
    let runs = scheduler::runs(db, "hangs", 1).await.expect("reads");
    assert_eq!(runs[0].outcome.as_deref(), Some("stopped"));
    let lease: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT lease_until FROM scheduler.tasks WHERE name = 'hangs'")
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(lease, None);
}

/// A task the overlay turns off isn't claimed.
#[tokio::test]
async fn a_task_turned_off_doesnt_run() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let count = Arc::new(AtomicUsize::new(0));
    let on = Arc::new(AtomicUsize::new(0));
    let tasks = configured(
        &[
            counting("off", Duration::ZERO, count.clone()),
            counting("on", Duration::ZERO, on.clone()),
        ],
        "scheduler:\n  off:\n    enabled: false\n",
    );
    for task in &tasks {
        make_due(db, task).await;
    }
    let stop = CancellationToken::new();
    let running = tokio::spawn(fixture.scheduler(tasks, "test/1").run(stop.clone()));
    ended_runs(db, "on", 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.cancel();
    running.await.expect("stops");
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(
        scheduler::runs(db, "off", 1)
            .await
            .expect("reads")
            .is_empty()
    );
}

/// The overlay's section: defaults with none, each field over its default, an unknown key refused, a
/// removed task skipped with a warning, and a schedule that doesn't parse or a zero timeout refused.
#[test]
fn the_overlay_s_scheduler_section_sets_each_task_over_its_defaults() {
    let defaults = configured(&Task::builtin(), "");
    let listed: Vec<(&str, &str, u64, bool)> = defaults
        .iter()
        .map(|t| {
            (
                t.task.name.as_str(),
                t.schedule.as_str(),
                t.timeout.as_secs(),
                t.enabled,
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("bucket_gc", "0 * * * *", 3000, true),
            ("yara_qa_prune", "0 5 * * *", 3600, true),
            ("bucket_orphans", "0 5 * * 1", 14400, true),
            ("bucket_verify", "0 5 * * 1", 14400, true),
        ]
    );
    let actors: Vec<String> = defaults.iter().map(|t| t.actor.to_string()).collect();
    assert_eq!(
        actors,
        [
            "internal:scheduler:bucket_gc",
            "internal:scheduler:yara_qa_prune",
            "internal:scheduler:bucket_orphans",
            "internal:scheduler:bucket_verify",
        ]
    );
    // ace3's 05:00 UTC on a Monday
    let monday = "2026-11-09T05:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("a time");
    assert_eq!(
        defaults[3].next(monday - chrono::Duration::days(3)),
        Some(monday)
    );
    assert_eq!(
        defaults[0].next("2026-11-08T12:34:56Z".parse().expect("a time")),
        Some("2026-11-08T13:00:00Z".parse().expect("a time"))
    );

    let set = configured(
        &Task::builtin(),
        "scheduler:\n  bucket_gc:\n    schedule: '*/15 * * * *'\n    timeout_seconds: 600\n  \
         bucket_verify:\n    enabled: false\n  cas_node_stats:\n    enabled: true\n",
    );
    assert_eq!(set.len(), 4, "the removed task is skipped");
    assert_eq!(
        (
            set[0].schedule.as_str(),
            set[0].timeout.as_secs(),
            set[0].enabled
        ),
        ("*/15 * * * *", 600, true)
    );
    assert_eq!(
        (
            set[3].schedule.as_str(),
            set[3].timeout.as_secs(),
            set[3].enabled
        ),
        ("0 5 * * 1", 14400, false)
    );

    let unknown = ace_sdk::Overlay::from_yaml("scheduler:\n  bucket_gc:\n    every: 60\n")
        .expect_err("refused");
    assert!(
        unknown.to_string().contains("unknown field `every`"),
        "{unknown}"
    );
    assert!(
        unknown.to_string().contains("scheduler.bucket_gc"),
        "{unknown}"
    );

    for (yaml, why) in [
        (
            "scheduler:\n  bucket_gc:\n    schedule: 'hourly'\n",
            "scheduler.bucket_gc.schedule \"hourly\"",
        ),
        (
            "scheduler:\n  bucket_gc:\n    timeout_seconds: 0\n",
            "scheduler.bucket_gc.timeout_seconds: a run needs at least a second",
        ),
    ] {
        let overlay = ace_sdk::Overlay::from_yaml(yaml).expect("parses");
        let error = configure(&Task::builtin(), &overlay.scheduler)
            .err()
            .expect("refused");
        assert!(error.starts_with(why), "{error}");
    }
}
