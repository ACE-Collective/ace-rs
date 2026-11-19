//! PLAN.md 6.7's Done check: each scheduled task runs once through the scheduler, as the component it
//! acts as, and does what ace3's does: `bucket_gc` deletes the unheld objects and expired holds and keeps
//! a held one, `yara_qa_prune` removes the expired QA matches with their holds and an audit row and keeps
//! a live one, `bucket_orphans` deletes bytes no index row names, and `bucket_verify` records an intact
//! object and fails on a corrupt one, which it keeps, `email_archive_partitions` drops the email archive's
//! old weeks and makes those ahead, and `nrd_refresh` rebuilds the newly registered
//! domains list as ace3's refresh did. SVS's tasks each run once too: the catalog's refresh, the run
//! timers, and (7.10 batch 8) the coverage refresh and the daily coverage snapshot. Then the scheduler's own rules: one run across
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
        )
        .await;
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
        sqlx::query("INSERT INTO store.objects (pool, sha256, size) VALUES ('alert_files', $1, 1)")
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

/// ace3's `daily/file-collection-prune` (PLAN.md 7.9): a collection that completed past its retention lets
/// go of its file, which the alert that asked for it keeps; a newer one's stays, and the run has its audit
/// row as `scheduler:file_collection_prune`.
#[tokio::test]
async fn file_collection_prune_lets_go_of_old_collections_files() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let mut ids = Vec::new();
    for (sha256, days) in [("a".repeat(64), 8), ("b".repeat(64), 1)] {
        sqlx::query("INSERT INTO store.objects (pool, sha256, size) VALUES ('alert_files', $1, 1)")
            .bind(&sha256)
            .execute(db.pool())
            .await
            .expect("an object");
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO queue.actions
                 (kind, handler, observable_type, observable_value, status, result, updated_at,
                  file_sha256, file_size, file_name)
             VALUES ('file_collection', 'edr', 'file_location', 'h@c:\\x', 'COMPLETED', 'SUCCESS',
                     now() - make_interval(days => $2), $1, 1, 'x')
             RETURNING id",
        )
        .bind(&sha256)
        .bind(days)
        .fetch_one(db.pool())
        .await
        .expect("a collection");
        for (kind, holder) in [
            ("file_collection", id.to_string()),
            ("root", root.id.to_string()),
        ] {
            sqlx::query(
                "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id) VALUES ('alert_files', $1, $2, $3)",
            )
            .bind(&sha256)
            .bind(kind)
            .bind(holder)
            .execute(db.pool())
            .await
            .expect("a hold");
        }
        ids.push((id, sha256));
    }
    let task = builtin("file_collection_prune");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "file_collection_prune").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(run.summary, Some(json!({"released": 1, "batches": 1})));
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds ORDER BY holder_kind, holder_id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    let mut expected = vec![
        ("file_collection".to_owned(), ids[1].0.to_string()),
        ("root".to_owned(), root.id.to_string()),
        ("root".to_owned(), root.id.to_string()),
    ];
    expected.sort();
    assert_eq!(holds, expected);
    let audit: (serde_json::Value, String, String, serde_json::Value) =
        sqlx::query_as("SELECT actor::jsonb, action, target_kind, before FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("one audit row");
    assert_eq!(
        (audit.0, audit.1.as_str(), audit.2.as_str()),
        (
            json!({"kind": "internal", "id": "scheduler:file_collection_prune"}),
            "prune_file_collections",
            "file_collections"
        )
    );
    assert_eq!(audit.3["retention_days"], 7);
    assert_eq!(audit.3["collections"][0]["id"], ids[0].0);
}

/// ace3's `daily/svs-validations-prune` (PLAN.md 7.10 batch 3): a validation that finished past
/// `svs.yara.retention_days` goes with its rows; a newer one and one still queued stay, and the run has its
/// audit row as `scheduler:svs_validations_prune`.
#[tokio::test]
async fn svs_validations_prune_removes_old_validations() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let mut uuids = Vec::new();
    for (head, state, days) in [
        ("a", "completed", 91),
        ("b", "failed", 1),
        ("c", "queued", 200),
    ] {
        let uuid = uuid::Uuid::new_v4();
        let finished = state != "queued";
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO svs.validations
                 (uuid, repository, base_sha, head_sha, branch, requested_by, state, active_key,
                  created_at, finished_at)
             VALUES ($1, 'rules', repeat('0', 40), repeat($2, 40), 'main',
                     '{\"kind\": \"internal\", \"id\": \"test\"}', $3::svs.validation_state,
                     CASE WHEN $4 THEN NULL ELSE repeat($2, 64) END,
                     now() - make_interval(days => $5), CASE WHEN $4 THEN now() - make_interval(days => $5) END)
             RETURNING id",
        )
        .bind(uuid)
        .bind(head)
        .bind(state)
        .bind(finished)
        .bind(days)
        .fetch_one(db.pool())
        .await
        .expect("a validation");
        sqlx::query(
            "INSERT INTO svs.validation_results
                 (validation_id, sha256, rule_uuid, rule_name, base, head, raw_base, raw_head, category)
             VALUES ($1, repeat('d', 64), 'r', 'rule', 'match', 'miss', true, false, 'regression')",
        )
        .bind(id)
        .execute(db.pool())
        .await
        .expect("a result");
        uuids.push(uuid);
    }
    let task = builtin("svs_validations_prune");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "svs_validations_prune").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(run.summary, Some(json!({"removed": 1, "batches": 1})));
    let left: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT uuid FROM svs.validations ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads");
    assert_eq!(left, uuids[1..]);
    let results: i64 = sqlx::query_scalar("SELECT count(*) FROM svs.validation_results")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(results, 2);
    let audit: (serde_json::Value, String, String, serde_json::Value) =
        sqlx::query_as("SELECT actor::jsonb, action, target_kind, before FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("one audit row");
    assert_eq!(
        (audit.0, audit.1.as_str(), audit.2.as_str()),
        (
            json!({"kind": "internal", "id": "scheduler:svs_validations_prune"}),
            "prune_svs_validations",
            "svs_validations"
        )
    );
    assert_eq!(audit.3["retention_days"], 90);
    assert_eq!(audit.3["validations"], json!([uuids[0]]));
}

/// A catalog repository for the refresh's tests: a bare origin with a working clone, and a file of one
/// test in it.
fn art_repository(root: &std::path::Path) -> ace_core::testing::rule_repo::RuleRepo {
    let repo = ace_core::testing::rule_repo::RuleRepo::new(root);
    repo.commit(
        &[(
            "atomics/T1003/T1003.yaml",
            "attack_technique: T1003\ndisplay_name: OS Credential Dumping\natomic_tests:\n\
             - name: Dump\n  auto_generated_guid: aaaaaaaa-1111-4111-8111-111111111111\n  \
             supported_platforms: [windows]\n  executor: {name: powershell, command: whoami}\n",
        )],
        "main",
    );
    repo
}

fn art_catalog(
    mirrors: &std::path::Path,
    repositories: &[(&str, String)],
) -> ace_core::svs::catalog::CatalogConfig {
    let section = ace_sdk::SvsCatalogSection {
        repositories: repositories
            .iter()
            .map(|(name, url)| {
                (
                    (*name).to_owned(),
                    ace_sdk::SvsCatalogRepository {
                        url: url.clone(),
                        branch: "main".to_owned(),
                        ssh_key: None,
                    },
                )
            })
            .collect(),
        mirror_dir: Some(mirrors.to_path_buf()),
        ..ace_sdk::SvsCatalogSection::default()
    };
    ace_core::svs::catalog::CatalogConfig::from_section(&section).expect("valid settings")
}

async fn catalog_guids(db: &Db) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT repository, guid::text FROM svs.catalog_tests WHERE removed_at IS NULL ORDER BY 1, 2",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// test_catalog.py's `test_the_service_refreshes_the_catalog` (PLAN.md 7.10 batch 4): ace3's
/// `service_svs` refreshes the catalog every `svs.catalog.refresh_interval_seconds`; here the scheduler's
/// `svs_catalog_refresh` does, every five minutes, and its store has its audit row as the task's
/// component.
#[tokio::test]
async fn svs_catalog_refresh_reads_the_catalog() {
    let mut fixture = Fixture::new().await;
    let tmp = tempfile::tempdir().expect("a directory");
    let repo = art_repository(&tmp.path().join("art"));
    fixture.service = fixture.service.clone().with_catalog(art_catalog(
        &tmp.path().join("mirrors"),
        &[("art", repo.origin.to_string_lossy().into_owned())],
    ));
    let db = fixture.db();
    let task = builtin("svs_catalog_refresh");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "svs_catalog_refresh").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(
        run.summary,
        Some(json!({
            "repositories": 1, "refreshed": 1, "retired": 0, "failed": 0,
            "added": 1, "changed": 0, "removed": 0,
        }))
    );
    assert_eq!(
        catalog_guids(db).await,
        [(
            "art".to_owned(),
            "aaaaaaaa-1111-4111-8111-111111111111".to_owned()
        )]
    );
    let audit: (serde_json::Value, String, String, String) =
        sqlx::query_as("SELECT actor::jsonb, action, target_kind, target_id FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("one audit row");
    assert_eq!(
        (
            audit.0,
            audit.1.as_str(),
            audit.2.as_str(),
            audit.3.as_str()
        ),
        (
            json!({"kind": "internal", "id": "scheduler:svs_catalog_refresh"}),
            "store_svs_catalog",
            "svs_catalog_repository",
            "art"
        )
    );
}

/// A run registered an hour ago whose launcher never started it, as the lifecycle leaves one, and its
/// state now.
async fn stale_run(db: &Db) -> uuid::Uuid {
    sqlx::query_scalar(
        "INSERT INTO svs.runs
             (uuid, test_guid, platform, test_content_hash, catalog_commit, state, marker, launcher,
              created_at, observation_seconds, attribution_seconds)
         VALUES (gen_random_uuid(), gen_random_uuid(), 'windows', repeat('0', 64), repeat('a', 40),
                 'created', $1, 'art', now() - interval '1 hour', 3600, 90000)
         RETURNING uuid",
    )
    .bind(ace_core::svs::markers::new_marker())
    .fetch_one(db.pool())
    .await
    .expect("adds a run")
}

async fn run_state(db: &Db, run: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT state::text FROM svs.runs WHERE uuid = $1")
        .bind(run)
        .fetch_one(db.pool())
        .await
        .expect("the run")
}

/// test_runs.py's `test_the_service_moves_runs` (PLAN.md 7.10 batch 5): ace3's `service_svs` moves runs on
/// by time every 30 seconds, as `svs_run_timers` does every minute, each move with its audit row as the
/// task's component.
#[tokio::test]
async fn svs_run_timers_move_runs() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let run = stale_run(db).await;
    let task = builtin("svs_run_timers");
    make_due(db, &task).await;

    let ran = run_once(&fixture, vec![task], "svs_run_timers").await;

    assert_eq!(ran.outcome.as_deref(), Some("succeeded"), "{ran:?}");
    assert_eq!(
        ran.summary,
        Some(json!({
            "timed_out": 1, "ended": 0, "closed": 0, "expired_windows": 0, "alerts_closed": 0,
            "late_alerts_closed": 0, "maintenance_alerts_closed": 0, "results_computed": 0,
            "pruned_refusals": 0, "failed": 0,
        }))
    );
    assert_eq!(run_state(db, run).await, "closed");
    let audit: (serde_json::Value, String, String, String) =
        sqlx::query_as("SELECT actor::jsonb, action, target_kind, target_id FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("one audit row");
    assert_eq!(
        audit,
        (
            json!({"kind": "internal", "id": "scheduler:svs_run_timers"}),
            "run_svs_timers".to_owned(),
            "svs_run".to_owned(),
            run.to_string()
        )
    );
}

/// test_runs.py's `test_the_run_timer_runs_until_stopped_and_survives_a_failure`: a pass in which a run
/// can't be moved fails, saying why, with the other run still moved; the task stays scheduled, and its
/// next pass moves the run once it can be.
#[tokio::test]
async fn svs_run_timers_survive_a_failure() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let stuck = stale_run(db).await;
    let other = stale_run(db).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION svs.broken_run() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'database went away'; END $$;
         CREATE TRIGGER broken BEFORE UPDATE ON svs.runs FOR EACH ROW
             WHEN (OLD.uuid = '{stuck}') EXECUTE FUNCTION svs.broken_run();"
    )))
    .execute(db.pool())
    .await
    .expect("breaks the run");
    let task = builtin("svs_run_timers");
    make_due(db, &task).await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(
        fixture
            .scheduler(vec![task.clone()], "test/1")
            .run(stop.clone()),
    );

    let runs = ended_runs(db, "svs_run_timers", 1).await;
    assert_eq!(runs[0].outcome.as_deref(), Some("failed"), "{runs:?}");
    let error = runs[0].error.clone().expect("an error");
    assert!(
        error.starts_with("1 moves failed, the first: ") && error.contains("database went away"),
        "{error}"
    );
    assert_eq!(runs[0].summary.as_ref().expect("a summary")["timed_out"], 1);
    assert_eq!(
        (run_state(db, stuck).await, run_state(db, other).await),
        ("created".to_owned(), "closed".to_owned())
    );

    // the run can move again; the task's next pass moves it
    sqlx::raw_sql("DROP TRIGGER broken ON svs.runs")
        .execute(db.pool())
        .await
        .expect("mends the run");
    make_due(db, &task).await;
    let runs = ended_runs(db, "svs_run_timers", 2).await;
    stop.cancel();
    running.await.expect("the scheduler stops");
    assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"), "{runs:?}");
    assert_eq!(run_state(db, stuck).await, "closed");
}

/// A service pinned to ace3's test ATT&CK release, v99.0, whose coverage is five rows.
fn pinned(fixture: &mut Fixture) {
    fixture.service = fixture
        .service
        .clone()
        .with_attack_catalog(Arc::new(ace_core::testing::attack_catalog()));
}

async fn coverage_rows(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM svs.coverage")
        .fetch_one(db.pool())
        .await
        .expect("counts")
}

/// test_coverage.py's `test_the_service_refreshes_coverage` (PLAN.md 7.10 batch 8): ace3's `service_svs`
/// recomputes coverage every `svs.coverage.refresh_interval_seconds`; here the scheduler's
/// `svs_coverage_refresh` does, every two minutes, with its audit row as the task's component.
#[tokio::test]
async fn svs_coverage_refresh_refreshes_coverage() {
    let mut fixture = Fixture::new().await;
    pinned(&mut fixture);
    let db = fixture.db();
    let task = builtin("svs_coverage_refresh");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "svs_coverage_refresh").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    assert_eq!(
        run.summary,
        Some(json!({
            "attack_release": "v99.0", "rows": 5, "changed": 5, "inserted": 5, "retired": 0,
            "skipped_tests": 0, "worklist_rows": 0, "worklist_changed": 0,
        }))
    );
    assert_eq!(coverage_rows(db).await, 5);
    let audit: (serde_json::Value, String, String) =
        sqlx::query_as("SELECT actor::jsonb, action, target_kind FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("one audit row");
    assert_eq!(
        audit,
        (
            json!({"kind": "internal", "id": "scheduler:svs_coverage_refresh"}),
            "refresh_svs_coverage".to_owned(),
            "svs_coverage".to_owned()
        )
    );
}

/// test_coverage.py's `test_the_refresher_survives_a_failure`: a refresh that fails records why and fails
/// its run; the task stays scheduled, and its next run refreshes once it can. ace3 patches the tags'
/// reader to raise; here the database refuses coverage's rows.
#[tokio::test]
async fn svs_coverage_refresh_survives_a_failure() {
    let mut fixture = Fixture::new().await;
    pinned(&mut fixture);
    let db = fixture.db();
    sqlx::raw_sql(
        "CREATE FUNCTION svs.boom() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'boom'; END $$;
         CREATE TRIGGER boom BEFORE INSERT ON svs.coverage
             FOR EACH ROW EXECUTE FUNCTION svs.boom();",
    )
    .execute(db.pool())
    .await
    .expect("breaks coverage");
    let task = builtin("svs_coverage_refresh");
    make_due(db, &task).await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(
        fixture
            .scheduler(vec![task.clone()], "test/1")
            .run(stop.clone()),
    );

    let runs = ended_runs(db, "svs_coverage_refresh", 1).await;
    assert_eq!(runs[0].outcome.as_deref(), Some("failed"), "{runs:?}");
    assert!(
        runs[0].error.as_deref().is_some_and(|e| e.contains("boom")),
        "{runs:?}"
    );
    assert_eq!(coverage_rows(db).await, 0);
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT error FROM svs.coverage_state WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("the refresh's state");
    assert!(recorded.is_some_and(|e| e.contains("boom")));

    // the database is back; the task's next run refreshes
    sqlx::raw_sql("DROP TRIGGER boom ON svs.coverage")
        .execute(db.pool())
        .await
        .expect("mends coverage");
    make_due(db, &task).await;
    let runs = ended_runs(db, "svs_coverage_refresh", 2).await;
    stop.cancel();
    running.await.expect("the scheduler stops");
    assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"), "{runs:?}");
    assert_eq!(coverage_rows(db).await, 5);
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT error FROM svs.coverage_state WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("the refresh's state");
    assert_eq!(recorded, None);
}

/// ace3's `etc/cron/daily/svs-coverage-snapshot` (PLAN.md 6.7): `svs_coverage_snapshot` refreshes coverage
/// and files the day's copy, UTC, as its own component, which holds both grants.
#[tokio::test]
async fn svs_coverage_snapshot_files_the_day() {
    let mut fixture = Fixture::new().await;
    pinned(&mut fixture);
    let db = fixture.db();
    let task = builtin("svs_coverage_snapshot");
    make_due(db, &task).await;
    let before = Utc::now().date_naive();

    let run = run_once(&fixture, vec![task], "svs_coverage_snapshot").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    let summary = run.summary.expect("a summary");
    assert_eq!(
        (
            &summary["attack_release"],
            &summary["rows"],
            &summary["deleted"]
        ),
        (&json!("v99.0"), &json!(5), &json!(0))
    );
    let days: Vec<(chrono::NaiveDate, i64)> = sqlx::query_as(
        "SELECT snapshot_date, count(*) FROM svs.coverage_snapshots GROUP BY snapshot_date",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads the snapshots");
    assert_eq!(days.len(), 1, "{days:?}");
    assert!(days[0].0 == before || days[0].0 == Utc::now().date_naive());
    assert_eq!(days[0].1, 5);
    assert_eq!(summary["snapshot_date"], json!(days[0].0.to_string()));
    let actions: Vec<(String, String)> =
        sqlx::query_as("SELECT actor ->> 'id', action FROM service.audit ORDER BY id")
            .fetch_all(db.pool())
            .await
            .expect("the audit rows");
    let as_task = |action: &str| {
        (
            "scheduler:svs_coverage_snapshot".to_owned(),
            action.to_owned(),
        )
    };
    assert_eq!(
        actions,
        [
            as_task("refresh_svs_coverage"),
            as_task("write_svs_coverage_snapshot")
        ]
    );
    // each coverage task holds what it does, and the refresher files no snapshot
    for (task, refresh, snapshot) in [
        ("svs_coverage_refresh", true, false),
        ("svs_coverage_snapshot", true, true),
        ("svs_run_timers", false, false),
    ] {
        let actor = builtin(task).actor;
        let holds = async |name| fixture.service.allowed(&actor, name).await.expect("checks");
        assert_eq!(
            (
                holds(&ace_service::SVS_COVERAGE_REFRESH).await,
                holds(&ace_service::SVS_COVERAGE_SNAPSHOT).await
            ),
            (refresh, snapshot),
            "{task}"
        );
    }
}

/// test_catalog.py's `test_the_refresher_runs_until_stopped_and_survives_a_failure`: a run in which a
/// repository can't be read fails, saying which, with the other repository still read; the task stays
/// scheduled, and its next run reads the repository once it can be.
#[tokio::test]
async fn svs_catalog_refresh_survives_a_failure() {
    let mut fixture = Fixture::new().await;
    let tmp = tempfile::tempdir().expect("a directory");
    let repo = art_repository(&tmp.path().join("art"));
    let late = tmp.path().join("late");
    fixture.service = fixture.service.clone().with_catalog(art_catalog(
        &tmp.path().join("mirrors"),
        &[
            ("art", repo.origin.to_string_lossy().into_owned()),
            ("late", late.join("origin").to_string_lossy().into_owned()),
        ],
    ));
    let db = fixture.db();
    let task = builtin("svs_catalog_refresh");
    make_due(db, &task).await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(
        fixture
            .scheduler(vec![task.clone()], "test/1")
            .run(stop.clone()),
    );

    let runs = ended_runs(db, "svs_catalog_refresh", 1).await;
    assert_eq!(runs[0].outcome.as_deref(), Some("failed"), "{runs:?}");
    let error = runs[0].error.clone().expect("an error");
    assert!(
        error.starts_with("late: unable to fetch main of repository late"),
        "{error}"
    );
    assert_eq!(runs[0].summary.as_ref().expect("a summary")["refreshed"], 1);
    assert_eq!(catalog_guids(db).await.len(), 1, "the other was read");

    // the repository appears; the task's next run reads it
    ace_core::testing::rule_repo::RuleRepo::new(&late).commit(
        &[(
            "atomics/T1105/T1105.yaml",
            "attack_technique: T1105\natomic_tests:\n- name: Copy\n  \
             auto_generated_guid: cccccccc-3333-4333-8333-333333333333\n",
        )],
        "main",
    );
    make_due(db, &task).await;
    let runs = ended_runs(db, "svs_catalog_refresh", 2).await;
    stop.cancel();
    running.await.expect("the scheduler stops");
    assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"), "{runs:?}");
    assert_eq!(
        runs[0].summary,
        Some(json!({
            "repositories": 2, "refreshed": 1, "retired": 0, "failed": 0,
            "added": 1, "changed": 0, "removed": 0,
        }))
    );
    assert_eq!(
        catalog_guids(db).await,
        [
            (
                "art".to_owned(),
                "aaaaaaaa-1111-4111-8111-111111111111".to_owned()
            ),
            (
                "late".to_owned(),
                "cccccccc-3333-4333-8333-333333333333".to_owned()
            ),
        ]
    );
}

/// The partitions of an email archive table, by name, the catchall's left out.
async fn archive_weeks(db: &Db, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = to_regclass($1) AND c.relname NOT LIKE '%catchall'
         ORDER BY c.relname",
    )
    .bind(format!("email_archive.{table}"))
    .fetch_all(db.pool())
    .await
    .expect("reads the partitions")
}

/// The analysis cache's day partitions (PLAN.md decision 26), as `psql`'s catalog lists them.
async fn cache_days(db: &ace_core::db::Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = to_regclass('cache.results') AND c.relname NOT LIKE '%catchall'
         ORDER BY c.relname",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads the partitions")
}

/// ace3's `daily/partitions`, its analysis cache half (PLAN.md decision 26): a day past retention goes,
/// with its rows, the days from today to three ahead are made, and a day the catchall holds rows of
/// isn't made, and the run fails naming it.
#[tokio::test]
async fn analysis_cache_partitions_drops_the_old_days_and_makes_the_ones_ahead() {
    use ace_core::cache::{DAYS_AHEAD, partition_name};
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let today = Utc::now().date_naive();
    // a day forty days back, past the default 35, made by hand, holding a row
    let old = today - chrono::Duration::days(40);
    let old_name = partition_name(old);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE cache.{old_name} PARTITION OF cache.results
         FOR VALUES FROM ('{old} 00:00:00+00') TO ('{} 00:00:00+00')",
        old + chrono::Duration::days(1)
    )))
    .execute(db.pool())
    .await
    .expect("makes an old day");
    sqlx::query(
        "INSERT INTO cache.results (key, module, observable_type, observable_value, envelope,
                                    created_at, expires_at)
         VALUES (sha256('old'::bytea), 'qrcode', 'file', 'x', '{}', $1, $1)",
    )
    .bind((old.and_hms_opt(12, 0, 0).expect("noon")).and_utc())
    .execute(db.pool())
    .await
    .expect("an old row");
    let task = builtin("analysis_cache_partitions");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "analysis_cache_partitions").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    let expected: Vec<String> = (0..=DAYS_AHEAD)
        .map(|ahead| partition_name(today + chrono::Duration::days(ahead)))
        .collect();
    assert_eq!(cache_days(db).await, expected);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM cache.results")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(rows, 0, "the old day went with its row");
    let summary = run.summary.expect("a summary");
    assert_eq!(summary["dropped"], json!([old_name]));

    // a row in the catchall of a day not yet made keeps that day from being made
    let ahead = today + chrono::Duration::days(DAYS_AHEAD + 1);
    sqlx::query(
        "INSERT INTO cache.results (key, module, observable_type, observable_value, envelope,
                                    created_at, expires_at)
         VALUES (sha256('ahead'::bytea), 'qrcode', 'file', 'y', '{}', $1, $1)",
    )
    .bind((ahead.and_hms_opt(1, 0, 0).expect("one")).and_utc())
    .execute(db.pool())
    .await
    .expect("a row past the days made");
    let done = fixture
        .service
        .maintain_analysis_cache(
            &builtin("analysis_cache_partitions").actor,
            &ace_core::cache::CacheSettings::default(),
            Utc::now() + chrono::Duration::days(1),
        )
        .await
        .expect("runs");
    assert_eq!(done.problems.len(), 1, "{done:?}");
    assert!(
        done.problems[0].contains(&partition_name(ahead)),
        "{done:?}"
    );
    assert!(!cache_days(db).await.contains(&partition_name(ahead)));
    fixture.clean_up().await;
}

/// ace3's `daily/partitions`, its email archive half (PLAN.md 7.5 batch 9): the weeks past retention go,
/// with their rows, and the weeks from the oldest kept to four ahead are made in each table; a week the
/// catchall holds rows of isn't made, and the run fails naming it, as ace3's exits 1.
#[tokio::test]
async fn email_archive_partitions_drops_the_old_weeks_and_makes_the_ones_ahead() {
    use ace_core::email_archive::partitions::{WEEKS_AHEAD, partition_name};
    use ace_core::email_archive::week_of;
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let now = Utc::now().naive_utc();
    // a week ten weeks back, made by hand, holding a row
    let (old, old_end) = week_of(now - chrono::Duration::weeks(10));
    let old_name = partition_name("archive", old);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE email_archive.{old_name} PARTITION OF email_archive.archive
         FOR VALUES FROM ('{old}') TO ('{old_end}')"
    )))
    .execute(db.pool())
    .await
    .expect("makes an old week");
    sqlx::query(
        "INSERT INTO email_archive.archive (hash, object_sha256, insert_date, root_id, observable_id)
         VALUES (sha256('old'::bytea), 'x', $1, gen_random_uuid(), 1)",
    )
    .bind(old + chrono::Duration::days(1))
    .execute(db.pool())
    .await
    .expect("an old row");
    let task = builtin("email_archive_partitions");
    make_due(db, &task).await;

    let run = run_once(&fixture, vec![task], "email_archive_partitions").await;

    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    let (this_week, _) = week_of(now);
    let (oldest_kept, _) = week_of(now - chrono::Duration::days(30));
    for table in ["archive", "archive_index", "email_history"] {
        let mut expected = Vec::new();
        let mut week = oldest_kept;
        while week <= this_week + chrono::Duration::weeks(WEEKS_AHEAD) {
            // the oldest week is made only while a row of it can still be kept
            if week + chrono::Duration::days(7) > now - chrono::Duration::days(30) {
                expected.push(partition_name(table, week));
            }
            week += chrono::Duration::weeks(1);
        }
        assert_eq!(archive_weeks(db, table).await, expected, "{table}");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM email_archive.archive")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(rows, 0, "the old week went with its row");
    let summary = run.summary.expect("a summary");
    assert_eq!(summary[0]["table"], "email_archive.archive");
    assert_eq!(summary[0]["dropped"], json!([old_name]));

    // a row in the catchall for a week not yet made keeps that week from being made
    let (ahead, _) = week_of(now + chrono::Duration::weeks(WEEKS_AHEAD + 1));
    sqlx::query(
        "INSERT INTO email_archive.email_history
             (insert_date, message_id, message_id_hash, recipient, recipient_hash)
         VALUES ($1, '<m>', sha256('m'::bytea), 'r', sha256('r'::bytea))",
    )
    .bind(ahead + chrono::Duration::days(1))
    .execute(db.pool())
    .await
    .expect("a row past the weeks made");
    let later = (Utc::now() + chrono::Duration::weeks(1))
        .naive_utc()
        .and_utc();
    let done = fixture
        .service
        .maintain_email_archive(
            &builtin("email_archive_partitions").actor,
            &ace_core::email_archive::ArchiveConfig::default(),
            later,
        )
        .await
        .expect("runs");
    let history = done
        .iter()
        .find(|t| t.table == "email_archive.email_history")
        .expect("a table");
    assert_eq!(history.problems.len(), 1, "{history:?}");
    assert!(
        history.problems[0].contains(&partition_name("email_history", ahead)),
        "{history:?}"
    );
    assert!(
        !archive_weeks(db, "email_history")
            .await
            .contains(&partition_name("email_history", ahead))
    );
    assert!(
        done.iter()
            .filter(|t| t.table != "email_archive.email_history")
            .all(|t| t.ok())
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
        ace_service::MONITORING_REPORT,
        ace_service::BUCKET_GC,
        ace_service::BUCKET_VERIFY,
        ace_service::SIGNATURE_QA_PURGE,
        ace_service::NRD_REFRESH,
        ace_service::EMAIL_ARCHIVE_MAINTAIN,
        ace_service::ANALYSIS_CACHE_MAINTAIN,
        ace_service::FILE_COLLECTION_PRUNE,
        ace_service::ALERT_READ,
    ];
    for (task, holds) in [
        ("bucket_gc", ace_service::BUCKET_GC),
        ("bucket_orphans", ace_service::BUCKET_GC),
        ("bucket_verify", ace_service::BUCKET_VERIFY),
        ("yara_qa_prune", ace_service::SIGNATURE_QA_PURGE),
        ("nrd_refresh", ace_service::NRD_REFRESH),
        (
            "email_archive_partitions",
            ace_service::EMAIL_ARCHIVE_MAINTAIN,
        ),
        (
            "analysis_cache_partitions",
            ace_service::ANALYSIS_CACHE_MAINTAIN,
        ),
        ("file_collection_prune", ace_service::FILE_COLLECTION_PRUNE),
    ] {
        let actor = builtin(task).actor;
        for name in &names {
            let allowed = fixture.service.allowed(&actor, name).await.expect("checks");
            assert_eq!(allowed, *name == holds, "{task} and {name}");
        }
    }
    // each monitoring check holds monitoring:report and nothing else (PLAN.md 7.12)
    for task in Task::monitors() {
        let actor = builtin(&task.name).actor;
        assert_eq!(
            actor.to_string(),
            format!("internal:scheduler:{}", task.name)
        );
        for name in names.iter().chain([&ace_service::MONITORING_READ]) {
            let allowed = fixture.service.allowed(&actor, name).await.expect("checks");
            assert_eq!(
                allowed,
                *name == ace_service::MONITORING_REPORT,
                "{} and {name}",
                task.name
            );
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
            ("email_archive_partitions", "0 5 * * *", 3600, true),
            ("analysis_cache_partitions", "0 5 * * *", 3600, true),
            ("file_collection_prune", "0 5 * * *", 3600, true),
            ("svs_validations_prune", "0 5 * * *", 3600, true),
            ("svs_catalog_refresh", "*/5 * * * *", 1500, true),
            ("svs_run_timers", "* * * * *", 600, true),
            // ace3's `svs.coverage.refresh_interval_seconds`, 120, and its daily cron
            ("svs_coverage_refresh", "*/2 * * * *", 600, true),
            ("svs_coverage_snapshot", "0 5 * * *", 3600, true),
            ("nrd_refresh", "*/30 * * * *", 1500, true),
            // ace3's monitors (PLAN.md 7.12): every 5 or 30 seconds there, every minute here; its
            // pools' every 300 seconds; and its hourly cron for the node's read cache
            ("monitor_workload", "* * * * *", 60, true),
            ("monitor_delayed_analysis", "* * * * *", 60, true),
            ("monitor_leases", "* * * * *", 60, true),
            ("monitor_queue", "* * * * *", 60, true),
            ("monitor_bucket_pools", "*/5 * * * *", 240, true),
            ("monitor_scheduler", "* * * * *", 60, true),
            ("bucket_node_stats", "0 * * * *", 600, true),
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
            "internal:scheduler:email_archive_partitions",
            "internal:scheduler:analysis_cache_partitions",
            "internal:scheduler:file_collection_prune",
            "internal:scheduler:svs_validations_prune",
            "internal:scheduler:svs_catalog_refresh",
            "internal:scheduler:svs_run_timers",
            "internal:scheduler:svs_coverage_refresh",
            "internal:scheduler:svs_coverage_snapshot",
            "internal:scheduler:nrd_refresh",
            "internal:scheduler:monitor_workload",
            "internal:scheduler:monitor_delayed_analysis",
            "internal:scheduler:monitor_leases",
            "internal:scheduler:monitor_queue",
            "internal:scheduler:monitor_bucket_pools",
            "internal:scheduler:monitor_scheduler",
            "internal:scheduler:bucket_node_stats",
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
    assert_eq!(set.len(), 20, "the removed task is skipped");
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

    // a monitoring check is a task like any other: on by default, and the overlay turns one off and leaves
    // the rest (ace3's test_enabled_defaults_to_true, test_mixed_enabled_and_disabled and
    // test_overlay_can_disable_a_default_monitor)
    let monitor_tasks = Task::monitors();
    let monitors: Vec<&str> = monitor_tasks.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        monitors,
        [
            "monitor_workload",
            "monitor_delayed_analysis",
            "monitor_leases",
            "monitor_queue",
            "monitor_bucket_pools",
            "monitor_scheduler",
            "bucket_node_stats"
        ]
    );
    for name in &monitors {
        let task = defaults
            .iter()
            .find(|t| t.task.name == *name)
            .expect("a core task");
        assert!(task.enabled, "{name}");
    }
    let quieter = configured(
        &Task::builtin(),
        "scheduler:\n  monitor_leases:\n    enabled: false\n  monitor_queue:\n    schedule: '*/5 * * * *'\n",
    );
    let of = |name: &str| {
        quieter
            .iter()
            .find(|t| t.task.name == name)
            .expect("a core task")
    };
    assert!(!of("monitor_leases").enabled);
    assert_eq!(
        (
            of("monitor_queue").schedule.as_str(),
            of("monitor_queue").enabled
        ),
        ("*/5 * * * *", true)
    );
    assert!(of("monitor_workload").enabled);

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

// ---- nrd_refresh (PLAN.md 7.4) ----

/// What the fake feed server serves at a path: the file, its ETag and Last-Modified, and how many
/// of the next requests for it answer 503 or break off their body.
#[derive(Clone, Default)]
struct Feed {
    body: Vec<u8>,
    etag: Option<String>,
    last_modified: Option<String>,
    unavailable: usize,
    broken: usize,
}

#[derive(Default)]
struct Feeds {
    files: std::collections::HashMap<String, Feed>,
    requests: Vec<(String, String)>,
}

/// A feed server on 127.0.0.1, over TLS with a self-signed certificate for `localhost` when `tls`.
/// Returns its base URL, its state, and the certificate's PEM.
async fn feed_server(tls: bool) -> (String, Arc<std::sync::Mutex<Feeds>>, Option<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let feeds = Arc::new(std::sync::Mutex::new(Feeds::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let port = listener.local_addr().expect("an address").port();
    let (acceptor, pem) = if tls {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a certificate");
        let pem = certified.cert.pem();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .expect("a server config");
        (
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
            Some(pem),
        )
    } else {
        (None, None)
    };
    async fn serve<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        mut stream: S,
        feeds: Arc<std::sync::Mutex<Feeds>>,
    ) {
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&request).into_owned();
        let mut words = text.split_whitespace();
        let method = words.next().unwrap_or_default().to_owned();
        let path = words.next().unwrap_or_default().to_owned();
        let feed = {
            let mut feeds = feeds.lock().expect("unpoisoned");
            feeds.requests.push((method.clone(), path.clone()));
            feeds.files.get_mut(&path).map(|feed| {
                let served = feed.clone();
                if feed.unavailable > 0 {
                    feed.unavailable -= 1;
                } else if method == "GET" && feed.broken > 0 {
                    feed.broken -= 1;
                }
                served
            })
        };
        let response = match feed {
            None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
            Some(feed) if feed.unavailable > 0 => {
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_vec()
            }
            Some(feed) => {
                let mut head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n",
                    feed.body.len()
                );
                if let Some(etag) = &feed.etag {
                    head.push_str(&format!("etag: {etag}\r\n"));
                }
                if let Some(lm) = &feed.last_modified {
                    head.push_str(&format!("last-modified: {lm}\r\n"));
                }
                head.push_str("\r\n");
                let mut response = head.into_bytes();
                if method == "GET" {
                    if feed.broken > 0 {
                        // half the body, then the connection closes: a body that broke off
                        response.extend_from_slice(&feed.body[..feed.body.len() / 2]);
                    } else {
                        response.extend_from_slice(&feed.body);
                    }
                }
                response
            }
        };
        if stream.write_all(&response).await.is_ok() {
            stream.shutdown().await.ok();
        }
    }
    let served = feeds.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let feeds = served.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(stream).await {
                            serve(tls, feeds).await;
                        }
                    }
                    None => serve(stream, feeds).await,
                }
            });
        }
    });
    let base = if tls {
        format!("https://localhost:{port}")
    } else {
        format!("http://127.0.0.1:{port}")
    };
    (base, feeds, pem)
}

fn nrd_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/nrd/lists")
            .join(name),
    )
    .expect("the fixture reads")
}

fn serve_feed(
    feeds: &std::sync::Mutex<Feeds>,
    path: &str,
    file: &str,
    etag: Option<&str>,
    lm: Option<&str>,
) {
    feeds.lock().expect("unpoisoned").files.insert(
        path.to_owned(),
        Feed {
            body: nrd_fixture(file),
            etag: etag.map(str::to_owned),
            last_modified: lm.map(str::to_owned),
            ..Feed::default()
        },
    );
}

fn nrd_actor() -> Actor {
    builtin("nrd_refresh").actor
}

fn nrd_section(base: &str, lists: &[(&str, &[&str])]) -> ace_sdk::NrdSection {
    ace_sdk::NrdSection {
        url_lists: lists
            .iter()
            .map(|(url, backups)| ace_sdk::NrdList {
                url: format!("{base}{url}"),
                backups: backups.iter().map(|b| format!("{base}{b}")).collect(),
            })
            .collect(),
        ..ace_sdk::NrdSection::default()
    }
}

async fn age_nrd_state(db: &Db, hours: i64) {
    sqlx::query("UPDATE nrd.state SET last_refreshed_at = now() - make_interval(hours => $1::int)")
        .bind(hours as i32)
        .execute(db.pool())
        .await
        .expect("ages the state");
}

/// What a step left: its sources with the server's base as ace3's was, and the list's domains.
async fn nrd_left(db: &Db, base: &str) -> Value {
    let state = ace_core::nrd::state(db).await.expect("reads");
    let domains = ace_core::nrd::domains(db).await.expect("reads");
    let Some(state) = state else {
        return Value::Null;
    };
    let rebase = |url: &str| url.replacen(base, "http://127.0.0.1:8091", 1);
    let sources: Vec<Value> = state
        .sources
        .iter()
        .map(|s| {
            json!({
                "content_length": s.content_length,
                "etag": s.etag,
                "fetched_from": rebase(&s.fetched_from),
                "last_modified": s.last_modified,
                "row_count": s.row_count,
                "url": rebase(&s.url),
            })
        })
        .collect();
    json!({"row_count": state.row_count, "sources": sources, "domains": domains})
}

/// The steps ace3's refresh went through in tools/ace3/dumps/nrd_reference.py, against the same
/// feeds served the same way: each makes the same requests and leaves the same list and sources, a
/// failed one leaving the list as it was. The URLs differ only by the server's port.
#[tokio::test]
async fn nrd_refresh_goes_through_ace3_s_steps_as_ace3_did() {
    let fixture = Fixture::new().await;
    let (base, feeds, _) = feed_server(false).await;
    let reference: Value = serde_json::from_str(
        &String::from_utf8(nrd_fixture("../../../reference/nrd/reference.json")).expect("UTF-8"),
    )
    .expect("JSON");
    let refresher = crate::nrd::Refresher::new(&ace_sdk::NrdSection::default())
        .expect("a client")
        .without_backoff();
    serve_feed(
        &feeds,
        "/first.txt",
        "first.txt",
        Some("\"first-1\""),
        Some("Sat, 07 Nov 2026 10:00:00 GMT"),
    );
    serve_feed(
        &feeds,
        "/second.txt",
        "second.txt",
        None,
        Some("Sat, 07 Nov 2026 11:00:00 GMT"),
    );
    serve_feed(
        &feeds,
        "/backup.txt",
        "backup.txt",
        Some("\"backup-1\""),
        None,
    );
    let mut refreshed_at = Vec::new();
    for step in reference["refresh"].as_array().expect("steps").iter() {
        let name = step["step"].as_str().expect("a name");
        match name {
            "after the interval, unchanged upstream" => age_nrd_state(fixture.db(), 25).await,
            "after the interval, changed upstream" => {
                age_nrd_state(fixture.db(), 25).await;
                serve_feed(
                    &feeds,
                    "/first.txt",
                    "changed.txt",
                    Some("\"first-2\""),
                    Some("Sun, 08 Nov 2026 10:00:00 GMT"),
                );
            }
            _ => {}
        }
        let lists: Vec<(String, Vec<String>)> = step["url_lists"]
            .as_array()
            .expect("lists")
            .iter()
            .map(|l| {
                (
                    l["url"].as_str().expect("a url").to_owned(),
                    l["backups"]
                        .as_array()
                        .expect("backups")
                        .iter()
                        .map(|b| b.as_str().expect("a url").to_owned())
                        .collect(),
                )
            })
            .collect();
        let borrowed: Vec<(&str, Vec<&str>)> = lists
            .iter()
            .map(|(u, b)| (u.as_str(), b.iter().map(String::as_str).collect()))
            .collect();
        let as_slices: Vec<(&str, &[&str])> =
            borrowed.iter().map(|(u, b)| (*u, b.as_slice())).collect();
        let section = nrd_section(&base, &as_slices);
        let outcome = refresher
            .refresh(&fixture.service, &nrd_actor(), &section)
            .await;
        assert_eq!(
            i32::from(outcome.is_err()),
            step["exit_code"].as_i64().expect("a code") as i32,
            "{name}: {outcome:?}"
        );
        let requests: Vec<Value> = std::mem::take(&mut feeds.lock().expect("unpoisoned").requests)
            .into_iter()
            .map(|(m, p)| json!([m, p]))
            .collect();
        assert_eq!(Value::Array(requests), step["requests"], "{name}");
        let left = nrd_left(fixture.db(), &base).await;
        let ace3 = &step["database"];
        assert_eq!(left["domains"], ace3["domains"], "{name}");
        assert_eq!(left["row_count"], ace3["meta"]["row_count"], "{name}");
        assert_eq!(left["sources"], ace3["meta"]["sources"], "{name}");
        refreshed_at.push(
            ace_core::nrd::state(fixture.db())
                .await
                .expect("reads")
                .map(|s| s.last_refreshed_at),
        );
    }
    // a run that changed nothing didn't move the clock; the HEAD check keeps asking until upstream changes
    assert_eq!(refreshed_at[1], refreshed_at[0]);
    assert_eq!(
        refreshed_at[5], refreshed_at[4],
        "a failed rebuild leaves the list as it was"
    );
}

/// As ace3's, a 503 and a body that breaks off are each tried once more, and a list with neither
/// left is fetched from its backup.
#[tokio::test]
async fn nrd_refresh_retries_a_server_error_and_a_broken_body_once() {
    let fixture = Fixture::new().await;
    let (base, feeds, _) = feed_server(false).await;
    let refresher = crate::nrd::Refresher::new(&ace_sdk::NrdSection::default())
        .expect("a client")
        .without_backoff();
    serve_feed(&feeds, "/first.txt", "first.txt", Some("\"a\""), None);
    serve_feed(&feeds, "/backup.txt", "backup.txt", None, None);
    {
        let mut feeds = feeds.lock().expect("unpoisoned");
        feeds
            .files
            .get_mut("/first.txt")
            .expect("served")
            .unavailable = 1;
        feeds.files.get_mut("/first.txt").expect("served").broken = 1;
    }
    let section = nrd_section(&base, &[("/first.txt", &["/backup.txt"])]);
    let done = refresher
        .refresh(&fixture.service, &nrd_actor(), &section)
        .await
        .expect("rebuilt");
    let crate::nrd::Refreshed::Rebuilt { state, .. } = done else {
        panic!("a rebuild: {done:?}");
    };
    assert_eq!(state.sources[0].fetched_from, format!("{base}/first.txt"));
    assert_eq!(
        state.row_count, 11,
        "the broken half was undone, then all of it taken"
    );
    let requests = std::mem::take(&mut feeds.lock().expect("unpoisoned").requests);
    // the 503, then the broken body, then the whole one
    assert_eq!(requests.len(), 3, "{requests:?}");

    // two broken bodies move on to the backup
    feeds
        .lock()
        .expect("unpoisoned")
        .files
        .get_mut("/first.txt")
        .expect("served")
        .broken = 2;
    let section = nrd_section(&base, &[("/first.txt", &["/backup.txt"])]);
    sqlx::query("DELETE FROM nrd.state")
        .execute(fixture.db().pool())
        .await
        .expect("deletes");
    let done = refresher
        .refresh(&fixture.service, &nrd_actor(), &section)
        .await
        .expect("rebuilt");
    let crate::nrd::Refreshed::Rebuilt { state, .. } = done else {
        panic!("a rebuild: {done:?}");
    };
    assert_eq!(state.sources[0].fetched_from, format!("{base}/backup.txt"));
    assert_eq!(
        ace_core::nrd::domains(fixture.db()).await.expect("reads"),
        ["ace4-backup.net"]
    );
}

/// The feeds are fetched with verified TLS: a certificate nobody trusts fails the run and leaves
/// the list as it was, and the same server with its CA in `nrd.ca_certificates` is fetched. A run
/// as a component without `nrd:refresh` reads and writes nothing. The task runs once through the
/// scheduler, as `scheduler:nrd_refresh`.
#[tokio::test]
async fn nrd_refresh_verifies_certificates_and_runs_as_its_component() {
    let fixture = Fixture::new().await;
    let (base, feeds, pem) = feed_server(true).await;
    serve_feed(&feeds, "/first.txt", "first.txt", Some("\"a\""), None);
    let section = nrd_section(&base, &[("/first.txt", &[])]);
    let untrusted = crate::nrd::Refresher::new(&section)
        .expect("a client")
        .without_backoff()
        .refresh(&fixture.service, &nrd_actor(), &section)
        .await;
    assert!(untrusted.is_err(), "{untrusted:?}");
    assert_eq!(
        ace_core::nrd::state(fixture.db()).await.expect("reads"),
        None
    );

    let dir = tempfile::tempdir().expect("a directory");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, pem.expect("a certificate")).expect("writes");
    let section = ace_sdk::NrdSection {
        ca_certificates: Some(ca),
        ..section
    };
    let mut task = builtin("nrd_refresh");
    make_due(fixture.db(), &task).await;
    let overlay = ace_sdk::Overlay {
        nrd: section.clone(),
        ..ace_sdk::Overlay::default()
    };
    let stop = CancellationToken::new();
    let running = tokio::spawn(
        fixture
            .scheduler(vec![task.clone()], "test/1")
            .with_overlay(overlay.clone())
            .run(stop.clone()),
    );
    let runs = ended_runs(fixture.db(), "nrd_refresh", 1).await;
    stop.cancel();
    running.await.expect("the scheduler stops");
    assert_eq!(runs[0].outcome.as_deref(), Some("succeeded"), "{runs:?}");
    assert_eq!(
        runs[0].summary.as_ref().map(|s| s["row_count"].clone()),
        Some(json!(11))
    );
    let before = ace_core::nrd::domains(fixture.db()).await.expect("reads");
    assert_eq!(before.len(), 11);

    task.actor = Actor::Internal {
        id: Component::new("scheduler:nobody").expect("valid"),
    };
    let refused = crate::nrd::Refresher::new(&section)
        .expect("a client")
        .refresh(&fixture.service, &task.actor, &section)
        .await;
    assert_eq!(
        refused.err().as_deref(),
        Some("internal:scheduler:nobody doesn't hold nrd:refresh")
    );
    assert_eq!(
        ace_core::nrd::domains(fixture.db()).await.expect("reads"),
        before
    );
}

/// A root in `mode`, with a pass in progress or not.
async fn root(db: &Db, mode: &str, in_progress: bool) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO analysis.roots (id, analysis_mode, event_time_source, pass, completed_pass)
         VALUES ($1, $2, 'unset', 1, $3)",
    )
    .bind(id)
    .bind(mode)
    .bind(if in_progress { 0 } else { 1 })
    .execute(db.pool())
    .await
    .expect("a root");
    id
}

/// A task of `module` on a new observable of `root`: `queued` since `since` ago, `delayed` until `since`
/// from now, or `running` under `owner` with a lease that ends `since` from now (negative: expired).
async fn task(
    db: &Db,
    root: uuid::Uuid,
    module: &str,
    state: &str,
    since: &str,
    owner: Option<&str>,
) -> i64 {
    let observable: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.observables (root_id, type, value) VALUES ($1, 'fqdn', $2) RETURNING id",
    )
    .bind(root)
    .bind(format!("{}.example", uuid::Uuid::new_v4().simple()))
    .fetch_one(db.pool())
    .await
    .expect("an observable");
    sqlx::query_scalar(
        "INSERT INTO queue.tasks (root_id, observable_id, module, state, run_after, lease_owner, lease_expires_at)
         VALUES ($1, $2, $3, $4::queue.task_state,
                 CASE $4 WHEN 'queued' THEN now() - $5::interval WHEN 'delayed' THEN now() + $5::interval
                         ELSE now() END,
                 $6, CASE WHEN $4 = 'running' THEN now() + $5::interval END)
         RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(module)
    .bind(state)
    .bind(since)
    .bind(owner)
    .fetch_one(db.pool())
    .await
    .expect("a task")
}

/// The records `task` last emitted: each one's path, identifier and value, in the order it emitted them.
async fn records(db: &Db, task: &str) -> Vec<(String, Option<String>, Value)> {
    sqlx::query_as(
        "SELECT path, identifier, value FROM monitoring.records WHERE task = $1 ORDER BY id",
    )
    .bind(task)
    .fetch_all(db.pool())
    .await
    .expect("reads the records")
}

/// Runs one monitoring check through the scheduler, once, and returns its run.
async fn check(fixture: &Fixture, name: &str) -> scheduler::Run {
    sqlx::query("DELETE FROM scheduler.runs WHERE task = $1")
        .bind(name)
        .execute(fixture.db().pool())
        .await
        .expect("forgets its earlier runs");
    let task = builtin(name);
    make_due(fixture.db(), &task).await;
    let run = run_once(fixture, vec![task], name).await;
    assert_eq!(run.outcome.as_deref(), Some("succeeded"), "{run:?}");
    run
}

/// PLAN.md 7.12's Done check: each of ace3's monitoring checks runs from the scheduler, as its own
/// component, and its records are what ace3's monitor emits of the same state. The cases are ace3's
/// `tests/saq/monitoring/test_monitors.py`, each named where it's checked; `test_monitoring_service.py`'s
/// `test_start_single_threaded_executes_each_monitor_once` is every check here run once.
#[tokio::test]
async fn the_monitoring_checks_run_from_the_scheduler() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let pool = &fixture.pool;

    // with nothing to report: one record with an empty workload, and no record of the others
    // (TestDistributedWorkloadMonitor.test_execute_emits_empty_workload)
    let run = check(&fixture, "monitor_workload").await;
    assert_eq!(run.summary, Some(json!({"records": 1, "left_out": 0})));
    assert_eq!(
        records(db, "monitor_workload").await,
        [(
            "workload.distributed".to_owned(),
            None,
            json!({"workload": []})
        )]
    );
    for name in [
        "monitor_delayed_analysis",
        "monitor_leases",
        "monitor_queue",
    ] {
        let run = check(&fixture, name).await;
        assert_eq!(
            run.summary,
            Some(json!({"records": 0, "left_out": 0})),
            "{name}"
        );
        assert!(records(db, name).await.is_empty(), "{name}");
    }

    // roots being analyzed in two modes, one that's done, and their tasks
    let first = root(db, "analysis", true).await;
    let second = root(db, "analysis", true).await;
    let third = root(db, "correlation", true).await;
    root(db, "email", false).await;
    task(db, first, "splunk", "delayed", "1 hour", None).await;
    task(db, first, "splunk", "delayed", "2 hours", None).await;
    task(db, first, "rdap_analyzer", "delayed", "1 hour", None).await;
    task(db, second, "splunk", "delayed", "1 hour", None).await;
    task(db, second, "file_type", "queued", "10 minutes", None).await;
    task(db, third, "file_type", "queued", "1 second", None).await;
    let held = task(
        db,
        third,
        "yara_scanner_v3_4",
        "running",
        "5 minutes",
        Some("parsers/host-a/7"),
    )
    .await;
    // a lease whose worker went away, and an owner with no shape at all
    let expired = task(
        db,
        third,
        "yara_scanner_v3_4",
        "running",
        "-90 seconds",
        Some("db-readonly"),
    )
    .await;

    // TestDistributedWorkloadMonitor.test_execute_counts_workload_per_analysis_mode: a count for each
    // mode with a root being analyzed, in mode order; the root that's done isn't counted
    check(&fixture, "monitor_workload").await;
    assert_eq!(
        records(db, "monitor_workload").await,
        [(
            "workload.distributed".to_owned(),
            None,
            json!({"workload": [
                {"analysis_mode": "analysis", "count": 2},
                {"analysis_mode": "correlation", "count": 1},
            ]})
        )]
    );

    // TestDistributedDelayedAnalysisMonitor.test_execute_emits_one_record_per_root_module_and_node: one
    // for each root and module, with its count, the most first.
    // test_execute_preserves_bare_module_name: the module is the task's key as it is.
    // test_execute_reports_every_node_not_just_the_local_one: every root's, whoever would run them
    let run = check(&fixture, "monitor_delayed_analysis").await;
    assert_eq!(run.summary, Some(json!({"records": 3, "left_out": 0})));
    let delayed = records(db, "monitor_delayed_analysis").await;
    let seen: Vec<(String, String, i64)> = delayed
        .iter()
        .map(|(path, identifier, value)| {
            assert_eq!(path, "workload.distributed.delayed_analysis");
            assert_eq!(
                identifier.as_deref(),
                Some(
                    format!(
                        "{}:{}",
                        value["uuid"].as_str().unwrap(),
                        value["module"].as_str().unwrap()
                    )
                    .as_str()
                )
            );
            assert!(value["next_run"].is_string(), "{value}");
            (
                value["uuid"].as_str().unwrap().to_owned(),
                value["module"].as_str().unwrap().to_owned(),
                value["count"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(seen[0], (first.to_string(), "splunk".to_owned(), 2));
    let mut rest = seen[1..].to_vec();
    rest.sort();
    let mut expected = vec![
        (first.to_string(), "rdap_analyzer".to_owned(), 1),
        (second.to_string(), "splunk".to_owned(), 1),
    ];
    expected.sort();
    assert_eq!(rest, expected);

    // TestDistributedLocksMonitor.test_execute_emits_correct_data: one record for each lease, with the
    // root, who holds it and since when. test_locks_attributed_to_the_owning_node and
    // test_lock_without_a_node_prefix_is_still_reported: the owner is the lease's, as it is, whatever
    // its shape. test_lock_reported_once_when_node_names_share_a_prefix: one record a lease, by its
    // task. The expired lease, whose worker went away, comes first and says so
    let run = check(&fixture, "monitor_leases").await;
    assert_eq!(run.summary, Some(json!({"records": 2, "left_out": 0})));
    let leases = records(db, "monitor_leases").await;
    let (path, identifier, value) = &leases[0];
    assert_eq!(
        (path.as_str(), identifier.as_deref()),
        (
            "workload.distributed.locks",
            Some(expired.to_string().as_str())
        )
    );
    assert_eq!(
        (
            &value["uuid"],
            &value["task"],
            &value["module"],
            &value["lock_owner"],
            &value["expired"]
        ),
        (
            &json!(third),
            &json!(expired),
            &json!("yara_scanner_v3_4"),
            &json!("db-readonly"),
            &json!(true)
        )
    );
    let (_, identifier, value) = &leases[1];
    assert_eq!(identifier.as_deref(), Some(held.to_string().as_str()));
    assert_eq!(
        (&value["lock_owner"], &value["expired"], &value["attempts"]),
        (&json!("parsers/host-a/7"), &json!(false), &json!(0))
    );
    assert!(
        value["lock_time"].is_string() && value["lease_expires_at"].is_string(),
        "{value}"
    );

    // what stands in for TestNodeStatusMonitorQueries: each module once, with all its counts
    // (test_each_node_reported_exactly_once_with_both_counts), the longest wait first, and an expired
    // lease told from a live one by the database's clock (test_heartbeat_age_comes_from_the_database_clock,
    // test_drained_node_is_distinguishable_from_a_crashed_one)
    let run = check(&fixture, "monitor_queue").await;
    assert_eq!(run.summary, Some(json!({"records": 4, "left_out": 0})));
    let queue = records(db, "monitor_queue").await;
    let modules: Vec<&str> = queue
        .iter()
        .map(|(_, id, _)| id.as_deref().unwrap())
        .collect();
    assert_eq!(
        modules[0], "file_type",
        "the module that has waited longest: {queue:?}"
    );
    let of = |module: &str| {
        let (path, _, value) = queue
            .iter()
            .find(|(_, id, _)| id.as_deref() == Some(module))
            .unwrap_or_else(|| panic!("no record of {module}"));
        assert_eq!(path, "workload.queue");
        value.clone()
    };
    let file_type = of("file_type");
    assert_eq!(
        (
            &file_type["queued"],
            &file_type["delayed"],
            &file_type["running"],
            &file_type["expired_leases"]
        ),
        (&json!(2), &json!(0), &json!(0), &json!(0))
    );
    let waited = file_type["oldest_waiting_seconds"].as_i64().unwrap();
    assert!((600..660).contains(&waited), "{waited}");
    assert_eq!(
        of("yara_scanner_v3_4"),
        json!({"module": "yara_scanner_v3_4", "queued": 0, "delayed": 0, "running": 2,
               "expired_leases": 1, "oldest_waiting_seconds": 0})
    );
    // a delayed task that isn't due yet hasn't waited
    assert_eq!(
        of("splunk"),
        json!({"module": "splunk", "queued": 0, "delayed": 3, "running": 0,
               "expired_leases": 0, "oldest_waiting_seconds": 0})
    );

    // a check's run replaces its records: what it no longer finds has none left
    sqlx::query("DELETE FROM queue.tasks WHERE state = 'running'")
        .execute(db.pool())
        .await
        .expect("the leases end");
    check(&fixture, "monitor_leases").await;
    assert!(records(db, "monitor_leases").await.is_empty());

    // TestCASPoolMonitor.test_emits_one_record_per_pool: a record for each configured pool, and for a
    // pool with rows in the index that isn't configured any more
    let held_bytes = fixture.unique("held");
    let overdue_bytes = fixture.unique("overdue");
    let fresh_bytes = fixture.unique("fresh");
    fixture
        .bucket
        .put_bytes(pool, &held_bytes, Some(&Hold::new("test", "keeps")))
        .await
        .expect("puts");
    fixture
        .bucket
        .hold(
            pool,
            &sha256_of(&held_bytes),
            &Hold::new("test", "old").until(Utc::now() - chrono::Duration::hours(1)),
        )
        .await
        .expect("holds");
    fixture
        .bucket
        .put_bytes(pool, &overdue_bytes, None)
        .await
        .expect("puts");
    fixture
        .bucket
        .put_bytes(pool, &fresh_bytes, None)
        .await
        .expect("puts");
    // unheld for three hours: past the pool's grace, none, and the two hours GC is given
    sqlx::query("UPDATE store.objects SET last_held_at = now() - interval '3 hours', verified_at = now() WHERE pool = $1 AND sha256 = $2")
        .bind(pool)
        .bind(sha256_of(&overdue_bytes).to_hex())
        .execute(db.pool())
        .await
        .expect("ages it");
    sqlx::query(
        "INSERT INTO store.objects (pool, sha256, size, state)
         VALUES ('renamed-away', repeat('a', 64), 7, 'deleting')",
    )
    .execute(db.pool())
    .await
    .expect("a row of a pool that isn't configured");
    let run = check(&fixture, "monitor_bucket_pools").await;
    assert_eq!(run.summary, Some(json!({"records": 2, "left_out": 0})));
    let pools = records(db, "monitor_bucket_pools").await;
    let size = (held_bytes.len() + overdue_bytes.len() + fresh_bytes.len()) as i64;
    assert_eq!(
        pools,
        [
            (
                "cas.pool".to_owned(),
                Some("renamed-away".to_owned()),
                json!({"pool": "renamed-away", "configured": false, "retention": null, "gc_overdue": null,
                       "objects_present": 0, "objects_deleting": 1, "size_bytes": 7, "never_verified": 1,
                       "verified_last_7d": 0, "holds_live": 0, "holds_expired": 0, "objects_held": 0})
            ),
            (
                "cas.pool".to_owned(),
                Some(pool.clone()),
                json!({"pool": pool, "configured": true, "retention": "held", "gc_overdue": 1,
                       "objects_present": 3, "objects_deleting": 0, "size_bytes": size, "never_verified": 2,
                       "verified_last_7d": 1, "holds_live": 1, "holds_expired": 1, "objects_held": 1})
            ),
        ]
    );

    // ace3's hourly `ace cas node-stats`: this node's read cache, against its cap and its filesystem
    let run = check(&fixture, "bucket_node_stats").await;
    assert_eq!(run.summary, Some(json!({"records": 1, "left_out": 0})));
    let node = records(db, "bucket_node_stats").await;
    assert_eq!(
        (node[0].0.as_str(), node[0].1.as_deref()),
        ("cas.node", Some("test/1"))
    );
    let value = &node[0].2;
    assert_eq!(
        (
            &value["node"],
            &value["kind"],
            &value["max_bytes"],
            &value["path"]
        ),
        (
            &json!("test/1"),
            &json!("read_cache"),
            &json!(1u64 << 30),
            &json!(fixture.bucket.store().cache().dir().display().to_string())
        )
    );
    // the three objects put above are in the node's cache
    assert_eq!(
        (&value["entries"], &value["bytes"]),
        (&json!(3), &json!(size))
    );
    let (free, total) = (
        value["fs_free_bytes"].as_u64().unwrap(),
        value["fs_total_bytes"].as_u64().unwrap(),
    );
    assert!(free > 0 && free <= total, "{value}");

    // the scheduler's own runs, which 6.7 left for this step to read: each task that has a row, when
    // it's due, how its last run ended and how many have failed since one succeeded
    let mut failing = builtin("bucket_gc");
    failing.actor = Actor::Internal {
        id: Component::new("scheduler:nobody").expect("valid"),
    };
    make_due(db, &failing).await;
    run_once(&fixture, vec![failing], "bucket_gc").await;
    let run = check(&fixture, "monitor_scheduler").await;
    let tasks = records(db, "monitor_scheduler").await;
    assert_eq!(
        run.summary,
        Some(json!({"records": tasks.len(), "left_out": 0}))
    );
    let names: Vec<&str> = tasks
        .iter()
        .map(|(_, id, _)| id.as_deref().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "by name");
    let of = |name: &str| {
        tasks
            .iter()
            .find(|(path, id, _)| path == "scheduler.task" && id.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("no record of {name}"))
            .2
            .clone()
    };
    let gc = of("bucket_gc");
    assert_eq!(
        (
            &gc["last_outcome"],
            &gc["failures_since_success"],
            &gc["running"],
            &gc["last_node"],
            &gc["schedule"]
        ),
        (
            &json!("failed"),
            &json!(1),
            &json!(false),
            &json!("test/1"),
            &json!("0 * * * *")
        )
    );
    assert_eq!(
        gc["last_error"],
        "internal:scheduler:nobody doesn't hold bucket:gc"
    );
    let workload = of("monitor_workload");
    assert_eq!(
        (
            &workload["last_outcome"],
            &workload["failures_since_success"],
            &workload["last_error"]
        ),
        (&json!("succeeded"), &json!(0), &Value::Null)
    );
    // the check that is reporting is the one running
    let itself = of("monitor_scheduler");
    assert_eq!(
        (&itself["running"], &itself["overdue_seconds"]),
        (&json!(true), &json!(0))
    );
    // a task nothing runs falls behind, and says by how much
    sqlx::query("UPDATE scheduler.tasks SET due_at = now() - interval '3 hours', run_id = NULL, lease_until = NULL WHERE name = 'bucket_gc'")
        .execute(db.pool())
        .await
        .expect("leaves it unrun");
    check(&fixture, "monitor_scheduler").await;
    let behind = records(db, "monitor_scheduler")
        .await
        .into_iter()
        .find(|(_, id, _)| id.as_deref() == Some("bucket_gc"))
        .expect("its record")
        .2;
    let overdue = behind["overdue_seconds"].as_i64().unwrap();
    assert!((10_800..10_860).contains(&overdue), "{behind}");

    // a check writes no audit row (ace_service's monitoring docs say why)
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM service.audit")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(audit, 0);

    // a check acting as a component without the grant is refused before it reads anything: its run
    // fails, and its records stay as they were (test_threaded_monitor.py's
    // test_main_loop_logs_error_on_exception: a check that fails is recorded and the next still runs)
    let before = records(db, "monitor_workload").await;
    sqlx::query("DELETE FROM scheduler.runs WHERE task = 'monitor_workload'")
        .execute(db.pool())
        .await
        .expect("forgets its earlier runs");
    let mut refused = builtin("monitor_workload");
    refused.actor = Actor::Internal {
        id: Component::new("scheduler:nobody").expect("valid"),
    };
    make_due(db, &refused).await;
    let run = run_once(&fixture, vec![refused], "monitor_workload").await;
    assert_eq!(run.outcome.as_deref(), Some("failed"));
    assert_eq!(
        run.error.as_deref(),
        Some("internal:scheduler:nobody doesn't hold monitoring:report")
    );
    assert_eq!(records(db, "monitor_workload").await, before);
    let run = check(&fixture, "monitor_workload").await;
    assert_eq!(run.summary, Some(json!({"records": 1, "left_out": 0})));
    fixture.clean_up().await;
}

/// A check that finds more than it emits records for emits the first `MAX_RECORDS` and says how many it
/// left out, in its run's summary: ace3 emits a record for every row, however many.
#[tokio::test]
async fn a_monitoring_check_is_bounded() {
    let fixture = Fixture::new().await;
    let db = fixture.db();
    let over = ace_core::monitoring::MAX_RECORDS + 25;
    let root = root(db, "analysis", true).await;
    sqlx::query(
        "WITH made AS (
             INSERT INTO analysis.observables (root_id, type, value)
             SELECT $1, 'fqdn', 'host-' || n || '.example' FROM generate_series(1, $2) n
             RETURNING id)
         INSERT INTO queue.tasks (root_id, observable_id, module, state, lease_owner, lease_expires_at)
         SELECT $1, id, 'file_type', 'running', 'parsers/host-a/7', now() + interval '5 minutes'
         FROM made",
    )
    .bind(root)
    .bind(over)
    .execute(db.pool())
    .await
    .expect("more leases than a run emits");
    let run = check(&fixture, "monitor_leases").await;
    assert_eq!(
        run.summary,
        Some(json!({"records": ace_core::monitoring::MAX_RECORDS, "left_out": 25}))
    );
    assert_eq!(
        records(db, "monitor_leases").await.len() as i64,
        ace_core::monitoring::MAX_RECORDS
    );
    // and the queue's record still counts them all
    check(&fixture, "monitor_queue").await;
    assert_eq!(records(db, "monitor_queue").await[0].2["running"], over);
    fixture.clean_up().await;
}
