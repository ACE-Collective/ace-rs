//! PLAN.md 2.11: a root is complete when it has no queued, delayed or running tasks, and each
//! analysis pass ends with exactly one completion event. And the pass's metrics events
//! (`ace_core::metrics`, ace3's per-root and per-module ones): one for each completed pass, with the
//! root's counts, and one for each module that ran in it, with its tasks' run times.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::queue::{self, Completion, Completions, Worker, reap_expired_leases};
use ace_core::testing::TestDb;
use ace_results::ObservableKind;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{result, root_with, worker};

/// Queues one task per observable and module, committed.
async fn queue_all(
    test_db: &TestDb,
    root: Uuid,
    ids: &[ace_core::tree::ObservableId],
    modules: &[&str],
) {
    let mut tx = test_db.db().begin().await.expect("begins");
    for id in ids {
        for module in modules {
            queue::enqueue(&mut tx, root, *id, module)
                .await
                .expect("queues")
                .expect("new");
        }
    }
    tx.commit().await.expect("commits");
}

/// Drains the worker's tasks, ending them three ways in turn: a result landed through the
/// orchestrator, a skip (completed with no result) and a failure.
async fn drain(worker: Arc<Worker>, orchestrator: Arc<Orchestrator>) {
    let empty: Value = json!({});
    while let Some(task) = worker.claim().await.expect("claims") {
        match task.id.0 % 3 {
            0 => {
                let mut tx = worker.db().begin().await.expect("begins");
                orchestrator
                    .land_result(
                        &mut tx,
                        &worker,
                        &task,
                        &result(json!({
                            "analysis_type": "test_stub",
                            "schema_version": 1,
                            "details": empty,
                        })),
                    )
                    .await
                    .expect("lands");
                tx.commit().await.expect("commits");
            }
            1 => worker.complete(task.id).await.expect("completes"),
            _ => worker.fail(task.id, "a test failure").await.expect("fails"),
        }
    }
}

/// Every completion notification about `root` until none comes for `quiet`.
async fn notifications(completions: &mut Completions, root: Uuid, quiet: Duration) -> Vec<i32> {
    let mut passes = Vec::new();
    while let Some(Completion { root: r, pass }) = completions.next(quiet).await.expect("listens") {
        if r == root {
            passes.push(pass);
        }
    }
    passes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn each_analysis_pass_ends_with_exactly_one_completion() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut completions = Completions::listen(db).await.expect("listens");
    // modules the catalog doesn't know, so results queue nothing more
    let orchestrator = Arc::new(Orchestrator::new(Catalog::default(), Modes::ace3()));
    let values: Vec<String> = (0..40).map(|i| format!("host{i}.example.com")).collect();
    let observables: Vec<(ObservableKind, &str)> = values
        .iter()
        .map(|v| (ObservableKind::Fqdn, v.as_str()))
        .collect();
    let (root, ids) = root_with(db, "analysis", &observables).await;

    for pass in 1..=2 {
        // each pass gets 200 new tasks, drained by four workers with four tasks in flight each,
        // so the last tasks of a pass end at nearly the same moment on different connections
        let names: Vec<String> = (0..5).map(|m| format!("pass{pass}_m{m}")).collect();
        let modules: Vec<&str> = names.iter().map(String::as_str).collect();
        queue_all(&test_db, root, &ids, &modules).await;
        let mut slots = tokio::task::JoinSet::new();
        for n in 0..4 {
            let worker = Arc::new(
                worker(
                    &test_db,
                    &format!("pass{pass}-worker{n}"),
                    &modules,
                    Duration::from_secs(60),
                )
                .await,
            );
            for _ in 0..4 {
                slots.spawn(drain(worker.clone(), orchestrator.clone()));
            }
        }
        slots.join_all().await;
        let seen = notifications(&mut completions, root, Duration::from_millis(500)).await;
        assert_eq!(seen, [pass], "pass {pass}'s notifications");
        let recorded: Vec<i32> = queue::completions(db, root)
            .await
            .expect("reads")
            .iter()
            .map(|c| c.pass)
            .collect();
        assert_eq!(recorded, (1..=pass).collect::<Vec<_>>());
    }
}

#[tokio::test]
async fn delayed_and_running_tasks_keep_a_root_open() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, root, &ids, &["slow"]).await;
    let worker = worker(&test_db, "w", &["slow"], Duration::from_secs(60)).await;

    let task = worker.claim().await.expect("claims").expect("a task");
    worker
        .delay(task.id, Duration::from_millis(200), &Value::Null)
        .await
        .expect("delays");
    assert!(
        queue::completions(db, root)
            .await
            .expect("reads")
            .is_empty()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let task = worker.claim().await.expect("claims").expect("due again");
    assert!(
        queue::completions(db, root)
            .await
            .expect("reads")
            .is_empty()
    );
    worker.complete(task.id).await.expect("completes");
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );
}

#[tokio::test]
async fn a_task_the_reaper_fails_can_end_the_pass_and_a_root_with_no_work_completes_at_start() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, root, &ids, &["crashing"]).await;
    sqlx::query("UPDATE queue.tasks SET max_attempts = 1 WHERE root_id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("sets the limit");
    let worker = worker(&test_db, "w", &["crashing"], Duration::from_millis(200)).await;
    let _claimed = worker.claim().await.expect("claims").expect("a task");
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        reap_expired_leases(db, None)
            .await
            .expect("reaps")
            .failed
            .len(),
        1
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );

    // the orchestrator starting a root that no module takes: its first pass ends at once
    let orchestrator = Orchestrator::new(Catalog::new(common::manifests()), Modes::ace3());
    let (idle, _) = root_with(db, "event", &[(ObservableKind::Fqdn, "example.org")]).await;
    let mut tx = db.begin().await.expect("begins");
    assert!(
        orchestrator
            .start(&mut tx, idle)
            .await
            .expect("starts")
            .is_empty()
    );
    tx.commit().await.expect("commits");
    assert_eq!(
        queue::completions(db, idle).await.expect("reads"),
        [Completion {
            root: idle,
            pass: 1
        }]
    );
}

/// The metrics events this test binary's roots emitted, as the JSON their log records carry.
///
/// The subscriber is the process's, set once: a thread's own would miss the records, because
/// `tracing` decides whether a log line is on from the thread that reaches it first while one
/// subscriber exists, and another test's thread, with none, would switch it off for good. It takes
/// only the metrics' target, so the other tests' log lines stay off.
mod emitted {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use ace_core::metrics;
    use serde_json::Value;
    use tracing::field::{Field, Visit};
    use tracing::subscriber::Interest;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use uuid::Uuid;

    type Events = Arc<Mutex<Vec<Value>>>;
    static EVENTS: OnceLock<Events> = OnceLock::new();

    struct Capture(Events);

    #[derive(Default)]
    struct Message(String);

    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    /// Whether the events are taken. The measurement turns it off to time a pass's end without them.
    static TAKEN: AtomicBool = AtomicBool::new(true);

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        // asked each time for the metrics' records, so `take` can turn them off, and never for others
        fn register_callsite(&self, metadata: &'static tracing::Metadata<'static>) -> Interest {
            if metadata.target() == metrics::TARGET {
                Interest::sometimes()
            } else {
                Interest::never()
            }
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>, _: Context<'_, S>) -> bool {
            metadata.target() == metrics::TARGET && TAKEN.load(Ordering::SeqCst)
        }

        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            assert_eq!(*event.metadata().level(), tracing::Level::INFO);
            let mut message = Message::default();
            event.record(&mut message);
            let (json, event_type) = match message.0.strip_prefix(metrics::MESSAGE_PREFIX) {
                Some(json) => (json, metrics::EVENT_TYPE_ROOT),
                None => (
                    message
                        .0
                        .strip_prefix(metrics::MODULE_MESSAGE_PREFIX)
                        .unwrap_or_else(|| panic!("a metrics record's message: {}", message.0)),
                    metrics::EVENT_TYPE_MODULE,
                ),
            };
            let value: Value = serde_json::from_str(json).expect("the event is JSON on one line");
            assert_eq!(
                value["event_type"], event_type,
                "its message's prefix: {json}"
            );
            self.0.lock().expect("the events").push(value);
        }
    }

    /// Starts keeping the events. A test calls it before the pass it reads the event of ends.
    pub fn capture() {
        EVENTS.get_or_init(|| {
            let events = Events::default();
            let subscriber = tracing_subscriber::registry().with(Capture(events.clone()));
            tracing::subscriber::set_global_default(subscriber).expect("no other subscriber");
            events
        });
    }

    /// Turns the events off or on again, as `ACE4_LOG` does for a process.
    pub fn take(taken: bool) {
        TAKEN.store(taken, Ordering::SeqCst);
    }

    /// The root events about `root` so far, in the order they were emitted.
    pub fn of(root: Uuid) -> Vec<Value> {
        of_type(root, "root")
    }

    /// The module events about `root` so far, in the order they were emitted.
    pub fn modules_of(root: Uuid) -> Vec<Value> {
        of_type(root, "module")
    }

    fn of_type(root: Uuid, event_type: &str) -> Vec<Value> {
        let events = EVENTS.get().expect("capture() first");
        events
            .lock()
            .expect("the events")
            .iter()
            .filter(|event| event["root_uuid"] == root.to_string())
            .filter(|event| event["event_type"] == event_type)
            .cloned()
            .collect()
    }

    /// Every event about `root` so far, root and module events alike, in the order they were
    /// emitted.
    pub fn all_of(root: Uuid) -> Vec<Value> {
        let events = EVENTS.get().expect("capture() first");
        events
            .lock()
            .expect("the events")
            .iter()
            .filter(|event| event["root_uuid"] == root.to_string())
            .cloned()
            .collect()
    }
}

/// ace3's `972058d1` and `6a9cd43f`: a pass emits one metrics event when it completes, not one for
/// each task or module, with the root's observable counts by type, and each later pass emits its own.
#[tokio::test]
async fn a_completed_pass_emits_one_metrics_event_with_the_roots_counts() {
    emitted::capture();
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(
        db,
        "analysis",
        &[
            (ObservableKind::Fqdn, "a.example.com"),
            (ObservableKind::Fqdn, "b.example.com"),
            (ObservableKind::Fqdn, "c.example.com"),
            (ObservableKind::Ipv4, "192.0.2.1"),
            (ObservableKind::Ipv4, "192.0.2.2"),
            (ObservableKind::Url, "https://a.example.com/"),
        ],
    )
    .await;
    // twelve module tasks, and the core's own hooks task, which the event's task count leaves out
    queue_all(&test_db, root, &ids, &["first", "second"]).await;
    queue_all(&test_db, root, &ids[..1], &[ace_core::hooks::HOOKS_MODULE]).await;
    let modules = ["first", "second", ace_core::hooks::HOOKS_MODULE];
    let worker = worker(&test_db, "w", &modules, Duration::from_secs(60)).await;

    // every task but the last ends, one of them failing, and nothing is emitted
    let mut ended = 0;
    let last = loop {
        let task = worker.claim().await.expect("claims").expect("a task");
        if ended == 12 {
            break task;
        }
        if ended == 4 {
            worker.fail(task.id, "a test failure").await.expect("fails");
        } else {
            worker.complete(task.id).await.expect("completes");
        }
        ended += 1;
        assert!(
            emitted::of(root).is_empty(),
            "no event after task {ended} of 13: the pass is open"
        );
    };
    let before = chrono::Utc::now();
    worker.complete(last.id).await.expect("completes");

    let events = emitted::of(root);
    assert_eq!(events.len(), 1, "one event for the pass: {events:?}");
    let event = &events[0];
    let completed_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT completed_at FROM queue.root_completions WHERE root_id = $1 AND pass = 1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the pass's completion");
    let seconds = event["pass_open_seconds"].as_f64().expect("a number");
    // from the transaction that queued the first task to the one that ended the last
    assert!(
        seconds > 0.0 && seconds <= (chrono::Utc::now() - before).as_seconds_f64() + 60.0,
        "{seconds}"
    );
    let mut expected = json!({
        "event_type": "root",
        "timestamp": completed_at,
        "root_uuid": root,
        "pass": 1,
        "total_analysis_time_seconds": event["total_analysis_time_seconds"].clone(),
        "pass_open_seconds": seconds,
        "alert_type": null,
        "is_alert": false,
        "queue": "default",
        "observable_count": 6,
        "observable_type_counts": {"fqdn": 3, "ipv4": 2, "url": 1},
        "task_count": 12,
        "failed_task_count": 1,
        "outcome": "completed",
    });
    assert_eq!(event, &expected);
    // and one event for each of the three modules that ran, the core's hooks among them, after the
    // root's, with the same timestamp and the pass's run times
    let modules = emitted::modules_of(root);
    assert_eq!(
        modules
            .iter()
            .map(|event| (
                event["module"].as_str().expect("a name"),
                event["exec_count"].as_i64()
            ))
            .collect::<Vec<_>>(),
        [
            (ace_core::hooks::HOOKS_MODULE, Some(1)),
            ("first", Some(6)),
            ("second", Some(6))
        ],
        "{modules:?}"
    );
    assert_module_events_add_up(db, root, 1, event, &modules).await;

    // a second pass: the root is an alert now, of a type and in a queue its submitter named, and
    // has one more observable. Its event is the second, and counts the whole root.
    sqlx::query(
        "UPDATE analysis.roots
         SET alerted_at = now(), queue = 'intel',
             origin = '{\"alert_type\": \"hunter - splunk - v2\"}'
         WHERE id = $1",
    )
    .bind(root)
    .execute(db.pool())
    .await
    .expect("makes it an alert");
    let mut tx = db.begin().await.expect("begins");
    let added = ace_core::tree::upsert_observable(
        &mut tx,
        root,
        &ace_results::NewObservable::new(ObservableKind::Url, "https://b.example.com/"),
    )
    .await
    .expect("adds");
    queue::enqueue(&mut tx, root, added.id, "first")
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");
    assert_eq!(emitted::of(root).len(), 1, "queueing work emits nothing");
    let task = worker.claim().await.expect("claims").expect("a task");
    worker.complete(task.id).await.expect("completes");

    let events = emitted::of(root);
    assert_eq!(events.len(), 2, "one event for each pass: {events:?}");
    assert_eq!(events[0], expected, "the first pass's event is as it was");
    let event = &events[1];
    let completed_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT completed_at FROM queue.root_completions WHERE root_id = $1 AND pass = 2",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the pass's completion");
    expected["timestamp"] = json!(completed_at);
    expected["pass"] = json!(2);
    expected["pass_open_seconds"] = event["pass_open_seconds"].clone();
    expected["total_analysis_time_seconds"] = event["total_analysis_time_seconds"].clone();
    expected["alert_type"] = json!("hunter - splunk - v2");
    expected["is_alert"] = json!(true);
    expected["queue"] = json!("intel");
    expected["observable_count"] = json!(7);
    expected["observable_type_counts"] = json!({"fqdn": 3, "ipv4": 2, "url": 2});
    expected["task_count"] = json!(13);
    assert_eq!(event, &expected);
    // its module events are the second pass's alone: one module ran, once
    let modules: Vec<Value> = emitted::modules_of(root)
        .into_iter()
        .filter(|module| module["pass"] == 2)
        .collect();
    assert_eq!(modules.len(), 1, "{modules:?}");
    assert_eq!(
        (&modules[0]["module"], &modules[0]["exec_count"]),
        (&json!("first"), &json!(1))
    );
    assert_module_events_add_up(db, root, 2, event, &modules).await;
    // the second pass is timed from its own start, not from the root's
    let second = event["pass_open_seconds"].as_f64().expect("a number");
    let started: Option<f64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (c.completed_at - r.pass_started_at))::float8
         FROM analysis.roots r JOIN queue.root_completions c ON c.root_id = r.id AND c.pass = 2
         WHERE r.id = $1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(Some(second), started);
    assert_eq!(
        queue::completions(db, root).await.expect("reads").len(),
        2,
        "as many events as completions"
    );
}

/// A pass's module events against its root event and the tasks' rows: each is the root's, of the
/// pass, at the root event's time, with its tasks' run time and runs in the pass; their times add up
/// to the root's `total_analysis_time_seconds` and their shares to 100.
async fn assert_module_events_add_up(
    db: &ace_core::db::Db,
    root: Uuid,
    pass: i32,
    event: &Value,
    modules: &[Value],
) {
    let total = event["total_analysis_time_seconds"]
        .as_f64()
        .expect("a number");
    let rows: Vec<(String, f64, i64)> = sqlx::query_as(
        "SELECT module, sum(run_seconds), sum(runs)::int8 FROM queue.tasks
         WHERE root_id = $1 AND run_pass = $2 AND runs > 0 GROUP BY module ORDER BY module",
    )
    .bind(root)
    .bind(pass)
    .fetch_all(db.pool())
    .await
    .expect("reads the runs");
    assert_eq!(modules.len(), rows.len(), "{modules:?} against {rows:?}");
    let (mut seconds, mut share) = (0.0, 0.0);
    for (module, (name, run_seconds, runs)) in modules.iter().zip(&rows) {
        assert_eq!(
            module,
            &json!({
                "event_type": "module",
                "timestamp": event["timestamp"],
                "root_uuid": root,
                "pass": pass,
                "module": name,
                "analysis_time_seconds": run_seconds,
                "percentage": module["percentage"],
                "exec_count": runs,
            })
        );
        assert!(*run_seconds > 0.0, "{module}");
        seconds += run_seconds;
        share += module["percentage"].as_f64().expect("a number");
    }
    assert!((seconds - total).abs() < 1e-9, "{seconds} against {total}");
    assert!(total > 0.0);
    assert!((share - 100.0).abs() < 1e-9, "{share}");
}

/// The event is of the pass a transaction ended, so one that rolls back emits nothing, and neither
/// does a root with no work, whose first pass ends when it starts, emit more than its one.
#[tokio::test]
async fn a_pass_whose_end_rolls_back_emits_nothing_until_one_commits() {
    emitted::capture();
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, root, &ids, &["only"]).await;
    let worker = worker(&test_db, "w", &["only"], Duration::from_secs(60)).await;
    let task = worker.claim().await.expect("claims").expect("a task");

    let mut tx = db.begin().await.expect("begins");
    let ended = worker
        .finish_in(&mut tx, task.id, queue::TaskState::Done, None)
        .await
        .expect("ends the task");
    assert_eq!(
        queue::check_completion(&mut tx, ended)
            .await
            .expect("checks"),
        Some(1),
        "the transaction ended the pass"
    );
    tx.rollback().await.expect("rolls back");
    assert!(emitted::of(root).is_empty(), "the pass didn't end");
    assert!(
        queue::completions(db, root)
            .await
            .expect("reads")
            .is_empty()
    );

    worker.complete(task.id).await.expect("completes");
    let events = emitted::of(root);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["pass"], 1);
    assert_eq!(events[0]["task_count"], 1);

    // a root no module takes: the pass ends in the transaction that starts it
    let orchestrator = Orchestrator::new(Catalog::new(common::manifests()), Modes::ace3());
    let (idle, _) = root_with(db, "event", &[(ObservableKind::Fqdn, "example.org")]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, idle).await.expect("starts");
    assert!(emitted::of(idle).is_empty(), "not before the commit");
    tx.commit().await.expect("commits");
    let events = emitted::of(idle);
    assert_eq!(events.len(), 1, "{events:?}");
    // ace3's "emitted even when no module did anything in the work item"
    assert_eq!(events[0]["task_count"], 0);
    assert_eq!(events[0]["total_analysis_time_seconds"], 0.0);
    assert!(emitted::modules_of(idle).is_empty(), "no module ran");
    assert_eq!(events[0]["observable_count"], 1);
    assert_eq!(events[0]["observable_type_counts"], json!({"fqdn": 1}));
}

/// ace3 emits the event for a work item that was cancelled, since its executor returns normally, and
/// for one whose module raised, which the engine catches. Here: a cancelled root's pass ends, at once
/// when nothing is running and otherwise when its last running task stops, and its event says it was
/// cancelled; a root whose only task failed has its event with the failure counted.
#[tokio::test]
async fn a_cancelled_root_and_a_root_whose_task_failed_each_emit_their_event() {
    emitted::capture();
    let test_db = TestDb::new().await;
    let db = test_db.db();

    // cancelled with nothing running: the pass ends in the cancelling transaction
    let (queued, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(&test_db, queued, &ids, &["never_claimed", "nor_this"]).await;
    let mut tx = db.begin().await.expect("begins");
    queue::cancel_root(&mut tx, queued).await.expect("cancels");
    assert!(emitted::of(queued).is_empty(), "not before the commit");
    tx.commit().await.expect("commits");
    let events = emitted::of(queued);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], "cancelled");
    assert_eq!(events[0]["pass"], 1);
    assert_eq!(events[0]["task_count"], 2);
    assert_eq!(events[0]["failed_task_count"], 0);
    // neither task ran, so no module event and no run time
    assert_eq!(events[0]["total_analysis_time_seconds"], 0.0);
    assert!(emitted::modules_of(queued).is_empty());

    // cancelled while a task runs: the event waits for the task to stop
    let (running, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.net")]).await;
    queue_all(&test_db, running, &ids, &["slow", "queued_behind"]).await;
    let slow = worker(&test_db, "slow", &["slow"], Duration::from_secs(60)).await;
    let task = slow.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let cancelled = queue::cancel_root(&mut tx, running).await.expect("cancels");
    tx.commit().await.expect("commits");
    assert_eq!(
        (cancelled.cancelled.len(), cancelled.signalled),
        (1, vec![task.id])
    );
    assert!(emitted::of(running).is_empty(), "a task is still running");
    slow.cancelled(task.id).await.expect("stops");
    let events = emitted::of(running);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], "cancelled");
    assert_eq!(events[0]["task_count"], 2);
    // the task that stopped ran; the one queued behind it didn't
    let modules = emitted::modules_of(running);
    assert_eq!(modules.len(), 1, "{modules:?}");
    assert_eq!(modules[0]["module"], "slow");
    assert_module_events_add_up(db, running, 1, &events[0], &modules).await;

    // a root whose only task failed
    let (failed, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.org")]).await;
    queue_all(&test_db, failed, &ids, &["failing"]).await;
    let failing = worker(&test_db, "failing", &["failing"], Duration::from_secs(60)).await;
    let task = failing.claim().await.expect("claims").expect("a task");
    failing
        .fail(task.id, "a test failure")
        .await
        .expect("fails");
    let events = emitted::of(failed);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], "completed");
    assert_eq!(events[0]["task_count"], 1);
    assert_eq!(events[0]["failed_task_count"], 1);
    // a failed run counts, as a module that raised does in ace3
    let modules = emitted::modules_of(failed);
    assert_eq!(modules.len(), 1, "{modules:?}");
    assert_eq!(modules[0]["exec_count"], 1);
    assert_module_events_add_up(db, failed, 1, &events[0], &modules).await;
}

/// A task's run time (`ace_core::metrics`, migration 0068): a run is from the claim that takes the
/// task's lease to the start of the transaction that ends it or delays it. A delayed task's runs in a
/// pass add up, without the wait between them; a claim the core holds, one released at shutdown and
/// one whose lease the reaper took back add nothing; a task queued again for a later pass starts over
/// there. The root's event is emitted before its module events, which follow in the module's order.
#[tokio::test]
async fn a_tasks_run_time_is_from_each_claim_to_its_end_in_the_pass() {
    emitted::capture();
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    queue_all(
        &test_db,
        root,
        &ids,
        &["delayed", "held", "released", "reaped"],
    )
    .await;
    let lease = Duration::from_secs(60);
    let claim = |worker: &Worker| {
        let worker = worker.clone();
        async move { worker.claim().await.expect("claims").expect("a task") }
    };
    let started = std::time::Instant::now();

    // two runs of 150 ms and 100 ms, with a wait of 300 ms between them
    let delayed = worker(&test_db, "delayed", &["delayed"], lease).await;
    let task = claim(&delayed).await;
    let delayed_task = task.id;
    tokio::time::sleep(Duration::from_millis(150)).await;
    delayed
        .delay(task.id, Duration::from_millis(300), &json!({"step": 1}))
        .await
        .expect("delays");
    tokio::time::sleep(Duration::from_millis(350)).await;
    let task = claim(&delayed).await;
    assert_eq!(task.id, delayed_task);
    tokio::time::sleep(Duration::from_millis(100)).await;
    delayed.complete(task.id).await.expect("completes");

    // held by the core for 300 ms, then a run of 50 ms
    let held = worker(&test_db, "held", &["held"], lease).await;
    let task = claim(&held).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    held.hold(task.id, Duration::ZERO).await.expect("holds");
    let task = claim(&held).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    held.complete(task.id).await.expect("completes");

    // released after 300 ms, as at a shutdown, then a run of 50 ms
    let released = worker(&test_db, "released", &["released"], lease).await;
    let task = claim(&released).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    released.release(task.id).await.expect("releases");
    let task = claim(&released).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    released.complete(task.id).await.expect("completes");

    // a lease of 200 ms that runs out and is reaped after a second, then a run of 50 ms
    let lost = worker(&test_db, "lost", &["reaped"], Duration::from_millis(200)).await;
    claim(&lost).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        reap_expired_leases(db, None)
            .await
            .expect("reaps")
            .requeued
            .len(),
        1
    );
    let reaped = worker(&test_db, "reaped", &["reaped"], lease).await;
    let task = claim(&reaped).await;
    assert_eq!(task.attempts, 2, "the reaped claim was an attempt");
    tokio::time::sleep(Duration::from_millis(50)).await;
    reaped.complete(task.id).await.expect("completes");
    let wall = started.elapsed().as_secs_f64();

    let events = emitted::all_of(root);
    assert_eq!(
        events
            .iter()
            .map(|event| (
                event["event_type"].as_str().expect("a type"),
                event["module"].as_str().unwrap_or("")
            ))
            .collect::<Vec<_>>(),
        [
            ("root", ""),
            ("module", "delayed"),
            ("module", "held"),
            ("module", "reaped"),
            ("module", "released"),
        ],
        "the root's event, then each module's by name"
    );
    let modules = &events[1..];
    assert_module_events_add_up(db, root, 1, &events[0], modules).await;
    let seconds = |module: &str| {
        let event = modules
            .iter()
            .find(|event| event["module"] == module)
            .expect("its event");
        (
            event["analysis_time_seconds"].as_f64().expect("a number"),
            event["exec_count"].as_i64().expect("a count"),
        )
    };
    let (delayed_seconds, delayed_runs) = seconds("delayed");
    assert_eq!(delayed_runs, 2, "a delayed task's runs add up");
    assert!(
        (0.25..0.25 + 0.3).contains(&delayed_seconds),
        "its two runs, without the wait between them: {delayed_seconds}"
    );
    for module in ["held", "released", "reaped"] {
        let (seconds, runs) = seconds(module);
        assert_eq!(runs, 1, "{module}: the claim given back isn't a run");
        assert!(
            (0.05..0.3).contains(&seconds),
            "{module}: only the run that ended: {seconds}"
        );
    }
    let total = events[0]["total_analysis_time_seconds"]
        .as_f64()
        .expect("a number");
    let open = events[0]["pass_open_seconds"].as_f64().expect("a number");
    assert!(total < open && open < wall + 1.0, "{total} {open} {wall}");

    // a second pass: the delayed task is queued again, and its run time there is its new run's alone
    let mut tx = db.begin().await.expect("begins");
    assert!(
        queue::requeue_ended(&mut tx, delayed_task)
            .await
            .expect("requeues")
    );
    tx.commit().await.expect("commits");
    let task = claim(&delayed).await;
    delayed.complete(task.id).await.expect("completes");
    let events = emitted::of(root);
    assert_eq!(events.len(), 2);
    let modules: Vec<Value> = emitted::modules_of(root)
        .into_iter()
        .filter(|event| event["pass"] == 2)
        .collect();
    assert_eq!(modules.len(), 1, "{modules:?}");
    assert_eq!(modules[0]["exec_count"], 1, "the runs start over");
    assert!(
        modules[0]["analysis_time_seconds"]
            .as_f64()
            .expect("a number")
            < 0.25,
        "{modules:?}"
    );
    assert_module_events_add_up(db, root, 2, &events[1], &modules).await;
    let row: (Option<i32>, i32) =
        sqlx::query_as("SELECT run_pass, runs FROM queue.tasks WHERE id = $1")
            .bind(delayed_task.0)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(row, (Some(2), 1));
}

/// The measurement of `docs/measurements/root-metrics.md`: what the event adds to the transaction
/// that ends a pass, on a root with as many tasks as the comparison's `ace3/archive/test.jar` (which
/// has 3,603; this has 3,622, on 71 observables). It ends a pass 200 times, the event taken and not taken in turn, and times the
/// call that ends the last task, which is the whole transaction; then it times the event's statement
/// by itself. Then what the tasks' run times (migration 0068) add: the event's statement as it is
/// against the one before them, the claim's statement with `claimed_at` against without, and the
/// statement that ends a task with its run against without, each pair in turn, 200 times. Not a
/// test: it asserts only that the passes ended. Run it alone:
///
/// ```text
/// cargo test --release -p ace-core --test completion -- --ignored --nocapture the_metrics_events_cost
/// ```
#[tokio::test]
#[ignore = "a measurement, run by hand"]
async fn the_metrics_events_cost_at_a_pass_s_end() {
    const OBSERVABLES: i32 = 71;
    const MODULES: i32 = 51;
    const PASSES: usize = 200;
    emitted::capture();
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    // the tree's shape: mostly files, as an archive's is
    sqlx::query(
        "INSERT INTO analysis.observables (root_id, type, value)
         SELECT $1, (ARRAY['file', 'file', 'file', 'sha256', 'url', 'fqdn'])[1 + n % 6],
                'observable ' || n
         FROM generate_series(2, $2) AS n",
    )
    .bind(root)
    .bind(OBSERVABLES)
    .execute(db.pool())
    .await
    .expect("adds the observables");
    // each task ran once in the root's first pass, as on a root of the comparison
    sqlx::query(
        "INSERT INTO queue.tasks (root_id, observable_id, module, state, claimed_at, run_pass,
                                  run_seconds, runs)
         SELECT o.root_id, o.id, 'module_' || m,
                CASE WHEN m = 7 AND o.id % 9 = 0 THEN 'failed' ELSE 'done' END::queue.task_state,
                now(), 1, random() / 10, 1
         FROM analysis.observables o, generate_series(1, $2) AS m WHERE o.root_id = $1",
    )
    .bind(root)
    .bind(MODULES)
    .execute(db.pool())
    .await
    .expect("adds the tasks");
    sqlx::query("ANALYZE queue.tasks, analysis.observables")
        .execute(db.pool())
        .await
        .expect("analyzes");
    let tasks: i64 = sqlx::query_scalar("SELECT count(*) FROM queue.tasks WHERE root_id = $1")
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("counts");

    let worker = worker(&test_db, "w", &["last"], Duration::from_secs(60)).await;
    let (mut with, mut without) = (Vec::new(), Vec::new());
    for pass in 0..PASSES {
        // one more task on the idle root begins a pass, and ending it ends the pass
        sqlx::query("DELETE FROM queue.tasks WHERE root_id = $1 AND module = 'last'")
            .bind(root)
            .execute(db.pool())
            .await
            .expect("clears");
        queue_all(&test_db, root, &ids, &["last"]).await;
        let task = worker.claim().await.expect("claims").expect("a task");
        let taken = pass % 2 == 0;
        emitted::take(taken);
        let started = std::time::Instant::now();
        worker.complete(task.id).await.expect("completes");
        let took = started.elapsed().as_secs_f64() * 1000.0;
        if taken { &mut with } else { &mut without }.push(took);
    }
    emitted::take(true);
    let events = emitted::of(root);
    assert_eq!(
        events.len(),
        PASSES / 2,
        "an event for each pass that took one"
    );
    assert_eq!(events[0]["task_count"], tasks + 1);
    assert_eq!(events[0]["observable_count"], i64::from(OBSERVABLES));
    assert_eq!(
        queue::completions(db, root).await.expect("reads").len(),
        PASSES
    );

    // the event's statement by itself, in a transaction that is already open
    let mut alone = Vec::new();
    let mut tx = db.begin().await.expect("begins");
    for _ in 0..PASSES {
        let started = std::time::Instant::now();
        ace_core::metrics::read(&mut tx, root, 1, chrono::Utc::now())
            .await
            .expect("reads")
            .expect("the root");
        alone.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    tx.rollback().await.expect("rolls back");

    // the statements as they were before the run times, against as they are, in turn
    const READ_BEFORE: &str = r#"SELECT r.origin ->> 'alert_type' AS alert_type,
                  r.alerted_at IS NOT NULL AS is_alert, r.queue::text AS queue,
                  r.cancelled_at IS NOT NULL AS cancelled,
                  EXTRACT(EPOCH FROM ($2::timestamptz - r.pass_started_at))::float8
                      AS total_time_seconds,
                  o.types, o.counts, t.tasks, t.failed
           FROM analysis.roots r,
                LATERAL (SELECT COALESCE(array_agg(c.type ORDER BY c.type), '{}') AS types,
                                COALESCE(array_agg(c.n ORDER BY c.type), '{}') AS counts
                         FROM (SELECT type, count(*) AS n FROM analysis.observables
                               WHERE root_id = r.id GROUP BY type) c) o,
                LATERAL (SELECT count(*) AS tasks,
                                count(*) FILTER (WHERE state = 'failed') AS failed
                         FROM queue.tasks WHERE root_id = r.id AND module <> $3) t
           WHERE r.id = $1"#;
    let (mut read_before, mut read_now) = (Vec::new(), Vec::new());
    let mut tx = db.begin().await.expect("begins");
    for turn in 0..PASSES * 2 {
        let started = std::time::Instant::now();
        if turn % 2 == 0 {
            sqlx::query(READ_BEFORE)
                .bind(root)
                .bind(chrono::Utc::now())
                .bind(ace_core::hooks::HOOKS_MODULE)
                .fetch_one(tx.conn())
                .await
                .expect("reads");
            read_before.push(started.elapsed().as_secs_f64() * 1000.0);
        } else {
            let read = ace_core::metrics::read(&mut tx, root, 1, chrono::Utc::now())
                .await
                .expect("reads")
                .expect("the root");
            assert_eq!(read.modules.len(), MODULES as usize);
            read_now.push(started.elapsed().as_secs_f64() * 1000.0);
        }
    }
    tx.rollback().await.expect("rolls back");

    // the claim and a task's end, each one statement in a transaction of its own as the core runs
    // them, on the one task of `last`, which each turn makes due again
    let last: i64 =
        sqlx::query_scalar("SELECT id FROM queue.tasks WHERE root_id = $1 AND module = 'last'")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("the last task");
    macro_rules! claim {
        ($claimed_at:literal) => {
            concat!(
                "WITH due AS MATERIALIZED (
                     SELECT id FROM queue.tasks
                     WHERE state IN ('queued', 'delayed') AND run_after <= now()
                       AND module = ANY($3)
                     ORDER BY run_after, id FOR UPDATE SKIP LOCKED LIMIT $4)
                 UPDATE queue.tasks t
                 SET state = 'running', lease_owner = $1,
                     lease_expires_at = now() + make_interval(secs => $2),
                     attempts = t.attempts + 1, ",
                $claimed_at,
                " updated_at = now()
                 FROM due, analysis.observables o
                 WHERE t.id = due.id AND o.id = t.observable_id
                 RETURNING t.id, t.root_id, t.module, t.attempts, t.input_hashes,
                           t.lease_expires_at, t.run_after, t.delay_state, t.first_delayed_at,
                           t.delays, o.id, o.type, o.value, o.time, o.directives"
            )
        };
    }
    macro_rules! end {
        ($run:literal) => {
            concat!(
                "UPDATE queue.tasks
                 SET state = 'done', error = NULL, lease_owner = NULL, lease_expires_at = NULL,
                     updated_at = now()",
                $run,
                " WHERE id = $1 AND lease_owner = $2 AND state = 'running'
                 RETURNING module, declined"
            )
        };
    }
    let (claim_before, claim_now) = (claim!(""), claim!("claimed_at = now(),"));
    let end_before = end!(", run_pass = run_pass + 0 * $3");
    let end_now = end!(
        ", run_seconds = CASE WHEN run_pass = $3 THEN run_seconds ELSE 0 END
             + GREATEST(COALESCE(EXTRACT(EPOCH FROM now() - claimed_at)::float8, 0), 0),
         runs = CASE WHEN run_pass = $3 THEN runs ELSE 0 END + 1, run_pass = $3"
    );
    let mut times: [Vec<f64>; 4] = Default::default();
    for turn in 0..PASSES * 2 {
        let with = turn % 2 == 1;
        sqlx::query("UPDATE queue.tasks SET state = 'queued', run_after = now() WHERE id = $1")
            .bind(last)
            .execute(db.pool())
            .await
            .expect("makes it due");
        let mut tx = db.begin().await.expect("begins");
        let started = std::time::Instant::now();
        let claimed = sqlx::query(if with { claim_now } else { claim_before })
            .bind("w")
            .bind(60.0_f64)
            .bind(vec!["last".to_owned()])
            .bind(1_i64)
            .fetch_all(tx.conn())
            .await
            .expect("claims");
        tx.commit().await.expect("commits");
        times[usize::from(with)].push(started.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(claimed.len(), 1);
        let mut tx = db.begin().await.expect("begins");
        let started = std::time::Instant::now();
        let ended = sqlx::query(if with { end_now } else { end_before })
            .bind(last)
            .bind("w")
            .bind(1_i32)
            .fetch_optional(tx.conn())
            .await
            .expect("ends");
        tx.commit().await.expect("commits");
        times[2 + usize::from(with)].push(started.elapsed().as_secs_f64() * 1000.0);
        assert!(ended.is_some());
    }
    let [
        mut claim_without,
        mut claim_with,
        mut end_without,
        mut end_with,
    ] = times;

    let summary = |name: &str, times: &mut Vec<f64>| {
        times.sort_by(f64::total_cmp);
        let median = (times[times.len() / 2 - 1] + times[times.len() / 2]) / 2.0;
        println!(
            "{name}: {} runs, median {median:.3} ms, range {:.3} to {:.3} ms",
            times.len(),
            times[0],
            times[times.len() - 1],
        );
        median
    };
    println!(
        "a root with {OBSERVABLES} observables and {} tasks",
        tasks + 1
    );
    let on = summary("the pass's last transaction, with the event", &mut with);
    let off = summary("the pass's last transaction, without it", &mut without);
    println!("the difference of the medians: {:.3} ms", on - off);
    summary("the event's statement alone", &mut alone);
    let before = summary(
        "the event's statement before the run times",
        &mut read_before,
    );
    let now = summary("the event's statement with them", &mut read_now);
    println!("the difference of the medians: {:.3} ms", now - before);
    let before = summary(
        "the claim's transaction without claimed_at",
        &mut claim_without,
    );
    let now = summary("the claim's transaction with it", &mut claim_with);
    println!("the difference of the medians: {:.3} ms", now - before);
    let before = summary(
        "the end's statement and commit without the run",
        &mut end_without,
    );
    let now = summary("the end's statement and commit with it", &mut end_with);
    println!("the difference of the medians: {:.3} ms", now - before);
}
