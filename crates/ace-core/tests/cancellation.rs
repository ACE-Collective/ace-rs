//! PLAN.md 2.12: cancelling a root cancels its queued tasks and signals running ones through
//! their cancellation token; dispositioning an alert cancels it and switches it to
//! dispositioned mode, where only that mode's modules run.

use crate::common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::queue::{self, CancelWatch, Completion, TaskState};
use ace_core::testing::TestDb;
use ace_core::tree;
use ace_results::ObservableKind;
use ace_sdk::{
    Lookup, Module, ModuleError, Observable, Outcome, Parser, TaskContext, run_lookup, run_parser,
};
use common::stubs::StubOutput;
use serde_json::json;

use common::{file_type_says_email, manifests, result, root_with, tasks_of, worker};

const EMAIL_SHA256: &str = "5d2569cdbe088294e456effabcfd8362108468f12deaf6464f95bc5400f85874";
/// How often the parser below checks its cancellation token.
const POLL: Duration = Duration::from_millis(250);

/// A parser that runs until cancelled, checking its token every `POLL`, as blocking code does.
struct Poller;

impl Module for Poller {
    const NAME: &'static str = "test_poller";
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    type Output = StubOutput;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Poller)
    }
}

impl Parser for Poller {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
        loop {
            ctx.check_cancelled()?;
            std::thread::sleep(POLL);
        }
    }
}

/// A lookup that waits on a peer that never answers.
struct Hung;

impl Module for Hung {
    const NAME: &'static str = "test_hung";
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    type Output = StubOutput;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Hung)
    }
}

impl Lookup for Hung {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
        tokio::time::sleep(Duration::from_secs(600)).await;
        Ok(Outcome::Skipped("never".to_owned()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_module_sees_the_cancel_within_one_poll_interval() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    queue::enqueue(&mut tx, root, ids[0], Poller::NAME)
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");

    // a long lease, so a renewal (every 10 seconds) can't be what delivers the cancel
    let worker = worker(
        &test_db,
        "parsers",
        &[Poller::NAME],
        Duration::from_secs(30),
    )
    .await;
    let watch = CancelWatch::start(worker.db()).await.expect("watches");
    let task = worker.claim().await.expect("claims").expect("a task");
    let keeper = worker.keep_lease(task.id);
    let _guard = watch.watch(task.id, keeper.token());
    let ctx = TaskContext::new::<Poller>(
        root,
        Observable::new(task.observable.kind, task.observable.value.clone()),
        Arc::new(()),
    )
    .with_cancel(keeper.token().clone());
    let running = tokio::task::spawn_blocking(move || {
        let outcome = run_parser(&Poller, &ctx);
        (outcome, Instant::now())
    });
    let token = keeper.token().clone();
    let fired = tokio::spawn(async move {
        token.cancelled().await;
        Instant::now()
    });
    tokio::time::sleep(POLL * 3).await;
    assert!(!running.is_finished());

    let mut tx = db.begin().await.expect("begins");
    let cancelled = queue::cancel_root(&mut tx, root).await.expect("cancels");
    tx.commit().await.expect("commits");
    let committed = Instant::now();
    assert_eq!(cancelled.signalled, [task.id]);

    let (outcome, seen) = running.await.expect("the module returns");
    let fired = fired.await.expect("the token fires");
    let to_token = fired.saturating_duration_since(committed);
    let to_module = seen.saturating_duration_since(committed);
    println!("token fired {to_token:?} and the module stopped {to_module:?} after the commit");
    assert!(
        matches!(outcome, Err(ModuleError::Cancelled)),
        "{outcome:?}"
    );
    assert!(to_token < Duration::from_millis(100), "{to_token:?}");
    // a poll is a sleep, which can overrun: it took 250.67 ms for a POLL of 250 ms
    assert!(
        to_module <= POLL + to_token + Duration::from_millis(50),
        "{to_module:?}"
    );

    worker.cancelled(task.id).await.expect("ends the task");
    assert_eq!(
        queue::state(db, task.id).await.expect("reads"),
        Some(TaskState::Cancelled)
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_notification_the_next_renewal_delivers_the_cancel() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    queue::enqueue(&mut tx, root, ids[0], Hung::NAME)
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");
    let lease = Duration::from_millis(900);
    let worker = worker(&test_db, "lookups", &[Hung::NAME], lease).await;
    let task = worker.claim().await.expect("claims").expect("a task");
    let keeper = worker.keep_lease(task.id);
    let ctx = TaskContext::new::<Hung>(
        root,
        Observable::new(task.observable.kind, task.observable.value.clone()),
        Arc::new(()),
    )
    .with_cancel(keeper.token().clone());
    let running = tokio::spawn(async move {
        let outcome = run_lookup(&Hung, &ctx).await;
        (outcome, Instant::now())
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut tx = db.begin().await.expect("begins");
    queue::cancel_root(&mut tx, root).await.expect("cancels");
    tx.commit().await.expect("commits");
    let committed = Instant::now();
    let (outcome, seen) = running.await.expect("the lookup returns");
    let waited = seen.saturating_duration_since(committed);
    println!("the lookup stopped {waited:?} after the commit");
    assert!(
        matches!(outcome, Err(ModuleError::Cancelled)),
        "{outcome:?}"
    );
    // renewals come every third of the lease
    assert!(
        waited <= lease / 3 + Duration::from_millis(150),
        "{waited:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dispositioned_alert_runs_only_alert_added_to_event() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = Orchestrator::new(Catalog::new(manifests()), Modes::ace3());
    let (root, ids) = root_with(
        db,
        "correlation",
        &[
            (ObservableKind::File, EMAIL_SHA256),
            (ObservableKind::Fqdn, "evil.example.com"),
        ],
    )
    .await;
    file_type_says_email(db, root, ids[0]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let modules: Vec<String> = tasks_of(db, root)
        .await
        .into_iter()
        .map(|(module, _, _)| module)
        .collect();
    assert_eq!(
        modules,
        [
            "archive",
            "email_analyzer",
            "rdap_analyzer",
            "yara_scanner_v3_4"
        ]
    );

    // the RDAP lookup is running when the analyst dispositions the alert
    let lookups = worker(
        &test_db,
        "lookups",
        &["rdap_analyzer"],
        Duration::from_secs(30),
    )
    .await;
    let watch = CancelWatch::start(lookups.db()).await.expect("watches");
    let rdap = lookups.claim().await.expect("claims").expect("a task");
    let keeper = lookups.keep_lease(rdap.id);
    let _guard = watch.watch(rdap.id, keeper.token());

    let mut tx = db.begin().await.expect("begins");
    let dispositioned = orchestrator
        .stop_for_disposition(&mut tx, root)
        .await
        .expect("stops analysis");
    tx.commit().await.expect("commits");
    assert_eq!(dispositioned.cancelled.cancelled.len(), 3);
    assert_eq!(dispositioned.cancelled.signalled, [rdap.id]);
    assert_eq!(dispositioned.queued.len(), 2, "one per observable");
    tokio::time::timeout(Duration::from_secs(5), keeper.token().cancelled())
        .await
        .expect("the running lookup is told");
    lookups.cancelled(rdap.id).await.expect("ends the lookup");

    // a worker that runs every module finds only alert_added_to_event's tasks
    let catalog = orchestrator.catalog();
    let all: Vec<&str> = catalog.keys().into_iter().collect();
    let everything = worker(&test_db, "everything", &all, Duration::from_secs(30)).await;
    let mut ran: BTreeMap<String, u32> = BTreeMap::new();
    while let Some(task) = everything.claim().await.expect("claims") {
        *ran.entry(task.module.clone()).or_default() += 1;
        let mut tx = db.begin().await.expect("begins");
        orchestrator
            .land_result(
                &mut tx,
                &everything,
                &task,
                &result(json!({
                    "analysis_type": "test_stub",
                    "schema_version": 1,
                    "details": {"note": "added to an event? no"},
                })),
            )
            .await
            .expect("lands");
        tx.commit().await.expect("commits");
    }
    assert_eq!(
        ran,
        BTreeMap::from([("alert_added_to_event".to_owned(), 2)])
    );

    let stored = tree::root(db.pool(), root)
        .await
        .expect("reads")
        .expect("exists");
    assert_eq!(stored.analysis_mode, "dispositioned");
    let states: BTreeMap<String, String> = tasks_of(db, root)
        .await
        .into_iter()
        .map(|(module, value, state)| (format!("{module} {value}"), state))
        .collect();
    let expect =
        |module: &str, value: &str, state: &str| (format!("{module} {value}"), state.to_owned());
    assert_eq!(
        states,
        BTreeMap::from([
            expect("alert_added_to_event", EMAIL_SHA256, "done"),
            expect("alert_added_to_event", "evil.example.com", "done"),
            expect("archive", EMAIL_SHA256, "cancelled"),
            expect("email_analyzer", EMAIL_SHA256, "cancelled"),
            expect("rdap_analyzer", "evil.example.com", "cancelled"),
            expect("yara_scanner_v3_4", EMAIL_SHA256, "cancelled"),
        ])
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );
}

/// ace3 runs a dispositioned mode's modules on every dispositioned pass, so SVS's capture runs again on
/// each disposition (PLAN.md 7.10 batch 2): a task of a module that stores no result is queued again,
/// done or failed, and one whose module stores results, and has its result, isn't.
#[tokio::test]
async fn each_disposition_runs_a_dispositioned_module_that_stores_nothing_again() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut catalog = manifests();
    catalog.push(common::stubs::SAMPLE_CAPTURE);
    let orchestrator = Orchestrator::new(Catalog::new(catalog), Modes::ace3());
    let (root, _) = root_with(db, "correlation", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let dispose = || async {
        let mut tx = db.begin().await.expect("begins");
        let dispositioned = orchestrator
            .stop_for_disposition(&mut tx, root)
            .await
            .expect("stops analysis");
        tx.commit().await.expect("commits");
        dispositioned.queued.len()
    };
    assert_eq!(dispose().await, 2, "the capture and alert_added_to_event");
    let everyone = worker(
        &test_db,
        "everyone",
        &["svs_yara_sample_capture", "alert_added_to_event"],
        Duration::from_secs(30),
    )
    .await;
    let mut ended = 0;
    while let Some(task) = everyone.claim().await.expect("claims") {
        let mut tx = db.begin().await.expect("begins");
        if task.module == "svs_yara_sample_capture" {
            // a skip: the task ends with no result
            everyone
                .finish_in(&mut tx, task.id, TaskState::Done, None)
                .await
                .expect("ends");
        } else {
            orchestrator
                .land_result(
                    &mut tx,
                    &everyone,
                    &task,
                    &result(json!({
                        "analysis_type": "test_stub",
                        "schema_version": 1,
                        "details": {"note": "not in an event"},
                    })),
                )
                .await
                .expect("lands");
        }
        tx.commit().await.expect("commits");
        ended += 1;
    }
    assert_eq!(ended, 2);
    // a disposition changed again queues the capture again, and only it
    assert_eq!(dispose().await, 1);
    let task = everyone.claim().await.expect("claims").expect("a task");
    assert_eq!(task.module, "svs_yara_sample_capture");
    everyone
        .fail(task.id, "the core was down")
        .await
        .expect("fails");
    // a failed one too
    assert_eq!(dispose().await, 1);
    assert!(everyone.claim().await.expect("claims").is_some());
}

#[tokio::test]
async fn a_result_that_lands_after_the_cancel_is_kept_and_queues_nothing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = Orchestrator::new(Catalog::new(manifests()), Modes::ace3());
    let (root, ids) = root_with(db, "email", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    file_type_says_email(db, root, ids[0]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let parsers = worker(
        &test_db,
        "parsers",
        &["email_analyzer"],
        Duration::from_secs(30),
    )
    .await;
    let task = parsers.claim().await.expect("claims").expect("a task");

    let mut tx = db.begin().await.expect("begins");
    queue::cancel_root(&mut tx, root).await.expect("cancels");
    tx.commit().await.expect("commits");
    // the module finished anyway, with an fqdn the email named
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &parsers,
            &task,
            &result(json!({
                "analysis_type": "email_analysis",
                "schema_version": 1,
                "details": {},
                "observables": [{"type": "url", "value": "https://evil.example.com/"}],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert!(landed.queued.is_empty());
    assert_eq!(
        tree::observables(db.pool(), root)
            .await
            .expect("reads")
            .len(),
        2
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [Completion { root, pass: 1 }]
    );
}
