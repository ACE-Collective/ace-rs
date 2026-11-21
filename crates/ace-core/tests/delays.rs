//! PLAN.md 2.9: a task whose run_after is in the future can't be claimed until then. 1.28's
//! delayed module, the Splunk module, runs through the queue against its recorded Splunk API,
//! and runs again after each delay it asks for.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ace_core::queue::{self, TaskState, Wakeups};
use ace_core::testing::TestDb;
use ace_mod_splunk::{PASSWORD, SplunkAnalyzer, SplunkSettings};
use ace_results::ObservableKind;
use ace_sdk::{
    Module, Observable, Outcome, Secret, Secrets, TaskContext, load_settings, run_lookup,
};
use ace_testkit::reference::dumps_dir;
use ace_testkit::replay::HttpReplay;
use chrono::Utc;
use serde_json::{Value, json};

use common::{root_with, worker};

/// Where ace3 reached the fake Splunk the recordings are of.
const SPLUNKD: &str = "https://127.0.0.1:8089";

/// proxy_domain_lookup as ace-mod-splunk's tests run it (its tests/common/mod.rs).
fn proxy_domain_lookup(base_url: &str) -> Value {
    json!({
        "base_url": base_url,
        "username": "ace4",
        "request_timeout_seconds": 10,
        "question": "Was this domain seen in proxy logs?",
        "summary": "Proxy correlation",
        "query": "index=proxy (transport=HTTPS OR transport=HTTP) hostname=\"<O_VALUE>\"\n| eval full_url = lower(transport) . \"://\" . url\n",
        "valid_observable_types": ["fqdn"],
        "observable_mapping": [
            {"field": "src_ip", "type": "ip"},
            {"field": "src_translated_ip", "type": "ip"},
            {"field": "dest_ip", "type": "ip"},
            {"field": "full_url", "type": "url"},
            {"field": "user", "type": "email_address"},
        ],
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_splunk_module_runs_again_after_each_delay_it_asks_for() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "analysis", &[(ObservableKind::Fqdn, "www.example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    let task_id = queue::enqueue(&mut tx, root, ids[0], SplunkAnalyzer::NAME)
        .await
        .expect("queues")
        .expect("new");
    tx.commit().await.expect("commits");

    let replay = HttpReplay::start(
        &dumps_dir().join("proxy_domain_lookup/fqdn_www.example.com.http"),
        &[],
    )
    .await
    .expect("the recording loads");
    let settings: SplunkSettings =
        load_settings(Some(&proxy_domain_lookup(&replay.local_url(SPLUNKD)))).expect("settings");
    let module = SplunkAnalyzer::init(&settings).expect("the module starts");
    let settings = Arc::new(settings);
    let secrets = Secrets::new().with(PASSWORD, Secret::new("ace4-fake-password"));

    let worker = worker(
        &test_db,
        "lookups",
        &[SplunkAnalyzer::NAME],
        Duration::from_secs(60),
    )
    .await;
    let mut wakeups = Wakeups::listen(worker.db()).await.expect("listens");

    let mut runs = Vec::new();
    let mut last_run_after = None;
    let result = loop {
        // a fallback of a minute, so only the due time can end the waits
        let (task, waits) = tokio::time::timeout(
            Duration::from_secs(30),
            worker.next_task(&mut wakeups, Duration::from_secs(60)),
        )
        .await
        .expect("a task within 30 seconds")
        .expect("claims");
        let claimed_at = Utc::now();
        assert_eq!(task.id, task_id);
        assert_eq!(waits.timed_out, 0);
        if let Some(run_after) = last_run_after {
            assert!(claimed_at >= run_after, "{claimed_at} before {run_after}");
            assert!(waits.due >= 1, "{waits:?}");
            assert_eq!(
                task.delayed.as_ref().map(|d| d.delays),
                Some(runs.len() as u32)
            );
        } else {
            assert!(task.delayed.is_none());
        }

        let mut ctx = TaskContext::new::<SplunkAnalyzer>(
            task.root,
            Observable::new(task.observable.kind, task.observable.value.clone()),
            settings.clone(),
        )
        .with_secrets(&secrets);
        if let Some(delayed) = task.delayed.clone() {
            ctx = ctx.with_delayed(delayed);
        }
        match run_lookup(&module, &ctx).await.expect("the module runs") {
            Outcome::Delay(delay) => {
                let run_after = worker
                    .delay(task.id, delay.run_after, &delay.state)
                    .await
                    .expect("delays");
                // not claimable before its time
                assert!(worker.claim().await.expect("claims").is_none());
                assert_eq!(
                    queue::state(db, task.id).await.expect("reads"),
                    Some(TaskState::Delayed)
                );
                runs.push(format!(
                    "delay {:?} {}",
                    delay.run_after,
                    delay.state["dispatch_state"]
                        .as_str()
                        .unwrap_or("submitted")
                ));
                last_run_after = Some(run_after);
            }
            Outcome::Done(result) => {
                worker.complete(task.id).await.expect("completes");
                break result;
            }
            Outcome::Skipped(why) => panic!("skipped: {why}"),
            Outcome::Incomplete(_) => panic!("incomplete"),
        }
    };

    println!("{runs:#?}");
    assert_eq!(
        runs,
        [
            "delay 1s submitted",
            "delay 1s RUNNING",
            "delay 1s RUNNING",
            "delay 1s RUNNING",
        ]
    );
    assert_eq!(
        result.summary.as_deref(),
        Some("Proxy correlation: (3 results)")
    );
    assert_eq!(result.details.dispatch_state.as_deref(), Some("DONE"));
    assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());
    assert_eq!(
        queue::state(db, task_id).await.expect("reads"),
        Some(TaskState::Done)
    );
}
