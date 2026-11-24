//! `ace export`'s passes (PLAN.md decision 58), over a test database, with an export held in memory: an
//! unchanged list publishes nothing, a changed one publishes, a failure is tried again on the next pass
//! with what it recorded kept, `due` and `--force` publish an unchanged list, a publish past its timeout
//! fails, two processes never publish at once, and the component holds only its class's grants and
//! reaches only its own record. ace3's `select_detections` and fingerprint are checked on their own.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use ace_core::testing::TestDb;
use ace_service::ServiceError;

use super::*;

fn service(test_db: &TestDb) -> Service {
    Service::new(
        test_db.db().clone(),
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new([]),
            ace_core::modes::Modes::ace3(),
        ),
    )
}

fn settings() -> RunSettings {
    RunSettings {
        interval: Duration::from_millis(10),
        publish_timeout: Duration::from_secs(5),
    }
}

fn exporter(test_db: &TestDb, name: &str, owner: &str) -> Exporter {
    Exporter::new(name, service(test_db), owner, settings()).expect("an exporter")
}

/// Adds a live detection, as the detection service would.
async fn detect(test_db: &TestDb, kind: &str, value: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO lists.entries (list, match, value, ignore_case, observable_type, created_by, updated_by)
         VALUES ('observable_detection', 'exact', $1, false, $2, $3, $3) RETURNING id",
    )
    .bind(value)
    .bind(kind)
    .bind(json!({"kind": "internal", "id": "test"}))
    .fetch_one(test_db.db().pool())
    .await
    .expect("a detection")
}

/// An export in memory: what it published, how often, and what it does next.
#[derive(Default)]
struct Memory {
    published: Mutex<Vec<Vec<(String, i64, String)>>>,
    forced: Mutex<Vec<bool>>,
    /// Publishes that fail before one lands, each recording a partial step in its state.
    failures: AtomicU32,
    /// How long a publish takes.
    takes: Mutex<Duration>,
    due: Mutex<bool>,
    salt: Mutex<String>,
    /// How many lists it was asked for: one each pass.
    lists: AtomicU32,
}

impl Memory {
    fn publishes(&self) -> usize {
        self.published.lock().expect("unpoisoned").len()
    }
}

impl DetectionExport for Memory {
    fn export_list(&self, detections: &[Detection]) -> ExportList {
        self.lists.fetch_add(1, Ordering::SeqCst);
        select(&["email_address", "fqdn"], detections)
    }

    fn fingerprint_salt(&self) -> String {
        self.salt.lock().expect("unpoisoned").clone()
    }

    fn due(&self, _state: &Value, _now: DateTime<Utc>) -> bool {
        *self.due.lock().expect("unpoisoned")
    }

    fn publish<'a>(
        &'a self,
        list: &'a ExportList,
        state: &'a mut Value,
        force: bool,
    ) -> PublishFuture<'a> {
        Box::pin(async move {
            let takes = *self.takes.lock().expect("unpoisoned");
            tokio::time::sleep(takes).await;
            self.forced.lock().expect("unpoisoned").push(force);
            let tries = state["tries"].as_u64().unwrap_or(0);
            state["tries"] = (tries + 1).into();
            if self
                .failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err("the target answered 503".to_owned());
            }
            self.published.lock().expect("unpoisoned").push(
                list.entries()
                    .iter()
                    .map(|e| (e.export_type.clone(), e.id, e.value.clone()))
                    .collect(),
            );
            Ok(())
        })
    }
}

#[tokio::test]
async fn an_unchanged_list_publishes_nothing_and_a_changed_one_publishes() {
    let test_db = TestDb::new().await;
    let from = detect(&test_db, "email_from", "bad@example.com").await;
    let fqdn = detect(&test_db, "fqdn", "evil.example.net").await;
    detect(&test_db, "ipv4", "10.0.0.1").await;
    let export = Memory::default();
    let exporter = exporter(&test_db, "memory", "node-a");
    let stop = CancellationToken::new();

    let first = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(first, PassOutcome::Published { entries: 2 });
    assert_eq!(
        export.published.lock().expect("unpoisoned")[0],
        [
            // a subtype is exported under the configured type it extends
            (
                "email_address".to_owned(),
                from,
                "bad@example.com".to_owned()
            ),
            ("fqdn".to_owned(), fqdn, "evil.example.net".to_owned()),
        ]
    );
    let second = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(second, PassOutcome::Unchanged { entries: 2 });
    assert_eq!(export.publishes(), 1, "nothing changed");

    detect(&test_db, "fqdn", "worse.example.net").await;
    let third = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(third, PassOutcome::Published { entries: 3 });
    // a new salt, such as a setting, publishes the same list again
    *export.salt.lock().expect("unpoisoned") = "a new setting".to_owned();
    let fourth = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(fourth, PassOutcome::Published { entries: 3 });
    assert_eq!(export.publishes(), 3);

    let record = exporter
        .service
        .export_record(&exporter.actor, "memory")
        .await
        .expect("reads")
        .expect("a record");
    assert_eq!(record.lease, None, "each pass let its lease go");
    assert!(record.published_at.is_some());
    assert_eq!(record.state, json!({"tries": 3}));
}

#[tokio::test]
async fn a_failed_publish_keeps_what_it_recorded_and_is_tried_again() {
    let test_db = TestDb::new().await;
    detect(&test_db, "fqdn", "evil.example.net").await;
    let export = Memory {
        failures: AtomicU32::new(1),
        ..Memory::default()
    };
    let exporter = exporter(&test_db, "memory", "node-a");
    let stop = CancellationToken::new();

    let failed = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(
        failed,
        PassOutcome::Failed {
            entries: 1,
            error: "the target answered 503".to_owned()
        }
    );
    let record = exporter
        .service
        .export_record(&exporter.actor, "memory")
        .await
        .expect("reads")
        .expect("a record");
    assert_eq!(record.fingerprint, None, "no list was taken in full");
    assert_eq!(record.published_at, None);
    assert_eq!(
        record.state,
        json!({"tries": 1}),
        "what it recorded is kept"
    );
    assert_eq!(record.lease, None);

    let again = exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(again, PassOutcome::Published { entries: 1 });
    assert_eq!(export.publishes(), 1);
    let record = exporter
        .service
        .export_record(&exporter.actor, "memory")
        .await
        .expect("reads")
        .expect("a record");
    assert!(record.fingerprint.is_some());
    assert_eq!(record.state, json!({"tries": 2}));
}

#[tokio::test]
async fn due_and_force_publish_an_unchanged_list() {
    let test_db = TestDb::new().await;
    detect(&test_db, "fqdn", "evil.example.net").await;
    let export = Memory::default();
    let exporter = exporter(&test_db, "memory", "node-a");
    let stop = CancellationToken::new();
    exporter.pass(&export, false, &stop).await.expect("a pass");
    assert_eq!(
        exporter.pass(&export, true, &stop).await.expect("a pass"),
        PassOutcome::Published { entries: 1 },
        "forced"
    );
    *export.due.lock().expect("unpoisoned") = true;
    assert_eq!(
        exporter.pass(&export, false, &stop).await.expect("a pass"),
        PassOutcome::Published { entries: 1 },
        "due"
    );
    assert_eq!(
        *export.forced.lock().expect("unpoisoned"),
        [false, true, false]
    );
}

#[tokio::test]
async fn a_publish_past_its_timeout_fails_and_lets_its_lease_go() {
    let test_db = TestDb::new().await;
    detect(&test_db, "fqdn", "evil.example.net").await;
    let export = Memory {
        takes: Mutex::new(Duration::from_secs(30)),
        ..Memory::default()
    };
    let exporter = Exporter::new(
        "memory",
        service(&test_db),
        "node-a",
        RunSettings {
            interval: Duration::from_millis(10),
            publish_timeout: Duration::from_millis(100),
        },
    )
    .expect("an exporter");
    let outcome = exporter
        .pass(&export, false, &CancellationToken::new())
        .await
        .expect("a pass");
    assert!(
        matches!(&outcome, PassOutcome::Failed { error, .. } if error.contains("didn't end within")),
        "{outcome:?}"
    );
    let record = exporter
        .service
        .export_record(&exporter.actor, "memory")
        .await
        .expect("reads")
        .expect("a record");
    assert_eq!(record.lease, None);
    assert_eq!(record.fingerprint, None);
}

/// Two replicas of one export: the one that claimed the pass publishes, the other's pass is `Busy`, and a
/// lease that ran out, as a dead process's does, is taken over; the dead one's late write lands nowhere.
#[tokio::test]
async fn two_processes_never_publish_at_once() {
    let test_db = TestDb::new().await;
    detect(&test_db, "fqdn", "evil.example.net").await;
    let service = service(&test_db);
    let actor = Actor::Internal {
        id: ace_service::Component::new("export:memory").expect("a component"),
    };
    let held = service
        .claim_export(&actor, "memory", "node-a", Duration::from_secs(60))
        .await
        .expect("claims")
        .expect("free");
    assert_eq!(
        held.lease.as_ref().map(|(owner, _)| owner.as_str()),
        Some("node-a")
    );

    let export = Memory::default();
    let other = exporter(&test_db, "memory", "node-b");
    assert_eq!(
        other
            .pass(&export, false, &CancellationToken::new())
            .await
            .expect("a pass"),
        PassOutcome::Busy
    );
    assert_eq!(export.publishes(), 0);

    // node-a died: its lease runs out, and node-b takes the pass
    sqlx::query("UPDATE export.targets SET lease_expires_at = now() - interval '1 second'")
        .execute(test_db.db().pool())
        .await
        .expect("ages the lease");
    assert_eq!(
        other
            .pass(&export, false, &CancellationToken::new())
            .await
            .expect("a pass"),
        PassOutcome::Published { entries: 1 }
    );
    let late = service
        .record_export(
            &actor,
            "memory",
            "node-a",
            &ExportOutcome {
                fingerprint: Some("stale"),
                state: &json!({}),
                published: true,
            },
        )
        .await
        .expect("answers");
    assert!(!late, "its lease is gone");
    let record = service
        .export_record(&actor, "memory")
        .await
        .expect("reads")
        .expect("a record");
    assert_ne!(record.fingerprint.as_deref(), Some("stale"));
}

/// `export:<name>` holds `detection:read` and `export:record` through the class `export` (migration
/// 0086) and nothing else, reaches only its own record, and a state the table can't hold is refused.
#[tokio::test]
async fn an_export_holds_its_class_s_grants_and_reaches_only_its_own_record() {
    let test_db = TestDb::new().await;
    let service = service(&test_db);
    let actor = |name: &str| Actor::Internal {
        id: ace_service::Component::new(format!("export:{name}")).expect("a component"),
    };
    let mine = actor("mine");
    for (permission, held) in [
        (ace_service::DETECTION_READ, true),
        (ace_service::EXPORT_RECORD, true),
        (ace_service::DETECTION_WRITE, false),
        (ace_service::ALERT_CREATE, false),
        (ace_service::LIST_READ, false),
    ] {
        assert_eq!(
            service.allowed(&mine, &permission).await.expect("checks"),
            held,
            "{permission}"
        );
    }
    assert!(service.active_detections(&mine).await.is_ok());
    assert!(matches!(
        service
            .claim_export(&mine, "theirs", "node-a", Duration::from_secs(60))
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.export_record(&mine, "theirs").await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    // a component of no class holds neither
    let other = Actor::Internal {
        id: ace_service::Component::new("collector:mine").expect("a component"),
    };
    assert!(matches!(
        service.active_detections(&other).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.export_record(&other, "mine").await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    service
        .claim_export(&mine, "mine", "node-a", Duration::from_secs(60))
        .await
        .expect("claims")
        .expect("free");
    let big = json!({"files": "x".repeat(ace_service::MAX_EXPORT_STATE_BYTES)});
    for state in [json!([]), big] {
        let refused = service
            .record_export(
                &mine,
                "mine",
                "node-a",
                &ExportOutcome {
                    fingerprint: None,
                    state: &state,
                    published: false,
                },
            )
            .await;
        assert!(
            matches!(refused, Err(ServiceError::InvalidRequest(_))),
            "{refused:?}"
        );
    }
}

/// ace3's `select_detections`: a configured type takes the types that extend it, the most specific
/// configured one wins, a type that isn't configured or extends none that is is left out, and blank
/// entries are ignored.
#[test]
fn select_is_ace3_s_select_detections() {
    let detection = |id: i64, kind: &str, value: &str| Detection {
        id,
        observable_type: kind.to_owned(),
        value: value.to_owned(),
    };
    let detections = [
        detection(3, "email_from", "a@example.com"),
        detection(1, "email_reply_to", "b@example.com"),
        detection(2, "email_address", "c@example.com"),
        detection(4, "ipv4", "10.0.0.1"),
        detection(5, "url", "https://example.com/"),
    ];
    let listed = |types: &[&str]| -> Vec<(String, i64)> {
        select(types, &detections)
            .entries()
            .iter()
            .map(|e| (e.export_type.clone(), e.id))
            .collect()
    };
    assert_eq!(
        listed(&["email_address", " ", "ipv4"]),
        [
            ("email_address".to_owned(), 1),
            ("email_address".to_owned(), 2),
            ("email_address".to_owned(), 3),
            ("ipv4".to_owned(), 4),
        ]
    );
    assert_eq!(
        listed(&["email_address", "email_from"]),
        [
            ("email_address".to_owned(), 1),
            ("email_address".to_owned(), 2),
            ("email_from".to_owned(), 3),
        ],
        "the most specific wins"
    );
    assert_eq!(
        listed(&["email_from"]),
        [("email_from".to_owned(), 3)],
        "a parent isn't its children's"
    );
    assert!(listed(&[]).is_empty());
}

/// ace3's `ObservableExport.fingerprint`: the list's own with no salt, else the sha256 of
/// `<list's>:<salt>`.
#[test]
fn the_fingerprint_is_ace3_s() {
    let list = ExportList::new(vec![ExportEntry {
        id: 7,
        export_type: "fqdn".to_owned(),
        observable_type: "fqdn".to_owned(),
        value: "evil.example.net".to_owned(),
    }]);
    // hashlib.sha256(json.dumps([["fqdn", 7, "evil.example.net"]], sort_keys=True,
    // ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    let own = list.fingerprint();
    assert_eq!(fingerprint(&list, ""), own);
    let salted: String = sha2::Sha256::digest(format!("{own}:salt").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(fingerprint(&list, "salt"), salted);
    assert_ne!(fingerprint(&list, "salt"), own);
}

#[test]
fn run_settings_take_the_section_s_numbers() {
    let defaults = RunSettings::from_section(&ExportSection::default()).expect("defaults");
    assert_eq!(
        defaults,
        RunSettings {
            interval: Duration::from_secs(60),
            publish_timeout: Duration::from_secs(600),
        }
    );
    let section = ExportSection {
        interval_seconds: Some(0),
        ..ExportSection::default()
    };
    assert!(RunSettings::from_section(&section).is_err());
    let section = ExportSection {
        publish_timeout_seconds: Some(0),
        ..ExportSection::default()
    };
    assert!(RunSettings::from_section(&section).is_err());
}

/// The loop runs passes until a stop, and `--once` runs one.
#[tokio::test]
async fn the_loop_runs_until_a_stop_or_once() {
    let test_db = TestDb::new().await;
    detect(&test_db, "fqdn", "evil.example.net").await;
    let export = Memory {
        failures: AtomicU32::new(1),
        ..Memory::default()
    };
    let exporter = exporter(&test_db, "memory", "node-a");
    let stop = CancellationToken::new();
    let (passes, failed) = run_passes(&exporter, &export, true, false, &stop).await;
    assert_eq!((passes, failed), (1, true), "one pass, which failed");

    // stopped once two more passes have begun, by count rather than after a fixed time, since a pass
    // can take longer than any fixed time on a loaded machine
    let begun = export.lists.load(Ordering::SeqCst);
    let ((passes, failed), ()) =
        tokio::join!(run_passes(&exporter, &export, false, false, &stop), async {
            tokio::time::timeout(Duration::from_secs(60), async {
                while export.lists.load(Ordering::SeqCst) < begun + 2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("two more passes begin within 60 seconds");
            stop.cancel();
        },);
    assert!(passes > 1, "{passes}");
    assert!(!failed);
    assert_eq!(export.publishes(), 1, "then nothing changed");
}
