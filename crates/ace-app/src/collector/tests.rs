//! `ace collect`'s loop, its submissions and its stop (PLAN.md 6.1), over a test database and the
//! stack's bucket, with a source held in memory.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::testing::TestDb;
use ace_results::{AlertPath, ObservableKind};
use ace_store::{BucketConfig, NodeCache, Store};

use super::*;

struct Fixture {
    test_db: TestDb,
    _cache: tempfile::TempDir,
    service: ace_service::Service,
    bucket: Bucket,
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
        let orchestrator = ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        );
        Fixture {
            service: ace_service::Service::new(test_db.db().clone(), orchestrator),
            bucket: Bucket::new(test_db.db().clone(), store, BucketSettings::default()),
            _cache: cache,
            test_db,
        }
    }

    fn submitter(&self, name: &str, stop: &CancellationToken) -> Submitter {
        Submitter::new(
            name,
            self.service.clone(),
            self.bucket.clone(),
            chrono::TimeDelta::hours(4),
            Retry {
                attempts: 3,
                first_wait: Duration::from_millis(10),
            },
            stop.clone(),
        )
        .expect("a submitter")
    }

    async fn roots(&self) -> Vec<(Uuid, String, Value, Value)> {
        sqlx::query_as::<_, (Uuid, String, Value, Value)>(
            "SELECT id, description, submitted_by::jsonb, coalesce(origin, 'null'::jsonb)
             FROM analysis.roots ORDER BY created_at, id",
        )
        .fetch_all(self.test_db.db().pool())
        .await
        .expect("the roots")
    }
}

/// A source in memory, as a queue queue: an item stays until the collector says it has it, and one
/// given back is offered again.
#[derive(Default)]
struct Queue {
    waiting: Mutex<VecDeque<(String, String)>>,
    taken: Mutex<Vec<(String, Submitted)>>,
    refused: Mutex<Vec<String>>,
    given_back: AtomicU32,
}

impl Queue {
    fn offer(&self, key: &str, mode: &str) {
        self.waiting
            .lock()
            .expect("the queue")
            .push_back((key.to_owned(), mode.to_owned()));
    }
}

struct QueueCollector {
    queue: Arc<Queue>,
}

impl Collector for QueueCollector {
    fn collect<'a>(&'a self, submitter: &'a Submitter) -> PassFuture<'a> {
        Box::pin(async move {
            loop {
                if submitter.stopping() {
                    return Ok(Pass::Drained);
                }
                let Some((key, mode)) = self.queue.waiting.lock().expect("the queue").pop_front()
                else {
                    return Ok(Pass::Drained);
                };
                let email = format!("Subject: {key}\n\nhello\n");
                let spooled = submitter
                    .spool_bytes(email.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                let item = Item {
                    key: Some(key.clone()),
                    submission: Submission {
                        description: format!("collected {key}"),
                        analysis_mode: Some(mode.clone()),
                        event_time: None,
                        // as the journal collector marks its email
                        observables: vec![SubmittedObservable {
                            kind: ObservableKind::File,
                            value: spooled.sha256.to_hex(),
                            time: None,
                            tags: vec![],
                            directives: vec!["no_scan".to_owned(), "original_email".to_owned()],
                            exclude_modules: vec![],
                        }],
                        file_yara_meta: Default::default(),
                    },
                    origin: Origin {
                        details: Some(serde_json::json!({"alert_type": "mailbox"})),
                        ..Origin::default()
                    },
                    files: vec![SubmittedFile {
                        path: AlertPath::new("email.rfc822").expect("a path"),
                        spooled,
                    }],
                };
                match submitter.submit(&item).await {
                    Ok(submitted) => self
                        .queue
                        .taken
                        .lock()
                        .expect("taken")
                        .push((key, submitted)),
                    Err(NotSubmitted::Refused(_)) => {
                        self.queue.refused.lock().expect("refused").push(key);
                    }
                    Err(NotSubmitted::GivenBack(_)) => {
                        self.queue.given_back.fetch_add(1, Ordering::SeqCst);
                        self.queue
                            .waiting
                            .lock()
                            .expect("the queue")
                            .push_front((key, mode));
                        return Ok(Pass::Drained);
                    }
                }
            }
        })
    }
}

fn settings() -> RunSettings {
    RunSettings {
        poll: Duration::from_millis(20),
        stop_wait: Duration::from_secs(5),
        ..RunSettings::from_section(&CollectorSection::default()).expect("the defaults")
    }
}

/// Waits until `done`, or fails after 30 seconds.
async fn until(what: &str, done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(30), "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Each item is submitted once, as `collector:<name>`, with its file, its directives and what the
/// collector said of it; a redelivered item makes no second root and is answered with the first; a
/// submission the core refuses is refused at once and makes nothing; and a stop ends the loop.
#[tokio::test]
async fn each_item_is_submitted_once() {
    let fixture = Fixture::new().await;
    let stop = CancellationToken::new();
    let submitter = fixture.submitter("journal", &stop);
    let queue = Arc::new(Queue::default());
    queue.offer("mail/a", "email");
    queue.offer("mail/b", "email");
    queue.offer("mail/bad", "no_such_mode");
    let collector = QueueCollector {
        queue: queue.clone(),
    };
    let settings = settings();
    let run = run_passes(&collector, &submitter, &settings, &stop);
    let check = async {
        until("three items handled", || {
            queue.taken.lock().expect("taken").len() == 2
                && queue.refused.lock().expect("refused").len() == 1
        })
        .await;
        // the source offers one again, as queue does when a delete didn't land
        queue.offer("mail/a", "email");
        until("the redelivered item handled", || {
            queue.taken.lock().expect("taken").len() == 3
        })
        .await;
        stop.cancel();
    };
    let (passes, ()) = tokio::join!(run, check);
    assert!(passes >= 1);

    let taken = queue.taken.lock().expect("taken").clone();
    let [
        (a, Submitted::New { root: first }),
        (b, Submitted::New { root: second }),
        (again, Submitted::Duplicate { root: same }),
    ] = taken.as_slice()
    else {
        panic!("{taken:?}");
    };
    assert_eq!(
        (a.as_str(), b.as_str(), again.as_str()),
        ("mail/a", "mail/b", "mail/a")
    );
    assert_eq!(
        same, first,
        "a duplicate is answered with the root its key made"
    );
    assert_ne!(first, second);
    assert_eq!(*queue.refused.lock().expect("refused"), ["mail/bad"]);
    assert_eq!(queue.given_back.load(Ordering::SeqCst), 0);

    let roots = fixture.roots().await;
    let by = serde_json::json!({"kind": "internal", "id": "collector:journal"});
    assert_eq!(
        roots,
        [
            (
                *first,
                "collected mail/a".to_owned(),
                by.clone(),
                serde_json::json!({"alert_type": "mailbox"})
            ),
            (
                *second,
                "collected mail/b".to_owned(),
                by,
                serde_json::json!({"alert_type": "mailbox"})
            ),
        ]
    );
    let (path, directives): (String, Vec<String>) = sqlx::query_as(
        "SELECT f.path, o.directives FROM analysis.files f
         JOIN analysis.observables o ON o.root_id = f.root_id AND o.id = f.observable_id
         WHERE f.root_id = $1",
    )
    .bind(first)
    .fetch_one(fixture.test_db.db().pool())
    .await
    .expect("the file");
    assert_eq!(path, "email.rfc822");
    assert_eq!(directives, ["no_scan", "original_email"]);
    let keys: Vec<(String, Option<Uuid>, bool)> = sqlx::query_as(
        "SELECT collector, root, expires_at > created_at + interval '3 hours 59 minutes'
         FROM collection.submitted_keys ORDER BY created_at",
    )
    .fetch_all(fixture.test_db.db().pool())
    .await
    .expect("the keys");
    assert_eq!(
        keys,
        [
            ("journal".to_owned(), Some(*first), true),
            ("journal".to_owned(), Some(*second), true)
        ],
        "a refused submission holds no key"
    );
}

/// Keys are each collector's own: another collector's item with the same key is submitted, and an
/// expired key holds nothing.
#[tokio::test]
async fn a_key_is_its_collector_s_and_expires() {
    let fixture = Fixture::new().await;
    let stop = CancellationToken::new();
    let item = |key: &str| Item {
        key: Some(key.to_owned()),
        submission: serde_json::from_value(serde_json::json!({"description": "x"}))
            .expect("a submission"),
        origin: Origin::default(),
        files: vec![],
    };
    let journal = fixture.submitter("journal", &stop);
    let feed = fixture.submitter("feed", &stop);
    let Ok(Submitted::New { root: first }) = journal.submit(&item("k")).await else {
        panic!("submitted");
    };
    assert!(matches!(feed.submit(&item("k")).await, Ok(Submitted::New { root }) if root != first));
    assert_eq!(
        journal.submit(&item("k")).await,
        Ok(Submitted::Duplicate { root: first })
    );
    sqlx::query(
        "UPDATE collection.submitted_keys SET expires_at = now() - interval '1 second'
         WHERE collector = 'journal'",
    )
    .execute(fixture.test_db.db().pool())
    .await
    .expect("expired");
    assert!(
        matches!(journal.submit(&item("k")).await, Ok(Submitted::New { root }) if root != first),
        "an expired key holds nothing"
    );
    // an item with no key is always submitted
    let mut keyless = item("k");
    keyless.key = None;
    for _ in 0..2 {
        assert!(matches!(
            journal.submit(&keyless).await,
            Ok(Submitted::New { .. })
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.roots")
        .fetch_one(fixture.test_db.db().pool())
        .await
        .expect("counted");
    assert_eq!(count, 5);
}

/// A component outside the class `collector` holds none of its grant: a collector's name is all
/// that gives it `alert:create`, and an item it can't submit for that is given back, never lost.
#[tokio::test]
async fn only_a_collector_holds_the_collector_grant() {
    let fixture = Fixture::new().await;
    let stop = CancellationToken::new();
    let mut submitter = fixture.submitter("journal", &stop);
    submitter.actor = ace_service::Actor::Internal {
        id: ace_service::Component::new("scheduler:journal").expect("a name"),
    };
    let item = Item {
        key: Some("k".to_owned()),
        submission: serde_json::from_value(serde_json::json!({"description": "x"}))
            .expect("a submission"),
        origin: Origin::default(),
        files: vec![],
    };
    assert!(matches!(
        submitter.submit(&item).await,
        Err(NotSubmitted::GivenBack(why)) if why.contains("doesn't hold alert:create")
    ));
    // and a deny on one collector wins over its class's allow
    sqlx::query(
        "INSERT INTO service.permissions (component, major, minor, effect, created_by)
         VALUES ('collector:journal', 'alert', 'create', 'deny', '{\"kind\": \"internal\", \"id\": \"test\"}')",
    )
    .execute(fixture.test_db.db().pool())
    .await
    .expect("denied");
    let journal = fixture.submitter("journal", &stop);
    assert!(matches!(
        journal.submit(&item).await,
        Err(NotSubmitted::GivenBack(_))
    ));
    assert!(matches!(
        fixture.submitter("feed", &stop).submit(&item).await,
        Ok(Submitted::New { .. })
    ));
    let keys: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM collection.submitted_keys WHERE collector = 'journal'",
    )
    .fetch_one(fixture.test_db.db().pool())
    .await
    .expect("counted");
    assert_eq!(keys, 0, "a refused write holds no key");
}

/// A stop ends the wait between passes at once, and a pass that ignores it is dropped after
/// `stop_wait`.
#[tokio::test]
async fn a_stop_ends_the_loop_in_time() {
    struct Stuck;
    impl Collector for Stuck {
        fn collect<'a>(&'a self, _: &'a Submitter) -> PassFuture<'a> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(Pass::Drained)
            })
        }
    }
    let fixture = Fixture::new().await;
    for (collector, stop_wait) in [
        (
            Box::new(QueueCollector {
                queue: Arc::new(Queue::default()),
            }) as Box<dyn Collector>,
            Duration::from_secs(30),
        ),
        (Box::new(Stuck), Duration::from_millis(200)),
    ] {
        let stop = CancellationToken::new();
        let submitter = fixture.submitter("journal", &stop);
        let settings = RunSettings {
            poll: Duration::from_secs(3600),
            stop_wait,
            ..settings()
        };
        let stopping = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            stopping.cancel();
        });
        let started = Instant::now();
        run_passes(collector.as_ref(), &submitter, &settings, &stop).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stopped in {:?}",
            started.elapsed()
        );
    }
}

/// A submission the core can't take is tried again, a bounded number of times, and then given
/// back; one it refuses as it is isn't tried again; a stop ends a wait at once and starts no attempt.
#[tokio::test]
async fn a_submission_is_retried_a_bounded_number_of_times() {
    let retry = Retry {
        attempts: 4,
        first_wait: Duration::from_millis(5),
    };
    let root = Uuid::from_u128(7);
    let tries = AtomicU32::new(0);
    let stop = CancellationToken::new();
    // down twice, then up
    let up_on_third = retrying(retry, &stop, || {
        let n = tries.fetch_add(1, Ordering::SeqCst);
        async move {
            if n < 2 {
                Err(AttemptError::Transient("down".to_owned()))
            } else {
                Ok(Submitted::New { root })
            }
        }
    })
    .await;
    assert_eq!(up_on_third, Ok(Submitted::New { root }));
    assert_eq!(tries.load(Ordering::SeqCst), 3);

    tries.store(0, Ordering::SeqCst);
    let always_down = retrying(retry, &stop, || {
        tries.fetch_add(1, Ordering::SeqCst);
        async { Err(AttemptError::Transient("connection refused".to_owned())) }
    })
    .await;
    assert_eq!(
        always_down,
        Err(NotSubmitted::GivenBack(
            "4 attempts failed: connection refused".to_owned()
        ))
    );
    assert_eq!(tries.load(Ordering::SeqCst), 4);

    tries.store(0, Ordering::SeqCst);
    let refused = retrying(retry, &stop, || {
        tries.fetch_add(1, Ordering::SeqCst);
        async { Err(AttemptError::Refused("no analysis mode".to_owned())) }
    })
    .await;
    assert_eq!(
        refused,
        Err(NotSubmitted::Refused("no analysis mode".to_owned()))
    );
    assert_eq!(tries.load(Ordering::SeqCst), 1);

    // a long wait, cut short by a stop: the item goes back without another attempt
    tries.store(0, Ordering::SeqCst);
    let slow = Retry {
        attempts: 5,
        first_wait: Duration::from_secs(3600),
    };
    let stopping = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        stopping.cancel();
    });
    let started = Instant::now();
    let stopped = retrying(slow, &stop, || {
        tries.fetch_add(1, Ordering::SeqCst);
        async { Err(AttemptError::Transient("down".to_owned())) }
    })
    .await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        stopped,
        Err(NotSubmitted::GivenBack(
            "stopping, after 1 attempts: down".to_owned()
        ))
    );
    assert_eq!(tries.load(Ordering::SeqCst), 1);
    let none = retrying(retry, &stop, || {
        tries.fetch_add(1, Ordering::SeqCst);
        async { Ok(Submitted::New { root }) }
    })
    .await;
    assert!(matches!(none, Err(NotSubmitted::GivenBack(_))));
    assert_eq!(
        tries.load(Ordering::SeqCst),
        1,
        "no attempt starts once stopping"
    );
}

/// A collector's section's numbers, with ace3's defaults, and the ones that can't be used.
#[test]
fn a_section_s_numbers() {
    let defaults = RunSettings::from_section(&CollectorSection::default()).expect("the defaults");
    assert_eq!(
        defaults,
        RunSettings {
            key_lifetime: chrono::TimeDelta::hours(4),
            poll: Duration::from_secs(1),
            retry: Retry::default(),
            stop_wait: Duration::from_secs(30),
        }
    );
    let section = CollectorSection {
        key_lifetime_seconds: Some(60),
        poll_seconds: Some(5),
        submit_attempts: Some(2),
        stop_seconds: Some(9),
        ..CollectorSection::default()
    };
    let set = RunSettings::from_section(&section).expect("set");
    assert_eq!(set.key_lifetime, chrono::TimeDelta::seconds(60));
    assert_eq!(set.poll, Duration::from_secs(5));
    assert_eq!(set.retry.attempts, 2);
    assert_eq!(set.stop_wait, Duration::from_secs(9));
    for bad in [
        CollectorSection {
            key_lifetime_seconds: Some(0),
            ..CollectorSection::default()
        },
        CollectorSection {
            submit_attempts: Some(0),
            ..CollectorSection::default()
        },
        CollectorSection {
            poll_seconds: Some(0),
            ..CollectorSection::default()
        },
        CollectorSection {
            key_lifetime_seconds: Some(u64::MAX),
            ..CollectorSection::default()
        },
    ] {
        assert!(RunSettings::from_section(&bad).is_err(), "{bad:?}");
    }
}
