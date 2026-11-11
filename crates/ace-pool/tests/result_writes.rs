//! PLAN.md 2.15's Done check: an invalid result is rejected with the field's path and nothing
//! from it is written. PLAN.md 4.2: the rejection also fails its task at once. The worker here is
//! this test, through the lease API's client.

mod common;

use std::time::Duration;

use ace_core::tree::{self, NewRoot};
use ace_pool::client::{ClientError, LeaseClient};
use ace_results::{NewObservable, ObservableKind, ObservableRef, Relationship, RelationshipKind};
use ace_sdk::wire::TaskEnd;
use serde_json::json;
use uuid::Uuid;

use common::{Core, TOKEN, task_of};

/// Rows a result could have written for the root.
async fn written(core: &Core, root: Uuid) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM analysis.results WHERE root_id = $1),
                (SELECT count(*) FROM analysis.observables WHERE root_id = $1),
                (SELECT count(*) FROM analysis.files WHERE root_id = $1),
                (SELECT count(*) FROM queue.tasks WHERE root_id = $1)",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("counts")
}

/// The attempts a root's only task has used.
async fn attempts(core: &Core, root: Uuid) -> i32 {
    sqlx::query_scalar("SELECT attempts FROM queue.tasks WHERE root_id = $1")
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the task")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_result_is_rejected_with_its_fields_path_nothing_is_written_and_its_task_fails()
{
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, zip) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    let client = LeaseClient::new(&core.url, TOKEN, "checker").expect("a client");
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the archive task");
    let before = written(&core, root).await;
    assert_eq!(before, (0, 1, 1, 1));

    // a details field of the wrong type, with an observable that must not be added
    let invalid = json!({
        "analysis_type": "archive_analysis",
        "schema_version": 1,
        "details": {"file_count": 1, "extracted_files": "not a list"},
        "observables": [{"type": "fqdn", "value": "evil.example.com"}],
    });
    let done = TaskEnd::Done {
        result: serde_json::from_value(invalid).expect("an envelope"),
        writes: Vec::new(),
    };
    let refused = client.end(task.id, &done).await;
    let Err(ClientError::Api { status, error }) = refused else {
        panic!("expected a refusal, got {refused:?}");
    };
    println!("{status}: {error:?}");
    assert_eq!(status, 422);
    assert!(
        error
            .fields
            .iter()
            .any(|f| f.path == "/details/extracted_files"),
        "{error:?}"
    );
    assert_eq!(written(&core, root).await, before, "nothing was written");
    // it won't be different next time, so the task fails now and its row says why
    let (state, row) = task_of(&core, root, "archive").await;
    assert_eq!(state, "failed");
    assert!(
        row.as_deref()
            .is_some_and(|row| row.contains("/details/extracted_files")),
        "{row:?}"
    );
    assert_eq!(attempts(&core, root).await, 1);
    assert!(
        matches!(
            client.end(task.id, &done).await,
            Err(ClientError::LeaseLost(_))
        ),
        "the task is over"
    );

    // a result of another module's type is refused for good too
    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the second archive task");
    let wrong_type = json!({
        "analysis_type": "email_analysis",
        "schema_version": 1,
        "details": {},
    });
    let refused = client
        .end(
            task.id,
            &TaskEnd::Done {
                result: serde_json::from_value(wrong_type).expect("an envelope"),
                writes: Vec::new(),
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(ClientError::Api { status: 422, error })
            if error.error.contains("archive writes archive_analysis")),
        "{refused:?}"
    );
    let (state, row) = task_of(&core, root, "archive").await;
    assert_eq!(state, "failed");
    assert!(
        row.as_deref()
            .is_some_and(|row| row.contains("archive writes archive_analysis")),
        "{row:?}"
    );

    // a result naming a file that was never uploaded could still be put right, so the task stays
    // the worker's, with nothing written
    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the third archive task");
    let before = written(&core, root).await;
    let missing = json!({
        "analysis_type": "archive_analysis",
        "schema_version": 1,
        "details": {"file_count": 0, "extracted_files": []},
        "files": [{
            "path": "test.zip.extracted/a",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 0,
        }],
    });
    let refused = client
        .end(
            task.id,
            &TaskEnd::Done {
                result: serde_json::from_value(missing).expect("an envelope"),
                writes: Vec::new(),
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(ClientError::Api { status: 400, .. })),
        "{refused:?}"
    );
    assert_eq!(written(&core, root).await, before, "still nothing written");
    assert_eq!(task_of(&core, root, "archive").await.0, "running");

    // and a valid result lands
    let valid = json!({
        "analysis_type": "archive_analysis",
        "schema_version": 1,
        "details": {"file_count": 0, "extracted_files": []},
        "observables": [{"type": "fqdn", "value": "evil.example.com"}],
    });
    client
        .end(
            task.id,
            &TaskEnd::Done {
                result: serde_json::from_value(valid).expect("an envelope"),
                writes: Vec::new(),
            },
        )
        .await
        .expect("a valid result lands");
    assert_eq!(written(&core, root).await, (1, 2, 1, 1));
    core.bucket
        .store()
        .delete(ace_core::bucket::ALERT_FILES, &zip)
        .await
        .expect("tidies the bucket");
}

/// The end route answers 422 only for a rejected result, because a pool takes that as the task's
/// end: a body the API can't read is the pool's bug, and the task keeps its lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_end_the_api_cant_read_doesnt_end_the_task() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    let client = LeaseClient::new(&core.url, TOKEN, "checker").expect("a client");
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the archive task");
    let http = ace_sdk::http::HttpClient::builder()
        .build()
        .expect("a client");
    let request = http
        .post(&format!(
            "{}{}",
            core.url,
            ace_sdk::wire::paths::task(task.id, "end")
        ))
        .bearer_auth(TOKEN)
        .header("x-ace4-worker", "checker")
        .json(&json!({"outcome": "no such end"}));
    let response = http.send(request).await.expect("an answer");
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(task_of(&core, root, "archive").await.0, "running");
}

/// A hostile file chooses how much text its result holds. One far past axum's usual 2 MB lands, so a
/// long macro can't lose its result, and one past the limit fails its task at once, saying why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_result_lands_and_one_past_the_limit_fails_its_task_at_once() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let client = LeaseClient::new(&core.url, TOKEN, "checker").expect("a client");
    for (name, size, state) in [("a.zip", 3 << 20, "done"), ("b.zip", 65 << 20, "failed")] {
        let (root, _, _) = core
            .root_with_file("file", "ace3/archive/test.zip", name)
            .await;
        let task = client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .expect("the archive task");
        let result =
            ace_results::ResultEnvelope::new(ace_results::types::archive::ArchiveAnalysis {
                file_count: 1,
                extracted_files: vec!["x".repeat(size)],
            })
            .to_raw()
            .expect("encodes");
        let sent = client
            .end(
                task.id,
                &TaskEnd::Done {
                    result,
                    writes: Vec::new(),
                },
            )
            .await;
        let (found, error) = task_of(&core, root, "archive").await;
        println!("{name}: {sent:?} {found} {error:?}");
        assert_eq!(found, state);
        if state == "failed" {
            assert!(matches!(sent, Err(ClientError::Api { status: 422, .. })));
            assert!(error.unwrap_or_default().contains("byte limit"));
        } else {
            assert!(sent.is_ok());
        }
    }
}

/// A module sees what its input redirects to: the YARA module needs it to sandbox the document a
/// part came out of (PLAN.md 3.1). It sees its input's relationships too, as the command line
/// module needs the host a command ran on (7.5 batch 3).
#[tokio::test]
async fn a_leased_task_says_what_its_observable_redirects_to_and_is_related_to() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let db = core.test_db.db();
    let root = NewRoot::new("analysis");
    let target = ObservableRef::new(ObservableKind::File, "aa".repeat(32));
    let mut part = NewObservable::new(ObservableKind::Fqdn, "part.example.com");
    part.redirection = Some(target.clone());
    let host = Relationship::new(
        RelationshipKind::ExecutedOn,
        ObservableRef::new(ObservableKind::Hostname, "WS-0042"),
    );
    part.relationships.push(host.clone());
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let id = tree::upsert_observable(&mut tx, root.id, &part)
        .await
        .expect("adds")
        .id;
    ace_core::queue::enqueue(&mut tx, root.id, id, "archive")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");

    let client = LeaseClient::new(&core.url, TOKEN, "checker").expect("a client");
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the task");
    assert_eq!(task.observable.redirection.as_ref(), Some(&target));
    assert_eq!(
        task.observable.to_observable(None).redirection,
        Some(target)
    );
    assert_eq!(task.observable.relationships, std::slice::from_ref(&host));
    let observable = task.observable.to_observable(None);
    assert_eq!(
        observable.relationship(RelationshipKind::ExecutedOn),
        Some(&host)
    );
}

/// Postgres refuses a NUL in text and in JSONB, and a module's output and errors can quote what a
/// hostile file holds. A task must still end, with the NUL replaced, not fail to land and wait out
/// its lease on every attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nul_from_a_hostile_file_doesnt_stop_a_task_ending() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let client = LeaseClient::new(&core.url, TOKEN, "checker").expect("a client");
    let db = core.test_db.db();

    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the task");
    let result = json!({
        "analysis_type": "archive_analysis",
        "schema_version": 1,
        "details": {"file_count": 1, "extracted_files": ["a\0b"]},
        "summary": "sum\0mary",
        "tags": ["ta\0g"],
        "observables": [{"type": "fqdn", "value": "evil\0.example.com"}],
    });
    client
        .end(
            task.id,
            &TaskEnd::Done {
                result: serde_json::from_value(result).expect("an envelope"),
                writes: Vec::new(),
            },
        )
        .await
        .expect("the result lands");
    let (extracted, summary, tag): (String, String, String) = sqlx::query_as(
        "SELECT details->'extracted_files'->>0, summary, tags[1] FROM analysis.results
         WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the result");
    assert_eq!(
        (extracted.as_str(), summary.as_str(), tag.as_str()),
        ("a\u{fffd}b", "sum\u{fffd}mary", "ta\u{fffd}g")
    );
    let observed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis.observables WHERE root_id = $1 AND value = $2",
    )
    .bind(root)
    .bind("evil\u{fffd}.example.com")
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(observed, 1);

    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/test.jar", "test.jar")
        .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the task");
    client
        .end(
            task.id,
            &TaskEnd::Failed {
                error: "couldn't read evil\0.exe".to_owned(),
            },
        )
        .await
        .expect("the failure lands");
    let (state, error) = task_of(&core, root, "archive").await;
    assert_eq!(state, "failed");
    assert_eq!(error.as_deref(), Some("couldn't read evil\u{fffd}.exe"));

    let (root, _, _) = core
        .root_with_file("file", "ace3/archive/evil.zip", "evil.zip")
        .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the task");
    client
        .end(
            task.id,
            &TaskEnd::Delay {
                after_seconds: 0.0,
                state: json!({"note\0": "st\0ate"}),
                scan: None,
            },
        )
        .await
        .expect("the delay lands");
    assert_eq!(task_of(&core, root, "archive").await.0, "delayed");
}
