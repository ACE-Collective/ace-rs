//! PLAN.md 2.15's Done check: an invalid result is rejected with the field's path and nothing
//! from it is written. The worker here is this test, through the lease API's client.

mod common;

use std::time::Duration;

use ace_pool::client::{ClientError, LeaseClient};
use ace_sdk::wire::TaskEnd;
use serde_json::json;
use uuid::Uuid;

use common::{Core, TOKEN};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_result_is_rejected_with_its_fields_path_and_nothing_is_written() {
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
    let refused = client
        .end(
            task.id,
            &TaskEnd::Done {
                result: serde_json::from_value(invalid).expect("an envelope"),
            },
        )
        .await;
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

    // a result of another module's type is refused too
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
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(ClientError::Api { status: 422, error })
            if error.error.contains("archive writes archive_analysis")),
        "{refused:?}"
    );
    // and so is a result naming a file that was never uploaded, before anything is written
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
            },
        )
        .await;
    assert!(
        matches!(&refused, Err(ClientError::Api { status: 400, .. })),
        "{refused:?}"
    );
    assert_eq!(written(&core, root).await, before, "still nothing written");

    // the task is still the worker's, and a valid result lands
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
