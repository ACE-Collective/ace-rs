//! PLAN.md 2.14's Done check: a worker with only an API token runs a task end to end. The
//! worker is the test pool binary, started with an empty environment plus the lease API's URL
//! and its pool's token, so it holds no database URL and no bucket key.

mod common;

use std::time::Duration;

use ace_core::bucket::ALERT_FILES;
use ace_results::Sha256;
use ace_store::Store;

use common::{Core, test_pool};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_with_only_an_api_token_runs_a_task_end_to_end() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, zip) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    assert_eq!(
        core.tasks(root).await,
        [("archive".to_owned(), zip.to_hex(), "queued".to_owned())]
    );

    let mut worker = test_pool(&core, &["once"]);
    let output = tokio::task::spawn_blocking(move || worker.output())
        .await
        .expect("joins")
        .expect("the worker runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(stdout.contains("(archive): done"), "{stdout}");

    let db = core.test_db.db();
    // the result is stored, and the file it extracted is in the tree, the bucket and the queue
    let result: (String, i32) = sqlx::query_as(
        "SELECT analysis_type, jsonb_array_length(details->'extracted_files')
         FROM analysis.results WHERE root_id = $1 AND module = 'archive'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("a result");
    assert_eq!(result, ("archive_analysis".to_owned(), 1));
    let (path, member): (String, String) = sqlx::query_as(
        "SELECT f.path, o.value FROM analysis.files f
         JOIN analysis.observables o ON o.id = f.observable_id
         WHERE f.root_id = $1 AND f.path <> 'test.zip'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the extracted file");
    assert_eq!(
        path,
        "test.zip.extracted/Faktura.FS.17.9.20_2018_2_13_AI02668779.pdf.js"
    );
    let member: Sha256 = member.parse().expect("a sha256");
    let object = core
        .bucket
        .object(ALERT_FILES, &member)
        .await
        .expect("reads")
        .expect("the member is in the bucket");
    assert_eq!(object.size, 23405);
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2",
    )
    .bind(ALERT_FILES)
    .bind(member.to_hex())
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(holds, [("root".to_owned(), root.to_string())]);
    // the upload is gone once the core checked it and moved it into the pool
    let uploads = core.bucket.store().list("uploads/").await.expect("lists");
    assert!(
        !uploads.iter().any(|key| key.ends_with(&member.to_hex())),
        "{uploads:?}"
    );
    assert_eq!(
        core.tasks(root).await,
        [
            ("archive".to_owned(), zip.to_hex(), "done".to_owned()),
            ("archive".to_owned(), member.to_hex(), "queued".to_owned()),
        ]
    );
    // tidy the shared bucket
    for sha in [zip, member] {
        core.bucket
            .store()
            .delete(ALERT_FILES, &sha)
            .await
            .expect("deletes");
    }
    assert!(Store::key(ALERT_FILES, &member).is_ok());
}

#[tokio::test]
async fn a_request_without_the_pools_token_is_refused() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, "not-the-token", "w").expect("a client");
    let refused = client.lease(&[], Duration::ZERO).await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 401, .. })
        ),
        "{refused:?}"
    );
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w").expect("a client");
    let other = client
        .lease(&["email_analyzer".to_owned()], Duration::ZERO)
        .await;
    assert!(
        matches!(
            &other,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{other:?}"
    );
    assert!(
        client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .is_none()
    );
}
