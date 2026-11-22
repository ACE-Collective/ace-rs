//! PLAN.md 2.28's Done check, from the core's side since 5.5: a submission creates a root in its mode
//! with its observables and files, each file is in the bucket held by the root, and the root's first
//! tasks are queued. One that names a mode that doesn't exist, or can't be stored, writes nothing.
//! The HTTP endpoint, its key and who is recorded are `ace-api`'s and `ace-service`'s tests. The
//! lease API's server answers the stack's healthcheck (2.29).

use std::path::Path;

use ace_core::api::{Api, ApiConfig, PoolAccess};
use ace_core::bucket::{ALERT_FILES, Bucket, BucketSettings};
use ace_core::db::Isolation;
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::submit::{self, Submission, SubmitError, SubmittedFile};
use ace_core::testing::TestDb;
use ace_results::{AlertPath, Sha256};
use ace_store::{BucketConfig, NodeCache, Store};
use serde_json::{Value, json};
use sha2::Digest;
use uuid::Uuid;

struct Stack {
    test_db: TestDb,
    bucket: Bucket,
    orchestrator: Orchestrator,
    _cache: tempfile::TempDir,
}

async fn stack() -> Stack {
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
    let catalog = Catalog::new([
        ace_mod_email::MANIFEST,
        ace_mod_archive::MANIFEST,
        ace_mod_yara::MANIFEST,
        ace_mod_rdap::MANIFEST,
    ]);
    Stack {
        test_db,
        bucket,
        orchestrator: Orchestrator::new(catalog, Modes::ace3()),
        _cache: cache,
    }
}

/// What `ace_service::Service::submit` does with the core, without the actor: parse the submission
/// as the endpoint does, spool the files, then prepare and create the root in one transaction.
async fn submit(
    stack: &Stack,
    analysis: &Value,
    files: &[(&str, &[u8])],
) -> Result<(Uuid, Vec<i64>), SubmitError> {
    let submission: Submission = serde_json::from_value(analysis.clone())
        .map_err(|e| SubmitError::Invalid(e.to_string()))?;
    let mut spooled = Vec::new();
    for (name, bytes) in files {
        spooled.push(SubmittedFile {
            path: AlertPath::new((*name).to_owned()).expect("a path"),
            spooled: stack
                .bucket
                .store()
                .spool_bytes(bytes)
                .await
                .expect("spools"),
        });
    }
    let root = submit::prepare(
        &stack.orchestrator,
        &submission,
        &submit::Origin::default(),
        &spooled,
    )?;
    let (root, submission, spooled) = (&root, &submission, &spooled);
    let queued = stack
        .test_db
        .db()
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                submit::create(
                    tx,
                    &stack.bucket,
                    &stack.orchestrator,
                    root,
                    submission,
                    &submit::Origin::default(),
                    spooled,
                    ace_core::tree::DirectivesFrom::submission("api_key:1"),
                )
                .await
            })
        })
        .await?;
    Ok((root.id, queued.into_iter().map(|id| id.0).collect()))
}

async fn roots(stack: &Stack) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM analysis.roots")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("counts")
}

fn sample(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples/ace3")
            .join(name),
    )
    .expect("the sample")
}

#[tokio::test]
async fn a_submitted_file_is_in_the_bucket_and_its_tasks_are_queued() {
    let stack = stack().await;
    let email = sample("email/pdf_attachment.email.rfc822");
    let sha256 = Sha256(sha2::Sha256::digest(&email).into());
    let analysis = json!({
        "description": "a test submission",
        "analysis_mode": "email",
        "event_time": "2026-11-01T12:00:00Z",
        "observables": [
            {"type": "fqdn", "value": "www.example.com", "tags": ["submitted"]},
        ],
    });
    let (root, queued) = submit(&stack, &analysis, &[("email.rfc822", &email)])
        .await
        .expect("submits");

    let pool = stack.test_db.db().pool();
    let (mode, description, event_time_source): (String, String, String) = sqlx::query_as(
        "SELECT analysis_mode, description, event_time_source::text FROM analysis.roots
         WHERE id = $1",
    )
    .bind(root)
    .fetch_one(pool)
    .await
    .expect("the root");
    assert_eq!(
        (
            mode.as_str(),
            description.as_str(),
            event_time_source.as_str()
        ),
        ("email", "a test submission", "event")
    );

    // the file: in the bucket, its row in alert_files held by the root, at its path
    assert!(
        stack
            .bucket
            .store()
            .exists(ALERT_FILES, &sha256)
            .await
            .expect("asks the bucket"),
        "the email's bytes are in the bucket"
    );
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2",
    )
    .bind(ALERT_FILES)
    .bind(sha256.to_hex())
    .fetch_all(pool)
    .await
    .expect("the holds");
    assert_eq!(holds, [("root".to_owned(), root.to_string())]);
    let path: String = sqlx::query_scalar("SELECT path FROM analysis.files WHERE root_id = $1")
        .bind(root)
        .fetch_one(pool)
        .await
        .expect("the file's record");
    assert_eq!(path, "email.rfc822");

    // its tasks: the email mode's file modules on the file that take it; RDAP isn't in the email
    // mode. The archive module declines a file of an email by its path, and the email module one
    // file_type hasn't called an email, and this catalog has no file_type (PLAN.md decision 23)
    let tasks: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT t.id, t.module, o.type, t.state::text FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.module",
    )
    .bind(root)
    .fetch_all(pool)
    .await
    .expect("the tasks");
    let described: Vec<(&str, &str, &str)> = tasks
        .iter()
        .map(|(_, m, t, s)| (m.as_str(), t.as_str(), s.as_str()))
        .collect();
    assert_eq!(described, [("yara_scanner_v3_4", "file", "queued")]);
    let mut ids: Vec<i64> = tasks.iter().map(|(id, ..)| *id).collect();
    let mut queued = queued;
    ids.sort_unstable();
    queued.sort_unstable();
    assert_eq!(queued, ids, "the answer lists the queued tasks");
    let observable: (String, Vec<String>) = sqlx::query_as(
        "SELECT value, tags FROM analysis.observables WHERE root_id = $1 AND type = 'fqdn'",
    )
    .bind(root)
    .fetch_one(pool)
    .await
    .expect("the fqdn");
    assert_eq!(
        observable,
        ("www.example.com".to_owned(), vec!["submitted".to_owned()])
    );
}

#[tokio::test]
async fn a_submission_can_say_what_its_files_are_for_yara() {
    let stack = stack().await;
    let analysis = json!({
        "description": "x",
        "analysis_mode": "email",
        "file_yara_meta": {"a.zip": ["type=email.attachment"]},
    });
    let (root, _) = submit(&stack, &analysis, &[("a.zip", b"zip"), ("b.txt", b"text")])
        .await
        .expect("submits");
    let files: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT path, yara_meta FROM analysis.files WHERE root_id = $1 ORDER BY path",
    )
    .bind(root)
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("the files");
    assert_eq!(
        files,
        [
            ("a.zip".to_owned(), vec!["type=email.attachment".to_owned()]),
            ("b.txt".to_owned(), vec![]),
        ]
    );

    // a path that wasn't submitted, or a tag that isn't one, writes nothing
    let before = roots(&stack).await;
    let not_submitted = json!({"description": "x", "file_yara_meta": {"c.zip": ["type=x"]}});
    let refused = submit(&stack, &not_submitted, &[("a.zip", b"zip")]).await;
    assert!(
        matches!(&refused, Err(SubmitError::Invalid(why)) if why.contains("c.zip")),
        "{refused:?}"
    );
    let not_a_tag = json!({"description": "x", "file_yara_meta": {"a.zip": ["no equals"]}});
    let refused = submit(&stack, &not_a_tag, &[("a.zip", b"zip")]).await;
    assert!(
        matches!(refused, Err(SubmitError::Invalid(_))),
        "{refused:?}"
    );
    assert_eq!(roots(&stack).await, before);
}

#[tokio::test]
async fn a_submission_with_an_unknown_mode_or_a_nul_writes_nothing() {
    let stack = stack().await;
    let unknown = json!({"description": "x", "analysis_mode": "no_such_mode"});
    let refused = submit(&stack, &unknown, &[("a.txt", b"hello")]).await;
    assert_eq!(
        refused.map_err(|e| e.to_string()),
        Err("no analysis mode \"no_such_mode\"".to_owned())
    );
    let nul = json!({"description": "a\0b"});
    let refused = submit(&stack, &nul, &[("a.txt", b"hello")]).await;
    assert_eq!(
        refused.map_err(|e| e.to_string()),
        Err("a submission can't hold a NUL character".to_owned())
    );
    let extra = json!({"description": "x", "colour": "red"});
    assert!(
        submit(&stack, &extra, &[]).await.is_err(),
        "an unknown key is refused"
    );
    assert_eq!(roots(&stack).await, 0);
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM store.objects")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("counts");
    assert_eq!(objects, 0);
}

#[tokio::test]
async fn a_submission_without_a_mode_gets_the_default_mode() {
    let stack = stack().await;
    let analysis = json!({
        "description": "just an fqdn",
        "observables": [{"type": "fqdn", "value": "example.com"}],
    });
    let (root, _) = submit(&stack, &analysis, &[]).await.expect("submits");
    let mode: String = sqlx::query_scalar("SELECT analysis_mode FROM analysis.roots WHERE id = $1")
        .bind(root)
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("the root");
    assert_eq!(mode, "analysis");
    // RDAP runs on an fqdn in the analysis mode, which has the correlation group
    let tasks: Vec<String> =
        sqlx::query_scalar("SELECT module FROM queue.tasks WHERE root_id = $1")
            .bind(root)
            .fetch_all(stack.test_db.db().pool())
            .await
            .expect("the tasks");
    assert_eq!(tasks, ["rdap_analyzer"]);
}

#[tokio::test]
async fn the_health_endpoint_answers_without_a_token() {
    let stack = stack().await;
    let api = Api::new(
        stack.test_db.db().clone(),
        stack.bucket.clone(),
        stack.orchestrator.clone(),
        ApiConfig::new(vec![PoolAccess::new("parsers", "a-token", Vec::new())]),
    )
    .await
    .expect("the API starts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let server = tokio::spawn(ace_core::api::serve(listener, api, std::future::pending()));
    let response = reqwest::get(format!("{url}/healthz"))
        .await
        .expect("answers");
    assert_eq!(response.status(), 200);
    let gone = reqwest::Client::new()
        .post(format!("{url}/api/analysis/v1/submit"))
        .send()
        .await
        .expect("answers");
    assert_eq!(
        gone.status(),
        404,
        "submissions are ace-api's, on its own listener"
    );
    server.abort();
}

/// PLAN.md decision 32 part (b): a root's pivot links, such as a hunt's, come with its origin and are
/// stored on it; a submission whose origin holds a link ace4 can't show (not `https://`, an icon that
/// isn't a name, past the bound) is refused and writes nothing. A result's links land with it.
#[tokio::test]
async fn a_root_and_a_result_keep_their_pivot_links() {
    let stack = stack().await;
    let submission: Submission =
        serde_json::from_value(json!({"description": "linked", "analysis_mode": "analysis"}))
            .expect("a submission");
    let link = ace_results::PivotLink::new("https://hunt.example.com/search?q=1", "Search")
        .with_icon("splunk");
    let origin = submit::Origin {
        pivot_links: vec![link.clone()],
        ..submit::Origin::default()
    };
    for (bad, why) in [
        (
            ace_results::PivotLink::new("http://hunt.example.com/", "Plain"),
            "https",
        ),
        (link.clone().with_icon("data:image/png;base64,AAAA"), "icon"),
    ] {
        let refused = submit::prepare(
            &stack.orchestrator,
            &submission,
            &submit::Origin {
                pivot_links: vec![bad],
                ..submit::Origin::default()
            },
            &[],
        );
        assert!(
            matches!(&refused, Err(SubmitError::Invalid(e)) if e.contains("pivot link")),
            "{why}: {refused:?}"
        );
    }
    let many = submit::Origin {
        pivot_links: vec![link.clone(); ace_results::MAX_PIVOT_LINKS + 1],
        ..submit::Origin::default()
    };
    assert!(submit::prepare(&stack.orchestrator, &submission, &many, &[]).is_err());
    let root = submit::prepare(&stack.orchestrator, &submission, &origin, &[]).expect("prepares");
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    submit::create(
        &mut tx,
        &stack.bucket,
        &stack.orchestrator,
        &root,
        &submission,
        &origin,
        &[],
        ace_core::tree::DirectivesFrom::hunt("a hunt"),
    )
    .await
    .expect("creates");
    let fqdn = ace_core::tree::upsert_observable(
        &mut tx,
        root.id,
        &ace_results::NewObservable::new(ace_results::ObservableKind::Fqdn, "example.com"),
    )
    .await
    .expect("adds");
    let result: ace_results::ResultEnvelope<Value> = serde_json::from_value(json!({
        "analysis_type": "example_line_stats", "schema_version": 1, "details": {},
        "pivot_links": [{"url": "https://rdap.example.com/d/1", "text": "RDAP"}],
    }))
    .expect("a result");
    ace_core::tree::insert_result(&mut tx, root.id, fqdn.id, "rdap_analyzer", &result)
        .await
        .expect("stores");
    tx.commit().await.expect("commits");
    let stored: Value = sqlx::query_scalar("SELECT pivot_links FROM analysis.roots WHERE id = $1")
        .bind(root.id)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(
        stored,
        json!([{"url": "https://hunt.example.com/search?q=1", "text": "Search", "icon": "splunk"}])
    );
    let stored: Value =
        sqlx::query_scalar("SELECT pivot_links FROM analysis.results WHERE root_id = $1")
            .bind(root.id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        stored,
        json!([{"url": "https://rdap.example.com/d/1", "text": "RDAP"}])
    );
}
