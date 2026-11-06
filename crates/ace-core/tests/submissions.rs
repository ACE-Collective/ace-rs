//! PLAN.md 2.28's Done check: a submission through the lease API's submit endpoint creates a
//! root in its mode with its observables and files, each file is in the bucket held by the root,
//! and the root's first tasks are queued. A request without the submit token, or with a mode
//! that doesn't exist, writes nothing. The same server answers the stack's healthcheck (2.29).

use std::path::Path;
use std::time::Duration;

use ace_core::api::{Api, ApiConfig, PoolAccess};
use ace_core::bucket::{ALERT_FILES, Bucket, BucketSettings};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::submit::Submitted;
use ace_core::testing::TestDb;
use ace_results::Sha256;
use ace_store::{BucketConfig, NodeCache, Store};
use serde_json::{Value, json};
use sha2::Digest;

const SUBMIT_TOKEN: &str = "ace4-test-submit-token";
const POOL_TOKEN: &str = "ace4-test-pool-token";
const BOUNDARY: &str = "ace4-test-boundary-7f3a";

struct Server {
    test_db: TestDb,
    bucket: Bucket,
    url: String,
    task: tokio::task::JoinHandle<()>,
    _cache: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server() -> Server {
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    );
    let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
    let catalog = Catalog::new([
        ace_mod_email::MANIFEST,
        ace_mod_archive::MANIFEST,
        ace_mod_yara::MANIFEST,
        ace_mod_rdap::MANIFEST,
    ]);
    let config = ApiConfig::new(vec![PoolAccess::new(
        "parsers",
        POOL_TOKEN,
        vec!["email_analyzer".to_owned()],
    )])
    .submit_token(SUBMIT_TOKEN);
    let api = Api::new(
        test_db.db().clone(),
        bucket.clone(),
        Orchestrator::new(catalog, Modes::ace3()),
        config,
    )
    .await
    .expect("the API starts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let task = tokio::spawn(async move {
        if let Err(e) = ace_core::api::serve(listener, api, std::future::pending()).await {
            eprintln!("the API stopped: {e}");
        }
    });
    Server {
        test_db,
        bucket,
        url,
        task,
        _cache: cache,
    }
}

/// A multipart form with the `analysis` field and one `file` field per (name, bytes).
fn form(analysis: &Value, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"analysis\"\r\n\r\n{analysis}\r\n"
        )
        .as_bytes(),
    );
    for (name, bytes) in files {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; \
                 filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn post(server: &Server, token: &str, body: Vec<u8>) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/api/analysis/v1/submit", server.url))
        .bearer_auth(token)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("the request is answered")
}

async fn roots(server: &Server) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM analysis.roots")
        .fetch_one(server.test_db.db().pool())
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
    let server = server().await;
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
    let response = post(
        &server,
        SUBMIT_TOKEN,
        form(&analysis, &[("email.rfc822", &email)]),
    )
    .await;
    assert_eq!(response.status(), 201);
    let submitted: Submitted = response.json().await.expect("a body");

    let pool = server.test_db.db().pool();
    let (mode, description, event_time_source): (String, String, String) = sqlx::query_as(
        "SELECT analysis_mode, description, event_time_source::text FROM analysis.roots
         WHERE id = $1",
    )
    .bind(submitted.uuid)
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
        server
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
    assert_eq!(holds, [("root".to_owned(), submitted.uuid.to_string())]);
    let path: String = sqlx::query_scalar("SELECT path FROM analysis.files WHERE root_id = $1")
        .bind(submitted.uuid)
        .fetch_one(pool)
        .await
        .expect("the file's record");
    assert_eq!(path, "email.rfc822");

    // its tasks: the email mode's file modules on the file; RDAP isn't in the email mode
    let tasks: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT t.id, t.module, o.type, t.state::text FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.module",
    )
    .bind(submitted.uuid)
    .fetch_all(pool)
    .await
    .expect("the tasks");
    let described: Vec<(&str, &str, &str)> = tasks
        .iter()
        .map(|(_, m, t, s)| (m.as_str(), t.as_str(), s.as_str()))
        .collect();
    assert_eq!(
        described,
        [
            ("archive", "file", "queued"),
            ("email_analyzer", "file", "queued"),
            ("yara_scanner_v3_4", "file", "queued"),
        ]
    );
    let mut ids: Vec<i64> = tasks.iter().map(|(id, ..)| *id).collect();
    let mut queued = submitted.queued.clone();
    ids.sort_unstable();
    queued.sort_unstable();
    assert_eq!(queued, ids, "the answer lists the queued tasks");
    let observable: (String, Vec<String>) = sqlx::query_as(
        "SELECT value, tags FROM analysis.observables WHERE root_id = $1 AND type = 'fqdn'",
    )
    .bind(submitted.uuid)
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
    let server = server().await;
    let analysis = json!({
        "description": "x",
        "analysis_mode": "email",
        "file_yara_meta": {"a.zip": ["type=email.attachment"]},
    });
    let response = post(
        &server,
        SUBMIT_TOKEN,
        form(&analysis, &[("a.zip", b"zip"), ("b.txt", b"text")]),
    )
    .await;
    assert_eq!(response.status(), 201);
    let submitted: Submitted = response.json().await.expect("a body");
    let files: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT path, yara_meta FROM analysis.files WHERE root_id = $1 ORDER BY path",
    )
    .bind(submitted.uuid)
    .fetch_all(server.test_db.db().pool())
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
    let before = roots(&server).await;
    let not_submitted = json!({"description": "x", "file_yara_meta": {"c.zip": ["type=x"]}});
    let response = post(
        &server,
        SUBMIT_TOKEN,
        form(&not_submitted, &[("a.zip", b"zip")]),
    )
    .await;
    assert_eq!(response.status(), 400);
    let not_a_tag = json!({"description": "x", "file_yara_meta": {"a.zip": ["no equals"]}});
    let response = post(
        &server,
        SUBMIT_TOKEN,
        form(&not_a_tag, &[("a.zip", b"zip")]),
    )
    .await;
    assert_eq!(response.status(), 400);
    assert_eq!(roots(&server).await, before);
}

#[tokio::test]
async fn a_submission_without_the_submit_token_or_with_an_unknown_mode_writes_nothing() {
    let server = server().await;
    let analysis = json!({"description": "x", "analysis_mode": "email"});
    let body = || form(&analysis, &[("a.txt", b"hello")]);
    assert_eq!(post(&server, "wrong", body()).await.status(), 401);
    assert_eq!(
        post(&server, POOL_TOKEN, body()).await.status(),
        401,
        "a pool's token can't submit"
    );
    let unknown = json!({"description": "x", "analysis_mode": "no_such_mode"});
    let response = post(
        &server,
        SUBMIT_TOKEN,
        form(&unknown, &[("a.txt", b"hello")]),
    )
    .await;
    assert_eq!(response.status(), 400);
    let error: Value = response.json().await.expect("a body");
    assert_eq!(error["error"], "no analysis mode \"no_such_mode\"");
    let nul = json!({"description": "a\0b"});
    let response = post(&server, SUBMIT_TOKEN, form(&nul, &[("a.txt", b"hello")])).await;
    assert_eq!(response.status(), 400);
    let error: Value = response.json().await.expect("a body");
    assert_eq!(error["error"], "a submission can't hold a NUL character");
    let extra = json!({"description": "x", "colour": "red"});
    assert_eq!(
        post(&server, SUBMIT_TOKEN, form(&extra, &[]))
            .await
            .status(),
        400,
        "an unknown key is refused"
    );
    assert_eq!(roots(&server).await, 0);
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM store.objects")
        .fetch_one(server.test_db.db().pool())
        .await
        .expect("counts");
    assert_eq!(objects, 0);
}

#[tokio::test]
async fn a_submission_without_a_mode_gets_the_default_mode() {
    let server = server().await;
    let analysis = json!({
        "description": "just an fqdn",
        "observables": [{"type": "fqdn", "value": "example.com"}],
    });
    let response = post(&server, SUBMIT_TOKEN, form(&analysis, &[])).await;
    assert_eq!(response.status(), 201);
    let submitted: Submitted = response.json().await.expect("a body");
    let mode: String = sqlx::query_scalar("SELECT analysis_mode FROM analysis.roots WHERE id = $1")
        .bind(submitted.uuid)
        .fetch_one(server.test_db.db().pool())
        .await
        .expect("the root");
    assert_eq!(mode, "analysis");
    // RDAP runs on an fqdn in the analysis mode, which has the correlation group
    let tasks: Vec<String> =
        sqlx::query_scalar("SELECT module FROM queue.tasks WHERE root_id = $1")
            .bind(submitted.uuid)
            .fetch_all(server.test_db.db().pool())
            .await
            .expect("the tasks");
    assert_eq!(tasks, ["rdap_analyzer"]);
}

#[tokio::test]
async fn the_health_endpoint_answers_without_a_token() {
    let server = server().await;
    let response = reqwest::get(format!("{}/healthz", server.url))
        .await
        .expect("answers");
    assert_eq!(response.status(), 200);
}
