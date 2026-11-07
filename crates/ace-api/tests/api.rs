//! PLAN.md 5.5's Done check: the alerts, analysis and observables endpoints have tests and are in the
//! OpenAPI document. `every_documented_status_is_tested` drives each endpoint through every status its
//! document lists, records what it saw, and fails when the two differ, so a new endpoint or status needs
//! its test. Every endpoint is also refused without a credential (401) and without its permission (403),
//! from the document's own list of routes. The committed `openapi.json` must be what utoipa derives.
//!
//! The server runs on a test database and the stack's bucket, over TCP, so a request has a peer address
//! as it does in `ace serve`. This crate can't depend on an ace-mod-* crate, so its modules are stubs.

use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::submit::{Submission, SubmittedObservable};
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot};
use ace_results::{AnalysisType, NewObservable, ObservableKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{
    Actor, Component, Effect, Holder, Password, PermissionPattern, Service, Username,
};
use ace_store::{BucketConfig, NodeCache, Store};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
struct StubOutput {
    note: String,
}

impl AnalysisType for StubOutput {
    const NAME: &'static str = "test_stub";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "rdap_analyzer";
}

/// Named for one of ace3's modules, so ace3's modes choose it.
struct Rdap;

impl Module for Rdap {
    const NAME: &'static str = "rdap_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = StubOutput;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(Rdap)
    }
}

impl Lookup for Rdap {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
        Ok(Outcome::Skipped("a stub".to_owned()))
    }
}

const BOUNDARY: &str = "ace4-api-test-boundary";
const PASSWORD: &str = "correct horse battery staple";
/// Small, so the limits are cheap to cross.
const MAX_JSON: usize = 64 << 10;
const MAX_SUBMISSION: usize = 1 << 20;

struct Stack {
    test_db: TestDb,
    service: Service,
    url: String,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
    _cache: tempfile::TempDir,
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn stack() -> Stack {
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    );
    let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
    let orchestrator = Orchestrator::new(
        Catalog::new(vec![Manifest::lookup::<Rdap>()]),
        Modes::ace3(),
    );
    let service = Service::new(test_db.db().clone(), orchestrator);
    let config = ace_api::WebConfig {
        max_json_bytes: MAX_JSON,
        max_submission_bytes: MAX_SUBMISSION,
        max_submitted_files: 3,
        ..ace_api::WebConfig::default()
    };
    let router = ace_api::Web::new(service.clone(), bucket, config).router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let task = tokio::spawn(async move {
        if let Err(e) = ace_api::serve(listener, router, std::future::pending()).await {
            eprintln!("the API stopped: {e}");
        }
    });
    Stack {
        test_db,
        service,
        url,
        http: reqwest::Client::new(),
        task,
        _cache: cache,
    }
}

fn bootstrap() -> Actor {
    Actor::Internal {
        id: Component::new("bootstrap").expect("a valid name"),
    }
}

/// A key with no owner holding these grants, as `ace user create-key` makes one.
async fn key(stack: &Stack, grants: &[&str]) -> String {
    let made = stack
        .service
        .create_api_key(&bootstrap(), "test", None)
        .await
        .expect("makes a key");
    for grant in grants {
        let (major, minor) = grant.split_once(':').expect("major:minor");
        stack
            .service
            .grant(
                &bootstrap(),
                &Holder::ApiKey(made.id),
                &PermissionPattern::new(major, minor).expect("a pattern"),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
    made.token.expose().to_owned()
}

/// A root a detection made an alert, with these observables. Each gets a later alerted time.
async fn alert(stack: &Stack, title: &str, observables: &[(ObservableKind, &str)]) -> Uuid {
    let root = NewRoot {
        description: title.to_owned(),
        ..NewRoot::new("correlation")
    };
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    for (kind, value) in observables {
        tree::upsert_observable(&mut tx, root.id, &NewObservable::new(*kind, *value))
            .await
            .expect("adds");
    }
    tx.commit().await.expect("commits");
    alerted(stack, root.id).await;
    root.id
}

async fn alerted(stack: &Stack, root: Uuid) {
    sqlx::query("UPDATE analysis.roots SET alerted_at = clock_timestamp() WHERE id = $1")
        .bind(root)
        .execute(stack.test_db.db().pool())
        .await
        .expect("makes it an alert");
}

/// A multipart form with the `analysis` field and one `file` field per (name, bytes).
fn form(analysis: &Value, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"analysis\"\r\n\r\n{analysis}\r\n"
    )
    .into_bytes();
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

/// What a request sends.
enum Send {
    Nothing,
    Json(Value),
    Bytes(Vec<u8>),
    Form(Vec<u8>),
}

/// A client that records each (method, route, status) it sees.
struct Client<'s> {
    stack: &'s Stack,
    seen: BTreeSet<(String, String, u16)>,
}

impl<'s> Client<'s> {
    fn new(stack: &'s Stack) -> Self {
        Client {
            stack,
            seen: BTreeSet::new(),
        }
    }

    /// Calls `route` with its `{...}` filled from `path`, with `token` as the bearer if there is one.
    async fn call(
        &mut self,
        method: Method,
        route: &str,
        path: &str,
        token: Option<&str>,
        send: Send,
    ) -> reqwest::Response {
        let mut request = self
            .stack
            .http
            .request(method.clone(), format!("{}{path}", self.stack.url));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request = match send {
            Send::Nothing => request,
            Send::Json(value) => request.json(&value),
            Send::Bytes(bytes) => request
                .header("content-type", "application/json")
                .body(bytes),
            Send::Form(body) => request
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(body),
        };
        let response = request.send().await.expect("answered");
        self.seen.insert((
            method.as_str().to_lowercase(),
            route.to_owned(),
            response.status().as_u16(),
        ));
        response
    }

    async fn json(
        &mut self,
        method: Method,
        route: &str,
        path: &str,
        token: Option<&str>,
        send: Send,
        status: StatusCode,
    ) -> Value {
        let response = self.call(method, route, path, token, send).await;
        let got = response.status();
        let text = response.text().await.expect("a body");
        assert_eq!(got, status, "{route}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{route}: {e}: {text}"))
    }
}

/// The document's (method, route, status) for every operation.
fn documented() -> BTreeSet<(String, String, u16)> {
    let document: Value = serde_json::from_str(&ace_api::openapi_json()).expect("JSON");
    let mut found = BTreeSet::new();
    for (route, item) in document["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("an item") {
            for status in operation["responses"]
                .as_object()
                .expect("responses")
                .keys()
            {
                found.insert((
                    method.clone(),
                    route.clone(),
                    status.parse().expect("a status"),
                ));
            }
        }
    }
    found
}

const LIST: &str = "/api/alerts/v1/alerts";
const ONE: &str = "/api/alerts/v1/alerts/{id}";
const OBSERVABLES: &str = "/api/alerts/v1/alerts/{id}/observables";
const FILE: &str = "/api/alerts/v1/alerts/{id}/observables/{observable}/file";
const DISPOSITION: &str = "/api/alerts/v1/alerts/{id}/disposition";
const SUBMIT: &str = "/api/analysis/v1/submit";
const LOOKUP: &str = "/api/observables/v1/lookup";

fn fill(route: &str, id: Uuid, observable: i64) -> String {
    route
        .replace("{id}", &id.to_string())
        .replace("{observable}", &observable.to_string())
}

/// A body each route would take, so a 401 or 403 is about the credential and nothing else.
fn good_body(route: &str) -> Send {
    match route {
        DISPOSITION => Send::Json(json!({"disposition": "FALSE_POSITIVE"})),
        SUBMIT => Send::Form(form(&json!({"description": "x"}), &[])),
        LOOKUP => Send::Json(json!({"observables": [{"type": "fqdn", "value": "a.example"}]})),
        _ => Send::Nothing,
    }
}

/// Every route in the document refuses a request with no credential, a wrong one or one in another
/// scheme, and a key holding nothing, and writes nothing for any of them.
async fn refuses_without_a_credential_or_a_permission(
    client: &mut Client<'_>,
    id: Uuid,
    file: i64,
) {
    let nothing = key(client.stack, &[]).await;
    let before = audit_count(client.stack).await;
    let roots = root_count(client.stack).await;
    let routes: BTreeSet<(String, String)> = documented()
        .into_iter()
        .map(|(method, route, _)| (method, route))
        .collect();
    assert_eq!(routes.len(), 7, "{routes:?}");
    for (method, route) in routes {
        let method: Method = method.to_uppercase().parse().expect("a method");
        let path = fill(&route, id, file);
        let response = client
            .call(method.clone(), &route, &path, None, good_body(&route))
            .await;
        assert_eq!(response.status(), 401, "{route} without a credential");
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer",
            "{route} says how to authenticate"
        );
        let body: Value = response.json().await.expect("an error body");
        assert_eq!(body, json!({"error": "not authenticated"}));
        for wrong in ["ace4k_00000000-0000-0000-0000-000000000000_x", "x"] {
            let response = client
                .call(
                    method.clone(),
                    &route,
                    &path,
                    Some(wrong),
                    good_body(&route),
                )
                .await;
            assert_eq!(response.status(), 401, "{route} with {wrong}");
        }
        let response = client
            .stack
            .http
            .request(method.clone(), format!("{}{path}", client.stack.url))
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), 401, "{route} with basic auth");
        let response = client
            .call(
                method.clone(),
                &route,
                &path,
                Some(&nothing),
                good_body(&route),
            )
            .await;
        assert_eq!(response.status(), 403, "{route} with a key holding nothing");
        let body: Value = response.json().await.expect("an error body");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("this needs ")),
            "{route}: {body}"
        );
    }
    assert_eq!(
        audit_count(client.stack).await,
        before,
        "no refusal has a row"
    );
    assert_eq!(
        root_count(client.stack).await,
        roots,
        "no refusal submitted"
    );
}

async fn audit_count(stack: &Stack) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM service.audit")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("counts")
}

async fn root_count(stack: &Stack) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM analysis.roots")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("counts")
}

/// The id of the file observable a submission made, after making its root an alert.
async fn submitted_file(client: &mut Client<'_>, token: &str, bytes: &[u8]) -> (Uuid, i64) {
    let analysis = json!({
        "description": "a file to download",
        "analysis_mode": "correlation",
        "observables": [{"type": "fqdn", "value": "evil.example.com"}],
    });
    let submitted = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(form(&analysis, &[("mail/invoice.zip", bytes)])),
            StatusCode::CREATED,
        )
        .await;
    let root: Uuid = submitted["id"]
        .as_str()
        .expect("an id")
        .parse()
        .expect("a uuid");
    alerted(client.stack, root).await;
    let observable: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'file'",
    )
    .bind(root)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the file");
    (root, observable)
}

async fn submits(client: &mut Client<'_>, token: &str) {
    let analysis = json!({
        "description": "a submission",
        "analysis_mode": "analysis",
        "event_time": "2026-11-01T12:00:00Z",
        "observables": [{"type": "fqdn", "value": "www.example.com", "tags": ["submitted"]}],
        "file_yara_meta": {"a.zip": ["type=email.attachment"]},
    });
    let submitted = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(form(&analysis, &[("a.zip", b"zip bytes")])),
            StatusCode::CREATED,
        )
        .await;
    let root: Uuid = submitted["id"]
        .as_str()
        .expect("an id")
        .parse()
        .expect("a uuid");
    let (mode, by): (String, Value) = sqlx::query_as(
        "SELECT analysis_mode, submitted_by::jsonb FROM analysis.roots WHERE id = $1",
    )
    .bind(root)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the root");
    assert_eq!(mode, "analysis");
    assert_eq!(
        by["kind"], "api_key",
        "the root records the key that submitted it"
    );
    assert_eq!(
        submitted["queued"].as_array().map(Vec::len),
        Some(1),
        "the stub RDAP on the fqdn: {submitted}"
    );
    let (action, src_ip): (String, Option<String>) =
        sqlx::query_as("SELECT action, host(src_ip) FROM service.audit WHERE target_id = $1::text")
            .bind(root)
            .fetch_one(client.stack.test_db.db().pool())
            .await
            .expect("its row");
    assert_eq!(
        (action.as_str(), src_ip.as_deref()),
        ("submit", Some("127.0.0.1")),
        "the row records the request's peer"
    );

    // what can't be taken writes nothing
    let roots = root_count(client.stack).await;
    for (analysis, files, why) in [
        (
            json!({"description": "x", "analysis_mode": "no_such_mode"}),
            vec![],
            "no analysis mode \"no_such_mode\"",
        ),
        (
            json!({"description": "x", "colour": "red"}),
            vec![],
            "unknown field `colour`",
        ),
        (
            json!({"description": "x", "file_yara_meta": {"c.zip": ["type=x"]}}),
            vec![("a.zip", &b"z"[..])],
            "isn't a submitted file",
        ),
        (json!({"description": "a\u{0}b"}), vec![], "NUL"),
        (
            json!({"description": "x"}),
            vec![("../escape", &b"z"[..])],
            "file name",
        ),
        (
            json!({"description": "x"}),
            vec![("a", &b"1"[..]), ("b", b"2"), ("c", b"3"), ("d", b"4")],
            "at most 3 files",
        ),
    ] {
        let error = client
            .json(
                Method::POST,
                SUBMIT,
                SUBMIT,
                Some(token),
                Send::Form(form(&analysis, &files)),
                StatusCode::BAD_REQUEST,
            )
            .await;
        assert!(
            error["error"].as_str().is_some_and(|e| e.contains(why)),
            "{why}: {error}"
        );
    }
    let error = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(b"not a form".to_vec()),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert!(error["error"].as_str().is_some(), "{error}");
    let no_analysis = format!("--{BOUNDARY}--\r\n").into_bytes();
    let error = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(no_analysis),
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert_eq!(error["error"], "no analysis field");

    // a form past its limit, in a file and in the analysis field
    let big = vec![b'a'; MAX_SUBMISSION + 1];
    let error = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(form(&json!({"description": "x"}), &[("big", &big)])),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
    assert_eq!(error["error"], "the form is too large");
    let long = json!({"description": "x".repeat(MAX_JSON)});
    let error = client
        .json(
            Method::POST,
            SUBMIT,
            SUBMIT,
            Some(token),
            Send::Form(form(&long, &[])),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|e| e.contains("analysis field")),
        "{error}"
    );
    assert_eq!(root_count(client.stack).await, roots);
}

async fn lists(client: &mut Client<'_>, token: &str) {
    let first = alert(client.stack, "first", &[]).await;
    let second = alert(client.stack, "second", &[]).await;
    let page = client
        .json(
            Method::GET,
            LIST,
            &format!("{LIST}?limit=1"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let ids: Vec<&str> = page["alerts"]
        .as_array()
        .expect("alerts")
        .iter()
        .map(|a| a["id"].as_str().expect("an id"))
        .collect();
    assert_eq!(ids.len(), 1);
    assert_ne!(ids[0], first.to_string(), "newest first");
    assert!(page["next"].is_string());
    for bad in [
        format!("{LIST}?limit=0"),
        format!("{LIST}?limit=1001"),
        format!("{LIST}?after=not-a-uuid"),
        format!("{LIST}?after={}", Uuid::nil()),
    ] {
        client
            .json(
                Method::GET,
                LIST,
                &bad,
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    let page = client
        .json(
            Method::GET,
            LIST,
            &format!("{LIST}?after={second}"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert!(
        page["alerts"]
            .as_array()
            .expect("alerts")
            .iter()
            .any(|a| a["id"] == first.to_string())
    );
}

async fn reads_one(client: &mut Client<'_>, token: &str, id: Uuid) {
    let one = client
        .json(
            Method::GET,
            ONE,
            &fill(ONE, id, 0),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(one["alert"]["id"], id.to_string());
    assert_eq!(one["alert"]["title"], "a file to download");
    assert_eq!(one["alert"]["submitted_by"]["kind"], "api_key");
    assert_eq!(
        (one["observables"].as_i64(), one["files"].as_i64()),
        (Some(2), Some(1))
    );
    client
        .json(
            Method::GET,
            ONE,
            "/api/alerts/v1/alerts/x",
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    let missing = client
        .json(
            Method::GET,
            ONE,
            &fill(ONE, Uuid::nil(), 0),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    assert_eq!(missing["error"], format!("no alert {}", Uuid::nil()));
}

async fn reads_observables(client: &mut Client<'_>, token: &str, id: Uuid, file: i64) {
    let db = client.stack.test_db.db().pool();
    let fqdn: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'fqdn'",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("the fqdn");
    let result: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary)
         VALUES ($1, $2, 'rdap_analyzer', 'test_stub', 1, '{\"note\": \"found\"}', 'a summary') RETURNING id",
    )
    .bind(id).bind(fqdn).fetch_one(db).await.expect("a result");
    sqlx::query("INSERT INTO analysis.detections (root_id, observable_id, result_id, description) VALUES ($1, $2, $3, 'bad')")
        .bind(id).bind(fqdn).bind(result).execute(db).await.expect("a detection");

    let page = client
        .json(
            Method::GET,
            OBSERVABLES,
            &format!("{}?limit=1", fill(OBSERVABLES, id, 0)),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let observables = page["observables"].as_array().expect("observables");
    assert_eq!(observables.len(), 1);
    assert_eq!(observables[0]["id"], fqdn, "in the order they were added");
    assert_eq!(
        observables[0]["results"][0]["details"],
        json!({"note": "found"})
    );
    assert_eq!(observables[0]["results"][0]["summary"], "a summary");
    assert_eq!(
        observables[0]["detections"][0],
        json!({"description": "bad", "details": null, "module": "rdap_analyzer"})
    );
    assert_eq!(page["next"], fqdn);
    let rest = client
        .json(
            Method::GET,
            OBSERVABLES,
            &format!("{}?after={fqdn}", fill(OBSERVABLES, id, 0)),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(rest["observables"][0]["id"], file);
    assert_eq!(
        rest["observables"][0]["files"][0]["path"],
        "mail/invoice.zip"
    );
    assert_eq!(rest["next"], Value::Null);
    for bad in ["?limit=501", "?limit=0", "?after=x"] {
        client
            .json(
                Method::GET,
                OBSERVABLES,
                &format!("{}{bad}", fill(OBSERVABLES, id, 0)),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            Method::GET,
            OBSERVABLES,
            &fill(OBSERVABLES, Uuid::nil(), 0),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    // a root no detection made an alert isn't one
    let root = NewRoot::new("analysis");
    let mut tx = client.stack.test_db.db().begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    client
        .json(
            Method::GET,
            OBSERVABLES,
            &fill(OBSERVABLES, root.id, 0),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    client
        .json(
            Method::GET,
            ONE,
            &fill(ONE, root.id, 0),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
}

async fn downloads(client: &mut Client<'_>, token: &str, id: Uuid, file: i64, bytes: &[u8]) {
    let response = client
        .call(
            Method::GET,
            FILE,
            &fill(FILE, id, file),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/zip");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let zipped = response.bytes().await.expect("the zip");
    let mut archive = zip::ZipArchive::new(Cursor::new(zipped.to_vec())).expect("a zip");
    assert!(archive.by_index(0).is_err(), "it needs the password");
    let mut entry = archive
        .by_index_decrypt(0, b"infected")
        .expect("opens with ace3's password");
    assert_eq!(entry.name().expect("a name"), "invoice.zip");
    let mut unzipped = Vec::new();
    entry.read_to_end(&mut unzipped).expect("reads");
    assert_eq!(unzipped, bytes);

    let (action, target, details, src_ip): (String, String, Value, Option<String>) = sqlx::query_as(
        "SELECT action, target_id, details, host(src_ip) FROM service.audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the download's row");
    assert_eq!(action, "download_file");
    assert_eq!(target, format!("{id}/{file}"));
    assert_eq!(details["path"], "mail/invoice.zip");
    assert_eq!(src_ip.as_deref(), Some("127.0.0.1"));

    let fqdn: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'fqdn'",
    )
    .bind(id)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the fqdn");
    let error = client
        .json(
            Method::GET,
            FILE,
            &fill(FILE, id, fqdn),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert_eq!(error["error"], format!("observable {fqdn} isn't a file"));
    client
        .json(
            Method::GET,
            FILE,
            &format!("/api/alerts/v1/alerts/{id}/observables/x/file"),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    client
        .json(
            Method::GET,
            FILE,
            &fill(FILE, id, file + 1000),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    client
        .json(
            Method::GET,
            FILE,
            &fill(FILE, Uuid::nil(), file),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
}

async fn dispositions(client: &mut Client<'_>, token: &str) {
    let id = alert(
        client.stack,
        "to disposition",
        &[(ObservableKind::Fqdn, "a.example")],
    )
    .await;
    let done = client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, id, 0),
            Some(token),
            Send::Json(json!({"disposition": "FALSE_POSITIVE"})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(done, json!({"cancelled": 0, "stopped": 0, "queued": 0}));
    let (disposition, by): (String, Value) = sqlx::query_as(
        "SELECT disposition, dispositioned_by::jsonb FROM analysis.roots WHERE id = $1",
    )
    .bind(id)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the root");
    assert_eq!(disposition, "FALSE_POSITIVE");
    assert_eq!(by["kind"], "api_key");
    for bad in [
        json!({"disposition": "false positive"}),
        json!({"disposition": ""}),
        json!({"verdict": "IGNORE"}),
        json!([]),
    ] {
        client
            .json(
                Method::PUT,
                DISPOSITION,
                &fill(DISPOSITION, id, 0),
                Some(token),
                Send::Json(bad),
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, id, 0),
            Some(token),
            Send::Bytes(b"{".to_vec()),
            StatusCode::BAD_REQUEST,
        )
        .await;
    client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, Uuid::nil(), 0),
            Some(token),
            Send::Json(json!({"disposition": "IGNORE"})),
            StatusCode::NOT_FOUND,
        )
        .await;
    let big = format!("{{\"disposition\": \"{}\"}}", "A".repeat(MAX_JSON));
    client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, id, 0),
            Some(token),
            Send::Bytes(big.into_bytes()),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
}

async fn looks_up(client: &mut Client<'_>, token: &str, file_alert: Uuid, file_bytes: &[u8]) {
    let one = alert(
        client.stack,
        "one",
        &[(ObservableKind::Fqdn, "seen.example")],
    )
    .await;
    let two = alert(
        client.stack,
        "two",
        &[(ObservableKind::Fqdn, "seen.example")],
    )
    .await;
    sqlx::query("UPDATE analysis.roots SET disposition = 'FALSE_POSITIVE', dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}' WHERE id = $1")
        .bind(one).execute(client.stack.test_db.db().pool()).await.expect("dispositions");
    let sha256 = sha256_hex(file_bytes).to_uppercase();
    let found = client
        .json(
            Method::POST,
            LOOKUP,
            LOOKUP,
            Some(token),
            Send::Json(json!({
                "observables": [
                    {"type": "fqdn", "value": "seen.example"},
                    {"type": "no_such_type", "value": "x"},
                    {"type": "fqdn", "value": "never.example"},
                    {"type": "file", "value": sha256},
                ],
                "recent_alerts": 1,
            })),
            StatusCode::OK,
        )
        .await;
    let results = found["results"].as_array().expect("results");
    assert_eq!(results[0]["alerts"], 2);
    assert_eq!(
        results[0]["dispositions"],
        json!({"FALSE_POSITIVE": 1, "OPEN": 1})
    );
    assert_eq!(results[0]["recent"].as_array().map(Vec::len), Some(1));
    assert_eq!(results[0]["recent"][0]["id"], two.to_string(), "the newest");
    assert!(
        results[1]["error"].is_string() && results[1]["value"].is_null(),
        "{}",
        results[1]
    );
    assert_eq!(
        (results[2]["alerts"].as_i64(), results[2]["error"].is_null()),
        (Some(0), true)
    );
    assert_eq!(
        results[3]["value"],
        sha256.to_lowercase(),
        "a file's hash is matched lowercased"
    );
    assert_eq!(results[3]["recent"][0]["id"], file_alert.to_string());
    let left_out = client
        .json(
            Method::POST,
            LOOKUP,
            LOOKUP,
            Some(token),
            Send::Json(json!({
                "observables": [{"type": "fqdn", "value": "seen.example"}],
                "exclude_alerts": [two],
            })),
            StatusCode::OK,
        )
        .await;
    assert_eq!(left_out["results"][0]["alerts"], 1);

    let many: Vec<Value> = (0..1001)
        .map(|i| json!({"type": "fqdn", "value": format!("{i}.example")}))
        .collect();
    for bad in [
        json!({"observables": []}),
        json!({"observables": many}),
        json!({"observables": [{"type": "fqdn", "value": "a"}], "recent_alerts": 21}),
        json!({"observables": [{"type": "fqdn"}]}),
    ] {
        client
            .json(
                Method::POST,
                LOOKUP,
                LOOKUP,
                Some(token),
                Send::Json(bad),
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    let big = format!(
        "{{\"observables\": [{{\"type\": \"fqdn\", \"value\": \"{}\"}}]}}",
        "a".repeat(MAX_JSON)
    );
    client
        .json(
            Method::POST,
            LOOKUP,
            LOOKUP,
            Some(token),
            Send::Bytes(big.into_bytes()),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The Done check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_documented_status_is_tested() {
    let stack = stack().await;
    let mut client = Client::new(&stack);
    let token = key(
        &stack,
        &[
            "alert:read",
            "alert:write",
            "alert:create",
            "observable:read",
        ],
    )
    .await;
    let bytes = b"PK\x03\x04 not really a zip, but a file".to_vec();
    let (id, file) = submitted_file(&mut client, &token, &bytes).await;

    refuses_without_a_credential_or_a_permission(&mut client, id, file).await;
    submits(&mut client, &token).await;
    lists(&mut client, &token).await;
    reads_one(&mut client, &token, id).await;
    reads_observables(&mut client, &token, id, file).await;
    downloads(&mut client, &token, id, file, &bytes).await;
    dispositions(&mut client, &token).await;
    looks_up(&mut client, &token, id, &bytes).await;

    assert_eq!(
        client.seen,
        documented(),
        "each status the document lists, and only those, was seen"
    );
}

/// `openapi.json` is what utoipa derives. `ACE4_WRITE_OPENAPI=1 cargo test -p ace-api` writes it.
#[tokio::test]
async fn the_committed_document_is_current() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("openapi.json");
    let derived = ace_api::openapi_json();
    if std::env::var_os("ACE4_WRITE_OPENAPI").is_some() {
        std::fs::write(&path, &derived).expect("writes the document");
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == derived,
        "{} isn't what the code derives: run `ACE4_WRITE_OPENAPI=1 cargo test -p ace-api` and commit it",
        path.display()
    );

    // and the server serves it, with no credential
    let stack = stack().await;
    let served = stack
        .http
        .get(format!("{}/api/openapi.json", stack.url))
        .send()
        .await
        .expect("answered");
    assert_eq!(served.status(), 200);
    assert_eq!(served.text().await.expect("a body"), derived);
}

/// The document's submission is the core's: the same fields, so a client the document guides sends
/// what the core reads.
#[test]
fn the_documented_submission_is_the_core_s() {
    let document: Value = serde_json::from_str(&ace_api::openapi_json()).expect("JSON");
    let schemas = &document["components"]["schemas"];
    let fields = |schema: &str| -> BTreeSet<String> {
        schemas[schema]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema} has properties"))
            .keys()
            .cloned()
            .collect()
    };
    let submission = Submission {
        description: "x".to_owned(),
        analysis_mode: Some("x".to_owned()),
        event_time: Some(chrono::Utc::now()),
        observables: vec![SubmittedObservable {
            kind: ObservableKind::Fqdn,
            value: "x".to_owned(),
            time: Some(chrono::Utc::now()),
            tags: vec![],
            directives: vec![],
            exclude_modules: vec![],
        }],
        file_yara_meta: Default::default(),
    };
    let core = serde_json::to_value(&submission).expect("JSON");
    let keys = |value: &Value| -> BTreeSet<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(fields("SubmissionBody"), keys(&core));
    assert_eq!(
        fields("SubmittedObservableBody"),
        keys(&core["observables"][0])
    );
}

/// A page cursor is a place in a fixed order, so alerts that arrive while a client pages are on the
/// first page and never shift a later one, and nothing is seen twice or skipped.
#[tokio::test]
async fn paging_through_alerts_sees_each_once_while_more_arrive() {
    let stack = stack().await;
    let token = key(&stack, &["alert:read"]).await;
    let mut made = Vec::new();
    for n in 0..5 {
        made.push(alert(&stack, &format!("alert {n}"), &[]).await);
    }
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let mut url = format!("{}{LIST}?limit=2", stack.url);
        if let Some(after) = &after {
            url.push_str(&format!("&after={after}"));
        }
        let page: Value = stack
            .http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .expect("answered")
            .json()
            .await
            .expect("a page");
        for alert in page["alerts"].as_array().expect("alerts") {
            seen.push(
                alert["id"]
                    .as_str()
                    .expect("an id")
                    .parse::<Uuid>()
                    .expect("a uuid"),
            );
        }
        // one arrives between pages
        alert(&stack, "late", &[]).await;
        match page["next"].as_str() {
            Some(next) => after = Some(next.to_owned()),
            None => break,
        }
    }
    made.reverse();
    assert_eq!(
        seen, made,
        "newest first, each once, and none that arrived meanwhile"
    );
}

/// A GUI session works as a key does, and the same-origin check refuses another site's write.
#[tokio::test]
async fn a_session_reads_and_another_site_can_t_write_with_it() {
    let stack = stack().await;
    let user = stack
        .service
        .create_user(
            &bootstrap(),
            &Username::new("analyst").expect("a name"),
            Password::new(PASSWORD),
        )
        .await
        .expect("makes a user");
    for grant in ["alert:read", "alert:write"] {
        let (major, minor) = grant.split_once(':').expect("a grant");
        stack
            .service
            .grant(
                &bootstrap(),
                &Holder::User(user),
                &PermissionPattern::new(major, minor).expect("a pattern"),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
    let session = stack
        .service
        .login("analyst", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let cookie = format!("ace4_session={}", session.token.expose());
    let id = alert(&stack, "an alert", &[]).await;

    let read = stack
        .http
        .get(format!("{}{}", stack.url, fill(ONE, id, 0)))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("answered");
    assert_eq!(read.status(), 200);
    let disposition = |origin: &str| {
        stack
            .http
            .put(format!("{}{}", stack.url, fill(DISPOSITION, id, 0)))
            .header("cookie", &cookie)
            .header("origin", origin)
            .json(&json!({"disposition": "IGNORE"}))
            .send()
    };
    let refused = disposition("https://evil.example").await.expect("answered");
    assert_eq!(refused.status(), 403);
    let error: Value = refused.json().await.expect("a body");
    assert_eq!(error["error"], "this request came from another site");
    let host = stack.url.trim_start_matches("http://").to_owned();
    let allowed = disposition(&format!("http://{host}"))
        .await
        .expect("answered");
    assert_eq!(allowed.status(), 200, "{:?}", allowed.text().await);
    let by: Value =
        sqlx::query_scalar("SELECT dispositioned_by::jsonb FROM analysis.roots WHERE id = $1")
            .bind(id)
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("the root");
    assert_eq!(by, json!({"kind": "user", "id": user.0, "name": "analyst"}));
}
