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
    Actor, Component, Effect, Holder, Password, PermissionPattern, Profile, Service, Username,
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
        .create_api_key(&bootstrap(), "test", None, &[])
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
        // a session's token goes as its cookie, from this server's own origin
        match token {
            Some(token) if token.starts_with("ace4s_") => {
                request = request
                    .header("cookie", format!("ace4_session={token}"))
                    .header("origin", &self.stack.url);
            }
            Some(token) => request = request.bearer_auth(token),
            None => {}
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
const USERS: &str = "/api/users/v1/users";
const USER: &str = "/api/users/v1/users/{id}";
const ENABLED: &str = "/api/users/v1/users/{id}/enabled";
const RESET: &str = "/api/users/v1/users/{id}/password";
const GROUPS: &str = "/api/users/v1/groups";
const GROUP: &str = "/api/users/v1/groups/{id}";
const MEMBER: &str = "/api/users/v1/groups/{id}/members/{user}";
const GRANTS: &str = "/api/users/v1/grants";
const REVOKE: &str = "/api/users/v1/grants/revoke";
const CATALOG: &str = "/api/users/v1/catalog";
const KEYS: &str = "/api/users/v1/keys";
const KEY: &str = "/api/users/v1/keys/{id}";
const ME: &str = "/api/users/v1/me";
const MY_PASSWORD: &str = "/api/users/v1/me/password";
const MY_KEYS: &str = "/api/users/v1/me/keys";
const MY_KEY: &str = "/api/users/v1/me/keys/{id}";
const OTHER_PASSWORD: &str = "a different long passphrase";

fn fill(route: &str, id: Uuid, observable: i64) -> String {
    route
        .replace("{id}", &id.to_string())
        .replace("{observable}", &observable.to_string())
        .replace("{user}", &id.to_string())
}

/// A route with `{id}` and `{user}` filled.
fn at(route: &str, id: impl std::fmt::Display, user: impl std::fmt::Display) -> String {
    route
        .replace("{id}", &id.to_string())
        .replace("{user}", &user.to_string())
}

/// A JSON body over the limit.
fn too_large() -> Send {
    Send::Bytes(format!("{{\"name\": \"{}\"}}", "x".repeat(MAX_JSON)).into_bytes())
}

fn scope_body(name: &str, scope: &[(&str, &str)]) -> Value {
    let scope: Vec<Value> = scope
        .iter()
        .map(|(major, minor)| json!({"major": major, "minor": minor}))
        .collect();
    json!({"name": name, "scope": scope})
}

/// A body each route would take, so a 401 or 403 is about the credential and nothing else.
fn good_body(route: &str) -> Send {
    match route {
        DISPOSITION => Send::Json(json!({"disposition": "FALSE_POSITIVE"})),
        SUBMIT => Send::Form(form(&json!({"description": "x"}), &[])),
        LOOKUP => Send::Json(json!({"observables": [{"type": "fqdn", "value": "a.example"}]})),
        USERS => Send::Json(json!({"username": "refused", "password": PASSWORD})),
        USER | ME => Send::Json(json!({"display_name": "x"})),
        ENABLED => Send::Json(json!({"enabled": true})),
        RESET => Send::Json(json!({"password": PASSWORD})),
        GROUPS => Send::Json(json!({"name": "refused"})),
        GRANTS | REVOKE => Send::Json(json!({
            "holder": {"kind": "user", "id": Uuid::nil()},
            "major": "alert",
            "minor": "read",
            "effect": "allow",
        })),
        KEYS | KEY | MY_KEYS | MY_KEY => Send::Json(scope_body("refused", &[("alert", "read")])),
        MY_PASSWORD => Send::Json(json!({"current": PASSWORD, "new": OTHER_PASSWORD})),
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
    assert_eq!(routes.len(), 32, "{routes:?}");
    for (method, route) in routes {
        let method: Method = method.to_uppercase().parse().expect("a method");
        let path = fill(&route, id, file);
        // a GET's body is nothing
        let send_for = |route: &str| {
            if method == Method::GET {
                Send::Nothing
            } else {
                good_body(route)
            }
        };
        let response = client
            .call(method.clone(), &route, &path, None, send_for(&route))
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
                .call(method.clone(), &route, &path, Some(wrong), send_for(&route))
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
                send_for(&route),
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

fn id_of(value: &Value) -> Uuid {
    value["id"]
        .as_str()
        .expect("an id")
        .parse()
        .expect("a uuid")
}

/// The users router's administration: users, groups, grants, the catalog and keys.
async fn manages_users(client: &mut Client<'_>, token: &str) {
    use Method as M;
    use StatusCode as S;
    let t = Some(token);
    let missing = Uuid::from_u128(0xBAD);
    let json = Send::Json;

    // users
    let rows = audit_count(client.stack).await;
    let made = client
        .json(
            M::POST,
            USERS,
            USERS,
            t,
            json(json!({
                "username": "Analyst",
                "password": PASSWORD,
                "display_name": "An Analyst",
                "email": "analyst@example.com",
                "timezone": "Europe/London",
            })),
            S::CREATED,
        )
        .await;
    let analyst = id_of(&made);
    assert_eq!(audit_count(client.stack).await, rows + 1, "the user's row");
    for bad in [
        json!({"username": "weak", "password": "short"}),
        json!({"username": "no spaces", "password": PASSWORD}),
        json!({"username": "zoned", "password": PASSWORD, "timezone": "Mars/Olympus"}),
        json!({"username": "extra", "password": PASSWORD, "admin": true}),
        json!({"password": PASSWORD}),
    ] {
        client
            .json(M::POST, USERS, USERS, t, json(bad), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::POST,
            USERS,
            USERS,
            t,
            json(json!({"username": "analyst", "password": PASSWORD})),
            S::CONFLICT,
        )
        .await;
    client
        .json(M::POST, USERS, USERS, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;

    let listed = client
        .json(M::GET, USERS, USERS, t, Send::Nothing, S::OK)
        .await;
    let names: Vec<&str> = listed
        .as_array()
        .expect("users")
        .iter()
        .map(|user| user["username"].as_str().expect("a name"))
        .collect();
    assert!(names.contains(&"analyst"), "{names:?}");
    client
        .json(
            M::GET,
            USERS,
            &format!("{USERS}?include_disabled=maybe"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    let one = at(USER, analyst, "");
    let detail = client
        .json(M::GET, USER, &one, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(detail["user"]["username"], "analyst");
    assert_eq!(detail["user"]["display_name"], "An Analyst");
    assert_eq!(detail["user"]["timezone"], "Europe/London");
    assert!(detail["user"].get("password_hash").is_none());
    client
        .json(
            M::GET,
            USER,
            &at(USER, "nope", ""),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            USER,
            &at(USER, missing, ""),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;

    let changed = client
        .json(
            M::PATCH,
            USER,
            &one,
            t,
            json(json!({"timezone": "Asia/Tokyo"})),
            S::OK,
        )
        .await;
    assert_eq!(changed, json!({"changed": true}));
    let again = client
        .json(
            M::PATCH,
            USER,
            &one,
            t,
            json(json!({"timezone": "Asia/Tokyo"})),
            S::OK,
        )
        .await;
    assert_eq!(again, json!({"changed": false}));
    client
        .json(
            M::PATCH,
            USER,
            &one,
            t,
            json(json!({"email": "nope"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PATCH,
            USER,
            &at(USER, missing, ""),
            t,
            json(json!({"timezone": "UTC"})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::PATCH, USER, &one, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;

    let enabled = at(ENABLED, analyst, "");
    let off = client
        .json(
            M::PUT,
            ENABLED,
            &enabled,
            t,
            json(json!({"enabled": false})),
            S::OK,
        )
        .await;
    assert_eq!(off, json!({"changed": true}));
    client
        .json(
            M::PUT,
            ENABLED,
            &enabled,
            t,
            json(json!({"enabled": true})),
            S::OK,
        )
        .await;
    client
        .json(
            M::PUT,
            ENABLED,
            &enabled,
            t,
            json(json!({"enabled": "no"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            ENABLED,
            &at(ENABLED, missing, ""),
            t,
            json(json!({"enabled": true})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::PUT,
            ENABLED,
            &enabled,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;

    let reset = at(RESET, analyst, "");
    let response = client
        .call(
            M::PUT,
            RESET,
            &reset,
            t,
            json(json!({"password": OTHER_PASSWORD})),
        )
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    client
        .stack
        .service
        .login("analyst", Password::new(OTHER_PASSWORD), None)
        .await
        .expect("the new password works");
    client
        .json(
            M::PUT,
            RESET,
            &reset,
            t,
            json(json!({"password": "short"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            RESET,
            &at(RESET, missing, ""),
            t,
            json(json!({"password": PASSWORD})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::PUT, RESET, &reset, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;

    // groups, members and grants
    let triage = id_of(
        &client
            .json(
                M::POST,
                GROUPS,
                GROUPS,
                t,
                json(json!({"name": "triage"})),
                S::CREATED,
            )
            .await,
    );
    client
        .json(
            M::POST,
            GROUPS,
            GROUPS,
            t,
            json(json!({"name": "triage"})),
            S::CONFLICT,
        )
        .await;
    client
        .json(
            M::POST,
            GROUPS,
            GROUPS,
            t,
            json(json!({"name": " "})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::POST,
            GROUPS,
            GROUPS,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let member = at(MEMBER, triage, analyst);
    for _ in 0..2 {
        let response = client.call(M::PUT, MEMBER, &member, t, Send::Nothing).await;
        assert_eq!(
            response.status(),
            S::NO_CONTENT,
            "putting a member in twice"
        );
    }
    client
        .json(
            M::PUT,
            MEMBER,
            &at(MEMBER, missing, analyst),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::PUT,
            MEMBER,
            &at(MEMBER, triage, "nope"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let to_triage = |effect: &str| {
        json!({
            "holder": {"kind": "group", "id": triage},
            "major": "Alert",
            "minor": "READ",
            "effect": effect,
        })
    };
    let granted = client
        .json(M::POST, GRANTS, GRANTS, t, json(to_triage("allow")), S::OK)
        .await;
    assert_eq!(granted, json!({"changed": true}));
    for bad in [
        json!({"holder": {"kind": "group", "id": triage}, "major": "alert:x", "minor": "read", "effect": "allow"}),
        json!({"holder": {"kind": "component", "id": triage}, "major": "alert", "minor": "read", "effect": "allow"}),
        json!({"holder": {"kind": "group", "id": triage}, "major": "alert", "minor": "read", "effect": "maybe"}),
    ] {
        client
            .json(M::POST, GRANTS, GRANTS, t, json(bad), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::POST,
            GRANTS,
            GRANTS,
            t,
            json(json!({
                "holder": {"kind": "user", "id": missing},
                "major": "alert",
                "minor": "read",
                "effect": "allow",
            })),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::POST,
            GRANTS,
            GRANTS,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let detail = client
        .json(M::GET, USER, &one, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(detail["groups"][0]["name"], "triage");
    assert_eq!(detail["groups"][0]["members"], json!([analyst]));
    assert_eq!(detail["groups"][0]["grants"][0]["major"], "alert");
    assert_eq!(detail["groups"][0]["grants"][0]["minor"], "read");
    let groups = client
        .json(M::GET, GROUPS, GROUPS, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(groups.as_array().expect("groups").len(), 1);

    // keys: one for the analyst, which holds what both it and the analyst hold
    let catalog = client
        .json(M::GET, CATALOG, CATALOG, t, Send::Nothing, S::OK)
        .await;
    assert!(
        catalog
            .as_array()
            .expect("entries")
            .iter()
            .any(|entry| entry["major"] == "user" && entry["minor"] == "self"),
        "{catalog}"
    );
    let mut body = scope_body("analyst's", &[("alert", "read"), ("observable", "read")]);
    body["owner"] = json!(analyst);
    let response = client.call(M::POST, KEYS, KEYS, t, json(body)).await;
    assert_eq!(response.status(), S::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let made: Value = response.json().await.expect("a key");
    let (analysts_key, analysts_token) = (
        id_of(&made),
        made["token"].as_str().expect("a token").to_owned(),
    );
    let reads = client
        .stack
        .http
        .get(format!("{}{LIST}", client.stack.url))
        .bearer_auth(&analysts_token)
        .send()
        .await
        .expect("answered");
    assert_eq!(
        reads.status(),
        200,
        "the analyst reads alerts through triage"
    );
    let looks = client
        .stack
        .http
        .post(format!("{}{LOOKUP}", client.stack.url))
        .bearer_auth(&analysts_token)
        .json(&json!({"observables": [{"type": "fqdn", "value": "a.example"}]}))
        .send()
        .await
        .expect("answered");
    assert_eq!(
        looks.status(),
        403,
        "the analyst doesn't hold observable:read"
    );
    let mut no_owner = scope_body("orphan", &[("alert", "read")]);
    no_owner["owner"] = json!(missing);
    client
        .json(M::POST, KEYS, KEYS, t, json(no_owner), S::NOT_FOUND)
        .await;
    for bad in [
        scope_body("selfish", &[("user", "self")]),
        scope_body(" ", &[("alert", "read")]),
        json!({"name": "x"}),
    ] {
        client
            .json(M::POST, KEYS, KEYS, t, json(bad), S::BAD_REQUEST)
            .await;
    }
    client
        .json(M::POST, KEYS, KEYS, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;
    let theirs = client
        .json(
            M::GET,
            KEYS,
            &format!("{KEYS}?owner={analyst}"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(theirs.as_array().expect("keys").len(), 1);
    assert_eq!(theirs[0]["name"], "analyst's");
    assert_eq!(theirs[0]["owner"], json!(analyst));
    assert_eq!(theirs[0]["grants"].as_array().expect("grants").len(), 2);
    assert!(theirs[0].get("token").is_none());
    client
        .json(
            M::GET,
            KEYS,
            &format!("{KEYS}?owner=nope"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    let key = at(KEY, analysts_key, "");
    let rescoped = client
        .json(
            M::PUT,
            KEY,
            &key,
            t,
            json(scope_body("analyst's", &[("observable", "read")])),
            S::OK,
        )
        .await;
    assert_eq!(rescoped, json!({"changed": true}));
    let reads = client
        .stack
        .http
        .get(format!("{}{LIST}", client.stack.url))
        .bearer_auth(&analysts_token)
        .send()
        .await
        .expect("answered");
    assert_eq!(reads.status(), 403, "the same token, with its new scope");
    client
        .json(
            M::PUT,
            KEY,
            &key,
            t,
            json(scope_body("analyst's", &[("bad:part", "read")])),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            KEY,
            &at(KEY, missing, ""),
            t,
            json(scope_body("x", &[])),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::PUT, KEY, &key, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;

    // revoking
    let revoked = client
        .json(M::POST, REVOKE, REVOKE, t, json(to_triage("allow")), S::OK)
        .await;
    assert_eq!(revoked, json!({"changed": true}));
    client
        .json(
            M::POST,
            REVOKE,
            REVOKE,
            t,
            json(
                json!({"holder": {"kind": "group"}, "major": "a", "minor": "b", "effect": "allow"}),
            ),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::POST,
            REVOKE,
            REVOKE,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let response = client.call(M::DELETE, KEY, &key, t, Send::Nothing).await;
    assert_eq!(response.status(), S::NO_CONTENT);
    client
        .json(M::DELETE, KEY, &key, t, Send::Nothing, S::NOT_FOUND)
        .await;
    client
        .json(
            M::DELETE,
            KEY,
            &at(KEY, "nope", ""),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let response = client
        .call(M::DELETE, MEMBER, &member, t, Send::Nothing)
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    client
        .json(M::DELETE, MEMBER, &member, t, Send::Nothing, S::NOT_FOUND)
        .await;
    client
        .json(
            M::DELETE,
            MEMBER,
            &at(MEMBER, "nope", analyst),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let group = at(GROUP, triage, "");
    let response = client
        .call(M::DELETE, GROUP, &group, t, Send::Nothing)
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    client
        .json(M::DELETE, GROUP, &group, t, Send::Nothing, S::NOT_FOUND)
        .await;
    client
        .json(
            M::DELETE,
            GROUP,
            &at(GROUP, "nope", ""),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
}

/// The caller's own account, password and keys, as a GUI session.
async fn serves_me(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let me = stack
        .service
        .create_user(
            &bootstrap(),
            &Username::new("me").expect("a name"),
            Password::new(PASSWORD),
            &Profile::default(),
        )
        .await
        .expect("makes a user");
    for grant in ["user:self", "alert:read"] {
        let (major, minor) = grant.split_once(':').expect("a grant");
        stack
            .service
            .grant(
                &bootstrap(),
                &Holder::User(me),
                &PermissionPattern::new(major, minor).expect("a pattern"),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
    let session = stack
        .service
        .login("me", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let token = session.token.expose().to_owned();
    let t = Some(token.as_str());

    let mine = client.json(M::GET, ME, ME, t, Send::Nothing, S::OK).await;
    assert_eq!(mine["id"], json!(me.0));
    assert_eq!(mine["username"], "me");
    let changed = client
        .json(
            M::PATCH,
            ME,
            ME,
            t,
            json(json!({"display_name": "Me", "timezone": "Europe/Paris"})),
            S::OK,
        )
        .await;
    assert_eq!(changed["display_name"], "Me");
    assert_eq!(changed["timezone"], "Europe/Paris");
    client
        .json(
            M::PATCH,
            ME,
            ME,
            t,
            json(json!({"email": "me@example.com"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(M::PATCH, ME, ME, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;
    // a session's write from another site is refused
    let refused = stack
        .http
        .patch(format!("{}{ME}", stack.url))
        .header("cookie", format!("ace4_session={token}"))
        .header("origin", "https://evil.example")
        .json(&json!({"display_name": "Evil"}))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), 403);

    let made = client
        .json(
            M::POST,
            MY_KEYS,
            MY_KEYS,
            t,
            json(scope_body("mine", &[("alert", "read")])),
            S::CREATED,
        )
        .await;
    let key = id_of(&made);
    for bad in [
        scope_body("mine", &[("alert", "*")]),
        scope_body("mine", &[]),
        scope_body("mine", &[("nothing", "here")]),
    ] {
        client
            .json(M::POST, MY_KEYS, MY_KEYS, t, json(bad), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::POST,
            MY_KEYS,
            MY_KEYS,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let listed = client
        .json(M::GET, MY_KEYS, MY_KEYS, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(listed.as_array().expect("keys").len(), 1);
    assert_eq!(listed[0]["owner"], json!(me.0));

    let one = at(MY_KEY, key, "");
    let renamed = client
        .json(
            M::PUT,
            MY_KEY,
            &one,
            t,
            json(scope_body("renamed", &[("alert", "read")])),
            S::OK,
        )
        .await;
    assert_eq!(renamed, json!({"changed": true}));
    client
        .json(
            M::PUT,
            MY_KEY,
            &one,
            t,
            json(scope_body("x", &[])),
            S::BAD_REQUEST,
        )
        .await;
    // another user's key is no key of mine
    let theirs = stack
        .service
        .create_api_key(&bootstrap(), "theirs", None, &[])
        .await
        .expect("makes a key");
    client
        .json(
            M::PUT,
            MY_KEY,
            &at(MY_KEY, theirs.id.0, ""),
            t,
            json(scope_body("mine now", &[("alert", "read")])),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::PUT, MY_KEY, &one, t, too_large(), S::PAYLOAD_TOO_LARGE)
        .await;
    client
        .json(
            M::DELETE,
            MY_KEY,
            &at(MY_KEY, theirs.id.0, ""),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            MY_KEY,
            &at(MY_KEY, "nope", ""),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let response = client.call(M::DELETE, MY_KEY, &one, t, Send::Nothing).await;
    assert_eq!(response.status(), S::NO_CONTENT);

    // the password, last, since a change ends the session
    client
        .json(
            M::PUT,
            MY_PASSWORD,
            MY_PASSWORD,
            t,
            json(json!({"current": PASSWORD, "new": "short"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            MY_PASSWORD,
            MY_PASSWORD,
            t,
            json(json!({"current": OTHER_PASSWORD, "new": OTHER_PASSWORD})),
            S::UNAUTHORIZED,
        )
        .await;
    client
        .json(
            M::PUT,
            MY_PASSWORD,
            MY_PASSWORD,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let response = client
        .call(
            M::PUT,
            MY_PASSWORD,
            MY_PASSWORD,
            t,
            json(json!({"current": PASSWORD, "new": OTHER_PASSWORD})),
        )
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    let cleared = response.headers()["set-cookie"].to_str().expect("text");
    assert!(
        cleared.starts_with("ace4_session=;") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    client
        .json(M::GET, ME, ME, t, Send::Nothing, S::UNAUTHORIZED)
        .await;
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
    let admin = key(&stack, &["user:read", "user:write"]).await;
    manages_users(&mut client, &admin).await;
    serves_me(&mut client).await;

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
            &Profile::default(),
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
