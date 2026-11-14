//! PLAN.md 5.5's Done check: the alerts, analysis and observables endpoints have tests and are in the
//! OpenAPI document. `every_documented_status_is_tested` drives each endpoint through every status its
//! document lists, records what it saw, and fails when the two differ, so a new endpoint or status needs
//! its test. Every endpoint is also refused without a credential (401) and without its permission (403),
//! from the document's own list of routes, but those the document marks as taking no credential, which
//! must be exactly the ping. The committed `openapi.json` must be what utoipa derives.
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
use ace_sdk::lists::{ListSpec, WireList};
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

/// A list, as a module declares one (PLAN.md 5.14).
const TEST_LIST: ListSpec = ListSpec {
    name: "test_whitelist",
    description: "a list for the tests",
    typed: false,
};

/// The list 7.6's `observable_detection` module reads, which the `detection` router keeps.
const DETECTION_SPEC: ListSpec = ListSpec {
    name: "observable_detection",
    description: "the observables ACE detects",
    typed: true,
};

/// A module that reads the lists. No mode names it, so a test queues its tasks itself.
struct ListReader;

impl Module for ListReader {
    const NAME: &'static str = "test_list_reader";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const LISTS: &'static [ListSpec] = &[TEST_LIST, DETECTION_SPEC];
    type Output = StubOutput;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(ListReader)
    }
}

impl Lookup for ListReader {
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
    bucket: Bucket,
    archive: ace_core::email_archive::EmailArchive,
    orchestrator: Orchestrator,
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

/// The test-only key the reference dumps' archive was sealed with.
fn archive_key() -> ace_core::email_archive::ArchiveKey {
    ace_core::email_archive::ArchiveKey::new(*b"ace4 test-only email archive key")
}

async fn stack() -> Stack {
    stack_with(ace_core::email_archive::ArchiveConfig::default().with_key(archive_key())).await
}

/// A stack whose email archive has `archive`'s key and retention.
async fn stack_with(archive: ace_core::email_archive::ArchiveConfig) -> Stack {
    stack_of(
        archive,
        Catalog::new(vec![
            Manifest::lookup::<Rdap>(),
            Manifest::lookup::<ListReader>(),
        ]),
    )
    .await
}

/// A stack whose modules are `catalog`'s.
async fn stack_of(archive: ace_core::email_archive::ArchiveConfig, catalog: Catalog) -> Stack {
    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    );
    let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
    let orchestrator = Orchestrator::new(catalog, Modes::ace3());
    // the site's dispositions are ace3's with two of its own, one of which only ACE sets
    let overlay = ace_sdk::Overlay::from_yaml(
        "dispositions:\n  SITE_CHECKED: {rank: 45, css: site-checked, show_save_to_event: true}\n  \
         SITE_SWEEP: {rank: 5, css: dark, analyst_selectable: false}\n\
         disposition_classification: {SITE_CHECKED: fp}\n",
    )
    .expect("the overlay parses");
    let service = Service::new(test_db.db().clone(), orchestrator.clone())
        .with_actions(test_actions())
        // what a refused SVS registration submits its alert with (PLAN.md 7.10 batch 5)
        .with_bucket(bucket.clone())
        .with_dispositions(ace_service::Dispositions::configured(&overlay).expect("good sections"))
        // a repository the validations' requests may name; requesting doesn't fetch it (PLAN.md 7.10)
        .with_validation(
            ace_core::svs::yara::ValidationConfig::from_section(
                &ace_sdk::Overlay::from_yaml(
                    "svs: {yara: {repositories: {svs_rules: {url: /nowhere, branch: main}}}}",
                )
                .expect("the overlay parses")
                .svs
                .yara,
            )
            .expect("valid settings"),
        )
        // the catalog's repositories, which the API lists and never fetches (PLAN.md 7.10 batch 4)
        .with_catalog(
            ace_core::svs::catalog::CatalogConfig::from_section(
                &ace_sdk::Overlay::from_yaml(
                    "svs: {catalog: {repositories: {\n\
                       art: {url: 'https://ghp_secret@git.invalid/redcanaryco/atomic-red-team.git', \
                             branch: master},\n\
                       unread: {url: /nowhere, branch: main}}}}",
                )
                .expect("the overlay parses")
                .svs
                .catalog,
            )
            .expect("valid settings"),
        );
    let config = ace_api::WebConfig {
        max_json_bytes: MAX_JSON,
        max_submission_bytes: MAX_SUBMISSION,
        max_submitted_files: 3,
        // small, so an export past it is cheap to make
        max_export_rows: 2,
        ..ace_api::WebConfig::default()
    };
    let archive =
        ace_core::email_archive::EmailArchive::new(test_db.db().clone(), bucket.clone(), archive);
    let router = ace_api::Web::new(service.clone(), bucket.clone(), config)
        .with_email_archive(archive.clone())
        .router();
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
        bucket,
        archive,
        orchestrator,
        url,
        http: reqwest::Client::new(),
        task,
        _cache: cache,
    }
}

/// A file collector that collects nothing, for the file collections' routes (PLAN.md 7.9).
static TEST_COLLECTOR: ace_sdk::actions::ActionSpec = ace_sdk::actions::ActionSpec {
    kind: ace_sdk::actions::ActionKind::FileCollection,
    name: "edr",
    display_name: "Test EDR",
    description: "Collects files in tests.",
    observable_type: "file_location",
    tcp_ports: &[],
    secrets: &[],
    retry: ace_sdk::actions::Retry::FILE_COLLECTION,
    supersede_grace_seconds: 0,
};

/// ace3's test remediator and a test collector.
fn test_actions() -> ace_core::actions::ActionCatalog {
    ace_core::actions::ActionCatalog::new(&[&ace_sdk::actions::TEST_REMEDIATOR, &TEST_COLLECTOR])
        .expect("a catalog")
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

/// The (method, route) of each operation the document says takes no credential: `security: [{}]`.
fn public() -> BTreeSet<(String, String)> {
    let document: Value = serde_json::from_str(&ace_api::openapi_json()).expect("JSON");
    let mut found = BTreeSet::new();
    for (route, item) in document["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("an item") {
            if operation["security"] == json!([{}]) {
                found.insert((method.clone(), route.clone()));
            }
        }
    }
    found
}

const PING: &str = "/api/health/v1/ping";
const LIST: &str = "/api/alerts/v1/alerts";
const ONE: &str = "/api/alerts/v1/alerts/{id}";
const OBSERVABLES: &str = "/api/alerts/v1/alerts/{id}/observables";
const GRAPH: &str = "/api/alerts/v1/alerts/{id}/graph";
const FILE: &str = "/api/alerts/v1/alerts/{id}/observables/{observable}/file";
const DISPOSITION: &str = "/api/alerts/v1/alerts/{id}/disposition";
const DISPOSITIONS: &str = "/api/alerts/v1/dispositions";
const SUBMIT: &str = "/api/analysis/v1/submit";
const LOOKUP: &str = "/api/observables/v1/lookup";
const TYPES: &str = "/api/observables/v1/types";
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
const COMMANDS: &str = "/api/cli/v1/commands";
const COMMAND: &str = "/api/cli/v1/commands/{id}";
const CANCEL_COMMAND: &str = "/api/cli/v1/commands/{id}/cancel";
const CRASHES: &str = "/api/crashes/v1/crashes";
const EMAIL_ARCHIVE: &str = "/api/email/v1/archive";
const CRASH: &str = "/api/crashes/v1/crashes/{id}";
const CRASH_DOWNLOAD: &str = "/api/crashes/v1/crashes/{id}/download";
const QA_RULES: &str = "/api/yara-qa/v1/rules";
const QA_RULE: &str = "/api/yara-qa/v1/rules/{uuid}";
const QA_RULE_MATCHES: &str = "/api/yara-qa/v1/rules/{uuid}/matches";
const QA_RULE_DOWNLOAD: &str = "/api/yara-qa/v1/rules/{uuid}/download";
const QA_PURGE: &str = "/api/yara-qa/v1/rules/{uuid}/purge";
const QA_MATCH: &str = "/api/yara-qa/v1/matches/{id}";
const QA_RECORD: &str = "/api/yara-qa/v1/matches/{id}/record";
const QA_MATCH_DOWNLOAD: &str = "/api/yara-qa/v1/matches/{id}/download";
const COMMENTS: &str = "/api/observables/v1/comments";
const COMMENT: &str = "/api/observables/v1/comments/{id}";
const DETECTIONS: &str = "/api/alerts/v1/detections";
const VERDICT: &str = "/api/alerts/v1/alerts/{id}/detections/{detection}/verdict";
const CONFIRM: &str = "/api/alerts/v1/alerts/{id}/detections/confirm";
const PREFERENCES: &str = "/api/users/v1/me/preferences";
const PREFERENCE: &str = "/api/users/v1/me/preferences/{key}";
const ALERT_CSV: &str = "/api/alerts/v1/alerts/export/csv";
const ALERT_NDJSON: &str = "/api/alerts/v1/alerts/export/ndjson";
const DETECTION_CSV: &str = "/api/alerts/v1/detections/export/csv";
const DETECTION_NDJSON: &str = "/api/alerts/v1/detections/export/ndjson";
const SCREEN: &str = "/api/filters/v1/screens/{screen}";
const ENCODE: &str = "/api/filters/v1/screens/{screen}/encode";
const DECODE: &str = "/api/filters/v1/screens/{screen}/decode";
const SAVED: &str = "/api/filters/v1/saved";
const SAVED_ONE: &str = "/api/filters/v1/saved/{id}";
const QUICK: &str = "/api/filters/v1/saved/quick";
const OPEN_EVENTS: &str = "/api/events/v1/events/open";
const EVENT: &str = "/api/events/v1/events/{event}";
const EVENT_STATUS: &str = "/api/events/v1/events/{event}/status";
const EVENT_CSV: &str = "/api/events/v1/events/export/csv";
const THREAT_TYPES: &str = "/api/events/v1/threat-types";
const THREAT_TYPE: &str = "/api/events/v1/threat-types/{id}";
const THREATS: &str = "/api/events/v1/threats";
const THREAT: &str = "/api/events/v1/threats/{malware}/{threat_type}";
const LISTS: &str = "/api/lists/v1/lists";
const LIST_ONE: &str = "/api/lists/v1/lists/{list}";
const ENTRIES: &str = "/api/lists/v1/lists/{list}/entries";
const ENTRY: &str = "/api/lists/v1/lists/{list}/entries/{id}";
const OBSERVED: &str = "/api/observables/v1/detections";
const OBSERVED_TYPES: &str = "/api/observables/v1/detections/types";
const OBSERVED_ONE: &str = "/api/observables/v1/detections/{id}";
const OBSERVED_EXPIRY: &str = "/api/observables/v1/detections/{id}/expiration";
const TARGETS: &str = "/api/remediation/v1/targets";
const REMEDIATIONS: &str = "/api/remediation/v1/remediations";
const REMEDIATIONS_CSV: &str = "/api/remediation/v1/remediations/export/csv";
const REMEDIATIONS_NDJSON: &str = "/api/remediation/v1/remediations/export/ndjson";
const REMEDIATION: &str = "/api/remediation/v1/remediations/{id}";
const REMEDIATION_HISTORY: &str = "/api/remediation/v1/remediations/{id}/history";
const REMEDIATION_CANCEL: &str = "/api/remediation/v1/remediations/{id}/cancel";
const REMEDIATION_RETRY: &str = "/api/remediation/v1/remediations/{id}/retry";
const REMEDIATION_RESTORE: &str = "/api/remediation/v1/remediations/{id}/restore";
const COLLECTIONS: &str = "/api/file-collections/v1/collections";
const SAMPLES: &str = "/api/svs/v1/samples";
const SAMPLES_CSV: &str = "/api/svs/v1/samples/export/csv";
const SAMPLES_NDJSON: &str = "/api/svs/v1/samples/export/ndjson";
const SAMPLES_MISSING: &str = "/api/svs/v1/samples/missing";
const SAMPLE_RECORD: &str = "/api/svs/v1/samples/captures/{id}/record";
const SAMPLE_DELETIONS: &str = "/api/svs/v1/samples/deletions";
const SAMPLES_DOWNLOAD: &str = "/api/svs/v1/samples/download";
const SAMPLE_FILE: &str = "/api/svs/v1/samples/{sha256}";
const SAMPLE: &str = "/api/svs/v1/samples/{sha256}/{rule_uuid}";
const SAMPLE_DOWNLOAD: &str = "/api/svs/v1/samples/{sha256}/{rule_uuid}/download";
const SAMPLE_LABEL: &str = "/api/svs/v1/samples/{sha256}/{rule_uuid}/label";
const SAMPLE_CONFIRM: &str = "/api/svs/v1/samples/{sha256}/{rule_uuid}/confirm";
const SAMPLE_RETIREMENT: &str = "/api/svs/v1/samples/{sha256}/{rule_uuid}/retirement";
const VALIDATIONS: &str = "/api/svs/v1/yara/validations";
const VALIDATIONS_CSV: &str = "/api/svs/v1/yara/validations/export/csv";
const VALIDATIONS_NDJSON: &str = "/api/svs/v1/yara/validations/export/ndjson";
const VALIDATION: &str = "/api/svs/v1/yara/validations/{uuid}";
const VALIDATION_STATUS: &str = "/api/svs/v1/yara/validations/{uuid}/status";
const VALIDATION_RESULTS: &str = "/api/svs/v1/yara/validations/{uuid}/results";
const VALIDATION_RESULTS_CSV: &str = "/api/svs/v1/yara/validations/{uuid}/results/export/csv";
const VALIDATION_RESULTS_NDJSON: &str = "/api/svs/v1/yara/validations/{uuid}/results/export/ndjson";
const VALIDATION_DOWNLOAD: &str = "/api/svs/v1/yara/validations/{uuid}/download";
const CATALOG_TESTS: &str = "/api/svs/v1/tests";
const CATALOG_TESTS_CSV: &str = "/api/svs/v1/tests/export/csv";
const CATALOG_TESTS_NDJSON: &str = "/api/svs/v1/tests/export/ndjson";
const CATALOG_TEST: &str = "/api/svs/v1/tests/{guid}";
const CATALOG_REPOSITORIES: &str = "/api/svs/v1/catalog/repositories";
const RUNS: &str = "/api/svs/v1/runs";
const RUNS_VALIDATE: &str = "/api/svs/v1/runs/validate";
const RUN: &str = "/api/svs/v1/runs/{run_id}";
const RUN_EVENTS: &str = "/api/svs/v1/runs/{run_id}/events";
const RUN_START: &str = "/api/svs/v1/runs/{run_id}/start";
const RUN_EXECUTED: &str = "/api/svs/v1/runs/{run_id}/executed";
const RUN_CLEANUP: &str = "/api/svs/v1/runs/{run_id}/cleanup";
const RUN_CANCEL: &str = "/api/svs/v1/runs/{run_id}/cancel";
const TEST_HOSTS: &str = "/api/svs/v1/test-hosts";
const TEST_HOST: &str = "/api/svs/v1/test-hosts/{host}";
const MAINTENANCE: &str = "/api/svs/v1/test-hosts/{host}/maintenance";
const COLLECTIONS_CSV: &str = "/api/file-collections/v1/collections/export/csv";
const COLLECTIONS_NDJSON: &str = "/api/file-collections/v1/collections/export/ndjson";
const COLLECTION: &str = "/api/file-collections/v1/collections/{id}";
const COLLECTION_HISTORY: &str = "/api/file-collections/v1/collections/{id}/history";
const COLLECTION_CANCEL: &str = "/api/file-collections/v1/collections/{id}/cancel";
const COLLECTION_RETRY: &str = "/api/file-collections/v1/collections/{id}/retry";
const HUNTS: &str = "/api/hunts/v1/hunts";
const HUNT: &str = "/api/hunts/v1/hunts/{uuid}";
const SUPPRESSIONS: &str = "/api/hunts/v1/hunts/{uuid}/suppressions";
const VALIDATE: &str = "/api/hunts/v1/validate";
const OTHER_PASSWORD: &str = "a different long passphrase";

/// A route with its `{...}` filled: a crash's `{id}` is a task's, which `observable` stands in for, since a
/// refusal comes before the id is looked up.
fn fill(route: &str, id: Uuid, observable: i64) -> String {
    if route == EMAIL_ARCHIVE {
        return format!("{EMAIL_ARCHIVE}?message_id=%3Ca%40example.com%3E");
    }
    if route == COMMENTS {
        return format!("{COMMENTS}?type=fqdn&value=a.example");
    }
    if route == EVENT_CSV {
        return format!("{EVENT_CSV}?ids=1");
    }
    if route == THREAT_TYPE || route == THREAT {
        return route
            .replace("{id}", "1")
            .replace("{malware}", "1")
            .replace("{threat_type}", "1");
    }
    if route.starts_with("/api/svs/") {
        return route
            .replace("{sha256}", &"ab".repeat(32))
            .replace("{rule_uuid}", "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f")
            .replace("{id}", &observable.to_string())
            .replace("{uuid}", &id.to_string())
            .replace("{guid}", &id.to_string())
            .replace("{run_id}", &id.to_string())
            .replace("{host}", "1");
    }
    if route.starts_with("/api/lists/") {
        return route
            .replace("{list}", TEST_LIST.name)
            .replace("{id}", &observable.to_string());
    }
    if route.starts_with("/api/crashes/")
        || route.starts_with("/api/remediation/")
        || route.starts_with("/api/file-collections/")
        || route.starts_with("/api/yara-qa/")
        || route.starts_with("/api/cli/")
        || route == COMMENT
        || route == OBSERVED_ONE
        || route == OBSERVED_EXPIRY
    {
        return route
            .replace("{id}", &observable.to_string())
            .replace("{uuid}", &id.to_string());
    }
    route
        .replace("{id}", &id.to_string())
        .replace("{observable}", &observable.to_string())
        .replace("{detection}", &observable.to_string())
        .replace("{user}", &id.to_string())
        .replace("{key}", "theme")
        .replace("{screen}", "alerts")
        .replace("{event}", &id.to_string())
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
        VERDICT => Send::Json(json!({"verdict": "fp"})),
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
        QA_PURGE => Send::Json(json!({"match_ids": [1]})),
        COMMENTS => Send::Json(json!({"type": "fqdn", "value": "a.example", "comment": "x"})),
        COMMENT => Send::Json(json!({"comment": "x"})),
        PREFERENCE => Send::Json(json!({"mode": "dark"})),
        ENCODE => Send::Json(json!({"filters": []})),
        SAVED => Send::Json(json!({
            "name": "refused",
            "filters": [{"name": "Disposition", "values": ["OPEN"]}],
        })),
        SAVED_ONE => Send::Json(json!({"name": "refused"})),
        QUICK => Send::Json(json!({"ids": []})),
        EVENT_STATUS => Send::Json(json!({"status": "OPEN"})),
        THREAT_TYPES | THREAT_TYPE => Send::Json(json!({"name": "refused"})),
        THREATS => Send::Json(json!({"malware_id": 1, "threat_type_id": 1})),
        COMMANDS => Send::Json(json!({"command": "--help"})),
        ENTRIES | ENTRY => Send::Json(json!({"match": "exact", "value": "refused"})),
        OBSERVED => Send::Json(json!({"type": "fqdn", "value": "refused.example"})),
        OBSERVED_EXPIRY => Send::Json(json!({"expires_on": null})),
        VALIDATE => Send::Json(json!({"compiled_hunt": {"target": "x.yaml", "assets": []}})),
        RUNS | RUNS_VALIDATE => Send::Json(json!({
            "test_guid": Uuid::nil(), "targets": [{"hostname": "refused"}], "launcher": "refused",
        })),
        RUN_EXECUTED => Send::Json(json!({"exit_code": 0})),
        TEST_HOSTS | TEST_HOST => Send::Json(json!({"hostname": "refused"})),
        MAINTENANCE => Send::Json(json!({"minutes": 30, "reason": "refused"})),
        TARGETS => Send::Json(json!({"observables": [{"type": "test", "value": "SUCCESS"}]})),
        REMEDIATIONS => Send::Json(json!({"action": "remove", "targets": [
            {"remediator": "test", "observable_type": "test", "observable_value": "SUCCESS"},
        ]})),
        SAMPLE_LABEL => Send::Json(json!({"verdict": "fp"})),
        SAMPLE_RETIREMENT | SAMPLE_FILE => Send::Json(json!({"reason": "refused"})),
        VALIDATIONS => Send::Json(validation_body(&"b".repeat(40))),
        COLLECTIONS => Send::Json(json!({
            "collector": "edr", "observable_type": "file_location", "observable_value": "h@C:\\x.exe",
        })),
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
    let public = public();
    assert_eq!(
        public,
        BTreeSet::from([("get".to_owned(), PING.to_owned())]),
        "only the ping takes no credential"
    );
    let routes: BTreeSet<(String, String)> = documented()
        .into_iter()
        .map(|(method, route, _)| (method, route))
        .filter(|route| !public.contains(route))
        .collect();
    assert_eq!(routes.len(), 168, "{routes:?}");
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

/// A detection on a root and the result that raised it, as the orchestrator writes one.
async fn detection(stack: &Stack, root: Uuid, description: &str, details: Option<Value>) -> i64 {
    let db = stack.test_db.db().pool();
    let observable: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 ORDER BY id LIMIT 1",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("an observable");
    let result: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details)
         VALUES ($1, $2, 'rdap_analyzer', 'test_stub', 1, '{}')
         ON CONFLICT ON CONSTRAINT results_one_per_module DO UPDATE SET details = excluded.details
         RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .fetch_one(db)
    .await
    .expect("a result");
    sqlx::query_scalar(
        "INSERT INTO analysis.detections
           (root_id, observable_id, result_id, description, details, queue, signature_uuid,
            signature_version, signature_family)
         VALUES ($1, $2, $3, $4, $5, 'external', 'b5a1d3f2-0000-4000-8000-000000000001', 'abc123', 'yara')
         RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(result)
    .bind(description)
    .bind(details)
    .fetch_one(db)
    .await
    .expect("a detection")
}

/// ace3's `detection_points` router, and its alerts router's list of one alert's: every alert's detections
/// in id order, a page at a time. A description and details a hostile rule wrote come back as written.
async fn detection_points(client: &mut Client<'_>, token: &str, earlier: Uuid) {
    let hostile = "<script>alert(1)</script> \"../../etc/passwd\"\n\u{fffd}";
    let details =
        json!({"rule": "<img src=x onerror=alert(1)>", "strings": ["$a", "\u{202e}gpj.exe"]});
    let target = alert(
        client.stack,
        "detected",
        &[(ObservableKind::Fqdn, "evil.example")],
    )
    .await;
    let first = detection(client.stack, target, hostile, Some(details.clone())).await;
    let second = detection(client.stack, target, "plain", None).await;
    // a root no detection made an alert has no detection points
    let quiet = NewRoot::new("analysis");
    let mut tx = client.stack.test_db.db().begin().await.expect("begins");
    tree::create_root(&mut tx, &quiet).await.expect("creates");
    tree::upsert_observable(
        &mut tx,
        quiet.id,
        &NewObservable::new(ObservableKind::Fqdn, "quiet.example"),
    )
    .await
    .expect("adds");
    tx.commit().await.expect("commits");
    let hidden = detection(client.stack, quiet.id, "not an alert's", None).await;

    let page = client
        .json(
            Method::GET,
            DETECTIONS,
            &format!("{DETECTIONS}?alert={target}&limit=1"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let fqdn: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'fqdn'",
    )
    .bind(target)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the fqdn");
    let listed = &page["detections"][0];
    assert_eq!(listed["id"], first);
    assert_eq!(listed["alert"], target.to_string());
    assert_eq!(
        listed["observable"],
        json!({"id": fqdn, "type": "fqdn", "value": "evil.example"})
    );
    assert_eq!(listed["module"], "rdap_analyzer");
    assert_eq!(listed["description"], hostile, "the description is data");
    assert_eq!(listed["details"], details, "the details are data");
    assert_eq!(listed["queue"], "external");
    assert_eq!(
        listed["signature_uuid"],
        "b5a1d3f2-0000-4000-8000-000000000001"
    );
    assert_eq!(listed["signature_version"], "abc123");
    assert_eq!(listed["signature_family"], "yara");
    assert!(listed["created_at"].is_string());
    assert_eq!(page["next"], first);
    let rest = client
        .json(
            Method::GET,
            DETECTIONS,
            &format!("{DETECTIONS}?alert={target}&after={first}"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(rest["detections"].as_array().map(Vec::len), Some(1));
    assert_eq!(rest["detections"][0]["id"], second);
    assert_eq!(rest["detections"][0]["details"], Value::Null);
    assert_eq!(rest["next"], Value::Null);
    // one on the alert itself, as configuration_defined_tagging makes (PLAN.md 7.6), has no observable
    let on_root: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.detections (root_id, description, signature_uuid)
         VALUES ($1, 'tag phish is configured to be alertable', '14564014-a223-440a-914f-03a1f322e1bf')
         RETURNING id",
    )
    .bind(target)
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("a detection");
    let root_page = client
        .json(
            Method::GET,
            DETECTIONS,
            &format!("{DETECTIONS}?alert={target}&after={second}"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(root_page["detections"][0]["id"], on_root);
    assert_eq!(root_page["detections"][0]["observable"], Value::Null);
    assert_eq!(root_page["detections"][0]["module"], Value::Null);

    // every alert's, oldest first, paged to the end
    let mut seen = Vec::new();
    let mut after: Option<i64> = None;
    loop {
        let path = match after {
            Some(after) => format!("{DETECTIONS}?limit=1&after={after}"),
            None => format!("{DETECTIONS}?limit=1"),
        };
        let page = client
            .json(
                Method::GET,
                DETECTIONS,
                &path,
                Some(token),
                Send::Nothing,
                StatusCode::OK,
            )
            .await;
        for listed in page["detections"].as_array().expect("detections") {
            seen.push((
                listed["id"].as_i64().expect("an id"),
                listed["alert"].as_str().expect("an alert").to_owned(),
            ));
        }
        match page["next"].as_i64() {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    let ids: Vec<i64> = seen.iter().map(|(id, _)| *id).collect();
    assert!(ids.is_sorted(), "{ids:?}");
    assert!(ids.contains(&first) && ids.contains(&second), "{ids:?}");
    assert!(
        !ids.contains(&hidden),
        "a root that isn't an alert isn't listed"
    );
    assert!(
        seen.iter().any(|(_, alert)| *alert == earlier.to_string()),
        "the earlier alert's detection is listed"
    );

    for bad in ["?limit=0", "?limit=1001", "?alert=x", "?after=x"] {
        client
            .json(
                Method::GET,
                DETECTIONS,
                &format!("{DETECTIONS}{bad}"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    for missing in [Uuid::nil(), quiet.id] {
        let body = client
            .json(
                Method::GET,
                DETECTIONS,
                &format!("{DETECTIONS}?alert={missing}"),
                Some(token),
                Send::Nothing,
                StatusCode::NOT_FOUND,
            )
            .await;
        assert_eq!(body["error"], format!("no alert {missing}"));
    }
}

/// ace3's verdict writes under `/alerts/{uuid}/detection-points` (PLAN.md 7.14): set, clear and confirm,
/// each answering with what the list says, and refused on an alert whose disposition doesn't take them.
async fn verdicts(client: &mut Client<'_>, token: &str) {
    let db = client.stack.test_db.db().pool();
    let target = alert(
        client.stack,
        "graded",
        &[(ObservableKind::Fqdn, "graded.example")],
    )
    .await;
    let first = detection(client.stack, target, "first", None).await;
    let second: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.detections (root_id, description, signature_uuid)
         VALUES ($1, 'tag phish is configured to be alertable', '14564014-a223-440a-914f-03a1f322e1bf')
         RETURNING id",
    )
    .bind(target)
    .fetch_one(db)
    .await
    .expect("a detection");
    let disposition = |name: &'static str| async move {
        sqlx::query(
            "UPDATE analysis.roots SET disposition = $2,
                 dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}'
             WHERE id = $1",
        )
        .bind(target)
        .bind(name)
        .execute(db)
        .await
        .expect("dispositions");
    };
    disposition("DELIVERY").await;
    let at = |detection: &dyn std::fmt::Display| {
        VERDICT
            .replace("{id}", &target.to_string())
            .replace("{detection}", &detection.to_string())
    };
    let confirm = CONFIRM.replace("{id}", &target.to_string());

    let set = client
        .json(
            Method::PUT,
            VERDICT,
            &at(&first),
            Some(token),
            Send::Json(json!({"verdict": "fp"})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(set["id"], first);
    assert_eq!(set["verdict"], "fp");
    assert_eq!(set["verdict_source"], "explicit");
    assert_eq!(set["override"], "fp");
    assert_eq!(set["override_by"]["kind"], "api_key");
    assert!(set["override_set_at"].is_string());
    let listed = client
        .json(
            Method::GET,
            DETECTIONS,
            &format!("{DETECTIONS}?alert={target}&f=verdict:fp"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(listed["detections"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["detections"][0]["id"], first);
    let unconfirmed = client
        .json(
            Method::GET,
            DETECTIONS,
            &format!("{DETECTIONS}?alert={target}&f=source:inherited_multi"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(unconfirmed["detections"][0]["id"], second);
    assert_eq!(unconfirmed["detections"][0]["verdict"], "tp");
    assert_eq!(unconfirmed["detections"][0]["override"], Value::Null);

    let cleared = client
        .json(
            Method::DELETE,
            VERDICT,
            &at(&first),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(cleared["verdict"], "tp");
    assert_eq!(cleared["verdict_source"], "inherited_multi");
    assert_eq!(cleared["override"], Value::Null);
    assert_eq!(cleared["override_by"], Value::Null);
    let confirmed = client
        .json(
            Method::POST,
            CONFIRM,
            &confirm,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(confirmed, json!({"confirmed": 2}));
    let again = client
        .json(
            Method::POST,
            CONFIRM,
            &confirm,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(again, json!({"confirmed": 0}));

    for bad in [
        json!({"verdict": "maybe"}),
        json!({"verdict": "TP"}),
        json!({}),
        json!({"verdict": "fp", "user": "x"}),
    ] {
        client
            .json(
                Method::PUT,
                VERDICT,
                &at(&first),
                Some(token),
                Send::Json(bad),
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            Method::PUT,
            VERDICT,
            &at(&"x"),
            Some(token),
            Send::Json(json!({"verdict": "fp"})),
            StatusCode::BAD_REQUEST,
        )
        .await;
    client
        .json(
            Method::DELETE,
            VERDICT,
            &at(&"x"),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    client
        .json(
            Method::POST,
            CONFIRM,
            &CONFIRM.replace("{id}", "x"),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    let elsewhere = VERDICT
        .replace("{id}", &Uuid::nil().to_string())
        .replace("{detection}", &first.to_string());
    for path in [at(&i64::MAX), elsewhere] {
        client
            .json(
                Method::PUT,
                VERDICT,
                &path,
                Some(token),
                Send::Json(json!({"verdict": "fp"})),
                StatusCode::NOT_FOUND,
            )
            .await;
        client
            .json(
                Method::DELETE,
                VERDICT,
                &path,
                Some(token),
                Send::Nothing,
                StatusCode::NOT_FOUND,
            )
            .await;
    }
    client
        .json(
            Method::POST,
            CONFIRM,
            &CONFIRM.replace("{id}", &Uuid::nil().to_string()),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    let big = format!("{{\"verdict\": \"{}\"}}", "f".repeat(MAX_JSON));
    client
        .json(
            Method::PUT,
            VERDICT,
            &at(&first),
            Some(token),
            Send::Bytes(big.into_bytes()),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;

    // an FP alert: correct its disposition instead
    disposition("FALSE_POSITIVE").await;
    let refused = client
        .json(
            Method::PUT,
            VERDICT,
            &at(&first),
            Some(token),
            Send::Json(json!({"verdict": "tp"})),
            StatusCode::CONFLICT,
        )
        .await;
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("correct its disposition")),
        "{refused}"
    );
    client
        .json(
            Method::DELETE,
            VERDICT,
            &at(&first),
            Some(token),
            Send::Nothing,
            StatusCode::CONFLICT,
        )
        .await;
    client
        .json(
            Method::POST,
            CONFIRM,
            &confirm,
            Some(token),
            Send::Nothing,
            StatusCode::CONFLICT,
        )
        .await;
    let (status, _, csv) = client
        .text(
            DETECTION_CSV,
            &format!("{DETECTION_CSV}?alert={target}"),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let header = csv.lines().next().unwrap_or_default();
    assert!(
        header.ends_with(",verdict,verdict_source,override,override_by,override_set_at"),
        "{header}"
    );
    assert!(
        csv.contains(",fp,inherited_single,tp,"),
        "the stored TP is masked: {csv}"
    );
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

/// PLAN.md 5.13: an alert's graph, built from its tree's observables, results, additions, tags and
/// relationships, with hostile text kept as it is; one past the bounds cut with a note; and its errors.
async fn reads_graph(client: &mut Client<'_>, token: &str) {
    let stack = client.stack;
    let db = stack.test_db.db().pool();
    let id = alert(
        stack,
        "<img src=x onerror=alert(1)>",
        &[(ObservableKind::Fqdn, "evil.example.com")],
    )
    .await;
    let fqdn: i64 = sqlx::query_scalar(
        "UPDATE analysis.observables SET tags = ARRAY['<b>tag</b>'] WHERE root_id = $1 RETURNING id",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("the fqdn");
    let result: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details)
         VALUES ($1, $2, 'rdap_analyzer', 'test_stub', 1, '{}') RETURNING id",
    )
    .bind(id)
    .bind(fqdn)
    .fetch_one(db)
    .await
    .expect("a result");
    let mut tx = stack.test_db.db().begin().await.expect("begins");
    let ip = tree::upsert_observable(
        &mut tx,
        id,
        &NewObservable::new(ObservableKind::Ip, "192.0.2.1"),
    )
    .await
    .expect("adds")
    .id
    .0;
    tx.commit().await.expect("commits");
    sqlx::query("INSERT INTO analysis.result_additions (root_id, result_id, observable_id) VALUES ($1, $2, $3)")
        .bind(id).bind(result).bind(ip).execute(db).await.expect("an addition");
    sqlx::query(
        "INSERT INTO analysis.relationships (root_id, observable_id, kind, target_type, target_value)
         VALUES ($1, $2, 'related_to', 'fqdn', 'evil.example.com')",
    )
    .bind(id).bind(ip).execute(db).await.expect("a relationship");

    let graph = client
        .json(
            Method::GET,
            GRAPH,
            &fill(GRAPH, id, 0),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let (o, r, i) = (format!("o{fqdn}"), format!("r{result}"), format!("o{ip}"));
    assert_eq!(graph["alert"], id.to_string());
    assert_eq!(
        graph["nodes"],
        json!([
            {"id": "alert", "kind": "alert", "label": "<img src=x onerror=alert(1)>", "observable": null, "result": null},
            {"id": o, "kind": "observable", "label": "fqdn: evil.example.com", "observable": fqdn, "result": null},
            {"id": "t0", "kind": "tag", "label": "<b>tag</b>", "observable": null, "result": null},
            {"id": r, "kind": "result", "label": "rdap_analyzer", "observable": null, "result": result},
            {"id": i, "kind": "observable", "label": "ip: 192.0.2.1", "observable": ip, "result": null},
        ])
    );
    assert_eq!(
        graph["edges"],
        json!([
            {"from": "alert", "to": o, "kind": "observed", "relationship": null},
            {"from": o, "to": "t0", "kind": "tagged", "relationship": null},
            {"from": o, "to": r, "kind": "analyzed", "relationship": null},
            {"from": r, "to": i, "kind": "added", "relationship": null},
            {"from": i, "to": o, "kind": "related", "relationship": "related_to"},
        ])
    );
    assert_eq!(
        (&graph["truncated"], &graph["note"]),
        (&json!(false), &Value::Null)
    );

    // past its bounds: the alert and the first 999 of 1200 observables
    let many: Vec<String> = (0..1200).map(|n| format!("h{n:04}.example")).collect();
    let observables: Vec<(ObservableKind, &str)> = many
        .iter()
        .map(|value| (ObservableKind::Fqdn, value.as_str()))
        .collect();
    let big = alert(stack, "many", &observables).await;
    let graph = client
        .json(
            Method::GET,
            GRAPH,
            &fill(GRAPH, big, 0),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        graph["nodes"].as_array().map(Vec::len),
        Some(ace_service::MAX_GRAPH_NODES)
    );
    assert_eq!(
        graph["edges"].as_array().map(Vec::len),
        Some(ace_service::MAX_GRAPH_NODES - 1)
    );
    assert_eq!(graph["nodes"][999]["label"], "fqdn: h0998.example");
    assert_eq!(graph["truncated"], true);
    assert_eq!(
        graph["note"],
        "The graph was cut short: it shows 1000 of 1201 nodes and 999 of 1200 edges, those nearest the alert."
    );

    client
        .json(
            Method::GET,
            GRAPH,
            "/api/alerts/v1/alerts/x/graph",
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    let missing = client
        .json(
            Method::GET,
            GRAPH,
            &fill(GRAPH, Uuid::nil(), 0),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    assert_eq!(missing["error"], format!("no alert {}", Uuid::nil()));
    // a root no detection made an alert isn't one
    let root = NewRoot::new("analysis");
    let mut tx = stack.test_db.db().begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    client
        .json(
            Method::GET,
            GRAPH,
            &fill(GRAPH, root.id, 0),
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
    // the site's set, in order, with every key and the class: ace3's, then the site's two
    let listed = client
        .json(
            Method::GET,
            DISPOSITIONS,
            DISPOSITIONS,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let listed = listed["dispositions"].as_array().expect("a list");
    let names: Vec<&str> = listed
        .iter()
        .map(|d| d["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        [
            "OPEN",
            "FALSE_POSITIVE",
            "IGNORE",
            "UNKNOWN",
            "REVIEWED",
            "GRAYWARE",
            "POLICY_VIOLATION",
            "RECONNAISSANCE",
            "WEAPONIZATION",
            "DELIVERY",
            "EXPLOITATION",
            "INSTALLATION",
            "COMMAND_AND_CONTROL",
            "EXFIL",
            "DAMAGE",
            "SIMULATED",
            "SITE_CHECKED",
            "SITE_SWEEP",
        ]
    );
    assert_eq!(
        listed[0],
        json!({"name": "OPEN", "rank": 0, "css": "light", "show_save_to_event": false,
               "analyst_selectable": true, "class": null})
    );
    assert_eq!(
        listed[1],
        json!({"name": "FALSE_POSITIVE", "rank": 20, "css": "success", "show_save_to_event": false,
               "analyst_selectable": true, "class": "fp"})
    );
    assert_eq!(
        listed[9],
        json!({"name": "DELIVERY", "rank": 100, "css": "danger", "show_save_to_event": true,
               "analyst_selectable": true, "class": "tp"})
    );
    assert_eq!(
        listed[15],
        json!({"name": "SIMULATED", "rank": 55, "css": "info", "show_save_to_event": false,
               "analyst_selectable": false, "class": "tp"})
    );
    assert_eq!(
        listed[16],
        json!({"name": "SITE_CHECKED", "rank": 45, "css": "site-checked", "show_save_to_event": true,
               "analyst_selectable": true, "class": "fp"})
    );
    assert_eq!(
        listed[17],
        json!({"name": "SITE_SWEEP", "rank": 5, "css": "dark", "show_save_to_event": false,
               "analyst_selectable": false, "class": null})
    );
    // whoever reads alerts reads them: alert:read alone, and not a key that only writes
    let reader = key(client.stack, &["alert:read"]).await;
    client
        .json(
            Method::GET,
            DISPOSITIONS,
            DISPOSITIONS,
            Some(&reader),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let writer = key(client.stack, &["alert:write"]).await;
    let refused = client
        .json(
            Method::GET,
            DISPOSITIONS,
            DISPOSITIONS,
            Some(&writer),
            Send::Nothing,
            StatusCode::FORBIDDEN,
        )
        .await;
    assert_eq!(refused["error"], "this needs alert:read");
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
    // the site's own disposition is taken
    client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, id, 0),
            Some(token),
            Send::Json(json!({"disposition": "SITE_CHECKED"})),
            StatusCode::OK,
        )
        .await;
    for bad in [
        json!({"disposition": "false positive"}),
        json!({"disposition": ""}),
        // well formed, but not one of the site's
        json!({"disposition": "MALICIOUS"}),
        // only ACE sets these, so an API key can't
        json!({"disposition": "SIMULATED"}),
        json!({"disposition": "SITE_SWEEP"}),
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
    // an alert whose disposition only ACE sets can't be changed by an API key
    sqlx::query("UPDATE analysis.roots SET disposition = 'SIMULATED' WHERE id = $1")
        .bind(id)
        .execute(client.stack.test_db.db().pool())
        .await
        .expect("sets it as ACE would");
    let refused = client
        .json(
            Method::PUT,
            DISPOSITION,
            &fill(DISPOSITION, id, 0),
            Some(token),
            Send::Json(json!({"disposition": "FALSE_POSITIVE"})),
            StatusCode::CONFLICT,
        )
        .await;
    assert!(refused.to_string().contains("set only by ACE"), "{refused}");
    let still: String = sqlx::query_scalar("SELECT disposition FROM analysis.roots WHERE id = $1")
        .bind(id)
        .fetch_one(client.stack.test_db.db().pool())
        .await
        .expect("the root");
    assert_eq!(still, "SIMULATED");
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
                "queue": "triage",
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
        json!({"username": "queued", "password": PASSWORD, "queue": "   "}),
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
    assert_eq!(
        detail["user"]["queue"], "triage",
        "the default queue (PLAN.md 7.13)"
    );
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
    // nor can it take its own user:write, or deny it to itself
    let Ok(Actor::ApiKey { id: me, .. }) = client.stack.service.authenticate_api_key(token).await
    else {
        panic!("the admin's key");
    };
    for effect in ["allow", "deny"] {
        let path = if effect == "allow" { REVOKE } else { GRANTS };
        let refused = client
            .json(
                M::POST,
                path,
                path,
                t,
                json(json!({
                    "holder": {"kind": "api_key", "id": me.0},
                    "major": "user",
                    "minor": "write",
                    "effect": effect,
                })),
                S::BAD_REQUEST,
            )
            .await;
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|error| error.contains("would take user:write from you")),
            "{refused}"
        );
    }
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
            json(json!({"display_name": "Me", "timezone": "Europe/Paris", "queue": "mine"})),
            S::OK,
        )
        .await;
    assert_eq!(changed["display_name"], "Me");
    assert_eq!(changed["timezone"], "Europe/Paris");
    assert_eq!(changed["queue"], "mine");
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

/// The ping answers with no credential, with one that isn't valid and with a valid one, and with the
/// database gone, so it checks nothing but that the API answers. It closes the stack's pool, so it
/// goes last.
async fn pings(client: &mut Client<'_>, token: &str) {
    let pong = json!({"result": "pong"});
    let wrong = "ace4k_00000000-0000-0000-0000-000000000000_x";
    for credential in [None, Some(wrong), Some(token)] {
        let body = client
            .json(
                Method::GET,
                PING,
                PING,
                credential,
                Send::Nothing,
                StatusCode::OK,
            )
            .await;
        assert_eq!(body, pong, "with {credential:?}");
    }
    let pool = client.stack.test_db.db().pool();
    pool.close().await;
    assert!(pool.is_closed());
    let body = client
        .json(Method::GET, PING, PING, None, Send::Nothing, StatusCode::OK)
        .await;
    assert_eq!(body, pong, "with the database closed");
}

/// ace3's `observable_types` router: every type the binary has, in name order, with what the registry
/// says of each. This process installs no list, so it's `BUILTIN`; `ace-site-example`'s test sees a
/// site's own type through its binary.
async fn lists_types(client: &mut Client<'_>, token: &str) {
    let body = client
        .json(
            Method::GET,
            TYPES,
            TYPES,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    let types = body["types"].as_array().expect("types");
    let names: Vec<&str> = types.iter().filter_map(|t| t["name"].as_str()).collect();
    let builtin: Vec<&str> = ObservableKind::BUILTIN.iter().map(|k| k.as_str()).collect();
    assert_eq!(names, builtin, "every built-in type, in name order");
    let named = |name: &str| {
        types
            .iter()
            .find(|t| t["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} is listed"))
    };
    assert_eq!(
        named("email_cc"),
        json!({
            "name": "email_cc",
            "parent": "email_address",
            "deprecated": false,
            "default_display_type": "Mail CC",
            "description": ObservableKind::EmailCc.description(),
        })
    );
    assert_eq!(
        named("cidr")["deprecated"],
        true,
        "deprecated types are listed"
    );
    assert_eq!(named("fqdn")["parent"], Value::Null);
}

/// ace3's `crashes` router: failed tasks, one with its inputs, and its download as ace3's zip. The error
/// quotes a hostile file name, and comes back as the string it is.
/// ace3's `email` router: an archived email by its Message-ID, decrypted, its read audited, and the 500
/// of a node with no key, from `keyless`, whose statuses it returns.
async fn email_archive(
    client: &mut Client<'_>,
    keyless: &Stack,
    token: &str,
) -> BTreeSet<(String, String, u16)> {
    let email = b"From: a@example.com\r\nMessage-ID: <a/b@example.com>\r\n\r\nthe body\r\n";
    let (archive_id, _) = client
        .stack
        .archive
        .seed(&ace_core::email_archive::Seed {
            email,
            message_id: "<a/b@example.com>",
            recipients: &["bob@example.com"],
            insert_date: chrono::Utc::now().naive_utc(),
            urls: &[],
        })
        .await
        .expect("archives");
    let audits = audit_count(client.stack).await;
    // a Message-ID can hold a "/", which is why it's a query parameter
    let response = client
        .call(
            Method::GET,
            EMAIL_ARCHIVE,
            &format!("{EMAIL_ARCHIVE}?message_id=%3Ca%2Fb%40example.com%3E"),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "message/rfc822");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.bytes().await.expect("a body").as_ref(), email);
    assert_eq!(audit_count(client.stack).await, audits + 1);
    let row: (String, String, Value) = sqlx::query_as(
        "SELECT target_kind, target_id, details FROM service.audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(client.stack.test_db.db().pool())
    .await
    .expect("the audit row");
    assert_eq!(row.0, "archived_email");
    assert_eq!(row.1, archive_id.to_string());
    assert_eq!(row.2["message_id"], "<a/b@example.com>");
    assert_eq!(row.2["hash"], sha256_hex(email));
    // without its brackets, as ace3 normalizes it
    let response = client
        .call(
            Method::GET,
            EMAIL_ARCHIVE,
            &format!("{EMAIL_ARCHIVE}?message_id=a%2Fb%40example.com"),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    let body = client
        .json(
            Method::GET,
            EMAIL_ARCHIVE,
            &format!("{EMAIL_ARCHIVE}?message_id=%3Cnothing%40example.com%3E"),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    assert_eq!(
        body["error"],
        "no archived email has message id <nothing@example.com>"
    );
    client
        .json(
            Method::GET,
            EMAIL_ARCHIVE,
            EMAIL_ARCHIVE,
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert_eq!(audit_count(client.stack).await, audits + 2);

    // a node with no key can't decrypt one, and says so
    let mut other = Client::new(keyless);
    let reader = key(keyless, &["email:read"]).await;
    let keyless_audits = audit_count(keyless).await;
    let body = other
        .json(
            Method::GET,
            EMAIL_ARCHIVE,
            &format!("{EMAIL_ARCHIVE}?message_id=%3Ca%40example.com%3E"),
            Some(&reader),
            Send::Nothing,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
    assert_eq!(
        body["error"],
        "archived emails cannot be decrypted: no encryption key is configured"
    );
    assert_eq!(audit_count(keyless).await, keyless_audits);
    other.seen
}

async fn crashes(client: &mut Client<'_>, token: &str, root: Uuid, file: i64, bytes: &[u8]) {
    let hostile =
        "the module panicked: \"<img src=x onerror=alert(1)>/../../etc/passwd\"\n\u{fffd}";
    let pool = client.stack.test_db.db().pool();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO queue.tasks (root_id, observable_id, module, state, attempts, error, input_hashes)
         SELECT o.root_id, o.id, 'crasher', 'failed', 3, $3, ARRAY[o.value, repeat('0', 64)]
         FROM analysis.observables o WHERE o.root_id = $1 AND o.id = $2
         RETURNING id",
    )
    .bind(root)
    .bind(file)
    .bind(hostile)
    .fetch_one(pool)
    .await
    .expect("a failed task");
    let sha256 = sha256_hex(bytes);

    let page = client
        .json(
            Method::GET,
            CRASHES,
            CRASHES,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(page["next"], Value::Null);
    let listed = &page["crashes"][0];
    assert_eq!(listed["id"], id);
    assert_eq!(listed["error"], hostile);
    assert_eq!(listed["root"], root.to_string());
    assert_eq!(listed["alerted"], true);
    assert_eq!(listed["module"], "crasher");
    assert_eq!(
        listed["observable"],
        json!({"id": file, "type": "file", "value": sha256})
    );
    assert_eq!(listed["input_hashes"], json!([sha256, "0".repeat(64)]));
    for query in [
        format!("?root={root}&module=crasher&limit=1"),
        "?module=crasher".to_owned(),
    ] {
        let page = client
            .json(
                Method::GET,
                CRASHES,
                &format!("{CRASHES}{query}"),
                Some(token),
                Send::Nothing,
                StatusCode::OK,
            )
            .await;
        assert_eq!(page["crashes"][0]["id"], id, "{query}");
    }
    let page = client
        .json(
            Method::GET,
            CRASHES,
            &format!("{CRASHES}?module=nothing"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(page["crashes"], json!([]));
    for query in ["?limit=0", "?limit=501", "?after=0", "?root=x"] {
        client
            .json(
                Method::GET,
                CRASHES,
                &format!("{CRASHES}{query}"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }

    let detail = client
        .json(
            Method::GET,
            CRASH,
            &format!("{CRASHES}/{id}"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(&detail["crash"], listed);
    assert_eq!(detail["paths"], json!(["mail/invoice.zip"]));
    assert_eq!(detail["root_title"], "a file to download");
    assert_eq!(detail["inputs"][0]["sha256"], sha256);
    assert_eq!(detail["inputs"][0]["present"], true);
    assert_eq!(detail["inputs"][0]["size"], bytes.len());
    assert_eq!(
        detail["inputs"][1],
        json!({"sha256": "0".repeat(64), "present": false, "size": null, "mime_type": null})
    );
    for route in [CRASH, CRASH_DOWNLOAD] {
        client
            .json(
                Method::GET,
                route,
                &route.replace("{id}", "x"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
        let error = client
            .json(
                Method::GET,
                route,
                &route.replace("{id}", &(id + 1000).to_string()),
                Some(token),
                Send::Nothing,
                StatusCode::NOT_FOUND,
            )
            .await;
        assert_eq!(error["error"], format!("no failed task {}", id + 1000));
    }

    let rows = audit_count(client.stack).await;
    let response = client
        .call(
            Method::GET,
            CRASH_DOWNLOAD,
            &format!("{CRASHES}/{id}/download"),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/zip");
    assert_eq!(
        response.headers()["content-disposition"],
        format!("attachment; filename=\"crash-{id}.zip\"")
    );
    let zipped = response.bytes().await.expect("the zip");
    let mut archive = zip::ZipArchive::new(Cursor::new(zipped.to_vec())).expect("a zip");
    let names: BTreeSet<String> = archive
        .file_names()
        .map(|name| name.expect("a name").into_owned())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            format!("task-{id}/task.json"),
            format!("task-{id}/inputs/{sha256}"),
        ])
    );
    assert!(archive.by_index(0).is_err(), "it needs the password");
    let mut read = |name: String| {
        let at = archive.index_for_name(&name).expect("an entry");
        let mut entry = archive.by_index_decrypt(at, b"infected").expect("opens");
        let mut unzipped = Vec::new();
        entry.read_to_end(&mut unzipped).expect("reads");
        unzipped
    };
    assert_eq!(read(format!("task-{id}/inputs/{sha256}")), bytes);
    let manifest: Value =
        serde_json::from_slice(&read(format!("task-{id}/task.json"))).expect("JSON");
    assert_eq!(manifest["crash"]["error"], hostile);
    assert_eq!(
        manifest["omitted"],
        json!([{"sha256": "0".repeat(64), "reason": "the bucket doesn't have it"}])
    );
    assert_eq!(
        audit_count(client.stack).await,
        rows + 1,
        "the download has a row"
    );
    let (action, target): (String, String) =
        sqlx::query_as("SELECT action, target_id FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("the download's row");
    assert_eq!(
        (action.as_str(), target),
        ("download_crash", id.to_string())
    );

    // alert:read alone doesn't read crashes
    let reader = key(client.stack, &["alert:read"]).await;
    for route in [CRASHES, CRASH, CRASH_DOWNLOAD] {
        let error = client
            .json(
                Method::GET,
                route,
                &route.replace("{id}", &id.to_string()),
                Some(&reader),
                Send::Nothing,
                StatusCode::FORBIDDEN,
            )
            .await;
        assert_eq!(error["error"], "this needs crash:read");
    }
}

/// A kept QA match of `uuid` on the submitted file, held as the core's recorder holds one.
async fn qa_match(stack: &Stack, root: Uuid, file: i64, uuid: &str) -> i64 {
    let pool = stack.test_db.db().pool();
    let record = json!({
        "rule": "qa_rule",
        "namespace": "ns",
        "meta": {"uuid": uuid, "modifiers": "qa", "description": "<script>alert(1)</script>"},
        "tags": ["candidate"],
        "commit": "c0ffee",
        "ruleset": null,
        "target": "mail/invoice.zip",
        "strings": [[4, "$a", {"base64": "RVZJTA=="}], [9, "$a", {"base64": "RVZJTA=="}]],
        "context": [],
        "match_context": [],
    });
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO yara.qa_matches
             (signature_uuid, signature_version, rule, namespace, sha256, file_path, root_id,
              observable_id, match, expires_at)
         SELECT $3, 'c0ffee', 'qa_rule', 'ns', o.value, $4, o.root_id, o.id, $5,
                now() + interval '30 days'
         FROM analysis.observables o WHERE o.root_id = $1 AND o.id = $2
         RETURNING id",
    )
    .bind(root)
    .bind(file)
    .bind(uuid)
    .bind("mail/<b>\u{fffd}/../../etc/passwd")
    .bind(record)
    .fetch_one(pool)
    .await
    .expect("a QA match");
    sqlx::query(
        "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id, expires_at)
         SELECT 'alert_files', sha256, 'yara_qa', id::text, expires_at
         FROM yara.qa_matches WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("holds the file");
    id
}

/// The names in a zip, and a function that reads one with ace3's password.
fn unzip(zipped: &[u8]) -> (BTreeSet<String>, impl FnMut(&str) -> Vec<u8>) {
    let mut archive = zip::ZipArchive::new(Cursor::new(zipped.to_vec())).expect("a zip");
    let names: BTreeSet<String> = archive
        .file_names()
        .map(|name| name.expect("a name").into_owned())
        .collect();
    assert!(archive.by_index(0).is_err(), "it needs the password");
    let read = move |name: &str| {
        let at = archive.index_for_name(name).expect("an entry");
        let mut entry = archive.by_index_decrypt(at, b"infected").expect("opens");
        let mut unzipped = Vec::new();
        entry.read_to_end(&mut unzipped).expect("reads");
        unzipped
    };
    (names, read)
}

/// ace3's `yara_qa` router: the rules in QA mode and with matches, one rule, its matches, one match and
/// its record, the downloads, and a purge. A rule's meta and a file's path come back as the text they are.
async fn yara_qa(client: &mut Client<'_>, token: &str, root: Uuid, file: i64, bytes: &[u8]) {
    const UUID: &str = "4c3c8330-545d-4673-9a7c-7bd4597d0098";
    let hostile = "../x <y>";
    let pool = client.stack.test_db.db().pool();
    let id = qa_match(client.stack, root, file, UUID).await;
    let other = qa_match(client.stack, root, file, hostile).await;
    sqlx::query(
        "INSERT INTO yara.rulesets
             (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules)
         VALUES (repeat('b', 64), 'c0ffee', 'tree', 'sources', $1, '[]', '[]', $2)",
    )
    .bind(ace_core::rulesets::YARA_X_VERSION)
    .bind(json!([
        {"namespace": "ns", "path": "ns/qa.yar", "name": "qa_rule", "uuid": UUID,
         "enabled": true, "tags": ["candidate"]},
        {"namespace": "ns", "path": "ns/new.yar", "name": "never_matched", "uuid": "never",
         "enabled": true, "tags": []},
    ]))
    .execute(pool)
    .await
    .expect("a ruleset");
    let sha256 = sha256_hex(bytes);

    let page = client
        .json(
            Method::GET,
            QA_RULES,
            QA_RULES,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(page["total"], 3);
    assert_eq!(
        (page["limit"].clone(), page["offset"].clone()),
        (json!(50), json!(0))
    );
    assert_eq!(page["ruleset"]["commit"], "c0ffee");
    assert_eq!(page["ruleset"]["qa_rules_recorded"], true);
    let names: Vec<&str> = page["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|r| r["signature_uuid"].as_str().expect("a uuid"))
        .collect();
    assert_eq!(names, ["never", hostile, UUID], "by name, then uuid");
    let listed = &page["rules"][2];
    assert_eq!(listed["status"], "qa");
    assert_eq!(listed["path"], "ns/qa.yar");
    assert_eq!(
        (
            listed["match_count"].clone(),
            listed["stored_count"].clone()
        ),
        (json!(1), json!(1))
    );
    assert_eq!(page["rules"][1]["status"], "not_qa");
    let page = client
        .json(
            Method::GET,
            QA_RULES,
            &format!("{QA_RULES}?status=not_qa&has_matches=true&sort=match_count&descending=true&limit=1&q=X"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(page["rules"][0]["signature_uuid"], hostile);
    assert_eq!(page["total"], 1);
    for query in ["?limit=0", "?status=missing", "?sort=size"] {
        client
            .json(
                Method::GET,
                QA_RULES,
                &format!("{QA_RULES}{query}"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }

    let detail = client
        .json(
            Method::GET,
            QA_RULE,
            &QA_RULE.replace("{uuid}", UUID),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(&detail["rule"], listed);
    assert_eq!(detail["versions"][0]["signature_version"], "c0ffee");
    assert_eq!(detail["versions"][0]["match_count"], 1);
    let error = client
        .json(
            Method::GET,
            QA_RULE,
            &QA_RULE.replace("{uuid}", "nothing"),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    assert_eq!(
        error["error"],
        "no rule in QA mode and no QA matches with that uuid"
    );
    for route in [QA_RULE, QA_RULE_MATCHES] {
        client
            .json(
                Method::GET,
                route,
                &route.replace("{uuid}", "%FF"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }

    let page = client
        .json(
            Method::GET,
            QA_RULE_MATCHES,
            &format!(
                "{}?version=c0ffee&limit=10",
                QA_RULE_MATCHES.replace("{uuid}", UUID)
            ),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(page["next"], Value::Null);
    let kept = &page["matches"][0];
    assert_eq!(kept["id"], id);
    assert_eq!(kept["sha256"], sha256);
    assert_eq!(
        kept["file_path"], "mail/<b>\u{fffd}/../../etc/passwd",
        "a path is data"
    );
    assert_eq!(kept["file_size"], bytes.len());
    assert_eq!(
        (kept["root"].clone(), kept["alerted"].clone()),
        (json!(root), json!(true))
    );
    client
        .json(
            Method::GET,
            QA_RULE_MATCHES,
            &format!("{}?after=x", QA_RULE_MATCHES.replace("{uuid}", UUID)),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;

    let detail = client
        .json(
            Method::GET,
            QA_MATCH,
            &QA_MATCH.replace("{id}", &id.to_string()),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(&detail["match"], kept);
    assert_eq!(
        detail["summary"]["meta"]["description"],
        "<script>alert(1)</script>"
    );
    assert_eq!(
        detail["summary"]["strings"],
        json!([{"identifier": "$a", "count": 2, "first_offset": 4}])
    );
    let response = client
        .call(
            Method::GET,
            QA_RECORD,
            &QA_RECORD.replace("{id}", &id.to_string()),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(
        response.headers()["content-disposition"],
        format!("inline; filename=\"yara-qa-match-{id}.json\"")
    );
    let record: Value = response.json().await.expect("JSON");
    assert_eq!(record["strings"][1][0], 9, "the whole record");
    for route in [QA_MATCH, QA_RECORD, QA_MATCH_DOWNLOAD] {
        client
            .json(
                Method::GET,
                route,
                &route.replace("{id}", "x"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
        let error = client
            .json(
                Method::GET,
                route,
                &route.replace("{id}", &(other + 1000).to_string()),
                Some(token),
                Send::Nothing,
                StatusCode::NOT_FOUND,
            )
            .await;
        assert_eq!(
            error["error"],
            format!("no kept YARA QA match {}", other + 1000)
        );
    }

    // one match's download, and a rule's: entries are named by id and hash, never by the file's path
    let rows = audit_count(client.stack).await;
    let response = client
        .call(
            Method::GET,
            QA_MATCH_DOWNLOAD,
            &QA_MATCH_DOWNLOAD.replace("{id}", &id.to_string()),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/zip");
    let label = format!("yara-qa-match-{id}");
    assert_eq!(
        response.headers()["content-disposition"],
        format!("attachment; filename=\"{label}.zip\"")
    );
    let zipped = response.bytes().await.expect("the zip");
    let (names, mut read) = unzip(&zipped);
    assert_eq!(
        names,
        BTreeSet::from([
            format!("{label}/manifest.json"),
            format!("{label}/{id}/match.json"),
            format!("{label}/{id}/{sha256}"),
        ])
    );
    assert_eq!(read(&format!("{label}/{id}/{sha256}")), bytes);
    let manifest: Value =
        serde_json::from_slice(&read(&format!("{label}/manifest.json"))).expect("JSON");
    assert_eq!(manifest["matches"][0]["file_path"], kept["file_path"]);
    assert_eq!(
        manifest["matches"][0]["file"],
        format!("{label}/{id}/{sha256}")
    );
    let record: Value =
        serde_json::from_slice(&read(&format!("{label}/{id}/match.json"))).expect("JSON");
    assert_eq!(record["rule"], "qa_rule");
    let (action, target): (String, String) =
        sqlx::query_as("SELECT action, target_id FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("the download's row");
    assert_eq!(
        (action.as_str(), target),
        ("download_qa_match", id.to_string())
    );

    // a uuid that isn't plain doesn't name the archive
    let response = client
        .call(
            Method::GET,
            QA_RULE_DOWNLOAD,
            &QA_RULE_DOWNLOAD.replace("{uuid}", "..%2Fx%20%3Cy%3E"),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"yara-qa-rule.zip\""
    );
    let zipped = response.bytes().await.expect("the zip");
    let (names, _) = unzip(&zipped);
    assert!(
        names.contains(&format!("yara-qa-rule/{other}/{sha256}")),
        "{names:?}"
    );
    let response = client
        .call(
            Method::GET,
            QA_RULE_DOWNLOAD,
            &format!(
                "{}?match_ids={id}",
                QA_RULE_DOWNLOAD.replace("{uuid}", UUID)
            ),
            Some(token),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-disposition"],
        format!("attachment; filename=\"yara-qa-{UUID}.zip\"")
    );
    assert_eq!(
        audit_count(client.stack).await,
        rows + 3,
        "each download has a row"
    );
    let many: Vec<String> = (1..=501).map(|n| n.to_string()).collect();
    for (query, status) in [
        ("?match_ids=x".to_owned(), StatusCode::BAD_REQUEST),
        (format!("?match_ids={other}"), StatusCode::NOT_FOUND),
        ("?version=none".to_owned(), StatusCode::NOT_FOUND),
        (
            format!("?match_ids={}", many.join(",")),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        client
            .json(
                Method::GET,
                QA_RULE_DOWNLOAD,
                &format!("{}{query}", QA_RULE_DOWNLOAD.replace("{uuid}", UUID)),
                Some(token),
                Send::Nothing,
                status,
            )
            .await;
    }

    // a purge: refused bodies first, then one that removes the match and its hold, with a row
    let purge = QA_PURGE.replace("{uuid}", UUID);
    for body in [
        Send::Json(json!({})),
        Send::Json(json!({"versions": ["c0ffee"], "match_ids": [id]})),
        Send::Json(json!({"match_ids": [id], "extra": 1})),
        Send::Bytes(b"not json".to_vec()),
    ] {
        client
            .json(
                Method::POST,
                QA_PURGE,
                &purge,
                Some(token),
                body,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            Method::POST,
            QA_PURGE,
            &purge,
            Some(token),
            too_large(),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
    let rows = audit_count(client.stack).await;
    let purged = client
        .json(
            Method::POST,
            QA_PURGE,
            &purge,
            Some(token),
            Send::Json(json!({"match_ids": [id, other], "reason": "noisy"})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(purged, json!({"purged": [id], "remaining": 0}));
    assert_eq!(audit_count(client.stack).await, rows + 1);
    let (action, target, reason): (String, String, Value) = sqlx::query_as(
        "SELECT action, target_id, details->'reason' FROM service.audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("the purge's row");
    assert_eq!(
        (action.as_str(), target.as_str(), reason),
        ("purge_qa_matches", UUID, json!("noisy"))
    );
    let holds: Vec<String> = sqlx::query_scalar(
        "SELECT holder_kind || ':' || holder_id FROM store.holds WHERE sha256 = $1 ORDER BY 1",
    )
    .bind(&sha256)
    .fetch_all(pool)
    .await
    .expect("the holds");
    assert_eq!(holds, [format!("root:{root}"), format!("yara_qa:{other}")]);
    client
        .json(
            Method::GET,
            QA_MATCH,
            &QA_MATCH.replace("{id}", &id.to_string()),
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;

    // signature:read reads and doesn't download or purge; alert:read does neither
    let reader = key(client.stack, &["signature:read"]).await;
    client
        .json(
            Method::GET,
            QA_RULES,
            QA_RULES,
            Some(&reader),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    for (route, path) in [
        (
            QA_RULE_DOWNLOAD,
            QA_RULE_DOWNLOAD.replace("{uuid}", "..%2Fx%20%3Cy%3E"),
        ),
        (
            QA_MATCH_DOWNLOAD,
            QA_MATCH_DOWNLOAD.replace("{id}", &other.to_string()),
        ),
    ] {
        let error = client
            .json(
                Method::GET,
                route,
                &path,
                Some(&reader),
                Send::Nothing,
                StatusCode::FORBIDDEN,
            )
            .await;
        assert_eq!(error["error"], "this needs signature:download");
    }
    let error = client
        .json(
            Method::POST,
            QA_PURGE,
            &purge,
            Some(&reader),
            Send::Json(json!({"match_ids": [other]})),
            StatusCode::FORBIDDEN,
        )
        .await;
    assert_eq!(error["error"], "this needs signature:qa_purge");
    let alerts = key(client.stack, &["alert:read"]).await;
    let error = client
        .json(
            Method::GET,
            QA_RULES,
            QA_RULES,
            Some(&alerts),
            Send::Nothing,
            StatusCode::FORBIDDEN,
        )
        .await;
    assert_eq!(error["error"], "this needs signature:read");
}

/// A user holding these, with a session's token.
async fn session_of(stack: &Stack, name: &str, grants: &[&str]) -> (Uuid, String) {
    let id = stack
        .service
        .create_user(
            &bootstrap(),
            &Username::new(name).expect("a name"),
            Password::new(PASSWORD),
            &Profile::default(),
        )
        .await
        .expect("makes a user");
    for grant in grants {
        let (major, minor) = grant.split_once(':').expect("a grant");
        stack
            .service
            .grant(
                &bootstrap(),
                &Holder::User(id),
                &PermissionPattern::new(major, minor).expect("a pattern"),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
    let session = stack
        .service
        .login(name, Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    (id.0, session.token.expose().to_owned())
}

/// ace3's `observable_comments` router: a comment on a type and value, listed for it from any alert,
/// written by a person, and changed or deleted only by its author. Its text comes back as sent.
async fn comments(client: &mut Client<'_>, file_alert: Uuid, file_bytes: &[u8]) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let grants = ["observable:read", "observable:write"];
    let (alice, alices) = session_of(stack, "commenter", &grants).await;
    let (_, bobs) = session_of(stack, "other-commenter", &grants).await;
    let (a, b) = (Some(alices.as_str()), Some(bobs.as_str()));
    let ownerless = key(stack, &["observable:write"]).await;
    let reader = bootstrap_reader(stack).await;
    let rows = audit_count(stack).await;

    let text = "<script>alert(1)</script>\r\n../../etc/passwd \u{FFFD}";
    let sha256 = sha256_hex(file_bytes);
    let added = client
        .json(
            M::POST,
            COMMENTS,
            COMMENTS,
            a,
            json(json!({"type": "file", "value": sha256.to_uppercase(), "comment": text})),
            S::CREATED,
        )
        .await;
    assert_eq!(added["type"], "file");
    assert_eq!(added["value"], sha256, "matched as the lookup matches");
    assert_eq!(added["comment"], text, "as it was sent");
    assert_eq!(added["author"]["id"], json!(alice));
    assert_eq!(added["author"]["username"], "commenter");
    assert_eq!(added["created_by"]["kind"], "user");
    assert_eq!(added["edited_at"], Value::Null);
    let id = added["id"].as_i64().expect("an id");
    assert_eq!(audit_count(stack).await, rows + 1);

    // listed for the file, which the submitted alert holds, and in that alert's comments
    let list = format!("{COMMENTS}?type=file&value={sha256}");
    let listed = client
        .json(M::GET, COMMENTS, &list, b, Send::Nothing, S::OK)
        .await;
    assert_eq!(listed, json!({"comments": [added.clone()]}));
    let in_alert = stack
        .service
        .alert_observable_comments(&reader, file_alert)
        .await
        .expect("reads");
    assert_eq!(in_alert.len(), 1);
    assert_eq!(in_alert[0].id, id);
    for bad in [
        format!("{COMMENTS}?type=no_such_type&value=x"),
        format!("{COMMENTS}?type=fqdn"),
    ] {
        client
            .json(M::GET, COMMENTS, &bad, a, Send::Nothing, S::BAD_REQUEST)
            .await;
    }

    // the author edits it; another user can't, and a key with no owner can't write one
    let one = at(COMMENT, id, "");
    let edited = client
        .json(
            M::PATCH,
            COMMENT,
            &one,
            a,
            json(json!({"comment": "the dropper"})),
            S::OK,
        )
        .await;
    assert_eq!(edited["comment"], "the dropper");
    assert!(edited["edited_at"].is_string(), "{edited}");
    let error = client
        .json(
            M::PATCH,
            COMMENT,
            &one,
            b,
            json(json!({"comment": "mine now"})),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(
        error["error"],
        "only a comment's author can change or delete it"
    );
    client
        .json(M::DELETE, COMMENT, &one, b, Send::Nothing, S::FORBIDDEN)
        .await;
    let error = client
        .json(
            M::POST,
            COMMENTS,
            COMMENTS,
            Some(&ownerless),
            json(json!({"type": "fqdn", "value": "a.example", "comment": "x"})),
            S::FORBIDDEN,
        )
        .await;
    assert!(
        error["error"]
            .as_str()
            .is_some_and(|e| e.starts_with("a comment is a person's")),
        "{error}"
    );

    // what isn't taken
    for body in [
        json!({"type": "fqdn", "value": "a.example", "comment": "  "}),
        json!({"type": "fqdn", "value": "a.example", "comment": "x".repeat(16385)}),
        json!({"type": "no_such_type", "value": "a.example", "comment": "x"}),
        json!({"type": "fqdn", "value": "a.example"}),
    ] {
        client
            .json(M::POST, COMMENTS, COMMENTS, a, json(body), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::PATCH,
            COMMENT,
            &one,
            a,
            json(json!({"comment": ""})),
            S::BAD_REQUEST,
        )
        .await;
    for route in [COMMENTS, COMMENT] {
        let method = if route == COMMENTS { M::POST } else { M::PATCH };
        let path = at(route, id, "");
        let response = client.call(method, route, &path, a, too_large()).await;
        assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE, "{route}");
    }
    let not_an_id = at(COMMENT, "x", "");
    client
        .json(
            M::PATCH,
            COMMENT,
            &not_an_id,
            a,
            json(json!({"comment": "x"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::DELETE,
            COMMENT,
            &not_an_id,
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    assert_eq!(
        audit_count(stack).await,
        rows + 2,
        "only the add and the edit"
    );

    // the author deletes it, and then it isn't there
    let response = client
        .call(M::DELETE, COMMENT, &one, a, Send::Nothing)
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    assert_eq!(audit_count(stack).await, rows + 3);
    let listed = client
        .json(M::GET, COMMENTS, &list, b, Send::Nothing, S::OK)
        .await;
    assert_eq!(listed, json!({"comments": []}));
    client
        .json(
            M::PATCH,
            COMMENT,
            &one,
            a,
            json(json!({"comment": "x"})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::DELETE, COMMENT, &one, a, Send::Nothing, S::NOT_FOUND)
        .await;
}

/// A component that may read alerts, for a service call the API has no route for yet.
async fn bootstrap_reader(stack: &Stack) -> Actor {
    let reader = Actor::Internal {
        id: Component::new("comment-reader").expect("a valid name"),
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::Component(Component::new("comment-reader").expect("a valid name")),
            &PermissionPattern::new("alert", "read").expect("a pattern"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    reader
}

/// ace3's `user_preferences` router: the caller's own, with no grant, defaults filled in, a value checked
/// by its key, and refused to a key.
async fn preferences(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let (_, token) = session_of(stack, "prefers", &[]).await;
    let t = Some(token.as_str());
    let theme = fill(PREFERENCE, Uuid::nil(), 0);

    let all = client
        .json(M::GET, PREFERENCES, PREFERENCES, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        all,
        json!({"preferences": [
            {"key": "theme", "value": {"mode": "system"}, "updated_at": null, "is_default": true},
            {"key": "alert_sections", "value": {"sections": {}}, "updated_at": null, "is_default": true},
            {
                "key": "manage_columns",
                "value": {"order": ["date", "description", "queue", "disposition", "status"], "hidden": []},
                "updated_at": null,
                "is_default": true,
            },
        ]})
    );
    let one = client
        .json(M::GET, PREFERENCE, &theme, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(one, all["preferences"][0]);

    let before = audit_count(stack).await;
    let set = client
        .json(
            M::PUT,
            PREFERENCE,
            &theme,
            t,
            Send::Json(json!({"mode": "dark"})),
            S::OK,
        )
        .await;
    assert_eq!(set["value"], json!({"mode": "dark"}));
    assert_eq!(set["is_default"], false);
    assert!(set["updated_at"].is_string(), "{set}");
    assert_eq!(audit_count(stack).await, before + 1, "a set has a row");
    let read = client
        .json(M::GET, PREFERENCE, &theme, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(read, set);
    // left out is the default, as ace3's schema fills it in
    let set = client
        .json(M::PUT, PREFERENCE, &theme, t, Send::Json(json!({})), S::OK)
        .await;
    assert_eq!(set["value"], json!({"mode": "system"}));
    assert_eq!(
        set["is_default"], false,
        "stored, even though it's the default's value"
    );

    for bad in [
        json!({"mode": "neon"}),
        json!({"mode": "dark", "extra": true}),
        json!(["dark"]),
    ] {
        let error = client
            .json(
                M::PUT,
                PREFERENCE,
                &theme,
                t,
                Send::Json(bad.clone()),
                S::BAD_REQUEST,
            )
            .await;
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|e| e.contains("theme preference")),
            "{bad}: {error}"
        );
    }
    client
        .json(
            M::PUT,
            PREFERENCE,
            &theme,
            t,
            Send::Bytes(format!("{{\"mode\": \"{}\"}}", "x".repeat(MAX_JSON)).into_bytes()),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    // 5.8's alert_sections: section ids as ace3's schema has them, at most 100
    let sections = "/api/users/v1/me/preferences/alert_sections";
    let set = client
        .json(
            M::PUT,
            PREFERENCE,
            sections,
            t,
            Send::Json(json!({"sections": {"alert_details": false, "url_clicks": true}})),
            S::OK,
        )
        .await;
    assert_eq!(
        set["value"],
        json!({"sections": {"alert_details": false, "url_clicks": true}})
    );
    let many: serde_json::Map<String, Value> =
        (0..101).map(|i| (format!("s{i}"), json!(true))).collect();
    for bad in [
        json!({"sections": {"Alert Details": true}}),
        json!({"sections": {"": true}}),
        json!({"sections": {"x".repeat(65): true}}),
        json!({"sections": {"alert_details": "yes"}}),
        json!({"sections": many}),
        json!({"sections": {}, "extra": 1}),
    ] {
        let error = client
            .json(
                M::PUT,
                PREFERENCE,
                sections,
                t,
                Send::Json(bad.clone()),
                S::BAD_REQUEST,
            )
            .await;
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|e| e.contains("alert_sections preference")),
            "{bad}: {error}"
        );
    }
    let read = client
        .json(M::GET, PREFERENCE, sections, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(read, set, "a refused value changes nothing");

    let unknown = "/api/users/v1/me/preferences/search_columns";
    for method in [M::GET, M::DELETE] {
        let error = client
            .json(method, PREFERENCE, unknown, t, Send::Nothing, S::NOT_FOUND)
            .await;
        assert_eq!(error["error"], "no preference is named \"search_columns\"");
    }
    client
        .json(
            M::PUT,
            PREFERENCE,
            unknown,
            t,
            Send::Json(json!({"mode": "dark"})),
            S::NOT_FOUND,
        )
        .await;

    let reset = client
        .json(M::DELETE, PREFERENCE, &theme, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        reset,
        json!({"key": "theme", "value": {"mode": "system"}, "updated_at": null, "is_default": true})
    );
    let before = audit_count(stack).await;
    client
        .json(M::DELETE, PREFERENCE, &theme, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        audit_count(stack).await,
        before,
        "a reset of a default has no row"
    );

    // Another site's page can't change it with the analyst's cookie.
    let refused = stack
        .http
        .put(format!("{}{theme}", stack.url))
        .header("cookie", format!("ace4_session={token}"))
        .header("origin", "https://evil.example")
        .json(&json!({"mode": "halloween"}))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), 403);
    let read = client
        .json(M::GET, PREFERENCE, &theme, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(read["value"], json!({"mode": "system"}));
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
            "crash:read",
            "email:read",
            "signature:read",
            "signature:download",
            "signature:qa_purge",
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
    reads_graph(&mut client, &token).await;
    detection_points(&mut client, &token, id).await;
    verdicts(&mut client, &token).await;
    downloads(&mut client, &token, id, file, &bytes).await;
    dispositions(&mut client, &token).await;
    looks_up(&mut client, &token, id, &bytes).await;
    lists_types(&mut client, &token).await;
    let admin = key(&stack, &["user:read", "user:write"]).await;
    manages_users(&mut client, &admin).await;
    serves_me(&mut client).await;
    crashes(&mut client, &token, id, file, &bytes).await;
    let keyless = stack_with(ace_core::email_archive::ArchiveConfig::default()).await;
    let seen = email_archive(&mut client, &keyless, &token).await;
    client.seen.extend(seen);
    commands(&mut client).await;
    yara_qa(&mut client, &token, id, file, &bytes).await;
    comments(&mut client, id, &bytes).await;
    preferences(&mut client).await;
    filters_and_exports(&mut client, &token).await;
    saved_filters(&mut client).await;
    events(&mut client).await;
    lists_router(&mut client).await;
    detection_router(&mut client).await;
    hunts_router(&mut client).await;
    remediation_routers(&mut client).await;
    svs_samples(&mut client, &token).await;
    svs_validations(&mut client, &token).await;
    svs_catalog(&mut client).await;
    svs_runs(&mut client).await;
    pings(&mut client, &token).await;

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

impl Client<'_> {
    /// Calls `route` and gives the status, the content type and the body as text.
    async fn text(&mut self, route: &str, path: &str, token: &str) -> (StatusCode, String, String) {
        let response = self
            .call(Method::GET, route, path, Some(token), Send::Nothing)
            .await;
        let status = response.status();
        let kind = response
            .headers()
            .get("content-type")
            .and_then(|kind| kind.to_str().ok())
            .unwrap_or("")
            .to_owned();
        (status, kind, response.text().await.expect("a body"))
    }
}

/// PLAN.md 5.10: the alert list's filters and orders, its exports and the detection points', with CSV's
/// cells guarded against formulas, and the filter screens' descriptor and share-link encoding.
async fn filters_and_exports(client: &mut Client<'_>, token: &str) {
    let stack = client.stack;
    let titles = [
        "=HYPERLINK(\"http://evil\")",
        "+plain, \"quoted\"",
        "@third\nline",
    ];
    let mut made = Vec::new();
    for title in titles {
        made.push(alert(stack, title, &[(ObservableKind::Fqdn, "csv.example")]).await);
    }
    let ids = |page: &Value| -> Vec<String> {
        page["alerts"]
            .as_array()
            .expect("alerts")
            .iter()
            .map(|a| a["id"].as_str().expect("an id").to_owned())
            .collect()
    };
    let page = client
        .json(
            Method::GET,
            LIST,
            &format!("{LIST}?f=observable:fqdn:csv.example&sort=description&dir=asc&limit=2"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        ids(&page),
        [made[1].to_string(), made[0].to_string()],
        "by the title's bytes"
    );
    assert_eq!(page["total"], 3);
    let next = page["next"].as_str().expect("more").to_owned();
    let rest = client
        .json(
            Method::GET,
            LIST,
            &format!(
                "{LIST}?f=observable:fqdn:csv.example&sort=description&dir=asc&limit=2&after={next}"
            ),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(ids(&rest), [made[2].to_string()]);
    assert_eq!(rest["next"], Value::Null);
    let page = client
        .json(
            Method::GET,
            LIST,
            &format!("{LIST}?f=description:HYPERLINK&tz=America/New_York"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(ids(&page), [made[0].to_string()]);
    // the queue order (PLAN.md 7.13): each alert has its queue, a formula in one is data, and the cursor
    // carries the queue its last alert was read in
    for (alert, queue) in [(made[0], "=cmd|' /C calc'!A0"), (made[1], "night.shift 2")] {
        sqlx::query("UPDATE analysis.roots SET queue = $2 WHERE id = $1")
            .bind(alert)
            .bind(queue)
            .execute(stack.test_db.db().pool())
            .await
            .expect("sets the queue");
    }
    let by_queue = format!("{LIST}?f=observable:fqdn:csv.example&sort=queue&dir=asc&limit=2");
    let page = client
        .json(
            Method::GET,
            LIST,
            &by_queue,
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        ids(&page),
        [made[0].to_string(), made[2].to_string()],
        "by the queue's bytes: =cmd…, default, night.shift 2"
    );
    assert_eq!(page["alerts"][0]["queue"], "=cmd|' /C calc'!A0");
    assert_eq!(page["alerts"][1]["queue"], "default");
    let next = page["next"].as_str().expect("more").to_owned();
    assert_eq!(next, format!("queue.asc.{}.default", made[2]));
    let rest = client
        .json(
            Method::GET,
            LIST,
            &format!("{by_queue}&after={next}"),
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(ids(&rest), [made[1].to_string()]);
    assert_eq!(rest["alerts"][0]["queue"], "night.shift 2");
    let unknown = client
        .json(
            Method::GET,
            LIST,
            &format!("{LIST}?sort=owner"),
            Some(token),
            Send::Nothing,
            StatusCode::BAD_REQUEST,
        )
        .await;
    assert_eq!(
        unknown["error"],
        "sort is alert_date, description, disposition or queue, not \"owner\""
    );
    for bad in [
        "?f=nope:x",
        "?f=owner:alice",
        "?f=queue:%20",
        "?f=tag:a,,b",
        "?f=",
        "?sort=owner",
        "?dir=up",
        "?tz=Mars/Base",
        "?limit=1&limit=2",
        &format!("?sort=description&after={}", made[0]),
    ] {
        client
            .json(
                Method::GET,
                LIST,
                &format!("{LIST}{bad}"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }

    // the exports: the list's filters and order, everything to the end, a cell guarded against formulas
    let two = "f=observable:fqdn:csv.example&f=!description:third&sort=description&dir=asc";
    let (status, kind, csv) = client
        .text(ALERT_CSV, &format!("{ALERT_CSV}?{two}"), token)
        .await;
    assert_eq!(status, StatusCode::OK, "{csv}");
    assert_eq!(kind, "text/csv; charset=utf-8");
    let lines: Vec<&str> = csv.split("\r\n").collect();
    assert_eq!(lines.len(), 4, "a header, two rows and the end: {csv:?}");
    assert!(lines[0].starts_with("id,title,analysis_mode,"), "{csv}");
    assert!(lines[0].ends_with(",analysis,queue"), "{csv}");
    // a queue that starts a formula is guarded as a title is
    assert!(
        lines[2].ends_with(",'=cmd|' /C calc'!A0")
            || lines[2].ends_with(r#","'=cmd|' /C calc'!A0""#),
        "{csv}"
    );
    assert!(lines[1].ends_with(",night.shift 2"), "{csv}");
    assert!(
        lines[1].contains(r#","'+plain, ""quoted""","#)
            || lines[1].contains(r#""'+plain, ""quoted""""#),
        "{csv}"
    );
    assert!(
        lines[2].contains(r#""'=HYPERLINK(""http://evil"")""#),
        "{csv}"
    );
    assert!(
        !csv.contains(",=") && !csv.contains(",+"),
        "no cell starts a formula: {csv}"
    );
    let (status, kind, ndjson) = client
        .text(ALERT_NDJSON, &format!("{ALERT_NDJSON}?{two}"), token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kind, "application/x-ndjson");
    let rows: Vec<Value> = ndjson
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["title"], titles[0], "NDJSON is the data as it is");
    assert_eq!(rows[1]["queue"], "=cmd|' /C calc'!A0");
    for route in [ALERT_CSV, ALERT_NDJSON] {
        let (status, _, body) = client
            .text(
                route,
                &format!("{route}?f=observable:fqdn:csv.example"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        let (status, _, _) = client
            .text(route, &format!("{route}?f=nope:x"), token)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // the detection points' filters and exports
    let target = made[0];
    detection(
        stack,
        target,
        "=cmd|' /C calc'!A0",
        Some(json!({"rule": "-2+3"})),
    )
    .await;
    detection(stack, target, "@SUM(1)", None).await;
    let signature = "b5a1d3f2-0000-4000-8000-000000000001";
    for (query, count) in [
        (format!("alert={target}&f=signature:{signature}:abc123"), 2),
        (format!("alert={target}&f=!signature:{signature}"), 0),
        (format!("alert={target}&f=family:hunt"), 0),
        (
            format!("alert={target}&changed_since=2000-01-01T00:00:00"),
            2,
        ),
        (
            format!("alert={target}&changed_since=2999-01-01T00:00:00Z"),
            0,
        ),
        (format!("alert={target}&f=alert_date:-1d&tz=Asia/Tokyo"), 2),
    ] {
        let page = client
            .json(
                Method::GET,
                DETECTIONS,
                &format!("{DETECTIONS}?{query}"),
                Some(token),
                Send::Nothing,
                StatusCode::OK,
            )
            .await;
        assert_eq!(
            page["detections"].as_array().map(Vec::len),
            Some(count),
            "{query}"
        );
    }
    for bad in [
        "f=tag:x",
        "f=verdict:maybe",
        "f=queue:%20%20",
        "changed_since=yesterday",
        "tz=x",
    ] {
        client
            .json(
                Method::GET,
                DETECTIONS,
                &format!("{DETECTIONS}?{bad}"),
                Some(token),
                Send::Nothing,
                StatusCode::BAD_REQUEST,
            )
            .await;
    }
    let (status, _, csv) = client
        .text(
            DETECTION_CSV,
            &format!("{DETECTION_CSV}?alert={target}"),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{csv}");
    assert!(csv.starts_with("id,alert,observable_id,"), "{csv}");
    assert!(
        csv.contains(r#""'=cmd|' /C calc'!A0""#) || csv.contains("'=cmd|' /C calc'!A0"),
        "{csv}"
    );
    assert!(csv.contains(",'@SUM(1),"), "{csv}");
    assert!(
        csv.contains(r#""{""rule"":""-2+3""}""#),
        "details are JSON, quoted: {csv}"
    );
    let (status, _, ndjson) = client
        .text(
            DETECTION_NDJSON,
            &format!("{DETECTION_NDJSON}?alert={target}"),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ndjson.lines().count(), 2);
    detection(stack, target, "a third", None).await;
    for route in [DETECTION_CSV, DETECTION_NDJSON] {
        let (status, _, _) = client
            .text(route, &format!("{route}?alert={target}"), token)
            .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _, _) = client.text(route, &format!("{route}?f=tag:x"), token).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = client
            .text(route, &format!("{route}?alert={}", Uuid::nil()), token)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // the screens' descriptors and the share-link encoding
    let screen = client
        .json(
            Method::GET,
            SCREEN,
            "/api/filters/v1/screens/alerts",
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert!(
        screen["filters"]
            .as_array()
            .expect("filters")
            .iter()
            .any(|f| f["slug"] == "alert_date" && f["kind"] == "date_range")
    );
    // the Disposition filter offers the site's dispositions, in their order, a site's own after ace3's
    let options = screen["filters"]
        .as_array()
        .expect("filters")
        .iter()
        .find(|f| f["slug"] == "disposition")
        .map(|f| f["options"].clone())
        .expect("the disposition filter");
    let options: Vec<&str> = options
        .as_array()
        .expect("options")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(options.first(), Some(&"OPEN"));
    assert_eq!(
        options[options.len() - 3..],
        ["SIMULATED", "SITE_CHECKED", "SITE_SWEEP"]
    );
    // the Queue filter came with alert routing (7.13)
    assert!(
        screen["filters"]
            .as_array()
            .expect("filters")
            .iter()
            .any(|f| f["slug"] == "queue" && f["kind"] == "multi")
    );
    assert!(
        !screen["left_out"]
            .as_array()
            .expect("left out")
            .iter()
            .any(|f| f["slug"] == "queue")
    );
    client
        .json(
            Method::GET,
            SCREEN,
            "/api/filters/v1/screens/svs_runs",
            Some(token),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    let encoded = client
        .json(
            Method::POST,
            ENCODE,
            "/api/filters/v1/screens/alerts/encode",
            Some(token),
            Send::Json(json!({"filters": [
                {"name": "Observable", "values": [["url", "https://evil.com/a,b"]]},
                {"name": "Tag", "inverted": true, "values": ["whitelisted"]},
            ]})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        encoded["f"],
        json!([
            "observable:url:https%3A%2F%2Fevil.com%2Fa%2Cb",
            "!tag:whitelisted"
        ])
    );
    for (path, body, status) in [
        (
            "/api/filters/v1/screens/alerts/encode",
            Send::Json(json!({"filters": [{"name": "Owner", "values": ["x"]}]})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/filters/v1/screens/alerts/encode",
            Send::Json(json!({"filters": "not a list"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/filters/v1/screens/nope/encode",
            Send::Json(json!({"filters": []})),
            StatusCode::NOT_FOUND,
        ),
        (
            "/api/filters/v1/screens/alerts/encode",
            too_large(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        client
            .json(Method::POST, ENCODE, path, Some(token), body, status)
            .await;
    }
    let decoded = client
        .json(
            Method::GET,
            DECODE,
            "/api/filters/v1/screens/alerts/decode?f=owner:alice&f=!tag:x",
            Some(token),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        decoded["filters"],
        json!([{"name": "Tag", "inverted": true, "values": ["x"]}])
    );
    assert_eq!(decoded["warnings"].as_array().map(Vec::len), Some(1));
    for (path, status) in [
        (
            "/api/filters/v1/screens/alerts/decode?f=tag:",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/filters/v1/screens/nope/decode?f=tag:x",
            StatusCode::NOT_FOUND,
        ),
    ] {
        client
            .json(
                Method::GET,
                DECODE,
                path,
                Some(token),
                Send::Nothing,
                status,
            )
            .await;
    }
}

/// ace3's `saved_filters` router: a person's own, under the screen's permission, named once, pinned in
/// order, and changed or deleted only by its owner.
async fn saved_filters(client: &mut Client<'_>) {
    let stack = client.stack;
    let (_, mine) = session_of(stack, "saver", &["alert:read"]).await;
    let (_, theirs) = session_of(stack, "other-saver", &["alert:read"]).await;
    let ownerless = key(stack, &["alert:read"]).await;
    let open = json!([{"name": "Disposition", "values": ["OPEN"]}]);
    let listed = client
        .json(
            Method::GET,
            SAVED,
            SAVED,
            Some(&mine),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(listed["saved_filters"], json!([]));
    client
        .json(
            Method::GET,
            SAVED,
            &format!("{SAVED}?screen=nope"),
            Some(&mine),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    // a key with no owner has no saved filters
    client
        .json(
            Method::GET,
            SAVED,
            SAVED,
            Some(&ownerless),
            Send::Nothing,
            StatusCode::FORBIDDEN,
        )
        .await;
    let first = client
        .json(
            Method::POST,
            SAVED,
            SAVED,
            Some(&mine),
            Send::Json(json!({"name": "Open <b>ones</b>", "filters": open, "quick_filter": true})),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(first["name"], "Open <b>ones</b>");
    assert_eq!(first["screen"], "alerts");
    assert_eq!(first["quick_filter_order"], 0);
    assert_eq!(
        first["filters"],
        json!([{"name": "Disposition", "inverted": false, "values": ["OPEN"]}])
    );
    let first_id = first["id"].as_str().expect("an id").to_owned();
    let second = client
        .json(
            Method::POST,
            SAVED,
            &format!("{SAVED}?screen=detection_points"),
            Some(&mine),
            Send::Json(
                json!({"name": "Yara", "filters": [{"name": "Family", "values": ["yara"]}]}),
            ),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(second["screen"], "detection_points");
    let other = client
        .json(
            Method::POST,
            SAVED,
            SAVED,
            Some(&mine),
            Send::Json(json!({"name": "Other", "filters": open})),
            StatusCode::CREATED,
        )
        .await;
    let other_id = other["id"].as_str().expect("an id").to_owned();
    for (path, body, status) in [
        (
            SAVED.to_owned(),
            json!({"name": "Other", "filters": open}),
            StatusCode::CONFLICT,
        ),
        (
            SAVED.to_owned(),
            json!({"name": "Empty", "filters": []}),
            StatusCode::BAD_REQUEST,
        ),
        (
            SAVED.to_owned(),
            json!({"name": "Wrong", "filters": [{"name": "Family", "values": ["yara"]}]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            SAVED.to_owned(),
            json!({"name": "Extra", "filters": open, "owner": "x"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{SAVED}?screen=nope"),
            json!({"name": "x", "filters": open}),
            StatusCode::NOT_FOUND,
        ),
    ] {
        client
            .json(
                Method::POST,
                SAVED,
                &path,
                Some(&mine),
                Send::Json(body),
                status,
            )
            .await;
    }
    client
        .json(
            Method::POST,
            SAVED,
            SAVED,
            Some(&mine),
            too_large(),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;

    let one = |id: &str| format!("{SAVED}/{id}");
    let read = client
        .json(
            Method::GET,
            SAVED_ONE,
            &one(&first_id),
            Some(&mine),
            Send::Nothing,
            StatusCode::OK,
        )
        .await;
    assert_eq!(read["id"], first_id);
    for (path, status) in [
        (one("not-a-uuid"), StatusCode::BAD_REQUEST),
        (one(&Uuid::nil().to_string()), StatusCode::NOT_FOUND),
    ] {
        client
            .json(
                Method::GET,
                SAVED_ONE,
                &path,
                Some(&mine),
                Send::Nothing,
                status,
            )
            .await;
    }
    // someone else's isn't found, and isn't theirs to change
    client
        .json(
            Method::GET,
            SAVED_ONE,
            &one(&first_id),
            Some(&theirs),
            Send::Nothing,
            StatusCode::NOT_FOUND,
        )
        .await;
    client
        .json(
            Method::PATCH,
            SAVED_ONE,
            &one(&first_id),
            Some(&theirs),
            Send::Json(json!({"name": "x"})),
            StatusCode::FORBIDDEN,
        )
        .await;
    client
        .json(
            Method::DELETE,
            SAVED_ONE,
            &one(&first_id),
            Some(&theirs),
            Send::Nothing,
            StatusCode::FORBIDDEN,
        )
        .await;

    let renamed = client
        .json(
            Method::PATCH,
            SAVED_ONE,
            &one(&first_id),
            Some(&mine),
            Send::Json(json!({"name": "Renamed", "quick_filter_indicator": true})),
            StatusCode::OK,
        )
        .await;
    assert_eq!(
        (
            renamed["name"].clone(),
            renamed["quick_filter_indicator"].clone()
        ),
        (json!("Renamed"), json!(true))
    );
    for (path, body, status) in [
        (
            one(&first_id),
            Send::Json(json!({"name": "Other"})),
            StatusCode::CONFLICT,
        ),
        (
            one(&first_id),
            Send::Json(json!({"filters": [{"name": "Nope", "values": ["x"]}]})),
            StatusCode::BAD_REQUEST,
        ),
        (
            one("not-a-uuid"),
            Send::Json(json!({"name": "x"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            one(&Uuid::nil().to_string()),
            Send::Json(json!({"name": "x"})),
            StatusCode::NOT_FOUND,
        ),
        (one(&first_id), too_large(), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        client
            .json(Method::PATCH, SAVED_ONE, &path, Some(&mine), body, status)
            .await;
    }

    let pinned = client
        .json(
            Method::PUT,
            QUICK,
            QUICK,
            Some(&mine),
            Send::Json(json!({"ids": [other_id, first_id]})),
            StatusCode::OK,
        )
        .await;
    let names: Vec<&str> = pinned["saved_filters"]
        .as_array()
        .expect("saved filters")
        .iter()
        .map(|f| f["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["Other", "Renamed"]);
    for (path, body, status) in [
        (
            QUICK.to_owned(),
            Send::Json(json!({"ids": [Uuid::nil()]})),
            StatusCode::BAD_REQUEST,
        ),
        (
            QUICK.to_owned(),
            Send::Json(json!({"ids": "x"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{QUICK}?screen=nope"),
            Send::Json(json!({"ids": []})),
            StatusCode::NOT_FOUND,
        ),
        (QUICK.to_owned(), too_large(), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        client
            .json(Method::PUT, QUICK, &path, Some(&mine), body, status)
            .await;
    }

    let gone = client
        .call(
            Method::DELETE,
            SAVED_ONE,
            &one(&first_id),
            Some(&mine),
            Send::Nothing,
        )
        .await;
    assert_eq!(gone.status(), StatusCode::NO_CONTENT);
    for (path, status) in [
        (one(&first_id), StatusCode::NOT_FOUND),
        (one("not-a-uuid"), StatusCode::BAD_REQUEST),
    ] {
        client
            .json(
                Method::DELETE,
                SAVED_ONE,
                &path,
                Some(&mine),
                Send::Nothing,
                status,
            )
            .await;
    }
}

/// An event route with `{event}` filled.
fn on_event(route: &str, event: impl std::fmt::Display) -> String {
    route.replace("{event}", &event.to_string())
}

/// An event on today's date with ace3's defaults and these alerts, as `ace-service`'s tests make one.
async fn event_of(stack: &Stack, name: &str, alerts: &[Uuid]) -> (i64, Uuid) {
    let pool = stack.test_db.db().pool();
    let (id, uuid): (i64, Uuid) = sqlx::query_as(
        "INSERT INTO events.events
             (creation_date, name, status_id, remediation_id, type_id, vector_id, risk_level_id,
              prevention_tool_id, comment, alert_time)
         VALUES (current_date, $1, (SELECT min(id) FROM events.statuses),
                 (SELECT min(id) FROM events.remediations), (SELECT min(id) FROM events.types),
                 (SELECT min(id) FROM events.vectors),
                 (SELECT id FROM events.risk_levels ORDER BY value LIMIT 1),
                 (SELECT min(id) FROM events.prevention_tools), $1, '2026-03-04T05:06:07Z')
         RETURNING id, uuid",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("makes an event");
    for alert in alerts {
        sqlx::query("INSERT INTO events.event_alerts (event_id, root_id) VALUES ($1, $2)")
            .bind(id)
            .bind(alert)
            .execute(pool)
            .await
            .expect("adds an alert");
    }
    (id, uuid)
}

/// PLAN.md 5.11's events (6a): ace3's events, threat_types and threats routers, every status each
/// documents, each write audited.
async fn events(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let reader = key(stack, &["event:read"]).await;
    let writer = key(stack, &["event:read", "event:write"]).await;
    let (r, w) = (Some(reader.as_str()), Some(writer.as_str()));
    let pool = stack.test_db.db().pool();

    let hostile = "=HYPERLINK(\"http://evil\") <script>";
    let alerted = alert(
        stack,
        "in an event",
        &[(ObservableKind::Fqdn, "event.example")],
    )
    .await;
    let (id, uuid) = event_of(stack, hostile, &[alerted]).await;
    let malware: i32 =
        sqlx::query_scalar("INSERT INTO events.malware (name) VALUES ('Emotet') RETURNING id")
            .fetch_one(pool)
            .await
            .expect("malware");
    sqlx::query("INSERT INTO events.event_malware VALUES ($1, $2)")
        .bind(id)
        .bind(malware)
        .execute(pool)
        .await
        .expect("records malware");

    // one event, by id or uuid
    let one = client
        .json(M::GET, EVENT, &on_event(EVENT, id), r, Send::Nothing, S::OK)
        .await;
    assert_eq!(one["uuid"], json!(uuid));
    assert_eq!(one["name"], hostile, "as it was written");
    assert_eq!(one["type"], "phish");
    assert_eq!(one["status"], "OPEN");
    assert_eq!(one["disposition"], "OPEN", "its one alert is open");
    assert_eq!(one["alerts"][0]["id"], json!(alerted));
    assert_eq!(one["alerts"][0]["title"], "in an event");
    assert_eq!(
        one["malware"],
        json!([{"id": malware, "name": "Emotet", "threat_types": []}])
    );
    let by_uuid = client
        .json(
            M::GET,
            EVENT,
            &on_event(EVENT, uuid),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(by_uuid, one);
    client
        .json(
            M::GET,
            EVENT,
            &on_event(EVENT, "443c-x"),
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            EVENT,
            &on_event(EVENT, Uuid::nil()),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;

    // the open ones, a page at a time
    let (second, _) = event_of(stack, "second", &[]).await;
    let page = client
        .json(
            M::GET,
            OPEN_EVENTS,
            &format!("{OPEN_EVENTS}?limit=1"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["events"][0], one);
    assert_eq!(page["next"], id);
    let page = client
        .json(
            M::GET,
            OPEN_EVENTS,
            &format!("{OPEN_EVENTS}?limit=1&after={id}"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["events"][0]["id"], second);
    assert_eq!(page["events"][0]["disposition"], "DELIVERY", "no alerts");
    assert_eq!(page["next"], Value::Null);
    client
        .json(
            M::GET,
            OPEN_EVENTS,
            &format!("{OPEN_EVENTS}?limit=0"),
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // a status: a reader can't, a status that isn't one, no such event, the one it has changes nothing
    let status = on_event(EVENT_STATUS, id);
    let rows = audit_count(stack).await;
    client
        .json(
            M::PUT,
            EVENT_STATUS,
            &status,
            r,
            json(json!({"status": "CLOSED"})),
            S::FORBIDDEN,
        )
        .await;
    let closed = client
        .json(
            M::PUT,
            EVENT_STATUS,
            &status,
            w,
            json(json!({"status": "CLOSED"})),
            S::OK,
        )
        .await;
    assert_eq!(closed["status"], "CLOSED");
    assert_eq!(audit_count(stack).await, rows + 1);
    client
        .json(
            M::PUT,
            EVENT_STATUS,
            &status,
            w,
            json(json!({"status": "CLOSED"})),
            S::OK,
        )
        .await;
    assert_eq!(audit_count(stack).await, rows + 1, "no change, no row");
    for bad in [
        json(json!({"status": "NOPE"})),
        json(json!({"state": "OPEN"})),
    ] {
        client
            .json(M::PUT, EVENT_STATUS, &status, w, bad, S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::PUT,
            EVENT_STATUS,
            &on_event(EVENT_STATUS, i64::MAX),
            w,
            json(json!({"status": "OPEN"})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::PUT,
            EVENT_STATUS,
            &status,
            w,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let page = client
        .json(M::GET, OPEN_EVENTS, OPEN_EVENTS, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        page["events"].as_array().map(Vec::len),
        Some(1),
        "closed isn't open"
    );

    // the export, with ace3's columns and a formula guarded
    let (got, kind, csv) = client
        .text(
            EVENT_CSV,
            &format!("{EVENT_CSV}?ids={second},{id},999999"),
            &reader,
        )
        .await;
    assert_eq!(got, S::OK, "{csv}");
    assert_eq!(kind, "text/csv; charset=utf-8");
    let lines: Vec<&str> = csv.split("\r\n").collect();
    assert_eq!(lines.len(), 4, "a header, two rows and the end: {csv:?}");
    assert!(
        lines[0].starts_with("id,uuid,creation_date,name,type,vector,threat_type,threat_name,"),
        "{csv}"
    );
    assert!(
        lines[0].ends_with("MAX(disposition),tags,alert_tags"),
        "{csv}"
    );
    assert!(
        lines[1].starts_with(&format!("{id},{uuid},")),
        "in id order: {csv}"
    );
    assert!(
        lines[1].contains(r#""'=HYPERLINK(""http://evil"") <script>""#),
        "{csv}"
    );
    assert!(lines[1].contains(",Emotet,"), "{csv}");
    assert!(lines[1].contains(",2026,Mar,OPEN,"), "{csv}");
    assert!(!csv.contains(",="), "no cell starts a formula: {csv}");
    let (got, _, _) = client
        .text(EVENT_CSV, &format!("{EVENT_CSV}?ids=1,x"), &reader)
        .await;
    assert_eq!(got, S::BAD_REQUEST);
    let many: Vec<String> = (0..=1000).map(|n| n.to_string()).collect();
    let (got, _, _) = client
        .text(
            EVENT_CSV,
            &format!("{EVENT_CSV}?ids={}", many.join(",")),
            &reader,
        )
        .await;
    assert_eq!(got, S::PAYLOAD_TOO_LARGE);

    // threat types
    let listed = client
        .json(M::GET, THREAT_TYPES, THREAT_TYPES, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(listed["threat_types"].as_array().map(Vec::len), Some(13));
    let made = client
        .json(
            M::POST,
            THREAT_TYPES,
            THREAT_TYPES,
            w,
            json(json!({"name": hostile})),
            S::CREATED,
        )
        .await;
    assert_eq!(made["name"], hostile);
    let made_id = made["id"].as_i64().expect("an id");
    for (body, status) in [
        (json(json!({"name": "ransomware"})), S::CONFLICT),
        (json(json!({"name": " "})), S::BAD_REQUEST),
        (too_large(), S::PAYLOAD_TOO_LARGE),
    ] {
        client
            .json(M::POST, THREAT_TYPES, THREAT_TYPES, w, body, status)
            .await;
    }
    let one_type = at(THREAT_TYPE, made_id, "");
    let read = client
        .json(M::GET, THREAT_TYPE, &one_type, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(read, made);
    client
        .json(
            M::GET,
            THREAT_TYPE,
            &at(THREAT_TYPE, "x", ""),
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            THREAT_TYPE,
            &at(THREAT_TYPE, i32::MAX, ""),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    let renamed = client
        .json(
            M::PATCH,
            THREAT_TYPE,
            &one_type,
            w,
            json(json!({"name": "dropper"})),
            S::OK,
        )
        .await;
    assert_eq!(renamed["name"], "dropper");
    for (path, body, status) in [
        (one_type.clone(), json(json!({"name": "rat"})), S::CONFLICT),
        (one_type.clone(), json(json!({})), S::BAD_REQUEST),
        (
            at(THREAT_TYPE, i32::MAX, ""),
            json(json!({"name": "y"})),
            S::NOT_FOUND,
        ),
        (one_type.clone(), too_large(), S::PAYLOAD_TOO_LARGE),
    ] {
        client
            .json(M::PATCH, THREAT_TYPE, &path, w, body, status)
            .await;
    }

    // threats: malware's threat types
    let threat = client
        .json(
            M::POST,
            THREATS,
            THREATS,
            w,
            json(json!({"malware_id": malware, "threat_type_id": made_id})),
            S::CREATED,
        )
        .await;
    assert_eq!(
        threat,
        json!({
            "malware_id": malware,
            "malware_name": "Emotet",
            "threat_type_id": made_id,
            "threat_type_name": "dropper",
        })
    );
    for (body, status) in [
        (
            json(json!({"malware_id": malware, "threat_type_id": made_id})),
            S::CONFLICT,
        ),
        (
            json(json!({"malware_id": i32::MAX, "threat_type_id": made_id})),
            S::NOT_FOUND,
        ),
        (json(json!({"malware_id": "x"})), S::BAD_REQUEST),
        (too_large(), S::PAYLOAD_TOO_LARGE),
    ] {
        client
            .json(M::POST, THREATS, THREATS, w, body, status)
            .await;
    }
    let listed = client
        .json(
            M::GET,
            THREATS,
            &format!("{THREATS}?malware={malware}"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(listed, json!({"threats": [threat]}));
    client
        .json(
            M::GET,
            THREATS,
            &format!("{THREATS}?malware=x"),
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let event = client
        .json(M::GET, EVENT, &on_event(EVENT, id), r, Send::Nothing, S::OK)
        .await;
    assert_eq!(event["malware"][0]["threat_types"], json!(["dropper"]));

    // a type in use can't be deleted; once its threat is gone it can
    client
        .json(
            M::DELETE,
            THREAT_TYPE,
            &one_type,
            w,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    let threat_path = THREAT
        .replace("{malware}", &malware.to_string())
        .replace("{threat_type}", &made_id.to_string());
    client
        .json(
            M::DELETE,
            THREAT,
            &threat_path,
            r,
            Send::Nothing,
            S::FORBIDDEN,
        )
        .await;
    let gone = client
        .call(M::DELETE, THREAT, &threat_path, w, Send::Nothing)
        .await;
    assert_eq!(gone.status(), S::NO_CONTENT);
    client
        .json(
            M::DELETE,
            THREAT,
            &threat_path,
            w,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            THREAT,
            &THREAT
                .replace("{malware}", "x")
                .replace("{threat_type}", "1"),
            w,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let gone = client
        .call(M::DELETE, THREAT_TYPE, &one_type, w, Send::Nothing)
        .await;
    assert_eq!(gone.status(), S::NO_CONTENT);
    client
        .json(
            M::DELETE,
            THREAT_TYPE,
            &one_type,
            w,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            THREAT_TYPE,
            &at(THREAT_TYPE, "x", ""),
            w,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PATCH,
            THREAT_TYPE,
            &at(THREAT_TYPE, "x", ""),
            w,
            json(json!({"name": "z"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            EVENT_STATUS,
            &on_event(EVENT_STATUS, "x-y"),
            w,
            json(json!({"status": "OPEN"})),
            S::BAD_REQUEST,
        )
        .await;
    // status, create, rename, add, remove and delete: one row each
    assert_eq!(audit_count(stack).await, rows + 6);
}

/// PLAN.md 5.12: ace3's `cli` router, a command queued for a pool and read back, and its cancel.
async fn commands(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let (alice, alices) = session_of(stack, "operator", &["cli:execute"]).await;
    let a = Some(alices.as_str());
    let ownerless = key(stack, &["cli:execute"]).await;
    let rows = audit_count(stack).await;

    let started = client
        .json(
            M::POST,
            COMMANDS,
            COMMANDS,
            a,
            json(json!({"command": "ace yara scan '<script>alert(1)</script>'", "timeout_seconds": 30})),
            S::ACCEPTED,
        )
        .await;
    let id = started["id"].as_i64().expect("an id");
    assert_eq!(started["command"], "yara scan '<script>alert(1)</script>'");
    assert_eq!(started["state"], "queued");
    assert_eq!(started["user_id"], json!(alice));
    assert_eq!(started["username"], "operator");
    assert_eq!(started["started_by"]["kind"], "user");
    assert_eq!(started["timeout_seconds"], 30);
    assert_eq!(started["output"], "");
    assert_eq!(started["deadline_at"], Value::Null);
    assert_eq!(audit_count(stack).await, rows + 1);
    let second = client
        .json(
            M::POST,
            COMMANDS,
            COMMANDS,
            a,
            json(json!({"command": "--help"})),
            S::ACCEPTED,
        )
        .await;
    assert_eq!(second["timeout_seconds"], 300, "ace3's default");
    let second = second["id"].as_i64().expect("an id");

    // a line that isn't one, a timeout out of range or a body that isn't one is 400, too much is 413
    for body in [
        json!({"command": ""}),
        json!({"command": "-c x node list"}),
        json!({"command": "'open"}),
        json!({"command": "--help", "timeout_seconds": 0}),
        json!({"command": "--help", "timeout_seconds": 3601}),
        json!({"command": "--help", "node_ids": [1]}),
        json!({}),
    ] {
        client
            .json(M::POST, COMMANDS, COMMANDS, a, json(body), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::POST,
            COMMANDS,
            COMMANDS,
            a,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    // a key with no owner runs nothing: a run names its person
    client
        .json(
            M::POST,
            COMMANDS,
            COMMANDS,
            Some(&ownerless),
            json(json!({"command": "--help"})),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(audit_count(stack).await, rows + 2, "no refusal has a row");

    let page = client
        .json(
            M::GET,
            COMMANDS,
            &format!("{COMMANDS}?limit=1"),
            Some(&ownerless),
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["commands"][0]["id"], second);
    assert_eq!(page["next"], second);
    assert!(
        page["commands"][0].get("output").is_none(),
        "a list has no output"
    );
    let page = client
        .json(
            M::GET,
            COMMANDS,
            &format!("{COMMANDS}?after={second}"),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["commands"][0]["id"], id);
    assert_eq!(page["next"], Value::Null);
    for query in ["?limit=0", "?limit=201", "?after=x"] {
        client
            .json(
                M::GET,
                COMMANDS,
                &format!("{COMMANDS}{query}"),
                a,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }

    // its output so far is text, as the pool reported it
    let worker = ace_core::commands::CommandWorker::new(
        stack.test_db.db().clone(),
        "test/api",
        std::time::Duration::from_secs(30),
    );
    let claimed = worker.claim().await.expect("claims").expect("a command");
    assert_eq!(claimed.id, id);
    let hostile = "<script>alert(1)</script>\0\u{1b}[31m";
    worker.report(id, hostile, true).await.expect("reports");
    let one = at(COMMAND, id, "");
    let read = client
        .json(M::GET, COMMAND, &one, a, Send::Nothing, S::OK)
        .await;
    assert_eq!(read["state"], "running");
    assert_eq!(
        read["output"],
        "<script>alert(1)</script>\u{fffd}\u{1b}[31m"
    );
    assert_eq!(read["output_truncated"], true);
    assert!(read["deadline_at"].is_string());
    client
        .json(
            M::GET,
            COMMAND,
            &at(COMMAND, "x", ""),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            COMMAND,
            &at(COMMAND, i64::MAX, ""),
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;

    // a cancel asks the running one to stop, and ends the queued one; an ended one is 409
    let cancel = at(CANCEL_COMMAND, id, "");
    let asked = client
        .json(M::POST, CANCEL_COMMAND, &cancel, a, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        (asked["state"].clone(), asked["cancel_requested"].clone()),
        (json!("running"), json!(true))
    );
    assert_eq!(asked["cancelled_by"]["id"], json!(alice));
    let ended = client
        .json(
            M::POST,
            CANCEL_COMMAND,
            &at(CANCEL_COMMAND, second, ""),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(ended["state"], "cancelled");
    client
        .json(
            M::POST,
            CANCEL_COMMAND,
            &at(CANCEL_COMMAND, second, ""),
            a,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    client
        .json(
            M::POST,
            CANCEL_COMMAND,
            &at(CANCEL_COMMAND, "x", ""),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::POST,
            CANCEL_COMMAND,
            &at(CANCEL_COMMAND, i64::MAX, ""),
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    assert_eq!(
        audit_count(stack).await,
        rows + 4,
        "two cancels, each with its row"
    );
}

/// The analyst-edited lists' router (PLAN.md 5.14): a list and its entries read back, each write audited
/// with its actor, a bad entry refused, and a value returned as it was sent.
async fn lists_router(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let (alice, alices) = session_of(stack, "list-editor", &["list:read", "list:write"]).await;
    let a = Some(alices.as_str());
    let reader = key(stack, &["list:read"]).await;
    let r = Some(reader.as_str());
    let entries = at(ENTRIES, "", "").replace("{list}", TEST_LIST.name);
    let entry = |id: i64| {
        ENTRY
            .replace("{list}", TEST_LIST.name)
            .replace("{id}", &id.to_string())
    };
    let rows = audit_count(stack).await;

    let listed = client
        .json(M::GET, LISTS, LISTS, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        listed,
        json!({"lists": [
            {
                "name": "observable_detection", "description": "the observables ACE detects",
                "typed": true, "entries": 0,
            },
            {
                "name": "test_whitelist", "description": "a list for the tests", "typed": false,
                "entries": 0,
            },
        ]})
    );

    let hostile = "<script>alert(1)</script>@evil.example";
    let added = client
        .json(
            M::POST,
            ENTRIES,
            &entries,
            a,
            json(json!({"match": "substring", "value": hostile, "note": "</td><b>x"})),
            S::CREATED,
        )
        .await;
    assert_eq!(added["value"], hostile, "as it was sent");
    assert_eq!(added["match"], "substring");
    assert_eq!(added["ignore_case"], true, "ace3's whitelist ignored case");
    assert_eq!(added["note"], "</td><b>x");
    assert_eq!(added["created_by"]["kind"], "user");
    assert_eq!(added["created_by"]["id"], json!(alice.to_string()));
    let id = added["id"].as_i64().expect("an id");
    assert_eq!(audit_count(stack).await, rows + 1);
    let (actor, action): (Value, String) =
        sqlx::query_as("SELECT actor::jsonb, action FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!(action, "add_list_entry");
    assert_eq!(
        actor["name"], "list-editor",
        "the audit row names the actor"
    );

    let second = client
        .json(
            M::POST,
            ENTRIES,
            &entries,
            a,
            json(json!({"match": "regex", "value": r"^bounce-\d+@", "ignore_case": false})),
            S::CREATED,
        )
        .await;
    let one = client
        .json(
            M::GET,
            LIST_ONE,
            &LIST_ONE.replace("{list}", TEST_LIST.name),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(one["entries"], json!([added.clone(), second.clone()]));
    assert!(one["version"].as_i64().is_some());
    client
        .json(
            M::GET,
            LIST_ONE,
            &LIST_ONE.replace("{list}", "no_such_list"),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;

    // what the service won't take
    for (body, status) in [
        (
            json!({"match": "regex", "value": "(unclosed"}),
            S::BAD_REQUEST,
        ),
        (
            json!({"match": "regex", "value": r"\w{100}"}),
            S::BAD_REQUEST,
        ),
        (json!({"match": "exact", "value": ""}), S::BAD_REQUEST),
        (json!({"match": "glob", "value": "x"}), S::BAD_REQUEST),
        (
            json!({"match": "exact", "value": "x", "observable_type": "ipv4"}),
            S::BAD_REQUEST,
        ),
        (json!({"match": "substring", "value": hostile}), S::CONFLICT),
    ] {
        client
            .json(M::POST, ENTRIES, &entries, a, json(body), status)
            .await;
    }
    client
        .json(
            M::POST,
            ENTRIES,
            &ENTRIES.replace("{list}", "no_such_list"),
            a,
            json(json!({"match": "exact", "value": "x"})),
            S::NOT_FOUND,
        )
        .await;
    let response = client
        .call(M::POST, ENTRIES, &entries, a, too_large())
        .await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);
    let refused = client
        .json(
            M::POST,
            ENTRIES,
            &entries,
            r,
            json(json!({"match": "exact", "value": "x"})),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(refused["error"], "this needs list:write");
    assert_eq!(
        audit_count(stack).await,
        rows + 2,
        "nothing refused has a row"
    );

    // replace an entry, keeping its place
    let replaced = client
        .json(
            M::PUT,
            ENTRY,
            &entry(id),
            a,
            json(json!({"match": "exact", "value": "relay@partner.example"})),
            S::OK,
        )
        .await;
    assert_eq!(replaced["id"], id);
    assert_eq!(replaced["value"], "relay@partner.example");
    assert_eq!(replaced["created_at"], added["created_at"]);
    assert_eq!(audit_count(stack).await, rows + 3);
    client
        .json(
            M::PUT,
            ENTRY,
            &entry(id),
            a,
            json(json!({"match": "regex", "value": r"^bounce-\d+@", "ignore_case": false})),
            S::CONFLICT,
        )
        .await;
    client
        .json(
            M::PUT,
            ENTRY,
            &entry(id),
            a,
            json(json!({"match": "regex", "value": "("})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            ENTRY,
            &ENTRY
                .replace("{list}", TEST_LIST.name)
                .replace("{id}", "abc"),
            a,
            json(json!({"match": "exact", "value": "x"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            ENTRY,
            &entry(i64::MAX),
            a,
            json(json!({"match": "exact", "value": "x"})),
            S::NOT_FOUND,
        )
        .await;
    let response = client.call(M::PUT, ENTRY, &entry(id), a, too_large()).await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);

    // and delete one
    let response = client
        .call(M::DELETE, ENTRY, &entry(id), a, Send::Nothing)
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    assert_eq!(audit_count(stack).await, rows + 4);
    client
        .json(M::DELETE, ENTRY, &entry(id), a, Send::Nothing, S::NOT_FOUND)
        .await;
    client
        .json(
            M::DELETE,
            ENTRY,
            &ENTRY
                .replace("{list}", TEST_LIST.name)
                .replace("{id}", "abc"),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let remaining = client
        .json(
            M::GET,
            LIST_ONE,
            &LIST_ONE.replace("{list}", TEST_LIST.name),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(remaining["entries"], json!([second]));
}

/// ace3's `detection` router (PLAN.md 7.6): the observables ACE detects, as entries of the
/// `observable_detection` list, listed and filtered as ace3 does, added with ace3's default lifetime,
/// removed, and given an expiry, each write audited and naming its actor. A value comes back as stored.
async fn detection_router(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let (_, editors) = session_of(stack, "detector", &["detection:read", "detection:write"]).await;
    let e = Some(editors.as_str());
    let reader = key(stack, &["detection:read"]).await;
    let r = Some(reader.as_str());
    let list_reader = key(stack, &["list:read"]).await;
    let one = |id: &Value| OBSERVED_ONE.replace("{id}", &id.to_string().replace('"', ""));
    let expiry = |id: &Value| OBSERVED_EXPIRY.replace("{id}", &id.to_string().replace('"', ""));
    let rows = audit_count(stack).await;

    let hostile = "<script>alert(1)</script>.evil.example";
    let added = client
        .json(
            M::POST,
            OBSERVED,
            OBSERVED,
            e,
            json(json!({"type": "fqdn", "value": hostile})),
            S::CREATED,
        )
        .await;
    assert_eq!(added["value"], hostile, "as it was sent");
    assert_eq!(added["type"], "fqdn");
    assert_eq!(added["detection_context"], "manually added by detector");
    assert!(added["expires_on"].is_string(), "ace3's 90 days: {added}");
    assert_eq!(added["expired"], false);
    assert_eq!(added["comments"], json!([]));
    let (actor, action): (Value, String) =
        sqlx::query_as("SELECT actor::jsonb, action FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!(action, "create_detection");
    assert_eq!(actor["name"], "detector", "the audit row names the actor");
    let forever = client
        .json(
            M::POST,
            OBSERVED,
            OBSERVED,
            e,
            json(json!({
                "type": "ipv4", "value": "192.0.2.1", "expires_on": null,
                "detection_context": "from the phish of the day",
            })),
            S::CREATED,
        )
        .await;
    assert_eq!(forever["expires_on"], Value::Null, "null never expires");
    assert_eq!(audit_count(stack).await, rows + 2);

    // what it won't take
    for (body, status) in [
        (
            json!({"type": "no_such_type", "value": "x"}),
            S::BAD_REQUEST,
        ),
        (
            json!({"type": "file", "value": "not a sha256"}),
            S::BAD_REQUEST,
        ),
        (json!({"type": "fqdn", "value": ""}), S::BAD_REQUEST),
        (
            json!({"type": "fqdn", "value": "x.example", "batch_id": "b"}),
            S::BAD_REQUEST,
        ),
        (
            json!({"type": "fqdn", "value": "x.example", "expires_on": "2001-01-01T00:00:00Z"}),
            S::BAD_REQUEST,
        ),
        (json!({"type": "fqdn", "value": hostile}), S::CONFLICT),
    ] {
        client
            .json(M::POST, OBSERVED, OBSERVED, e, json(body), status)
            .await;
    }
    let response = client
        .call(M::POST, OBSERVED, OBSERVED, e, too_large())
        .await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);
    let refused = client
        .json(
            M::POST,
            OBSERVED,
            OBSERVED,
            r,
            json(json!({"type": "fqdn", "value": "x.example"})),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(refused["error"], "this needs detection:write");
    assert_eq!(
        audit_count(stack).await,
        rows + 2,
        "nothing refused has a row"
    );

    // the listing: a page, filters, and the types
    let page = client
        .json(M::GET, OBSERVED, OBSERVED, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(page["total"], 2);
    assert_eq!(
        (
            page["page"].clone(),
            page["page_size"].clone(),
            page["total_pages"].clone()
        ),
        (json!(1), json!(50), json!(1))
    );
    assert_eq!(
        page["items"],
        json!([added.clone(), forever.clone()]),
        "by type, then value"
    );
    let searched = client
        .json(
            M::GET,
            OBSERVED,
            &format!("{OBSERVED}?search=*.EVIL.example&type=fqdn&status=all&page=3&page_size=25"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(searched["items"], json!([added.clone()]));
    assert_eq!(
        (searched["page"].clone(), searched["page_size"].clone()),
        (json!(1), json!(25))
    );
    let expired = client
        .json(
            M::GET,
            OBSERVED,
            &format!("{OBSERVED}?status=expired"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(expired["total"], 0);
    client
        .json(
            M::GET,
            OBSERVED,
            &format!("{OBSERVED}?status=dormant"),
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let types = client
        .json(
            M::GET,
            OBSERVED_TYPES,
            OBSERVED_TYPES,
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(types["present"], json!(["fqdn", "ipv4"]));
    assert!(
        types["all"]
            .as_array()
            .is_some_and(|all| all.contains(&json!("file")))
    );

    // each is an entry of the list the module reads, exact and with case
    let list = client
        .json(
            M::GET,
            LIST_ONE,
            &LIST_ONE.replace("{list}", "observable_detection"),
            Some(list_reader.as_str()),
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(list["entries"][0]["match"], "exact");
    assert_eq!(list["entries"][0]["ignore_case"], false);
    assert_eq!(list["entries"][0]["note"], "manually added by detector");

    // an expiry
    let id = &forever["id"];
    let set = client
        .json(
            M::PATCH,
            OBSERVED_EXPIRY,
            &expiry(id),
            e,
            json(json!({"expires_on": "2999-01-01T00:00:00Z"})),
            S::OK,
        )
        .await;
    assert_eq!(set["expires_on"], "2999-01-01T00:00:00Z");
    assert_eq!(audit_count(stack).await, rows + 3);
    for (path, body, status) in [
        (
            expiry(id),
            json!({"expires_on": "2001-01-01T00:00:00Z"}),
            S::BAD_REQUEST,
        ),
        (expiry(id), json!({"expires": null}), S::BAD_REQUEST),
        (
            expiry(&json!("abc")),
            json!({"expires_on": null}),
            S::BAD_REQUEST,
        ),
        (
            expiry(&json!(i64::MAX)),
            json!({"expires_on": null}),
            S::NOT_FOUND,
        ),
    ] {
        client
            .json(M::PATCH, OBSERVED_EXPIRY, &path, e, json(body), status)
            .await;
    }
    let response = client
        .call(M::PATCH, OBSERVED_EXPIRY, &expiry(id), e, too_large())
        .await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);

    // and removing one
    let response = client
        .call(M::DELETE, OBSERVED_ONE, &one(id), e, Send::Nothing)
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    assert_eq!(audit_count(stack).await, rows + 4);
    client
        .json(
            M::DELETE,
            OBSERVED_ONE,
            &one(id),
            e,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            OBSERVED_ONE,
            &one(&json!("abc")),
            e,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    let remaining = client
        .json(M::GET, OBSERVED, OBSERVED, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(remaining["items"], json!([added]));
    let response = client
        .call(
            M::DELETE,
            OBSERVED_ONE,
            &one(&added["id"]),
            e,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);

    // a server whose modules don't read the list has no detections
    let bare = stack_of(
        ace_core::email_archive::ArchiveConfig::default(),
        Catalog::new(vec![Manifest::lookup::<Rdap>()]),
    )
    .await;
    let mut other = Client::new(&bare);
    let admin = key(&bare, &["detection:read", "detection:write"]).await;
    let a = Some(admin.as_str());
    other
        .json(M::GET, OBSERVED, OBSERVED, a, Send::Nothing, S::NOT_FOUND)
        .await;
    other
        .json(
            M::GET,
            OBSERVED_TYPES,
            OBSERVED_TYPES,
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    other
        .json(
            M::POST,
            OBSERVED,
            OBSERVED,
            a,
            json(json!({"type": "fqdn", "value": "x.example"})),
            S::NOT_FOUND,
        )
        .await;
    let seen = other.seen;
    client.seen.extend(seen);
}

const LIST_POOL_TOKEN: &str = "list-pool-token";

/// The core's lease API on a listener of its own, with a pool that runs the list reader.
async fn lease_api(stack: &Stack) -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
    let api = ace_core::api::Api::new(
        stack.test_db.db().clone(),
        stack.bucket.clone(),
        stack.orchestrator.clone(),
        ace_core::api::ApiConfig::new(vec![ace_core::api::PoolAccess::new(
            "lists",
            LIST_POOL_TOKEN,
            vec![ListReader::NAME.to_owned()],
        )]),
    )
    .await
    .expect("the lease API starts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let server = tokio::spawn(ace_core::api::serve(listener, api, std::future::pending()));
    (url, server)
}

/// Queues a list reader's task on a new fqdn in `root` and leases it, as a pool would. Returns the
/// list it carries.
async fn lease_list(stack: &Stack, http: &reqwest::Client, url: &str, root: Uuid) -> WireList {
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let observable = tree::upsert_observable(
        &mut tx,
        root,
        &NewObservable::new(ObservableKind::Fqdn, format!("{}.example", Uuid::new_v4())),
    )
    .await
    .expect("adds")
    .id;
    ace_core::queue::enqueue(&mut tx, root, observable, ListReader::NAME)
        .await
        .expect("queues")
        .expect("a task");
    tx.commit().await.expect("commits");
    let response = http
        .post(format!("{url}{}", ace_sdk::wire::paths::LEASE))
        .bearer_auth(LIST_POOL_TOKEN)
        .json(&json!({"worker": "test/1", "modules": [ListReader::NAME]}))
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), 200);
    let task: ace_sdk::wire::LeasedTask = response.json().await.expect("a task");
    assert_eq!(
        task.lists.len(),
        2,
        "the task carries the lists its module reads"
    );
    task.lists
        .into_iter()
        .find(|list| list.name == TEST_LIST.name)
        .expect("the list")
}

/// PLAN.md 5.14's Done check: an edit through the API applies to the next task leased, with nothing
/// restarted, and its audit row names the actor. Every edit is followed by a lease, so a list served from
/// a cache older than the edit fails it; then edits race leases, and a lease begun after an edit's
/// response must carry that edit or a later one.
#[tokio::test]
async fn an_edit_through_the_api_applies_to_the_next_task_without_a_restart() {
    let stack = stack().await;
    let (lease_url, server) = lease_api(&stack).await;
    let http = reqwest::Client::new();
    let (editor_id, editor) = session_of(&stack, "whitelister", &["list:write"]).await;
    let root = NewRoot::new("analysis");
    let mut tx = stack.test_db.db().begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let entries = ENTRIES.replace("{list}", TEST_LIST.name);
    let session = |request: reqwest::RequestBuilder| {
        request
            .header("cookie", format!("ace4_session={editor}"))
            .header("origin", &stack.url)
    };

    let empty = lease_list(&stack, &http, &lease_url, root.id).await;
    assert_eq!(empty.name, TEST_LIST.name);
    assert!(empty.entries.is_empty());

    // add an entry, and the next task has it
    let response = session(http.post(format!("{}{entries}", stack.url)))
        .json(&json!({"match": "substring", "value": "@partner.example"}))
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), 201);
    let added: Value = response.json().await.expect("an entry");
    let id = added["id"].as_i64().expect("an id");
    let list = lease_list(&stack, &http, &lease_url, root.id).await;
    assert!(list.version > empty.version);
    assert_eq!(
        list.entries
            .iter()
            .map(|e| e.value.as_str())
            .collect::<Vec<_>>(),
        ["@partner.example"]
    );
    // nothing changed, so the next task has the same version, from the core's cache
    assert_eq!(lease_list(&stack, &http, &lease_url, root.id).await, list);

    // every edit applies to the very next task
    let entry = format!(
        "{}{}",
        stack.url,
        ENTRY
            .replace("{list}", TEST_LIST.name)
            .replace("{id}", &id.to_string())
    );
    let mut version = list.version;
    for i in 0..20 {
        let response = session(http.put(&entry))
            .json(&json!({"match": "exact", "value": format!("relay-{i}@partner.example")}))
            .send()
            .await
            .expect("answers");
        assert_eq!(response.status(), 200);
        let list = lease_list(&stack, &http, &lease_url, root.id).await;
        assert!(list.version > version, "edit {i}");
        version = list.version;
        assert_eq!(list.entries.len(), 1);
        assert_eq!(
            list.entries[0].value,
            format!("relay-{i}@partner.example"),
            "edit {i}"
        );
    }

    // edits racing leases: a lease begun after an edit answered carries it, or a later one
    let done = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(-1));
    let writer = {
        let (http, entry, done) = (http.clone(), entry.clone(), done.clone());
        let (cookie, origin) = (format!("ace4_session={editor}"), stack.url.clone());
        tokio::spawn(async move {
            for i in 0..40_i64 {
                let response = http
                    .put(&entry)
                    .header("cookie", &cookie)
                    .header("origin", &origin)
                    .json(&json!({"match": "exact", "value": format!("race-{i:03}")}))
                    .send()
                    .await
                    .expect("answers");
                assert_eq!(response.status(), 200);
                done.store(i, std::sync::atomic::Ordering::SeqCst);
            }
        })
    };
    let mut leases = 0;
    while !writer.is_finished() {
        let answered = done.load(std::sync::atomic::Ordering::SeqCst);
        let list = lease_list(&stack, &http, &lease_url, root.id).await;
        let seen = list.entries[0]
            .value
            .strip_prefix("race-")
            .map_or(-1, |n| n.parse::<i64>().expect("a number"));
        assert!(
            seen >= answered,
            "a lease after edit {answered} carried edit {seen}"
        );
        leases += 1;
    }
    writer.await.expect("the writer finished");
    assert!(leases > 1, "the leases raced the edits");
    let last = lease_list(&stack, &http, &lease_url, root.id).await;
    assert_eq!(last.entries[0].value, "race-039");

    // a delete applies too
    let response = session(http.delete(&entry)).send().await.expect("answers");
    assert_eq!(response.status(), 204);
    assert!(
        lease_list(&stack, &http, &lease_url, root.id)
            .await
            .entries
            .is_empty()
    );

    // and each write's audit row names the actor
    let rows: Vec<(Value, String, String)> = sqlx::query_as(
        "SELECT actor::jsonb, action, target_id FROM service.audit
         WHERE target_kind = 'list_entry' ORDER BY id",
    )
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("reads");
    assert_eq!(rows.len(), 1 + 20 + 40 + 1);
    for (actor, _, target) in &rows {
        assert_eq!(
            actor,
            &json!({"kind": "user", "id": editor_id, "name": "whitelister"})
        );
        assert_eq!(target, &id.to_string());
    }
    assert_eq!(rows[0].1, "add_list_entry");
    assert_eq!(rows[rows.len() - 1].1, "delete_list_entry");
    server.abort();
}

/// A Splunk hunt of the test's own, as a compiled package's assets.
fn hunt_package(rule: &str) -> Value {
    json!({
        "version": 2,
        "target": "hunts/splunk/case.yaml",
        "package_root": "/home/someone/signatures",
        "assets": [
            {"kind": "yaml", "path": "hunts/splunk/case.yaml", "content": rule},
            {"kind": "query", "path": "hunts/splunk/case.spl", "content": "index=auth action=failure"},
        ],
    })
}

const HUNT_RULE: &str = "rule:
  uuid: 00000000-0000-0000-0000-0000000000a1
  name: \"{{ user }} failed\"
  type: splunk
  enabled: true
  description: a hunt for the router's test
  alert_type: hunter - splunk
  frequency: \"00:10:00\"
  time_range: \"00:10:00\"
  full_coverage: false
  use_index_time: false
  search: __pkg__/hunts/splunk/case.spl
  observable_mapping:
    - field: user
      type: user
";

/// ace3's `hunt` router and the loaded hunts (PLAN.md 6.4).
async fn hunts_router(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let db = stack.test_db.db();
    let reader = key(stack, &["hunt:read"]).await;
    let r = Some(reader.as_str());
    let writer = key(stack, &["hunt:write"]).await;
    let w = Some(writer.as_str());

    sqlx::query(
        "INSERT INTO hunts.hunts (type, path, name, uuid, enabled, frequency, error, loaded_at) VALUES
         ('splunk', 'hunts/splunk/a.yaml', '<b>a</b>', 'uuid-a', true, '00:10:00', NULL, now()),
         ('splunk', 'hunts/splunk/b.yaml', NULL, NULL, NULL, NULL, 'ValueError: nope', now())",
    )
    .execute(db.pool())
    .await
    .expect("hunts");
    sqlx::query(
        "INSERT INTO hunts.state (type, name, last_executed_time, last_end_time, last_alert_times)
         VALUES ('splunk', '<b>a</b>', '2026-11-01T12:00:00Z', '2026-11-01T12:00:00Z', '{\"10.1.1.1\": \"2026-11-01T12:00:00Z\"}')",
    )
    .execute(db.pool())
    .await
    .expect("state");

    let listed = client
        .json(M::GET, HUNTS, HUNTS, r, Send::Nothing, S::OK)
        .await;
    let hunts = listed["hunts"].as_array().expect("hunts");
    assert_eq!(hunts.len(), 2);
    assert_eq!(hunts[0]["name"], "<b>a</b>", "as the hunt names itself");
    assert_eq!(hunts[0]["state"]["last_end_time"], "2026-11-01T12:00:00Z");
    assert_eq!(
        hunts[0]["state"]["last_alert_times"]["10.1.1.1"],
        "2026-11-01T12:00:00Z"
    );
    assert_eq!(hunts[1]["error"], "ValueError: nope");
    assert_eq!(hunts[1]["state"], Value::Null);
    let one = client
        .json(
            M::GET,
            HUNT,
            &HUNT.replace("{uuid}", "uuid-a"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(one["path"], "hunts/splunk/a.yaml");
    client
        .json(
            M::GET,
            HUNT,
            &HUNT.replace("{uuid}", "no-such"),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    // the hits a hunt dropped (PLAN.md 6.5), newest first, a page at a time
    sqlx::query(
        "INSERT INTO hunts.suppressions
             (type, name, uuid, reason, key, group_value, description, event_time, events,
              window_start, window_end, cause_root, search_start, search_end, decided_at)
         VALUES
             ('splunk', '<b>a</b>', 'uuid-a', 'duplicate', 'uuid-a:alice', NULL, '<script>alice</script>',
              '2026-11-01T11:59:00Z', 1, '2026-11-01T11:00:00Z', '2026-11-01T15:00:00Z',
              '00000000-0000-0000-0000-0000000000c1', '2026-11-01T11:50:00Z', '2026-11-01T12:00:00Z',
              '2026-11-01T12:00:00Z'),
             ('splunk', '<b>a</b>', 'uuid-a', 'group', '10.1.1.1', '\"10.1.1.1\"', 'a: 10.1.1.1',
              '2026-11-01T12:05:00Z', 3, '2026-11-01T12:00:00Z', '2026-11-01T13:00:00Z', NULL,
              '2026-11-01T12:00:00Z', '2026-11-01T12:10:00Z', '2026-11-01T12:10:00Z')",
    )
    .execute(db.pool())
    .await
    .expect("suppressions");
    let path = SUPPRESSIONS.replace("{uuid}", "uuid-a");
    let page = client
        .json(
            M::GET,
            SUPPRESSIONS,
            &format!("{path}?limit=1"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    let rows = page["suppressions"].as_array().expect("suppressions");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["reason"], "group");
    assert_eq!(rows[0]["group_value"], "10.1.1.1");
    assert_eq!(rows[0]["events"], 3);
    assert_eq!(rows[0]["window_end"], "2026-11-01T13:00:00Z");
    assert_eq!(rows[0]["cause_root"], Value::Null);
    let next = page["next"].as_i64().expect("another page");
    let page = client
        .json(
            M::GET,
            SUPPRESSIONS,
            &format!("{path}?limit=1&after={next}"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    let rows = page["suppressions"].as_array().expect("suppressions");
    assert_eq!(rows[0]["reason"], "duplicate");
    assert_eq!(rows[0]["key"], "uuid-a:alice");
    assert_eq!(rows[0]["description"], "<script>alice</script>", "as data");
    assert_eq!(
        rows[0]["cause_root"],
        "00000000-0000-0000-0000-0000000000c1"
    );
    assert_eq!(page["next"], Value::Null);
    for query in ["?limit=0", "?limit=501", "?after=999999", "?limit=x"] {
        client
            .json(
                M::GET,
                SUPPRESSIONS,
                &format!("{path}{query}"),
                r,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::GET,
            SUPPRESSIONS,
            &SUPPRESSIONS.replace("{uuid}", "no-such"),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(M::GET, SUPPRESSIONS, &path, w, Send::Nothing, S::FORBIDDEN)
        .await;

    // a reader can't validate, and a validator can't list
    client
        .json(
            M::POST,
            VALIDATE,
            VALIDATE,
            r,
            good_body(VALIDATE),
            S::FORBIDDEN,
        )
        .await;
    client
        .json(M::GET, HUNTS, HUNTS, w, Send::Nothing, S::FORBIDDEN)
        .await;

    let rows = audit_count(stack).await;
    let valid = client
        .json(
            M::POST,
            VALIDATE,
            VALIDATE,
            w,
            Send::Json(json!({"compiled_hunt": hunt_package(HUNT_RULE)})),
            S::OK,
        )
        .await;
    assert_eq!(valid, json!({"valid": true}));
    assert_eq!(
        audit_count(stack).await,
        rows + 1,
        "a validation is audited"
    );
    let (action, target): (String, String) =
        sqlx::query_as("SELECT action, target_id FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        (action.as_str(), target.as_str()),
        ("validate_hunt", "splunk")
    );

    let ran = client
        .json(
            M::POST,
            VALIDATE,
            VALIDATE,
            w,
            Send::Json(json!({
                "compiled_hunt": hunt_package(HUNT_RULE),
                "execution_arguments": {"query_results": [
                    {"_time": "2026-11-01T11:55:00.000+00:00", "user": "CORP\\alice"},
                    {"user": "<script>"},
                ]},
            })),
            S::OK,
        )
        .await;
    let roots = ran["roots"].as_array().expect("roots");
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["description"], "CORP\\alice failed");
    assert_eq!(roots[0]["event_time"], "2026-11-01T11:55:00+00:00");
    assert_eq!(roots[0]["observables"][0]["value"], "alice");
    assert_eq!(
        roots[0]["details"]["query"],
        Value::Null,
        "nothing was searched"
    );
    assert_eq!(
        roots[1]["description"], "<script> failed",
        "as the row had it"
    );

    for (body, why) in [
        (
            json!({"compiled_hunt": hunt_package("rule: [")}),
            "invalid hunt config",
        ),
        (
            json!({"compiled_hunt": {"target": "../x.yaml", "assets": []}}),
            "outside the package root",
        ),
        (
            json!({"compiled_hunt": hunt_package(HUNT_RULE), "execution_arguments": {"start_time": "11/01/2026:11:50:00"}}),
            "only ace hunter holds",
        ),
        (
            json!({"compiled_hunt": hunt_package(HUNT_RULE), "execution_arguments": {"query_results": [], "create_alerts": true}}),
            "create_alerts",
        ),
    ] {
        let refused = client
            .json(
                M::POST,
                VALIDATE,
                VALIDATE,
                w,
                Send::Json(body),
                S::BAD_REQUEST,
            )
            .await;
        assert_eq!(refused["valid"], false);
        assert!(
            refused["error"].as_str().is_some_and(|e| e.contains(why)),
            "{why}: {refused}"
        );
    }
    client
        .json(
            M::POST,
            VALIDATE,
            VALIDATE,
            w,
            Send::Json(json!({"compiled": 1})),
            S::UNPROCESSABLE_ENTITY,
        )
        .await;

    // a correlated hunt (PLAN.md 6.6): checked as ace3's validation checks one, and run over the
    // rows sent, its saved queries replayed, a query it can't replay failing its step
    let rows = audit_count(stack).await;
    let correlated = client
        .json(
            M::POST,
            VALIDATE,
            VALIDATE,
            w,
            Send::Json(json!({
                "compiled_hunt": hunt_package(&format!("{HUNT_RULE}{CORRELATE}")),
                "execution_arguments": {
                    "query_results": [
                        {"_time": "2026-11-01T11:55:00.000+00:00", "user": "alice"},
                        {"_time": "2026-11-01T11:56:00.000+00:00", "user": "bob"},
                        {"_time": "2026-11-01T11:57:00.000+00:00", "user": "carol"},
                    ],
                    "correlate_results": {"version": 1, "queries": [
                        {"source": "splunk", "query": "search ctx user=alice", "results": [{"seen": "1"}]},
                    ]},
                },
            })),
            S::OK,
        )
        .await;
    assert_eq!(audit_count(stack).await, rows + 1, "audited");
    let roots = correlated["roots"].as_array().expect("roots");
    // bob is filtered
    assert_eq!(roots.len(), 2);
    assert_eq!(
        roots[0]["details"]["events"][0]["ctx"],
        json!([{"seen": "1"}])
    );
    assert!(
        roots[0]["tags"]
            .as_array()
            .is_some_and(|t| t.contains(&json!("correlated")))
    );
    let trace = &correlated["correlation_trace"]["event_traces"];
    assert_eq!(trace[1]["outcome"], "filter");
    // carol's query wasn't saved and this process has no data source: her event alerts
    assert_eq!(trace[2]["outcome"], "error");
    assert!(
        trace[2]["steps"][1]["step"]["error"]
            .as_str()
            .is_some_and(|e| e.contains("query source not registered")),
        "{trace}"
    );
    assert!(
        roots[1]["tags"]
            .as_array()
            .is_some_and(|t| t.contains(&json!("warning:hunt_error")))
    );
    assert_eq!(
        correlated["original_events"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        correlated["correlate_results"],
        json!({"version": 1, "queries": [
            {"source": "splunk", "query": "search ctx user=alice", "results": [{"seen": "1"}]},
        ]})
    );
    // a hunt that doesn't correlate has none
    assert_eq!(ran["correlation_trace"], Value::Null);
    assert_eq!(ran["correlate_results"], Value::Null);
    for (correlate, why) in [
        (
            CORRELATE.replace("{{ _event.user }}", "{{ _secrets.key }}"),
            "references _secrets",
        ),
        (
            "  correlate:\n    logic:\n      - transform:\n          property_name: x\n          command: {type: wiz_lookup}\n".to_owned(),
            "unknown command type 'wiz_lookup'",
        ),
    ] {
        let refused = client
            .json(
                M::POST,
                VALIDATE,
                VALIDATE,
                w,
                Send::Json(json!({"compiled_hunt": hunt_package(&format!("{HUNT_RULE}{correlate}"))})),
                S::BAD_REQUEST,
            )
            .await;
        assert!(
            refused["error"].as_str().is_some_and(|e| e.contains(why)),
            "{why}: {refused}"
        );
    }
}

/// A correlation for the router's test: bob filtered, each other row's context from a query.
const CORRELATE: &str = "  correlate:
    logic:
      - when: {type: equals, property: user, value: bob}
        execute:
          - action: filter
      - transform:
          property_name: ctx
          property_type: list
          command:
            type: query
            source: splunk
            query: \"search ctx user={{ _event.user }}\"
";

/// PLAN.md 7.9: ace3's `remediation` and `file_collection` routers. Each status the document lists, the
/// writes audited and attributed, and a key with no owner refused a remediation.
async fn remediation_routers(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let json = Send::Json;
    let stack = client.stack;
    let db = stack.test_db.db();
    let (_, analyst) = session_of(
        stack,
        "remediator",
        &[
            "remediation:read",
            "remediation:write",
            "file_collection:read",
            "file_collection:write",
            "file_collection:create",
        ],
    )
    .await;
    let a = Some(analyst.as_str());
    let ownerless = key(stack, &["remediation:read", "remediation:write"]).await;
    let o = Some(ownerless.as_str());
    let at = |route: &str, id: &Value| route.replace("{id}", &id.to_string().replace('"', ""));
    let rows = audit_count(stack).await;

    // queueing: attributed to the analyst, audited once, and refused a key with no owner
    let queued = client
        .json(
            M::POST,
            REMEDIATIONS,
            REMEDIATIONS,
            a,
            json(json!({"action": "remove", "targets": [
                {"remediator": "test", "observable_type": "test", "observable_value": "SUCCESS"},
                {"remediator": "test", "observable_type": "test", "observable_value": "<b>DELAYED</b>"},
                {"remediator": "test", "observable_type": "test", "observable_value": "=FAILED"},
            ]})),
            S::CREATED,
        )
        .await;
    let ids: Vec<Value> = queued["remediations"]
        .as_array()
        .expect("remediations")
        .iter()
        .map(|r| r["id"].clone())
        .collect();
    assert_eq!(queued["remediations"][0]["status"], "NEW");
    assert_eq!(audit_count(stack).await, rows + 1);
    let refused = client
        .json(
            M::POST,
            REMEDIATIONS,
            REMEDIATIONS,
            o,
            good_body_json(REMEDIATIONS),
            S::FORBIDDEN,
        )
        .await;
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("analyst's")),
        "{refused}"
    );
    for body in [
        json!({"action": "remove", "targets": []}),
        json!({"action": "remove", "targets": [
            {"remediator": "office365_email", "observable_type": "test", "observable_value": "x"}]}),
        json!({"action": "remove", "targets": [
            {"remediator": "test", "observable_type": "fqdn", "observable_value": "x"}]}),
        json!({"action": "explode", "targets": []}),
    ] {
        client
            .json(
                M::POST,
                REMEDIATIONS,
                REMEDIATIONS,
                a,
                json(body),
                S::BAD_REQUEST,
            )
            .await;
    }
    let response = client
        .call(M::POST, REMEDIATIONS, REMEDIATIONS, a, too_large())
        .await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);
    assert_eq!(
        audit_count(stack).await,
        rows + 1,
        "nothing refused has a row"
    );

    // targets of observables and of alerts
    let targets = client
        .json(
            M::POST,
            TARGETS,
            TARGETS,
            a,
            json(json!({"observables": [{"type": "test", "value": "SUCCESS"}]})),
            S::OK,
        )
        .await;
    assert_eq!(
        targets["targets"][0]["remediator_display_name"],
        "Test Remediator"
    );
    assert_eq!(targets["targets"][0]["current"]["id"], ids[0]);
    let alert_id = alert(stack, "with targets", &[(ObservableKind::Test, "NEW_ONE")]).await;
    let of_alert = client
        .json(
            M::POST,
            TARGETS,
            TARGETS,
            a,
            json(json!({"alerts": [alert_id]})),
            S::OK,
        )
        .await;
    assert_eq!(of_alert["targets"][0]["observable_value"], "NEW_ONE");
    assert_eq!(of_alert["targets"][0]["current"], Value::Null);
    for body in [
        json!({}),
        json!({"alerts": [alert_id], "observables": [{"type": "test", "value": "x"}]}),
        json!({"observables": [{"type": "no_such_type", "value": "x"}]}),
    ] {
        client
            .json(M::POST, TARGETS, TARGETS, a, json(body), S::BAD_REQUEST)
            .await;
    }
    client
        .json(
            M::POST,
            TARGETS,
            TARGETS,
            a,
            json(json!({"alerts": [Uuid::nil()]})),
            S::NOT_FOUND,
        )
        .await;
    let response = client.call(M::POST, TARGETS, TARGETS, a, too_large()).await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);

    // the list, one, the exports
    let page = client
        .json(
            M::GET,
            REMEDIATIONS,
            &format!("{REMEDIATIONS}?limit=2"),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["total"], 3);
    assert_eq!(page["remediations"][0]["id"], ids[2], "newest first");
    assert_eq!(page["remediations"][0]["analyst"], "remediator");
    assert_eq!(page["next"], ids[1]);
    let filtered = client
        .json(
            M::GET,
            REMEDIATIONS,
            &format!("{REMEDIATIONS}?f=value:DELAYED"),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(
        filtered["remediations"][0]["observable_value"], "<b>DELAYED</b>",
        "as stored"
    );
    for bad in [
        "?f=nope:x",
        "?f=result:HOST_OFFLINE",
        "?limit=0",
        "?after=x",
    ] {
        client
            .json(
                M::GET,
                REMEDIATIONS,
                &format!("{REMEDIATIONS}{bad}"),
                a,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let one = client
        .json(
            M::GET,
            REMEDIATION,
            &at(REMEDIATION, &ids[0]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(one["action"], "remove");
    client
        .json(
            M::GET,
            REMEDIATION,
            &at(REMEDIATION, &json!("x")),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            REMEDIATION,
            &at(REMEDIATION, &json!(i64::MAX)),
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    for (route, kind) in [
        (REMEDIATIONS_CSV, "text/csv"),
        (REMEDIATIONS_NDJSON, "application/x-ndjson"),
    ] {
        let (status, content, body) = client
            .text(route, &format!("{route}?f=value:SUCCESS"), &analyst)
            .await;
        assert_eq!(status, S::OK, "{body}");
        assert!(content.starts_with(kind), "{content}");
        assert!(body.contains("SUCCESS"), "{body}");
        let (status, _, _) = client.text(route, route, &analyst).await;
        assert_eq!(
            status,
            S::PAYLOAD_TOO_LARGE,
            "three is past the export's two"
        );
        let (status, _, _) = client
            .text(route, &format!("{route}?f=nope:x"), &analyst)
            .await;
        assert_eq!(status, S::BAD_REQUEST);
    }
    let (_, _, csv) = client
        .text(
            REMEDIATIONS_CSV,
            &format!("{REMEDIATIONS_CSV}?f=value:FAILED"),
            &analyst,
        )
        .await;
    assert!(csv.contains(",'=FAILED,"), "a formula is guarded: {csv}");

    // cancel, retry, restore, history, delete
    let cancelled = client
        .json(
            M::POST,
            REMEDIATION_CANCEL,
            &at(REMEDIATION_CANCEL, &ids[1]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(cancelled["result"], "CANCELLED");
    client
        .json(
            M::POST,
            REMEDIATION_CANCEL,
            &at(REMEDIATION_CANCEL, &ids[1]),
            a,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    let retried = client
        .json(
            M::POST,
            REMEDIATION_RETRY,
            &at(REMEDIATION_RETRY, &ids[1]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(retried["status"], "NEW");
    client
        .json(
            M::POST,
            REMEDIATION_RETRY,
            &at(REMEDIATION_RETRY, &ids[1]),
            a,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    client
        .json(
            M::POST,
            REMEDIATION_RESTORE,
            &at(REMEDIATION_RESTORE, &ids[0]),
            a,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    sqlx::query(
        "UPDATE queue.actions SET status = 'COMPLETED', result = 'SUCCESS', attempts = 1,
                updated_at = now(), restore_key = 'moved' WHERE id = $1",
    )
    .bind(ids[0].as_i64().expect("an id"))
    .execute(db.pool())
    .await
    .expect("completes");
    let restore = client
        .json(
            M::POST,
            REMEDIATION_RESTORE,
            &at(REMEDIATION_RESTORE, &ids[0]),
            a,
            Send::Nothing,
            S::CREATED,
        )
        .await;
    assert_eq!(restore["action"], "restore");
    let history = client
        .json(
            M::GET,
            REMEDIATION_HISTORY,
            &at(REMEDIATION_HISTORY, &ids[1]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(history["attempts"][0]["message"], "cancelled by remediator");
    client
        .json(
            M::GET,
            REMEDIATION_HISTORY,
            &format!("{}?limit=0", at(REMEDIATION_HISTORY, &ids[1])),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    for (route, method) in [
        (REMEDIATION_HISTORY, M::GET),
        (REMEDIATION_CANCEL, M::POST),
        (REMEDIATION_RETRY, M::POST),
        (REMEDIATION_RESTORE, M::POST),
    ] {
        client
            .json(
                method.clone(),
                route,
                &at(route, &json!(i64::MAX)),
                a,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
        client
            .json(
                method,
                route,
                &at(route, &json!("x")),
                a,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let response = client
        .call(
            M::DELETE,
            REMEDIATION,
            &at(REMEDIATION, &ids[2]),
            a,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::NO_CONTENT);
    let response = client
        .call(
            M::DELETE,
            REMEDIATION,
            &at(REMEDIATION, &ids[2]),
            a,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::NOT_FOUND);
    let response = client
        .call(
            M::DELETE,
            REMEDIATION,
            &at(REMEDIATION, &json!("x")),
            a,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::BAD_REQUEST);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM service.audit WHERE action LIKE '%remediation%' ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(
        actions,
        [
            "queue_remediations",
            "cancel_remediation",
            "retry_remediation",
            "restore_remediation",
            "delete_remediation"
        ]
    );

    // the file collections: two alerts share one, which belongs to each
    let other = alert(stack, "also asks", &[(ObservableKind::Fqdn, "x.example")]).await;
    let catalog = test_actions();
    let mut made = Vec::new();
    for (root, value) in [
        (Some(alert_id), "h@C:\\a.exe"),
        (Some(other), "h@C:\\a.exe"),
        (None, "h@C:\\b.exe"),
        (None, "=h@C:\\c.exe"),
    ] {
        let mut tx = db.begin().await.expect("begins");
        let requested = ace_core::actions::request_collection(
            &mut tx,
            &catalog,
            &ace_core::actions::NewCollection {
                handler: "edr",
                observable_type: "file_location",
                observable_value: value,
                root,
                requested_by: None,
                user: None,
            },
        )
        .await
        .expect("requests");
        tx.commit().await.expect("commits");
        made.push(json!(requested.id()));
    }
    assert_eq!(made[0], made[1], "joined");
    let page = client
        .json(M::GET, COLLECTIONS, COLLECTIONS, a, Send::Nothing, S::OK)
        .await;
    assert_eq!(page["total"], 3);
    assert_eq!(page["collections"][2]["alerts"], json!([alert_id, other]));
    assert_eq!(page["collections"][2]["collector_display_name"], "Test EDR");
    for bad in ["?f=alert:x", "?f=remediator:x", "?limit=x"] {
        client
            .json(
                M::GET,
                COLLECTIONS,
                &format!("{COLLECTIONS}{bad}"),
                a,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let one = client
        .json(
            M::GET,
            COLLECTION,
            &at(COLLECTION, &made[0]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(one["status"], "NEW");
    client
        .json(
            M::GET,
            COLLECTION,
            &at(COLLECTION, &json!("x")),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::GET,
            COLLECTION,
            &at(COLLECTION, &ids[0]),
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    for route in [COLLECTIONS_CSV, COLLECTIONS_NDJSON] {
        let (status, _, body) = client
            .text(route, &format!("{route}?f=value:c.exe"), &analyst)
            .await;
        assert_eq!(status, S::OK, "{body}");
        let (status, _, _) = client.text(route, route, &analyst).await;
        assert_eq!(status, S::PAYLOAD_TOO_LARGE);
        let (status, _, _) = client
            .text(route, &format!("{route}?f=nope:x"), &analyst)
            .await;
        assert_eq!(status, S::BAD_REQUEST);
    }
    client
        .json(
            M::POST,
            COLLECTION_CANCEL,
            &at(COLLECTION_CANCEL, &made[2]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    client
        .json(
            M::POST,
            COLLECTION_CANCEL,
            &at(COLLECTION_CANCEL, &made[2]),
            a,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    let retried = client
        .json(
            M::POST,
            COLLECTION_RETRY,
            &at(COLLECTION_RETRY, &made[2]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(retried["status"], "NEW");
    let history = client
        .json(
            M::GET,
            COLLECTION_HISTORY,
            &at(COLLECTION_HISTORY, &made[2]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(history["attempts"][0]["result"], "CANCELLED");
    client
        .json(
            M::GET,
            COLLECTION_HISTORY,
            &format!("{}?limit=x", at(COLLECTION_HISTORY, &made[2])),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    for (route, method) in [
        (COLLECTION_HISTORY, M::GET),
        (COLLECTION_CANCEL, M::POST),
        (COLLECTION_RETRY, M::POST),
    ] {
        client
            .json(
                method.clone(),
                route,
                &at(route, &json!(i64::MAX)),
                a,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
        client
            .json(
                method,
                route,
                &at(route, &json!("x")),
                a,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    for (path, status) in [
        (at(COLLECTION, &made[3]), S::NO_CONTENT),
        (at(COLLECTION, &made[3]), S::NOT_FOUND),
        (at(COLLECTION, &json!("x")), S::BAD_REQUEST),
    ] {
        let response = client
            .call(M::DELETE, COLLECTION, &path, a, Send::Nothing)
            .await;
        assert_eq!(response.status(), status, "{path}");
    }

    // asking for a file (the owner's decision of 2026-11-13): a new collection, 201, and a request for a
    // file a pending collection is fetching joins it, 200, its alerts belonging to it as well (#1101)
    let asker = key(stack, &["file_collection:create"]).await;
    let rows = audit_count(stack).await;
    let ask = |value: &str, alerts: &[Uuid]| {
        json!({
            "collector": "edr", "observable_type": "file_location", "observable_value": value,
            "alerts": alerts,
        })
    };
    let asked = client
        .json(
            M::POST,
            COLLECTIONS,
            COLLECTIONS,
            a,
            json(ask("h@C:\\d.exe", &[])),
            S::CREATED,
        )
        .await;
    assert_eq!(
        (&asked["queued"], &asked["status"], &asked["alerts"]),
        (&json!(true), &json!("NEW"), &json!([]))
    );
    let third = alert(stack, "asks as well", &[]).await;
    let joined = client
        .json(
            M::POST,
            COLLECTIONS,
            COLLECTIONS,
            a,
            json(ask("h@C:\\a.exe", &[third])),
            S::OK,
        )
        .await;
    assert_eq!(
        (&joined["id"], &joined["queued"]),
        (&made[0], &json!(false))
    );
    assert_eq!(joined["alerts"], json!([alert_id, other, third]));
    let one = client
        .json(
            M::GET,
            COLLECTION,
            &at(COLLECTION, &asked["id"]),
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(one["requested_by"], "remediator");
    // a key with no owner may ask: the request is the key's
    let by_key = client
        .json(
            M::POST,
            COLLECTIONS,
            COLLECTIONS,
            Some(asker.as_str()),
            json(ask("h@C:\\e.exe", &[])),
            S::CREATED,
        )
        .await;
    assert_eq!(by_key["queued"], true);
    assert_eq!(audit_count(stack).await, rows + 3);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM service.audit WHERE action = 'request_file_collection' ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(actions.len(), 3);
    for body in [
        json!({"collector": "endpoint", "observable_type": "file_location", "observable_value": "h@C:\\x"}),
        json!({"collector": "edr", "observable_type": "hostname", "observable_value": "h"}),
        json!({"collector": "edr", "observable_type": "file_location", "observable_value": "no host"}),
        json!({"collector": "edr", "observable_type": "file_location", "observable_value": "h@C:\\x", "extra": 1}),
        json!({"collector": "edr", "observable_type": "file_location"}),
        json!({"collector": "edr", "observable_type": "file_location", "observable_value": "h@C:\\x", "alerts": ["x"]}),
    ] {
        client
            .json(
                M::POST,
                COLLECTIONS,
                COLLECTIONS,
                a,
                json(body),
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::POST,
            COLLECTIONS,
            COLLECTIONS,
            a,
            json(ask("h@C:\\x.exe", &[Uuid::nil()])),
            S::NOT_FOUND,
        )
        .await;
    let response = client
        .call(M::POST, COLLECTIONS, COLLECTIONS, a, too_large())
        .await;
    assert_eq!(response.status(), S::PAYLOAD_TOO_LARGE);
    assert_eq!(
        audit_count(stack).await,
        rows + 3,
        "nothing refused has a row"
    );
}

/// `good_body`'s JSON, for a route that takes one.
fn good_body_json(route: &str) -> Send {
    match good_body(route) {
        Send::Json(value) => Send::Json(value),
        _ => panic!("{route} takes no JSON body"),
    }
}

// ---- SVS's samples (PLAN.md 7.10 batch 2) ----

const SAMPLE_RULE: &str = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f";
const SAMPLE_OTHER_RULE: &str = "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b";

/// An alert of `disposition` with a file YARA's rules matched, its detections, and a stored capture of
/// it per rule with its bytes in the samples' pool, as the core's capture leaves them. Returns the alert,
/// the file's sha256 and the bytes.
async fn sample_fixture(
    stack: &Stack,
    disposition: &str,
    rules: &[&str],
) -> (Uuid, String, Vec<u8>) {
    let db = stack.test_db.db();
    let bytes = format!("<b>svs</b> sample {}", Uuid::new_v4()).into_bytes();
    let sha256 = sha256_hex(&bytes);
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let observable = tree::upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::File, sha256.clone()),
    )
    .await
    .expect("adds")
    .id;
    tree::add_file(&mut tx, root.id, observable, "mail/<b>x</b>.doc", &[])
        .await
        .expect("its path");
    tx.commit().await.expect("commits");
    let spooled = stack
        .bucket
        .store()
        .spool_bytes(&bytes)
        .await
        .expect("spools");
    for (index, rule) in rules.iter().enumerate() {
        sqlx::query(
            "INSERT INTO analysis.detections
                 (root_id, observable_id, description, details, signature_uuid, signature_version)
             VALUES ($1, $2, 'matched', $3, $4, 'c')",
        )
        .bind(root.id)
        .bind(observable.0)
        .bind(json!({"sha256": sha256, "rule": format!("rule_{index}"), "namespace": "ns", "rule_uuid": rule}))
        .bind(rule)
        .execute(db.pool())
        .await
        .expect("a detection");
        let capture: i64 = sqlx::query_scalar(
            "INSERT INTO svs.yara_captures
                 (root_id, observable_id, sha256, rule_uuid, rule_name, namespace, signature_version,
                  file_path, file_size, state, record, match_summary, stored_at)
             VALUES ($1, $2, $3, $4, '<i>rule</i>', 'ns', 'c', 'mail/<b>x</b>.doc', $5, 'stored',
                     '{\"rule\": \"<i>rule</i>\"}', '{\"string_match_count\": 1}', now())
             RETURNING id",
        )
        .bind(root.id)
        .bind(observable.0)
        .bind(&sha256)
        .bind(rule)
        .bind(i64::try_from(bytes.len()).expect("small"))
        .fetch_one(db.pool())
        .await
        .expect("a capture");
        let mut tx = db.begin().await.expect("begins");
        stack
            .bucket
            .put_in(
                &mut tx,
                "svs_samples",
                &spooled,
                Some(&ace_core::bucket::Hold::new(
                    "svs_capture",
                    capture.to_string(),
                )),
            )
            .await
            .expect("puts");
        tx.commit().await.expect("commits");
    }
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = now(), disposition = $2,
             dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}'
         WHERE id = $1",
    )
    .bind(root.id)
    .bind(disposition)
    .execute(db.pool())
    .await
    .expect("dispositions it");
    (root.id, sha256, bytes)
}

fn sample_at(route: &str, sha256: &str, rule: &str) -> String {
    route
        .replace("{sha256}", sha256)
        .replace("{rule_uuid}", rule)
}

/// ace3's `tests/aceapi_v2/svs/test_samples.py`: the list with its label and counts, its filters, sorts,
/// cursors and exports, one sample with its captures and their verdicts, a capture's record, the missing
/// counts, the downloads and their limits, relabel, reset and confirm, retire and unretire, a deletion and
/// its audit, with each documented status.
async fn svs_samples(client: &mut Client<'_>, token: &str) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let admin = key(stack, &["svs:admin"]).await;
    let t = Some(token);
    let (root, sha256, bytes) =
        sample_fixture(stack, "DELIVERY", &[SAMPLE_RULE, SAMPLE_OTHER_RULE]).await;
    let (_, fp_sha, _) = sample_fixture(stack, "FALSE_POSITIVE", &[SAMPLE_RULE]).await;
    let (_, simulated, _) =
        sample_fixture(stack, "SIMULATED", &[SAMPLE_RULE, SAMPLE_OTHER_RULE]).await;

    // the list: rows carry the label and counts
    let page = client
        .json(
            M::GET,
            SAMPLES,
            &format!("{SAMPLES}?sort=sha256&desc=false&limit=10"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    let rows = page["samples"].as_array().expect("samples");
    assert_eq!(rows.len(), 5);
    let ours = rows
        .iter()
        .find(|r| r["sha256"] == sha256 && r["rule_uuid"] == SAMPLE_RULE)
        .expect("our sample");
    assert_eq!(ours["label"], "tp");
    assert_eq!(ours["label_source"], "inherited_multi");
    assert_eq!(ours["capture_count"], 1);
    assert_eq!(ours["stored"], 1);
    assert_eq!(ours["votes"]["tp_inherited_multi"], 1);
    assert_eq!(ours["file_path"], "mail/<b>x</b>.doc", "a path is data");
    assert_eq!(ours["rule_name"], "<i>rule</i>");
    assert_eq!(page["next"], Value::Null);
    // a filter, and paging that follows next to the end
    let filtered = client
        .json(
            M::GET,
            SAMPLES,
            &format!("{SAMPLES}?f=label%3Afp"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(filtered["samples"].as_array().expect("samples").len(), 1);
    assert_eq!(filtered["samples"][0]["sha256"], fp_sha);
    let first = client
        .json(
            M::GET,
            SAMPLES,
            &format!("{SAMPLES}?limit=2"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    let cursor = first["next"].as_str().expect("a next page").to_owned();
    let second = client
        .json(
            M::GET,
            SAMPLES,
            &format!("{SAMPLES}?limit=2&cursor={cursor}"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(second["samples"].as_array().expect("samples").len(), 2);
    for query in [
        "?limit=0",
        "?sort=size",
        "?desc=maybe",
        "?f=label%3Amaybe",
        "?f=nope%3Ax",
        "?changed_since=yesterday",
        "?cursor=nonsense",
    ] {
        client
            .json(
                M::GET,
                SAMPLES,
                &format!("{SAMPLES}{query}"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    // a cursor belongs to its order
    client
        .json(
            M::GET,
            SAMPLES,
            &format!("{SAMPLES}?limit=2&sort=rule&cursor={cursor}"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // the exports, past their bound of 2 and within it
    for route in [SAMPLES_CSV, SAMPLES_NDJSON] {
        client
            .json(M::GET, route, route, t, Send::Nothing, S::PAYLOAD_TOO_LARGE)
            .await;
        client
            .json(
                M::GET,
                route,
                &format!("{route}?f=bogus%3Ax"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
        let response = client
            .call(
                M::GET,
                route,
                &format!("{route}?f=sha256%3A{sha256}"),
                t,
                Send::Nothing,
            )
            .await;
        assert_eq!(response.status(), S::OK);
        let text = response.text().await.expect("text");
        if route == SAMPLES_CSV {
            let mut lines = text.lines();
            assert!(
                lines
                    .next()
                    .expect("a header")
                    .starts_with("sha256,rule_uuid,rule_name")
            );
            assert_eq!(lines.count(), 2);
        } else {
            assert_eq!(text.lines().count(), 2);
            let row: Value =
                serde_json::from_str(text.lines().next().expect("a line")).expect("JSON");
            assert_eq!(row["sha256"], sha256);
        }
    }

    // one sample, its captures and their verdicts
    let detail = client
        .json(
            M::GET,
            SAMPLE,
            &sample_at(SAMPLE, &sha256, SAMPLE_RULE),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(detail["sample"]["sha256"], sha256);
    let capture = &detail["captures"][0];
    assert_eq!(capture["alert"], json!(root));
    assert_eq!(capture["state"], "stored");
    assert_eq!(capture["has_record"], true);
    assert_eq!(capture["detections"][0]["verdict"], "tp");
    assert_eq!(
        capture["detections"][0]["verdict_source"],
        "inherited_multi"
    );
    assert_eq!(detail["relabel_refusal"], Value::Null);
    let refused = client
        .json(
            M::GET,
            SAMPLE,
            &sample_at(SAMPLE, &fp_sha, SAMPLE_RULE),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert!(
        refused["relabel_refusal"]
            .as_str()
            .is_some_and(|r| r.contains("correct its disposition")),
        "{refused}"
    );
    client
        .json(
            M::GET,
            SAMPLE,
            &sample_at(SAMPLE, &sha256, "no-such-rule"),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            SAMPLE,
            &sample_at(SAMPLE, "not-a-sha", SAMPLE_RULE),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // a capture's record, inline and never sniffed
    let id = capture["id"].as_i64().expect("an id");
    let response = client
        .call(
            M::GET,
            SAMPLE_RECORD,
            &SAMPLE_RECORD.replace("{id}", &id.to_string()),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["content-type"], "application/json");
    let record: Value = response.json().await.expect("JSON");
    assert_eq!(record["rule"], "<i>rule</i>");
    client
        .json(
            M::GET,
            SAMPLE_RECORD,
            &SAMPLE_RECORD.replace("{id}", "0"),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            SAMPLE_RECORD,
            &SAMPLE_RECORD.replace("{id}", "x"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // the missing counts
    sqlx::query(
        "INSERT INTO svs.yara_captures (root_id, sha256, rule_uuid, rule_name, signature_version,
                                        file_path, state, missing_reason)
         VALUES ($1, repeat('c', 64), $2, 'gone_rule', 'c', 'x', 'missing', 'file')",
    )
    .bind(Uuid::new_v4())
    .bind(SAMPLE_RULE)
    .execute(stack.test_db.db().pool())
    .await
    .expect("a missing capture");
    let missing = client
        .json(
            M::GET,
            SAMPLES_MISSING,
            SAMPLES_MISSING,
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(
        missing,
        json!([{"rule_uuid": SAMPLE_RULE, "rule_name": "gone_rule", "reason": "file", "count": 1}])
    );

    // one sample's download: its file once and its records, in a zip with ace3's password
    let response = client
        .call(
            M::GET,
            SAMPLE_DOWNLOAD,
            &sample_at(SAMPLE_DOWNLOAD, &sha256, SAMPLE_RULE),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let zipped = response.bytes().await.expect("the zip");
    let (names, mut read) = unzip(&zipped);
    let label = format!("svs-sample-{sha256}");
    assert!(names.contains(&format!("{label}/manifest.json")));
    assert_eq!(read(&format!("{label}/{sha256}/{sha256}")), bytes);
    assert!(names.contains(&format!("{label}/{sha256}/match-{id}.json")));
    client
        .json(
            M::GET,
            SAMPLE_DOWNLOAD,
            &sample_at(SAMPLE_DOWNLOAD, &sha256, "no-such-rule"),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            SAMPLE_DOWNLOAD,
            &sample_at(SAMPLE_DOWNLOAD, "nope", SAMPLE_RULE),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    // the bulk download: each file once, whatever its rules
    let response = client
        .call(
            M::GET,
            SAMPLES_DOWNLOAD,
            &format!("{SAMPLES_DOWNLOAD}?f=sha256%3A{sha256}"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let zipped = response.bytes().await.expect("the zip");
    let (names, mut read) = unzip(&zipped);
    let manifest: Value =
        serde_json::from_slice(&read("svs-samples/manifest.json")).expect("a manifest");
    assert_eq!(manifest["files"].as_array().expect("files").len(), 1);
    assert_eq!(
        manifest["files"][0]["rule_uuids"]
            .as_array()
            .expect("rules")
            .len(),
        2
    );
    assert!(names.contains(&format!("svs-samples/{sha256}/{sha256}")));
    client
        .json(
            M::GET,
            SAMPLES_DOWNLOAD,
            &format!("{SAMPLES_DOWNLOAD}?f=rule%3Anothing"),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            SAMPLES_DOWNLOAD,
            &format!("{SAMPLES_DOWNLOAD}?f=bogus%3Ax"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    // past the limit of files
    sqlx::query(
        "INSERT INTO svs.yara_captures (root_id, sha256, rule_uuid, rule_name, signature_version,
                                        file_path, file_size, state, stored_at, record)
         SELECT gen_random_uuid(), encode(sha256(n::text::bytea), 'hex'), 'bulk', 'bulk_rule', 'c',
                'x', 1, 'stored', now(), '{}'
         FROM generate_series(1, $1) n",
    )
    .bind(i32::try_from(ace_service::MAX_SAMPLE_DOWNLOAD_FILES + 1).expect("small"))
    .execute(stack.test_db.db().pool())
    .await
    .expect("many captures");
    client
        .json(
            M::GET,
            SAMPLES_DOWNLOAD,
            &format!("{SAMPLES_DOWNLOAD}?f=signature%3Abulk"),
            t,
            Send::Nothing,
            S::PAYLOAD_TOO_LARGE,
        )
        .await;

    // relabel, reset and confirm
    let label_path = sample_at(SAMPLE_LABEL, &sha256, SAMPLE_RULE);
    let changed = client
        .json(
            M::PUT,
            SAMPLE_LABEL,
            &label_path,
            t,
            Send::Json(json!({"verdict": "fp"})),
            S::OK,
        )
        .await;
    assert_eq!(changed["changed"], 1);
    assert_eq!(
        (changed["label"].clone(), changed["label_source"].clone()),
        (json!("fp"), json!("explicit"))
    );
    let reset = client
        .json(
            M::DELETE,
            SAMPLE_LABEL,
            &label_path,
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(reset["changed"], 1);
    assert_eq!(reset["label_source"], "inherited_multi");
    client
        .json(
            M::PUT,
            SAMPLE_LABEL,
            &label_path,
            t,
            Send::Json(json!({"verdict": "maybe"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            SAMPLE_LABEL,
            &label_path,
            t,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    client
        .json(
            M::PUT,
            SAMPLE_LABEL,
            &sample_at(SAMPLE_LABEL, &fp_sha, SAMPLE_RULE),
            t,
            Send::Json(json!({"verdict": "tp"})),
            S::CONFLICT,
        )
        .await;
    for route in [SAMPLE_LABEL, SAMPLE_CONFIRM] {
        let method = if route == SAMPLE_LABEL {
            M::DELETE
        } else {
            M::POST
        };
        client
            .json(
                method.clone(),
                route,
                &sample_at(route, &sha256, "no-such-rule"),
                t,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
        client
            .json(
                method,
                route,
                &sample_at(route, "zz", SAMPLE_RULE),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::PUT,
            SAMPLE_LABEL,
            &sample_at(SAMPLE_LABEL, &sha256, "no-such-rule"),
            t,
            Send::Json(json!({"verdict": "fp"})),
            S::NOT_FOUND,
        )
        .await;
    let confirmed = client
        .json(
            M::POST,
            SAMPLE_CONFIRM,
            &sample_at(SAMPLE_CONFIRM, &sha256, SAMPLE_RULE),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(confirmed["changed"], 1);
    assert_eq!(confirmed["label_source"], "explicit");
    // only ACE grades a SIMULATED alert's detections
    client
        .json(
            M::POST,
            SAMPLE_CONFIRM,
            &sample_at(SAMPLE_CONFIRM, &simulated, SAMPLE_RULE),
            t,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;

    // retire and unretire, by an admin
    let a = Some(admin.as_str());
    let retirement = sample_at(SAMPLE_RETIREMENT, &sha256, SAMPLE_RULE);
    let retired = client
        .json(
            M::PUT,
            SAMPLE_RETIREMENT,
            &retirement,
            a,
            Send::Json(json!({"reason": "stale"})),
            S::OK,
        )
        .await;
    assert_eq!(
        (retired["retired"].clone(), retired["reason"].clone()),
        (json!(true), json!("stale"))
    );
    for body in [json!({"reason": "  "}), json!({"why": "x"})] {
        client
            .json(
                M::PUT,
                SAMPLE_RETIREMENT,
                &retirement,
                a,
                Send::Json(body),
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::PUT,
            SAMPLE_RETIREMENT,
            &retirement,
            a,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    client
        .json(
            M::PUT,
            SAMPLE_RETIREMENT,
            &sample_at(SAMPLE_RETIREMENT, &sha256, "no-such-rule"),
            a,
            Send::Json(json!({"reason": "x"})),
            S::NOT_FOUND,
        )
        .await;
    let unretired = client
        .json(
            M::DELETE,
            SAMPLE_RETIREMENT,
            &retirement,
            a,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(unretired["retired"], false);
    client
        .json(
            M::DELETE,
            SAMPLE_RETIREMENT,
            &retirement,
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            SAMPLE_RETIREMENT,
            &sample_at(SAMPLE_RETIREMENT, "zz", SAMPLE_RULE),
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // a deletion, its audit, and the deletions page
    let file = SAMPLE_FILE.replace("{sha256}", &sha256);
    let deleted = client
        .json(
            M::DELETE,
            SAMPLE_FILE,
            &file,
            a,
            Send::Json(json!({"reason": "legal request"})),
            S::OK,
        )
        .await;
    assert_eq!(deleted["capture_count"], 2);
    assert!(deleted["purged_at"].is_string());
    client
        .json(
            M::GET,
            SAMPLE,
            &sample_at(SAMPLE, &sha256, SAMPLE_RULE),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            SAMPLE_FILE,
            &SAMPLE_FILE.replace("{sha256}", &"ef".repeat(32)),
            a,
            Send::Json(json!({"reason": "x"})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            SAMPLE_FILE,
            &SAMPLE_FILE.replace("{sha256}", "zz"),
            a,
            Send::Json(json!({"reason": "x"})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::DELETE,
            SAMPLE_FILE,
            &file,
            a,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let page = client
        .json(
            M::GET,
            SAMPLE_DELETIONS,
            &format!("{SAMPLE_DELETIONS}?limit=1"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["deletions"][0]["sha256"], sha256);
    assert_eq!(page["deletions"][0]["reason"], "legal request");
    assert_eq!(page["next"], Value::Null);
    for query in ["?limit=0", "?cursor=nope", "?changed_since=x"] {
        client
            .json(
                M::GET,
                SAMPLE_DELETIONS,
                &format!("{SAMPLE_DELETIONS}{query}"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
}

/// A validation request of `base` × 40 against `head`.
fn validation_body(head: &str) -> Value {
    json!({
        "repository": "svs_rules",
        "base_sha": "a".repeat(40),
        "head_sha": head,
        "branch": "feature",
        "pr_url": "https://git.example/pr/7",
    })
}

/// A completed validation of the request for `head`, its report listing `rows` of (sha256, category,
/// rule uuid), as a worker would leave it.
async fn completed_validation_at(stack: &Stack, head: &str, rows: &[(String, &str, &str)]) -> Uuid {
    use ace_core::svs::validations as queue;
    use ace_core::svs::yara::diff::{Category, Outcome as ScanOutcome, ResultRow};
    use ace_core::svs::yara::replay::{FileError, ReplayResult};
    let db = stack.test_db.db();
    let actor = json!({"kind": "internal", "id": "test"});
    let mut tx = db.begin().await.expect("begins");
    let (uuid, _) = queue::request_validation(
        tx.conn(),
        &queue::ValidationRequest {
            repository: "svs_rules",
            base_sha: &"a".repeat(40),
            head_sha: head,
            branch: "feature",
            pr_url: None,
            requested_by: &actor,
        },
        "v",
        "f",
    )
    .await
    .expect("requests");
    tx.commit().await.expect("commits");
    sqlx::query(
        "UPDATE svs.validations SET created_at = created_at - interval '100 years' WHERE uuid = $1",
    )
    .bind(uuid)
    .execute(db.pool())
    .await
    .expect("makes it the oldest");
    let claimed = queue::claim(db, "node1", std::time::Duration::from_secs(300), 3)
        .await
        .expect("claims")
        .expect("a claim");
    assert_eq!(claimed.uuid, uuid);
    let mut result = ReplayResult::new("svs_rules", &"a".repeat(40), head);
    let mut counts = std::collections::BTreeMap::new();
    result.rows = rows
        .iter()
        .map(|(sha256, category, rule)| {
            let category = Category::parse(category).expect("a category");
            *counts.entry(category).or_default() += 1;
            ResultRow {
                sha256: sha256.clone(),
                rule_uuid: (*rule).to_owned(),
                rule_name: "<i>svs_rule</i>".to_owned(),
                namespace: Some("acme".to_owned()),
                label: Some("tp".to_owned()),
                label_source: Some("inherited_single".to_owned()),
                base: ScanOutcome::Match,
                head: ScanOutcome::Miss,
                raw_base: true,
                raw_head: false,
                category,
                note: None,
            }
        })
        .collect();
    result.counts = ReplayResult::all_counts(&counts);
    result.diffed = true;
    result.head.file_errors = vec![FileError {
        file: "yara/acme/broken.yar".to_owned(),
        namespace: "acme".to_owned(),
        error: "syntax error".to_owned(),
        dropped: vec![],
    }];
    queue::complete(db, &claimed, &result, "v", "f")
        .await
        .expect("completes");
    uuid
}

/// ace3's `tests/aceapi_v2/svs/test_validations.py`: a request queued then shared (202, then 200) with
/// its audit rows, bad requests, the status that names rules and never a sample, the CI key that reads only
/// the status, the list's filters, pages and exports, the detail with its report, the rows by category and
/// rule with their exports, and the selection's encrypted download and its limits, with each documented
/// status.
/// A test of the catalog, seeded as ace3's API tests seed theirs: `custom_removed` for one of the
/// repository `custom` that was removed.
async fn catalog_test(
    stack: &Stack,
    n: u128,
    technique: &str,
    name: &str,
    platforms: &[&str],
    executor: &str,
    custom_removed: bool,
) {
    let (repository, removed) = if custom_removed {
        ("custom", true)
    } else {
        ("atomic-red-team", false)
    };
    sqlx::query(
        "INSERT INTO svs.catalog_tests
             (guid, repository, technique, technique_name, name, description, platforms, executor, test,
              content_hash, commit, path, removed_at)
         VALUES ($1, $2, $3, $3 || ' name', $4, $4 || ' does a thing', $5, $6,
                 jsonb_build_object('name', $4, 'executor',
                                    jsonb_build_object('name', $6, 'command', 'whoami')),
                 repeat('0', 64), repeat('a', 40), 'atomics/' || $3 || '/' || $3 || '.yaml',
                 CASE WHEN $7 THEN now() END)",
    )
    .bind(catalog_guid(n))
    .bind(repository)
    .bind(technique)
    .bind(name)
    .bind(platforms.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>())
    .bind(executor)
    .bind(removed)
    .execute(stack.test_db.db().pool())
    .await
    .expect("seeds a test");
}

/// The runs' launcher calls and the test hosts with their maintenance windows (PLAN.md 7.10 batch 5, part
/// 5a): ace3's `tests/aceapi_v2/svs/test_runs.py` and `test_test_hosts.py`, each case named where it's
/// ported. `test_a_change_from_a_stale_form_is_refused`, `test_the_listing_pages_by_hostname` and
/// `test_exports` come with part 5b's preconditions, paging and exports.
async fn svs_runs(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let db = stack.test_db.db();
    let launcher = key(stack, &["svs:run_register"]).await;
    let reader = key(stack, &["svs:run_read"]).await;
    let admin = key(stack, &["svs:admin", "svs:run_read"]).await;
    let (l, r, a) = (
        Some(launcher.as_str()),
        Some(reader.as_str()),
        Some(admin.as_str()),
    );
    catalog_test(
        stack,
        21,
        "T1105",
        "A run's test",
        &["windows"],
        "powershell",
        false,
    )
    .await;
    catalog_test(stack, 22, "T1105", "A linux test", &["linux"], "sh", false).await;
    let guid = catalog_guid(21);
    let at = |route: &str, id: &dyn std::fmt::Display| {
        route
            .replace("{run_id}", &id.to_string())
            .replace("{host}", &id.to_string())
    };

    // test_create_read_update_delete
    let made = client
        .json(
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS,
            a,
            Send::Json(json!({
                "hostname": "WIN10-01.lab.example", "usernames": ["LAB\\svc_art"],
                "ips": ["10.0.0.5"], "platform": "Windows", "notes": "lab 3",
            })),
            S::CREATED,
        )
        .await;
    let host_id = made["id"].as_i64().expect("an id");
    assert_eq!(
        (
            &made["hostname"],
            &made["fqdn"],
            &made["usernames"],
            &made["ips"],
            &made["platform"],
            &made["notes"],
            &made["created_by"]["kind"]
        ),
        (
            &json!("win10-01"),
            &json!("win10-01.lab.example"),
            &json!(["svc_art"]),
            &json!(["10.0.0.5"]),
            &json!("windows"),
            &json!("lab 3"),
            &json!("api_key")
        )
    );
    let host = at(TEST_HOST, &host_id);
    let read = client
        .json(M::GET, TEST_HOST, &host, r, Send::Nothing, S::OK)
        .await;
    assert_eq!(read, made);
    let any = client
        .json(
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS,
            a,
            Send::Json(json!({"hostname": "anyuser-01"})),
            S::CREATED,
        )
        .await;
    let any_id = any["id"].as_i64().expect("an id");
    let changed = client
        .json(
            M::PUT,
            TEST_HOST,
            &at(TEST_HOST, &any_id),
            a,
            Send::Json(json!({"hostname": "anyuser-01", "notes": "any user"})),
            S::OK,
        )
        .await;
    assert_eq!(
        (&changed["notes"], &changed["usernames"]),
        (&json!("any user"), &json!([]))
    );
    let listed = client
        .json(M::GET, TEST_HOSTS, TEST_HOSTS, r, Send::Nothing, S::OK)
        .await;
    let names: Vec<&str> = listed
        .as_array()
        .expect("hosts")
        .iter()
        .map(|h| h["hostname"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["anyuser-01", "win10-01"]);
    let srv = client
        .json(
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS,
            a,
            Send::Json(json!({"hostname": "srv-01"})),
            S::CREATED,
        )
        .await;
    let srv_id = srv["id"].as_i64().expect("an id");

    // test_errors
    let taken = client
        .json(
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS,
            a,
            Send::Json(json!({"hostname": "win10-01.other.example"})),
            S::CONFLICT,
        )
        .await;
    assert_eq!(taken["error"], "win10-01 is already a test host");
    for body in [
        json!({"hostname": "not a host"}),
        json!({"hostname": "ok", "platform": "amiga"}),
        json!({"hostname": "ok", "surprise": 1}),
    ] {
        client
            .json(
                M::POST,
                TEST_HOSTS,
                TEST_HOSTS,
                a,
                Send::Json(body.clone()),
                S::BAD_REQUEST,
            )
            .await;
        client
            .json(
                M::PUT,
                TEST_HOST,
                &host,
                a,
                Send::Json(body),
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS,
            a,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    client
        .json(
            M::PUT,
            TEST_HOST,
            &host,
            a,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    client
        .json(
            M::PUT,
            TEST_HOST,
            &host,
            a,
            Send::Json(json!({"hostname": "anyuser-01"})),
            S::CONFLICT,
        )
        .await;
    let nowhere = at(TEST_HOST, &999_999);
    let not_a_number = at(TEST_HOST, &"win10-01");
    client
        .json(M::GET, TEST_HOST, &nowhere, r, Send::Nothing, S::NOT_FOUND)
        .await;
    client
        .json(
            M::GET,
            TEST_HOST,
            &not_a_number,
            r,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::PUT,
            TEST_HOST,
            &nowhere,
            a,
            Send::Json(json!({"hostname": "gone"})),
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            TEST_HOST,
            &nowhere,
            a,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::DELETE,
            TEST_HOST,
            &not_a_number,
            a,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // test_reading_needs_run_read_and_writing_needs_admin
    for (method, route, path, token, body) in [
        (M::GET, TEST_HOSTS, TEST_HOSTS.to_owned(), l, Send::Nothing),
        (M::GET, TEST_HOST, host.clone(), l, Send::Nothing),
        (
            M::POST,
            TEST_HOSTS,
            TEST_HOSTS.to_owned(),
            r,
            Send::Json(json!({"hostname": "nope"})),
        ),
        (
            M::PUT,
            TEST_HOST,
            host.clone(),
            r,
            Send::Json(json!({"hostname": "nope"})),
        ),
        (M::DELETE, TEST_HOST, host.clone(), l, Send::Nothing),
    ] {
        client
            .json(method, route, &path, token, body, S::FORBIDDEN)
            .await;
    }

    // test_the_request_is_validated
    let body = |targets: Value| {
        json!({"test_guid": guid, "targets": targets, "launcher": "art",
                                        "batch_id": "batch-1", "extra": {"ticket": 42}})
    };
    let on = |host: &str, user: Option<&str>| body(json!([{"hostname": host, "username": user}]));
    for bad in [
        json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}]}),
        json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}], "launcher": ""}),
        json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}], "launcher": "art",
               "batch_id": "x".repeat(257)}),
        json!({"test_guid": guid, "targets": "anyuser-01", "launcher": "art"}),
        json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}], "launcher": "art",
               "surprise": true}),
    ] {
        for route in [RUNS, RUNS_VALIDATE] {
            client
                .json(
                    M::POST,
                    route,
                    route,
                    l,
                    Send::Json(bad.clone()),
                    S::BAD_REQUEST,
                )
                .await;
        }
    }
    for route in [RUNS, RUNS_VALIDATE] {
        client
            .json(M::POST, route, route, l, too_large(), S::PAYLOAD_TOO_LARGE)
            .await;
    }

    // test_invalid_registrations
    for (bad, expected) in [
        (
            json!({"test_guid": catalog_guid(99), "targets": [{"hostname": "anyuser-01"}], "launcher": "art"}),
            "is not in the catalog",
        ),
        (
            json!({"test_guid": catalog_guid(22), "targets": [{"hostname": "win10-01", "username": "svc_art"}],
                   "launcher": "art"}),
            "test host win10-01 is windows",
        ),
        (body(json!([])), "at least one target"),
        (
            json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}], "launcher": "art",
                   "extra": {"blob": "x".repeat(20000)}}),
            "larger than 16384 bytes",
        ),
        (
            json!({"test_guid": guid, "targets": [{"hostname": "anyuser-01"}], "launcher": "art",
                   "extra": ["not", "an", "object"]}),
            "must be a JSON object",
        ),
    ] {
        let error = client
            .json(
                M::POST,
                RUNS,
                RUNS,
                l,
                Send::Json(bad.clone()),
                S::BAD_REQUEST,
            )
            .await;
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|e| e.contains(expected)),
            "{expected}: {error}"
        );
        // a dry run says the same, as a decision
        let decision = client
            .json(
                M::POST,
                RUNS_VALIDATE,
                RUNS_VALIDATE,
                l,
                Send::Json(bad),
                S::OK,
            )
            .await;
        assert_eq!(
            (&decision["decision"], &decision["status_code"]),
            (&json!("invalid"), &json!(400))
        );
        assert_eq!(decision["message"], error["error"]);
    }

    // test_validate_answers_what_registering_would_and_writes_nothing
    let run_count = async || -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM svs.runs")
            .fetch_one(db.pool())
            .await
            .expect("counts")
    };
    let (audited, roots) = (audit_count(stack).await, root_count(stack).await);
    let decision = client
        .json(
            M::POST,
            RUNS_VALIDATE,
            RUNS_VALIDATE,
            l,
            Send::Json(on("WIN10-01", Some("svc_art@lab.example"))),
            S::OK,
        )
        .await;
    assert_eq!(
        decision,
        json!({
            "decision": "accepted", "status_code": 201, "message": null,
            "targets": [{"hostname": "WIN10-01", "username": "svc_art@lab.example", "accepted": true,
                         "reason": null, "test_host": "win10-01", "platform": "windows", "held_by": []}],
            "platform": "windows", "observation_seconds": 3600, "observation_source": "all_hunts",
            "attribution_seconds": 90000, "holds_host": false,
        })
    );
    let refused = client
        .json(
            M::POST,
            RUNS_VALIDATE,
            RUNS_VALIDATE,
            l,
            Send::Json(body(
                json!([{"hostname": "anyuser-01"}, {"hostname": "prod-dc-01"}]),
            )),
            S::OK,
        )
        .await;
    assert_eq!(
        (
            &refused["decision"],
            &refused["status_code"],
            &refused["platform"]
        ),
        (&json!("refused"), &json!(403), &Value::Null)
    );
    assert_eq!(
        refused["targets"][1],
        json!({"hostname": "prod-dc-01", "username": null, "accepted": false,
               "reason": "prod-dc-01 is not a test host", "test_host": null, "platform": null,
               "held_by": []})
    );
    assert_eq!(run_count().await, 0);
    assert_eq!(
        (audit_count(stack).await, root_count(stack).await),
        (audited, roots),
        "a dry run writes nothing and alerts nobody"
    );

    // test_the_lifecycle
    let run = client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(on("WIN10-01", Some("svc_art@lab.example"))),
            S::CREATED,
        )
        .await;
    let run_id: Uuid = run["run_id"]
        .as_str()
        .expect("an id")
        .parse()
        .expect("a uuid");
    assert_eq!(
        (
            &run["state"],
            &run["test_guid"],
            &run["platform"],
            &run["observation_seconds"],
            &run["attribution_seconds"],
            &run["holds_host"],
            &run["started_at"]
        ),
        (
            &json!("created"),
            &json!(guid),
            &json!("windows"),
            &json!(3600),
            &json!(90000),
            &json!(false),
            &Value::Null
        )
    );
    assert!(ace_core::svs::markers::is_marker(
        run["marker"].as_str().expect("a marker")
    ));
    assert_eq!(
        run["targets"],
        json!([{"hostname": "WIN10-01", "username": "svc_art@lab.example", "host": "win10-01",
                "fqdn": "win10-01.lab.example", "user": "svc_art"}])
    );
    let start = at(RUN_START, &run_id);
    let started = client
        .json(M::POST, RUN_START, &start, l, Send::Nothing, S::OK)
        .await;
    assert_eq!(started["state"], "started");
    assert!(started["started_at"].is_string() && started["observation_ends_at"].is_string());
    assert_eq!(started["marker"], run["marker"]);

    // test_a_host_held_by_another_run_is_409
    let busy = client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(on("win10-01", Some("svc_art"))),
            S::CONFLICT,
        )
        .await;
    assert!(
        busy["error"]
            .as_str()
            .is_some_and(|e| e.starts_with(&format!(
                "test host win10-01 is held by run {run_id} (started, until "
            ))),
        "{busy}"
    );
    let decision = client
        .json(
            M::POST,
            RUNS_VALIDATE,
            RUNS_VALIDATE,
            l,
            Send::Json(on("win10-01", Some("svc_art"))),
            S::OK,
        )
        .await;
    assert_eq!(
        (&decision["decision"], &decision["status_code"]),
        (&json!("host_busy"), &json!(409))
    );
    let held = &decision["targets"][0]["held_by"][0];
    assert_eq!(
        (
            &held["host"],
            &held["run_id"],
            &held["state"],
            &held["maintenance_id"]
        ),
        (
            &json!("win10-01"),
            &json!(run_id),
            &json!("started"),
            &Value::Null
        )
    );
    assert_eq!(held["until"], started["observation_ends_at"]);

    // test_start_answers_409_when_another_run_holds_the_host: a run no registration decided
    let undecided = Uuid::new_v4();
    sqlx::query(
        "WITH run AS (
             INSERT INTO svs.runs
                 (uuid, test_guid, platform, test_content_hash, catalog_commit, state, marker, launcher,
                  observation_seconds, attribution_seconds)
             VALUES ($1, $2, 'windows', repeat('0', 64), repeat('a', 40), 'created', $3, 'art', 3600, 90000)
             RETURNING id)
         INSERT INTO svs.run_targets (run_id, hostname, host, test_host_id)
         SELECT run.id, 'win10-01', 'win10-01', $4 FROM run",
    )
    .bind(undecided)
    .bind(guid)
    .bind(ace_core::svs::markers::new_marker())
    .bind(host_id)
    .execute(db.pool())
    .await
    .expect("adds a run");
    let refused = client
        .json(
            M::POST,
            RUN_START,
            &at(RUN_START, &undecided),
            l,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains(&format!("is held by run {run_id}"))),
        "{refused}"
    );
    client
        .json(
            M::POST,
            RUN_CANCEL,
            &at(RUN_CANCEL, &undecided),
            l,
            Send::Nothing,
            S::OK,
        )
        .await;

    // test_conflicts_and_unknown_runs
    let conflict = client
        .json(M::POST, RUN_START, &start, l, Send::Nothing, S::CONFLICT)
        .await;
    assert_eq!(
        conflict["error"],
        format!("run {run_id} is started; start does not apply")
    );
    let unknown = Uuid::new_v4();
    for route in [RUN_START, RUN_CLEANUP, RUN_CANCEL] {
        client
            .json(
                M::POST,
                route,
                &at(route, &unknown),
                l,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
        client
            .json(
                M::POST,
                route,
                &at(route, &"not-a-uuid"),
                l,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let executed_body = Send::Json(json!({"exit_code": 0}));
    client
        .json(
            M::POST,
            RUN_EXECUTED,
            &at(RUN_EXECUTED, &unknown),
            l,
            executed_body,
            S::NOT_FOUND,
        )
        .await;
    for route in [RUN, RUN_EVENTS] {
        client
            .json(
                M::GET,
                route,
                &at(route, &unknown),
                r,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
        client
            .json(
                M::GET,
                route,
                &at(route, &"not-a-uuid"),
                r,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }

    // test_cleanup
    let cleanup = at(RUN_CLEANUP, &run_id);
    let cleaned = client
        .json(M::POST, RUN_CLEANUP, &cleanup, l, Send::Nothing, S::OK)
        .await;
    assert!(cleaned["cleanup_at"].is_string());
    client
        .json(
            M::POST,
            RUN_CLEANUP,
            &cleanup,
            l,
            Send::Nothing,
            S::CONFLICT,
        )
        .await;

    // the rest of test_the_lifecycle: executed, with what the test printed
    let executed = at(RUN_EXECUTED, &run_id);
    for bad in [
        json!({}),
        json!({"exit_code": "zero"}),
        json!({"exit_code": 0, "error": "x".repeat(8193)}),
    ] {
        client
            .json(
                M::POST,
                RUN_EXECUTED,
                &executed,
                l,
                Send::Json(bad),
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::POST,
            RUN_EXECUTED,
            &at(RUN_EXECUTED, &"not-a-uuid"),
            l,
            Send::Json(json!({"exit_code": 0})),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::POST,
            RUN_EXECUTED,
            &executed,
            l,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    let reported = client
        .json(
            M::POST,
            RUN_EXECUTED,
            &executed,
            l,
            Send::Json(json!({"exit_code": 0, "output": "<b>Executing</b> test\n"})),
            S::OK,
        )
        .await;
    assert_eq!(
        (&reported["state"], &reported["error_reason"]),
        (&json!("started"), &Value::Null)
    );
    let detail = client
        .json(M::GET, RUN, &at(RUN, &run_id), r, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        (
            &detail["run_id"],
            &detail["state"],
            &detail["launcher"],
            &detail["batch_id"],
            &detail["extra"],
            &detail["exit_code"],
            &detail["launcher_output"],
            &detail["registered_by"]["kind"],
            &detail["catalog_commit"]
        ),
        (
            &json!(run_id),
            &json!("started"),
            &json!("art"),
            &json!("batch-1"),
            &json!({"ticket": 42}),
            &json!(0),
            &json!("<b>Executing</b> test\n"),
            &json!("api_key"),
            &json!("a".repeat(40))
        )
    );
    let events = client
        .json(
            M::GET,
            RUN_EVENTS,
            &at(RUN_EVENTS, &run_id),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    let kinds: Vec<(&str, Option<&str>)> = events["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| {
            (
                e["kind"].as_str().expect("a kind"),
                e["details"]["outcome"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("registered", None),
            ("transition", None),
            ("launcher_call", Some("started")),
            ("launcher_call", Some("conflict")),
            ("launcher_call", Some("recorded")),
            ("launcher_call", Some("conflict")),
            ("launcher_call", Some("recorded")),
        ]
    );
    assert_eq!(events["next"], Value::Null);
    let page = client
        .json(
            M::GET,
            RUN_EVENTS,
            &format!("{}?limit=2", at(RUN_EVENTS, &run_id)),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(page["events"].as_array().map(Vec::len), Some(2));
    let rest = client
        .json(
            M::GET,
            RUN_EVENTS,
            &format!(
                "{}?limit=1000&after={}",
                at(RUN_EVENTS, &run_id),
                page["next"]
            ),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(rest["events"].as_array().map(Vec::len), Some(5));
    for bad in ["limit=0", "limit=1001", "after=x", "limit=1&limit=2"] {
        client
            .json(
                M::GET,
                RUN_EVENTS,
                &format!("{}?{bad}", at(RUN_EVENTS, &run_id)),
                r,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let cancel = at(RUN_CANCEL, &run_id);
    let canceled = client
        .json(M::POST, RUN_CANCEL, &cancel, l, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        (&canceled["state"], &canceled["close_reason"]),
        (&json!("canceled"), &Value::Null)
    );
    client
        .json(M::POST, RUN_CANCEL, &cancel, l, Send::Nothing, S::CONFLICT)
        .await;
    client
        .json(
            M::POST,
            RUN_EXECUTED,
            &executed,
            l,
            Send::Json(json!({"exit_code": 0})),
            S::CONFLICT,
        )
        .await;

    // test_a_reported_failure_and_a_cancel_before_start
    let second = client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(on("anyuser-01", None)),
            S::CREATED,
        )
        .await;
    let second_id = second["run_id"].as_str().expect("an id").to_owned();
    client
        .json(
            M::POST,
            RUN_START,
            &at(RUN_START, &second_id),
            l,
            Send::Nothing,
            S::OK,
        )
        .await;
    let failed = client
        .json(
            M::POST,
            RUN_EXECUTED,
            &at(RUN_EXECUTED, &second_id),
            l,
            Send::Json(json!({"exit_code": 1, "error": "Access is denied."})),
            S::OK,
        )
        .await;
    assert_eq!(
        (&failed["state"], &failed["error_reason"]),
        (
            &json!("error"),
            &json!("the launcher reported a failure (exit code 1: Access is denied.)")
        )
    );

    // test_every_call_needs_run_register: a reader's key makes none of the launcher's calls, and a
    // launcher's reads nothing
    for (method, route, path, token, body) in [
        (
            M::POST,
            RUNS,
            RUNS.to_owned(),
            r,
            Send::Json(on("prod-dc-01", None)),
        ),
        (
            M::POST,
            RUNS_VALIDATE,
            RUNS_VALIDATE.to_owned(),
            r,
            Send::Json(on("anyuser-01", None)),
        ),
        (M::POST, RUN_START, start.clone(), r, Send::Nothing),
        (
            M::POST,
            RUN_EXECUTED,
            executed.clone(),
            r,
            Send::Json(json!({"exit_code": 0})),
        ),
        (M::POST, RUN_CLEANUP, cleanup.clone(), r, Send::Nothing),
        (M::POST, RUN_CANCEL, cancel.clone(), a, Send::Nothing),
        (M::GET, RUN, at(RUN, &run_id), l, Send::Nothing),
        (
            M::GET,
            RUN_EVENTS,
            at(RUN_EVENTS, &run_id),
            l,
            Send::Nothing,
        ),
    ] {
        let refused = client
            .json(method, route, &path, token, body, S::FORBIDDEN)
            .await;
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("this needs svs:run_re")),
            "{route}: {refused}"
        );
    }

    // test_a_registration_against_a_non_test_host_is_refused_and_alerts
    let (audited, roots) = (audit_count(stack).await, root_count(stack).await);
    let refused = client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(body(
                json!([{"hostname": "ubuntu-77"}, {"hostname": "PROD-DC-01.corp.example"}]),
            )),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(
        refused["error"],
        "registration refused: ubuntu-77 is not a test host; prod-dc-01 is not a test host"
    );
    assert_eq!(
        root_count(stack).await,
        roots + 2,
        "an alert for each refused host"
    );
    assert_eq!(audit_count(stack).await, audited + 1);
    let alert: (String, String, Value, Value) = sqlx::query_as(
        "SELECT r.description, r.queue, r.origin, r.submitted_by::jsonb
         FROM svs.registration_refusals f JOIN analysis.roots r ON r.id = f.root_id
         WHERE f.host = 'prod-dc-01.corp.example'",
    )
    .fetch_one(db.pool())
    .await
    .expect("the refusal's alert");
    assert_eq!(
        (alert.0.as_str(), alert.1.as_str(), &alert.3),
        (
            "SVS test run registration refused: test targeted PROD-DC-01.corp.example",
            "default",
            &json!({"kind": "internal", "id": "svs"})
        )
    );
    assert_eq!(
        (
            &alert.2["alert_type"],
            &alert.2["details"]["caller_address"],
            &alert.2["details"]["launcher"]
        ),
        (
            &json!("svs - registration refused"),
            &json!("127.0.0.1"),
            &json!("art")
        )
    );
    // again this hour: refused, and no second alert
    client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(body(json!([{"hostname": "prod-dc-01.corp.example"}]))),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(root_count(stack).await, roots + 2);

    // test_maintenance_windows
    let window_of = |host: &dyn std::fmt::Display| at(MAINTENANCE, host);
    let opened = client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&"SRV-01"),
            l,
            Send::Json(json!({"minutes": 30, "reason": " staging mimikatz "})),
            S::CREATED,
        )
        .await;
    assert_eq!(
        (
            &opened["host"],
            &opened["test_host_id"],
            &opened["reason"],
            &opened["ended_at"],
            &opened["end_reason"],
            &opened["opened_by"]["name"]
        ),
        (
            &json!("srv-01"),
            &json!(srv_id),
            &json!("staging mimikatz"),
            &Value::Null,
            &Value::Null,
            &json!("test")
        )
    );
    // a window holds the host for runs and windows alike
    let again = client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&srv_id),
            l,
            Send::Json(json!({"minutes": 30, "reason": "again"})),
            S::CONFLICT,
        )
        .await;
    assert!(
        again["error"].as_str().is_some_and(|e| e.contains(&format!(
            "is in maintenance window {}",
            opened["maintenance_id"].as_str().expect("an id")
        ))),
        "{again}"
    );
    let busy = client
        .json(
            M::POST,
            RUNS,
            RUNS,
            l,
            Send::Json(on("srv-01", None)),
            S::CONFLICT,
        )
        .await;
    assert!(
        busy["error"]
            .as_str()
            .is_some_and(|e| e.contains("is in maintenance window"))
    );
    for bad in [
        json!({"minutes": 0, "reason": "staging"}),
        json!({"minutes": 241, "reason": "staging"}),
        json!({"minutes": 30, "reason": "  "}),
        json!({"minutes": 30}),
    ] {
        client
            .json(
                M::POST,
                MAINTENANCE,
                &window_of(&"win10-01"),
                l,
                Send::Json(bad),
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&"win10-01"),
            l,
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
    client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&999_999),
            l,
            Send::Json(json!({"minutes": 30, "reason": "staging"})),
            S::NOT_FOUND,
        )
        .await;
    // a host that isn't a test host is refused, which alerts
    let roots = root_count(stack).await;
    let refused = client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&"prod-web-01"),
            l,
            Send::Json(json!({"minutes": 30, "reason": "staging"})),
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(refused["error"], "prod-web-01 is not a test host");
    let refused = client
        .json(
            M::DELETE,
            MAINTENANCE,
            &window_of(&"prod-web-02"),
            l,
            Send::Nothing,
            S::FORBIDDEN,
        )
        .await;
    assert_eq!(refused["error"], "prod-web-02 is not a test host");
    assert_eq!(root_count(stack).await, roots + 2);
    let ended = client
        .json(
            M::DELETE,
            MAINTENANCE,
            &window_of(&"srv-01"),
            l,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(
        (
            &ended["maintenance_id"],
            &ended["end_reason"],
            &ended["ended_by"]["name"]
        ),
        (&opened["maintenance_id"], &json!("ended"), &json!("test"))
    );
    assert!(ended["ended_at"].is_string());
    let none = client
        .json(
            M::DELETE,
            MAINTENANCE,
            &window_of(&"srv-01"),
            l,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    assert_eq!(
        none["error"],
        "test host srv-01 has no open maintenance window"
    );

    // test_maintenance_listing_pages_by_window
    for reason in ["second", "third"] {
        client
            .json(
                M::POST,
                MAINTENANCE,
                &window_of(&srv_id),
                l,
                Send::Json(json!({"minutes": 5, "reason": reason})),
                S::CREATED,
            )
            .await;
        client
            .json(
                M::DELETE,
                MAINTENANCE,
                &window_of(&srv_id),
                l,
                Send::Nothing,
                S::OK,
            )
            .await;
    }
    let first = client
        .json(
            M::GET,
            MAINTENANCE,
            &format!("{}?limit=2", window_of(&"srv-01")),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    let reasons = |page: &Value| -> Vec<String> {
        page["windows"]
            .as_array()
            .expect("windows")
            .iter()
            .map(|w| w["reason"].as_str().expect("a reason").to_owned())
            .collect()
    };
    assert_eq!(reasons(&first), ["third", "second"]);
    let rest = client
        .json(
            M::GET,
            MAINTENANCE,
            &format!("{}?limit=2&before={}", window_of(&srv_id), first["next"]),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(reasons(&rest), ["staging mimikatz"]);
    assert_eq!(rest["next"], Value::Null);
    for bad in ["limit=0", "before=x"] {
        client
            .json(
                M::GET,
                MAINTENANCE,
                &format!("{}?{bad}", window_of(&srv_id)),
                r,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    for host in ["999999", "win10%2001"] {
        client
            .json(
                M::GET,
                MAINTENANCE,
                &window_of(&host),
                r,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
    }

    // test_maintenance_permissions
    for (method, token, body) in [
        (
            M::POST,
            r,
            Send::Json(json!({"minutes": 30, "reason": "staging"})),
        ),
        (
            M::POST,
            a,
            Send::Json(json!({"minutes": 30, "reason": "staging"})),
        ),
        (M::DELETE, r, Send::Nothing),
        (M::GET, l, Send::Nothing),
    ] {
        client
            .json(
                method,
                MAINTENANCE,
                &window_of(&"prod-web-03"),
                token,
                body,
                S::FORBIDDEN,
            )
            .await;
    }
    assert_eq!(
        root_count(stack).await,
        roots + 2,
        "a refused permission alerts nobody"
    );

    // test_removing_a_test_host_ends_its_maintenance_window
    let window = client
        .json(
            M::POST,
            MAINTENANCE,
            &window_of(&srv_id),
            l,
            Send::Json(json!({"minutes": 30, "reason": "its host goes"})),
            S::CREATED,
        )
        .await;
    let removed = client
        .call(
            M::DELETE,
            TEST_HOST,
            &at(TEST_HOST, &srv_id),
            a,
            Send::Nothing,
        )
        .await;
    assert_eq!(removed.status(), S::NO_CONTENT);
    let after = client
        .json(
            M::GET,
            MAINTENANCE,
            &window_of(&"srv-01"),
            r,
            Send::Nothing,
            S::OK,
        )
        .await;
    let last = &after["windows"][0];
    assert_eq!(
        (
            &last["maintenance_id"],
            &last["end_reason"],
            &last["test_host_id"]
        ),
        (&window["maintenance_id"], &json!("ended"), &Value::Null)
    );
    assert!(last["ended_at"].is_string());
    client
        .json(
            M::GET,
            TEST_HOST,
            &at(TEST_HOST, &srv_id),
            r,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
}

fn catalog_guid(n: u128) -> Uuid {
    Uuid::from_u128((n << 96) | 0x0000_4000_8000_0000_0000_0000)
}

/// The catalog's routes (PLAN.md 7.10 batch 4): ace3's `tests/aceapi_v2/svs/test_catalog.py`, but its
/// state and run history, which wait for batches 5 and 8. Everything reads with `svs:run_read` alone
/// (`test_permissions`).
async fn svs_catalog(client: &mut Client<'_>) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let reader = key(stack, &["svs:run_read"]).await;
    let t = Some(reader.as_str());
    let windows: &[&str] = &["windows"];
    catalog_test(
        stack,
        1,
        "T1059.001",
        "PowerShell download",
        windows,
        "powershell",
        false,
    )
    .await;
    catalog_test(
        stack,
        2,
        "T1059",
        "Command interpreter",
        &["linux", "macos"],
        "sh",
        false,
    )
    .await;
    catalog_test(
        stack,
        3,
        "T1003",
        "Dump credentials",
        windows,
        "powershell",
        false,
    )
    .await;
    catalog_test(
        stack,
        4,
        "T1059.003",
        "Batch file",
        windows,
        "command_prompt",
        true,
    )
    .await;
    catalog_test(
        stack,
        5,
        "T10590",
        "Not a sub-technique of T1059",
        windows,
        "powershell",
        false,
    )
    .await;
    let numbers = |body: &Value| -> Vec<u128> {
        body["tests"]
            .as_array()
            .expect("tests")
            .iter()
            .map(|t| {
                t["guid"]
                    .as_str()
                    .expect("a guid")
                    .parse::<Uuid>()
                    .expect("a uuid")
                    .as_u128()
                    >> 96
            })
            .collect()
    };

    // test_ordered_by_technique_then_name, and what a test carries
    let all = client
        .json(
            M::GET,
            CATALOG_TESTS,
            CATALOG_TESTS,
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(numbers(&all), [3, 2, 1, 4, 5]);
    assert_eq!(all["next"], Value::Null);
    let first = &all["tests"][1];
    assert_eq!(
        (
            first["repository"].clone(),
            first["technique"].clone(),
            first["technique_name"].clone(),
            first["name"].clone(),
            first["platforms"].clone(),
            first["executor"].clone(),
            first["path"].clone(),
            first["commit"].clone(),
            first["removed_at"].clone()
        ),
        (
            json!("atomic-red-team"),
            json!("T1059"),
            json!("T1059 name"),
            json!("Command interpreter"),
            json!(["linux", "macos"]),
            json!("sh"),
            json!("atomics/T1059/T1059.yaml"),
            json!("a".repeat(40)),
            Value::Null
        )
    );
    assert!(first["first_seen_at"].is_string() && first["updated_at"].is_string());
    assert!(first.get("description").is_none() && first.get("entry").is_none());
    assert!(all["tests"][3]["removed_at"].is_string());

    // test_filters: a technique also finds its sub-techniques, and nothing that only shares its prefix
    for (query, expected) in [
        ("?f=technique%3AT1059", vec![2, 1, 4]),
        ("?f=technique%3At1059.001", vec![1]),
        ("?f=!technique%3AT1059", vec![3, 5]),
        ("?f=platform%3Alinux", vec![2]),
        ("?f=executor%3Ash%2Ccommand_prompt", vec![2, 4]),
        ("?f=name%3Adownload", vec![1]),
        ("?f=repository%3Acustom", vec![4]),
        ("?f=removed%3Atrue", vec![4]),
        ("?f=removed%3Afalse&f=technique%3AT1059", vec![2, 1]),
        ("?changed_since=2999-01-01T00%3A00%3A00Z", vec![]),
        (
            "?changed_since=2000-01-01T00%3A00%3A00Z&limit=1000",
            vec![3, 2, 1, 4, 5],
        ),
    ] {
        let body = client
            .json(
                M::GET,
                CATALOG_TESTS,
                &format!("{CATALOG_TESTS}{query}"),
                t,
                Send::Nothing,
                S::OK,
            )
            .await;
        assert_eq!(numbers(&body), expected, "{query}");
    }

    // test_pages
    let mut pages = Vec::new();
    let mut cursor = String::new();
    loop {
        let body = client
            .json(
                M::GET,
                CATALOG_TESTS,
                &format!("{CATALOG_TESTS}?limit=2{cursor}"),
                t,
                Send::Nothing,
                S::OK,
            )
            .await;
        pages.push(numbers(&body));
        match body["next"].as_str() {
            Some(next) => cursor = format!("&cursor={next}"),
            None => break,
        }
    }
    assert_eq!(pages, [vec![3, 2], vec![1, 4], vec![5]]);

    // test_a_bad_filter_is_422, here 400, with the other parameters that aren't one
    for query in [
        "?f=technique%3Amimikatz",
        "?f=nonsense%3Ax",
        "?f=removed%3Amaybe",
        "?changed_since=yesterday",
        "?limit=0",
        "?limit=1001",
        "?cursor=zz",
        "?cursor=a&cursor=b",
    ] {
        let refused = client
            .json(
                M::GET,
                CATALOG_TESTS,
                &format!("{CATALOG_TESTS}{query}"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
        assert!(refused["error"].is_string(), "{query}: {refused}");
    }

    // test_exports: the list's rows as NDJSON, and as CSV with the platforms joined
    let response = client
        .call(
            M::GET,
            CATALOG_TESTS_NDJSON,
            &format!("{CATALOG_TESTS_NDJSON}?f=technique%3AT1059&f=removed%3Afalse"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    assert_eq!(response.headers()["content-type"], "application/x-ndjson");
    let lines: Vec<Value> = response
        .text()
        .await
        .expect("a body")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a line"))
        .collect();
    assert_eq!(
        lines
            .iter()
            .map(|l| l["guid"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        [catalog_guid(2).to_string(), catalog_guid(1).to_string()]
    );
    assert_eq!(lines[0]["platforms"], json!(["linux", "macos"]));
    let response = client
        .call(
            M::GET,
            CATALOG_TESTS_CSV,
            &format!("{CATALOG_TESTS_CSV}?f=technique%3AT1059&f=removed%3Afalse"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let csv = response.text().await.expect("a body");
    let mut rows = csv.lines();
    assert_eq!(
        rows.next(),
        Some(
            "guid,repository,technique,technique_name,name,platforms,executor,path,commit,content_hash,\
             first_seen_at,removed_at,updated_at"
        )
    );
    let row = rows.next().expect("a row");
    assert!(
        row.starts_with(&format!(
            "{},atomic-red-team,T1059,T1059 name,Command interpreter,\"linux,macos\",sh,atomics/T1059/T1059.yaml,",
            catalog_guid(2)
        )),
        "{row}"
    );
    assert_eq!(csv.lines().count(), 3);
    for route in [CATALOG_TESTS_CSV, CATALOG_TESTS_NDJSON] {
        // five tests are more than the test's export holds
        client
            .json(M::GET, route, route, t, Send::Nothing, S::PAYLOAD_TOO_LARGE)
            .await;
        client
            .json(
                M::GET,
                route,
                &format!("{route}?f=technique%3Amimikatz"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }

    // test_detail: a guid in any case; one that isn't a uuid; one the catalog doesn't have
    let one = CATALOG_TEST.replace("{guid}", &catalog_guid(1).to_string().to_uppercase());
    let detail = client
        .json(M::GET, CATALOG_TEST, &one, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(
        (
            detail["guid"].clone(),
            detail["name"].clone(),
            detail["technique"].clone(),
            detail["description"].clone(),
            detail["platforms"].clone(),
            detail["platform_slugs"].clone(),
            detail["removed_at"].clone()
        ),
        (
            json!(catalog_guid(1)),
            json!("PowerShell download"),
            json!("T1059.001"),
            json!("PowerShell download does a thing"),
            json!(["windows"]),
            json!(["windows"]),
            Value::Null
        )
    );
    assert_eq!(detail["entry"]["executor"]["command"], "whoami");
    let refused = client
        .json(
            M::GET,
            CATALOG_TEST,
            &CATALOG_TEST.replace("{guid}", "not-a-guid"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    assert_eq!(refused["error"], "invalid test guid \"not-a-guid\"");
    client
        .json(
            M::GET,
            CATALOG_TEST,
            &CATALOG_TEST.replace("{guid}", &catalog_guid(99).to_string()),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;

    // test_repositories: every repository of the overlay and every one with a row, by name; a URL
    // never shows its credentials
    sqlx::query(
        "INSERT INTO svs.catalog_repositories (name, commit, refreshed_at, test_count, skipped_count)
         VALUES ('art', repeat('c', 40), '2026-10-20T08:30:00Z', 1700, 2),
                ('dropped', repeat('d', 40), '2026-10-01T00:00:00Z', 0, 0)",
    )
    .execute(stack.test_db.db().pool())
    .await
    .expect("seeds the repositories");
    sqlx::query("UPDATE svs.catalog_repositories SET error = $1 WHERE name = 'dropped'")
        .bind(ace_core::svs::catalog::RETIRED_ERROR)
        .execute(stack.test_db.db().pool())
        .await
        .expect("retires one");
    let repositories = client
        .json(
            M::GET,
            CATALOG_REPOSITORIES,
            CATALOG_REPOSITORIES,
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(
        repositories,
        json!([
            {"name": "art", "configured": true,
             "git_url": "https://git.invalid/redcanaryco/atomic-red-team.git", "branch": "master",
             "commit": "c".repeat(40), "refreshed_at": "2026-10-20T08:30:00Z", "test_count": 1700,
             "skipped_count": 2, "removed_count": 0, "error": null, "retired": false},
            {"name": "dropped", "configured": false, "git_url": null, "branch": null,
             "commit": "d".repeat(40), "refreshed_at": "2026-10-01T00:00:00Z", "test_count": 0,
             "skipped_count": 0, "removed_count": 0, "error": null, "retired": true},
            {"name": "unread", "configured": true, "git_url": "/nowhere", "branch": "main",
             "commit": null, "refreshed_at": null, "test_count": 0, "skipped_count": 0,
             "removed_count": 0, "error": null, "retired": false},
        ])
    );

    // test_permissions: another permission reads none of it
    let other = key(stack, &["signature:read", "svs:validate", "svs:admin"]).await;
    for (route, path) in [
        (CATALOG_TESTS, CATALOG_TESTS.to_owned()),
        (CATALOG_TESTS_CSV, CATALOG_TESTS_CSV.to_owned()),
        (CATALOG_TESTS_NDJSON, CATALOG_TESTS_NDJSON.to_owned()),
        (CATALOG_TEST, one.clone()),
        (CATALOG_REPOSITORIES, CATALOG_REPOSITORIES.to_owned()),
    ] {
        let refused = client
            .json(
                M::GET,
                route,
                &path,
                Some(&other),
                Send::Nothing,
                S::FORBIDDEN,
            )
            .await;
        assert_eq!(refused["error"], "this needs svs:run_read", "{route}");
    }
}

async fn svs_validations(client: &mut Client<'_>, token: &str) {
    use Method as M;
    use StatusCode as S;
    let stack = client.stack;
    let t = Some(token);
    let ci = key(stack, &["svs:validate"]).await;

    // a request is queued, then shared, and both are audited
    let audits = audit_count(stack).await;
    let queued = client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            Send::Json(validation_body(&"B".repeat(40))),
            S::ACCEPTED,
        )
        .await;
    assert_eq!(
        (queued["state"].clone(), queued["head_sha"].clone()),
        (json!("queued"), json!("b".repeat(40)))
    );
    let uuid = queued["uuid"].as_str().expect("a uuid").to_owned();
    assert_eq!(
        queued["report_path"],
        format!("/signatures/validations/{uuid}")
    );
    let again = client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            Send::Json(validation_body(&"b".repeat(40))),
            S::OK,
        )
        .await;
    assert_eq!(again["uuid"], uuid);
    assert_eq!(audit_count(stack).await, audits + 2);
    // bad requests
    let mut elsewhere = validation_body(&"c".repeat(40));
    elsewhere["repository"] = json!("elsewhere");
    let refused = client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            Send::Json(elsewhere),
            S::BAD_REQUEST,
        )
        .await;
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("svs.yara.repositories"),
        "{refused}"
    );
    // an abbreviated commit wouldn't be recognized as the same commit
    client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            Send::Json(validation_body(&"b".repeat(12))),
            S::BAD_REQUEST,
        )
        .await;
    let mut script = validation_body(&"c".repeat(40));
    script["pr_url"] = json!("javascript:alert(1)");
    client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            Send::Json(script),
            S::BAD_REQUEST,
        )
        .await;
    client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            Some(&ci),
            too_large(),
            S::PAYLOAD_TOO_LARGE,
        )
        .await;

    // the status names rules, never a sample
    let shas = ["11".repeat(32), "22".repeat(32), "33".repeat(32)];
    let reported = completed_validation_at(
        stack,
        &"d".repeat(40),
        &[
            (shas[0].clone(), "regression", SAMPLE_RULE),
            (shas[1].clone(), "regression", SAMPLE_RULE),
            (shas[2].clone(), "new_fp_other_rule", SAMPLE_OTHER_RULE),
        ],
    )
    .await;
    let path = |route: &str| route.replace("{uuid}", &reported.to_string());
    let response = client
        .call(
            M::GET,
            VALIDATION_STATUS,
            &path(VALIDATION_STATUS),
            Some(&ci),
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let text = response.text().await.expect("a body");
    let status: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(status["state"], "completed");
    assert_eq!(status["counts"]["regression"], 2);
    assert_eq!(
        status["rules"]["regression"],
        json!([{"rule_uuid": SAMPLE_RULE, "rule_name": "<i>svs_rule</i>", "count": 2}])
    );
    assert_eq!(
        status["compile_errors"],
        json!([{"file": "yara/acme/broken.yar", "error": "syntax error"}])
    );
    for secret in &shas {
        assert!(!text.contains(secret.as_str()), "{secret} in {text}");
    }
    let unknown = VALIDATION_STATUS.replace("{uuid}", &Uuid::new_v4().to_string());
    client
        .json(
            M::GET,
            VALIDATION_STATUS,
            &unknown,
            Some(&ci),
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            VALIDATION_STATUS,
            &VALIDATION_STATUS.replace("{uuid}", "nope"),
            Some(&ci),
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    // the CI key reads the status only
    for route in [
        VALIDATIONS,
        VALIDATION,
        VALIDATION_RESULTS,
        VALIDATION_DOWNLOAD,
        SAMPLES,
    ] {
        client
            .json(
                M::GET,
                route,
                &path(route),
                Some(&ci),
                Send::Nothing,
                S::FORBIDDEN,
            )
            .await;
    }
    // a reader can't request, nor read the status
    client
        .json(
            M::POST,
            VALIDATIONS,
            VALIDATIONS,
            t,
            Send::Json(validation_body(&"e".repeat(40))),
            S::FORBIDDEN,
        )
        .await;
    client
        .json(
            M::GET,
            VALIDATION_STATUS,
            &path(VALIDATION_STATUS),
            t,
            Send::Nothing,
            S::FORBIDDEN,
        )
        .await;

    // the list: filters, pages, exports
    let clean = completed_validation_at(stack, &"f".repeat(40), &[]).await;
    let listed = |page: &Value| -> Vec<String> {
        page["validations"]
            .as_array()
            .expect("validations")
            .iter()
            .map(|v| v["uuid"].as_str().unwrap().to_owned())
            .collect()
    };
    let page = client
        .json(
            M::GET,
            VALIDATIONS,
            &format!("{VALIDATIONS}?f=has_regressions%3Atrue"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(listed(&page), [reported.to_string()]);
    let page = client
        .json(
            M::GET,
            VALIDATIONS,
            &format!("{VALIDATIONS}?f=head%3Affff"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(listed(&page), [clean.to_string()]);
    let all = client
        .json(M::GET, VALIDATIONS, VALIDATIONS, t, Send::Nothing, S::OK)
        .await;
    assert_eq!(listed(&all).len(), 3);
    let row = all["validations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["uuid"] == reported.to_string())
        .unwrap();
    assert_eq!(
        (
            row["regressions"].clone(),
            row["new_fps"].clone(),
            row["compile_errors"].clone()
        ),
        (json!(2), json!(1), json!(1))
    );
    let first = client
        .json(
            M::GET,
            VALIDATIONS,
            &format!("{VALIDATIONS}?limit=2"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    let cursor = first["next"].as_str().expect("a next page").to_owned();
    let second = client
        .json(
            M::GET,
            VALIDATIONS,
            &format!("{VALIDATIONS}?limit=2&cursor={cursor}"),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!([listed(&first), listed(&second)].concat(), listed(&all));
    assert_eq!(second["next"], Value::Null);
    for query in [
        "?f=state%3Adone",
        "?limit=0",
        "?cursor=junk",
        "?changed_since=yesterday",
        "?tz=Nowhere",
    ] {
        client
            .json(
                M::GET,
                VALIDATIONS,
                &format!("{VALIDATIONS}{query}"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    let response = client
        .call(
            M::GET,
            VALIDATIONS_NDJSON,
            &format!("{VALIDATIONS_NDJSON}?f=has_regressions%3Atrue"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let lines: Vec<Value> = response
        .text()
        .await
        .expect("a body")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a line"))
        .collect();
    assert_eq!(
        lines
            .iter()
            .map(|l| l["uuid"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        [reported.to_string()]
    );
    let response = client
        .call(
            M::GET,
            VALIDATIONS_CSV,
            &format!("{VALIDATIONS_CSV}?f=state%3Acompleted"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let csv = response.text().await.expect("a body");
    let header = csv.lines().next().expect("a header");
    assert!(
        header.starts_with("uuid,repository,") && !header.contains("counts"),
        "{header}"
    );
    assert_eq!(csv.lines().count(), 3);
    for route in [VALIDATIONS_CSV, VALIDATIONS_NDJSON] {
        // three validations are more than the test's export holds
        client
            .json(M::GET, route, route, t, Send::Nothing, S::PAYLOAD_TOO_LARGE)
            .await;
        client
            .json(
                M::GET,
                route,
                &format!("{route}?f=state%3Adone"),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }

    // the detail carries the report
    let detail = client
        .json(
            M::GET,
            VALIDATION,
            &path(VALIDATION),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(
        (
            detail["state"].clone(),
            detail["attempts"].clone(),
            detail["claimed_by"].clone()
        ),
        (json!("completed"), json!(1), json!("node1"))
    );
    assert_eq!(
        detail["report"]["head"]["file_errors"][0]["file"],
        "yara/acme/broken.yar"
    );
    assert!(detail["report"].get("rows").is_none());
    client
        .json(
            M::GET,
            VALIDATION,
            &unknown.replace("/status", ""),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            VALIDATION,
            &VALIDATION.replace("{uuid}", "nope"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;

    // the rows, by category and rule, and their exports
    let results = client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &path(VALIDATION_RESULTS),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    let shas_of = |page: &Value| -> Vec<String> {
        page["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|r| r["sha256"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(shas_of(&results), shas);
    assert_eq!(
        (
            results["results"][0]["label"].clone(),
            results["results"][0]["base"].clone()
        ),
        (json!("tp"), json!("match"))
    );
    let regressions = client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &format!("{}?category=regression", path(VALIDATION_RESULTS)),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(shas_of(&regressions).len(), 2);
    let other = client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &format!("{}?rule_uuid={SAMPLE_OTHER_RULE}", path(VALIDATION_RESULTS)),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(shas_of(&other), [shas[2].clone()]);
    let first = client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &format!("{}?limit=2", path(VALIDATION_RESULTS)),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    let cursor = first["next"].as_str().expect("a next page").to_owned();
    let second = client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &format!("{}?limit=2&cursor={cursor}", path(VALIDATION_RESULTS)),
            t,
            Send::Nothing,
            S::OK,
        )
        .await;
    assert_eq!(shas_of(&second), [shas[2].clone()]);
    for query in ["?category=known_fp", "?limit=0", "?cursor=junk"] {
        client
            .json(
                M::GET,
                VALIDATION_RESULTS,
                &format!("{}{query}", path(VALIDATION_RESULTS)),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
    }
    client
        .json(
            M::GET,
            VALIDATION_RESULTS,
            &VALIDATION_RESULTS.replace("{uuid}", &Uuid::new_v4().to_string()),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    let response = client
        .call(
            M::GET,
            VALIDATION_RESULTS_CSV,
            &format!("{}?category=regression", path(VALIDATION_RESULTS_CSV)),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let csv = response.text().await.expect("a body");
    assert_eq!(
        csv.lines()
            .skip(1)
            .map(|l| l.split(',').nth(11).unwrap().to_owned())
            .collect::<Vec<_>>(),
        ["regression", "regression"]
    );
    let response = client
        .call(
            M::GET,
            VALIDATION_RESULTS_NDJSON,
            &format!(
                "{}?category=new_fp_other_rule",
                path(VALIDATION_RESULTS_NDJSON)
            ),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let lines: Vec<Value> = response
        .text()
        .await
        .expect("a body")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a line"))
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["sha256"], shas[2]);
    for route in [VALIDATION_RESULTS_CSV, VALIDATION_RESULTS_NDJSON] {
        // three rows are more than the test's export holds
        client
            .json(
                M::GET,
                route,
                &path(route),
                t,
                Send::Nothing,
                S::PAYLOAD_TOO_LARGE,
            )
            .await;
        client
            .json(
                M::GET,
                route,
                &format!("{}?category=unchanged", path(route)),
                t,
                Send::Nothing,
                S::BAD_REQUEST,
            )
            .await;
        client
            .json(
                M::GET,
                route,
                &route.replace("{uuid}", &Uuid::new_v4().to_string()),
                t,
                Send::Nothing,
                S::NOT_FOUND,
            )
            .await;
    }

    // the selection's files, in a zip with ace3's password, audited
    let (_, stored, bytes) = sample_fixture(stack, "DELIVERY", &[SAMPLE_RULE]).await;
    let downloadable = completed_validation_at(
        stack,
        &"0".repeat(40),
        &[
            (stored.clone(), "regression", SAMPLE_RULE),
            // another rule's pair: the file still downloads, with its own samples' records
            (stored.clone(), "new_fp_other_rule", SAMPLE_OTHER_RULE),
            ("99".repeat(32), "new_fp", SAMPLE_RULE),
        ],
    )
    .await;
    let download = VALIDATION_DOWNLOAD.replace("{uuid}", &downloadable.to_string());
    let audits = audit_count(stack).await;
    let response = client
        .call(
            M::GET,
            VALIDATION_DOWNLOAD,
            &format!("{download}?category=regression&category=new_fp_other_rule"),
            t,
            Send::Nothing,
        )
        .await;
    assert_eq!(response.status(), S::OK);
    let zipped = response.bytes().await.expect("the zip");
    let (names, mut read) = unzip(&zipped);
    let label = format!("svs-validation-{downloadable}");
    assert_eq!(read(&format!("{label}/{stored}/{stored}")), bytes);
    let manifest: Value =
        serde_json::from_slice(&read(&format!("{label}/manifest.json"))).expect("a manifest");
    assert_eq!(
        manifest["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| f["sha256"].clone())
            .collect::<Vec<_>>(),
        [json!(stored)]
    );
    assert!(names.iter().any(|n| n.contains("/match-")));
    assert_eq!(audit_count(stack).await, audits + 1);
    // nothing of the selection is stored
    client
        .json(
            M::GET,
            VALIDATION_DOWNLOAD,
            &format!("{download}?category=new_fp"),
            t,
            Send::Nothing,
            S::NOT_FOUND,
        )
        .await;
    client
        .json(
            M::GET,
            VALIDATION_DOWNLOAD,
            &format!("{download}?category=unchanged"),
            t,
            Send::Nothing,
            S::BAD_REQUEST,
        )
        .await;
    // past the limit of files: the samples' bulk captures, each a row of a report
    let bulk: Vec<(String,)> =
        sqlx::query_as("SELECT sha256 FROM svs.yara_captures WHERE rule_uuid = 'bulk'")
            .fetch_all(stack.test_db.db().pool())
            .await
            .expect("the bulk captures");
    assert!(bulk.len() > ace_service::MAX_SAMPLE_DOWNLOAD_FILES);
    let rows: Vec<(String, &str, &str)> = bulk
        .into_iter()
        .map(|(sha256,)| (sha256, "regression", "bulk"))
        .collect();
    let large = completed_validation_at(stack, &"1".repeat(40), &rows).await;
    client
        .json(
            M::GET,
            VALIDATION_DOWNLOAD,
            &VALIDATION_DOWNLOAD.replace("{uuid}", &large.to_string()),
            t,
            Send::Nothing,
            S::PAYLOAD_TOO_LARGE,
        )
        .await;
}
