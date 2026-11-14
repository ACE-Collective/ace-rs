//! PLAN.md 5.1: one actor type, carried by every write. Each kind of actor writes through the same
//! function: the analysis it stops and starts is the same, and only who is recorded differs.
//!
//! PLAN.md 5.2: one case rule for permissions, and a check every write goes through. A permission
//! behaves the same in any case when stored and when checked, for every kind of actor.
//!
//! PLAN.md 5.3: every write records who changed what, atomically with the change. The two tests that
//! read this crate's source fail until a new write function has an audit test.
//!
//! PLAN.md 5.4: a GUI session and an API key each reach the service layer as the right actor, where
//! 5.2's check and 5.3's audit hold, and a failure to authenticate says and logs nothing useful.
//!
//! PLAN.md 5.5: a submission records its actor on the root and in its row, and a download is a row of
//! what was read, each with the source address an adapter gives. The API's own tests are `ace-api`'s.
//!
//! PLAN.md 5.6's `yara_qa`: the rules in QA mode merge the current ruleset with the matches kept, a
//! download is a row of what was read, and a purge releases only its own holds.
//!
//! PLAN.md 5.6's `observable_comments`: a comment is on a type and value across alerts, a person's, and
//! changed or deleted only by its author, with a deleted one kept in its audit row.
//!
//! PLAN.md 5.7's preferences: a user's own, checked by key, a default where none is stored or a stored
//! one can't be read, and refused to anyone but a user.
//!
//! PLAN.md 5.10: the alert list filters and pages through fixture alerts, every filter and its inverse,
//! every order both ways, with hostile values as data; ace3's share links and date ranges; the detection
//! points' filters; saved filters, their owner and their audit rows; and `manage_columns`.
//!
//! PLAN.md 7.6's `detection`: the observables ACE detects are entries of the `observable_detection`
//! list, listed, searched and paged as ace3 does, with ace3's default lifetimes, and audited as list
//! writes are.
//!
//! PLAN.md 7.9: remediations and file collections listed through their screens' filters, the targets of
//! alerts and observables, an alert's remediation coverage, and each write's audit row.
//!
//! PLAN.md 7.14: ace3's `tests/saq/detection_verdicts/` cases as Rust tests, each named for its case: the
//! effective rule in Rust and in SQL, the writes with their history and audit rows, batches and confirms,
//! and the verdict filters.
//!
//! PLAN.md 7.13: ace3's `tests/saq/alert_routing/` cases as Rust tests (`routing_tests`, whose comment maps
//! each case), and the routing's audited move.
//!
//! PLAN.md 5.11's events (6c): the event list's filters checked, each filter and each order both ways
//! through the keyset, the filters' choices, and an event's alerts with their state and tags.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ace_core::bucket::{ALERT_FILES, Bucket, BucketSettings, Hold};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::{Orchestrator, OrchestratorError};
use ace_core::submit::{Submission, SubmittedFile};
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot};
use ace_core::{Db, queue};
use ace_results::{AlertPath, AnalysisType, NewObservable, ObservableKind};
use ace_sdk::actions::RemediationAction;
use ace_sdk::lists::{ListSpec, MAX_ENTRIES};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{
    ALERT_WRITE, ActionQuery, Actor, ApiKeyId, CATALOG, CampaignChoice, CommandState, Component,
    CoverageState, CrashFilter, CrashInput, DetectionExpiry, DetectionFilter, DetectionPage,
    DetectionPointFilter, DetectionStatus, Effect, EventChoice, EventEdit, EventRef, EventTimes,
    GroupId, GroupSuppressed, Holder, HuntRun, HuntState, HuntSubmission, HuntValidation,
    ListEntry, LoadedHuntRow, MAX_CRASHES_PAGE, MIN_PASSWORD_CHARS, MalwareChoice, MatchKind,
    NewDetection, NewEvent, NewListEntry, NewSession, Password, PermissionName, PermissionPattern,
    PreferenceKey, PreferenceValue, Profile, QaPruned, QaPurge, QaRuleFilter, QaSort, QaStatus,
    RequestParts, SESSION_LIFETIME_SECONDS, Service, ServiceError, SessionCookie,
    SuppressionReason, TargetKey, Theme, ThemePreference, Transport, USER_SELF, USER_WRITE, UserId,
    Username, with_source_ip,
};
use ace_store::{BucketConfig, NodeCache, Store};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StubOutput {
    note: String,
}

impl AnalysisType for StubOutput {
    const NAME: &'static str = "test_stub";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "test_stub";
}

macro_rules! stub {
    ($ty:ident, $name:literal) => {
        struct $ty;

        impl Module for $ty {
            const NAME: &'static str = $name;
            const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
            type Output = StubOutput;
            type Settings = ();

            fn init(_: &()) -> Result<Self, ModuleError> {
                Ok($ty)
            }
        }

        impl Lookup for $ty {
            const TCP_PORTS: &'static [u16] = &[];

            async fn analyze(
                &self,
                _: &TaskContext<()>,
            ) -> Result<Outcome<StubOutput>, ModuleError> {
                Ok(Outcome::Skipped("a stub".to_owned()))
            }
        }
    };
}

// Named for ace3's modules, so ace3's modes choose them. This crate can't depend on an ace-mod-*
// crate, not even for its tests (crates/ace-layering).
stub!(CorrelationStub, "rdap_analyzer");
stub!(DispositionedStub, "alert_added_to_event");

/// A list for the tests, as a module declares one (PLAN.md 5.14).
const TEST_LIST: ListSpec = ListSpec {
    name: "test_whitelist",
    description: "a list for the tests",
    typed: false,
};

/// A typed one, whose entries name an observable type.
const TYPED_LIST: ListSpec = ListSpec {
    name: "test_typed_list",
    description: "a typed list for the tests",
    typed: true,
};

/// The list 7.6's `observable_detection` module reads, which the `detection` service keeps.
const DETECTION_SPEC: ListSpec = ListSpec {
    name: ace_service::DETECTION_LIST,
    description: "the observables ACE detects",
    typed: true,
};

/// A module that reads the lists. No mode names it, so it never runs.
struct ListReader;

impl Module for ListReader {
    const NAME: &'static str = "test_list_reader";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const LISTS: &'static [ListSpec] = &[TEST_LIST, TYPED_LIST, DETECTION_SPEC];
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

fn orchestrator() -> Orchestrator {
    let catalog = Catalog::new(vec![
        Manifest::lookup::<CorrelationStub>(),
        Manifest::lookup::<DispositionedStub>(),
        Manifest::lookup::<ListReader>(),
    ]);
    Orchestrator::new(catalog, Modes::ace3())
}

fn service(db: &Db) -> Service {
    Service::new(db.clone(), orchestrator()).with_actions(test_actions())
}

/// A file collector that collects nothing, for the file collections' tests (PLAN.md 7.9).
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

/// The stack's bucket, with a node cache of the test's own, which goes when the directory does.
fn bucket(db: &Db) -> (Bucket, tempfile::TempDir) {
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    );
    (
        Bucket::new(db.clone(), store, BucketSettings::default()),
        cache,
    )
}

/// A submission in correlation mode with one fqdn, and one file spooled for it.
async fn submission(bucket: &Bucket, bytes: &[u8]) -> (Submission, Vec<SubmittedFile>) {
    let submission = serde_json::from_value(json!({
        "description": "a submission",
        "analysis_mode": "correlation",
        "observables": [{"type": "fqdn", "value": "evil.example.com"}],
    }))
    .expect("a submission");
    let file = SubmittedFile {
        path: AlertPath::new("mail/a.txt".to_owned()).expect("a path"),
        spooled: bucket.store().spool_bytes(bytes).await.expect("spools"),
    };
    (submission, vec![file])
}

/// A submitted alert with a file: the root and the file's observable.
async fn file_alert(db: &Db, bucket: &Bucket) -> (Uuid, i64) {
    file_alert_with(db, bucket, b"some file").await
}

/// `file_alert` with these bytes, for a test that collects them, since other tests share the bucket.
async fn file_alert_with(db: &Db, bucket: &Bucket, bytes: &[u8]) -> (Uuid, i64) {
    let (submission, files) = submission(bucket, bytes).await;
    let root = service(db)
        .submit(&admin(db).await, bucket, &submission, &files)
        .await
        .expect("submits")
        .uuid;
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    let observable = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'file'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the file");
    (root, observable)
}

async fn root_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM analysis.roots")
        .fetch_one(db.pool())
        .await
        .expect("counts")
}

async fn src_ip_of_last(db: &Db) -> Option<String> {
    sqlx::query_scalar("SELECT host(src_ip) FROM service.audit ORDER BY id DESC LIMIT 1")
        .fetch_one(db.pool())
        .await
        .expect("reads")
}

/// An alert with one observable and its first task queued.
async fn alert(db: &Db) -> Uuid {
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tree::upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::Fqdn, "evil.example.com"),
    )
    .await
    .expect("adds");
    orchestrator()
        .start(&mut tx, root.id)
        .await
        .expect("starts");
    tx.commit().await.expect("commits");
    root.id
}

/// What a disposition left on the root's row.
#[derive(Debug, PartialEq)]
struct Row {
    mode: String,
    disposition: Option<String>,
    dispositioned_at_set: bool,
    by: Option<Value>,
}

async fn row(db: &Db, root: Uuid) -> Row {
    let (mode, disposition, dispositioned_at_set, by): (
        String,
        Option<String>,
        bool,
        Option<Value>,
    ) = sqlx::query_as(
        "SELECT analysis_mode, disposition, dispositioned_at IS NOT NULL,
                dispositioned_by::jsonb
         FROM analysis.roots WHERE id = $1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    Row {
        mode,
        disposition,
        dispositioned_at_set,
        by,
    }
}

/// Each task as (module, state), in module order.
async fn tasks(db: &Db, root: Uuid) -> Vec<(String, String)> {
    sqlx::query_as("SELECT module, state::text FROM queue.tasks WHERE root_id = $1 ORDER BY module")
        .bind(root)
        .fetch_all(db.pool())
        .await
        .expect("reads")
}

fn user(id: UserId) -> Actor {
    Actor::User {
        id,
        name: "alice".to_owned(),
    }
}

fn component(name: &str) -> Actor {
    Actor::Internal {
        id: Component::new(name).expect("a valid name"),
    }
}

fn key(id: ApiKeyId, owner: Option<UserId>) -> Actor {
    Actor::ApiKey {
        id,
        name: "triage".to_owned(),
        owner,
    }
}

fn pattern(major: &str, minor: &str) -> PermissionPattern {
    PermissionPattern::new(major, minor).expect("a valid pattern")
}

fn name(major: &str, minor: &str) -> PermissionName {
    PermissionName::new(major, minor).expect("a valid name")
}

/// Gives a holder a row to stand on, since 5.4 gave a grant a foreign key on its holder. These can't
/// log in: nothing hashes to this password.
async fn exists(db: &Db, holder: &Holder) {
    match holder {
        Holder::User(id) => {
            sqlx::query(
                "INSERT INTO service.users (id, username, password_hash, created_by)
                 VALUES ($1, $2, '$argon2id$none', '{\"kind\": \"internal\", \"id\": \"test\"}')
                 ON CONFLICT DO NOTHING",
            )
            .bind(id.0)
            .bind(format!("u{}", id.0.simple()))
            .execute(db.pool())
            .await
            .expect("seeds a user");
        }
        Holder::ApiKey(id) => {
            sqlx::query(
                "INSERT INTO service.api_keys (id, name, secret_hash, created_by)
                 VALUES ($1, 'triage', decode(repeat('00', 32), 'hex'),
                         '{\"kind\": \"internal\", \"id\": \"test\"}')
                 ON CONFLICT DO NOTHING",
            )
            .bind(id.0)
            .execute(db.pool())
            .await
            .expect("seeds a key");
        }
        Holder::Group(_) | Holder::Component(_) => {}
    }
}

/// An admin, as 5.4's first admin is: `*:*`, on a row the service didn't write here, since nothing
/// can grant until someone holds `user:write`.
async fn admin(db: &Db) -> Actor {
    let id = UserId(Uuid::from_u128(0xAD));
    exists(db, &Holder::User(id)).await;
    sqlx::query(
        "INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
         VALUES ($1, '*', '*', 'allow', '{\"kind\": \"internal\", \"id\": \"test\"}')
         ON CONFLICT ON CONSTRAINT permissions_are_unique DO NOTHING",
    )
    .bind(id.0)
    .execute(db.pool())
    .await
    .expect("seeds");
    user(id)
}

/// Grants through the service, as an admin.
async fn grant(db: &Db, holder: &Holder, major: &str, minor: &str, effect: Effect) {
    exists(db, holder).await;
    service(db)
        .grant(&admin(db).await, holder, &pattern(major, minor), effect)
        .await
        .expect("grants");
}

/// Everything each actor's disposition needs.
async fn may_disposition(db: &Db, holders: &[Holder]) {
    for holder in holders {
        grant(db, holder, "alert", "write", Effect::Allow).await;
    }
}

async fn group_of(db: &Db, id: Uuid, member: UserId) -> Holder {
    sqlx::query("INSERT INTO service.groups (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(id.to_string())
        .execute(db.pool())
        .await
        .expect("adds a group");
    exists(db, &Holder::User(member)).await;
    sqlx::query("INSERT INTO service.group_members (group_id, user_id) VALUES ($1, $2)")
        .bind(id)
        .bind(member.0)
        .execute(db.pool())
        .await
        .expect("adds a member");
    Holder::Group(GroupId(id))
}

#[tokio::test]
async fn every_kind_of_actor_writes_through_the_same_function() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = UserId(Uuid::from_u128(1));
    let key = ApiKeyId(Uuid::from_u128(2));
    let alice_id = "00000000-0000-0000-0000-000000000001";
    let key_id = "00000000-0000-0000-0000-000000000002";

    let cases = [
        (
            user(alice),
            json!({"kind": "user", "id": alice_id, "name": "alice"}),
            format!("user:{alice_id}"),
        ),
        (
            Actor::ApiKey {
                id: key,
                name: "triage".to_owned(),
                owner: Some(alice),
            },
            json!({"kind": "api_key", "id": key_id, "name": "triage", "owner": alice_id}),
            format!("api_key:{key_id}"),
        ),
        (
            Actor::ApiKey {
                id: key,
                name: "triage".to_owned(),
                owner: None,
            },
            json!({"kind": "api_key", "id": key_id, "name": "triage", "owner": null}),
            format!("api_key:{key_id}"),
        ),
        (
            component("svs:maintenance"),
            json!({"kind": "internal", "id": "svs:maintenance"}),
            "internal:svs:maintenance".to_owned(),
        ),
    ];

    may_disposition(
        db,
        &[
            Holder::User(alice),
            Holder::ApiKey(key),
            Holder::Component(Component::new("svs:maintenance").expect("valid")),
        ],
    )
    .await;

    for (actor, recorded, identity) in cases {
        let root = alert(db).await;
        assert_eq!(row(db, root).await.by, None);

        let dispositioned = service
            .disposition(&actor, root, "FALSE_POSITIVE")
            .await
            .expect("dispositions");

        // what differs: who is recorded
        assert_eq!(actor.to_string(), identity);
        assert_eq!(
            row(db, root).await,
            Row {
                mode: "dispositioned".to_owned(),
                disposition: Some("FALSE_POSITIVE".to_owned()),
                dispositioned_at_set: true,
                by: Some(recorded),
            },
            "{actor}"
        );
        // what doesn't: what it does to the analysis
        assert_eq!(dispositioned.cancelled.cancelled.len(), 1, "{actor}");
        assert_eq!(dispositioned.queued.len(), 1, "{actor}");
        assert_eq!(
            tasks(db, root).await,
            [
                ("alert_added_to_event".to_owned(), "queued".to_owned()),
                ("rdap_analyzer".to_owned(), "cancelled".to_owned()),
            ],
            "{actor}"
        );
    }
}

#[tokio::test]
async fn a_later_disposition_replaces_the_earlier_one_and_its_actor() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let root = alert(db).await;
    may_disposition(
        db,
        &[
            Holder::Component(Component::new("svs:maintenance").expect("valid")),
            Holder::User(UserId(Uuid::from_u128(1))),
        ],
    )
    .await;

    service
        .disposition(&component("svs:maintenance"), root, "IGNORE")
        .await
        .expect("dispositions");
    let alice = user(UserId(Uuid::from_u128(1)));
    service
        .disposition(&alice, root, "FALSE_POSITIVE")
        .await
        .expect("dispositions again");

    let stored = row(db, root).await;
    assert_eq!(stored.disposition.as_deref(), Some("FALSE_POSITIVE"));
    assert_eq!(stored.by.expect("an actor")["kind"], "user");
}

#[test]
fn a_rename_changes_a_name_and_not_an_identity() {
    let alice = UserId(Uuid::from_u128(1));
    let renamed = Actor::User {
        id: alice,
        name: "alice.smith".to_owned(),
    };
    assert_eq!(renamed.to_string(), user(alice).to_string());
}

#[tokio::test]
async fn an_actor_that_can_t_be_stored_leaves_the_alert_as_it_was() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let root = alert(db).await;
    let before = row(db, root).await;
    let before_tasks = tasks(db, root).await;
    may_disposition(db, &[Holder::User(UserId(Uuid::from_u128(1)))]).await;

    // jsonb can't hold a NUL, so the write fails after the analysis was stopped in its transaction
    let actor = Actor::User {
        id: UserId(Uuid::from_u128(1)),
        name: "al\0ice".to_owned(),
    };
    service
        .disposition(&actor, root, "FALSE_POSITIVE")
        .await
        .expect_err("refused");

    assert_eq!(row(db, root).await, before);
    assert_eq!(tasks(db, root).await, before_tasks);
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [],
        "nothing ended the pass"
    );
}

#[tokio::test]
async fn a_missing_root_is_an_error() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let missing = Uuid::from_u128(9);
    may_disposition(
        db,
        &[Holder::Component(
            Component::new("scheduler").expect("valid"),
        )],
    )
    .await;
    let error = service(db)
        .disposition(&component("scheduler"), missing, "IGNORE")
        .await
        .expect_err("refused");
    assert!(
        matches!(
            error,
            ServiceError::Orchestrator(OrchestratorError::NoRoot(root)) if root == missing
        ),
        "{error}"
    );
}

/// A write that goes around the service layer's function can't leave a disposition with no actor,
/// or an actor that has no identity.
#[tokio::test]
async fn the_database_refuses_a_disposition_without_a_whole_actor() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let root = alert(db).await;

    let without = sqlx::query("UPDATE analysis.roots SET disposition = 'IGNORE' WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect_err("refused");
    assert!(
        without
            .to_string()
            .contains("roots_disposition_has_an_actor"),
        "{without}"
    );

    for malformed in [
        json!({}),
        json!({"kind": "user"}),
        json!({"id": "x"}),
        json!({"kind": "user", "id": ""}),
        json!({"kind": "root", "id": "x"}),
    ] {
        let refused = sqlx::query(
            "UPDATE analysis.roots SET disposition = 'IGNORE', dispositioned_by = $2::jsonb
             WHERE id = $1",
        )
        .bind(root)
        .bind(&malformed)
        .execute(db.pool())
        .await
        .expect_err("refused");
        assert!(
            refused.to_string().contains("actor"),
            "{malformed}: {refused}"
        );
    }
}

#[test]
fn a_component_name_is_checked() {
    for name in ["scheduler", "collector:journal", "pool:parsers", "a-b_c.d1"] {
        assert_eq!(Component::new(name).expect("valid").as_str(), name);
    }
    for name in ["", "Scheduler", "two words", "user\n"] {
        assert!(Component::new(name).is_err(), "{name:?}");
    }
}

/// Each kind of actor and the rows that make up what it holds. A key with an owner needs a row on
/// both, and a user can hold through a group, so each row goes to all of `holders`.
struct Who {
    actor: Actor,
    holders: Vec<Holder>,
}

/// One of each kind of actor, new each call, so rows from another case don't reach it.
async fn everyone(db: &Db, serial: &mut u128) -> Vec<Who> {
    let mut next = || {
        *serial += 1;
        Uuid::from_u128(*serial)
    };
    let direct = UserId(next());
    let member = UserId(next());
    let group = group_of(db, next(), member).await;
    let owner = UserId(next());
    let owned = ApiKeyId(next());
    let unowned = ApiKeyId(next());
    let internal = format!("component-{}", next().as_u128());
    vec![
        Who {
            actor: user(direct),
            holders: vec![Holder::User(direct)],
        },
        Who {
            actor: user(member),
            holders: vec![group],
        },
        Who {
            actor: key(owned, Some(owner)),
            holders: vec![Holder::ApiKey(owned), Holder::User(owner)],
        },
        Who {
            actor: key(unowned, None),
            holders: vec![Holder::ApiKey(unowned)],
        },
        Who {
            actor: component(&internal),
            holders: vec![Holder::Component(Component::new(&internal).expect("valid"))],
        },
    ]
}

fn lower(text: &str) -> String {
    text.to_lowercase()
}

fn upper(text: &str) -> String {
    text.to_uppercase()
}

/// `aLeRt`
fn mixed(text: &str) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

/// The Done check of PLAN.md 5.2: what a row does doesn't depend on the case it was stored in or the
/// case it's checked in. Every row of this table runs for each kind of actor, in each pair of cases.
#[tokio::test]
async fn a_permission_behaves_the_same_in_any_case_for_every_actor() {
    use Effect::{Allow, Deny};

    type Row = (&'static str, &'static str, Effect);
    type Checked = (&'static str, &'static str);
    #[rustfmt::skip]
    let table: &[(&str, &[Row], Checked, bool)] = &[
        // no grants fails closed, even for a name that looks like everything
        ("no rows",            &[],                                       ("alert", "write"), false),
        ("allow",              &[("alert", "write", Allow)],              ("alert", "write"), true),
        ("another minor",      &[("alert", "write", Allow)],              ("alert", "read"),  false),
        ("another major",      &[("alert", "write", Allow)],              ("event", "write"), false),
        ("deny",               &[("alert", "write", Deny)],               ("alert", "write"), false),
        ("deny beats allow",   &[("alert", "write", Allow), ("alert", "write", Deny)], ("alert", "write"), false),
        ("all",                &[("*", "*", Allow)],                      ("alert", "write"), true),
        ("any minor",          &[("alert", "*", Allow)],                  ("alert", "write"), true),
        ("any minor, not major", &[("alert", "*", Allow)],                ("event", "write"), false),
        ("any major",          &[("*", "write", Allow)],                  ("alert", "write"), true),
        ("any major, not minor", &[("*", "write", Allow)],                ("alert", "read"),  false),
        ("partial wildcards",  &[("al*", "w?ite", Allow)],                ("alert", "write"), true),
        ("a class",            &[("[a-c]lert", "write", Allow)],          ("alert", "write"), true),
        ("a negated class",    &[("[!a-c]lert", "write", Allow)],         ("alert", "write"), false),
        ("deny beats all",     &[("*", "*", Allow), ("alert", "write", Deny)], ("alert", "write"), false),
        ("a deny stays narrow", &[("*", "*", Allow), ("alert", "write", Deny)], ("alert", "read"), true),
        ("a wide deny",        &[("alert", "write", Allow), ("alert", "*", Deny)], ("alert", "write"), false),
    ];
    type Case = fn(&str) -> String;
    let cases: [(&str, Case); 3] = [("lower", lower), ("upper", upper), ("mixed", mixed)];

    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let admin = admin(db).await;
    let mut serial = 0x1000;

    for (label, rows, checked, expected) in table {
        for (stored_case, store) in cases {
            for (checked_case, check) in cases {
                for who in everyone(db, &mut serial).await {
                    for holder in &who.holders {
                        exists(db, holder).await;
                        for (major, minor, effect) in *rows {
                            service
                                .grant(
                                    &admin,
                                    holder,
                                    &pattern(&store(major), &store(minor)),
                                    *effect,
                                )
                                .await
                                .expect("grants");
                        }
                    }
                    let name = name(&check(checked.0), &check(checked.1));
                    assert_eq!(
                        service.allowed(&who.actor, &name).await.expect("checks"),
                        *expected,
                        "{label}: stored {stored_case}, checked {checked_case}, as {:?}",
                        who.actor,
                    );
                }
            }
        }
    }
}

/// What ace3's `check_permission` does for a key: its scope and its owner's permissions both have to
/// allow, and a deny on either refuses. A key with an allow on `*:*` is ace3's `inherit_user_scope`.
#[tokio::test]
async fn a_key_with_an_owner_holds_what_it_and_its_owner_both_allow() {
    use Effect::{Allow, Deny};

    type Row = (&'static str, &'static str, Effect);
    #[rustfmt::skip]
    let table: &[(&str, &[Row], &[Row], bool)] = &[
        ("neither",          &[],                          &[],                          false),
        ("only its scope",   &[("alert", "write", Allow)], &[],                          false),
        ("only its owner",   &[],                          &[("alert", "write", Allow)], false),
        ("both",             &[("alert", "write", Allow)], &[("alert", "write", Allow)], true),
        ("inherits",         &[("*", "*", Allow)],         &[("alert", "write", Allow)], true),
        ("a wider owner",    &[("alert", "read", Allow)],  &[("*", "*", Allow)],         false),
        ("its owner denied", &[("*", "*", Allow)],         &[("*", "*", Allow), ("alert", "write", Deny)], false),
        ("its own deny",     &[("*", "*", Allow), ("alert", "write", Deny)], &[("*", "*", Allow)], false),
    ];

    let test_db = TestDb::new().await;
    let db = test_db.db();
    for (i, (label, scope, owners, expected)) in table.iter().enumerate() {
        let key_id = ApiKeyId(Uuid::from_u128(0x100 + i as u128));
        let owner = UserId(Uuid::from_u128(0x200 + i as u128));
        for (major, minor, effect) in *scope {
            grant(db, &Holder::ApiKey(key_id), major, minor, *effect).await;
        }
        for (major, minor, effect) in *owners {
            grant(db, &Holder::User(owner), major, minor, *effect).await;
        }
        assert_eq!(
            service(db)
                .allowed(&key(key_id, Some(owner)), &ALERT_WRITE)
                .await
                .expect("checks"),
            *expected,
            "{label}"
        );
    }

    // the owner's group counts as the owner
    let key_id = ApiKeyId(Uuid::from_u128(0x300));
    let owner = UserId(Uuid::from_u128(0x301));
    let group = group_of(db, Uuid::from_u128(0x302), owner).await;
    grant(db, &Holder::ApiKey(key_id), "*", "*", Allow).await;
    grant(db, &group, "alert", "write", Allow).await;
    let actor = key(key_id, Some(owner));
    assert!(
        service(db)
            .allowed(&actor, &ALERT_WRITE)
            .await
            .expect("checks")
    );
    grant(db, &group, "alert", "write", Deny).await;
    assert!(
        !service(db)
            .allowed(&actor, &ALERT_WRITE)
            .await
            .expect("checks")
    );
}

#[tokio::test]
async fn a_row_reaches_only_its_holder() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let check = async |actor: &Actor| service.allowed(actor, &ALERT_WRITE).await.expect("checks");

    // a key's row isn't its owner's
    let alice = UserId(Uuid::from_u128(1));
    let key_id = ApiKeyId(Uuid::from_u128(2));
    grant(db, &Holder::ApiKey(key_id), "alert", "write", Effect::Allow).await;
    assert!(!check(&user(alice)).await);
    assert!(check(&key(key_id, None)).await);

    // nor is a user's the same id as a key's
    assert!(!check(&key(ApiKeyId(Uuid::from_u128(1)), None)).await);
    grant(db, &Holder::User(alice), "alert", "write", Effect::Allow).await;
    assert!(!check(&key(ApiKeyId(alice.0), None)).await);

    // a user's row isn't another user's, nor a key's without that owner
    let bob = UserId(Uuid::from_u128(3));
    assert!(!check(&user(bob)).await);
    assert!(check(&key(key_id, Some(alice))).await);
    assert!(!check(&key(key_id, Some(bob))).await);

    // a group's row is its members'
    let carol = UserId(Uuid::from_u128(4));
    let group = group_of(db, Uuid::from_u128(5), carol).await;
    grant(db, &group, "alert", "write", Effect::Allow).await;
    assert!(check(&user(carol)).await);
    assert!(!check(&user(bob)).await);

    // a component's row is that component's
    let scheduler = Holder::Component(Component::new("scheduler").expect("valid"));
    grant(db, &scheduler, "alert", "write", Effect::Allow).await;
    assert!(check(&component("scheduler")).await);
    assert!(!check(&component("collector:journal")).await);
}

/// ace3's tests for a deny on one side and an allow on the other.
#[tokio::test]
async fn a_deny_wins_between_a_user_and_their_groups() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let check = async |actor: &Actor| {
        service(db)
            .allowed(actor, &ALERT_WRITE)
            .await
            .expect("checks")
    };

    let alice = UserId(Uuid::from_u128(1));
    let group = group_of(db, Uuid::from_u128(2), alice).await;
    grant(db, &Holder::User(alice), "alert", "write", Effect::Allow).await;
    grant(db, &group, "alert", "write", Effect::Deny).await;
    assert!(!check(&user(alice)).await);

    let bob = UserId(Uuid::from_u128(3));
    let group = group_of(db, Uuid::from_u128(4), bob).await;
    grant(db, &group, "alert", "write", Effect::Allow).await;
    grant(db, &Holder::User(bob), "alert", "write", Effect::Deny).await;
    assert!(!check(&user(bob)).await);
}

#[tokio::test]
async fn only_a_user_can_hold_user_self() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let alice = UserId(Uuid::from_u128(1));
    let key_id = ApiKeyId(Uuid::from_u128(2));
    let other = ApiKeyId(Uuid::from_u128(3));
    let scheduler = Component::new("scheduler").expect("valid");
    for holder in [
        Holder::User(alice),
        Holder::ApiKey(key_id),
        Holder::ApiKey(other),
        Holder::Component(scheduler.clone()),
    ] {
        grant(db, &holder, "user", "self", Effect::Allow).await;
        grant(db, &holder, "*", "*", Effect::Allow).await;
    }
    let service = service(db);

    for (actor, expected) in [
        (user(alice), true),
        (key(key_id, Some(alice)), false),
        (key(other, None), false),
        (Actor::Internal { id: scheduler }, false),
    ] {
        assert_eq!(
            service.allowed(&actor, &USER_SELF).await.expect("checks"),
            expected,
            "{actor}"
        );
        assert!(
            service.allowed(&actor, &USER_WRITE).await.expect("checks"),
            "{actor} holds the rest of *:*"
        );
    }
}

/// An actor with no grants can't do any write, and the alert stays as it was. A refusal also comes
/// before the write looks, so it says nothing about whether the alert exists.
#[tokio::test]
async fn an_actor_with_no_grants_is_refused_every_write() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let root = alert(db).await;
    let before = row(db, root).await;
    let before_tasks = tasks(db, root).await;
    let alice = UserId(Uuid::from_u128(1));
    let target = Holder::User(UserId(Uuid::from_u128(2)));
    let every = pattern("*", "*");

    for actor in [
        user(alice),
        key(ApiKeyId(Uuid::from_u128(3)), Some(alice)),
        key(ApiKeyId(Uuid::from_u128(4)), None),
        component("scheduler"),
    ] {
        assert!(
            !service.allowed(&actor, &ALERT_WRITE).await.expect("checks"),
            "{actor}"
        );
        for missing_or_not in [root, Uuid::from_u128(9)] {
            let error = service
                .disposition(&actor, missing_or_not, "IGNORE")
                .await
                .expect_err("refused");
            assert!(
                matches!(
                    &error,
                    ServiceError::PermissionDenied { actor: who, permission }
                        if *who == actor.to_string() && *permission == ALERT_WRITE
                ),
                "{error}"
            );
        }
        for error in [
            service
                .grant(&actor, &target, &every, Effect::Allow)
                .await
                .expect_err("refused"),
            service
                .revoke(&actor, &target, &every, Effect::Allow)
                .await
                .expect_err("refused"),
        ] {
            assert!(
                matches!(
                    &error,
                    ServiceError::PermissionDenied { permission, .. } if *permission == USER_WRITE
                ),
                "{error}"
            );
        }
    }

    assert_eq!(row(db, root).await, before);
    assert_eq!(tasks(db, root).await, before_tasks);
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM service.permissions
         WHERE component IS NULL
            OR (component NOT IN ('bootstrap', 'hunter', 'alert_routing')
                AND component NOT LIKE 'scheduler:%')",
    )
    .fetch_one(db.pool())
    .await
    .expect("counts");
    // the migrations' grants are the bootstrap's, the hunter's, the scheduler's tasks' and alert
    // routing's (0022, 0034, 0036, 0050)
    assert_eq!(rows, 0, "nothing was granted, and no admin was seeded");
}

#[tokio::test]
async fn a_disposition_follows_its_actor_s_grants() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = UserId(Uuid::from_u128(1));
    let actor = user(alice);
    let root = alert(db).await;

    // a permission for something else doesn't do
    grant(db, &Holder::User(alice), "alert", "read", Effect::Allow).await;
    service
        .disposition(&actor, root, "IGNORE")
        .await
        .expect_err("refused");

    // a mixed-case wildcard does
    grant(db, &Holder::User(alice), "ALERT", "*", Effect::Allow).await;
    service
        .disposition(&actor, root, "IGNORE")
        .await
        .expect("dispositions");
    assert_eq!(row(db, root).await.disposition.as_deref(), Some("IGNORE"));

    // and a deny takes it back at the next write
    grant(db, &Holder::User(alice), "Alert", "Write", Effect::Deny).await;
    let error = service
        .disposition(&actor, root, "FALSE_POSITIVE")
        .await
        .expect_err("refused");
    assert!(
        matches!(error, ServiceError::PermissionDenied { .. }),
        "{error}"
    );
    assert_eq!(row(db, root).await.disposition.as_deref(), Some("IGNORE"));
}

/// ace3's #831: two case variants of a grant failed on the unique index, with a 500.
#[tokio::test]
async fn case_variants_of_a_grant_are_one_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let admin = admin(db).await;
    let alice = Holder::User(UserId(Uuid::from_u128(1)));
    exists(db, &alice).await;
    let actor = user(UserId(Uuid::from_u128(1)));
    let added = async |major: &str, minor: &str, effect: Effect| {
        service
            .grant(&admin, &alice, &pattern(major, minor), effect)
            .await
            .expect("grants")
    };
    let rows = async || -> Vec<(String, String, String, Value)> {
        sqlx::query_as(
            "SELECT major::text, minor::text, effect::text, created_by::jsonb
             FROM service.permissions WHERE user_id = $1 ORDER BY id",
        )
        .bind(Uuid::from_u128(1))
        .fetch_all(db.pool())
        .await
        .expect("reads")
    };

    assert!(added("SIGNATURE", "Read", Effect::Allow).await);
    assert!(!added("signature", "read", Effect::Allow).await);
    assert!(!added("Signature", "READ", Effect::Allow).await);
    assert_eq!(
        rows().await,
        [(
            "signature".to_owned(),
            "read".to_owned(),
            "allow".to_owned(),
            json!({"kind": "user", "id": "00000000-0000-0000-0000-0000000000ad", "name": "alice"}),
        )],
        "stored once, lowercase, with who granted it"
    );

    // as in ace3, an allow and a deny of one pattern are two rows
    assert!(added("signature", "READ", Effect::Deny).await);
    assert_eq!(rows().await.len(), 2);
    assert!(
        !service
            .allowed(&actor, &name("signature", "read"))
            .await
            .expect("checks")
    );

    // revoking goes by pattern and effect, in any case
    let revoke = async |major: &str, minor: &str, effect: Effect| {
        service
            .revoke(&admin, &alice, &pattern(major, minor), effect)
            .await
            .expect("revokes")
    };
    assert!(revoke("SIGNATURE", "read", Effect::Deny).await);
    assert!(
        !revoke("signature", "READ", Effect::Deny).await,
        "already gone"
    );
    assert!(
        service
            .allowed(&actor, &name("SIGNATURE", "READ"))
            .await
            .expect("checks")
    );
    assert!(revoke("Signature", "Read", Effect::Allow).await);
    assert_eq!(rows().await, []);
    assert!(
        !service
            .allowed(&actor, &name("signature", "read"))
            .await
            .expect("checks")
    );
}

#[tokio::test]
async fn a_grant_to_a_group_that_doesn_t_exist_is_an_error() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let error = service(db)
        .grant(
            &admin(db).await,
            &Holder::Group(GroupId(Uuid::from_u128(1))),
            &pattern("*", "*"),
            Effect::Allow,
        )
        .await
        .expect_err("refused");
    let missing = "00000000-0000-0000-0000-000000000001";
    assert!(
        matches!(error, ServiceError::NotFound(ref what) if *what == format!("no group:{missing}")),
        "{error}"
    );
    // the same for the holders 5.4 gave a foreign key
    for (holder, kind) in [
        (Holder::User(UserId(Uuid::from_u128(1))), "user"),
        (Holder::ApiKey(ApiKeyId(Uuid::from_u128(1))), "api_key"),
    ] {
        let error = service(db)
            .grant(&admin(db).await, &holder, &pattern("*", "*"), Effect::Allow)
            .await
            .expect_err("refused");
        assert_eq!(error.to_string(), format!("no {kind}:{missing}"));
    }
}

/// A row written outside the type can't break the rule. This is the database's half of it.
#[tokio::test]
async fn the_database_refuses_a_row_that_breaks_the_rule() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let by = json!({"kind": "internal", "id": "test"});
    let user_id = Uuid::from_u128(1);
    exists(db, &Holder::User(UserId(user_id))).await;
    let insert = async |major: &str, minor: &str| {
        sqlx::query(
            "INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
             VALUES ($1, $2, $3, 'allow', $4)",
        )
        .bind(user_id)
        .bind(major)
        .bind(minor)
        .bind(&by)
        .execute(db.pool())
        .await
    };

    let long = "a".repeat(513);
    for (major, minor) in [
        ("Alert", "write"),
        ("alert", "WRITE"),
        ("", "write"),
        ("alert", ""),
        (" alert", "write"),
        ("alert\n", "write"),
        ("alert:x", "write"),
        ("\u{212A}ey", "write"),
        (long.as_str(), "write"),
    ] {
        let refused = insert(major, minor).await.expect_err("refused");
        assert!(
            refused.to_string().contains("permission_part"),
            "{major:?}:{minor:?}: {refused}"
        );
    }

    // what the type makes is what the database takes
    for (major, minor) in [
        ("alert", "write"),
        ("*", "*"),
        ("[!a-c]?", "x_y.z-1"),
        ("[]]", "["),
    ] {
        insert(major, minor).await.expect("stored");
    }
    let longest = "a".repeat(512);
    insert(&longest, "write").await.expect("stored");

    // one holder, always
    for sql in [
        "INSERT INTO service.permissions (major, minor, effect, created_by)
         VALUES ('alert', 'write', 'allow', $1)",
        "INSERT INTO service.permissions (user_id, api_key_id, major, minor, effect, created_by)
         VALUES ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002',
                 'alert', 'write', 'allow', $1)",
    ] {
        let refused = sqlx::query(sql)
            .bind(&by)
            .execute(db.pool())
            .await
            .expect_err("refused");
        assert!(
            refused.to_string().contains("permissions_have_one_holder"),
            "{refused}"
        );
    }

    // a component's name has a case rule too, or its rows would never reach it
    let refused = sqlx::query(
        "INSERT INTO service.permissions (component, major, minor, effect, created_by)
         VALUES ('Scheduler', 'alert', 'write', 'allow', $1)",
    )
    .bind(&by)
    .execute(db.pool())
    .await
    .expect_err("refused");
    assert!(refused.to_string().contains("check"), "{refused}");

    // and a row says who made it
    let refused = sqlx::query(
        "INSERT INTO service.permissions (user_id, major, minor, effect)
         VALUES ($1, 'alert', 'write', 'allow')",
    )
    .bind(user_id)
    .execute(db.pool())
    .await
    .expect_err("refused");
    assert!(refused.to_string().contains("created_by"), "{refused}");
}

/// A row that gets past the database anyway is an error, not a row to skip: it could be a deny.
#[tokio::test]
async fn a_row_the_type_can_t_read_fails_the_check() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let alice = UserId(Uuid::from_u128(1));
    grant(db, &Holder::User(alice), "*", "*", Effect::Allow).await;

    sqlx::raw_sql(
        "ALTER TABLE service.permissions ALTER COLUMN major TYPE text;
         INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
         VALUES ('00000000-0000-0000-0000-000000000001', 'a b', '*', 'deny',
                 '{\"kind\": \"internal\", \"id\": \"test\"}')",
    )
    .execute(db.pool())
    .await
    .expect("breaks the rule");

    let error = service(db)
        .disposition(&user(alice), alert(db).await, "IGNORE")
        .await
        .expect_err("refused");
    assert!(
        matches!(error, ServiceError::InvalidPermission(_)),
        "{error}"
    );
}

#[test]
fn a_name_is_one_value_in_any_case() {
    for (major, minor) in [("alert", "write"), ("ALERT", "WRITE"), ("Alert", "wRiTe")] {
        let parsed = name(major, minor);
        assert_eq!(parsed, ALERT_WRITE);
        assert_eq!(parsed.major(), "alert");
        assert_eq!(parsed.minor(), "write");
        assert_eq!(parsed.to_string(), "alert:write");

        let stored = pattern(major, minor);
        assert_eq!(stored, pattern("alert", "write"));
        assert_eq!(stored.major(), "alert");
        assert_eq!(stored.minor(), "write");
        assert_eq!(stored.to_string(), "alert:write");
        assert!(stored.matches(&parsed));
    }
    assert_eq!(pattern("[A-Z]*", "*"), pattern("[a-z]*", "*"));
}

#[test]
fn a_part_that_isn_t_ascii_or_is_badly_formed_is_refused() {
    let long = "a".repeat(513);
    for part in [
        "",
        " alert",
        "alert ",
        "al ert",
        "alert\n",
        "a:b",
        // U+212A lowercases to k in Unicode, and U+0130 to i with a mark
        "\u{212A}ey",
        "\u{0130}d",
        "é",
        long.as_str(),
    ] {
        assert!(PermissionName::new(part, "x").is_err(), "{part:?}");
        assert!(PermissionName::new("x", part).is_err(), "{part:?}");
        assert!(PermissionPattern::new(part, "x").is_err(), "{part:?}");
        assert!(PermissionPattern::new("x", part).is_err(), "{part:?}");
    }
    // a name is what code asks for, so it can't hold a wildcard
    for part in ["*", "a?", "[a]", "!a"] {
        assert!(PermissionName::new(part, "x").is_err(), "{part:?}");
        assert!(PermissionPattern::new(part, "x").is_ok(), "{part:?}");
    }
    assert!(PermissionName::new(&"a".repeat(512), "x").is_ok());
}

/// What Python 3.14's `fnmatch.fnmatchcase` says for each, run in ace3's dev container. ace3 matches
/// with it. Those whose value can't be a name, such as `[`, aren't here.
#[test]
fn a_pattern_matches_as_ace3_s_fnmatch_does() {
    #[rustfmt::skip]
    let table = [
        ("*", "alert", true), ("alert", "alert", true), ("alert", "alerts", false),
        ("a*", "alert", true), ("*t", "alert", true), ("a*t", "alert", true),
        ("a*x", "alert", false), ("**", "alert", true), ("a**t", "alert", true),
        ("?", "a", true), ("?", "ab", false), ("a?ert", "alert", true),
        ("test?", "test1", true), ("test?", "test", false),
        ("[abc]", "a", true), ("[abc]", "d", false), ("[!abc]", "a", false), ("[!abc]", "d", true),
        ("[a-c]lert", "blert", true), ("[a-c]lert", "dlert", false), ("[!a-c]lert", "blert", false),
        ("[c-a]", "b", false), ("[!c-a]", "b", true),
        ("[a", "a", false), ("[]a]", "a", true), ("[!]]", "a", true), ("[!]", "a", false),
        ("[a-]", "-", true), ("[-a]", "-", true), ("[a-]", "a", true), ("[a--]", "a", false),
        ("[--a]", ".", true), ("[a-c-e]", "-", true), ("[a-c-e]", "d", false), ("[a-c-e]", "e", true),
        ("a*b*c", "axxbyyc", true), ("a*b*c", "axxbyy", false),
        ("*a*a*a*", "aaa", true), ("*a*a*a*", "aa", false), ("[ab]*[cd]", "a_d", true),
        ("a.c", "abc", false), ("a.c", "a.c", true),
        ("user_*", "user_read", true), ("*_read", "run_read", true),
        ("?*", "a", true), ("*?", "a", true),
    ];
    for (stored, value, expected) in table {
        assert_eq!(
            pattern(stored, "*").matches(&name(value, "x")),
            expected,
            "{stored} against {value}"
        );
        assert_eq!(
            pattern("*", stored).matches(&name("x", value)),
            expected,
            "{stored} against {value}, as a minor"
        );
    }
}

// PLAN.md 5.3: the audit record.

#[derive(Debug, PartialEq)]
struct AuditRow {
    actor: Value,
    action: String,
    target: (String, String),
    before: Option<Value>,
    after: Option<Value>,
    details: Value,
}

type RawAudit = (
    Value,
    String,
    String,
    String,
    Option<Value>,
    Option<Value>,
    Value,
);

async fn audit_rows(db: &Db) -> Vec<AuditRow> {
    let rows: Vec<RawAudit> = sqlx::query_as(
        "SELECT actor::jsonb, action, target_kind, target_id, before, after, details
         FROM service.audit ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    rows.into_iter()
        .map(
            |(actor, action, kind, id, before, after, details)| AuditRow {
                actor,
                action,
                target: (kind, id),
                before,
                after,
                details,
            },
        )
        .collect()
}

async fn last_audit(db: &Db) -> AuditRow {
    audit_rows(db).await.pop().expect("an audit row")
}

fn alice_json() -> Value {
    json!({"kind": "user", "id": Uuid::from_u128(1), "name": "alice"})
}

/// A row in `service.permissions`, whole.
async fn permission_rows(db: &Db) -> Vec<(i64, Option<Uuid>, String, String, String)> {
    sqlx::query_as(
        "SELECT id, user_id, major::text, minor::text, effect::text
         FROM service.permissions ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// The functions in this crate's source that call `Gate::write` or `Gate::write_own`. Each must call it once, with its
/// own name as the action, so one row's action always names one function. A function that holds the
/// gate under another name isn't seen: this reads text.
fn write_functions() -> BTreeSet<String> {
    fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("reads the source") {
            let path = entry.expect("reads the source").path();
            if path.is_dir() {
                rust_files(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    let pattern =
        regex::Regex::new(r"\bfn\s+(\w+)|\bgate\s*\.\s*write(?:_own)?\s*\(\s*&?\w+\s*,\s*([^,]*),")
            .expect("a valid pattern");
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut functions = BTreeSet::new();
    for file in files {
        let source = std::fs::read_to_string(&file).expect("reads the source");
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut current = String::new();
        for found in pattern.captures_iter(&code) {
            if let Some(name) = found.get(1) {
                current = name.as_str().to_owned();
            } else {
                let action = found[2].trim();
                assert_eq!(
                    action,
                    format!("\"{current}\""),
                    "{}: {current} has to call Gate::write with its own name as the action",
                    file.display()
                );
                assert!(
                    functions.insert(current.clone()),
                    "{current} calls Gate::write twice, or two functions share its name"
                );
            }
        }
    }
    functions
}

const WRITES_NEED_A_TEST: &str = "a service function calls Gate::write without an audit test: add it \
     to every_write_function_has_an_audit_test and every_write_fails_when_its_audit_fails";

/// The Done check. Each function below runs one write and compares its whole row, and what it returns
/// is the action read from that row, so a function counts only when a row with its name was compared.
/// A new function that calls `Gate::write` fails this until it has one, and so does removing a line.
#[tokio::test]
async fn every_write_function_has_an_audit_test() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let covered = BTreeSet::from([
        disposition_records_its_row(db).await,
        grant_records_its_row(db).await,
        revoke_records_its_row(db).await,
        create_first_user_records_its_row().await,
        create_user_records_its_row(db).await,
        set_user_enabled_records_its_row(db).await,
        reset_password_records_its_row(db).await,
        change_own_password_records_its_row(db).await,
        create_api_key_records_its_row(db).await,
        revoke_api_key_records_its_row(db).await,
        login_records_its_row(db).await,
        logout_records_its_row(db).await,
        submit_records_its_row(db).await,
        download_file_records_its_row(db).await,
        download_crash_records_its_row(db).await,
        archived_email_records_its_row(db).await,
        download_qa_match_records_its_row(db).await,
        download_qa_matches_records_its_row(db).await,
        purge_qa_matches_records_its_row(db).await,
        prune_qa_matches_records_its_row(db).await,
        add_observable_comment_records_its_row(db).await,
        edit_observable_comment_records_its_row(db).await,
        delete_observable_comment_records_its_row(db).await,
        update_user_records_its_row(db).await,
        update_own_profile_records_its_row(db).await,
        create_group_records_its_row(db).await,
        delete_group_records_its_row(db).await,
        add_group_member_records_its_row(db).await,
        remove_group_member_records_its_row(db).await,
        set_api_key_scope_records_its_row(db).await,
        create_own_api_key_records_its_row(db).await,
        set_own_api_key_scope_records_its_row(db).await,
        revoke_own_api_key_records_its_row(db).await,
        set_preference_records_its_row(db).await,
        reset_preference_records_its_row(db).await,
        create_saved_filter_records_its_row(db).await,
        update_saved_filter_records_its_row(db).await,
        delete_saved_filter_records_its_row(db).await,
        set_quick_filters_records_its_row(db).await,
        seed_saved_filters_records_its_row(db).await,
        set_event_status_records_its_row(db).await,
        create_threat_type_records_its_row(db).await,
        rename_threat_type_records_its_row(db).await,
        delete_threat_type_records_its_row(db).await,
        add_threat_records_its_row(db).await,
        remove_threat_records_its_row(db).await,
        add_to_event_records_its_row(db).await,
        edit_event_records_its_row(db).await,
        remove_alerts_records_its_row(db).await,
        add_event_tags_records_its_row(db).await,
        start_command_records_its_row(db).await,
        cancel_command_records_its_row(db).await,
        add_list_entry_records_its_row(db).await,
        edit_list_entry_records_its_row(db).await,
        delete_list_entry_records_its_row(db).await,
        create_detection_records_its_row(db).await,
        delete_detection_records_its_row(db).await,
        set_detection_expiration_records_its_row(db).await,
        sync_hunts_records_its_row(db).await,
        record_hunt_run_records_its_row(db).await,
        validate_hunt_records_its_row(db).await,
        queue_remediations_records_its_row(db).await,
        cancel_remediation_records_its_row(db).await,
        retry_remediation_records_its_row(db).await,
        restore_remediation_records_its_row(db).await,
        delete_remediation_records_its_row(db).await,
        request_file_collection_records_its_row(db).await,
        cancel_file_collection_records_its_row(db).await,
        retry_file_collection_records_its_row(db).await,
        delete_file_collection_records_its_row(db).await,
        prune_file_collections_records_its_row(db).await,
        set_detection_verdict_records_its_row(db).await,
        clear_detection_verdict_records_its_row(db).await,
        set_detection_verdicts_records_its_row(db).await,
        confirm_detections_records_its_row(db).await,
        create_test_host_records_its_row(db).await,
        update_test_host_records_its_row(db).await,
        delete_test_host_records_its_row(db).await,
        relabel_svs_sample_records_its_row(db).await,
        reset_svs_sample_label_records_its_row(db).await,
        confirm_svs_sample_records_its_row(db).await,
        retire_svs_sample_records_its_row(db).await,
        unretire_svs_sample_records_its_row(db).await,
        delete_svs_sample_records_its_row(db).await,
        download_svs_sample_records_its_row(db).await,
        download_svs_samples_records_its_row(db).await,
        request_svs_validation_records_its_row(db).await,
        download_svs_validation_records_its_row(db).await,
        prune_svs_validations_records_its_row(db).await,
        svs_catalog_tests::store_svs_catalog_records_its_row(db).await,
        svs_catalog_tests::record_svs_catalog_error_records_its_row(db).await,
        svs_catalog_tests::retire_svs_catalog_repository_records_its_row(db).await,
        routing_tests::route_due_records_its_row(db).await,
    ]);
    assert_eq!(covered, write_functions(), "{WRITES_NEED_A_TEST}");
}

async fn submit_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let actor = admin(db).await;
    let (submission, files) = submission(&bucket, b"hello").await;
    let source = "192.0.2.7".parse().expect("an address");
    let submitted = with_source_ip(
        Some(source),
        service(db).submit(&actor, &bucket, &submission, &files),
    )
    .await
    .expect("submits");
    let row = last_audit(db).await;
    let after = row.after.clone().expect("an after");
    assert!(after["event_time"].is_string(), "{after}");
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "submit".to_owned(),
            target: ("root".to_owned(), submitted.uuid.to_string()),
            before: None,
            after: Some(json!({
                "analysis_mode": "correlation",
                "event_time": after["event_time"],
                "observables": 1,
                "files": 1,
                "queued": submitted.queued.len(),
            })),
            details: json!({"title": "a submission"}),
        }
    );
    assert_eq!(src_ip_of_last(db).await.as_deref(), Some("192.0.2.7"));
    let by: Value =
        sqlx::query_scalar("SELECT submitted_by::jsonb FROM analysis.roots WHERE id = $1")
            .bind(submitted.uuid)
            .fetch_one(db.pool())
            .await
            .expect("the root");
    assert_eq!(by, boss_json(), "the root records who submitted it");

    // an actor without alert:create submits nothing and learns nothing, not even that a mode is wrong
    let outsider = user(UserId(Uuid::from_u128(0x5B)));
    let unknown: Submission = serde_json::from_value(json!({
        "description": "x",
        "analysis_mode": "no_such_mode",
    }))
    .expect("a submission");
    let roots = root_count(db).await;
    assert!(matches!(
        service(db).submit(&outsider, &bucket, &unknown, &[]).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service(db).submit(&actor, &bucket, &unknown, &[]).await,
        Err(ServiceError::InvalidRequest(why)) if why == "no analysis mode \"no_such_mode\""
    ));
    assert_eq!(root_count(db).await, roots);
    row.action
}

async fn download_file_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let actor = admin(db).await;
    let download = service(db)
        .download_file(&actor, root, observable)
        .await
        .expect("may download");
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    assert_eq!(
        (download.sha256.as_str(), download.path.as_str()),
        (sha256.as_str(), "mail/a.txt")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_file".to_owned(),
            target: ("observable".to_owned(), format!("{root}/{observable}")),
            before: None,
            after: None,
            details: json!({"sha256": sha256, "path": "mail/a.txt"}),
        }
    );
    assert_eq!(
        src_ip_of_last(db).await,
        None,
        "a call outside a request has no address"
    );

    // a read needs alert:read, and a refusal has no row
    let rows = audit_rows(db).await.len();
    let outsider = user(UserId(Uuid::from_u128(0x5C)));
    assert!(matches!(
        service(db).download_file(&outsider, root, observable).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service(db)
            .alerts(&outsider, &ace_service::AlertQuery::default(), None, None)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// A task of `crasher` on the file alert's file that failed with `error`, reading the file and a hash the
/// bucket never had, as the pool's supervisor ends one.
async fn failed_task(db: &Db, root: Uuid, observable: i64, module: &str, error: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO queue.tasks (root_id, observable_id, module, state, attempts, error, input_hashes)
         SELECT o.root_id, o.id, $3, 'failed', 3, $4, ARRAY[o.value, repeat('0', 64)]
         FROM analysis.observables o WHERE o.root_id = $1 AND o.id = $2
         RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(module)
    .bind(error)
    .fetch_one(db.pool())
    .await
    .expect("a failed task")
}

async fn download_crash_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let id = failed_task(db, root, observable, "crasher", "the module panicked: boom").await;
    let actor = admin(db).await;
    let source = "192.0.2.9".parse().expect("an address");
    let detail = with_source_ip(Some(source), service(db).download_crash(&actor, id))
        .await
        .expect("may download");
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    assert_eq!(detail.crash.input_hashes, [sha256.clone(), "0".repeat(64)]);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_crash".to_owned(),
            target: ("task".to_owned(), id.to_string()),
            before: None,
            after: None,
            details: json!({
                "root": root,
                "module": "crasher",
                "inputs": [sha256, "0".repeat(64)],
            }),
        }
    );
    assert_eq!(src_ip_of_last(db).await.as_deref(), Some("192.0.2.9"));

    // it needs crash:read, which alert:read isn't, and a refusal or a missing task has no row
    let reader = UserId(Uuid::from_u128(0x5D));
    grant(db, &Holder::User(reader), "alert", "read", Effect::Allow).await;
    let rows = audit_rows(db).await.len();
    for refused in [
        service(db).download_crash(&user(reader), id).await,
        service(db).crash(&user(reader), id).await,
    ] {
        assert!(
            matches!(refused, Err(ServiceError::PermissionDenied { ref permission, .. })
                if permission.to_string() == "crash:read"),
            "{refused:?}"
        );
    }
    assert!(matches!(
        service(db).download_crash(&actor, id + 1000).await,
        Err(ServiceError::NotFound(why)) if why == format!("no failed task {}", id + 1000)
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// The test-only key the reference dumps' archive was sealed with.
fn archive_key() -> ace_core::email_archive::ArchiveKey {
    ace_core::email_archive::ArchiveKey::new(*b"ace4 test-only email archive key")
}

fn email_archive(bucket: &Bucket, db: &Db) -> ace_core::email_archive::EmailArchive {
    ace_core::email_archive::EmailArchive::new(
        db.clone(),
        bucket.clone(),
        ace_core::email_archive::ArchiveConfig::default().with_key(archive_key()),
    )
}

/// Archives an email with `message_id`, as the archiver would have.
async fn archived(
    archive: &ace_core::email_archive::EmailArchive,
    email: &[u8],
    message_id: &str,
) -> i64 {
    archive
        .seed(&ace_core::email_archive::Seed {
            email,
            message_id,
            recipients: &["bob@example.com"],
            insert_date: chrono::Utc::now().naive_utc(),
            urls: &[],
        })
        .await
        .expect("archives")
        .0
}

async fn archived_email_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let archive = email_archive(&bucket, db);
    let email = b"From: a@example.com\r\nMessage-ID: <archived@example.com>\r\n\r\nhi\r\n";
    let id = archived(&archive, email, "<archived@example.com>").await;
    let actor = admin(db).await;
    let source = "192.0.2.12".parse().expect("an address");
    // the Message-ID is normalized, as ace3's lookup normalizes it
    let read = with_source_ip(
        Some(source),
        service(db).archived_email(&actor, &archive, "archived@example.com"),
    )
    .await
    .expect("may read");
    assert_eq!(read.bytes, email);
    assert_eq!(read.archive_id, id);
    let sha256 = hex::encode(Sha256::digest(email));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "archived_email".to_owned(),
            target: ("archived_email".to_owned(), id.to_string()),
            before: None,
            after: None,
            details: json!({
                "message_id": "archived@example.com",
                "archive_id": id,
                "hash": sha256,
            }),
        }
    );
    assert_eq!(src_ip_of_last(db).await.as_deref(), Some("192.0.2.12"));

    // it needs email:read, which alert:read isn't; a refusal, a Message-ID the archive doesn't have
    // and a node with no key have no row
    let reader = UserId(Uuid::from_u128(0x5E));
    grant(db, &Holder::User(reader), "alert", "read", Effect::Allow).await;
    let rows = audit_rows(db).await.len();
    let refused = service(db)
        .archived_email(&user(reader), &archive, "<archived@example.com>")
        .await;
    assert!(
        matches!(refused, Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "email:read"),
        "{refused:?}"
    );
    assert!(matches!(
        service(db).archived_email(&actor, &archive, "<nothing@example.com>").await,
        Err(ServiceError::NotFound(why)) if why == "no archived email has message id <nothing@example.com>"
    ));
    let keyless = ace_core::email_archive::EmailArchive::new(
        db.clone(),
        bucket.clone(),
        ace_core::email_archive::ArchiveConfig::default(),
    );
    assert!(matches!(
        service(db).archived_email(&actor, &keyless, "<archived@example.com>").await,
        Err(ServiceError::Unconfigured(why)) if why.contains("no encryption key")
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// ace3's crash listing: failed tasks newest first, filtered by root and module, in pages, with one
/// task's inputs as the bucket has them. Tasks in other states aren't crashes.
/// A root with an fqdn, made an alert when `alerted`, and a detection on it as a module's result raises one.
async fn detected(db: &Db, alerted: bool, description: &str) -> (Uuid, i64) {
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let observable = tree::upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::Fqdn, "evil.example.com"),
    )
    .await
    .expect("adds");
    tx.commit().await.expect("commits");
    if alerted {
        sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
            .bind(root.id)
            .execute(db.pool())
            .await
            .expect("makes it an alert");
    }
    let id = detection_on(db, root.id, observable.id.0, description).await;
    (root.id, id)
}

async fn detection_on(db: &Db, root: Uuid, observable: i64, description: &str) -> i64 {
    let result: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details)
         VALUES ($1, $2, 'rdap_analyzer', 'test_stub', 1, '{}')
         ON CONFLICT ON CONSTRAINT results_one_per_module DO UPDATE SET details = excluded.details
         RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .fetch_one(db.pool())
    .await
    .expect("a result");
    sqlx::query_scalar(
        "INSERT INTO analysis.detections (root_id, observable_id, result_id, description, details)
         VALUES ($1, $2, $3, $4, '{\"rule\": \"<b>x</b>\"}') RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(result)
    .bind(description)
    .fetch_one(db.pool())
    .await
    .expect("a detection")
}

#[tokio::test]
async fn detection_points_page_through_every_alert_s_detections_once_while_more_arrive() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (one, first) = detected(db, true, "first").await;
    let (_, hidden) = detected(db, false, "on a root that isn't an alert").await;
    let (two, second) = detected(db, true, "<script>alert(1)</script>").await;
    let observable: i64 =
        sqlx::query_scalar("SELECT id FROM analysis.observables WHERE root_id = $1")
            .bind(one)
            .fetch_one(db.pool())
            .await
            .expect("the fqdn");
    let third = detection_on(db, one, observable, "third").await;

    let all = DetectionPointFilter::default();
    let page = service
        .detection_points(&actor, &all, Some(2), None)
        .await
        .expect("lists");
    let ids = |page: &ace_service::DetectionPointPage| {
        page.detections.iter().map(|d| d.id).collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&page),
        [first, second],
        "oldest first, and only alerts'"
    );
    assert_eq!(page.next, Some(second));
    let listed = &page.detections[1];
    assert_eq!(listed.alert, two);
    assert_eq!(
        listed.description, "<script>alert(1)</script>",
        "data, unchanged"
    );
    assert_eq!(listed.details, Some(json!({"rule": "<b>x</b>"})));
    assert_eq!(listed.module.as_deref(), Some("rdap_analyzer"));
    assert_eq!(
        listed
            .observable
            .as_ref()
            .map(|(_, kind, value)| (kind.as_str(), value.as_str())),
        Some(("fqdn", "evil.example.com"))
    );

    // one that arrives while a puller pages is on a later page, and nothing repeats
    let (_, fourth) = detected(db, true, "arrived while paging").await;
    let rest = service
        .detection_points(&actor, &all, Some(2), page.next)
        .await
        .expect("lists");
    assert_eq!(ids(&rest), [third, fourth]);
    assert_eq!(rest.next, None, "a full last page says it's the last");
    let past = service
        .detection_points(&actor, &all, Some(2), Some(fourth))
        .await
        .expect("lists");
    assert_eq!((ids(&past), past.next), (Vec::new(), None));
    assert!(![&page, &rest].iter().any(|p| ids(p).contains(&hidden)));

    let of_one = DetectionPointFilter {
        alert: Some(one),
        ..DetectionPointFilter::default()
    };
    let page = service
        .detection_points(&actor, &of_one, None, None)
        .await
        .expect("lists");
    assert_eq!(ids(&page), [first, third]);
    assert_eq!(page.next, None);

    for limit in [0, ace_service::MAX_DETECTIONS_PAGE + 1] {
        assert!(matches!(
            service
                .detection_points(&actor, &all, Some(limit), None)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    let missing = DetectionPointFilter {
        alert: Some(Uuid::nil()),
        ..DetectionPointFilter::default()
    };
    assert!(matches!(
        service.detection_points(&actor, &missing, None, None).await,
        Err(ServiceError::NotFound(_))
    ));
    // alert:read is what it needs
    let reader = user(UserId(Uuid::from_u128(0xDE7)));
    exists(db, &Holder::User(UserId(Uuid::from_u128(0xDE7)))).await;
    assert!(matches!(
        service.detection_points(&reader, &all, None, None).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    grant(
        db,
        &Holder::User(UserId(Uuid::from_u128(0xDE7))),
        "alert",
        "read",
        Effect::Allow,
    )
    .await;
    let audit = audit_rows(db).await.len();
    assert_eq!(
        service
            .detection_points(&reader, &all, Some(1), None)
            .await
            .expect("lists")
            .detections[0]
            .id,
        first
    );
    assert_eq!(audit_rows(db).await.len(), audit, "a read writes no row");
}

#[tokio::test]
async fn crashes_are_failed_tasks() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let actor = admin(db).await;
    let (root, file) = file_alert(db, &bucket).await;
    let (other, other_file) = file_alert(db, &bucket).await;
    let hostile = "the module panicked: <script>alert(1)</script> in \"../../etc/passwd\"";
    let first = failed_task(db, root, file, "crasher", hostile).await;
    let second = failed_task(db, other, other_file, "crasher", "killed by SIGKILL").await;
    let third = failed_task(db, root, file, "hanger", "ran past its deadline").await;
    // a task that isn't failed isn't listed
    let done: i64 = sqlx::query_scalar(
        "INSERT INTO queue.tasks (root_id, observable_id, module, state, error)
         VALUES ($1, $2, 'fine', 'done', 'an error a done task kept') RETURNING id",
    )
    .bind(root)
    .bind(file)
    .fetch_one(db.pool())
    .await
    .expect("a done task");
    // the oldest failure first, so the order is by when each failed and not by id
    for (id, ago) in [(second, 3), (first, 2), (third, 1)] {
        sqlx::query(
            "UPDATE queue.tasks SET updated_at = now() - make_interval(mins => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(ago)
        .execute(db.pool())
        .await
        .expect("ages");
    }
    let ids = |page: &ace_service::CrashPage| page.crashes.iter().map(|c| c.id).collect::<Vec<_>>();
    let all = service
        .crashes(&actor, &CrashFilter::default(), None, None)
        .await
        .expect("lists");
    assert_eq!(ids(&all), [third, first, second]);
    assert_eq!(all.next, None);
    let listed = &all.crashes[1];
    assert_eq!(listed.error, hostile, "the error is data, unchanged");
    assert_eq!(
        (
            listed.root,
            listed.module.as_str(),
            listed.observable_type.as_str()
        ),
        (root, "crasher", "file")
    );
    assert!(listed.alerted);
    assert_eq!((listed.attempts, listed.max_attempts), (3, 3));

    let by_root = CrashFilter {
        root: Some(root),
        ..CrashFilter::default()
    };
    let page = service
        .crashes(&actor, &by_root, None, None)
        .await
        .expect("lists");
    assert_eq!(ids(&page), [third, first]);
    let by_module = CrashFilter {
        module: Some("crasher".to_owned()),
        ..CrashFilter::default()
    };
    let page = service
        .crashes(&actor, &by_module, None, None)
        .await
        .expect("lists");
    assert_eq!(ids(&page), [first, second]);
    let both = CrashFilter {
        root: Some(other),
        module: Some("hanger".to_owned()),
    };
    let page = service
        .crashes(&actor, &both, None, None)
        .await
        .expect("lists");
    assert_eq!(ids(&page), Vec::<i64>::new());

    let page = service
        .crashes(&actor, &CrashFilter::default(), Some(2), None)
        .await
        .expect("lists");
    assert_eq!((ids(&page), page.next), (vec![third, first], Some(first)));
    let page = service
        .crashes(&actor, &CrashFilter::default(), Some(2), page.next)
        .await
        .expect("lists");
    assert_eq!((ids(&page), page.next), (vec![second], None));
    for limit in [0, MAX_CRASHES_PAGE + 1] {
        assert!(matches!(
            service
                .crashes(&actor, &CrashFilter::default(), Some(limit), None)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    assert!(matches!(
        service.crashes(&actor, &CrashFilter::default(), None, Some(done)).await,
        Err(ServiceError::InvalidRequest(why)) if why == format!("the cursor {done} names no failed task")
    ));

    let detail = service.crash(&actor, first).await.expect("reads");
    assert_eq!(detail.crash, all.crashes[1]);
    assert_eq!(detail.paths, ["mail/a.txt"]);
    assert_eq!(detail.root_title, "a submission");
    assert_eq!(detail.analysis_mode, "correlation");
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    assert_eq!(
        detail.inputs,
        [
            CrashInput {
                sha256,
                size: Some(9),
                mime_type: Some("text/plain".to_owned()),
            },
            CrashInput {
                sha256: "0".repeat(64),
                size: None,
                mime_type: None,
            },
        ]
    );
    assert!(matches!(
        service.crash(&actor, done).await,
        Err(ServiceError::NotFound(why)) if why == format!("no failed task {done}")
    ));

    // reads need crash:read and write no row
    let rows = audit_rows(db).await.len();
    let outsider = user(UserId(Uuid::from_u128(0x5E)));
    assert!(matches!(
        service
            .crashes(&outsider, &CrashFilter::default(), None, None)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.crash(&outsider, first).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
}

// PLAN.md 5.6's yara_qa router.

const QA_UUID: &str = "4c3c8330-545d-4673-9a7c-7bd4597d0098";

/// A match record as the YARA module writes one, with meta a rule's author could write.
fn qa_record(uuid: &str) -> Value {
    json!({
        "rule": "qa_rule",
        "namespace": "ns",
        "meta": {"uuid": uuid, "modifiers": "qa", "description": "<script>alert(1)</script>"},
        "tags": ["candidate"],
        "commit": "c0ffee",
        "ruleset": null,
        "target": "mail/a.txt",
        "strings": [
            [10, "$a", {"base64": "RVZJTA=="}],
            [4, "$a", {"base64": "RVZJTA=="}],
            [7, "$b", {"base64": "RVZJTA=="}],
        ],
        "context": [],
        "match_context": [],
    })
}

/// A kept QA match of `uuid` at `version` on a file alert's file, held as the core's recorder holds one.
async fn qa_match(
    db: &Db,
    bucket: &Bucket,
    root: Uuid,
    observable: i64,
    uuid: &str,
    version: &str,
) -> i64 {
    let (id, sha256, expires_at): (i64, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "INSERT INTO yara.qa_matches
             (signature_uuid, signature_version, rule, namespace, sha256, file_path, root_id,
              observable_id, match, expires_at)
         SELECT $3, $4, 'qa_rule', 'ns', o.value, 'mail/a.txt', o.root_id, o.id, $5,
                now() + interval '30 days'
         FROM analysis.observables o WHERE o.root_id = $1 AND o.id = $2
         RETURNING id, sha256, expires_at",
    )
    .bind(root)
    .bind(observable)
    .bind(uuid)
    .bind(version)
    .bind(qa_record(uuid))
    .fetch_one(db.pool())
    .await
    .expect("a QA match");
    bucket
        .hold(
            ALERT_FILES,
            &sha256.parse().expect("a sha256"),
            &Hold::new(ace_core::yara_qa::HOLDER_KIND, id.to_string()).until(expires_at),
        )
        .await
        .expect("holds");
    id
}

/// The current ruleset's row, with these QA rules, or none recorded.
async fn qa_ruleset(db: &Db, qa_rules: Option<Value>) {
    sqlx::query(
        "INSERT INTO yara.rulesets
             (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules)
         VALUES (repeat('a', 64), md5(random()::text), 'tree', 'sources', $1, '[]', '[]', $2)",
    )
    .bind(ace_core::rulesets::YARA_X_VERSION)
    .bind(qa_rules)
    .execute(db.pool())
    .await
    .expect("a ruleset");
}

/// Every QA match and every hold, whole.
async fn qa_state(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(q)::text FROM yara.qa_matches q
         UNION ALL SELECT row_to_json(h)::text FROM store.holds h
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// The holds on a file, as (kind, id).
async fn holds_on(db: &Db, sha256: &str) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds
         WHERE pool = 'alert_files' AND sha256 = $1 ORDER BY 1, 2",
    )
    .bind(sha256)
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

async fn download_qa_match_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let id = qa_match(db, &bucket, root, observable, QA_UUID, "v1").await;
    let actor = admin(db).await;
    let source = "192.0.2.10".parse().expect("an address");
    let download = with_source_ip(Some(source), service(db).download_qa_match(&actor, id))
        .await
        .expect("may download");
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    assert_eq!(download.qa_match.sha256, sha256);
    assert_eq!(download.record, qa_record(QA_UUID));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_qa_match".to_owned(),
            target: ("yara_qa_match".to_owned(), id.to_string()),
            before: None,
            after: None,
            details: json!({
                "signature_uuid": QA_UUID,
                "signature_version": "v1",
                "sha256": sha256,
            }),
        }
    );
    assert_eq!(src_ip_of_last(db).await.as_deref(), Some("192.0.2.10"));

    // it needs signature:download, which signature:read isn't, and a refusal or a missing match has no row
    let reader = UserId(Uuid::from_u128(0x6A));
    grant(
        db,
        &Holder::User(reader),
        "signature",
        "read",
        Effect::Allow,
    )
    .await;
    let rows = audit_rows(db).await.len();
    for refused in [
        service(db)
            .download_qa_match(&user(reader), id)
            .await
            .map(|_| ()),
        service(db)
            .download_qa_matches(&user(reader), QA_UUID, None, &[])
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(refused, Err(ServiceError::PermissionDenied { ref permission, .. })
                if permission.to_string() == "signature:download"),
            "{refused:?}"
        );
    }
    assert!(service(db).qa_match(&user(reader), id).await.is_ok());
    assert!(matches!(
        service(db).download_qa_match(&actor, id + 1000).await,
        Err(ServiceError::NotFound(why)) if why == format!("no kept YARA QA match {}", id + 1000)
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn download_qa_matches_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let uuid = "download-these";
    let first = qa_match(db, &bucket, root, observable, uuid, "v1").await;
    let second = qa_match(db, &bucket, root, observable, uuid, "v2").await;
    let actor = admin(db).await;
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    let downloads = service(db)
        .download_qa_matches(&actor, uuid, None, &[])
        .await
        .expect("may download");
    let ids: Vec<i64> = downloads.iter().map(|d| d.qa_match.id).collect();
    assert_eq!(ids, [first, second], "oldest first");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_qa_matches".to_owned(),
            target: ("yara_rule".to_owned(), uuid.to_owned()),
            before: None,
            after: None,
            details: json!({
                "version": null,
                "matches": [{"id": first, "sha256": sha256}, {"id": second, "sha256": sha256}],
            }),
        }
    );
    let downloads = service(db)
        .download_qa_matches(&actor, uuid, Some("v2"), &[])
        .await
        .expect("may download");
    assert_eq!(downloads.len(), 1);
    assert_eq!(last_audit(db).await.details["version"], "v2");

    // ids that aren't the rule's, nothing to download, or too many ids, are refused with no row
    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service(db).download_qa_matches(&actor, uuid, None, &[first, first + 1000]).await,
        Err(ServiceError::NotFound(why)) if why == format!("no kept matches of this rule with ids [{}]", first + 1000)
    ));
    assert!(matches!(
        service(db)
            .download_qa_matches(&actor, uuid, Some("v3"), &[])
            .await,
        Err(ServiceError::NotFound(_))
    ));
    let many: Vec<i64> = (1..=501).collect();
    assert!(matches!(
        service(db)
            .download_qa_matches(&actor, uuid, None, &many)
            .await,
        Err(ServiceError::TooLarge(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn purge_qa_matches_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let uuid = "purge-these";
    let first = qa_match(db, &bucket, root, observable, uuid, "v1").await;
    let second = qa_match(db, &bucket, root, observable, uuid, "v2").await;
    let actor = admin(db).await;
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    let purged = service(db)
        .purge_qa_matches(
            &actor,
            uuid,
            &QaPurge {
                versions: Some(vec!["v1".to_owned()]),
                match_ids: None,
                reason: Some("a noisy version <b>".to_owned()),
            },
        )
        .await
        .expect("may purge");
    assert_eq!((purged.purged, purged.remaining), (vec![first], 0));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "purge_qa_matches".to_owned(),
            target: ("yara_rule".to_owned(), uuid.to_owned()),
            before: Some(json!({
                "matches": [{"id": first, "signature_version": "v1", "sha256": sha256, "root": root}],
            })),
            after: None,
            details: json!({
                "versions": ["v1"],
                "match_ids": null,
                "reason": "a noisy version <b>",
                "remaining": 0,
            }),
        }
    );

    // a purge that finds nothing has no row, nor does a refusal or a request the service won't take
    let rows = audit_rows(db).await.len();
    let nothing = service(db)
        .purge_qa_matches(
            &actor,
            uuid,
            &QaPurge {
                match_ids: Some(vec![first]),
                ..QaPurge::default()
            },
        )
        .await
        .expect("may purge");
    assert_eq!((nothing.purged, nothing.remaining), (vec![], 0));
    let reader = UserId(Uuid::from_u128(0x6B));
    grant(
        db,
        &Holder::User(reader),
        "signature",
        "download",
        Effect::Allow,
    )
    .await;
    let rows_after_grant = audit_rows(db).await.len();
    assert_eq!(rows_after_grant, rows + 1, "the grant's own row");
    let one = QaPurge {
        match_ids: Some(vec![second]),
        ..QaPurge::default()
    };
    assert!(matches!(
        service(db).purge_qa_matches(&user(reader), uuid, &one).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "signature:qa_purge"
    ));
    for (bad, why) in [
        (QaPurge::default(), "give versions or match_ids, not both"),
        (
            QaPurge {
                versions: Some(vec!["v2".to_owned()]),
                match_ids: Some(vec![second]),
                reason: None,
            },
            "give versions or match_ids, not both",
        ),
        (
            QaPurge {
                versions: Some(vec![]),
                ..QaPurge::default()
            },
            "give 1 to 1000 versions",
        ),
        (
            QaPurge {
                match_ids: Some((0..501).collect()),
                ..QaPurge::default()
            },
            "give 1 to 500 match ids, or purge by version",
        ),
        (
            QaPurge {
                match_ids: Some(vec![second]),
                reason: Some("x".repeat(1025)),
                ..QaPurge::default()
            },
            "a reason is at most 1024 characters",
        ),
    ] {
        assert!(
            matches!(
                service(db).purge_qa_matches(&actor, uuid, &bad).await,
                Err(ServiceError::InvalidRequest(ref got)) if got == why
            ),
            "{why}"
        );
    }
    assert_eq!(audit_rows(db).await.len(), rows_after_grant);
    // other writes here hold the same bytes, so only this test's holds are looked at
    let holds = holds_on(db, &sha256).await;
    assert!(holds.contains(&("root".to_owned(), root.to_string())));
    assert!(
        holds.contains(&("yara_qa".to_owned(), second.to_string())),
        "the refused purges left the other match's hold"
    );
    assert!(!holds.contains(&("yara_qa".to_owned(), first.to_string())));
    row.action
}

/// PLAN.md 6.7: the scheduler's daily prune removes the matches past their expiry with their own holds,
/// in a batch with one row listing them, as the component the migration grants `signature:qa_purge`. A
/// live match and its hold stay, a prune that finds nothing has no row, and one without the grant is
/// refused.
async fn prune_qa_matches_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let (root, observable) = file_alert(db, &bucket).await;
    let uuid = "prune-these";
    let expired = qa_match(db, &bucket, root, observable, uuid, "v1").await;
    let live = qa_match(db, &bucket, root, observable, uuid, "v2").await;
    expire_qa_match(db, expired).await;
    let pruner = Actor::Internal {
        id: Component::new("scheduler:yara_qa_prune").expect("valid"),
    };
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    let pruned = service(db)
        .prune_qa_matches(&pruner)
        .await
        .expect("may prune");
    assert_eq!(
        pruned,
        QaPruned {
            removed: 1,
            batches: 1
        }
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "internal", "id": "scheduler:yara_qa_prune"}),
            action: "prune_qa_matches".to_owned(),
            target: ("yara_qa_matches".to_owned(), "expired".to_owned()),
            before: Some(json!({
                "matches": [{"id": expired, "signature_version": "v1", "sha256": sha256, "root": root}],
            })),
            after: None,
            details: json!({}),
        }
    );
    let rows = audit_rows(db).await.len();
    let nothing = service(db)
        .prune_qa_matches(&pruner)
        .await
        .expect("may prune");
    assert_eq!(nothing, QaPruned::default());
    let reader = UserId(Uuid::from_u128(0x6C));
    exists(db, &Holder::User(reader)).await;
    assert!(matches!(
        service(db).prune_qa_matches(&user(reader)).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "signature:qa_purge"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    let holds = holds_on(db, &sha256).await;
    assert!(holds.contains(&("yara_qa".to_owned(), live.to_string())));
    assert!(!holds.contains(&("yara_qa".to_owned(), expired.to_string())));
    row.action
}

/// Moves a QA match and its hold past their expiry.
async fn expire_qa_match(db: &Db, id: i64) {
    sqlx::query("UPDATE yara.qa_matches SET expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await
        .expect("expires the match");
    sqlx::query(
        "UPDATE store.holds SET expires_at = now() - interval '1 day'
         WHERE holder_kind = 'yara_qa' AND holder_id = $1",
    )
    .bind(id.to_string())
    .execute(db.pool())
    .await
    .expect("expires its hold");
}

/// ace3's listing: the QA rules of the current ruleset, matched or not, merged with the rules that have
/// matches kept, filtered, ordered and paged; one rule with its versions; its matches newest first; and a
/// match with its record. A match past its expiry isn't served. Each read needs signature:read and writes
/// no row.
#[tokio::test]
async fn qa_rules_merge_the_ruleset_and_the_kept_matches() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let actor = admin(db).await;
    let (root, file) = file_alert(db, &bucket).await;
    let empty = service
        .qa_rules(&actor, &QaRuleFilter::default(), None, 0)
        .await
        .expect("lists");
    assert_eq!((empty.total, empty.ruleset), (0, None));

    // matched under two versions, a rule that left QA mode, and one past its expiry
    let old = qa_match(db, &bucket, root, file, QA_UUID, "v1").await;
    let new = qa_match(db, &bucket, root, file, QA_UUID, "v2").await;
    sqlx::query(
        "UPDATE yara.qa_matches SET hit_count = 3, first_seen = now() - interval '2 days',
                last_seen = now() - interval '1 day' WHERE id = $1",
    )
    .bind(old)
    .execute(db.pool())
    .await
    .expect("ages");
    let left = qa_match(db, &bucket, root, file, "left-qa", "v1").await;
    let expired = qa_match(db, &bucket, root, file, QA_UUID, "v0").await;
    sqlx::query(
        "UPDATE yara.qa_matches SET expires_at = now() - interval '1 second',
                first_seen = now() - interval '40 days', last_seen = now() - interval '31 days'
         WHERE id = $1",
    )
    .bind(expired)
    .execute(db.pool())
    .await
    .expect("expires");

    // a ruleset from before QA rules were recorded lists only what matched
    qa_ruleset(db, None).await;
    let page = service
        .qa_rules(&actor, &QaRuleFilter::default(), None, 0)
        .await
        .expect("lists");
    assert_eq!(page.total, 2);
    assert!(!page.ruleset.expect("a ruleset").qa_rules_recorded);
    assert!(page.rules.iter().all(|r| r.status == QaStatus::NotQa));

    let hostile_uuid = "<img src=x onerror=alert(1)>/../../etc/passwd";
    qa_ruleset(
        db,
        Some(json!([
            {"namespace": "ns", "path": "ns/qa.yar", "name": "qa_rule", "uuid": QA_UUID,
             "enabled": true, "tags": ["candidate"]},
            {"namespace": "ns", "path": "ns/qa.yar", "name": "never_matched", "uuid": hostile_uuid,
             "enabled": false, "tags": []},
            {"namespace": "ns", "path": "ns/qa.yar", "name": "no_uuid", "uuid": null,
             "enabled": true, "tags": []},
        ])),
    )
    .await;
    let page = service
        .qa_rules(&actor, &QaRuleFilter::default(), None, 0)
        .await
        .expect("lists");
    let ruleset = page.ruleset.clone().expect("a ruleset");
    assert!(ruleset.qa_rules_recorded);
    assert_eq!(ruleset.key, "a".repeat(64));
    let names: Vec<&str> = page.rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        ["never_matched", "qa_rule", "qa_rule"],
        "by name, then uuid"
    );
    assert_eq!(page.total, 3);
    let qa = page
        .rules
        .iter()
        .find(|r| r.signature_uuid == QA_UUID)
        .expect("the QA rule");
    assert_eq!(qa.status, QaStatus::Qa);
    assert_eq!(qa.enabled, Some(true));
    assert_eq!(qa.path.as_deref(), Some("ns/qa.yar"));
    assert_eq!(qa.tags, ["candidate"]);
    assert_eq!(
        (qa.match_count, qa.stored_count, qa.version_count),
        (5, 2, 3)
    );
    let never = &page.rules[0];
    assert_eq!(never.signature_uuid, hostile_uuid, "a uuid is data");
    assert_eq!(
        (
            never.status,
            never.enabled,
            never.match_count,
            never.last_match_at
        ),
        (QaStatus::Qa, Some(false), 0, None)
    );
    let gone = page
        .rules
        .iter()
        .find(|r| r.signature_uuid == "left-qa")
        .expect("the rule that left QA mode");
    assert_eq!(
        (gone.status, gone.enabled, &gone.path),
        (QaStatus::NotQa, None, &None)
    );

    let listed = |filter: QaRuleFilter, limit: Option<u32>, offset: u32| {
        let service = service.clone();
        let actor = actor.clone();
        async move {
            service
                .qa_rules(&actor, &filter, limit, offset)
                .await
                .expect("lists")
                .rules
                .into_iter()
                .map(|r| r.signature_uuid)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        listed(
            QaRuleFilter {
                q: Some(" NEVER ".to_owned()),
                ..QaRuleFilter::default()
            },
            None,
            0
        )
        .await,
        [hostile_uuid]
    );
    assert_eq!(
        listed(
            QaRuleFilter {
                status: Some(QaStatus::NotQa),
                ..QaRuleFilter::default()
            },
            None,
            0
        )
        .await,
        ["left-qa"]
    );
    assert_eq!(
        listed(
            QaRuleFilter {
                has_matches: Some(false),
                ..QaRuleFilter::default()
            },
            None,
            0
        )
        .await,
        [hostile_uuid]
    );
    assert_eq!(
        listed(
            QaRuleFilter {
                sort: QaSort::MatchCount,
                descending: true,
                ..QaRuleFilter::default()
            },
            None,
            0
        )
        .await,
        [QA_UUID, "left-qa", hostile_uuid]
    );
    assert_eq!(
        listed(
            QaRuleFilter {
                sort: QaSort::LastMatch,
                ..QaRuleFilter::default()
            },
            Some(1),
            1
        )
        .await,
        [QA_UUID],
        "never matched first, then the oldest last match"
    );
    for limit in [0, 501] {
        assert!(matches!(
            service
                .qa_rules(&actor, &QaRuleFilter::default(), Some(limit), 0)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }

    let detail = service.qa_rule(&actor, QA_UUID).await.expect("reads");
    assert_eq!(&detail.rule, qa);
    let versions: Vec<(&str, i64, i64)> = detail
        .versions
        .iter()
        .map(|v| (v.signature_version.as_str(), v.match_count, v.stored_count))
        .collect();
    assert_eq!(versions, [("v2", 1, 1), ("v1", 3, 1), ("v0", 1, 0)]);
    assert!(service.qa_rule(&actor, hostile_uuid).await.is_ok());
    assert!(matches!(
        service.qa_rule(&actor, "nothing").await,
        Err(ServiceError::NotFound(_))
    ));

    let page = service
        .qa_matches(&actor, QA_UUID, None, None, None)
        .await
        .expect("lists");
    let ids: Vec<i64> = page.matches.iter().map(|m| m.id).collect();
    assert_eq!(
        (ids, page.next),
        (vec![new, old], None),
        "the expired one isn't served"
    );
    let first = &page.matches[0];
    assert_eq!(
        (
            first.root,
            first.alerted,
            first.observable_id,
            first.file_size
        ),
        (root, true, file, Some(9))
    );
    assert_eq!(first.file_path, "mail/a.txt");
    let page = service
        .qa_matches(&actor, QA_UUID, None, Some(1), None)
        .await
        .expect("lists");
    assert_eq!(page.next, Some(new));
    let page = service
        .qa_matches(&actor, QA_UUID, None, Some(1), page.next)
        .await
        .expect("lists");
    assert_eq!((page.matches[0].id, page.next), (old, None));
    let page = service
        .qa_matches(&actor, QA_UUID, Some("v1"), None, None)
        .await
        .expect("lists");
    assert_eq!(page.matches.len(), 1);
    assert!(matches!(
        service
            .qa_matches(&actor, QA_UUID, None, Some(0), None)
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));

    let detail = service.qa_match(&actor, new).await.expect("reads");
    let summary = detail.summary.expect("a summary");
    assert_eq!(
        summary.meta["description"], "<script>alert(1)</script>",
        "the meta is data"
    );
    let strings: Vec<(&str, usize, u64)> = summary
        .strings
        .iter()
        .map(|s| (s.identifier.as_str(), s.count, s.first_offset))
        .collect();
    assert_eq!(strings, [("$a", 2, 4), ("$b", 1, 7)]);
    assert_eq!(summary.commit.as_deref(), Some("c0ffee"));
    assert_eq!(
        service.qa_match_record(&actor, new).await.expect("reads"),
        qa_record(QA_UUID)
    );
    for missing in [expired, left + 1000] {
        assert!(matches!(
            service.qa_match(&actor, missing).await,
            Err(ServiceError::NotFound(_))
        ));
        assert!(matches!(
            service.qa_match_record(&actor, missing).await,
            Err(ServiceError::NotFound(_))
        ));
    }

    // a record the scanner didn't write has no summary
    sqlx::query("UPDATE yara.qa_matches SET match = '{\"not\": \"a scan result\"}' WHERE id = $1")
        .bind(left)
        .execute(db.pool())
        .await
        .expect("changes the record");
    assert_eq!(
        service.qa_match(&actor, left).await.expect("reads").summary,
        None
    );

    // reads need signature:read, which alert:read isn't, and write no row
    let rows = audit_rows(db).await.len();
    let outsider = UserId(Uuid::from_u128(0x6C));
    grant(db, &Holder::User(outsider), "alert", "read", Effect::Allow).await;
    let outsider = user(outsider);
    let refusals = [
        service
            .qa_rules(&outsider, &QaRuleFilter::default(), None, 0)
            .await
            .map(|_| ()),
        service.qa_rule(&outsider, QA_UUID).await.map(|_| ()),
        service
            .qa_matches(&outsider, QA_UUID, None, None, None)
            .await
            .map(|_| ()),
        service.qa_match(&outsider, new).await.map(|_| ()),
        service.qa_match_record(&outsider, new).await.map(|_| ()),
    ];
    for refused in refusals {
        assert!(
            matches!(refused, Err(ServiceError::PermissionDenied { ref permission, .. })
                if permission.to_string() == "signature:read"),
            "{refused:?}"
        );
    }
    assert_eq!(audit_rows(db).await.len(), rows + 1, "only the grant's row");
}

/// A purge releases only its own matches' holds: a file that a root or another match still holds stays
/// through GC, and goes once nothing holds it. A purge of more than 500 says what's left.
#[tokio::test]
async fn a_purge_releases_only_its_own_holds() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let actor = admin(db).await;
    let bytes = b"a file only the purge test holds";
    let (root, file) = file_alert_with(db, &bucket, bytes).await;
    let sha256 = hex::encode(Sha256::digest(bytes));
    let ours = qa_match(db, &bucket, root, file, QA_UUID, "v1").await;
    let theirs = qa_match(db, &bucket, root, file, "another-rule", "v1").await;
    let age_and_collect = || async {
        sqlx::query(
            "UPDATE store.objects SET last_held_at = now() - interval '2 days'
             WHERE pool = 'alert_files' AND sha256 = $1",
        )
        .bind(&sha256)
        .execute(db.pool())
        .await
        .expect("ages");
        bucket.gc(ALERT_FILES).await.expect("collects");
        bucket
            .object(ALERT_FILES, &sha256.parse().expect("a sha256"))
            .await
            .expect("reads")
            .is_some()
    };

    let purged = service
        .purge_qa_matches(
            &actor,
            QA_UUID,
            &QaPurge {
                match_ids: Some(vec![ours, theirs]),
                ..QaPurge::default()
            },
        )
        .await
        .expect("purges");
    assert_eq!(
        purged.purged,
        [ours],
        "another rule's match isn't this rule's to purge"
    );
    assert_eq!(
        holds_on(db, &sha256).await,
        [
            ("root".to_owned(), root.to_string()),
            ("yara_qa".to_owned(), theirs.to_string()),
        ]
    );
    let last_held: bool = sqlx::query_scalar(
        "SELECT last_held_at > now() - interval '1 minute' FROM store.objects
         WHERE pool = 'alert_files' AND sha256 = $1",
    )
    .bind(&sha256)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert!(last_held, "a release starts the grace again");
    assert!(
        age_and_collect().await,
        "the root and the other match hold it"
    );

    service
        .purge_qa_matches(
            &actor,
            "another-rule",
            &QaPurge {
                versions: Some(vec!["v1".to_owned()]),
                ..QaPurge::default()
            },
        )
        .await
        .expect("purges");
    assert_eq!(
        holds_on(db, &sha256).await,
        [("root".to_owned(), root.to_string())]
    );
    assert!(age_and_collect().await, "the root still holds it");
    bucket
        .release(
            ALERT_FILES,
            &sha256.parse().expect("a sha256"),
            &Hold::root(root),
        )
        .await
        .expect("releases");
    assert!(!age_and_collect().await, "nothing holds it, so it goes");

    // more than one purge's worth: 501 versions of one rule
    sqlx::query(
        "INSERT INTO yara.qa_matches
             (signature_uuid, signature_version, rule, namespace, sha256, file_path, root_id,
              observable_id, match, expires_at)
         SELECT 'many', 'v' || n, 'r', 'ns', $1, 'p', $2, 1, '{}', now() + interval '1 day'
         FROM generate_series(1, 501) AS n",
    )
    .bind(&sha256)
    .bind(root)
    .execute(db.pool())
    .await
    .expect("adds matches");
    let versions: Vec<String> = (1..=501).map(|n| format!("v{n}")).collect();
    let everything = QaPurge {
        versions: Some(versions),
        ..QaPurge::default()
    };
    let first = service
        .purge_qa_matches(&actor, "many", &everything)
        .await
        .expect("purges");
    assert_eq!((first.purged.len(), first.remaining), (500, 1));
    let rest = service
        .purge_qa_matches(&actor, "many", &everything)
        .await
        .expect("purges");
    assert_eq!((rest.purged.len(), rest.remaining), (1, 0));
}

async fn disposition_records_its_row(db: &Db) -> String {
    let service = service(db);
    let root = alert(db).await;
    let alice = user(UserId(Uuid::from_u128(1)));
    may_disposition(db, &[Holder::User(UserId(Uuid::from_u128(1)))]).await;
    let scheduler = component("scheduler");
    may_disposition(
        db,
        &[Holder::Component(
            Component::new("scheduler").expect("valid"),
        )],
    )
    .await;

    service
        .disposition(&alice, root, "FALSE_POSITIVE")
        .await
        .expect("dispositions");
    let first = last_audit(db).await;
    assert_eq!(first.actor, alice_json());
    assert_eq!(first.action, "disposition");
    assert_eq!(first.target, ("root".to_owned(), root.to_string()));
    assert_eq!(
        first.before,
        Some(json!({
            "disposition": null,
            "dispositioned_by": null,
            "analysis_mode": "correlation",
        }))
    );
    assert_eq!(
        first.after,
        Some(json!({
            "disposition": "FALSE_POSITIVE",
            "dispositioned_by": alice_json(),
            "analysis_mode": row(db, root).await.mode,
        }))
    );
    let mut keys: Vec<&str> = first
        .details
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["event_time", "root_created_at", "title"]);

    // the row's time and the disposition's are one transaction's
    let (same,): (bool,) = sqlx::query_as(
        "SELECT a.created_at = r.dispositioned_at FROM service.audit a, analysis.roots r
         WHERE r.id = $1 AND a.target_id = $1::text",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("compares");
    assert!(same);

    // a later disposition says what it replaced, even when the disposition is the same
    service
        .disposition(&scheduler, root, "FALSE_POSITIVE")
        .await
        .expect("dispositions again");
    let second = last_audit(db).await;
    assert_eq!(
        second.before.as_ref().expect("a before")["dispositioned_by"],
        alice_json()
    );
    assert_eq!(second.actor, json!({"kind": "internal", "id": "scheduler"}));
    second.action
}

async fn grant_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let holder = Holder::Component(Component::new("collector:journal").expect("valid"));
    assert!(
        service(db)
            .grant(&actor, &holder, &pattern("ALERT", "Read"), Effect::Deny)
            .await
            .expect("grants")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "user", "id": Uuid::from_u128(0xAD), "name": "alice"}),
            action: "grant".to_owned(),
            target: ("component".to_owned(), "collector:journal".to_owned()),
            before: None,
            after: Some(json!({"major": "alert", "minor": "read", "effect": "deny"})),
            details: json!({}),
        }
    );
    row.action
}

async fn revoke_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let target = UserId(Uuid::from_u128(0xB0B));
    grant(db, &Holder::User(target), "alert", "write", Effect::Allow).await;
    assert!(
        service(db)
            .revoke(
                &actor,
                &Holder::User(target),
                &pattern("alert", "write"),
                Effect::Allow
            )
            .await
            .expect("revokes")
    );
    let actor_json = json!({"kind": "user", "id": Uuid::from_u128(0xAD), "name": "alice"});
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json.clone(),
            action: "revoke".to_owned(),
            target: ("user".to_owned(), target.0.to_string()),
            before: Some(json!({
                "major": "alert",
                "minor": "write",
                "effect": "allow",
                "created_by": actor_json,
            })),
            after: None,
            details: json!({}),
        }
    );
    row.action
}

/// A write whose audit can't be stored fails and leaves no write. The constraint refuses every new row,
/// whichever way a future bug would: this is the failure, not a stand-in for it.
#[tokio::test]
async fn every_write_fails_when_its_audit_fails() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (hunt_bucket, _hunt_cache) = bucket(db);
    let root = alert(db).await;
    let actor = admin(db).await;
    let held = Holder::User(UserId(Uuid::from_u128(2)));
    exists(db, &held).await;
    exists(db, &Holder::User(UserId(Uuid::from_u128(3)))).await;
    let every = pattern("*", "*");
    service
        .grant(&actor, &held, &every, Effect::Allow)
        .await
        .expect("grants");
    let bob = new_user(&service, &actor, "bob").await;
    let bob_actor = Actor::User {
        id: bob,
        name: "bob".to_owned(),
    };
    let bobs_session = service
        .login("bob", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let key = service
        .create_api_key(&actor, "triage", None, &[])
        .await
        .expect("makes a key");
    for grant in [pattern("user", "self"), pattern("alert", "read")] {
        service
            .grant(&actor, &Holder::User(bob), &grant, Effect::Allow)
            .await
            .expect("grants");
    }
    let bobs_key = service
        .create_own_api_key(&bob_actor, "bob's", &[pattern("alert", "read")])
        .await
        .expect("makes bob's key");
    let team = service.create_group(&actor, "team").await.expect("a group");
    service
        .add_group_member(&actor, team, bob)
        .await
        .expect("adds bob");
    let other_team = service
        .create_group(&actor, "other team")
        .await
        .expect("a group");
    let (bucket, _cache) = bucket(db);
    let (file_root, file) = file_alert(db, &bucket).await;
    let crash = failed_task(db, file_root, file, "crasher", "the module panicked").await;
    let qa = qa_match(db, &bucket, file_root, file, QA_UUID, "v1").await;
    let expired_qa = qa_match(db, &bucket, file_root, file, "expired", "v1").await;
    expire_qa_match(db, expired_qa).await;
    let (submitted, files) = submission(&bucket, b"another file").await;
    let comment = service
        .add_observable_comment(&actor, "fqdn", "evil.example.com", "before")
        .await
        .expect("comments");
    service
        .set_preference(&bob_actor, &theme(Theme::Dark))
        .await
        .expect("sets bob's theme");
    let bobs_filter = service
        .create_saved_filter(
            &bob_actor,
            FilterScreen::Alerts,
            &new_filter("bob's", vec![text("Disposition", false, &["OPEN"])]),
        )
        .await
        .expect("saves bob's filter");
    let event = event_with(db, "audit fails", &[root]).await;
    let other_alert = alert(db).await;
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = ANY($1)")
        .bind(vec![root, other_alert])
        .execute(db.pool())
        .await
        .expect("makes them alerts");
    let unused_type = service
        .create_threat_type(&actor, "unused")
        .await
        .expect("adds a type");
    let malware = malware_named(db, "audit-fails").await;
    let threat = service
        .add_threat(&actor, malware, unused_type.id)
        .await
        .expect("adds a threat");
    let other_type = service
        .create_threat_type(&actor, "other")
        .await
        .expect("adds a type");
    let event_now = service
        .event(&actor, EventRef::Id(event))
        .await
        .expect("reads the event");
    let queued_command = service
        .start_command(&actor, "--help", None)
        .await
        .expect("starts a command")
        .run
        .id;
    let listed = service
        .add_list_entry(
            &actor,
            TEST_LIST.name,
            &list_entry(MatchKind::Substring, "before"),
        )
        .await
        .expect("adds an entry");
    let detected = service
        .create_detection(&actor, &new_detection("fqdn", "before.example"))
        .await
        .expect("adds a detection");
    let archive = email_archive(&bucket, db);
    archived(&archive, b"an archived email", "<audit-fails@example.com>").await;
    let acted = action_fixtures(db, &service, &actor).await;
    let (graded, graded_ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    service
        .set_detection_verdict(&actor, graded, graded_ids[0], Verdict::Fp)
        .await
        .expect("sets a verdict to clear");
    let verdicts_before = (
        stored_verdicts(db, graded).await,
        verdict_history(db, graded).await,
    );
    let lab = service
        .create_test_host(&actor, &HostFields::new("win10-01"))
        .await
        .expect("adds a test host");
    let hosts_before = test_host_rows(db).await;
    // a sample for each of its actions
    let (_, relabelled, _) = audited_sample(db).await;
    let (_, reset, _) = audited_sample(db).await;
    service
        .relabel_svs_sample(&actor, &reset, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels to reset");
    let (_, confirmed, _) = audited_sample(db).await;
    let (_, retired, _) = audited_sample(db).await;
    let (_, unretired, _) = audited_sample(db).await;
    service
        .retire_svs_sample(&actor, &unretired, RULE_UUID, "to unretire")
        .await
        .expect("retires");
    let (_, deleted, _) = audited_sample(db).await;
    // a validation to request again, one to download from and one to prune (PLAN.md 7.10 batch 3)
    let svs_repo = svs_repository();
    let validations = validating(db, &svs_repo);
    let validation_content = format!("svs audit fails {}", Uuid::new_v4()).into_bytes();
    let validation_sample = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &validation_content,
        &[RULE_UUID],
        "sample.bin",
    )
    .await;
    let downloadable = completed_validation(
        db,
        &svs_repo,
        &validation_head(),
        vec![result_row(
            ValidationCategory::Regression,
            &validation_sample,
        )],
    )
    .await;
    let prunable = completed_validation(db, &svs_repo, &"c".repeat(40), vec![]).await;
    sqlx::query(
        "UPDATE svs.validations SET finished_at = now() - interval '100 days' WHERE uuid = $1",
    )
    .bind(prunable)
    .execute(db.pool())
    .await
    .expect("ages it");
    let routable = routing_tests::routable(db).await;
    let routing_before = routing_tests::routing_rows(db, routable).await;
    let validations_before = validation_rows(db).await;
    let catalog = svs_catalog_tests::art(&["art_unittest"]).service(db);
    let catalog_before = svs_catalog_tests::catalog_rows(db).await;
    let samples_before = sample_rows(db).await;
    let actions_before = action_rows(db).await;
    let lists_before = list_rows(db).await;
    let commands_before = command_rows(db).await;
    let before = (
        row(db, root).await,
        tasks(db, root).await,
        permission_rows(db).await,
        audit_rows(db).await,
        credential_rows(db).await,
        root_count(db).await,
        group_rows(db).await,
        qa_state(db).await,
        comment_rows(db).await,
        preference_rows(db).await,
        saved_rows(db).await,
        event_rows(db).await,
    );

    sqlx::raw_sql("ALTER TABLE service.audit ADD CONSTRAINT broken CHECK (false) NOT VALID")
        .execute(db.pool())
        .await
        .expect("breaks the audit");

    let fresh = Holder::User(UserId(Uuid::from_u128(3)));
    let attempts = [
        (
            "disposition",
            service
                .disposition(&actor, root, "IGNORE")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "grant",
            service
                .grant(&actor, &fresh, &every, Effect::Allow)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "revoke",
            service
                .revoke(&actor, &held, &every, Effect::Allow)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_first_user",
            service
                .create_first_user(&username("first"), Password::new(PASSWORD), true)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_user",
            service
                .create_user(
                    &actor,
                    &username("carol"),
                    Password::new(PASSWORD),
                    &Profile::default(),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_user_enabled",
            service
                .set_user_enabled(&actor, bob, false)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "reset_password",
            service
                .reset_password(&actor, bob, Password::new(OTHER_PASSWORD))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "change_own_password",
            service
                .change_own_password(
                    &bob_actor,
                    Password::new(PASSWORD),
                    Password::new(OTHER_PASSWORD),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_api_key",
            service
                .create_api_key(&actor, "another", None, &[])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "revoke_api_key",
            service
                .revoke_api_key(&actor, key.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "login",
            service
                .login("bob", Password::new(PASSWORD), None)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "logout",
            service
                .logout(bobs_session.token.expose())
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "submit",
            service
                .submit(&actor, &bucket, &submitted, &files)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_file",
            service
                .download_file(&actor, file_root, file)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_crash",
            service
                .download_crash(&actor, crash)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_qa_match",
            service
                .download_qa_match(&actor, qa)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_qa_matches",
            service
                .download_qa_matches(&actor, QA_UUID, None, &[])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "purge_qa_matches",
            service
                .purge_qa_matches(
                    &actor,
                    QA_UUID,
                    &QaPurge {
                        match_ids: Some(vec![qa]),
                        ..QaPurge::default()
                    },
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "prune_qa_matches",
            service
                .prune_qa_matches(&actor)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_observable_comment",
            service
                .add_observable_comment(&actor, "fqdn", "evil.example.com", "after")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "edit_observable_comment",
            service
                .edit_observable_comment(&actor, comment.id, "after")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_observable_comment",
            service
                .delete_observable_comment(&actor, comment.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "update_user",
            service
                .update_user(&actor, bob, &display_name("Bob"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "update_own_profile",
            service
                .update_own_profile(&bob_actor, &display_name("Bobby"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_group",
            service
                .create_group(&actor, "a third team")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_group",
            service
                .delete_group(&actor, team)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_group_member",
            service
                .add_group_member(&actor, other_team, bob)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "remove_group_member",
            service
                .remove_group_member(&actor, team, bob)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_api_key_scope",
            service
                .set_api_key_scope(&actor, key.id, "triage", &[pattern("alert", "read")])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_own_api_key",
            service
                .create_own_api_key(&bob_actor, "another", &[pattern("alert", "read")])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_own_api_key_scope",
            service
                .set_own_api_key_scope(
                    &bob_actor,
                    bobs_key.id,
                    "renamed",
                    &[pattern("alert", "read")],
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "revoke_own_api_key",
            service
                .revoke_own_api_key(&bob_actor, bobs_key.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_preference",
            service
                .set_preference(&bob_actor, &theme(Theme::Light))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "reset_preference",
            service
                .reset_preference(&bob_actor, PreferenceKey::Theme)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_saved_filter",
            service
                .create_saved_filter(
                    &bob_actor,
                    FilterScreen::Alerts,
                    &new_filter("another", vec![text("Disposition", false, &["OPEN"])]),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "update_saved_filter",
            service
                .update_saved_filter(
                    &bob_actor,
                    bobs_filter.id,
                    &ace_service::SavedFilterChange {
                        name: Some("renamed".to_owned()),
                        ..ace_service::SavedFilterChange::default()
                    },
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_saved_filter",
            service
                .delete_saved_filter(&bob_actor, bobs_filter.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_quick_filters",
            service
                .set_quick_filters(&bob_actor, FilterScreen::Alerts, &[bobs_filter.id])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        // the admin has no saved filter yet, so the seeding has two to add
        (
            "seed_saved_filters",
            service
                .seed_saved_filters(&actor, FilterScreen::Alerts)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_event_status",
            service
                .set_event_status(&actor, EventRef::Id(event), "CLOSED")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_threat_type",
            service
                .create_threat_type(&actor, "never made")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "rename_threat_type",
            service
                .rename_threat_type(&actor, other_type.id, "never renamed")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_threat_type",
            service
                .delete_threat_type(&actor, other_type.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_threat",
            service
                .add_threat(&actor, malware, other_type.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "remove_threat",
            service
                .remove_threat(&actor, threat.malware_id, threat.threat_type_id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_to_event",
            service
                .add_to_event(
                    &actor,
                    &EventChoice::New(NewEvent {
                        name: "never made".to_owned(),
                        ..NewEvent::default()
                    }),
                    &[root],
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_to_event",
            service
                .add_to_event(
                    &actor,
                    &EventChoice::Existing(EventRef::Id(event)),
                    &[other_alert],
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "edit_event",
            service
                .edit_event(
                    &actor,
                    EventRef::Id(event),
                    &EventEdit {
                        name: "never renamed".to_owned(),
                        campaign: CampaignChoice::New("never made".to_owned()),
                        malware: vec![MalwareChoice::New {
                            name: "never made".to_owned(),
                            threat_types: vec![other_type.id],
                        }],
                        ..edit_of(db, &event_now).await
                    },
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "remove_alerts",
            service
                .remove_alerts(&actor, EventRef::Id(event), &[root])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_event_tags",
            service
                .add_event_tags(&actor, EventRef::Id(event), &["never".to_owned()])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "start_command",
            service
                .start_command(&actor, "--version", Some(5))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "cancel_command",
            service
                .cancel_command(&actor, queued_command)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "add_list_entry",
            service
                .add_list_entry(
                    &actor,
                    TEST_LIST.name,
                    &list_entry(MatchKind::Exact, "after"),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "edit_list_entry",
            service
                .edit_list_entry(
                    &actor,
                    TEST_LIST.name,
                    listed.id,
                    &list_entry(MatchKind::Exact, "after"),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_list_entry",
            service
                .delete_list_entry(&actor, TEST_LIST.name, listed.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_detection",
            service
                .create_detection(&actor, &new_detection("fqdn", "after.example"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_detection",
            service
                .delete_detection(&actor, detected.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_detection_expiration",
            service
                .set_detection_expiration(&actor, detected.id, None)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "sync_hunts",
            service
                .sync_hunts(&hunter(), "splunk", &[loaded_hunt("a.yaml")])
                .await
                .expect_err("refused"),
        ),
        (
            "validate_hunt",
            service
                .validate_hunt(&actor, &|| (validation(), ()))
                .await
                .expect_err("refused"),
        ),
        (
            "archived_email",
            service
                .archived_email(&actor, &archive, "<audit-fails@example.com>")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "record_hunt_run",
            service
                .record_hunt_run(
                    &hunter(),
                    &hunt_bucket,
                    &hunt_run(HuntState::default(), vec![]),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "queue_remediations",
            service
                .queue_remediations(&actor, RemediationAction::Remove, &[test_target("SUCCESS")])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "cancel_remediation",
            service
                .cancel_remediation(&actor, acted.pending)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "retry_remediation",
            service
                .retry_remediation(&actor, acted.removed)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "restore_remediation",
            service
                .restore_remediation(&actor, acted.removed)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_remediation",
            service
                .delete_remediation(&actor, acted.removed)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "request_file_collection",
            service
                .request_file_collection(&actor, &collection_ask("h9@C:\\z.exe", &[]))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "cancel_file_collection",
            service
                .cancel_file_collection(&actor, acted.collection)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "retry_file_collection",
            service
                .retry_file_collection(&actor, acted.collection)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_file_collection",
            service
                .delete_file_collection(&actor, acted.collection)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "prune_file_collections",
            service
                .prune_file_collections(&component("scheduler:file_collection_prune"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_detection_verdict",
            service
                .set_detection_verdict(&actor, graded, graded_ids[1], Verdict::Fp)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "clear_detection_verdict",
            service
                .clear_detection_verdict(&actor, graded, graded_ids[0])
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "set_detection_verdicts",
            service
                .set_detection_verdicts(
                    &actor,
                    &targets(graded, &graded_ids),
                    Some(Verdict::Tp),
                    &BatchRules::default(),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "confirm_detections",
            service
                .confirm_detections(&actor, graded)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "create_test_host",
            service
                .create_test_host(&actor, &HostFields::new("win10-02"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "update_test_host",
            service
                .update_test_host(&actor, lab.id, &HostFields::new("win10-03"))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_test_host",
            service
                .delete_test_host(&actor, lab.id)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "relabel_svs_sample",
            service
                .relabel_svs_sample(&actor, &relabelled, RULE_UUID, Verdict::Fp)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "reset_svs_sample_label",
            service
                .reset_svs_sample_label(&actor, &reset, RULE_UUID)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "confirm_svs_sample",
            service
                .confirm_svs_sample(&actor, &confirmed, RULE_UUID)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "retire_svs_sample",
            service
                .retire_svs_sample(&actor, &retired, RULE_UUID, "stale")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "unretire_svs_sample",
            service
                .unretire_svs_sample(&actor, &unretired, RULE_UUID)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "delete_svs_sample",
            service
                .delete_svs_sample(&actor, &bucket, &deleted, "privacy")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_svs_sample",
            service
                .download_svs_sample(&actor, &deleted, RULE_UUID)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_svs_samples",
            service
                .download_svs_samples(
                    &actor,
                    &SampleQuery {
                        filters: vec![FilterEntry::text("SHA256", false, &[&deleted])],
                        ..SampleQuery::default()
                    },
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
    ];
    let mut attempts = Vec::from(attempts);
    attempts.extend([
        (
            "request_svs_validation",
            validations
                .request_svs_validation(&actor, &ask(&validation_base(), &"d".repeat(40)))
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "download_svs_validation",
            validations
                .download_svs_validation(&actor, downloadable, &ResultSelection::default())
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "prune_svs_validations",
            validations
                .prune_svs_validations(&actor)
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
    ]);
    let refresher = svs_catalog_tests::refresher();
    attempts.extend([
        (
            "store_svs_catalog",
            catalog
                .store_svs_catalog(
                    &refresher,
                    "art_unittest",
                    &"c".repeat(40),
                    &svs_catalog_tests::one_parsed(svs_catalog_tests::GUID_A),
                )
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "record_svs_catalog_error",
            catalog
                .record_svs_catalog_error(&refresher, "art_unittest", "it failed")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
        (
            "retire_svs_catalog_repository",
            catalog
                .retire_svs_catalog_repository(&refresher, "gone")
                .await
                .map(|_| ())
                .expect_err("refused"),
        ),
    ]);
    // the first routing that moves an alert fails; one before it that moves nothing commits
    let routing_failed = loop {
        match service
            .route_due(&ace_service::routing::routing_actor())
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => panic!("nothing due moved an alert"),
            Err(error) => break error,
        }
    };
    attempts.push(("route_due", routing_failed));
    let mut covered = BTreeSet::new();
    for (function, error) in &attempts {
        assert!(error.to_string().contains("broken"), "{function}: {error}");
        covered.insert((*function).to_owned());
    }
    assert_eq!(covered, write_functions(), "{WRITES_NEED_A_TEST}");

    let after = (
        row(db, root).await,
        tasks(db, root).await,
        permission_rows(db).await,
        audit_rows(db).await,
        credential_rows(db).await,
        root_count(db).await,
        group_rows(db).await,
        qa_state(db).await,
        comment_rows(db).await,
        preference_rows(db).await,
        saved_rows(db).await,
        event_rows(db).await,
    );
    assert_eq!(after, before);
    assert_eq!(
        (
            stored_verdicts(db, graded).await,
            verdict_history(db, graded).await,
        ),
        verdicts_before,
        "no verdict changed"
    );
    assert_eq!(action_rows(db).await, actions_before);
    assert_eq!(
        test_host_rows(db).await,
        hosts_before,
        "no test host changed"
    );
    assert_eq!(command_rows(db).await, commands_before);
    assert_eq!(sample_rows(db).await, samples_before, "no sample changed");
    assert_eq!(
        validation_rows(db).await,
        validations_before,
        "no validation changed"
    );
    assert_eq!(
        svs_catalog_tests::catalog_rows(db).await,
        catalog_before,
        "no catalog row changed"
    );
    assert_eq!(
        routing_tests::routing_rows(db, routable).await,
        routing_before,
        "no alert moved, and its routing is still due"
    );
    assert_eq!(
        list_rows(db).await,
        lists_before,
        "no list changed, nor its version"
    );
    assert_eq!(
        queue::completions(db, root).await.expect("reads"),
        [],
        "nothing ended the pass"
    );
}

/// As in ace3, a refusal is a log line and not a record, a failed write rolled its row back, and a
/// write that found nothing to do isn't an event.
#[tokio::test]
async fn only_a_change_that_committed_has_a_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let root = alert(db).await;
    let outsider = user(UserId(Uuid::from_u128(4)));
    let actor = admin(db).await;
    let holder = Holder::User(UserId(Uuid::from_u128(5)));
    exists(db, &holder).await;
    let every = pattern("*", "*");

    service
        .disposition(&outsider, root, "IGNORE")
        .await
        .expect_err("refused");
    service
        .grant(&outsider, &holder, &every, Effect::Allow)
        .await
        .expect_err("refused");
    service
        .revoke(&outsider, &holder, &every, Effect::Allow)
        .await
        .expect_err("refused");
    service
        .disposition(&actor, Uuid::from_u128(9), "IGNORE")
        .await
        .expect_err("no such root");
    assert!(
        !service
            .revoke(&actor, &holder, &every, Effect::Allow)
            .await
            .expect("finds nothing")
    );
    assert_eq!(audit_rows(db).await, []);

    assert!(
        service
            .grant(&actor, &holder, &every, Effect::Allow)
            .await
            .expect("grants")
    );
    assert!(
        !service
            .grant(&actor, &holder, &every, Effect::Allow)
            .await
            .expect("finds it there")
    );
    assert_eq!(audit_rows(db).await.len(), 1);
}

/// Each row's `before` is the state the last one left, since the write locks the root first.
#[tokio::test]
async fn concurrent_dispositions_each_record_what_they_replaced() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let root = alert(db).await;
    let actor = admin(db).await;
    let writes = [
        "IGNORE",
        "FALSE_POSITIVE",
        "UNKNOWN",
        "REVIEWED",
        "GRAYWARE",
        "DELIVERY",
    ]
    .map(|disposition| {
        let (service, actor) = (service.clone(), actor.clone());
        tokio::spawn(async move {
            service
                .disposition(&actor, root, disposition)
                .await
                .expect("dispositions");
        })
    });
    for write in writes {
        write.await.expect("runs");
    }
    let rows = audit_rows(db).await;
    assert_eq!(rows.len(), 6);
    let mut last = Value::Null;
    for row in rows {
        assert_eq!(row.before.expect("a before")["disposition"], last);
        last = row.after.expect("an after")["disposition"].clone();
    }
    assert_eq!(
        row(db, root).await.disposition,
        last.as_str().map(str::to_owned)
    );
}

/// A row can't change or go, whichever statement tries, and it still needs a whole actor.
#[tokio::test]
async fn the_audit_table_is_append_only() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    exists(db, &Holder::User(UserId(Uuid::from_u128(5)))).await;
    service(db)
        .grant(
            &actor,
            &Holder::User(UserId(Uuid::from_u128(5))),
            &pattern("*", "*"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    let before = audit_rows(db).await;

    for statement in [
        "UPDATE service.audit SET action = 'forged'",
        "UPDATE service.audit SET action = 'forged' WHERE false",
        "DELETE FROM service.audit",
        "TRUNCATE service.audit",
    ] {
        let error = sqlx::raw_sql(statement)
            .execute(db.pool())
            .await
            .expect_err(statement);
        assert!(error.to_string().contains("append-only"), "{error}");
    }
    assert_eq!(audit_rows(db).await, before);

    for statement in [
        "INSERT INTO service.audit (actor, action, target_kind, target_id, after)
         VALUES (NULL, 'grant', 'user', 'x', '{}')",
        "INSERT INTO service.audit (actor, action, target_kind, target_id, after)
         VALUES ('{}', 'grant', 'user', 'x', '{}')",
        r#"INSERT INTO service.audit (actor, action, target_kind, target_id, after)
           VALUES ('{"kind": "wizard", "id": "x"}', 'grant', 'user', 'x', '{}')"#,
        r#"INSERT INTO service.audit (actor, action, target_kind, target_id, after)
           VALUES ('{"kind": "user", "id": ""}', 'grant', 'user', 'x', '{}')"#,
    ] {
        let error = sqlx::raw_sql(statement)
            .execute(db.pool())
            .await
            .expect_err(statement);
        assert!(error.as_database_error().is_some(), "{error}");
    }
}

/// Deleting what a row describes leaves the row, and the row can still say what it was.
#[tokio::test]
async fn a_row_outlives_what_it_describes() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let mut new_root = NewRoot::new("correlation");
    new_root.description = "Quarterly invoice".to_owned();
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &new_root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    service
        .disposition(&actor, new_root.id, "IGNORE")
        .await
        .expect("dispositions");
    let group = group_of(db, Uuid::from_u128(7), UserId(Uuid::from_u128(8))).await;
    service
        .grant(&actor, &group, &pattern("alert", "read"), Effect::Allow)
        .await
        .expect("grants");
    let before = audit_rows(db).await;
    assert_eq!(before.len(), 2);

    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(new_root.id)
        .execute(db.pool())
        .await
        .expect("deletes the alert");
    sqlx::query("DELETE FROM service.groups WHERE id = $1")
        .bind(Uuid::from_u128(7))
        .execute(db.pool())
        .await
        .expect("deletes the group and its grants");

    let after = audit_rows(db).await;
    assert_eq!(after, before);
    assert_eq!(after[0].details["title"], "Quarterly invoice");
}

/// What an alert's sender wrote is kept as they wrote it, up to the cap, and comes back as data. A row
/// that names an API key holds its id and name and nothing else about it.
#[tokio::test]
async fn untrusted_text_is_data_and_no_credential_reaches_a_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let id = ApiKeyId(Uuid::from_u128(6));
    let owner = UserId(Uuid::from_u128(1));
    let actor = key(id, Some(owner));
    may_disposition(db, &[Holder::ApiKey(id), Holder::User(owner)]).await;
    let hostile = r#"'); DROP TABLE service.audit; -- <script>alert("x")</script> é"#;
    let mut new_root = NewRoot::new("correlation");
    new_root.description = hostile.repeat(100);
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &new_root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");

    service(db)
        .disposition(&actor, new_root.id, "IGNORE")
        .await
        .expect("dispositions");

    let row = last_audit(db).await;
    let capped: String = new_root.description.chars().take(1024).collect();
    assert_eq!(row.details["title"], capped);
    assert_eq!(
        row.actor,
        json!({"kind": "api_key", "id": id.0, "name": "triage", "owner": owner.0}),
        "the whole actor, so a new field holding a key would fail here"
    );
}

/// ace3 #830's complaint: an operator couldn't search one field for what a user or key did. Here a
/// user's own writes and their keys' come back from one identity, and a component is found the same way.
#[tokio::test]
async fn one_query_finds_what_an_identity_did() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = UserId(Uuid::from_u128(1));
    let alices_key = ApiKeyId(Uuid::from_u128(2));
    let others_key = ApiKeyId(Uuid::from_u128(3));
    let scheduler = Component::new("scheduler").expect("valid");
    may_disposition(
        db,
        &[
            Holder::User(alice),
            Holder::ApiKey(alices_key),
            Holder::ApiKey(others_key),
            Holder::Component(scheduler.clone()),
        ],
    )
    .await;
    let setup = audit_rows(db).await.len();
    for actor in [
        user(alice),
        key(alices_key, Some(alice)),
        key(others_key, None),
        component("scheduler"),
    ] {
        let root = alert(db).await;
        service
            .disposition(&actor, root, "IGNORE")
            .await
            .expect("dispositions");
    }
    assert_eq!(audit_rows(db).await.len(), setup + 4);

    let did = |identity: String| async move {
        let found: Vec<(String,)> = sqlx::query_as(
            "SELECT actor ->> 'kind' FROM service.audit
             WHERE action = 'disposition' AND (actor ->> 'id' = $1 OR actor ->> 'owner' = $1)
             ORDER BY id",
        )
        .bind(identity)
        .fetch_all(db.pool())
        .await
        .expect("reads");
        found.into_iter().map(|(kind,)| kind).collect::<Vec<_>>()
    };
    assert_eq!(did(alice.0.to_string()).await, ["user", "api_key"]);
    assert_eq!(did(others_key.0.to_string()).await, ["api_key"]);
    assert_eq!(did("scheduler".to_owned()).await, ["internal"]);
}

// PLAN.md 5.4: authentication.

const PASSWORD: &str = "correct horse battery staple";
const OTHER_PASSWORD: &str = "a different long passphrase";

fn username(name: &str) -> Username {
    Username::new(name).expect("a valid username")
}

async fn new_user(service: &Service, actor: &Actor, name: &str) -> UserId {
    service
        .create_user(
            actor,
            &username(name),
            Password::new(PASSWORD),
            &Profile::default(),
        )
        .await
        .expect("makes a user")
}

/// Every row that can authenticate, whole.
async fn credential_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(u)::text FROM service.users u
         UNION ALL SELECT row_to_json(k)::text FROM service.api_keys k
         UNION ALL SELECT row_to_json(s)::text FROM service.sessions s
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

async fn sessions_of(db: &Db, user: UserId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM service.sessions WHERE user_id = $1")
        .bind(user.0)
        .fetch_one(db.pool())
        .await
        .expect("reads")
}

fn is_not_authenticated<T: std::fmt::Debug>(result: Result<T, ServiceError>) -> bool {
    matches!(result, Err(ServiceError::NotAuthenticated))
}

/// The Done check. A session and a key each become their actor, and that actor reaches
/// `Service::disposition`: 5.2's check refuses it until a grant allows it, and 5.3's row names it.
#[tokio::test]
async fn a_session_and_an_api_key_reach_the_service_layer_as_their_actors() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "Alice").await;

    let session = service
        .login("ALICE", Password::new(PASSWORD), None)
        .await
        .expect("logs in, in any case");
    let from_session = service
        .authenticate_session(session.token.expose())
        .await
        .expect("authenticates");
    let expected_user = Actor::User {
        id: alice,
        name: "alice".to_owned(),
    };
    assert_eq!(from_session, expected_user);
    assert_eq!(session.actor, expected_user);

    let owned = service
        .create_api_key(&boss, "triage", Some(alice), &[])
        .await
        .expect("makes a key");
    let from_owned = service
        .authenticate_api_key(owned.token.expose())
        .await
        .expect("authenticates");
    assert_eq!(
        from_owned,
        Actor::ApiKey {
            id: owned.id,
            name: "triage".to_owned(),
            owner: Some(alice),
        }
    );
    let unowned = service
        .create_api_key(&boss, "collector", None, &[])
        .await
        .expect("makes a key");
    let from_unowned = service
        .authenticate_api_key(unowned.token.expose())
        .await
        .expect("authenticates");
    assert_eq!(
        from_unowned,
        Actor::ApiKey {
            id: unowned.id,
            name: "collector".to_owned(),
            owner: None,
        }
    );

    // 5.2: nobody holds anything yet.
    let root = alert(db).await;
    for actor in [&from_session, &from_owned, &from_unowned] {
        assert!(
            matches!(
                service.disposition(actor, root, "IGNORE").await,
                Err(ServiceError::PermissionDenied { .. })
            ),
            "{actor}"
        );
    }

    // Alice's grant reaches her session and not yet her key, which needs its own as well.
    grant(db, &Holder::User(alice), "alert", "write", Effect::Allow).await;
    service
        .disposition(&from_session, root, "FALSE_POSITIVE")
        .await
        .expect("a session dispositions");
    let by_session = last_audit(db).await;
    assert_eq!(by_session.action, "disposition");
    assert_eq!(
        by_session.actor,
        json!({"kind": "user", "id": alice.0, "name": "alice"})
    );
    assert!(matches!(
        service.disposition(&from_owned, root, "IGNORE").await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    grant(db, &Holder::ApiKey(owned.id), "alert", "*", Effect::Allow).await;
    service
        .disposition(&from_owned, root, "IGNORE")
        .await
        .expect("a key dispositions");
    let by_key = last_audit(db).await;
    assert_eq!(
        by_key.actor,
        json!({"kind": "api_key", "id": owned.id.0, "name": "triage", "owner": alice.0})
    );
    assert_eq!(
        row(db, root).await.by,
        Some(json!({"kind": "api_key", "id": owned.id.0, "name": "triage", "owner": alice.0}))
    );

    // And the owner losing the grant stops the key at once, with the same token.
    service
        .revoke(
            &boss,
            &Holder::User(alice),
            &pattern("alert", "write"),
            Effect::Allow,
        )
        .await
        .expect("revokes");
    let still = service
        .authenticate_api_key(owned.token.expose())
        .await
        .expect("still authenticates");
    assert!(matches!(
        service.disposition(&still, root, "IGNORE").await,
        Err(ServiceError::PermissionDenied { .. })
    ));
}

/// The same answer, in every word, whichever check failed.
#[tokio::test]
async fn every_failed_login_gets_the_same_answer() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let off = new_user(&service, &boss, "off").await;
    service
        .set_user_enabled(&boss, off, false)
        .await
        .expect("disables");

    let too_long = format!("{PASSWORD}{}", "x".repeat(2000));
    let attempts = [
        ("alice", "wrong password wrong password"),
        ("alice", ""),
        ("alice", &too_long),
        ("nobody", PASSWORD),
        ("not a valid username!", PASSWORD),
        ("", PASSWORD),
        ("off", PASSWORD),
    ];
    for (name, password) in attempts {
        let error = service
            .login(name, Password::new(password), None)
            .await
            .expect_err("refused");
        assert!(
            matches!(error, ServiceError::NotAuthenticated),
            "{name}: {error}"
        );
        assert_eq!(error.to_string(), "not authenticated", "{name}");
    }
    assert_eq!(sessions_of(db, alice).await, 0);
    assert_eq!(sessions_of(db, off).await, 0);
    assert_eq!(
        audit_rows(db)
            .await
            .iter()
            .filter(|row| row.action == "login")
            .count(),
        0,
        "a failed login has no row, so nobody can fill the table from outside"
    );
}

/// An unknown user costs what a wrong password costs: the median over interleaved attempts, within a
/// factor far wider than noise and far narrower than what leaving out the dummy hash does, which
/// is about a hundred times.
#[tokio::test]
async fn an_unknown_user_takes_as_long_as_a_wrong_password() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    new_user(&service, &boss, "alice").await;
    let off = new_user(&service, &boss, "off").await;
    service
        .set_user_enabled(&boss, off, false)
        .await
        .expect("disables");

    async fn time(service: &Service, name: &str) -> Duration {
        let started = Instant::now();
        assert!(is_not_authenticated(
            service
                .login(name, Password::new("not this one, surely"), None)
                .await
        ));
        started.elapsed()
    }
    // The dummy is made on first use.
    time(&service, "nobody").await;

    let names = ["alice", "nobody", "off", "not a valid username!"];
    let mut timings = vec![Vec::new(); names.len()];
    for _ in 0..15 {
        for (name, times) in names.iter().zip(&mut timings) {
            times.push(time(&service, name).await);
        }
    }
    let medians: Vec<Duration> = timings
        .iter_mut()
        .map(|times| {
            times.sort();
            times[times.len() / 2]
        })
        .collect();
    for (name, median) in names.iter().zip(&medians).skip(1) {
        assert!(
            *median < medians[0] * 4 && medians[0] < *median * 4,
            "{name} took {median:?} and a wrong password {:?}",
            medians[0]
        );
    }
}

/// Stored only as hashes: a token, a secret and a password appear nowhere, and the stored value is what
/// the docs say it is.
#[tokio::test]
async fn credentials_are_stored_only_as_hashes() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let key = service
        .create_api_key(&boss, "triage", Some(alice), &[])
        .await
        .expect("makes a key");

    let rows = credential_rows(db).await.join("\n");
    let audit: String =
        sqlx::query_scalar("SELECT string_agg(row_to_json(a)::text, ' ') FROM service.audit a")
            .fetch_one(db.pool())
            .await
            .expect("reads");
    for token in [session.token.expose(), key.token.expose()] {
        let secret = token.rsplit('_').next().expect("a secret");
        assert_eq!(secret.len(), 64, "256 bits as hex");
        assert!(!rows.contains(secret));
        assert!(!audit.contains(secret));
    }
    assert!(!rows.contains(PASSWORD));
    assert!(!audit.contains(PASSWORD));
    assert!(!audit.contains("argon2"), "not even a password's hash");

    let (hash, stored_session, stored_key): (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT u.password_hash,
                (SELECT secret_hash FROM service.sessions),
                (SELECT secret_hash FROM service.api_keys WHERE name = 'triage')
         FROM service.users u WHERE u.username = 'alice'",
    )
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert!(
        hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "{hash}"
    );
    assert_eq!(
        stored_session,
        Sha256::digest(session.token.expose()).to_vec()
    );
    assert_eq!(stored_key, Sha256::digest(key.token.expose()).to_vec());

    // Two users with one password share no hash.
    let bob = new_user(&service, &boss, "bob").await;
    let bobs: String = sqlx::query_scalar("SELECT password_hash FROM service.users WHERE id = $1")
        .bind(bob.0)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_ne!(hash, bobs);

    // The database refuses a password that isn't a hash, whatever writes it.
    let plaintext = sqlx::query("UPDATE service.users SET password_hash = $1 WHERE id = $2")
        .bind(PASSWORD)
        .bind(alice.0)
        .execute(db.pool())
        .await
        .expect_err("refused");
    assert!(
        plaintext.to_string().contains("password_hash"),
        "{plaintext}"
    );

    // Neither is printable by accident.
    assert_eq!(
        format!("{:?}", Password::new(PASSWORD)),
        "Password([hidden])"
    );
    assert!(!format!("{session:?}").contains(session.token.expose()));
    assert!(!format!("{key:?}").contains(key.token.expose()));
}

/// A wrong secret fails wherever it's wrong, and the right secret under another kind or id does too.
#[tokio::test]
async fn a_token_must_match_in_every_byte() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let key = service
        .create_api_key(&boss, "triage", None, &[])
        .await
        .expect("makes a key");
    let other = service
        .create_api_key(&boss, "other", None, &[])
        .await
        .expect("makes a key");

    fn flip(token: &str, index: usize) -> String {
        let mut bytes = token.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("ASCII")
    }
    let secret_at = key.token.expose().rfind('_').expect("a secret") + 1;
    let length = key.token.expose().len();
    for index in [
        secret_at,
        secret_at + 1,
        secret_at + 31,
        length - 2,
        length - 1,
    ] {
        assert!(
            is_not_authenticated(
                service
                    .authenticate_api_key(&flip(key.token.expose(), index))
                    .await
            ),
            "byte {index} of a key"
        );
        assert!(
            is_not_authenticated(
                service
                    .authenticate_session(&flip(session.token.expose(), index))
                    .await
            ),
            "byte {index} of a session"
        );
    }

    let (key_kind, session_kind) = (key.token.expose(), session.token.expose());
    let as_session = key_kind.replacen("ace4k", "ace4s", 1);
    let as_key = session_kind.replacen("ace4s", "ace4k", 1);
    let other_id = format!(
        "ace4k_{}_{}",
        other.id.0.simple(),
        key_kind.rsplit('_').next().expect("a secret")
    );
    for (what, presented) in [
        ("a key as a session", key_kind),
        ("a key's kind changed", as_session.as_str()),
        ("empty", ""),
        ("no secret", "ace4s_0_"),
        ("cut short", &session_kind[..session_kind.len() - 1]),
    ] {
        assert!(
            is_not_authenticated(service.authenticate_session(presented).await),
            "{what}"
        );
    }
    for (what, presented) in [
        ("a session as a key", session_kind),
        ("a session's kind changed", as_key.as_str()),
        ("another key's id", other_id.as_str()),
        ("empty", ""),
    ] {
        assert!(
            is_not_authenticated(service.authenticate_api_key(presented).await),
            "{what}"
        );
    }
    // A secret whose hash starts, or ends, with the same two bytes as the real one's. Comparing only
    // part of the hash would let one through, and changing a byte above wouldn't show that.
    let stored = Sha256::digest(key_kind.as_bytes());
    let prefix = &key_kind[..key_kind.len() - 64];
    let near_miss = |same: &dyn Fn(&[u8]) -> bool| {
        (0_u64..)
            .map(|n| format!("{prefix}{n:064x}"))
            .find(|candidate| {
                candidate != key_kind && same(Sha256::digest(candidate.as_bytes()).as_slice())
            })
            .expect("one exists")
    };
    let starts = near_miss(&|hash| hash[..2] == stored[..2]);
    let ends = near_miss(&|hash| hash[30..] == stored[30..]);
    for (what, presented) in [("starts", &starts), ("ends", &ends)] {
        assert!(
            is_not_authenticated(service.authenticate_api_key(presented).await),
            "a hash that {what} the same"
        );
    }

    // The originals still work, so the refusals above weren't for some other reason.
    service
        .authenticate_api_key(key_kind)
        .await
        .expect("authenticates");
    service
        .authenticate_session(session_kind)
        .await
        .expect("authenticates");
}

/// A session ends at its time, as the database's clock has it, and a login clears out the dead ones.
#[tokio::test]
async fn a_session_expires() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let left = session.expires_at - chrono::Utc::now();
    assert!(
        (left.num_seconds() - i64::from(SESSION_LIFETIME_SECONDS)).abs() < 60,
        "{left}"
    );
    service
        .authenticate_session(session.token.expose())
        .await
        .expect("authenticates");

    sqlx::query("UPDATE service.sessions SET expires_at = now() - interval '1 second'")
        .execute(db.pool())
        .await
        .expect("ages it");
    assert!(is_not_authenticated(
        service.authenticate_session(session.token.expose()).await
    ));
    assert!(
        !service
            .logout(session.token.expose())
            .await
            .expect("logs out"),
        "an expired session has nothing to end"
    );
    assert_eq!(sessions_of(db, alice).await, 1, "the row is still there");

    service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    assert_eq!(sessions_of(db, alice).await, 1, "the dead one went");
}

/// A login always ends in a new id, and stops the one it came with. Sessions don't otherwise affect
/// each other, as with two browsers.
#[tokio::test]
async fn a_login_rotates_and_a_logout_revokes() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let login = |previous: Option<String>| {
        let service = service.clone();
        async move {
            service
                .login("alice", Password::new(PASSWORD), previous.as_deref())
                .await
                .expect("logs in")
        }
    };

    let first = login(None).await;
    let other_browser = login(None).await;
    let second = login(Some(first.token.expose().to_owned())).await;
    assert_ne!(first.token.expose(), second.token.expose());
    assert!(is_not_authenticated(
        service.authenticate_session(first.token.expose()).await
    ));
    service
        .authenticate_session(other_browser.token.expose())
        .await
        .expect("still live");

    // A cookie with the right id and a wrong secret ends nothing.
    let forged = format!(
        "{}{}",
        &second.token.expose()[..second.token.expose().len() - 1],
        if second.token.expose().ends_with('0') {
            '1'
        } else {
            '0'
        }
    );
    login(Some(forged)).await;
    service
        .authenticate_session(second.token.expose())
        .await
        .expect("still live");

    assert!(
        service
            .logout(second.token.expose())
            .await
            .expect("logs out")
    );
    assert!(is_not_authenticated(
        service.authenticate_session(second.token.expose()).await
    ));
    assert!(
        !service
            .logout(second.token.expose())
            .await
            .expect("no error"),
        "a second logout is nothing"
    );
    assert!(!service.logout("rubbish").await.expect("no error"));
    assert_eq!(sessions_of(db, alice).await, 2);
}

/// A disabled user gets no actor from anything, their live sessions die and stay dead, and their keys
/// come back only with them. A key with no owner doesn't care.
#[tokio::test]
async fn a_disabled_user_has_no_actor_and_a_revoked_key_has_none() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let owned = service
        .create_api_key(&boss, "owned", Some(alice), &[])
        .await
        .expect("makes a key");
    let unowned = service
        .create_api_key(&boss, "unowned", None, &[])
        .await
        .expect("makes a key");

    assert!(
        service
            .set_user_enabled(&boss, alice, false)
            .await
            .expect("disables")
    );
    assert!(
        !service
            .set_user_enabled(&boss, alice, false)
            .await
            .expect("no-op"),
        "already off"
    );
    assert_eq!(sessions_of(db, alice).await, 0);
    assert!(is_not_authenticated(
        service.authenticate_session(session.token.expose()).await
    ));
    assert!(is_not_authenticated(
        service.authenticate_api_key(owned.token.expose()).await
    ));
    assert!(is_not_authenticated(
        service.login("alice", Password::new(PASSWORD), None).await
    ));
    service
        .authenticate_api_key(unowned.token.expose())
        .await
        .expect("no owner to be disabled");

    assert!(
        service
            .set_user_enabled(&boss, alice, true)
            .await
            .expect("enables")
    );
    assert!(
        is_not_authenticated(service.authenticate_session(session.token.expose()).await),
        "enabling doesn't bring a session back"
    );
    service
        .authenticate_api_key(owned.token.expose())
        .await
        .expect("the key is back with its owner");
    service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in again");

    // `enabled` is what's checked at each request, whatever turned it off.
    let live = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    sqlx::query("UPDATE service.users SET enabled = false WHERE id = $1")
        .bind(alice.0)
        .execute(db.pool())
        .await
        .expect("disables around the service");
    assert!(is_not_authenticated(
        service.authenticate_session(live.token.expose()).await
    ));
    sqlx::query("UPDATE service.users SET enabled = true WHERE id = $1")
        .bind(alice.0)
        .execute(db.pool())
        .await
        .expect("enables around the service");

    // Revoked: the token is dead, and so are its grants.
    grant(
        db,
        &Holder::ApiKey(owned.id),
        "alert",
        "write",
        Effect::Allow,
    )
    .await;
    assert!(
        service
            .revoke_api_key(&boss, owned.id)
            .await
            .expect("revokes")
    );
    assert!(
        !service
            .revoke_api_key(&boss, owned.id)
            .await
            .expect("no-op"),
        "already gone"
    );
    assert!(is_not_authenticated(
        service.authenticate_api_key(owned.token.expose()).await
    ));
    let grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM service.permissions WHERE api_key_id = $1")
            .bind(owned.id.0)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(grants, 0);
}

/// A login racing a disable, many times: however they fall, no session outlives the disable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_session_survives_a_disable_it_raced() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    for _ in 0..10 {
        let login = {
            let service = service.clone();
            tokio::spawn(async move { service.login("alice", Password::new(PASSWORD), None).await })
        };
        let disable = {
            let (service, boss) = (service.clone(), boss.clone());
            tokio::spawn(async move { service.set_user_enabled(&boss, alice, false).await })
        };
        let login = login.await.expect("joins");
        disable.await.expect("joins").expect("disables");
        if let Ok(session) = &login {
            assert!(is_not_authenticated(
                service.authenticate_session(session.token.expose()).await
            ));
        }
        assert_eq!(sessions_of(db, alice).await, 0);
        service
            .set_user_enabled(&boss, alice, true)
            .await
            .expect("enables");
    }
}

#[tokio::test]
async fn a_user_changes_their_own_password_and_only_their_own() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let owned = service
        .create_api_key(&boss, "owned", Some(alice), &[])
        .await
        .expect("makes a key");
    let key_actor = service
        .authenticate_api_key(owned.token.expose())
        .await
        .expect("authenticates");

    // No grants are needed. A key can't, whatever it holds: a leak mustn't become an account.
    grant(db, &Holder::ApiKey(owned.id), "*", "*", Effect::Allow).await;
    let refused = service
        .change_own_password(
            &key_actor,
            Password::new(PASSWORD),
            Password::new(OTHER_PASSWORD),
        )
        .await
        .expect_err("refused");
    assert!(
        matches!(&refused, ServiceError::PermissionDenied { permission, .. } if *permission == USER_SELF),
        "{refused}"
    );

    assert!(is_not_authenticated(
        service
            .change_own_password(
                &session.actor,
                Password::new("not the right one"),
                Password::new(OTHER_PASSWORD),
            )
            .await
    ));
    assert!(matches!(
        service
            .change_own_password(
                &session.actor,
                Password::new(PASSWORD),
                Password::new("short"),
            )
            .await,
        Err(ServiceError::WeakPassword)
    ));
    service
        .authenticate_session(session.token.expose())
        .await
        .expect("nothing changed yet");

    service
        .change_own_password(
            &session.actor,
            Password::new(PASSWORD),
            Password::new(OTHER_PASSWORD),
        )
        .await
        .expect("changes");
    assert!(is_not_authenticated(
        service.authenticate_session(session.token.expose()).await
    ));
    assert!(is_not_authenticated(
        service.login("alice", Password::new(PASSWORD), None).await
    ));
    service
        .login("alice", Password::new(OTHER_PASSWORD), None)
        .await
        .expect("the new one works");
    service
        .authenticate_api_key(owned.token.expose())
        .await
        .expect("a key survives its owner's password change, as in ace3");

    // An admin's reset needs no old password and needs user:write, and ends sessions.
    assert!(matches!(
        service
            .reset_password(&session.actor, alice, Password::new(PASSWORD))
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    service
        .reset_password(&boss, alice, Password::new(PASSWORD))
        .await
        .expect("resets");
    assert_eq!(sessions_of(db, alice).await, 0);
    service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    assert!(matches!(
        service
            .reset_password(&boss, UserId(Uuid::from_u128(77)), Password::new(PASSWORD))
            .await,
        Err(ServiceError::NoUser(_))
    ));
}

/// Writes on users and keys need `user:write`, and refuse bad values before anything is stored.
#[tokio::test]
async fn account_writes_check_their_permission_and_their_values() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let nobody = session.actor.clone();
    let before = credential_rows(db).await;
    let audit_before = audit_rows(db).await;

    let refusals = [
        service
            .create_user(
                &nobody,
                &username("bob"),
                Password::new(PASSWORD),
                &Profile::default(),
            )
            .await
            .map(|_| ()),
        service
            .set_user_enabled(&nobody, alice, false)
            .await
            .map(|_| ()),
        service
            .create_api_key(&nobody, "mine", None, &[])
            .await
            .map(|_| ()),
        service
            .revoke_api_key(&nobody, ApiKeyId(Uuid::from_u128(5)))
            .await
            .map(|_| ()),
    ];
    for refusal in refusals {
        assert!(
            matches!(
                &refusal,
                Err(ServiceError::PermissionDenied { permission, .. }) if *permission == USER_WRITE
            ),
            "{refusal:?}"
        );
    }

    assert!(matches!(
        service
            .create_user(
                &boss,
                &username("ALICE"),
                Password::new(PASSWORD),
                &Profile::default()
            )
            .await,
        Err(ServiceError::UsernameTaken)
    ));
    for weak in [
        "",
        "short",
        &"x".repeat(MIN_PASSWORD_CHARS - 1),
        &"x".repeat(1025),
    ] {
        assert!(
            matches!(
                service
                    .create_user(
                        &boss,
                        &username("carol"),
                        Password::new(weak),
                        &Profile::default()
                    )
                    .await,
                Err(ServiceError::WeakPassword)
            ),
            "{} bytes",
            weak.len()
        );
    }
    for name in ["", "   ", &"x".repeat(256)] {
        assert!(matches!(
            service.create_api_key(&boss, name, None, &[]).await,
            Err(ServiceError::InvalidKeyName)
        ));
    }
    assert!(matches!(
        service
            .create_api_key(&boss, "orphan", Some(UserId(Uuid::from_u128(77))), &[])
            .await,
        Err(ServiceError::NoUser(_))
    ));
    assert!(matches!(
        service
            .set_user_enabled(&boss, UserId(Uuid::from_u128(77)), false)
            .await,
        Err(ServiceError::NoUser(_))
    ));
    // As in ace3, nobody disables themselves, or through their own key.
    let boss_id = match &boss {
        Actor::User { id, .. } => *id,
        _ => unreachable!("an admin is a user"),
    };
    assert!(matches!(
        service.set_user_enabled(&boss, boss_id, false).await,
        Err(ServiceError::CantDisableYourself)
    ));
    let own_key = Actor::ApiKey {
        id: ApiKeyId(Uuid::from_u128(0xAE)),
        name: "boss's".to_owned(),
        owner: Some(boss_id),
    };
    grant(
        db,
        &Holder::ApiKey(ApiKeyId(Uuid::from_u128(0xAE))),
        "*",
        "*",
        Effect::Allow,
    )
    .await;
    assert!(matches!(
        service.set_user_enabled(&own_key, boss_id, false).await,
        Err(ServiceError::CantDisableYourself)
    ));

    assert_eq!(
        credential_rows(db)
            .await
            .iter()
            .filter(|row| !row.contains("triage"))
            .cloned()
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(
        audit_rows(db)
            .await
            .into_iter()
            .filter(|row| row.action != "grant")
            .count(),
        audit_before.len()
            - audit_before
                .iter()
                .filter(|row| row.action == "grant")
                .count()
    );
}

/// A change to grants or groups that would leave its actor without `user:write` is refused and changes
/// nothing, whichever way it would go; one that leaves them holding it some other way goes ahead, and
/// someone else may still take it from them.
#[tokio::test]
async fn nobody_takes_their_own_user_write() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice_id = new_user(&service, &boss, "alice").await;
    let alice = user(alice_id);
    let admins = service.create_group(&boss, "admins").await.expect("makes");
    service
        .add_group_member(&boss, admins, alice_id)
        .await
        .expect("adds");
    service
        .grant(
            &boss,
            &Holder::Group(admins),
            &pattern("user", "*"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    let audit = audit_rows(db).await.len();
    let refusals = [
        service
            .remove_group_member(&alice, admins, alice_id)
            .await
            .map(|_| ()),
        service.delete_group(&alice, admins).await.map(|_| ()),
        service
            .grant(
                &alice,
                &Holder::User(alice_id),
                &pattern("user", "write"),
                Effect::Deny,
            )
            .await
            .map(|_| ()),
        service
            .revoke(
                &alice,
                &Holder::Group(admins),
                &pattern("user", "*"),
                Effect::Allow,
            )
            .await
            .map(|_| ()),
    ];
    for refusal in refusals {
        assert!(
            matches!(refusal, Err(ServiceError::CantDropYourOwnUserWrite)),
            "{refusal:?}"
        );
    }
    assert_eq!(audit_rows(db).await.len(), audit, "nothing changed");
    assert!(service.allowed(&alice, &USER_WRITE).await.expect("checks"));

    // a change that leaves her holding it goes ahead
    service
        .grant(
            &alice,
            &Holder::User(alice_id),
            &pattern("user", "write"),
            Effect::Allow,
        )
        .await
        .expect("grants herself what she holds");
    assert!(
        service
            .remove_group_member(&alice, admins, alice_id)
            .await
            .expect("leaves")
    );
    // and someone else may take it from her
    assert!(
        service
            .revoke(
                &boss,
                &Holder::User(alice_id),
                &pattern("user", "write"),
                Effect::Allow
            )
            .await
            .expect("revokes")
    );
    assert!(!service.allowed(&alice, &USER_WRITE).await.expect("checks"));
}

#[test]
fn a_username_is_one_value_in_any_case() {
    assert_eq!(
        Username::new("Alice.B+1@Example.COM")
            .expect("valid")
            .as_str(),
        "alice.b+1@example.com"
    );
    let too_long = "x".repeat(65);
    for bad in ["", " ", "a b", "al\u{212A}ce", "a\nb", &too_long, "a:b"] {
        let error = Username::new(bad).expect_err("refused");
        assert!(
            bad.trim().is_empty() || !error.to_string().contains(bad),
            "an error doesn't repeat what was typed"
        );
    }
}

/// A grant goes with its holder. What records an actor stays: a row's `created_by`, a root's
/// `dispositioned_by` and the audit table, none of which has a foreign key.
#[tokio::test]
async fn deleting_a_user_removes_what_they_could_do_and_not_what_they_did() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let alice = new_user(&service, &boss, "alice").await;
    let bob = new_user(&service, &boss, "bob").await;
    let key = service
        .create_api_key(&boss, "alices", Some(alice), &[])
        .await
        .expect("makes a key");
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let member_of = group_of(db, Uuid::from_u128(40), alice).await;
    for holder in [
        Holder::User(alice),
        Holder::ApiKey(key.id),
        member_of.clone(),
    ] {
        grant(db, &holder, "*", "*", Effect::Allow).await;
    }
    let root = alert(db).await;
    service
        .disposition(&session.actor, root, "IGNORE")
        .await
        .expect("dispositions");
    // Alice grants something to Bob, so a row of someone else's names her as its maker.
    service
        .grant(
            &session.actor,
            &Holder::User(bob),
            &pattern("alert", "read"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    let audit_before = audit_rows(db).await;

    sqlx::query("DELETE FROM service.users WHERE id = $1")
        .bind(alice.0)
        .execute(db.pool())
        .await
        .expect("deletes");

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM service.permissions WHERE user_id = $1 OR api_key_id = $2),
                (SELECT count(*) FROM service.group_members WHERE user_id = $1),
                (SELECT count(*) FROM service.api_keys WHERE id = $2),
                (SELECT count(*) FROM service.sessions WHERE user_id = $1)",
    )
    .bind(alice.0)
    .bind(key.id.0)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(counts, (0, 0, 0, 0));

    let by = json!({"kind": "user", "id": alice.0, "name": "alice"});
    assert_eq!(row(db, root).await.by, Some(by.clone()));
    let created_by: Value =
        sqlx::query_scalar("SELECT created_by::jsonb FROM service.permissions WHERE user_id = $1")
            .bind(bob.0)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(created_by, by);
    assert_eq!(audit_rows(db).await, audit_before);

    // The group's own grant stays: only the membership was hers.
    assert!(matches!(member_of, Holder::Group(_)));
    let group_grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM service.permissions WHERE group_id = $1")
            .bind(Uuid::from_u128(40))
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(group_grants, 1);

    // An actor kept past that point holds nothing.
    assert!(
        !service
            .allowed(&session.actor, &ALERT_WRITE)
            .await
            .expect("checks")
    );
}

/// The first admin: no account exists until an operator makes one, it holds everything, and a second
/// needs forcing. The command itself is in `ace-site-example`'s test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_user_is_an_admin_and_a_second_needs_forcing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);

    assert_eq!(
        credential_rows(db).await,
        Vec::<String>::new(),
        "no default account"
    );
    let bootstrap = component("bootstrap");
    assert!(
        service
            .allowed(&bootstrap, &USER_WRITE)
            .await
            .expect("checks")
    );
    assert!(
        !service
            .allowed(&bootstrap, &ALERT_WRITE)
            .await
            .expect("checks"),
        "it can make accounts and nothing else"
    );

    // Two at once: one wins.
    let attempts: Vec<_> = ["one", "two", "three", "four"]
        .into_iter()
        .map(|name| {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .create_first_user(&username(name), Password::new(PASSWORD), false)
                    .await
            })
        })
        .collect();
    let mut winners = Vec::new();
    for attempt in attempts {
        match attempt.await.expect("joins") {
            Ok(id) => winners.push(id),
            Err(ServiceError::UsersExist) => {}
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(winners.len(), 1);
    let users_before = credential_rows(db).await;

    assert!(matches!(
        service
            .create_first_user(&username("another"), Password::new(PASSWORD), false)
            .await,
        Err(ServiceError::UsersExist)
    ));
    assert_eq!(credential_rows(db).await, users_before);

    let first = sqlx::query_scalar::<_, String>("SELECT username::text FROM service.users")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    let session = service
        .login(&first, Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    for permission in [&ALERT_WRITE, &USER_WRITE, &name("anything", "at-all")] {
        assert!(
            service
                .allowed(&session.actor, permission)
                .await
                .expect("checks"),
            "{permission}"
        );
    }
    let created_by: Value =
        sqlx::query_scalar("SELECT created_by::jsonb FROM service.permissions WHERE user_id = $1")
            .bind(winners[0].0)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(created_by, json!({"kind": "internal", "id": "bootstrap"}));

    let forced = service
        .create_first_user(&username("rescue"), Password::new(PASSWORD), true)
        .await
        .expect("forced");
    assert_ne!(forced, winners[0]);
    assert!(matches!(
        service
            .create_first_user(&username("rescue"), Password::new(PASSWORD), true)
            .await,
        Err(ServiceError::UsernameTaken)
    ));
}

/// What a browser gets told to keep.
#[tokio::test]
async fn the_session_cookie_has_its_attributes() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    new_user(&service, &admin(db).await, "alice").await;
    let session: NewSession = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let token = session.token.expose();

    let tls = SessionCookie::new(Transport::Tls);
    assert_eq!(
        tls.set(&session),
        format!(
            "__Host-ace4_session={token}; Max-Age={SESSION_LIFETIME_SECONDS}; \
             Path=/; HttpOnly; SameSite=Lax; Secure"
        )
    );
    assert_eq!(
        tls.clear(),
        "__Host-ace4_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure"
    );
    let plain = SessionCookie::new(Transport::Plain);
    assert_eq!(
        plain.set(&session),
        format!(
            "ace4_session={token}; Max-Age={SESSION_LIFETIME_SECONDS}; Path=/; HttpOnly; SameSite=Lax"
        )
    );
    assert_eq!(
        plain.clear(),
        "ace4_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
    );

    let header = format!("session=ace3-flask-cookie; ace4_session={token}; other=1");
    assert_eq!(plain.read(&header), Some(token));
    assert_eq!(tls.read(&header), None, "not the name a TLS site uses");
    assert_eq!(plain.read("session=ace3-flask-cookie"), None);
}

fn request<'a>(method: &'a str, cookie: Option<&'a str>) -> RequestParts<'a> {
    RequestParts {
        transport: Transport::Plain,
        method,
        authorization: None,
        cookie,
        sec_fetch_site: None,
        origin: None,
        host: Some("ace.example.com:7443"),
    }
}

/// ace3's `_reject_cross_site_cookie_write`, plus the port, plus the extractor that applies it.
#[tokio::test]
async fn a_request_authenticates_by_its_key_or_its_same_origin_session() {
    let safe = request("GET", None);
    assert!(safe.same_origin());
    assert!(
        RequestParts {
            method: "head",
            ..safe
        }
        .same_origin()
    );
    assert!(
        RequestParts {
            method: "OPTIONS",
            ..safe
        }
        .same_origin()
    );

    let write = request("POST", None);
    assert!(!write.same_origin(), "says nothing: not a browser");
    for (site, passes) in [
        ("same-origin", true),
        ("none", true),
        ("same-site", false),
        ("cross-site", false),
        ("nonsense", false),
    ] {
        assert_eq!(
            RequestParts {
                sec_fetch_site: Some(site),
                ..write
            }
            .same_origin(),
            passes,
            "{site}"
        );
    }
    assert!(
        !RequestParts {
            sec_fetch_site: Some("cross-site"),
            origin: Some("https://ace.example.com:7443"),
            ..write
        }
        .same_origin(),
        "Sec-Fetch-Site is what's believed when it's there"
    );
    for (origin, passes) in [
        ("https://ace.example.com:7443", true),
        ("https://ACE.example.com:7443", true),
        ("https://ace.example.com:5000", false),
        ("https://ace.example.com", false),
        ("https://evil.example.com:7443", false),
        ("https://ace.example.com:7443.evil.example", false),
        ("null", false),
    ] {
        assert_eq!(
            RequestParts {
                origin: Some(origin),
                ..write
            }
            .same_origin(),
            passes,
            "{origin}"
        );
    }
    assert!(
        !RequestParts {
            origin: Some("https://x"),
            host: None,
            ..write
        }
        .same_origin()
    );

    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    new_user(&service, &boss, "alice").await;
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let key = service
        .create_api_key(&boss, "triage", None, &[])
        .await
        .expect("makes a key");
    let key_actor = service
        .authenticate_api_key(key.token.expose())
        .await
        .expect("authenticates");
    let cookie = format!("ace4_session={}", session.token.expose());

    let good_read = request("GET", Some(&cookie));
    assert_eq!(
        service
            .authenticate_request(&good_read)
            .await
            .expect("a read"),
        session.actor
    );
    let good_write = RequestParts {
        sec_fetch_site: Some("same-origin"),
        ..request("POST", Some(&cookie))
    };
    assert_eq!(
        service
            .authenticate_request(&good_write)
            .await
            .expect("a write"),
        session.actor
    );
    let cross_site = RequestParts {
        sec_fetch_site: Some("cross-site"),
        ..good_write
    };
    assert!(matches!(
        service.authenticate_request(&cross_site).await,
        Err(ServiceError::CrossSiteRequest)
    ));
    let bare = request("POST", Some(&cookie));
    assert!(matches!(
        service.authenticate_request(&bare).await,
        Err(ServiceError::CrossSiteRequest)
    ));
    assert!(is_not_authenticated(
        service.authenticate_request(&request("GET", None)).await
    ));

    // A bearer token needs no CSRF check: no other site's page can make a browser send one.
    let header = format!("bearer {}", key.token.expose());
    let by_key = RequestParts {
        authorization: Some(&header),
        ..request("POST", None)
    };
    assert_eq!(
        service.authenticate_request(&by_key).await.expect("a key"),
        key_actor
    );
    // A bad key isn't rescued by a good cookie.
    for authorization in ["Bearer rubbish", "Basic abc", "Bearer", "rubbish"] {
        let bad = RequestParts {
            authorization: Some(authorization),
            sec_fetch_site: Some("same-origin"),
            ..request("POST", Some(&cookie))
        };
        assert!(
            is_not_authenticated(service.authenticate_request(&bad).await),
            "{authorization}"
        );
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("a lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
    type Writer = Captured;

    fn make_writer(&self) -> Captured {
        self.clone()
    }
}

/// Everything at TRACE, including sqlx's statements, through every path a credential takes, with no
/// credential in it. The subscriber is global, because with a thread's own subscriber another test's
/// thread can reach a log line first and leave it switched off for good: `tracing` asks only the thread
/// that got there when one subscriber exists. So it also hears whichever other tests are running, which
/// use the same password.
#[tokio::test]
async fn no_credential_reaches_the_log() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;

    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only global subscriber here");

    let alice = new_user(&service, &boss, "alice").await;
    let in_the_wrong_box = "my-password-in-the-username-box";
    let wrong = "a-wrong-password-for-alice";
    assert!(is_not_authenticated(
        service.login("alice", Password::new(wrong), None).await
    ));
    assert!(is_not_authenticated(
        service
            .login(in_the_wrong_box, Password::new(wrong), None)
            .await
    ));
    let session = service
        .login("alice", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let actor = service
        .authenticate_session(session.token.expose())
        .await
        .expect("authenticates");
    let key = service
        .create_api_key(&boss, "triage", Some(alice), &[])
        .await
        .expect("makes a key");
    service
        .authenticate_api_key(key.token.expose())
        .await
        .expect("authenticates");
    assert!(is_not_authenticated(
        service
            .authenticate_api_key(&format!("{}x", key.token.expose()))
            .await
    ));
    let second = service
        .login(
            "alice",
            Password::new(PASSWORD),
            Some(session.token.expose()),
        )
        .await
        .expect("logs in");
    service
        .logout(second.token.expose())
        .await
        .expect("logs out");
    service
        .change_own_password(
            &actor,
            Password::new(PASSWORD),
            Password::new(OTHER_PASSWORD),
        )
        .await
        .expect("changes");
    service
        .reset_password(&boss, alice, Password::new("a third long passphrase"))
        .await
        .expect("resets");
    let first = service
        .create_first_user(
            &username("rescue"),
            Password::new("a fourth long passphrase"),
            true,
        )
        .await
        .expect("forced");
    let cookie = format!("ace4_session={}", session.token.expose());
    assert!(is_not_authenticated(
        service
            .authenticate_request(&request("POST", Some(&cookie)))
            .await
    ));

    let log = String::from_utf8(captured.0.lock().expect("a lock").clone()).expect("text");

    // It really was listening.
    assert!(log.contains("a login failed"), "{log}");
    assert!(
        log.contains("a login failed for a name that isn't a user's"),
        "{log}"
    );
    assert!(log.contains(&alice.0.to_string()), "{log}");
    assert!(log.contains(&first.0.to_string()), "{log}");
    assert!(log.contains("AUDIT"), "{log}");
    assert!(log.contains("service.sessions"), "sqlx's statements: {log}");

    let (session_secret, key_secret) = (
        session.token.expose().rsplit('_').next().expect("a secret"),
        key.token.expose().rsplit('_').next().expect("a secret"),
    );
    let (second_secret, stored) = (
        second.token.expose().rsplit('_').next().expect("a secret"),
        hex::encode(Sha256::digest(key.token.expose())),
    );
    for secret in [
        PASSWORD,
        OTHER_PASSWORD,
        "a third long passphrase",
        "a fourth long passphrase",
        wrong,
        in_the_wrong_box,
        session_secret,
        key_secret,
        second_secret,
        &stored,
        // a real hash: this test binary's seeded users have '$argon2id$none'
        "$argon2id$v=",
    ] {
        assert!(!log.contains(secret), "{secret} is in the log");
    }
}

async fn create_first_user_records_its_row() -> String {
    // Its own database, since it needs to find no users.
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let id = service(db)
        .create_first_user(&username("root"), Password::new(PASSWORD), false)
        .await
        .expect("makes it");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "internal", "id": "bootstrap"}),
            action: "create_first_user".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: None,
            after: Some(
                json!({"username": "root", "enabled": true, "timezone": "UTC", "queue": "default"})
            ),
            details: json!({"grants": "*:*", "forced": false}),
        }
    );
    row.action
}

fn boss_json() -> Value {
    json!({"kind": "user", "id": Uuid::from_u128(0xAD), "name": "alice"})
}

async fn create_user_records_its_row(db: &Db) -> String {
    let service = service(db);
    let profile = Profile {
        display_name: Some(" Audited User ".to_owned()),
        email: Some("audited@example.com".to_owned()),
        timezone: Some("Europe/London".to_owned()),
        queue: Some(" triage ".to_owned()),
    };
    let id = service
        .create_user(
            &admin(db).await,
            &username("audited-user"),
            Password::new(PASSWORD),
            &profile,
        )
        .await
        .expect("makes a user");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_user".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: None,
            after: Some(json!({
                "username": "audited-user",
                "enabled": true,
                "display_name": "Audited User",
                "email": "audited@example.com",
                "timezone": "Europe/London",
                "queue": "triage",
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn set_user_enabled_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let id = new_user(&service, &boss, "audited-disable").await;
    service
        .login("audited-disable", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    service
        .set_user_enabled(&boss, id, false)
        .await
        .expect("disables");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "set_user_enabled".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: Some(json!({"enabled": true})),
            after: Some(json!({"enabled": false})),
            details: json!({"sessions_ended": 1}),
        }
    );
    let count = audit_rows(db).await.len();
    service
        .set_user_enabled(&boss, id, false)
        .await
        .expect("no-op");
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn reset_password_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let id = new_user(&service, &boss, "audited-reset").await;
    service
        .reset_password(&boss, id, Password::new(OTHER_PASSWORD))
        .await
        .expect("resets");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "reset_password".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: None,
            after: Some(json!({"password_changed": true})),
            details: json!({"sessions_ended": 0}),
        }
    );
    row.action
}

async fn change_own_password_records_its_row(db: &Db) -> String {
    let service = service(db);
    let id = new_user(&service, &admin(db).await, "audited-change").await;
    let session = service
        .login("audited-change", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    service
        .change_own_password(
            &session.actor,
            Password::new(PASSWORD),
            Password::new(OTHER_PASSWORD),
        )
        .await
        .expect("changes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "user", "id": id.0, "name": "audited-change"}),
            action: "change_own_password".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: None,
            after: Some(json!({"password_changed": true})),
            details: json!({"sessions_ended": 1}),
        }
    );
    row.action
}

async fn create_api_key_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let owner = new_user(&service, &boss, "audited-owner").await;
    let key = service
        .create_api_key(
            &boss,
            "  audited key  ",
            Some(owner),
            &[
                pattern("alert", "read"),
                pattern("Alert", "READ"),
                pattern("observable", "*"),
            ],
        )
        .await
        .expect("makes a key");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_api_key".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: None,
            after: Some(json!({
                "name": "audited key",
                "owner": owner.0,
                "scope": ["alert:read", "observable:*"],
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn revoke_api_key_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let key = service
        .create_api_key(&boss, "audited revoke", None, &[pattern("alert", "read")])
        .await
        .expect("makes a key");
    service
        .revoke_api_key(&boss, key.id)
        .await
        .expect("revokes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "revoke_api_key".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: Some(json!({"name": "audited revoke", "owner": null, "scope": ["alert:read"]})),
            after: None,
            details: json!({}),
        }
    );
    row.action
}

/// The session's id out of its token: it's what a row names, and it can't authenticate alone.
fn session_id(session: &NewSession) -> String {
    let id = session.token.expose().split('_').nth(1).expect("an id");
    Uuid::try_parse(id).expect("a uuid").to_string()
}

async fn login_records_its_row(db: &Db) -> String {
    let service = service(db);
    let id = new_user(&service, &admin(db).await, "audited-login").await;
    let first = service
        .login("audited-login", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    let second = service
        .login(
            "audited-login",
            Password::new(PASSWORD),
            Some(first.token.expose()),
        )
        .await
        .expect("logs in");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "user", "id": id.0, "name": "audited-login"}),
            action: "login".to_owned(),
            target: ("session".to_owned(), session_id(&second)),
            before: None,
            after: Some(json!({
                "user": id.0,
                "expires_at": second.expires_at,
            })),
            details: json!({"replaced_session": session_id(&first)}),
        }
    );
    row.action
}

async fn logout_records_its_row(db: &Db) -> String {
    let service = service(db);
    let id = new_user(&service, &admin(db).await, "audited-logout").await;
    let session = service
        .login("audited-logout", Password::new(PASSWORD), None)
        .await
        .expect("logs in");
    service
        .logout(session.token.expose())
        .await
        .expect("logs out");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "user", "id": id.0, "name": "audited-logout"}),
            action: "logout".to_owned(),
            target: ("session".to_owned(), session_id(&session)),
            before: Some(json!({
                "user": id.0,
                "expires_at": session.expires_at,
            })),
            after: None,
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    service.logout(session.token.expose()).await.expect("no-op");
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

/// `write_own` skips the permission check, so its callers are a short list, on purpose.
#[test]
fn only_a_person_s_own_writes_skip_the_permission_check() {
    let source = |file: &str| {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file))
            .expect("reads the source")
    };
    let calls = regex::Regex::new(r#"\.write_own\(\s*&?\w+\s*,\s*"(\w+)""#).expect("a pattern");
    let (auth, users, preferences) = (
        source("auth.rs"),
        source("users.rs"),
        source("preferences.rs"),
    );
    let found: BTreeSet<&str> = calls
        .captures_iter(&auth)
        .chain(calls.captures_iter(&users))
        .chain(calls.captures_iter(&preferences))
        .map(|call| call.get(1).expect("a name").as_str())
        .collect();
    assert_eq!(
        found,
        BTreeSet::from([
            "change_own_password",
            "login",
            "logout",
            "reset_preference",
            "set_preference",
            "update_own_profile"
        ])
    );
    assert!(!source("lib.rs").contains(".write_own("));
    assert!(!source("permission.rs").contains(".write_own("));
}

// PLAN.md 5.6: the users router's reads and writes.

fn display_name(name: &str) -> Profile {
    Profile {
        display_name: Some(name.to_owned()),
        ..Profile::default()
    }
}

/// Every group and membership, whole.
async fn group_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(g)::text FROM service.groups g
         UNION ALL SELECT row_to_json(m)::text FROM service.group_members m
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// A user who holds these, acting as themselves.
async fn holding(service: &Service, db: &Db, name: &str, grants: &[(&str, &str)]) -> Actor {
    let boss = admin(db).await;
    let id = new_user(service, &boss, name).await;
    for (major, minor) in grants {
        service
            .grant(
                &boss,
                &Holder::User(id),
                &pattern(major, minor),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
    Actor::User {
        id,
        name: name.to_owned(),
    }
}

fn actor_id(actor: &Actor) -> UserId {
    match actor {
        Actor::User { id, .. } => *id,
        _ => panic!("a user"),
    }
}

fn actor_json(actor: &Actor) -> Value {
    serde_json::to_value(actor).expect("JSON")
}

async fn update_user_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let id = new_user(&service, &boss, "audited-profile").await;
    let profile = Profile {
        display_name: Some("Audited".to_owned()),
        email: Some("a@example.com".to_owned()),
        timezone: Some("Asia/Tokyo".to_owned()),
        queue: Some("tier2".to_owned()),
    };
    assert!(
        service
            .update_user(&boss, id, &profile)
            .await
            .expect("updates")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "update_user".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: Some(
                json!({"display_name": null, "email": null, "timezone": "UTC", "queue": "default"})
            ),
            after: Some(json!({
                "display_name": "Audited",
                "email": "a@example.com",
                "timezone": "Asia/Tokyo",
                "queue": "tier2",
            })),
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(
        !service
            .update_user(&boss, id, &profile)
            .await
            .expect("a no-op")
    );
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn update_own_profile_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-own-profile", &[]).await;
    let profile = Profile {
        display_name: Some("Me".to_owned()),
        timezone: Some("America/New_York".to_owned()),
        queue: Some("my_queue".to_owned()),
        ..Profile::default()
    };
    assert!(
        service
            .update_own_profile(&me, &profile)
            .await
            .expect("needs no grant")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "update_own_profile".to_owned(),
            target: ("user".to_owned(), actor_id(&me).0.to_string()),
            before: Some(
                json!({"display_name": null, "email": null, "timezone": "UTC", "queue": "default"})
            ),
            after: Some(json!({
                "display_name": "Me",
                "email": null,
                "timezone": "America/New_York",
                "queue": "my_queue",
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn create_group_records_its_row(db: &Db) -> String {
    let service = service(db);
    let group = service
        .create_group(&admin(db).await, " audited group ")
        .await
        .expect("makes a group");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_group".to_owned(),
            target: ("group".to_owned(), group.0.to_string()),
            before: None,
            after: Some(json!({"name": "audited group"})),
            details: json!({}),
        }
    );
    row.action
}

async fn delete_group_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let group = service
        .create_group(&boss, "audited deletion")
        .await
        .expect("makes a group");
    let member = new_user(&service, &boss, "audited-member").await;
    service
        .add_group_member(&boss, group, member)
        .await
        .expect("adds");
    service
        .grant(
            &boss,
            &Holder::Group(group),
            &pattern("alert", "read"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    assert!(service.delete_group(&boss, group).await.expect("deletes"));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_group".to_owned(),
            target: ("group".to_owned(), group.0.to_string()),
            before: Some(json!({"name": "audited deletion"})),
            after: None,
            details: json!({"members": 1, "grants": 1}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(!service.delete_group(&boss, group).await.expect("a no-op"));
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn add_group_member_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let group = service
        .create_group(&boss, "audited joining")
        .await
        .expect("makes a group");
    let member = new_user(&service, &boss, "audited-joiner").await;
    assert!(
        service
            .add_group_member(&boss, group, member)
            .await
            .expect("adds")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_group_member".to_owned(),
            target: ("group".to_owned(), group.0.to_string()),
            before: None,
            after: Some(json!({"member": member.0})),
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(
        !service
            .add_group_member(&boss, group, member)
            .await
            .expect("a no-op")
    );
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn remove_group_member_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let group = service
        .create_group(&boss, "audited leaving")
        .await
        .expect("makes a group");
    let member = new_user(&service, &boss, "audited-leaver").await;
    service
        .add_group_member(&boss, group, member)
        .await
        .expect("adds");
    assert!(
        service
            .remove_group_member(&boss, group, member)
            .await
            .expect("removes")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "remove_group_member".to_owned(),
            target: ("group".to_owned(), group.0.to_string()),
            before: Some(json!({"member": member.0})),
            after: None,
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(
        !service
            .remove_group_member(&boss, group, member)
            .await
            .expect("a no-op")
    );
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn set_api_key_scope_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let key = service
        .create_api_key(&boss, "audited scope", None, &[pattern("alert", "read")])
        .await
        .expect("makes a key");
    let scope = [pattern("observable", "read"), pattern("alert", "*")];
    assert!(
        service
            .set_api_key_scope(&boss, key.id, "rescoped", &scope)
            .await
            .expect("sets it")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "set_api_key_scope".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: Some(json!({"name": "audited scope", "owner": null, "scope": ["alert:read"]})),
            after: Some(json!({
                "name": "rescoped",
                "owner": null,
                "scope": ["alert:*", "observable:read"],
            })),
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(
        !service
            .set_api_key_scope(&boss, key.id, "rescoped", &scope)
            .await
            .expect("a no-op")
    );
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn create_own_api_key_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(
        &service,
        db,
        "audited-own-key",
        &[("user", "self"), ("alert", "read")],
    )
    .await;
    let key = service
        .create_own_api_key(&me, "mine", &[pattern("alert", "read")])
        .await
        .expect("makes a key");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "create_own_api_key".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: None,
            after: Some(json!({
                "name": "mine",
                "owner": actor_id(&me).0,
                "scope": ["alert:read"],
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn set_own_api_key_scope_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(
        &service,
        db,
        "audited-own-scope",
        &[("user", "self"), ("alert", "*")],
    )
    .await;
    let key = service
        .create_own_api_key(&me, "mine", &[pattern("alert", "read")])
        .await
        .expect("makes a key");
    assert!(
        service
            .set_own_api_key_scope(&me, key.id, "still mine", &[pattern("alert", "write")])
            .await
            .expect("sets it")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "set_own_api_key_scope".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: Some(json!({
                "name": "mine",
                "owner": actor_id(&me).0,
                "scope": ["alert:read"],
            })),
            after: Some(json!({
                "name": "still mine",
                "owner": actor_id(&me).0,
                "scope": ["alert:write"],
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn revoke_own_api_key_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(
        &service,
        db,
        "audited-own-revoke",
        &[("user", "self"), ("alert", "read")],
    )
    .await;
    let key = service
        .create_own_api_key(&me, "mine", &[pattern("alert", "read")])
        .await
        .expect("makes a key");
    assert!(
        service
            .revoke_own_api_key(&me, key.id)
            .await
            .expect("revokes")
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "revoke_own_api_key".to_owned(),
            target: ("api_key".to_owned(), key.id.0.to_string()),
            before: Some(json!({
                "name": "mine",
                "owner": actor_id(&me).0,
                "scope": ["alert:read"],
            })),
            after: None,
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    assert!(
        !service
            .revoke_own_api_key(&me, key.id)
            .await
            .expect("a no-op")
    );
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

/// ace3's `_check_scope_within_grants`: a key a user makes for themselves lists what it needs, each
/// pattern covering something ACE checks that they hold, and never `user:self`, and `own_permissions`
/// offers those. A key can't make one.
#[tokio::test]
async fn a_user_s_own_key_holds_only_what_they_do() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let me = holding(
        &service,
        db,
        "keymaker",
        &[("user", "self"), ("alert", "read")],
    )
    .await;
    // what the picker offers: the catalog's permissions they hold, without user:self
    let offered: Vec<String> = service
        .own_permissions(&me)
        .await
        .expect("reads")
        .iter()
        .map(|entry| entry.name.to_string())
        .collect();
    assert_eq!(offered, ["alert:read"]);
    let before = (permission_rows(db).await, credential_rows(db).await);
    for (scope, says) in [
        (vec![], "has to list"),
        (
            vec![pattern("alret", "read")],
            "alret:read matches no permission",
        ),
        (vec![pattern("alert", "*")], "alert:*"),
        (vec![pattern("*", "*")], "which you don't hold"),
        (
            vec![pattern("user", "self")],
            "user:self is only ever a person's",
        ),
    ] {
        let error = service
            .create_own_api_key(&me, "mine", &scope)
            .await
            .expect_err("refused");
        assert!(
            matches!(error, ServiceError::InvalidRequest(_)) && error.to_string().contains(says),
            "{scope:?}: {error}"
        );
    }
    let error = service
        .create_own_api_key(&me, "mine", &[pattern("alert", "*")])
        .await
        .expect_err("refused");
    assert_eq!(
        error.to_string(),
        "alert:* covers alert:create, alert:queue, alert:write, which you don't hold"
    );
    assert_eq!(
        (permission_rows(db).await, credential_rows(db).await),
        before,
        "a refused scope made nothing"
    );

    // what it may hold, it gets, and a repeated pattern is one row
    let key = service
        .create_own_api_key(
            &me,
            "mine",
            &[pattern("alert", "read"), pattern("ALERT", "Read")],
        )
        .await
        .expect("makes a key");
    let mine = service.own_api_keys(&me).await.expect("reads");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id, key.id);
    assert_eq!(mine[0].owner, Some(actor_id(&me)));
    assert_eq!(
        mine[0]
            .grants
            .iter()
            .map(|grant| format!("{}:{}", grant.major, grant.minor))
            .collect::<Vec<_>>(),
        ["alert:read"]
    );
    let as_key = service
        .authenticate_api_key(key.token.expose())
        .await
        .expect("authenticates");
    assert!(
        matches!(
            service
                .create_own_api_key(&as_key, "another", &[pattern("alert", "read")])
                .await,
            Err(ServiceError::PermissionDenied { ref permission, .. }) if *permission == USER_SELF
        ),
        "a key can't make a key"
    );
    assert!(matches!(
        service.own_account(&as_key).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.own_permissions(&as_key).await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    // someone else's key isn't there, to them
    let other = holding(
        &service,
        db,
        "other",
        &[("user", "self"), ("alert", "read")],
    )
    .await;
    let count = audit_rows(db).await.len();
    assert!(matches!(
        service
            .set_own_api_key_scope(&other, key.id, "theirs", &[pattern("alert", "read")])
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(
        !service
            .revoke_own_api_key(&other, key.id)
            .await
            .expect("reads as missing")
    );
    assert_eq!(audit_rows(db).await.len(), count);
    assert_eq!(service.own_api_keys(&other).await.expect("reads"), []);

    // a scope the owner no longer holds has to go before the key changes
    let boss = admin(db).await;
    service
        .revoke(
            &boss,
            &Holder::User(actor_id(&me)),
            &pattern("alert", "read"),
            Effect::Allow,
        )
        .await
        .expect("revokes");
    assert!(matches!(
        service
            .set_own_api_key_scope(&me, key.id, "renamed", &[pattern("alert", "read")])
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
}

/// Setting a scope replaces a key's allows and leaves a deny, so an administrator's deny can't be lifted
/// by rescoping.
#[tokio::test]
async fn a_scope_keeps_a_key_s_deny() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let key = service
        .create_api_key(&boss, "scoped", None, &[pattern("alert", "*")])
        .await
        .expect("makes a key");
    service
        .grant(
            &boss,
            &Holder::ApiKey(key.id),
            &pattern("alert", "write"),
            Effect::Deny,
        )
        .await
        .expect("denies");
    service
        .set_api_key_scope(&boss, key.id, "scoped", &[pattern("*", "*")])
        .await
        .expect("sets it");
    let as_key = service
        .authenticate_api_key(key.token.expose())
        .await
        .expect("authenticates");
    assert!(
        service
            .allowed(&as_key, &name("observable", "read"))
            .await
            .expect("checks")
    );
    assert!(
        !service
            .allowed(&as_key, &ALERT_WRITE)
            .await
            .expect("checks")
    );
    let keys = service.api_keys(&boss, None).await.expect("lists");
    let grants: Vec<String> = keys[0]
        .grants
        .iter()
        .map(|grant| format!("{}:{}:{:?}", grant.major, grant.minor, grant.effect))
        .collect();
    assert_eq!(grants, ["*:*:Allow", "alert:write:Deny"]);
    assert!(matches!(
        service
            .set_api_key_scope(&boss, ApiKeyId(Uuid::from_u128(99)), "x", &[])
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .create_api_key(&boss, "x", None, &[pattern("user", "self")])
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
}

/// The management reads: what each user holds, through which group, and who may see it.
#[tokio::test]
async fn reading_users_and_groups_needs_user_read() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let reader = holding(&service, db, "reader", &[("user", "read")]).await;
    let nobody = holding(&service, db, "nobody", &[]).await;
    let member = new_user(&service, &boss, "member").await;
    let group = service
        .create_group(&boss, "triage")
        .await
        .expect("a group");
    service
        .add_group_member(&boss, group, member)
        .await
        .expect("adds");
    service
        .grant(
            &boss,
            &Holder::Group(group),
            &pattern("alert", "read"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    service
        .grant(
            &boss,
            &Holder::User(member),
            &pattern("alert", "write"),
            Effect::Deny,
        )
        .await
        .expect("denies");
    service
        .set_user_enabled(&boss, member, false)
        .await
        .expect("disables");

    let detail = service.user(&reader, member).await.expect("reads");
    assert_eq!(detail.user.username, "member");
    assert!(!detail.user.enabled);
    assert_eq!(detail.grants.len(), 1);
    assert_eq!(detail.grants[0].effect, Effect::Deny);
    assert_eq!(detail.groups.len(), 1);
    assert_eq!(detail.groups[0].id, group);
    assert_eq!(detail.groups[0].members, [member]);
    assert_eq!(detail.groups[0].grants[0].major, "alert");

    let names = |users: Vec<ace_service::User>| -> Vec<String> {
        users.into_iter().map(|user| user.username).collect()
    };
    let all = names(service.users(&reader, true).await.expect("lists"));
    assert!(all.contains(&"member".to_owned()));
    let enabled = names(service.users(&reader, false).await.expect("lists"));
    assert!(!enabled.contains(&"member".to_owned()));
    assert_eq!(service.groups(&reader).await.expect("lists").len(), 1);
    assert!(
        service
            .permission_catalog(&reader)
            .await
            .expect("reads")
            .iter()
            .any(|entry| entry.name == ALERT_WRITE)
    );
    assert!(matches!(
        service.user(&reader, UserId(Uuid::from_u128(98))).await,
        Err(ServiceError::NoUser(_))
    ));

    for refused in [
        service.users(&nobody, true).await.map(|_| ()),
        service.user(&nobody, member).await.map(|_| ()),
        service.groups(&nobody).await.map(|_| ()),
        service.api_keys(&nobody, None).await.map(|_| ()),
        service.permission_catalog(&nobody).await.map(|_| ()),
    ] {
        assert!(matches!(
            refused,
            Err(ServiceError::PermissionDenied { .. })
        ));
    }
    let own = service.own_account(&nobody).await.expect("needs no grant");
    assert_eq!(own.username, "nobody");
    assert_eq!(own.timezone, "UTC");

    service
        .create_group(&boss, "Triage")
        .await
        .expect("a name in another case is another group");
    assert!(matches!(
        service.create_group(&boss, "triage").await,
        Err(ServiceError::GroupNameTaken)
    ));
    assert!(matches!(
        service
            .add_group_member(&boss, GroupId(Uuid::from_u128(97)), member)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .grant(
                &boss,
                &Holder::Group(GroupId(Uuid::from_u128(97))),
                &pattern("a", "b"),
                Effect::Allow
            )
            .await,
        Err(ServiceError::NotFound(_))
    ));
}

/// A profile's fields are checked before anything is written, and a user changes only their own name and
/// timezone.
#[tokio::test]
async fn a_profile_is_checked() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let me = holding(&service, db, "profiled", &[]).await;
    let id = actor_id(&me);
    for bad in [
        Profile {
            timezone: Some("Mars/Olympus".to_owned()),
            ..Profile::default()
        },
        Profile {
            email: Some("no at sign".to_owned()),
            ..Profile::default()
        },
        Profile {
            email: Some("@example.com".to_owned()),
            ..Profile::default()
        },
        display_name("a\u{7}bell"),
        display_name(&"x".repeat(1025)),
    ] {
        assert!(
            matches!(
                service.update_user(&boss, id, &bad).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        service
            .update_own_profile(
                &me,
                &Profile {
                    email: Some("me@example.com".to_owned()),
                    ..Profile::default()
                }
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .update_user(&boss, UserId(Uuid::from_u128(96)), &display_name("x"))
            .await,
        Err(ServiceError::NoUser(_))
    ));
    // an empty field clears it, and a timezone's name is the canonical one
    service
        .update_user(
            &boss,
            id,
            &Profile {
                display_name: Some("Shown".to_owned()),
                email: Some("me@example.com".to_owned()),
                timezone: Some(" US/Eastern ".to_owned()),
                queue: None,
            },
        )
        .await
        .expect("updates");
    service
        .update_own_profile(&me, &display_name("  "))
        .await
        .expect("clears");
    let own = service.own_account(&me).await.expect("reads");
    assert_eq!(own.display_name, None);
    assert_eq!(own.email.as_deref(), Some("me@example.com"));
    assert_eq!(own.timezone, "US/Eastern");
}

/// The catalog lists every permission this crate checks, so a router that brings one has to add it.
#[test]
fn the_catalog_lists_every_permission_checked() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/permission.rs"))
            .expect("reads the source");
    let known =
        regex::Regex::new(r#"PermissionName::known\("(\w+)", "(\w+)"\)"#).expect("a pattern");
    let checked: BTreeSet<String> = known
        .captures_iter(&source)
        .map(|found| format!("{}:{}", &found[1], &found[2]))
        .collect();
    let listed: BTreeSet<String> = CATALOG.iter().map(|entry| entry.name.to_string()).collect();
    assert_eq!(listed.len(), CATALOG.len(), "each once");
    assert_eq!(listed, checked);
    let mut directories = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("reads the source") {
            let path = entry.expect("reads the source").path();
            if path.is_dir() {
                directories.push(path);
            } else if !path.ends_with("permission.rs") {
                let text = std::fs::read_to_string(&path).expect("reads the source");
                assert!(
                    !text.contains("PermissionName::known("),
                    "{}: a known permission belongs in permission.rs, beside the catalog",
                    path.display()
                );
            }
        }
    }
}

// PLAN.md 5.6's `observable_comments`.

/// Every comment row, whole.
async fn comment_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(c)::text FROM analysis.observable_comments c ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

async fn add_observable_comment_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let added = service(db)
        .add_observable_comment(&actor, "fqdn", "audited.example.com", "<b>bad</b>\r\n")
        .await
        .expect("comments");
    assert_eq!(added.comment, "<b>bad</b>\r\n", "kept as it was sent");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_observable_comment".to_owned(),
            target: ("observable_comment".to_owned(), added.id.to_string()),
            before: None,
            after: Some(json!({
                "type": "fqdn",
                "value": "audited.example.com",
                "author": Uuid::from_u128(0xAD),
                "comment": "<b>bad</b>\r\n",
            })),
            details: json!({}),
        }
    );

    // a refusal, or a comment the service won't take, has no row
    let rows = audit_rows(db).await.len();
    let reader = UserId(Uuid::from_u128(0xC0));
    exists(db, &Holder::User(reader)).await;
    assert!(matches!(
        service(db)
            .add_observable_comment(&user(reader), "fqdn", "a.example", "x")
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "observable:write"
    ));
    assert!(matches!(
        service(db)
            .add_observable_comment(&actor, "fqdn", "a.example", " \n")
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn edit_observable_comment_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let added = service
        .add_observable_comment(&actor, "ipv4", "192.0.2.1", "first\r\nthought")
        .await
        .expect("comments");
    let edited = service
        .edit_observable_comment(&actor, added.id, "second thought")
        .await
        .expect("edits");
    assert!(edited.edited_at.is_some());
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "edit_observable_comment".to_owned(),
            target: ("observable_comment".to_owned(), added.id.to_string()),
            before: Some(json!({"comment": "first\r\nthought"})),
            after: Some(json!({"comment": "second thought"})),
            details: json!({
                "type": "ipv4",
                "value": "192.0.2.1",
                "author": Uuid::from_u128(0xAD),
            }),
        }
    );

    // the same text, trimmed or with LF line endings, isn't an edit, as in ace3
    let rows = audit_rows(db).await.len();
    let same = service
        .edit_observable_comment(&actor, added.id, "  second thought\n")
        .await
        .expect("edits");
    assert_eq!(same, edited, "nothing changed, not even when it was edited");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn delete_observable_comment_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let added = service
        .add_observable_comment(&actor, "url", "http://bad.example/<x>", "phish")
        .await
        .expect("comments");
    service
        .delete_observable_comment(&actor, added.id)
        .await
        .expect("deletes");
    let created_at: Value = sqlx::query_scalar(
        "SELECT to_jsonb(created_at) FROM analysis.observable_comments WHERE id = $1",
    )
    .bind(added.id)
    .fetch_optional(db.pool())
    .await
    .expect("reads")
    .unwrap_or(Value::Null);
    assert_eq!(created_at, Value::Null, "the row is gone");
    let row = last_audit(db).await;
    let before = row.before.clone().expect("a before");
    assert!(before["created_at"].is_string(), "{before}");
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_observable_comment".to_owned(),
            target: ("observable_comment".to_owned(), added.id.to_string()),
            before: Some(json!({
                "type": "url",
                "value": "http://bad.example/<x>",
                "author": Uuid::from_u128(0xAD),
                "comment": "phish",
                "created_by": boss_json(),
                "created_at": before["created_at"],
                "edited_at": null,
            })),
            after: None,
            details: json!({}),
        }
    );

    // a comment that's gone is a 404, and has no row
    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service.delete_observable_comment(&actor, added.id).await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// ace3's comments: on a type and value, so they show in every alert that holds the observable; a person's,
/// a key's being its owner's; and changed or deleted only by their author.
#[tokio::test]
async fn observable_comments_apply_across_alerts_and_only_their_author_changes_them() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = holding(
        &service,
        db,
        "alice",
        &[("observable", "*"), ("alert", "read")],
    )
    .await;
    let bob = holding(&service, db, "bob", &[("observable", "*")]).await;
    let reader = holding(&service, db, "reader", &[("observable", "read")]).await;
    let boss = admin(db).await;

    // two alerts hold the same fqdn, and a comment on it shows in both
    let (first, second) = (alert(db).await, alert(db).await);
    for root in [first, second] {
        sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
            .bind(root)
            .execute(db.pool())
            .await
            .expect("makes it an alert");
    }
    let on_fqdn = service
        .add_observable_comment(&alice, "fqdn", "evil.example.com", "seen in the phish")
        .await
        .expect("comments");
    let by_bob = service
        .add_observable_comment(
            &bob,
            "fqdn",
            "evil.example.com",
            "<script>alert(1)</script>",
        )
        .await
        .expect("comments");
    service
        .add_observable_comment(&alice, "fqdn", "other.example.com", "not this one")
        .await
        .expect("comments");
    // the fqdn's hash is the same in another type, which doesn't count
    service
        .add_observable_comment(&alice, "hostname", "evil.example.com", "a hostname")
        .await
        .expect("comments");
    assert_eq!(on_fqdn.author.username, "alice");
    assert_eq!(on_fqdn.created_by.kind, "user");
    assert_eq!(on_fqdn.edited_at, None);
    let listed = service
        .observable_comments(&reader, "fqdn", "evil.example.com")
        .await
        .expect("reads");
    assert_eq!(
        listed,
        vec![on_fqdn.clone(), by_bob.clone()],
        "oldest first"
    );
    assert_eq!(listed[1].comment, "<script>alert(1)</script>", "as data");
    for root in [first, second] {
        assert_eq!(
            service
                .alert_observable_comments(&alice, root)
                .await
                .expect("reads"),
            listed,
            "in every alert that holds it"
        );
    }
    assert!(matches!(
        service.alert_observable_comments(&alice, Uuid::nil()).await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service.alert_observable_comments(&bob, first).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "alert:read"
    ));

    // a file is matched by its sha256, which is lowercased as the lookup lowercases it
    let sha256 = hex::encode(Sha256::digest(b"some file"));
    let on_file = service
        .add_observable_comment(&alice, "file", &sha256.to_uppercase(), "the dropper")
        .await
        .expect("comments");
    assert_eq!(on_file.value, sha256);
    assert_eq!(
        service
            .observable_comments(&reader, "file", &sha256)
            .await
            .expect("reads"),
        vec![on_file]
    );

    // a key with an owner writes as its owner, who can then change it; one with no owner can't write
    let alices_key = ApiKeyId(Uuid::from_u128(0xA11CE));
    exists(db, &Holder::ApiKey(alices_key)).await;
    grant(
        db,
        &Holder::ApiKey(alices_key),
        "observable",
        "write",
        Effect::Allow,
    )
    .await;
    let as_key = key(alices_key, Some(actor_id(&alice)));
    let by_key = service
        .add_observable_comment(&as_key, "ipv4", "198.51.100.7", "from a script")
        .await
        .expect("comments");
    assert_eq!(by_key.author.id, actor_id(&alice));
    assert_eq!(
        (
            by_key.created_by.kind.as_str(),
            by_key.created_by.id.clone()
        ),
        ("api_key", alices_key.0.to_string())
    );
    service
        .edit_observable_comment(&alice, by_key.id, "from alice's script")
        .await
        .expect("the owner edits it");
    let ownerless = ApiKeyId(Uuid::from_u128(0x0B0E));
    grant(
        db,
        &Holder::ApiKey(ownerless),
        "observable",
        "write",
        Effect::Allow,
    )
    .await;
    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service
            .add_observable_comment(&key(ownerless, None), "ipv4", "198.51.100.7", "x")
            .await,
        Err(ServiceError::Forbidden(_))
    ));

    // only the author edits or deletes, not another analyst and not an admin
    for other in [&bob, &boss, &key(ownerless, None)] {
        assert!(matches!(
            service
                .edit_observable_comment(other, on_fqdn.id, "mine now")
                .await,
            Err(ServiceError::Forbidden(_))
        ));
        assert!(matches!(
            service.delete_observable_comment(other, on_fqdn.id).await,
            Err(ServiceError::Forbidden(_))
        ));
    }
    assert!(matches!(
        service
            .edit_observable_comment(&reader, on_fqdn.id, "x")
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "observable:write"
    ));
    assert!(matches!(
        service.edit_observable_comment(&alice, i64::MAX, "x").await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows, "no refusal has a row");

    // what the service won't take
    let long = "x".repeat(ace_service::MAX_COMMENT_CHARS + 1);
    for (kind, value, comment, why) in [
        ("fqdn", "a.example", "", "a comment can't be empty"),
        ("fqdn", "a.example", " \r\n\t", "a comment can't be empty"),
        (
            "fqdn",
            "a.example",
            long.as_str(),
            "a comment is at most 16384 characters",
        ),
        (
            "fqdn",
            "a.example",
            "a\0b",
            "a comment can't hold a NUL character",
        ),
        (
            "fqdn",
            "a\0b",
            "x",
            "an observable's value can't hold a NUL character",
        ),
        ("fqdn", "", "x", "an empty value"),
        ("no_such_type", "a.example", "x", "no_such_type"),
        (
            "file",
            "not a sha256",
            "x",
            "a file is looked up by its sha256",
        ),
    ] {
        let error = service
            .add_observable_comment(&alice, kind, value, comment)
            .await
            .expect_err(why);
        assert!(
            matches!(&error, ServiceError::InvalidRequest(got) if got.contains(why)),
            "{why}: {error}"
        );
    }
    let longest = "é".repeat(ace_service::MAX_COMMENT_CHARS);
    service
        .add_observable_comment(&alice, "fqdn", "a.example", &longest)
        .await
        .expect("16384 characters, however many bytes");
    assert!(matches!(
        service
            .edit_observable_comment(&alice, on_fqdn.id, "")
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));

    // the author deletes it, and it's gone from every alert
    service
        .delete_observable_comment(&alice, on_fqdn.id)
        .await
        .expect("deletes");
    assert_eq!(
        service
            .alert_observable_comments(&alice, second)
            .await
            .expect("reads"),
        vec![by_bob]
    );
}

// PLAN.md 5.7: a user's GUI preferences.

fn theme(mode: Theme) -> PreferenceValue {
    PreferenceValue::Theme(ThemePreference { mode })
}

async fn preference_rows(db: &Db) -> Vec<(Uuid, String, Value)> {
    sqlx::query_as("SELECT user_id, key, value FROM service.user_preferences ORDER BY user_id, key")
        .fetch_all(db.pool())
        .await
        .expect("reads")
}

async fn set_preference_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-set-preference", &[]).await;
    let target = (
        "user_preference".to_owned(),
        format!("{}/theme", actor_id(&me).0),
    );
    service
        .set_preference(&me, &theme(Theme::Dark))
        .await
        .expect("needs no grant");
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "set_preference".to_owned(),
            target: target.clone(),
            before: None,
            after: Some(json!({"value": {"mode": "dark"}})),
            details: json!({}),
        }
    );
    service
        .set_preference(&me, &theme(Theme::Halloween))
        .await
        .expect("sets");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "set_preference".to_owned(),
            target,
            before: Some(json!({"value": {"mode": "dark"}})),
            after: Some(json!({"value": {"mode": "halloween"}})),
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    service
        .set_preference(&me, &theme(Theme::Halloween))
        .await
        .expect("a no-op");
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

async fn reset_preference_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-reset-preference", &[]).await;
    service
        .set_preference(&me, &theme(Theme::Jd))
        .await
        .expect("sets");
    let reset = service
        .reset_preference(&me, PreferenceKey::Theme)
        .await
        .expect("needs no grant");
    assert_eq!(reset.value, theme(Theme::System));
    assert!(reset.is_default);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: actor_json(&me),
            action: "reset_preference".to_owned(),
            target: (
                "user_preference".to_owned(),
                format!("{}/theme", actor_id(&me).0)
            ),
            before: Some(json!({"value": {"mode": "jd"}})),
            after: None,
            details: json!({}),
        }
    );
    let count = audit_rows(db).await.len();
    service
        .reset_preference(&me, PreferenceKey::Theme)
        .await
        .expect("a no-op");
    assert_eq!(audit_rows(db).await.len(), count, "a no-op has no row");
    row.action
}

/// A user without a stored value has the default; a value is checked by its key, as ace3's schema
/// checks it; a stored value this release can't read is the default again, with no failure; and only a
/// user has preferences, each their own.
#[tokio::test]
async fn preferences_are_a_user_s_own_and_checked_by_key() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = holding(&service, db, "alice", &[]).await;
    let bob = holding(&service, db, "bob", &[]).await;

    let defaults = service.preferences(&alice).await.expect("reads");
    assert_eq!(defaults.len(), PreferenceKey::ALL.len());
    assert_eq!(defaults[0].value, theme(Theme::System));
    assert!(defaults[0].is_default);
    assert_eq!(defaults[0].updated_at, None);
    assert_eq!(service.theme(&alice).await.expect("reads"), Theme::System);

    let set = service
        .set_preference(&alice, &theme(Theme::Dark))
        .await
        .expect("sets");
    assert!(!set.is_default);
    assert!(set.updated_at.is_some());
    assert_eq!(
        service
            .preference(&alice, PreferenceKey::Theme)
            .await
            .expect("reads"),
        set
    );
    assert_eq!(service.theme(&alice).await.expect("reads"), Theme::Dark);
    assert_eq!(
        service.theme(&bob).await.expect("reads"),
        Theme::System,
        "one user's preference isn't another's"
    );

    // ace3's ThemePreference: `mode` defaults to "system", and nothing else is allowed.
    let key = PreferenceKey::named("theme").expect("a key");
    assert_eq!(
        key.parse(json!({})).expect("a default"),
        theme(Theme::System)
    );
    assert_eq!(
        key.parse(json!({"mode": "halloween"})).expect("valid"),
        theme(Theme::Halloween)
    );
    for invalid in [
        json!({"mode": "neon"}),
        json!({"mode": "DARK"}),
        json!({"mode": "dark", "extra": 1}),
        json!("dark"),
        json!([]),
    ] {
        assert!(
            matches!(
                key.parse(invalid.clone()),
                Err(ServiceError::InvalidRequest(_))
            ),
            "{invalid}"
        );
    }
    assert_eq!(
        PreferenceKey::named("manage_columns"),
        Some(PreferenceKey::ManageColumns)
    );
    assert_eq!(PreferenceKey::named("search_columns"), None);
    assert_eq!(PreferenceKey::named("Theme"), None);

    // A row this release can't read, as after a theme is removed: the default, and a set replaces it.
    sqlx::query(
        "UPDATE service.user_preferences SET value = '{\"mode\": \"retired\"}' WHERE user_id = $1",
    )
    .bind(actor_id(&alice).0)
    .execute(db.pool())
    .await
    .expect("stales the row");
    let stale = service
        .preference(&alice, PreferenceKey::Theme)
        .await
        .expect("reads");
    assert_eq!(stale.value, theme(Theme::System));
    assert!(stale.is_default);
    assert!(stale.updated_at.is_some());
    assert_eq!(service.theme(&alice).await.expect("reads"), Theme::System);
    service
        .set_preference(&alice, &theme(Theme::Light))
        .await
        .expect("replaces it");
    let row = last_audit(db).await;
    assert_eq!(row.before, Some(json!({"unreadable": true})));
    assert_eq!(row.after, Some(json!({"value": {"mode": "light"}})));

    // A row under a key this release doesn't have isn't given.
    sqlx::query(
        "INSERT INTO service.user_preferences (user_id, key, value) VALUES ($1, 'retired', '{}')",
    )
    .bind(actor_id(&alice).0)
    .execute(db.pool())
    .await
    .expect("adds a row");
    let all = service.preferences(&alice).await.expect("reads");
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].value, theme(Theme::Light));
    assert_eq!(all[1].value.key(), PreferenceKey::AlertSections);
    assert!(all[1].is_default);
    assert_eq!(all[2].value.key(), PreferenceKey::ManageColumns);
    assert!(all[2].is_default);

    // Only a user has preferences. A key, even one of the user's own holding everything, and a
    // component are refused, and change nothing; their pages have the default theme.
    let boss = admin(db).await;
    let key = service
        .create_api_key(
            &boss,
            "alice's",
            Some(actor_id(&alice)),
            &[pattern("*", "*")],
        )
        .await
        .expect("makes a key");
    let as_key = service
        .authenticate_api_key(key.token.expose())
        .await
        .expect("authenticates");
    let component = Actor::Internal {
        id: Component::new("bootstrap").expect("a name"),
    };
    let rows = preference_rows(db).await;
    for actor in [&as_key, &component] {
        assert!(matches!(
            service.preferences(actor).await,
            Err(ServiceError::PermissionDenied { .. })
        ));
        assert!(matches!(
            service.preference(actor, PreferenceKey::Theme).await,
            Err(ServiceError::PermissionDenied { .. })
        ));
        assert!(matches!(
            service.set_preference(actor, &theme(Theme::Dark)).await,
            Err(ServiceError::PermissionDenied { .. })
        ));
        assert!(matches!(
            service.reset_preference(actor, PreferenceKey::Theme).await,
            Err(ServiceError::PermissionDenied { .. })
        ));
        assert_eq!(
            service.theme(actor).await.expect("a default"),
            Theme::System
        );
    }
    assert_eq!(preference_rows(db).await, rows);

    // A user's preferences go with the user, as their grants do.
    sqlx::query("DELETE FROM service.users WHERE id = $1")
        .bind(actor_id(&bob).0)
        .execute(db.pool())
        .await
        .expect("deletes bob");
    service
        .set_preference(&alice, &theme(Theme::Jd))
        .await
        .expect("sets");
    sqlx::query("DELETE FROM service.api_keys WHERE owner_id = $1")
        .bind(actor_id(&alice).0)
        .execute(db.pool())
        .await
        .expect("deletes alice's key");
    sqlx::query("DELETE FROM service.users WHERE id = $1")
        .bind(actor_id(&alice).0)
        .execute(db.pool())
        .await
        .expect("deletes alice");
    assert_eq!(preference_rows(db).await, []);
}

// PLAN.md 5.10: the alert list's filters, sorts and keyset pages, the share-link encoding, date ranges,
// the detection points' filters, saved filters and the manage_columns preference.

use ace_service::filters::{self as filter_model, FilterScreen};
use ace_service::{AlertQuery, AlertSort, FilterEntry, FilterValue};

/// One alert of the list's fixtures.
struct Fixture<'a> {
    title: &'a str,
    /// When it became an alert, as Postgres reads a timestamptz.
    alerted: &'a str,
    /// The disposition and the name of who set it, when it has one.
    disposition: Option<(&'a str, &'a str, &'a str)>,
    event_time: Option<&'a str>,
    observables: &'a [(ObservableKind, &'a str, &'a [&'a str])],
    /// A result of this module, with these tags, on the first observable.
    result: Option<(&'a str, &'a [&'a str])>,
    /// A detection by this signature uuid and version on the first observable.
    signature: Option<(&'a str, Option<&'a str>)>,
}

impl Default for Fixture<'_> {
    fn default() -> Self {
        Fixture {
            title: "",
            alerted: "2026-01-01T00:00:00Z",
            disposition: None,
            event_time: None,
            observables: &[],
            result: None,
            signature: None,
        }
    }
}

async fn listed(db: &Db, fixture: Fixture<'_>) -> Uuid {
    let root = NewRoot {
        description: fixture.title.to_owned(),
        ..NewRoot::new("correlation")
    };
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let mut first = None;
    for (kind, value, tags) in fixture.observables {
        let mut observable = NewObservable::new(*kind, *value);
        observable.tags = tags.iter().map(|tag| (*tag).to_owned()).collect();
        let added = tree::upsert_observable(&mut tx, root.id, &observable)
            .await
            .expect("adds");
        first.get_or_insert(added.id.0);
    }
    tx.commit().await.expect("commits");
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = $2::timestamptz,
                event_time = $3::timestamptz,
                event_time_source = CASE WHEN $3 IS NULL THEN 'unset' ELSE 'event' END::analysis.event_time_source
         WHERE id = $1",
    )
    .bind(root.id)
    .bind(fixture.alerted)
    .bind(fixture.event_time)
    .execute(db.pool())
    .await
    .expect("makes it an alert");
    if let Some((disposition, by, at)) = fixture.disposition {
        sqlx::query(
            "UPDATE analysis.roots SET disposition = $2, dispositioned_at = $4::timestamptz,
                    dispositioned_by = jsonb_build_object('kind', 'user', 'id', gen_random_uuid()::text, 'name', $3::text)
             WHERE id = $1",
        )
        .bind(root.id)
        .bind(disposition)
        .bind(by)
        .bind(at)
        .execute(db.pool())
        .await
        .expect("dispositions it");
    }
    let observable = first.unwrap_or_default();
    let mut result_id: Option<i64> = None;
    if let Some((module, tags)) = fixture.result {
        let tags: Vec<String> = tags.iter().map(|tag| (*tag).to_owned()).collect();
        result_id = Some(
            sqlx::query_scalar(
                "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, tags)
                 VALUES ($1, $2, $3, 'test_stub', 1, '{}', $4) RETURNING id",
            )
            .bind(root.id)
            .bind(observable)
            .bind(module)
            .bind(&tags)
            .fetch_one(db.pool())
            .await
            .expect("a result"),
        );
    }
    if let Some((uuid, version)) = fixture.signature {
        sqlx::query(
            "INSERT INTO analysis.detections
                 (root_id, observable_id, result_id, description, signature_uuid, signature_version, signature_family)
             VALUES ($1, $2, $3, 'a rule matched', $4, $5, 'yara')",
        )
        .bind(root.id)
        .bind(observable)
        .bind(result_id)
        .bind(uuid)
        .bind(version)
        .execute(db.pool())
        .await
        .expect("a detection");
    }
    root.id
}

const SIGNATURE_ONE: &str = "4C3C8330-545D-4673-9A7C-7BD4597D0001";
const SIGNATURE_TWO: &str = "4c3c8330-545d-4673-9a7c-7bd4597d0002";
const FILE_SHA256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const HOSTILE_TITLE: &str = "quarterly'; DROP TABLE analysis.roots; --";

/// The list's fixtures: four alerts and a root that isn't one, as (A, B, C, D).
/// Puts each alert in its queue.
async fn set_queues(db: &Db, queues: &[(Uuid, &str)]) {
    for (root, queue) in queues {
        sqlx::query("UPDATE analysis.roots SET queue = $2 WHERE id = $1")
            .bind(root)
            .bind(queue)
            .execute(db.pool())
            .await
            .expect("sets the queue");
    }
}

async fn list_fixtures(db: &Db) -> (Uuid, Uuid, Uuid, Uuid) {
    let a = listed(
        db,
        Fixture {
            title: "Phish from evil.example.com",
            alerted: "2026-01-10T10:00:00Z",
            event_time: Some("2026-01-10T09:00:00Z"),
            observables: &[(ObservableKind::Fqdn, "evil.example.com", &["phish"])],
            result: Some(("rdap_analyzer", &["whois"])),
            signature: Some((SIGNATURE_ONE, Some("v1"))),
            ..Fixture::default()
        },
    )
    .await;
    let b = listed(
        db,
        Fixture {
            title: r"100% off_sale \ invoice",
            alerted: "2026-01-11T10:00:00Z",
            disposition: Some(("FALSE_POSITIVE", "alice", "2026-01-12T08:00:00Z")),
            observables: &[
                (ObservableKind::Ipv4, "10.0.0.1", &[]),
                (ObservableKind::Url, "https://evil.example.com/a,b:c", &[]),
            ],
            ..Fixture::default()
        },
    )
    .await;
    // when B did, so the order's tie is broken by the id
    let c = listed(
        db,
        Fixture {
            title: "Weekly report",
            alerted: "2026-01-11T10:00:00Z",
            disposition: Some(("DELIVERY", "bob", "2026-01-13T08:00:00Z")),
            observables: &[(ObservableKind::Fqdn, "other.example", &["Phishing-Kit"])],
            signature: Some((SIGNATURE_TWO, None)),
            ..Fixture::default()
        },
    )
    .await;
    let d = listed(
        db,
        Fixture {
            title: HOSTILE_TITLE,
            alerted: &(Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            observables: &[(ObservableKind::File, FILE_SHA256, &[])],
            ..Fixture::default()
        },
    )
    .await;
    // a root that isn't an alert is never listed
    let root = NewRoot {
        description: "Phish, but never an alert".to_owned(),
        ..NewRoot::new("correlation")
    };
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    (a, b, c, d)
}

use chrono::Utc;

fn text(name: &str, inverted: bool, values: &[&str]) -> FilterEntry {
    FilterEntry::text(name, inverted, values)
}

fn pair(inverted: bool, kind: &str, value: &str) -> FilterEntry {
    FilterEntry::new(
        "Observable",
        inverted,
        vec![FilterValue::Pair(kind.to_owned(), value.to_owned())],
    )
}

/// Every alert a query lists, paging `limit` at a time to the end, in order, and the total each page gave.
async fn every_alert(
    service: &Service,
    actor: &Actor,
    query: &AlertQuery,
    limit: u32,
) -> (Vec<Uuid>, i64) {
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    let mut total = None;
    loop {
        let page = service
            .alerts(actor, query, Some(limit), after.as_deref())
            .await
            .expect("lists");
        assert!(page.alerts.len() <= limit as usize);
        match total {
            None => total = Some(page.total),
            Some(total) => assert_eq!(page.total, total, "each page counts the same"),
        }
        seen.extend(page.alerts.iter().map(|alert| alert.id));
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    (seen, total.unwrap_or(0))
}

async fn matching(service: &Service, actor: &Actor, filters: Vec<FilterEntry>) -> Vec<Uuid> {
    let query = AlertQuery {
        filters,
        ..AlertQuery::default()
    };
    let (mut ids, total) = every_alert(service, actor, &query, 2).await;
    assert_eq!(total, ids.len() as i64);
    ids.sort();
    ids
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

/// The Done check's service half: the list filters and pages through fixture alerts, each filter matching
/// what it says, inverted matching exactly the rest, and every order total and stable.
#[tokio::test]
async fn the_alert_list_filters_and_pages_through_fixture_alerts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (a, b, c, d) = list_fixtures(db).await;
    let all = sorted(vec![a, b, c, d]);
    // queues (PLAN.md 7.13): B is in triage, C in external, and the viewer works triage
    set_queues(db, &[(b, "triage"), (c, "external")]).await;
    sqlx::query("UPDATE service.users SET queue = 'triage' WHERE id = $1")
        .bind(Uuid::from_u128(0xAD))
        .execute(db.pool())
        .await
        .expect("sets the viewer's queue");

    // no filter: every alert, newest first, the tie between B and C broken by the id
    let (newest, total) = every_alert(&service, &actor, &AlertQuery::default(), 2).await;
    assert_eq!(total, 4);
    let (bc_first, bc_second) = if b > c { (b, c) } else { (c, b) };
    assert_eq!(newest, [d, bc_first, bc_second, a]);

    let cases: Vec<(Vec<FilterEntry>, Vec<Uuid>)> = vec![
        (vec![text("Disposition", false, &["OPEN"])], vec![a, d]),
        (vec![text("Disposition", true, &["OPEN"])], vec![b, c]),
        (
            vec![text("Disposition", false, &["FALSE_POSITIVE", "DELIVERY"])],
            vec![b, c],
        ),
        // two entries of one filter are merged, so they mean either
        (
            vec![
                text("Disposition", false, &["OPEN"]),
                text("Disposition", false, &["DELIVERY"]),
            ],
            vec![a, c, d],
        ),
        (vec![text("Disposition By", false, &["alice"])], vec![b]),
        (vec![text("Disposition By", false, &["None"])], vec![a, d]),
        (vec![text("Disposition By", true, &["None"])], vec![b, c]),
        (
            vec![text("Disposition By", true, &["alice"])],
            vec![a, c, d],
        ),
        (vec![text("Description", false, &["PHISH"])], vec![a]),
        (vec![text("Description", true, &["report"])], vec![a, b, d]),
        // %, _ and \ are themselves, not patterns
        (vec![text("Description", false, &["%"])], vec![b]),
        (vec![text("Description", false, &["_"])], vec![b]),
        (vec![text("Description", false, &[r"\"])], vec![b]),
        (vec![text("Description", false, &["f_s"])], vec![b]),
        (vec![text("Description", false, &["o%f"])], vec![]),
        (vec![pair(false, "fqdn", "evil.example.com")], vec![a]),
        (vec![pair(true, "fqdn", "evil.example.com")], vec![b, c, d]),
        (vec![pair(false, "Any", "10.0.0.1")], vec![b]),
        (
            vec![pair(false, "url", "https://evil.example.com/a,b:c")],
            vec![b],
        ),
        (
            vec![pair(false, "file", &FILE_SHA256.to_ascii_uppercase())],
            vec![d],
        ),
        (vec![text("Tag", false, &["phish*"])], vec![a, c]),
        (vec![text("Tag", false, &["phish"])], vec![a]),
        (vec![text("Tag", false, &["whois"])], vec![a]),
        (vec![text("Tag", true, &["phish*"])], vec![b, d]),
        (vec![text("Queue", false, &["triage"])], vec![b]),
        (
            vec![text("Queue", false, &["triage", "external"])],
            vec![b, c],
        ),
        (vec![text("Queue", false, &["default"])], vec![a, d]),
        (vec![text("Queue", true, &["default"])], vec![b, c]),
        (vec![text("Queue", false, &["$USER_QUEUE"])], vec![b]),
        (
            vec![text("Queue", false, &["$USER_QUEUE", "external"])],
            vec![b, c],
        ),
        (vec![text("Queue", false, &["nobody's"])], vec![]),
        (vec![text("Analysis", false, &["rdap_analyzer"])], vec![a]),
        (
            vec![text("Analysis", true, &["rdap_analyzer"])],
            vec![b, c, d],
        ),
        (
            vec![text("Detection Point", false, &[SIGNATURE_ONE])],
            vec![a],
        ),
        (
            vec![text(
                "Detection Point",
                false,
                &[&format!("{}:v1", SIGNATURE_ONE.to_ascii_lowercase())],
            )],
            vec![a],
        ),
        (
            vec![text(
                "Detection Point",
                false,
                &[&format!("{SIGNATURE_ONE}:v2")],
            )],
            vec![],
        ),
        (
            vec![text("Detection Point", false, &[SIGNATURE_TWO])],
            vec![c],
        ),
        (
            vec![text("Detection Point", true, &[SIGNATURE_ONE])],
            vec![b, c, d],
        ),
        (vec![text("Alert Date", false, &["-24h"])], vec![d]),
        (vec![text("Alert Date", true, &["-24h"])], vec![a, b, c]),
        (
            vec![text(
                "Alert Date",
                false,
                &["01-11-2026 00:00 - 01-11-2026 23:59"],
            )],
            vec![b, c],
        ),
        (
            vec![text(
                "Event Date",
                false,
                &["01-10-2026 08:00 - 01-10-2026 09:30"],
            )],
            vec![a],
        ),
        // an alert with no event time is in the inverse
        (
            vec![text(
                "Event Date",
                true,
                &["01-10-2026 08:00 - 01-10-2026 09:30"],
            )],
            vec![b, c, d],
        ),
        (
            vec![text(
                "Disposition Date",
                false,
                &["01-12-2026 00:00 - 01-12-2026 23:59"],
            )],
            vec![b],
        ),
        (
            vec![
                text("Disposition", false, &["OPEN"]),
                text("Alert Date", false, &["-24h"]),
            ],
            vec![d],
        ),
    ];
    for (filters, expected) in cases {
        let shown = format!("{filters:?}");
        assert_eq!(
            matching(&service, &actor, filters.clone()).await,
            sorted(expected.clone()),
            "{shown}"
        );
        // and an entry inverted is exactly the rest, when it's the only one
        if let [entry] = filters.as_slice() {
            let mut inverse = entry.clone();
            inverse.inverted = !inverse.inverted;
            let rest: Vec<Uuid> = all
                .iter()
                .copied()
                .filter(|id| !expected.contains(id))
                .collect();
            assert_eq!(
                matching(&service, &actor, vec![inverse]).await,
                rest,
                "the inverse of {shown}"
            );
        }
    }

    // every order, both ways, paged two at a time: total, with the id breaking ties
    let summaries = every_alert(&service, &actor, &AlertQuery::default(), 10)
        .await
        .0;
    assert_eq!(summaries.len(), 4);
    // each row has its queue, the list's Queue column
    let mut queues: Vec<(Uuid, String)> = service
        .alerts(&actor, &AlertQuery::default(), Some(10), None)
        .await
        .expect("lists")
        .alerts
        .into_iter()
        .map(|alert| (alert.id, alert.queue))
        .collect();
    queues.sort();
    let mut expected_queues = vec![
        (a, "default".to_owned()),
        (b, "triage".to_owned()),
        (c, "external".to_owned()),
        (d, "default".to_owned()),
    ];
    expected_queues.sort();
    assert_eq!(queues, expected_queues);
    assert_eq!(
        service.alert(&actor, b).await.expect("reads").summary.queue,
        "triage"
    );
    let titles: std::collections::HashMap<Uuid, (&str, &str)> = [
        (a, ("Phish from evil.example.com", "OPEN")),
        (b, (r"100% off_sale \ invoice", "FALSE_POSITIVE")),
        (c, ("Weekly report", "DELIVERY")),
        (d, (HOSTILE_TITLE, "OPEN")),
    ]
    .into_iter()
    .collect();
    for sort in AlertSort::ALL {
        for descending in [false, true] {
            let query = AlertQuery {
                sort: *sort,
                descending,
                ..AlertQuery::default()
            };
            let mut expected = all.clone();
            match sort {
                AlertSort::AlertDate => {
                    let at = |id: &Uuid| newest.iter().position(|n| n == id).expect("listed");
                    expected.sort_by_key(|id| std::cmp::Reverse(at(id)));
                }
                AlertSort::Description => {
                    expected.sort_by(|x, y| {
                        (titles[x].0.as_bytes(), x).cmp(&(titles[y].0.as_bytes(), y))
                    });
                }
                AlertSort::Disposition => {
                    expected.sort_by(|x, y| (titles[x].1, x).cmp(&(titles[y].1, y)));
                }
                // ace3's Queue order (PLAN.md 7.13): A and D in default, C in external, B in triage
                AlertSort::Queue => {
                    let queue = |id: &Uuid| match id {
                        id if *id == b => "triage",
                        id if *id == c => "external",
                        _ => "default",
                    };
                    expected.sort_by(|x, y| (queue(x), x).cmp(&(queue(y), y)));
                }
            }
            if descending {
                expected.reverse();
            }
            for limit in [1, 2, 3] {
                let (seen, total) = every_alert(&service, &actor, &query, limit).await;
                assert_eq!(total, 4);
                assert_eq!(
                    seen, expected,
                    "{sort:?}, descending {descending}, {limit} a page"
                );
            }
        }
    }

    // an alert that arrives while a client pages is on the first page, and never shifts a later one
    let query = AlertQuery::default();
    let first = service
        .alerts(&actor, &query, Some(2), None)
        .await
        .expect("lists");
    listed(
        &db.clone(),
        Fixture {
            title: "late",
            alerted: &Utc::now().to_rfc3339(),
            ..Fixture::default()
        },
    )
    .await;
    let rest = service
        .alerts(&actor, &query, Some(2), first.next.as_deref())
        .await
        .expect("lists");
    let paged: Vec<Uuid> = first
        .alerts
        .iter()
        .chain(&rest.alerts)
        .map(|alert| alert.id)
        .collect();
    assert_eq!(paged, newest, "each once, and none that arrived meanwhile");
    assert_eq!(rest.next, None);
    assert_eq!(rest.total, 5, "the count is of now");

    // a disposition order's cursor holds the disposition it was read with
    let by_disposition = AlertQuery {
        sort: AlertSort::Disposition,
        ..AlertQuery::default()
    };
    let page = service
        .alerts(&actor, &by_disposition, Some(1), None)
        .await
        .expect("lists");
    let cursor = page.next.expect("more");
    assert!(cursor.starts_with("disposition.desc."), "{cursor}");
    // a cursor of another order, or one that isn't one, is refused
    for (query, cursor) in [
        (&query, cursor.as_str()),
        (
            &by_disposition,
            "alert_date.desc.00000000-0000-0000-0000-000000000000",
        ),
        (&by_disposition, "disposition.desc.not-a-uuid.OPEN"),
        (
            &by_disposition,
            "disposition.desc.00000000-0000-0000-0000-000000000000.open",
        ),
        (&query, "nonsense"),
        (&query, &Uuid::nil().to_string()),
    ] {
        assert!(
            matches!(
                service.alerts(&actor, query, Some(1), Some(cursor)).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{cursor}"
        );
    }
    // past the end, an empty page still says how many match
    let last = service
        .alerts(&actor, &query, Some(1), Some(&a.to_string()))
        .await
        .expect("lists");
    assert_eq!((last.alerts.len(), last.next, last.total), (0, None, 5));

    // a queue order's cursor holds the queue its last alert was read in, whatever text a queue's name
    // has: one with dots and a space pages like any other. An alert moved to a later queue between two
    // pages is met again there, and the page still starts after the queue it was read in, hiding none
    let by_queue = AlertQuery {
        sort: AlertSort::Queue,
        descending: false,
        ..AlertQuery::default()
    };
    set_queues(db, &[(a, "night.shift 2.0"), (d, "night.shift 2.0")]).await;
    let page = service
        .alerts(&actor, &by_queue, Some(4), None)
        .await
        .expect("lists");
    let (ad_first, ad_second) = if a < d { (a, d) } else { (d, a) };
    assert_eq!(
        page.alerts[1..]
            .iter()
            .map(|alert| alert.id)
            .collect::<Vec<_>>(),
        [c, ad_first, ad_second],
        "default (the late one), external, night.shift 2.0 twice by id; triage is next"
    );
    let cursor = page.next.expect("more");
    assert_eq!(cursor, format!("queue.asc.{ad_second}.night.shift 2.0"));
    set_queues(db, &[(ad_second, "zebra")]).await;
    let rest = service
        .alerts(&actor, &by_queue, Some(4), Some(&cursor))
        .await
        .expect("the cursor's own queue, not the alert's new one");
    assert_eq!(
        rest.alerts
            .iter()
            .map(|alert| (alert.id, alert.queue.as_str()))
            .collect::<Vec<_>>(),
        [(b, "triage"), (ad_second, "zebra")]
    );
    assert_eq!(rest.next, None);
    for cursor in [
        // no queue, an empty one, one too long, one with a control character, another order's key
        format!("queue.asc.{a}"),
        format!("queue.asc.{a}."),
        format!("queue.asc.{a}.{}", "q".repeat(65)),
        format!("queue.asc.{a}.a\u{7}b"),
        format!("queue.desc.{a}.default"),
        "queue.asc.not-a-uuid.default".to_owned(),
    ] {
        assert!(
            matches!(
                service
                    .alerts(&actor, &by_queue, Some(1), Some(&cursor))
                    .await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{cursor:?}"
        );
    }
    // a hostile queue in a cursor is a bound value
    let hostile = format!("queue.asc.{a}.'; DROP TABLE analysis.roots; --");
    service
        .alerts(&actor, &by_queue, Some(1), Some(&hostile))
        .await
        .expect("a queue's name is any text");
    assert_eq!(
        root_count(db).await,
        6,
        "five alerts and the root that isn't one"
    );
}

/// Values are data: whatever text a filter holds reaches the query as a bound parameter, a pattern's
/// characters are themselves, and a value past the bounds or of the wrong shape is refused, saying why.
#[tokio::test]
async fn hostile_filter_values_are_refused_or_are_data() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (_, _, _, d) = list_fixtures(db).await;
    let roots = root_count(db).await;

    // a title holding SQL is found by its text, and the text runs nothing
    assert_eq!(
        matching(
            &service,
            &actor,
            vec![text("Description", false, &[HOSTILE_TITLE])]
        )
        .await,
        [d]
    );
    for value in [
        "' OR '1'='1",
        "%' OR 1=1 --",
        "\"; SELECT pg_sleep(10); --",
        "*' OR '1'='1",
        "$1",
        "' UNION SELECT id FROM service.users --",
        "ünïcödé ✓",
    ] {
        for name in ["Description", "Tag", "Disposition By", "Analysis"] {
            let filters = vec![text(name, false, &[value])];
            match service
                .alerts(
                    &actor,
                    &AlertQuery {
                        filters,
                        ..AlertQuery::default()
                    },
                    None,
                    None,
                )
                .await
            {
                Ok(page) => assert!(page.alerts.is_empty(), "{name} {value:?}"),
                // Analysis takes only a module's name
                Err(ServiceError::InvalidRequest(why)) => {
                    assert_eq!(name, "Analysis", "{why}");
                }
                Err(error) => panic!("{name} {value:?}: {error}"),
            }
        }
        assert!(
            matching(&service, &actor, vec![pair(false, "Any", value)])
                .await
                .is_empty()
        );
    }
    assert_eq!(root_count(db).await, roots, "nothing ran");

    let refused = |filters: Vec<FilterEntry>| {
        let service = service.clone();
        let actor = actor.clone();
        async move {
            match service
                .alerts(
                    &actor,
                    &AlertQuery {
                        filters,
                        ..AlertQuery::default()
                    },
                    None,
                    None,
                )
                .await
            {
                Err(ServiceError::InvalidRequest(why)) => why,
                other => panic!("not refused: {other:?}"),
            }
        }
    };
    let long = "x".repeat(filter_model::MAX_FILTER_VALUE_CHARS + 1);
    let many: Vec<String> = (0..=filter_model::MAX_FILTER_VALUES)
        .map(|n| n.to_string())
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    for (filters, says) in [
        (
            vec![text("Description", false, &[&long])],
            "at most 256 characters",
        ),
        (
            vec![text("Description", false, &["a\0b"])],
            "control character",
        ),
        (
            vec![text("Description", false, &["line\nbreak"])],
            "control character",
        ),
        (vec![text("Description", false, &[""])], "can't be empty"),
        (vec![text("Description", false, &many)], "1 to 64 values"),
        (
            vec![FilterEntry::new("Description", false, vec![])],
            "1 to 64 values",
        ),
        (vec![text("Nope", false, &["x"])], "no filter named"),
        (vec![text("Queue", false, &["  "])], "a queue needs a name"),
        (
            vec![text("Queue", false, &[&"q".repeat(65)])],
            "longer than 64 characters",
        ),
        (vec![text("Owner", false, &["alice"])], "no step in PLAN.md"),
        (
            vec![text("Alert Date", false, &["yesterday"])],
            "isn't a date",
        ),
        (vec![text("Alert Date", false, &["-7dd"])], "isn't a date"),
        (
            vec![text("Detection Point", false, &["not-a-uuid"])],
            "signature uuid",
        ),
        (
            vec![text(
                "Detection Point",
                false,
                &[&format!("{SIGNATURE_TWO}:")],
            )],
            "empty version",
        ),
        (
            vec![text("Disposition", false, &["open"])],
            "isn't a disposition",
        ),
        (
            vec![text("Analysis", false, &["Rdap Analyzer"])],
            "module's name",
        ),
        (vec![pair(false, "no_such_type", "x")], "Observable"),
        (vec![pair(false, "file", "not a sha256")], "sha256"),
        (
            vec![text("Observable", false, &["x"])],
            "[type, value] pair",
        ),
        (
            vec![FilterEntry::new(
                "Description",
                false,
                vec![FilterValue::Pair("a".to_owned(), "b".to_owned())],
            )],
            "not a pair",
        ),
    ] {
        let why = refused(filters.clone()).await;
        assert!(why.contains(says), "{filters:?}: {why}");
    }
    let too_many: Vec<FilterEntry> = (0..=filter_model::MAX_FILTER_ENTRIES)
        .map(|n| text("Description", n % 2 == 0, &[&n.to_string()]))
        .chain((0..filter_model::MAX_FILTER_ENTRIES).map(|n| text("Tag", false, &[&n.to_string()])))
        .collect();
    // merged, they're four entries, so that's allowed: a list is bounded once merged
    assert!(matching(&service, &actor, too_many).await.is_empty());
    let names = ["Description", "Tag", "Disposition By", "Analysis"];
    let wide: Vec<FilterEntry> = (0..=filter_model::MAX_FILTER_ENTRIES)
        .map(|n| text(names[n % 4], n % 8 >= 4, &["x"]))
        .collect();
    assert_eq!(
        filter_model::check(FilterScreen::Alerts, &wide)
            .expect("merges")
            .len(),
        8
    );
}

/// ace3's share-link encoding: `[!]<slug>:<v1>,<v2>`, with `:`, `,` and `%` percent-encoded in a value and
/// an observable's type colon literal, ace3's own examples among them.
#[test]
fn share_links_encode_and_decode_as_ace3_s_do() {
    let screen = FilterScreen::Alerts;
    let filters = vec![
        text("Disposition", false, &["OPEN", "FALSE_POSITIVE"]),
        text("Tag", true, &["whitelisted"]),
        text("Alert Date", false, &["-7d"]),
        pair(false, "url", "https://evil.com/a,b"),
        text("Description", false, &["50% off: now"]),
    ];
    let f = filter_model::encode(screen, &filters).expect("encodes");
    assert_eq!(
        f,
        [
            "disposition:OPEN,FALSE_POSITIVE",
            "!tag:whitelisted",
            "alert_date:-7d",
            "observable:url:https%3A%2F%2Fevil.com%2Fa%2Cb",
            "description:50%25%20off%3A%20now",
        ]
    );
    let (decoded, warnings) = filter_model::decode(screen, &f, true).expect("decodes");
    assert_eq!(decoded, filters);
    assert!(warnings.is_empty());

    // ace3's examples, as a wiki holds them
    let (decoded, _) = filter_model::decode(
        screen,
        &[
            "!tag:whitelisted".to_owned(),
            "observable:email_address:a%40b.example".to_owned(),
        ],
        true,
    )
    .expect("decodes");
    assert_eq!(
        decoded,
        [
            text("Tag", true, &["whitelisted"]),
            pair(false, "email_address", "a@b.example")
        ]
    );

    // a filter this list doesn't have is left out, saying why, unless the caller is strict
    let old = ["owner:alice".to_owned(), "disposition:OPEN".to_owned()];
    let (decoded, warnings) = filter_model::decode(screen, &old, false).expect("decodes");
    assert_eq!(decoded, [text("Disposition", false, &["OPEN"])]);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("no owner"), "{warnings:?}");
    // the Queue filter came with 7.13, `$USER_QUEUE` and all
    let (decoded, warnings) =
        filter_model::decode(screen, &["queue:$USER_QUEUE,triage".to_owned()], true)
            .expect("decodes");
    assert_eq!(decoded, [text("Queue", false, &["$USER_QUEUE", "triage"])]);
    assert!(warnings.is_empty());
    assert!(filter_model::decode(screen, &old, true).is_err());
    assert!(
        filter_model::decode(screen, &["nonsense:x".to_owned()], false)
            .expect("decodes")
            .1[0]
            .contains("no filter")
    );

    // a malformed one is refused either way: showing more than its author meant isn't safe
    for broken in [
        "disposition",
        ":x",
        "tag:a,,b",
        "tag:",
        "observable:no-colon",
        "disposition:open",
    ] {
        assert!(
            filter_model::decode(screen, &[broken.to_owned()], false).is_err(),
            "{broken}"
        );
    }
    // the detection points screen has its own slugs
    let (decoded, _) = filter_model::decode(
        FilterScreen::DetectionPoints,
        &[
            format!("signature:{SIGNATURE_ONE}:abc"),
            "family:YARA".to_owned(),
        ],
        true,
    )
    .expect("decodes");
    assert_eq!(
        decoded,
        [
            text(
                "Signature",
                false,
                &[&format!("{}:abc", SIGNATURE_ONE.to_ascii_lowercase())]
            ),
            text("Family", false, &["yara"]),
        ]
    );
}

/// ace3's date range values: relative tokens resolved in the viewer's timezone at the moment of the read,
/// snaps toward the past, `@w` the Sunday before, and absolute endpoints as that zone's wall clock.
#[test]
fn date_ranges_resolve_as_ace3_s_do() {
    let at = |text: &str| -> chrono::DateTime<Utc> { text.parse().expect("a time") };
    // a Sunday, the morning New York moves to summer time
    let now = at("2026-03-08T12:00:00Z");
    let york: chrono_tz::Tz = "America/New_York".parse().expect("a zone");
    let window = |value: &str, tz| filter_model::date_window(value, now, tz).expect(value);
    assert_eq!(window("-7d", york), (at("2026-03-01T12:00:00Z"), now));
    assert_eq!(window("-7d - now", york), (at("2026-03-01T12:00:00Z"), now));
    assert_eq!(window("now", york), (now, now));
    assert_eq!(window("+1d", york), (now, at("2026-03-09T12:00:00Z")));
    assert_eq!(window("-8h30m", york), (at("2026-03-08T03:30:00Z"), now));
    assert_eq!(window("-1d 12h", york), (at("2026-03-07T00:00:00Z"), now));
    assert_eq!(window("-1Y", york), (at("2025-03-08T12:00:00Z"), now));
    // midnight on the change is still winter time, five hours behind
    assert_eq!(window("@d", york), (at("2026-03-08T05:00:00Z"), now));
    assert_eq!(window("now@d", york), (at("2026-03-08T05:00:00Z"), now));
    assert_eq!(window("-1d@d", york), (at("2026-03-07T05:00:00Z"), now));
    assert_eq!(window("@w", york), (at("2026-03-08T05:00:00Z"), now));
    assert_eq!(window("-1d@w", york), (at("2026-03-01T05:00:00Z"), now));
    assert_eq!(window("@mon", york), (at("2026-03-01T05:00:00Z"), now));
    assert_eq!(window("@y", york), (at("2026-01-01T05:00:00Z"), now));
    assert_eq!(window("@h", chrono_tz::Tz::UTC), (now, now));
    assert_eq!(
        window("@d", chrono_tz::Tz::UTC),
        (at("2026-03-08T00:00:00Z"), now)
    );
    assert_eq!(
        window("-1d@d - @d", york),
        (at("2026-03-07T05:00:00Z"), at("2026-03-08T05:00:00Z"))
    );
    // absolute endpoints are the zone's wall clock; 02:30 doesn't happen there that day
    assert_eq!(
        window("03-07-2026 08:00 - 03-08-2026 02:30", york),
        (at("2026-03-07T13:00:00Z"), at("2026-03-08T07:30:00Z"))
    );
    assert_eq!(
        window("-7d - 03-08-2026 08:00", chrono_tz::Tz::UTC),
        (at("2026-03-01T12:00:00Z"), at("2026-03-08T08:00:00Z"))
    );
    // 01:30 on the first Sunday of November happens twice in New York: the later, as pytz takes it
    assert_eq!(
        window("11-01-2026 01:30 - 11-01-2026 01:30", york).0,
        at("2026-11-01T06:30:00Z")
    );
    for bad in [
        "",
        "7d",
        "-7dd",
        "-d",
        "-",
        "@",
        "@x",
        "now@",
        "tomorrow",
        "-7d - now - 1d",
        "13-40-2026 00:00",
        "-9999999999y",
        "- 7d",
    ] {
        assert!(
            filter_model::date_window(bad, now, york).is_err(),
            "{bad:?}"
        );
    }
}

/// 5.6's detection points with 5.10's filters, `changed_since` and the count an export checks first.
#[tokio::test]
async fn detection_points_filter_and_count() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (a, _, c, _) = list_fixtures(db).await;
    // the alert's queue (PLAN.md 7.13): C is in external, and the viewer's queue is the default
    set_queues(db, &[(c, "external")]).await;
    let ids = |page: ace_service::DetectionPointPage| {
        page.detections.iter().map(|d| d.alert).collect::<Vec<_>>()
    };
    let filtered = |filters: Vec<FilterEntry>| DetectionPointFilter {
        filters,
        ..DetectionPointFilter::default()
    };
    for (filters, expected) in [
        (vec![], vec![a, c]),
        (vec![text("Signature", false, &[SIGNATURE_ONE])], vec![a]),
        (
            vec![text("Signature", false, &[&format!("{SIGNATURE_ONE}:v1")])],
            vec![a],
        ),
        (
            vec![text("Signature", false, &[&format!("{SIGNATURE_ONE}:v9")])],
            vec![],
        ),
        (vec![text("Signature", true, &[SIGNATURE_ONE])], vec![c]),
        (vec![text("Family", false, &["YARA"])], vec![a, c]),
        (vec![text("Family", true, &["yara"])], vec![]),
        (
            vec![text(
                "Alert Date",
                false,
                &["01-11-2026 00:00 - 01-12-2026 00:00"],
            )],
            vec![c],
        ),
        (vec![text("Queue", false, &["external"])], vec![c]),
        (vec![text("Queue", true, &["external"])], vec![a]),
        (vec![text("Queue", false, &["$USER_QUEUE"])], vec![a]),
    ] {
        let filter = filtered(filters.clone());
        let page = service
            .detection_points(&actor, &filter, None, None)
            .await
            .expect("lists");
        assert_eq!(ids(page), expected, "{filters:?}");
        assert_eq!(
            service
                .detection_point_count(&actor, &filter, 100)
                .await
                .expect("counts"),
            expected.len() as i64
        );
    }
    // the count stops one past its cap
    assert_eq!(
        service
            .detection_point_count(&actor, &DetectionPointFilter::default(), 0)
            .await
            .expect("counts"),
        1
    );
    // changed_since: a detection made, or whose root became an alert, at or after the time
    let since = DetectionPointFilter {
        changed_since: Some(Utc::now() + chrono::Duration::hours(1)),
        ..DetectionPointFilter::default()
    };
    assert!(
        service
            .detection_points(&actor, &since, None, None)
            .await
            .expect("lists")
            .detections
            .is_empty()
    );
    let since = DetectionPointFilter {
        changed_since: Some(Utc::now() - chrono::Duration::hours(1)),
        ..DetectionPointFilter::default()
    };
    assert_eq!(
        ids(service
            .detection_points(&actor, &since, None, None)
            .await
            .expect("lists")),
        [a, c],
        "both were made in the last hour"
    );
    // a filter of the alert screen isn't this screen's
    assert!(matches!(
        service
            .detection_points(
                &actor,
                &filtered(vec![text("Tag", false, &["x"])]),
                None,
                None
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .detection_point_count(&actor, &filtered(vec![text("Queue", false, &[&"q".repeat(65)])]), 10)
            .await,
        Err(ServiceError::InvalidRequest(why)) if why.contains("longer than 64")
    ));
    let outsider = user(UserId(Uuid::from_u128(0xDE8)));
    exists(db, &Holder::User(UserId(Uuid::from_u128(0xDE8)))).await;
    assert!(matches!(
        service
            .detection_point_count(&outsider, &DetectionPointFilter::default(), 10)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
}

fn saved_rows_query() -> &'static str {
    "SELECT row_to_json(f)::text FROM (SELECT id, user_id, screen, name, description, filters,
            quick_filter_order, quick_filter_indicator FROM service.saved_filters ORDER BY id) f"
}

async fn saved_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(saved_rows_query())
        .fetch_all(db.pool())
        .await
        .expect("reads")
}

fn new_filter(name: &str, filters: Vec<FilterEntry>) -> ace_service::NewSavedFilter {
    ace_service::NewSavedFilter {
        name: name.to_owned(),
        filters,
        ..ace_service::NewSavedFilter::default()
    }
}

/// ace3's saved filters: a person's own on a screen, checked for it, named once, pinned in order, and
/// changed or deleted only by their owner.
#[tokio::test]
async fn saved_filters_are_their_owner_s() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = holding(&service, db, "saver-alice", &[("alert", "read")]).await;
    let bob = holding(&service, db, "saver-bob", &[("alert", "read")]).await;
    let open = vec![text("Disposition", false, &["OPEN"])];
    let first = service
        .create_saved_filter(
            &alice,
            FilterScreen::Alerts,
            &ace_service::NewSavedFilter {
                name: "Open".to_owned(),
                description: Some("<b>mine</b>".to_owned()),
                filters: vec![
                    text("Disposition", false, &["OPEN"]),
                    text("Disposition", false, &["OPEN"]),
                ],
                quick_filter: true,
                quick_filter_indicator: true,
            },
        )
        .await
        .expect("saves");
    assert_eq!(first.filters, open, "merged and canonical");
    assert_eq!(first.quick_filter_order, Some(0));
    assert_eq!(first.description.as_deref(), Some("<b>mine</b>"));
    let second = service
        .create_saved_filter(
            &alice,
            FilterScreen::Alerts,
            &ace_service::NewSavedFilter {
                quick_filter: true,
                ..new_filter("Phish", vec![text("Tag", false, &["phish*"])])
            },
        )
        .await
        .expect("saves");
    assert_eq!(second.quick_filter_order, Some(1));
    let third = service
        .create_saved_filter(
            &alice,
            FilterScreen::Alerts,
            &new_filter("A later one", open.clone()),
        )
        .await
        .expect("saves");
    assert_eq!(third.quick_filter_order, None);
    // the same name on another screen is another filter
    service
        .create_saved_filter(
            &alice,
            FilterScreen::DetectionPoints,
            &new_filter("Open", vec![text("Family", false, &["yara"])]),
        )
        .await
        .expect("saves");
    assert!(matches!(
        service
            .create_saved_filter(&alice, FilterScreen::Alerts, &new_filter("Open", open.clone()))
            .await,
        Err(ServiceError::FilterNameTaken(name)) if name == "Open"
    ));
    // bob may use the name: it's alice's
    service
        .create_saved_filter(
            &bob,
            FilterScreen::Alerts,
            &new_filter("Open", open.clone()),
        )
        .await
        .expect("saves");
    let names = |saved: Vec<ace_service::SavedFilter>| {
        saved
            .into_iter()
            .map(|filter| filter.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(
            service
                .saved_filters(&alice, FilterScreen::Alerts)
                .await
                .expect("lists")
        ),
        ["Open", "Phish", "A later one"],
        "quick filters first, in order, then by name"
    );
    // checked for the screen, and never empty
    for (screen, filters) in [
        (FilterScreen::Alerts, vec![]),
        (FilterScreen::Alerts, vec![text("Family", false, &["yara"])]),
        (
            FilterScreen::DetectionPoints,
            vec![text("Tag", false, &["x"])],
        ),
    ] {
        assert!(matches!(
            service
                .create_saved_filter(&alice, screen, &new_filter("x", filters))
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    for name in ["", "   ", &"n".repeat(256)] {
        assert!(matches!(
            service
                .create_saved_filter(
                    &alice,
                    FilterScreen::Alerts,
                    &new_filter(name, open.clone())
                )
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }

    // only the owner sees, changes or deletes one
    assert_eq!(
        service.saved_filter(&alice, first.id).await.expect("reads"),
        first
    );
    assert!(matches!(
        service.saved_filter(&bob, first.id).await,
        Err(ServiceError::NotFound(_))
    ));
    let rename = ace_service::SavedFilterChange {
        name: Some("Mine".to_owned()),
        ..ace_service::SavedFilterChange::default()
    };
    assert!(matches!(
        service.update_saved_filter(&bob, first.id, &rename).await,
        Err(ServiceError::Forbidden(_))
    ));
    assert!(matches!(
        service.delete_saved_filter(&bob, first.id).await,
        Err(ServiceError::Forbidden(_))
    ));
    assert!(matches!(
        service
            .update_saved_filter(&alice, Uuid::nil(), &rename)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .update_saved_filter(
                &alice,
                first.id,
                &ace_service::SavedFilterChange {
                    name: Some("Phish".to_owned()),
                    ..ace_service::SavedFilterChange::default()
                }
            )
            .await,
        Err(ServiceError::FilterNameTaken(_))
    ));
    // a change is checked for the row's own screen
    assert!(matches!(
        service
            .update_saved_filter(
                &alice,
                first.id,
                &ace_service::SavedFilterChange {
                    filters: Some(vec![text("Family", false, &["yara"])]),
                    ..ace_service::SavedFilterChange::default()
                }
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    let renamed = service
        .update_saved_filter(&alice, first.id, &rename)
        .await
        .expect("renames");
    assert_eq!(renamed.name, "Mine");

    // the quick filters are the whole ordered list
    let quick = service
        .set_quick_filters(&alice, FilterScreen::Alerts, &[third.id, first.id])
        .await
        .expect("pins");
    assert_eq!(names(quick), ["A later one", "Mine", "Phish"]);
    let rows = audit_rows(db).await.len();
    service
        .set_quick_filters(&alice, FilterScreen::Alerts, &[third.id, first.id])
        .await
        .expect("pins");
    assert_eq!(
        audit_rows(db).await.len(),
        rows,
        "the same list again changes nothing"
    );
    for ids in [vec![Uuid::nil()], vec![first.id, first.id]] {
        assert!(matches!(
            service
                .set_quick_filters(&alice, FilterScreen::Alerts, &ids)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    let bobs = service
        .saved_filters(&bob, FilterScreen::Alerts)
        .await
        .expect("lists");
    assert!(
        matches!(
            service
                .set_quick_filters(&alice, FilterScreen::Alerts, &[bobs[0].id])
                .await,
            Err(ServiceError::InvalidRequest(_))
        ),
        "bob's isn't alice's to pin"
    );

    // a person's: a key with no owner, or a component, has none
    let ownerless = Actor::ApiKey {
        id: ApiKeyId(Uuid::from_u128(0x5AF)),
        name: "ownerless".to_owned(),
        owner: None,
    };
    exists(db, &Holder::ApiKey(ApiKeyId(Uuid::from_u128(0x5AF)))).await;
    grant(
        db,
        &Holder::ApiKey(ApiKeyId(Uuid::from_u128(0x5AF))),
        "alert",
        "read",
        Effect::Allow,
    )
    .await;
    assert!(matches!(
        service
            .saved_filters(&ownerless, FilterScreen::Alerts)
            .await,
        Err(ServiceError::Forbidden(_))
    ));
    assert!(matches!(
        service
            .create_saved_filter(
                &ownerless,
                FilterScreen::Alerts,
                &new_filter("k", open.clone())
            )
            .await,
        Err(ServiceError::Forbidden(_))
    ));
    // and it needs the screen's permission first
    let nobody = holding(&service, db, "saver-nobody", &[]).await;
    assert!(matches!(
        service.saved_filters(&nobody, FilterScreen::Alerts).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service
            .create_saved_filter(
                &nobody,
                FilterScreen::Alerts,
                &new_filter("n", open.clone())
            )
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.delete_saved_filter(&nobody, first.id).await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    service
        .delete_saved_filter(&alice, first.id)
        .await
        .expect("deletes");
    assert!(matches!(
        service.saved_filter(&alice, first.id).await,
        Err(ServiceError::NotFound(_))
    ));
    // a user's rows go with the user
    sqlx::query("DELETE FROM service.users WHERE id = $1")
        .bind(actor_id(&bob).0)
        .execute(db.pool())
        .await
        .expect("deletes bob");
    assert!(
        !saved_rows(db)
            .await
            .iter()
            .any(|row| row.contains(&actor_id(&bob).0.to_string()))
    );
}

/// A user has at most `MAX_SAVED_FILTERS` on a screen.
#[tokio::test]
async fn saved_filters_are_bounded() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = holding(&service, db, "bounded", &[("alert", "read")]).await;
    sqlx::query(
        "INSERT INTO service.saved_filters (id, user_id, screen, name, filters)
         SELECT gen_random_uuid(), $1, 'alerts', 'f' || n, '[]' FROM generate_series(1, $2) n",
    )
    .bind(actor_id(&alice).0)
    .bind(ace_service::MAX_SAVED_FILTERS as i32)
    .execute(db.pool())
    .await
    .expect("fills");
    assert!(matches!(
        service
            .create_saved_filter(
                &alice,
                FilterScreen::Alerts,
                &new_filter("one more", vec![text("Disposition", false, &["OPEN"])])
            )
            .await,
        Err(ServiceError::InvalidRequest(why)) if why.contains("at most 200")
    ));
}

/// ace3's `manage_columns`: normalized as its validators do, and a stored value from an older release
/// still reads.
#[tokio::test]
async fn manage_columns_is_normalized() {
    use ace_service::{ManageColumnsPreference, PreferenceKey, PreferenceValue};
    let normal = ManageColumnsPreference::default();
    assert_eq!(
        normal.order,
        ["date", "description", "queue", "disposition", "status"],
        "ace3's order, without the columns that come later"
    );
    assert!(normal.hidden.is_empty());
    let parsed = PreferenceKey::ManageColumns
        .parse(json!({
            "order": ["status", "remediation", "status", "description"],
            "hidden": ["description", "date", "owner", "date"],
        }))
        .expect("parses");
    let PreferenceValue::ManageColumns(columns) = parsed else {
        panic!("manage_columns")
    };
    assert_eq!(
        columns.order,
        ["status", "description", "date", "queue", "disposition"]
    );
    assert_eq!(columns.hidden, ["date"], "description is always shown");
    assert_eq!(
        columns
            .visible()
            .iter()
            .map(|column| column.id)
            .collect::<Vec<_>>(),
        ["status", "description", "queue", "disposition"]
    );
    assert!(
        PreferenceKey::ManageColumns
            .parse(json!({"order": [], "extra": 1}))
            .is_err()
    );
    assert!(PreferenceKey::ManageColumns.parse(json!([])).is_err());

    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let alice = holding(&service, db, "columns", &[]).await;
    assert_eq!(service.manage_columns(&alice).await.expect("reads"), normal);
    service
        .set_preference(&alice, &PreferenceValue::ManageColumns(columns.clone()))
        .await
        .expect("sets");
    assert_eq!(
        service.manage_columns(&alice).await.expect("reads"),
        columns
    );
    // a key has only the default
    let key = key(ApiKeyId(Uuid::from_u128(0xC01)), None);
    assert_eq!(service.manage_columns(&key).await.expect("reads"), normal);
}

async fn create_saved_filter_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-save-filter", &[("alert", "read")]).await;
    let saved = service
        .create_saved_filter(
            &me,
            FilterScreen::Alerts,
            &ace_service::NewSavedFilter {
                name: "<b>Open</b>".to_owned(),
                description: Some("mine".to_owned()),
                filters: vec![text("Disposition", false, &["OPEN"])],
                quick_filter: true,
                quick_filter_indicator: false,
            },
        )
        .await
        .expect("saves");
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "create_saved_filter".to_owned(),
            target: ("saved_filter".to_owned(), saved.id.to_string()),
            before: None,
            after: Some(json!({
                "screen": "alerts",
                "owner": actor_id(&me).0,
                "name": "<b>Open</b>",
                "description": "mine",
                "filters": [{"name": "Disposition", "inverted": false, "values": ["OPEN"]}],
                "quick_filter_order": 0,
                "quick_filter_indicator": false,
            })),
            details: json!({}),
        }
    );
    "create_saved_filter".to_owned()
}

async fn update_saved_filter_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-update-filter", &[("alert", "read")]).await;
    let saved = service
        .create_saved_filter(
            &me,
            FilterScreen::Alerts,
            &new_filter("before", vec![text("Disposition", false, &["OPEN"])]),
        )
        .await
        .expect("saves");
    let change = ace_service::SavedFilterChange {
        name: Some("after".to_owned()),
        filters: Some(vec![pair(false, "url", "https://a.example/x,y")]),
        ..ace_service::SavedFilterChange::default()
    };
    service
        .update_saved_filter(&me, saved.id, &change)
        .await
        .expect("changes");
    let record = |name: &str, filters: Value| {
        json!({
            "screen": "alerts",
            "owner": actor_id(&me).0,
            "name": name,
            "description": null,
            "filters": filters,
            "quick_filter_order": null,
            "quick_filter_indicator": false,
        })
    };
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "update_saved_filter".to_owned(),
            target: ("saved_filter".to_owned(), saved.id.to_string()),
            before: Some(record(
                "before",
                json!([{"name": "Disposition", "inverted": false, "values": ["OPEN"]}])
            )),
            after: Some(record(
                "after",
                json!([{"name": "Observable", "inverted": false, "values": [["url", "https://a.example/x,y"]]}])
            )),
            details: json!({}),
        }
    );
    // the same change again changes nothing, and has no row
    let rows = audit_rows(db).await.len();
    service
        .update_saved_filter(&me, saved.id, &change)
        .await
        .expect("changes");
    assert_eq!(audit_rows(db).await.len(), rows);
    "update_saved_filter".to_owned()
}

async fn delete_saved_filter_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-delete-filter", &[("alert", "read")]).await;
    let saved = service
        .create_saved_filter(
            &me,
            FilterScreen::Alerts,
            &new_filter("gone", vec![text("Tag", true, &["noise"])]),
        )
        .await
        .expect("saves");
    service
        .delete_saved_filter(&me, saved.id)
        .await
        .expect("deletes");
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "delete_saved_filter".to_owned(),
            target: ("saved_filter".to_owned(), saved.id.to_string()),
            before: Some(json!({
                "screen": "alerts",
                "owner": actor_id(&me).0,
                "name": "gone",
                "description": null,
                "filters": [{"name": "Tag", "inverted": true, "values": ["noise"]}],
                "quick_filter_order": null,
                "quick_filter_indicator": false,
            })),
            after: None,
            details: json!({}),
        }
    );
    "delete_saved_filter".to_owned()
}

async fn set_quick_filters_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-quick", &[("alert", "read")]).await;
    let one = service
        .create_saved_filter(
            &me,
            FilterScreen::Alerts,
            &ace_service::NewSavedFilter {
                quick_filter: true,
                ..new_filter("one", vec![text("Disposition", false, &["OPEN"])])
            },
        )
        .await
        .expect("saves");
    let two = service
        .create_saved_filter(
            &me,
            FilterScreen::Alerts,
            &new_filter("two", vec![text("Disposition", false, &["IGNORE"])]),
        )
        .await
        .expect("saves");
    service
        .set_quick_filters(&me, FilterScreen::Alerts, &[two.id])
        .await
        .expect("pins");
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "set_quick_filters".to_owned(),
            target: (
                "quick_filters".to_owned(),
                format!("{}/alerts", actor_id(&me).0)
            ),
            before: Some(json!({"pinned": [one.id]})),
            after: Some(json!({"pinned": [two.id]})),
            details: json!({}),
        }
    );
    "set_quick_filters".to_owned()
}

async fn seed_saved_filters_records_its_row(db: &Db) -> String {
    let service = service(db);
    let me = holding(&service, db, "audited-seed", &[("alert", "read")]).await;
    let seeded = service
        .seed_saved_filters(&me, FilterScreen::Alerts)
        .await
        .expect("seeds");
    assert_eq!(seeded.len(), 2);
    let record = |name: &str, description: &str, window: &str, order: i32| {
        json!({
            "screen": "alerts",
            "owner": actor_id(&me).0,
            "name": name,
            "description": description,
            "filters": [
                {"name": "Queue", "inverted": false, "values": ["$USER_QUEUE"]},
                {"name": "Alert Date", "inverted": false, "values": [window]},
            ],
            "quick_filter_order": order,
            "quick_filter_indicator": false,
        })
    };
    assert_eq!(
        last_audit(db).await,
        AuditRow {
            actor: actor_json(&me),
            action: "seed_saved_filters".to_owned(),
            target: (
                "quick_filters".to_owned(),
                format!("{}/alerts", actor_id(&me).0)
            ),
            before: None,
            after: Some(json!({"filters": [
                record("Last 24h", "Alerts in your queue from the last 24 hours", "-24h", 0),
                record("Last 7d", "Alerts in your queue from the last 7 days", "-7d", 1),
            ]})),
            details: json!({}),
        }
    );
    "seed_saved_filters".to_owned()
}

/// ace3's `ensure_default_saved_filters` (PLAN.md 7.13): a person new to the alert list gets `Last 24h` and
/// `Last 7d` as quick filters, once. Each is the viewer's queue and a relative window, so it lists what its
/// name says for whoever has it. Someone who had filters already gets none, and someone who deletes the
/// two doesn't get them back.
#[tokio::test]
async fn a_person_new_to_the_alert_list_gets_ace3_s_quick_filters() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let me = holding(&service, db, "new-analyst", &[("alert", "read")]).await;
    let (a, b, _, d) = list_fixtures(db).await;
    // D alerted just now, A and B in January; the viewer works triage, where B and D are
    set_queues(db, &[(b, "triage"), (d, "triage")]).await;
    sqlx::query("UPDATE service.users SET queue = 'triage' WHERE id = $1")
        .bind(actor_id(&me).0)
        .execute(db.pool())
        .await
        .expect("sets the viewer's queue");
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() - interval '3 days' WHERE id = $1")
        .bind(b)
        .execute(db.pool())
        .await
        .expect("B alerted three days ago");
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() - interval '1 hour' WHERE id = $1")
        .bind(a)
        .execute(db.pool())
        .await
        .expect("A alerted an hour ago, in the default queue");

    assert!(
        service
            .saved_filters(&me, FilterScreen::Alerts)
            .await
            .expect("lists")
            .is_empty(),
        "reading seeds nothing"
    );
    let audits = audit_rows(db).await.len();
    let seeded = service
        .seed_saved_filters(&me, FilterScreen::Alerts)
        .await
        .expect("seeds");
    assert_eq!(audit_rows(db).await.len(), audits + 1, "one row for both");
    let listed = service
        .saved_filters(&me, FilterScreen::Alerts)
        .await
        .expect("lists");
    assert_eq!(seeded, listed);
    assert_eq!(
        listed
            .iter()
            .map(|filter| (
                filter.name.as_str(),
                filter.description.as_deref(),
                filter.quick_filter_order,
                filter.quick_filter_indicator
            ))
            .collect::<Vec<_>>(),
        [
            (
                "Last 24h",
                Some("Alerts in your queue from the last 24 hours"),
                Some(0),
                false
            ),
            (
                "Last 7d",
                Some("Alerts in your queue from the last 7 days"),
                Some(1),
                false
            ),
        ]
    );
    // each lists what it says: the viewer's queue, in its window
    assert_eq!(
        matching(&service, &me, listed[0].filters.clone()).await,
        [d]
    );
    assert_eq!(
        matching(&service, &me, listed[1].filters.clone()).await,
        sorted(vec![b, d])
    );

    // once: a second call adds nothing, and nor does one after the person deleted them
    let audits = audit_rows(db).await.len();
    assert!(
        service
            .seed_saved_filters(&me, FilterScreen::Alerts)
            .await
            .expect("nothing to do")
            .is_empty()
    );
    for filter in &listed {
        service
            .delete_saved_filter(&me, filter.id)
            .await
            .expect("deletes");
    }
    assert!(
        service
            .seed_saved_filters(&me, FilterScreen::Alerts)
            .await
            .expect("nothing to do")
            .is_empty()
    );
    assert!(
        service
            .saved_filters(&me, FilterScreen::Alerts)
            .await
            .expect("lists")
            .is_empty(),
        "deleted filters stay deleted"
    );
    assert_eq!(
        audit_rows(db).await.len(),
        audits + 2,
        "only the two deletes"
    );

    // someone with a saved filter already isn't new: they get none, then or later
    let settled = holding(&service, db, "settled-analyst", &[("alert", "read")]).await;
    let own = service
        .create_saved_filter(
            &settled,
            FilterScreen::Alerts,
            &new_filter("Last 24h", vec![text("Disposition", false, &["OPEN"])]),
        )
        .await
        .expect("saves");
    for _ in 0..2 {
        assert!(
            service
                .seed_saved_filters(&settled, FilterScreen::Alerts)
                .await
                .expect("nothing to do")
                .is_empty()
        );
    }
    service
        .delete_saved_filter(&settled, own.id)
        .await
        .expect("deletes");
    assert!(
        service
            .seed_saved_filters(&settled, FilterScreen::Alerts)
            .await
            .expect("nothing to do")
            .is_empty()
    );

    // a screen with no defaults has none, and seeding is a person's, under the screen's permission
    assert!(
        service
            .seed_saved_filters(&me, FilterScreen::DetectionPoints)
            .await
            .expect("nothing to do")
            .is_empty()
    );
    let outsider = holding(&service, db, "seed-outsider", &[]).await;
    assert!(matches!(
        service
            .seed_saved_filters(&outsider, FilterScreen::Alerts)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    let ace = component("alert_reader");
    grant(
        db,
        &Holder::Component(Component::new("alert_reader").expect("valid")),
        "alert",
        "read",
        Effect::Allow,
    )
    .await;
    assert!(matches!(
        service.seed_saved_filters(&ace, FilterScreen::Alerts).await,
        Err(ServiceError::Forbidden(_))
    ));
    let seeds: i64 = sqlx::query_scalar("SELECT count(*) FROM service.saved_filter_seeds")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(seeds, 2, "the two people, and nobody refused");
}

// PLAN.md 5.11's events (6a): ace3's events, threat types and threats.

/// An event named `name` on today's date with these alerts, written as ace3's GUI writes one: each
/// reference row the first by id, the risk level the first by value, as ace3's `add_to_event` takes them.
async fn event_with(db: &Db, name: &str, alerts: &[Uuid]) -> i64 {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO events.events
             (creation_date, name, status_id, remediation_id, type_id, vector_id, risk_level_id,
              prevention_tool_id)
         VALUES (current_date, $1, (SELECT min(id) FROM events.statuses),
                 (SELECT min(id) FROM events.remediations), (SELECT min(id) FROM events.types),
                 (SELECT min(id) FROM events.vectors),
                 (SELECT id FROM events.risk_levels ORDER BY value LIMIT 1),
                 (SELECT min(id) FROM events.prevention_tools))
         RETURNING id",
    )
    .bind(name)
    .fetch_one(db.pool())
    .await
    .expect("makes an event");
    for alert in alerts {
        sqlx::query("INSERT INTO events.event_alerts (event_id, root_id) VALUES ($1, $2)")
            .bind(id)
            .bind(alert)
            .execute(db.pool())
            .await
            .expect("adds an alert");
    }
    id
}

async fn malware_named(db: &Db, name: &str) -> i32 {
    sqlx::query_scalar("INSERT INTO events.malware (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(db.pool())
        .await
        .expect("makes malware")
}

async fn threat_type_id(db: &Db, name: &str) -> i32 {
    sqlx::query_scalar("SELECT id FROM events.threat_types WHERE name = $1")
        .bind(name)
        .fetch_one(db.pool())
        .await
        .expect("a seeded type")
}

/// Every row an event write could touch, whole.
async fn event_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'event ' || row_to_json(e)::text FROM events.events e
         UNION ALL SELECT 'type ' || row_to_json(t)::text FROM events.threat_types t
         UNION ALL SELECT 'threat ' || row_to_json(m)::text FROM events.malware_threats m
         UNION ALL SELECT 'in event ' || row_to_json(a)::text FROM events.event_alerts a
         UNION ALL SELECT 'campaign ' || row_to_json(c)::text FROM events.campaigns c
         UNION ALL SELECT 'malware ' || row_to_json(w)::text FROM events.malware w
         UNION ALL SELECT 'event malware ' || row_to_json(em)::text FROM events.event_malware em
         UNION ALL SELECT 'tag ' || row_to_json(g)::text FROM events.event_tags g
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// A user holding nothing to do with events.
async fn no_events(db: &Db) -> Actor {
    let id = UserId(Uuid::from_u128(0xE0));
    exists(db, &Holder::User(id)).await;
    user(id)
}

async fn set_event_status_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = event_with(db, "<b>status</b>", &[]).await;
    let uuid: Uuid = sqlx::query_scalar("SELECT uuid FROM events.events WHERE id = $1")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    let set = service
        .set_event_status(&actor, EventRef::Uuid(uuid), "CLOSED")
        .await
        .expect("sets");
    assert_eq!(set.status, "CLOSED");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "set_event_status".to_owned(),
            target: ("event".to_owned(), id.to_string()),
            before: Some(json!({"status": "OPEN"})),
            after: Some(json!({"status": "CLOSED"})),
            details: json!({"uuid": uuid, "name": "<b>status</b>"}),
        }
    );

    // the status it has, one that isn't one, no such event and a refusal have no row
    let rows = audit_rows(db).await.len();
    let same = service
        .set_event_status(&actor, EventRef::Id(id), "CLOSED")
        .await
        .expect("changes nothing");
    assert_eq!(same, set);
    assert!(matches!(
        service
            .set_event_status(&actor, EventRef::Id(id), "closed")
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .set_event_status(&actor, EventRef::Id(i64::MAX), "OPEN")
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .set_event_status(&no_events(db).await, EventRef::Id(id), "OPEN")
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn create_threat_type_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let made = service
        .create_threat_type(&actor, "<script>x</script>")
        .await
        .expect("adds");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_threat_type".to_owned(),
            target: ("threat_type".to_owned(), made.id.to_string()),
            before: None,
            after: Some(json!({"id": made.id, "name": "<script>x</script>"})),
            details: json!({}),
        }
    );

    // a taken name, one of ace3's seeded ones, a name that isn't one and a refusal have no row
    let rows = audit_rows(db).await.len();
    for taken in ["<script>x</script>", "ransomware"] {
        assert!(
            matches!(
                service.create_threat_type(&actor, taken).await,
                Err(ServiceError::Conflict(_))
            ),
            "{taken}"
        );
    }
    assert!(matches!(
        service.create_threat_type(&actor, " ").await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .create_threat_type(&no_events(db).await, "refused")
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn rename_threat_type_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let made = service
        .create_threat_type(&actor, "before the rename")
        .await
        .expect("adds");
    let renamed = service
        .rename_threat_type(&actor, made.id, "after the rename")
        .await
        .expect("renames");
    assert_eq!(renamed.name, "after the rename");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "rename_threat_type".to_owned(),
            target: ("threat_type".to_owned(), made.id.to_string()),
            before: Some(json!({"name": "before the rename"})),
            after: Some(json!({"name": "after the rename"})),
            details: json!({}),
        }
    );

    let rows = audit_rows(db).await.len();
    assert_eq!(
        service
            .rename_threat_type(&actor, made.id, "after the rename")
            .await
            .expect("changes nothing"),
        renamed
    );
    assert!(matches!(
        service.rename_threat_type(&actor, made.id, "rat").await,
        Err(ServiceError::Conflict(_))
    ));
    assert!(matches!(
        service.rename_threat_type(&actor, i32::MAX, "x").await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn delete_threat_type_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let made = service
        .create_threat_type(&actor, "to delete")
        .await
        .expect("adds");
    service
        .delete_threat_type(&actor, made.id)
        .await
        .expect("deletes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_threat_type".to_owned(),
            target: ("threat_type".to_owned(), made.id.to_string()),
            before: Some(json!({"id": made.id, "name": "to delete"})),
            after: None,
            details: json!({}),
        }
    );

    // gone, and one that malware has stays, as in ace3
    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service.delete_threat_type(&actor, made.id).await,
        Err(ServiceError::NotFound(_))
    ));
    let used = threat_type_id(db, "botnet").await;
    let malware = malware_named(db, "delete-guard").await;
    sqlx::query("INSERT INTO events.malware_threats VALUES ($1, $2)")
        .bind(malware)
        .bind(used)
        .execute(db.pool())
        .await
        .expect("maps");
    assert!(matches!(
        service.delete_threat_type(&actor, used).await,
        Err(ServiceError::Conflict(ref e)) if e.contains("used by 1 malware")
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn add_threat_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let malware = malware_named(db, "Emotet").await;
    let kind = threat_type_id(db, "downloader").await;
    let added = service
        .add_threat(&actor, malware, kind)
        .await
        .expect("adds");
    assert_eq!(added.threat_type_name, "downloader");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_threat".to_owned(),
            target: ("threat".to_owned(), format!("{malware}/{kind}")),
            before: None,
            after: Some(json!({
                "malware_id": malware,
                "malware_name": "Emotet",
                "threat_type_id": kind,
                "threat_type_name": "downloader",
            })),
            details: json!({}),
        }
    );

    // ace3's database refuses these with a 500; here they're a conflict and a 404
    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service.add_threat(&actor, malware, kind).await,
        Err(ServiceError::Conflict(_))
    ));
    assert!(matches!(
        service.add_threat(&actor, i32::MAX, kind).await,
        Err(ServiceError::NotFound(ref e)) if e.contains("malware")
    ));
    assert!(matches!(
        service.add_threat(&actor, malware, i32::MAX).await,
        Err(ServiceError::NotFound(ref e)) if e.contains("threat type")
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn remove_threat_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let malware = malware_named(db, "Qakbot").await;
    let kind = threat_type_id(db, "infostealer").await;
    service
        .add_threat(&actor, malware, kind)
        .await
        .expect("adds");
    service
        .remove_threat(&actor, malware, kind)
        .await
        .expect("removes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "remove_threat".to_owned(),
            target: ("threat".to_owned(), format!("{malware}/{kind}")),
            before: Some(json!({
                "malware_id": malware,
                "malware_name": "Qakbot",
                "threat_type_id": kind,
                "threat_type_name": "infostealer",
            })),
            after: None,
            details: json!({}),
        }
    );

    let rows = audit_rows(db).await.len();
    assert!(matches!(
        service.remove_threat(&actor, malware, kind).await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// ace3's events as its router serves them: by id or uuid, with its alerts, its malware and their threat
/// types, its owner, its tags and its alerts' tags, and a disposition rolled up from its alerts'; the open
/// ones a page at a time; and the export's events. `event:read` is needed for each.
#[tokio::test]
async fn events_are_read_as_ace3_serves_them() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let reader = holding(&service, db, "event-reader", &[("event", "read")]).await;

    // two alerts, one dispositioned, one with tagged observables
    let first = alert(db).await;
    let second = alert(db).await;
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = now() - interval '1 hour', description = '<i>first</i>'
         WHERE id = $1",
    )
    .bind(first)
    .execute(db.pool())
    .await
    .expect("alerts");
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(second)
        .execute(db.pool())
        .await
        .expect("alerts");
    service
        .disposition(&boss, first, "DELIVERY")
        .await
        .expect("dispositions");
    sqlx::query("UPDATE analysis.observables SET tags = '{zeta, Alpha}' WHERE root_id = $1")
        .bind(second)
        .execute(db.pool())
        .await
        .expect("tags");

    let hostile = "<script>alert(1)</script>";
    let id = event_with(db, hostile, &[second, first]).await;
    let campaign: i32 =
        sqlx::query_scalar("INSERT INTO events.campaigns (name) VALUES ('APT-x') RETURNING id")
            .fetch_one(db.pool())
            .await
            .expect("a campaign");
    let emotet = malware_named(db, "Emotet").await;
    for kind in ["downloader", "botnet"] {
        let kind = threat_type_id(db, kind).await;
        service
            .add_threat(&boss, emotet, kind)
            .await
            .expect("a threat");
    }
    let bare = malware_named(db, "Unnamed").await;
    sqlx::query(
        "UPDATE events.events SET owner_id = $2, campaign_id = $3, comment = $4,
             alert_time = '2026-03-04T05:06:07Z' WHERE id = $1",
    )
    .bind(id)
    .bind(Uuid::from_u128(0xAD))
    .bind(campaign)
    .bind(hostile)
    .execute(db.pool())
    .await
    .expect("records");
    for malware in [emotet, bare] {
        sqlx::query("INSERT INTO events.event_malware VALUES ($1, $2)")
            .bind(id)
            .bind(malware)
            .execute(db.pool())
            .await
            .expect("records malware");
    }
    sqlx::query("INSERT INTO events.event_tags VALUES ($1, 'phish-kit'), ($1, 'Campaign')")
        .bind(id)
        .execute(db.pool())
        .await
        .expect("tags the event");

    let event = service
        .event(&reader, EventRef::Id(id))
        .await
        .expect("reads");
    assert_eq!(event.name, hostile, "as it was written");
    assert_eq!(event.comment.as_deref(), Some(hostile));
    assert_eq!(
        (
            event.status.as_str(),
            event.remediation.as_str(),
            event.kind.as_str(),
            event.vector.as_str(),
            event.risk_level.as_str(),
            event.prevention_tool.as_str(),
        ),
        (
            "OPEN",
            "not remediated",
            "phish",
            "corporate email",
            "0",
            "response team"
        ),
        "ace3's defaults"
    );
    assert_eq!(event.campaign.as_deref(), Some("APT-x"));
    let owner = event.owner.clone().expect("an owner");
    assert_eq!(owner.id, UserId(Uuid::from_u128(0xAD)));
    assert_eq!(event.disposition, "DELIVERY", "its alerts' highest");
    assert_eq!(
        event.alerts.iter().map(|a| a.id).collect::<Vec<_>>(),
        [first, second],
        "oldest alert first"
    );
    assert_eq!(event.alerts[0].title, "<i>first</i>");
    assert_eq!(event.alerts[0].disposition.as_deref(), Some("DELIVERY"));
    assert_eq!(
        event.alerts[0]
            .dispositioned_by
            .as_ref()
            .map(|a| a.kind.as_str()),
        Some("user")
    );
    assert_eq!(event.alerts[1].disposition, None);
    assert_eq!(event.tags, ["Campaign", "phish-kit"]);
    assert_eq!(event.alert_tags, ["Alpha", "zeta"]);
    assert_eq!(
        event
            .malware
            .iter()
            .map(|m| (m.name.as_str(), m.threat_types.clone()))
            .collect::<Vec<_>>(),
        [
            ("Emotet", vec!["botnet".to_owned(), "downloader".to_owned()]),
            ("Unnamed", vec![]),
        ]
    );
    assert_eq!(event.threat_types(), ["botnet", "downloader"]);
    assert_eq!(
        service
            .event(&reader, EventRef::Uuid(event.uuid))
            .await
            .expect("reads"),
        event,
        "by its uuid too"
    );
    for missing in [EventRef::Id(i64::MAX), EventRef::Uuid(Uuid::nil())] {
        assert!(matches!(
            service.event(&reader, missing).await,
            Err(ServiceError::NotFound(_))
        ));
    }

    // an event with no alerts is DELIVERY, as ace3's roll-up has it, and only open events are listed
    let empty = event_with(db, "empty", &[]).await;
    let closed = event_with(db, "closed", &[first]).await;
    service
        .set_event_status(&boss, EventRef::Id(closed), "CLOSED")
        .await
        .expect("closes");
    let page = service.open_events(&reader, None, 1).await.expect("lists");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0], event);
    assert_eq!(page.next, Some(id));
    let page = service
        .open_events(&reader, page.next, 1)
        .await
        .expect("lists");
    assert_eq!(page.events[0].id, empty);
    assert_eq!(page.events[0].disposition, "DELIVERY");
    assert_eq!(page.next, None, "the closed one isn't open");
    for limit in [0, ace_service::MAX_EVENTS_PAGE + 1] {
        assert!(matches!(
            service.open_events(&reader, None, limit).await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }

    // the export's events, in id order, leaving out an id with no event
    let exported = service
        .events_for_export(&reader, &[closed, i64::MAX, id])
        .await
        .expect("exports");
    assert_eq!(
        exported.iter().map(|e| e.id).collect::<Vec<_>>(),
        [id, closed]
    );
    let too_many: Vec<i64> = (0..=ace_service::MAX_EXPORT_EVENTS as i64).collect();
    assert!(matches!(
        service.events_for_export(&reader, &too_many).await,
        Err(ServiceError::TooLarge(_))
    ));

    // threat types by name, and the threats by malware
    let types = service.threat_types(&reader).await.expect("lists");
    assert_eq!(types.len(), 13, "ace3's seeded list");
    let names: Vec<&str> = types.iter().map(|t| t.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    let botnet = threat_type_id(db, "botnet").await;
    assert_eq!(
        service
            .threat_type(&reader, botnet)
            .await
            .expect("reads")
            .name,
        "botnet"
    );
    let threats = service.threats(&reader, Some(emotet)).await.expect("lists");
    assert_eq!(
        threats
            .iter()
            .map(|t| t.threat_type_name.as_str())
            .collect::<Vec<_>>(),
        ["botnet", "downloader"]
    );
    assert!(
        service
            .threats(&reader, Some(bare))
            .await
            .expect("lists")
            .is_empty()
    );
    assert_eq!(
        service.threats(&reader, None).await.expect("lists"),
        threats
    );

    // a reader can't write, and someone with no event permission can't read
    assert!(matches!(
        service.create_threat_type(&reader, "nope").await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    let outsider = no_events(db).await;
    let refused = [
        service.event(&outsider, EventRef::Id(id)).await.map(|_| ()),
        service.open_events(&outsider, None, 10).await.map(|_| ()),
        service
            .events_for_export(&outsider, &[id])
            .await
            .map(|_| ()),
        service.threat_types(&outsider).await.map(|_| ()),
        service.threat_type(&outsider, botnet).await.map(|_| ()),
        service.threats(&outsider, None).await.map(|_| ()),
        service.closed_events(&outsider, None, 10).await.map(|_| ()),
    ];
    for result in refused {
        assert!(matches!(
            result,
            Err(ServiceError::PermissionDenied { ref permission, .. })
                if permission.to_string() == "event:read"
        ));
    }

    // an alert that's deleted leaves its events
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(second)
        .execute(db.pool())
        .await
        .expect("deletes");
    let event = service
        .event(&reader, EventRef::Id(id))
        .await
        .expect("reads");
    assert_eq!(event.alerts.len(), 1);
    assert!(event.alert_tags.is_empty());
}

// PLAN.md 5.11's events (6b): adding alerts to an event, ace3's add_to_event.

/// A root made an alert at `at`.
async fn alert_at(db: &Db, at: &str) -> Uuid {
    let root = alert(db).await;
    sqlx::query("UPDATE analysis.roots SET alerted_at = $2::timestamptz WHERE id = $1")
        .bind(root)
        .bind(at)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    root
}

fn at(text: &str) -> chrono::DateTime<chrono::Utc> {
    text.parse().expect("a time")
}

fn new_event(name: &str) -> EventChoice {
    EventChoice::New(NewEvent {
        name: name.to_owned(),
        ..NewEvent::default()
    })
}

/// The alerts in an event, by id.
async fn in_event(db: &Db, event: i64) -> BTreeSet<Uuid> {
    sqlx::query_scalar("SELECT root_id FROM events.event_alerts WHERE event_id = $1")
        .bind(event)
        .fetch_all(db.pool())
        .await
        .expect("reads")
        .into_iter()
        .collect()
}

async fn add_to_event_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let older = alert_at(db, "2026-01-02T03:04:05Z").await;
    let newer = alert_at(db, "2026-01-03T00:00:00Z").await;
    let not_an_alert = alert(db).await;
    let gone = Uuid::from_u128(0x6011E);
    let times = EventTimes {
        event_time: Some(at("2026-01-01T00:00:00Z")),
        alert_time: Some(at("2026-01-02T03:04:05Z")),
        ownership_time: Some(at("2026-01-02T03:04:05Z")),
        ..EventTimes::default()
    };
    let added = service
        .add_to_event(
            &actor,
            &EventChoice::New(NewEvent {
                name: "  <b>new</b> event  ".to_owned(),
                comment: Some("first look".to_owned()),
                times,
            }),
            &[newer, older, gone, not_an_alert, older],
        )
        .await
        .expect("adds");
    assert!(added.made);
    assert_eq!(added.added, [newer, older]);
    assert_eq!(added.missing, [gone, not_an_alert]);
    assert!(added.already.is_empty());
    let event = &added.event;
    assert_eq!(event.name, "<b>new</b> event", "trimmed, as ace3 trims it");
    assert_eq!(
        event.creation_date.to_string(),
        "2026-01-02",
        "its oldest alert's day"
    );
    assert_eq!(
        (
            event.status.as_str(),
            event.remediation.as_str(),
            event.kind.as_str(),
            event.vector.as_str(),
            event.risk_level.as_str(),
            event.prevention_tool.as_str(),
        ),
        (
            "OPEN",
            "not remediated",
            "phish",
            "corporate email",
            "0",
            "response team"
        ),
        "ace3's defaults: the first of each by id, the risk level first by value"
    );
    assert_eq!(event.owner.as_ref().map(|o| o.id), Some(actor_id(&actor)));
    assert_eq!(event.comment.as_deref(), Some("first look"));
    assert_eq!(event.event_time, times.event_time);
    assert_eq!(event.contain_time, None);
    assert_eq!(in_event(db, event.id).await, BTreeSet::from([older, newer]));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_to_event".to_owned(),
            target: ("event".to_owned(), event.id.to_string()),
            before: None,
            after: Some(json!({
                "uuid": event.uuid,
                "creation_date": "2026-01-02",
                "name": "<b>new</b> event",
                "status": "OPEN",
                "remediation": "not remediated",
                "type": "phish",
                "vector": "corporate email",
                "risk_level": "0",
                "prevention_tool": "response team",
                "comment": "first look",
                "event_time": "2026-01-01T00:00:00Z",
                "alert_time": "2026-01-02T03:04:05Z",
                "ownership_time": "2026-01-02T03:04:05Z",
                "disposition_time": null,
                "contain_time": null,
                "remediation_time": null,
                "owner": Uuid::from_u128(0xAD),
                "alerts": [newer, older],
            })),
            details: json!({
                "uuid": event.uuid,
                "name": "<b>new</b> event",
                "missing": [gone, not_an_alert],
            }),
        }
    );

    // to an event that exists, by its id: one row naming the alert it added
    let third = alert_at(db, "2026-01-04T00:00:00Z").await;
    let again = service
        .add_to_event(
            &actor,
            &EventChoice::Existing(EventRef::Id(event.id)),
            &[older, third],
        )
        .await
        .expect("adds");
    assert!(!again.made);
    assert_eq!(again.added, [third]);
    assert_eq!(again.already, [older]);
    let second_row = last_audit(db).await;
    assert_eq!(
        second_row,
        AuditRow {
            actor: boss_json(),
            action: "add_to_event".to_owned(),
            target: ("event".to_owned(), event.id.to_string()),
            before: None,
            after: Some(json!({"alerts": [third]})),
            details: json!({"uuid": event.uuid, "name": "<b>new</b> event", "missing": []}),
        }
    );

    // nothing new to add, a name or times that aren't, too many, no such event and a refusal have no row
    let rows = audit_rows(db).await.len();
    let same = service
        .add_to_event(
            &actor,
            &EventChoice::Existing(EventRef::Uuid(event.uuid)),
            &[older, gone],
        )
        .await
        .expect("changes nothing");
    assert!(same.added.is_empty());
    assert_eq!(same.missing, [gone]);
    for name in [
        "",
        "   ",
        "a\nb",
        &"x".repeat(ace_service::MAX_EVENT_NAME_CHARS + 1),
    ] {
        assert!(
            matches!(
                service
                    .add_to_event(&actor, &new_event(name), &[older])
                    .await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{name:?}"
        );
    }
    let out_of_order = EventChoice::New(NewEvent {
        name: "bad times".to_owned(),
        comment: None,
        times: EventTimes {
            event_time: Some(at("2026-01-02T00:00:00Z")),
            remediation_time: Some(at("2026-01-01T00:00:00Z")),
            ..EventTimes::default()
        },
    });
    assert!(matches!(
        service.add_to_event(&actor, &out_of_order, &[older]).await,
        Err(ServiceError::InvalidRequest(ref why)) if why.contains("out of order")
    ));
    let too_long = EventChoice::New(NewEvent {
        name: "long comment".to_owned(),
        comment: Some("x".repeat(ace_service::MAX_EVENT_COMMENT_CHARS + 1)),
        times: EventTimes::default(),
    });
    assert!(matches!(
        service.add_to_event(&actor, &too_long, &[older]).await,
        Err(ServiceError::InvalidRequest(_))
    ));
    let too_many: Vec<Uuid> = (0..=ace_service::MAX_EVENT_ALERTS as u128)
        .map(Uuid::from_u128)
        .collect();
    assert!(matches!(
        service
            .add_to_event(&actor, &new_event("too many"), &too_many)
            .await,
        Err(ServiceError::TooLarge(_))
    ));
    assert!(matches!(
        service
            .add_to_event(
                &actor,
                &EventChoice::Existing(EventRef::Id(i64::MAX)),
                &[older]
            )
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .add_to_event(&no_events(db).await, &new_event("refused"), &[older])
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// ace3's rules for adding to an event: a new event's name taken on its day adds to that one, even when
/// several analysts make it at once; another day's is another event; a new event with none of its alerts
/// left is dated today; a closed event takes alerts; an alert added by two at once is in it once; and the
/// form's closed events come a page at a time, newest first.
#[tokio::test]
async fn adding_to_an_event_follows_ace3_s_rules() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let writer = holding(&service, db, "event-writer", &[("event", "write")]).await;

    let first = alert_at(db, "2026-03-01T08:00:00Z").await;
    let made = service
        .add_to_event(
            &writer,
            &EventChoice::New(NewEvent {
                name: "Phish".to_owned(),
                comment: Some("the first".to_owned()),
                times: EventTimes::default(),
            }),
            &[first],
        )
        .await
        .expect("makes it");
    assert!(made.made);
    assert_eq!(
        made.event.owner.as_ref().map(|o| o.username.as_str()),
        Some("event-writer")
    );

    // the same name on the same day is the same event, keeping its comment
    let second = alert_at(db, "2026-03-01T23:59:59Z").await;
    let found = service
        .add_to_event(
            &writer,
            &EventChoice::New(NewEvent {
                name: " Phish ".to_owned(),
                comment: Some("ignored".to_owned()),
                times: EventTimes::default(),
            }),
            &[second],
        )
        .await
        .expect("adds to it");
    assert!(!found.made);
    assert_eq!(found.event.id, made.event.id);
    assert_eq!(found.event.comment.as_deref(), Some("the first"));
    assert_eq!(found.added, [second]);
    // another day's is another event
    let next_day = alert_at(db, "2026-03-02T00:00:00Z").await;
    let other = service
        .add_to_event(&writer, &new_event("Phish"), &[next_day])
        .await
        .expect("makes another");
    assert!(other.made);
    assert_ne!(other.event.id, made.event.id);
    // none of its alerts left: dated today
    let today = service
        .add_to_event(&writer, &new_event("all gone"), &[Uuid::from_u128(0xDEAD)])
        .await
        .expect("makes it");
    assert!(today.made);
    assert_eq!(today.event.creation_date, chrono::Utc::now().date_naive());
    assert!(today.event.alerts.is_empty());

    // several making one event at once: one makes it, the others add to it, and none fails
    let racers: Vec<Uuid> = {
        let mut racers = Vec::new();
        for _ in 0..8 {
            racers.push(alert_at(db, "2026-04-01T12:00:00Z").await);
        }
        racers
    };
    let mut racing = tokio::task::JoinSet::new();
    for alert in racers.iter().copied() {
        let service = service.clone();
        let writer = writer.clone();
        racing.spawn(async move {
            service
                .add_to_event(&writer, &new_event("at once"), &[alert])
                .await
        });
    }
    let results: Vec<_> = racing
        .join_all()
        .await
        .into_iter()
        .map(|r| r.expect("each succeeds"))
        .collect();
    assert_eq!(results.iter().filter(|r| r.made).count(), 1);
    let race_event = results[0].event.id;
    assert!(results.iter().all(|r| r.event.id == race_event));
    assert_eq!(
        in_event(db, race_event).await,
        racers.iter().copied().collect()
    );

    // one alert added to one event by several at once is in it once
    let shared = alert_at(db, "2026-04-02T00:00:00Z").await;
    let mut racing = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let service = service.clone();
        let writer = writer.clone();
        racing.spawn(async move {
            service
                .add_to_event(
                    &writer,
                    &EventChoice::Existing(EventRef::Id(race_event)),
                    &[shared],
                )
                .await
        });
    }
    let added: usize = racing
        .join_all()
        .await
        .into_iter()
        .map(|r| r.expect("each succeeds").added.len())
        .sum();
    assert_eq!(added, 1);

    // a closed event takes alerts
    service
        .set_event_status(&boss, EventRef::Id(other.event.id), "CLOSED")
        .await
        .expect("closes");
    let late = alert_at(db, "2026-03-05T00:00:00Z").await;
    let to_closed = service
        .add_to_event(
            &writer,
            &EventChoice::Existing(EventRef::Id(other.event.id)),
            &[late],
        )
        .await
        .expect("adds");
    assert_eq!(to_closed.added, [late]);
    assert_eq!(to_closed.event.status, "CLOSED");

    // the closed events a page at a time, newest first
    service
        .set_event_status(&boss, EventRef::Id(made.event.id), "CLOSED")
        .await
        .expect("closes");
    service
        .set_event_status(&boss, EventRef::Id(race_event), "CLOSED")
        .await
        .expect("closes");
    let reader = holding(&service, db, "event-reader", &[("event", "read")]).await;
    let page = service
        .closed_events(&reader, None, 2)
        .await
        .expect("lists");
    assert_eq!(
        page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        [race_event, other.event.id],
        "2026-04-01, then 2026-03-02"
    );
    assert_eq!(page.next, Some(other.event.id));
    let page = service
        .closed_events(&reader, page.next, 2)
        .await
        .expect("lists");
    assert_eq!(
        page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        [made.event.id]
    );
    assert_eq!(page.next, None);
    for limit in [0, ace_service::MAX_EVENTS_PAGE + 1] {
        assert!(matches!(
            service.closed_events(&reader, None, limit).await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    // a reader can't add
    assert!(matches!(
        service.add_to_event(&reader, &new_event("reader's"), &[first]).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
}

// PLAN.md 5.11's events (6c): the event list, ace3's events.manage, and what an event's page reads.

/// The event list's filters are checked and spelt canonically, and refused past their bounds or with a
/// value of the wrong shape.
#[test]
fn the_event_list_s_filters_are_checked() {
    use ace_service::{EventFilters, EventOwnerFilter, EventSort};
    let filters = EventFilters {
        created: Some("  ".to_owned()),
        statuses: vec![" OPEN ".to_owned(), "OPEN".to_owned(), String::new()],
        owners: vec![
            EventOwnerFilter::User(Uuid::from_u128(2)),
            EventOwnerFilter::Nobody,
            EventOwnerFilter::User(Uuid::from_u128(2)),
        ],
        kind: Some(" phish ".to_owned()),
        observable_type: Some("ipv4".to_owned()),
        observable_value: Some(" 10.0.0.1 ".to_owned()),
        malware: vec![3, 1, 3],
        ..EventFilters::default()
    }
    .check()
    .expect("checks");
    assert_eq!(filters.created, None, "an empty range is no filter");
    assert_eq!(filters.statuses, ["OPEN"]);
    assert_eq!(
        filters.owners,
        [
            EventOwnerFilter::Nobody,
            EventOwnerFilter::User(Uuid::from_u128(2))
        ]
    );
    assert_eq!(filters.kind.as_deref(), Some("phish"));
    assert_eq!(filters.observable_value.as_deref(), Some("10.0.0.1"));
    assert_eq!(filters.malware, [1, 3]);
    assert_eq!(EventFilters::ace3_default().statuses, ["OPEN"]);

    for bad in [
        EventFilters {
            created: Some("last tuesday".to_owned()),
            ..EventFilters::default()
        },
        EventFilters {
            observable_type: Some("no-such-type".to_owned()),
            ..EventFilters::default()
        },
        EventFilters {
            tags: vec!["a\nb".to_owned()],
            ..EventFilters::default()
        },
        EventFilters {
            kind: Some("x".repeat(257)),
            ..EventFilters::default()
        },
        EventFilters {
            statuses: (0..=ace_service::MAX_EVENT_FILTER_VALUES)
                .map(|n| n.to_string())
                .collect(),
            ..EventFilters::default()
        },
        EventFilters {
            campaigns: (0..=ace_service::MAX_EVENT_FILTER_IDS as i32).collect(),
            ..EventFilters::default()
        },
    ] {
        assert!(
            matches!(bad.check(), Err(ServiceError::InvalidRequest(_))),
            "{bad:?}"
        );
    }
    for sort in EventSort::ALL {
        assert_eq!(EventSort::named(sort.as_str()), Some(*sort));
    }
    assert_eq!(EventSort::named("risk_level"), Some(EventSort::RiskLevel));
    assert_eq!(EventSort::named("nope"), None);
}

/// Sets an event's fields by SQL: its day, status, type, vector, risk level, prevention tool,
/// remediation, campaign and owner, by value.
#[allow(clippy::too_many_arguments)]
async fn shape_event(
    db: &Db,
    id: i64,
    day: &str,
    status: &str,
    kind: &str,
    risk: &str,
    campaign: Option<i32>,
    owner: Option<Uuid>,
) {
    sqlx::query(
        "UPDATE events.events SET creation_date = $2::date,
             status_id = (SELECT id FROM events.statuses WHERE value = $3),
             type_id = (SELECT id FROM events.types WHERE value = $4),
             risk_level_id = (SELECT id FROM events.risk_levels WHERE value = $5),
             campaign_id = $6, owner_id = $7
         WHERE id = $1",
    )
    .bind(id)
    .bind(day)
    .bind(status)
    .bind(kind)
    .bind(risk)
    .bind(campaign)
    .bind(owner)
    .execute(db.pool())
    .await
    .expect("shapes the event");
}

/// Every page of the list for a query, as ids, following the cursors.
async fn every_page(
    service: &Service,
    actor: &Actor,
    query: &ace_service::EventQuery,
    limit: u32,
) -> Vec<i64> {
    let mut ids = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = service
            .event_list(actor, query, after.as_deref(), limit)
            .await
            .expect("lists");
        assert!(page.events.len() <= limit as usize);
        ids.extend(page.events.iter().map(|e| e.id));
        match page.next {
            Some(next) => after = Some(next),
            None => return ids,
        }
    }
}

/// The event list, through the service: every filter ace4 has a field for, each sort both ways with the id
/// breaking ties, a keyset that pages through each once, the cursor checked, the total, hostile text as
/// data, and `event:read`; the filters' choices; and an event's alerts with their state and tags.
#[tokio::test]
async fn the_event_list_filters_sorts_and_pages_as_ace3_does() {
    use ace_service::{EventFilters, EventOwnerFilter, EventQuery, EventSort};
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let boss = admin(db).await;
    let reader = holding(&service, db, "event-list-reader", &[("event", "read")]).await;
    let owner = actor_id(&reader).0;

    // alerts: one dispositioned DAMAGE, one FALSE_POSITIVE, one open and still running with a tag
    let damage = alert(db).await;
    let false_positive = alert(db).await;
    let running = alert(db).await;
    sqlx::query("UPDATE analysis.roots SET alerted_at = now(), pass = 1, completed_pass = 1")
        .execute(db.pool())
        .await
        .expect("alerts");
    sqlx::query("UPDATE analysis.roots SET pass = 2 WHERE id = $1")
        .bind(running)
        .execute(db.pool())
        .await
        .expect("runs");
    service
        .disposition(&boss, damage, "DAMAGE")
        .await
        .expect("dispositions");
    service
        .disposition(&boss, false_positive, "FALSE_POSITIVE")
        .await
        .expect("dispositions");
    // a disposition can start a pass, so the two dispositioned ones are made idle after
    sqlx::query("UPDATE analysis.roots SET completed_pass = pass WHERE id <> $1")
        .bind(running)
        .execute(db.pool())
        .await
        .expect("completes");
    sqlx::query(
        "INSERT INTO analysis.observables (root_id, type, value, tags)
         VALUES ($1, 'ipv4', '10.0.0.9', '{beta, Alpha}')",
    )
    .bind(running)
    .execute(db.pool())
    .await
    .expect("an observable");

    let hostile = "<script>alert(1)</script>";
    let campaign: i32 =
        sqlx::query_scalar("INSERT INTO events.campaigns (name) VALUES ('APT-x') RETURNING id")
            .fetch_one(db.pool())
            .await
            .expect("a campaign");
    let emotet = malware_named(db, "Emotet").await;
    // a: DAMAGE, b: FALSE_POSITIVE + the running alert, c: none (DELIVERY), d: closed, e: open, hostile
    let a = event_with(db, "alpha", &[damage]).await;
    let b = event_with(db, "bravo", &[false_positive, running]).await;
    let c = event_with(db, "charlie", &[]).await;
    let d = event_with(db, "delta", &[]).await;
    let e = event_with(db, hostile, &[]).await;
    shape_event(
        db,
        a,
        "2026-01-05",
        "OPEN",
        "phish",
        "3",
        Some(campaign),
        Some(owner),
    )
    .await;
    shape_event(db, b, "2026-01-05", "OPEN", "recon", "1", None, None).await;
    shape_event(db, c, "2026-01-03", "OPEN", "phish", "2", None, Some(owner)).await;
    shape_event(
        db,
        d,
        "2026-01-04",
        "CLOSED",
        "phish",
        "0",
        Some(campaign),
        None,
    )
    .await;
    shape_event(db, e, "2026-01-01", "OPEN", "pentest", "1", None, None).await;
    sqlx::query("INSERT INTO events.event_malware VALUES ($1, $2)")
        .bind(c)
        .bind(emotet)
        .execute(db.pool())
        .await
        .expect("records malware");
    sqlx::query("INSERT INTO events.event_tags VALUES ($1, 'kit'), ($2, 'other')")
        .bind(e)
        .bind(d)
        .execute(db.pool())
        .await
        .expect("tags");

    let list = |filters: EventFilters| {
        let query = EventQuery {
            filters,
            ..EventQuery::default()
        };
        let (service, reader) = (&service, &reader);
        async move { every_page(service, reader, &query, 2).await }
    };
    let all = || EventFilters::default();

    // ace3's list as it opens: the open events, newest first, the id breaking the tie between a and b
    assert_eq!(
        every_page(&service, &reader, &EventQuery::default(), 2).await,
        [b, a, c, e]
    );
    assert_eq!(list(all()).await, [b, a, d, c, e], "every status");
    let first = service
        .event_list(&reader, &EventQuery::default(), None, 3)
        .await
        .expect("lists");
    assert_eq!(first.total, 4);
    let hostile_event = first.events.iter().find(|ev| ev.id == e);
    assert!(hostile_event.is_none(), "not on the first page of 3");
    let rest = service
        .event_list(&reader, &EventQuery::default(), first.next.as_deref(), 3)
        .await
        .expect("lists");
    assert_eq!(rest.events[0].name, hostile, "as it was written");
    assert_eq!(rest.next, None);
    assert_eq!(rest.total, 4);

    // each filter
    assert_eq!(
        list(EventFilters {
            created: Some("01-03-2026 00:00 - 01-04-2026 23:59".to_owned()),
            ..all()
        })
        .await,
        [d, c]
    );
    assert_eq!(
        list(EventFilters {
            dispositions: vec!["DAMAGE".to_owned(), "DELIVERY".to_owned()],
            ..all()
        })
        .await,
        [a, d, c, e],
        "the rolled-up disposition, DELIVERY with no alerts"
    );
    assert_eq!(
        list(EventFilters {
            dispositions: vec!["FALSE_POSITIVE".to_owned()],
            ..all()
        })
        .await,
        [b],
        "an open alert doesn't outrank a dispositioned one"
    );
    assert_eq!(
        list(EventFilters {
            statuses: vec!["CLOSED".to_owned()],
            ..all()
        })
        .await,
        [d]
    );
    assert_eq!(
        list(EventFilters {
            owners: vec![EventOwnerFilter::User(owner)],
            ..all()
        })
        .await,
        [a, c]
    );
    assert_eq!(
        list(EventFilters {
            owners: vec![EventOwnerFilter::Nobody],
            ..all()
        })
        .await,
        [b, d, e]
    );
    assert_eq!(
        list(EventFilters {
            owners: vec![EventOwnerFilter::Nobody, EventOwnerFilter::User(owner)],
            ..all()
        })
        .await,
        [b, a, d, c, e]
    );
    assert_eq!(
        list(EventFilters {
            kind: Some("phish".to_owned()),
            risk_level: Some("0".to_owned()),
            ..all()
        })
        .await,
        [d]
    );
    assert_eq!(
        list(EventFilters {
            vector: Some("corporate email".to_owned()),
            prevention_tool: Some("response team".to_owned()),
            ..all()
        })
        .await
        .len(),
        5,
        "ace3's defaults"
    );
    assert!(
        list(EventFilters {
            vector: Some("usb".to_owned()),
            ..all()
        })
        .await
        .is_empty()
    );
    assert!(
        list(EventFilters {
            kind: Some(hostile.to_owned()),
            ..all()
        })
        .await
        .is_empty(),
        "hostile text is a value"
    );
    for (kind, value, want) in [
        (Some("ipv4"), Some("10.0.0.9"), vec![b]),
        (None, Some("10.0.0.9"), vec![b]),
        (Some("ipv4"), None, vec![b]),
        (Some("fqdn"), None, vec![b, a]),
        (Some("fqdn"), Some("evil.example.com"), vec![b, a]),
        (None, Some("10.0.0"), vec![]),
        (Some("fqdn"), Some("10.0.0.9"), vec![]),
    ] {
        assert_eq!(
            list(EventFilters {
                observable_type: kind.map(str::to_owned),
                observable_value: value.map(str::to_owned),
                ..all()
            })
            .await,
            want,
            "{kind:?} {value:?}"
        );
    }
    assert_eq!(
        list(EventFilters {
            tags: vec!["kit".to_owned(), "other".to_owned()],
            ..all()
        })
        .await,
        [d, e]
    );
    assert!(
        list(EventFilters {
            tags: vec!["Alpha".to_owned()],
            ..all()
        })
        .await
        .is_empty(),
        "an alert's tag isn't the event's"
    );
    assert_eq!(
        list(EventFilters {
            malware: vec![emotet],
            ..all()
        })
        .await,
        [c]
    );
    assert_eq!(
        list(EventFilters {
            campaigns: vec![campaign, i32::MAX],
            ..all()
        })
        .await,
        [a, d]
    );

    // each sort both ways, paged two at a time, each event once, the id breaking ties
    let sorted = |sort: EventSort, descending: bool| {
        let query = EventQuery {
            filters: all(),
            sort,
            descending,
        };
        let (service, reader) = (&service, &reader);
        async move { every_page(service, reader, &query, 2).await }
    };
    for (sort, ascending) in [
        (EventSort::Date, vec![e, c, d, a, b]),
        // type, vector, name: pentest, phish (alpha, charlie, delta), recon
        (EventSort::Event, vec![e, a, c, d, b]),
        // none first going up, then APT-x
        (EventSort::Campaign, vec![b, c, e, a, d]),
        (EventSort::RiskLevel, vec![d, b, e, c, a]),
        // FALSE_POSITIVE 20, DELIVERY 100, DAMAGE 160
        (EventSort::Disposition, vec![b, c, d, e, a]),
        (EventSort::Prevention, vec![a, b, c, d, e]),
        (EventSort::Remediation, vec![a, b, c, d, e]),
        (EventSort::Status, vec![d, a, b, c, e]),
        // nobody first, then the reader's username
        (EventSort::Owner, vec![b, d, e, a, c]),
    ] {
        assert_eq!(sorted(sort, false).await, ascending, "{sort:?} up");
        let mut descending = ascending.clone();
        descending.reverse();
        assert_eq!(sorted(sort, true).await, descending, "{sort:?} down");
    }

    // a cursor of another order, a broken one, and a page past the end
    let page = service
        .event_list(&reader, &EventQuery::default(), None, 1)
        .await
        .expect("lists");
    let cursor = page.next.expect("more");
    let other = EventQuery {
        descending: false,
        ..EventQuery::default()
    };
    for bad in [
        cursor.as_str(),
        "date.desc.1",
        "date.desc.1.zz",
        "nope.desc.1.5b5d",
    ] {
        let query = if bad == cursor {
            &other
        } else {
            &EventQuery::default()
        };
        assert!(
            matches!(
                service.event_list(&reader, query, Some(bad), 10).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad}"
        );
    }
    for limit in [0, ace_service::MAX_EVENTS_PAGE + 1] {
        assert!(matches!(
            service
                .event_list(&reader, &EventQuery::default(), None, limit)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    let bad_filter = EventQuery {
        filters: EventFilters {
            created: Some("whenever".to_owned()),
            ..all()
        },
        ..EventQuery::default()
    };
    assert!(matches!(
        service.event_list(&reader, &bad_filter, None, 10).await,
        Err(ServiceError::InvalidRequest(_))
    ));

    // an event's alerts with their state and tags, and whether one still runs
    let bravo = service
        .event(&reader, EventRef::Id(b))
        .await
        .expect("reads");
    let states: Vec<(Uuid, ace_service::AnalysisState, Vec<String>)> = bravo
        .alerts
        .iter()
        .map(|alert| (alert.id, alert.analysis, alert.tags.clone()))
        .collect();
    assert!(states.contains(&(
        running,
        ace_service::AnalysisState::Running,
        vec!["Alpha".to_owned(), "beta".to_owned()]
    )));
    assert!(states.contains(&(false_positive, ace_service::AnalysisState::Complete, vec![])));
    assert!(bravo.still_analyzing());
    assert_eq!(bravo.alert_tags, ["Alpha", "beta"]);
    let alpha = service
        .event(&reader, EventRef::Id(a))
        .await
        .expect("reads");
    assert!(!alpha.still_analyzing());

    // the filters' choices: each table by value, the owners of events, malware, campaigns and tags
    let choices = service.event_choices(&reader).await.expect("reads");
    let values = |v: &[ace_service::EventValue]| -> Vec<String> {
        v.iter().map(|v| v.value.clone()).collect()
    };
    assert_eq!(values(&choices.statuses), ["CLOSED", "IGNORE", "OPEN"]);
    assert_eq!(values(&choices.risk_levels), ["0", "1", "2", "3"]);
    assert_eq!(choices.types.len(), 9);
    assert_eq!(choices.vectors.len(), 9);
    assert_eq!(choices.prevention_tools.len(), 9);
    assert_eq!(
        choices.owners.iter().map(|o| o.id.0).collect::<Vec<_>>(),
        [owner],
        "only users who own an event"
    );
    assert_eq!(values(&choices.malware), ["Emotet"]);
    assert_eq!(values(&choices.campaigns), ["APT-x"]);
    assert_eq!(choices.tags, ["kit", "other"]);

    // someone with no event permission learns nothing
    let outsider = no_events(db).await;
    for result in [
        service
            .event_list(&outsider, &EventQuery::default(), None, 10)
            .await
            .map(|_| ()),
        service.event_choices(&outsider).await.map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(ServiceError::PermissionDenied { ref permission, .. })
                if permission.to_string() == "event:read"
        ));
    }
}

/// An event's disposition by the site's ranks, in the event list's query as in Rust: the overlay puts IGNORE
/// above DAMAGE, and a site's own ties with DAMAGE, which the name decides.
#[tokio::test]
async fn the_event_list_rolls_up_by_the_sites_ranks() {
    use ace_service::{EventFilters, EventQuery, EventSort};
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let overlay = ace_sdk::Overlay::from_yaml(
        "dispositions:\n  IGNORE: {rank: 500}\n  BREACH: {rank: 160, css: danger}\n",
    )
    .expect("parses");
    let service = service(db)
        .with_dispositions(ace_service::Dispositions::configured(&overlay).expect("good"));
    let reader = admin(db).await;
    let mut alerts = Vec::new();
    for disposition in ["DAMAGE", "IGNORE", "DAMAGE", "BREACH", "FALSE_POSITIVE"] {
        let root = alert(db).await;
        set_disposition_row(db, root, Some(disposition)).await;
        alerts.push(root);
    }
    let ignored = event_with(db, "ignored", &alerts[0..2]).await;
    let tied = event_with(db, "tied", &alerts[2..4]).await;
    let false_positive = event_with(db, "fp", &alerts[4..5]).await;
    let listed = |filters: EventFilters, sort: EventSort| {
        let query = EventQuery {
            filters,
            sort,
            descending: true,
        };
        let (service, reader) = (&service, &reader);
        async move {
            service
                .event_list(reader, &query, None, 10)
                .await
                .expect("lists")
                .events
                .into_iter()
                .map(|event| (event.id, event.disposition))
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        listed(EventFilters::default(), EventSort::Disposition).await,
        [
            (ignored, "IGNORE".to_owned()),
            (tied, "BREACH".to_owned()),
            (false_positive, "FALSE_POSITIVE".to_owned()),
        ]
    );
    for (wanted, expected) in [
        ("IGNORE", vec![ignored]),
        ("BREACH", vec![tied]),
        ("DAMAGE", vec![]),
    ] {
        let found = listed(
            EventFilters {
                dispositions: vec![wanted.to_owned()],
                ..EventFilters::default()
            },
            EventSort::Disposition,
        )
        .await;
        assert_eq!(
            found.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
            expected,
            "{wanted}"
        );
    }
    let one = service
        .event(&reader, ace_service::EventRef::Id(tied))
        .await
        .expect("reads");
    assert_eq!(one.disposition, "BREACH");
}

// The events module's own checks, which were a `#[cfg(test)]` module in src/events.rs that never ran:
// this crate's library tests are off (Cargo.toml), so they're here.

#[test]
fn an_event_rolls_its_alerts_dispositions_up_as_ace3_does() {
    let ace3 = ace_service::Dispositions::ace3();
    let rolled_up = |alerts: &[Option<&str>]| ace3.rolled_up(alerts.iter().copied());
    assert_eq!(rolled_up(&[]), "DELIVERY", "no alerts");
    assert_eq!(rolled_up(&[None, Some("OPEN")]), "OPEN");
    assert_eq!(rolled_up(&[Some("IGNORE")]), "IGNORE");
    assert_eq!(
        rolled_up(&[Some("DAMAGE"), Some("FALSE_POSITIVE"), None]),
        "DAMAGE"
    );
    assert_eq!(
        rolled_up(&[Some("GRAYWARE"), Some("SIMULATED"), Some("REVIEWED")]),
        "GRAYWARE"
    );
    assert_eq!(rolled_up(&[Some("SITE_OWN")]), "OPEN", "no rank never wins");
    assert_eq!(rolled_up(&[Some("SITE_OWN"), Some("IGNORE")]), "IGNORE");
    // the site's ranks: IGNORE above DAMAGE, a disposition of its own, and a tie, which the name decides
    let site = ace_service::Dispositions::configured(
        &ace_sdk::Overlay::from_yaml(
            "dispositions:\n  IGNORE: {rank: 500}\n  SITE_OWN: {rank: 160, css: dark}\n",
        )
        .expect("parses"),
    )
    .expect("good");
    let rolled_up = |alerts: &[Option<&str>]| site.rolled_up(alerts.iter().copied());
    assert_eq!(rolled_up(&[Some("DAMAGE"), Some("IGNORE")]), "IGNORE");
    assert_eq!(rolled_up(&[Some("SITE_OWN"), Some("REVIEWED")]), "SITE_OWN");
    assert_eq!(rolled_up(&[Some("SITE_OWN"), Some("DAMAGE")]), "DAMAGE");
    assert_eq!(rolled_up(&[Some("DAMAGE"), Some("SITE_OWN")]), "DAMAGE");
}

#[test]
fn an_event_is_named_by_its_id_or_its_uuid() {
    assert_eq!(EventRef::parse("42").expect("an id"), EventRef::Id(42));
    let uuid = Uuid::from_u128(7);
    assert_eq!(
        EventRef::parse(&uuid.to_string()).expect("a uuid"),
        EventRef::Uuid(uuid)
    );
    // ace3's warning: a uuid starting with digits isn't an id
    assert!(matches!(
        EventRef::parse("443c2e1a-719b-4f5d"),
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        EventRef::parse("99999999999999999999"),
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        EventRef::parse(""),
        Err(ServiceError::InvalidRequest(_))
    ));
}

/// A threat type's name is 1 to 256 characters, not all whitespace, with no control characters, when
/// it's made and when it's renamed, and a refused one writes nothing.
#[tokio::test]
async fn a_threat_type_name_is_checked() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let longest = "x".repeat(ace_service::MAX_THREAT_TYPE_CHARS);
    let made = service
        .create_threat_type(&actor, &longest)
        .await
        .expect("the longest fits");
    let rows = audit_rows(db).await.len();
    for bad in [
        "",
        "  ",
        "a\nb",
        "a\0b",
        &"x".repeat(ace_service::MAX_THREAT_TYPE_CHARS + 1),
    ] {
        assert!(
            matches!(
                service.create_threat_type(&actor, bad).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad:?}"
        );
        assert!(
            matches!(
                service.rename_threat_type(&actor, made.id, bad).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad:?}"
        );
    }
    assert_eq!(audit_rows(db).await.len(), rows);
}

// PLAN.md 5.11's events (6d): an event's edit, its alerts removed, its own tags.

/// The edit that changes nothing about an event as it is now.
async fn edit_of(db: &Db, event: &ace_service::Event) -> EventEdit {
    let campaign = match &event.campaign {
        Some(name) => CampaignChoice::Existing(
            sqlx::query_scalar("SELECT id FROM events.campaigns WHERE name = $1")
                .bind(name)
                .fetch_one(db.pool())
                .await
                .expect("its campaign"),
        ),
        None => CampaignChoice::None,
    };
    EventEdit {
        version: event.edit_version(),
        name: event.name.clone(),
        status: event.status.clone(),
        owner: event.owner.as_ref().map(|owner| owner.id),
        remediation: event.remediation.clone(),
        kind: event.kind.clone(),
        vector: event.vector.clone(),
        risk_level: event.risk_level.clone(),
        prevention_tool: event.prevention_tool.clone(),
        comment: event.comment.clone(),
        campaign,
        times: EventTimes::default(),
        malware: event
            .malware
            .iter()
            .map(|m| MalwareChoice::Existing(m.id))
            .collect(),
    }
}

/// Every row an edit could make or change, whole: campaigns, malware, their threats, the event's malware
/// and tags.
async fn edit_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'campaign ' || row_to_json(c)::text FROM events.campaigns c
         UNION ALL SELECT 'malware ' || row_to_json(m)::text FROM events.malware m
         UNION ALL SELECT 'threat ' || row_to_json(t)::text FROM events.malware_threats t
         UNION ALL SELECT 'event malware ' || row_to_json(em)::text FROM events.event_malware em
         UNION ALL SELECT 'tag ' || row_to_json(g)::text FROM events.event_tags g
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

async fn edit_event_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = event_with(db, "<b>edit</b>", &[]).await;
    sqlx::query("UPDATE events.events SET event_time = '2026-01-01T00:00:00Z' WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await
        .expect("sets a time");
    let kept = malware_named(db, "Kept").await;
    let (rat, ransomware) = (
        threat_type_id(db, "rat").await,
        threat_type_id(db, "ransomware").await,
    );
    let before = service
        .event(&actor, EventRef::Id(id))
        .await
        .expect("reads");
    let edit = EventEdit {
        name: "  <i>renamed</i> ".to_owned(),
        status: "IGNORE".to_owned(),
        owner: Some(actor_id(&actor)),
        remediation: "reimaged".to_owned(),
        kind: "recon".to_owned(),
        vector: "usb".to_owned(),
        risk_level: "2".to_owned(),
        prevention_tool: "edr".to_owned(),
        comment: Some("<script>why</script>".to_owned()),
        campaign: CampaignChoice::New(" APT-<x> ".to_owned()),
        times: EventTimes {
            alert_time: Some(at("2026-01-02T00:00:00Z")),
            ..EventTimes::default()
        },
        malware: vec![
            MalwareChoice::Existing(kept),
            MalwareChoice::New {
                name: "Fresh".to_owned(),
                threat_types: vec![ransomware, rat, rat],
            },
        ],
        ..edit_of(db, &before).await
    };
    let after = service
        .edit_event(&actor, EventRef::Uuid(before.uuid), &edit)
        .await
        .expect("edits");
    assert_eq!(after.name, "<i>renamed</i>", "trimmed");
    assert_eq!(after.campaign.as_deref(), Some("APT-<x>"));
    assert_eq!(after.event_time, Some(at("2026-01-01T00:00:00Z")), "kept");
    assert_eq!(after.alert_time, Some(at("2026-01-02T00:00:00Z")));
    assert_ne!(after.edit_version(), before.edit_version());
    let mut threats = vec!["ransomware".to_owned(), "rat".to_owned()];
    threats.sort();
    let mut added = [ransomware, rat];
    added.sort_unstable();
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "edit_event".to_owned(),
            target: ("event".to_owned(), id.to_string()),
            before: Some(json!({
                "name": "<b>edit</b>",
                "status": "OPEN",
                "remediation": "not remediated",
                "type": "phish",
                "vector": "corporate email",
                "risk_level": "0",
                "prevention_tool": "response team",
                "campaign": null,
                "comment": null,
                "event_time": "2026-01-01T00:00:00Z",
                "alert_time": null,
                "ownership_time": null,
                "disposition_time": null,
                "contain_time": null,
                "remediation_time": null,
                "owner": null,
                "malware": [],
            })),
            after: Some(json!({
                "name": "<i>renamed</i>",
                "status": "IGNORE",
                "remediation": "reimaged",
                "type": "recon",
                "vector": "usb",
                "risk_level": "2",
                "prevention_tool": "edr",
                "campaign": "APT-<x>",
                "comment": "<script>why</script>",
                "event_time": "2026-01-01T00:00:00Z",
                "alert_time": "2026-01-02T00:00:00Z",
                "ownership_time": null,
                "disposition_time": null,
                "contain_time": null,
                "remediation_time": null,
                "owner": Uuid::from_u128(0xAD),
                "malware": [
                    {"name": "Fresh", "threat_types": threats},
                    {"name": "Kept", "threat_types": []},
                ],
            })),
            details: json!({
                "uuid": before.uuid,
                "made_campaign": "APT-<x>",
                "made_malware": ["Fresh"],
                "added_threats": [
                    {"malware": "Fresh", "threat_type": added[0]},
                    {"malware": "Fresh", "threat_type": added[1]},
                ],
            }),
        }
    );

    // the same edit again, from the new version, changes nothing and has no row
    let rows = audit_rows(db).await.len();
    let same = EventEdit {
        version: after.edit_version(),
        ..edit_of(db, &after).await
    };
    assert_eq!(
        service
            .edit_event(&actor, EventRef::Id(id), &same)
            .await
            .expect("changes nothing"),
        after
    );
    // a refusal has no row
    assert!(matches!(
        service
            .edit_event(&no_events(db).await, EventRef::Id(id), &same)
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// ace3's rules: CLOSED only by Close Event; a closed event's times don't change; the times after an edit
/// are in order; a campaign and malware are found by name before one is made, and malware found is given
/// the types it lacks; and every value is checked. Each refusal writes nothing.
#[tokio::test]
async fn an_event_is_edited_by_ace3_s_rules() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let id = event_with(db, "rules", &[]).await;
    let read = || async {
        service
            .event(&actor, EventRef::Id(id))
            .await
            .expect("reads")
    };
    let open = read().await;
    let base = edit_of(db, &open).await;
    let refused = |result: Result<ace_service::Event, ServiceError>| match result {
        Err(error) => error,
        Ok(event) => panic!("edited: {event:?}"),
    };
    let rows = (
        audit_rows(db).await.len(),
        edit_rows(db).await,
        event_rows(db).await,
    );

    // an open event isn't given CLOSED by an edit, nor a status, type or other value that isn't one
    for edit in [
        EventEdit {
            status: "CLOSED".to_owned(),
            ..base.clone()
        },
        EventEdit {
            status: "closed".to_owned(),
            ..base.clone()
        },
        EventEdit {
            kind: "<b>nope</b>".to_owned(),
            ..base.clone()
        },
        EventEdit {
            risk_level: "9".to_owned(),
            ..base.clone()
        },
        EventEdit {
            remediation: String::new(),
            ..base.clone()
        },
        EventEdit {
            name: " ".to_owned(),
            ..base.clone()
        },
        EventEdit {
            comment: Some("x".repeat(ace_service::MAX_EVENT_COMMENT_CHARS + 1)),
            ..base.clone()
        },
        EventEdit {
            campaign: CampaignChoice::New("  ".to_owned()),
            ..base.clone()
        },
        // times out of order, the stored ones counted
        EventEdit {
            times: EventTimes {
                event_time: Some(at("2026-02-01T00:00:00Z")),
                alert_time: Some(at("2026-01-01T00:00:00Z")),
                ..EventTimes::default()
            },
            ..base.clone()
        },
        // new malware needs a name and a type, where ace3 drops it
        EventEdit {
            malware: vec![MalwareChoice::New {
                name: "no types".to_owned(),
                threat_types: Vec::new(),
            }],
            ..base.clone()
        },
        EventEdit {
            malware: vec![MalwareChoice::New {
                name: String::new(),
                threat_types: vec![1],
            }],
            ..base.clone()
        },
    ] {
        assert!(
            matches!(
                refused(service.edit_event(&actor, EventRef::Id(id), &edit).await),
                ServiceError::InvalidRequest(_)
            ),
            "{edit:?}"
        );
    }
    // what's named and isn't there is a 404, too many a 413
    let nobody = UserId(Uuid::from_u128(0x404));
    for edit in [
        EventEdit {
            owner: Some(nobody),
            ..base.clone()
        },
        EventEdit {
            campaign: CampaignChoice::Existing(i32::MAX),
            ..base.clone()
        },
        EventEdit {
            malware: vec![MalwareChoice::Existing(i32::MAX)],
            ..base.clone()
        },
        EventEdit {
            malware: vec![MalwareChoice::New {
                name: "typo".to_owned(),
                threat_types: vec![i32::MAX],
            }],
            ..base.clone()
        },
    ] {
        assert!(
            matches!(
                refused(service.edit_event(&actor, EventRef::Id(id), &edit).await),
                ServiceError::NotFound(_)
            ),
            "{edit:?}"
        );
    }
    assert!(matches!(
        refused(
            service
                .edit_event(&actor, EventRef::Id(i64::MAX), &base)
                .await
        ),
        ServiceError::NotFound(_)
    ));
    assert!(matches!(
        refused(
            service
                .edit_event(
                    &actor,
                    EventRef::Id(id),
                    &EventEdit {
                        malware: vec![
                            MalwareChoice::Existing(1);
                            ace_service::MAX_EDIT_MALWARE + 1
                        ],
                        ..base.clone()
                    },
                )
                .await
        ),
        ServiceError::TooLarge(_)
    ));
    // a disabled user isn't given the event
    let disabled = UserId(Uuid::from_u128(0xD15));
    exists(db, &Holder::User(disabled)).await;
    sqlx::query("UPDATE service.users SET enabled = false WHERE id = $1")
        .bind(disabled.0)
        .execute(db.pool())
        .await
        .expect("disables");
    assert!(matches!(
        refused(
            service
                .edit_event(
                    &actor,
                    EventRef::Id(id),
                    &EventEdit {
                        owner: Some(disabled),
                        ..base.clone()
                    },
                )
                .await
        ),
        ServiceError::InvalidRequest(_)
    ));
    // a name another event has on its day
    event_with(db, "taken", &[]).await;
    assert!(matches!(
        refused(
            service
                .edit_event(
                    &actor,
                    EventRef::Id(id),
                    &EventEdit {
                        name: "taken".to_owned(),
                        ..base.clone()
                    },
                )
                .await
        ),
        ServiceError::Conflict(_)
    ));
    let mut rows_after = (
        audit_rows(db).await.len(),
        edit_rows(db).await,
        event_rows(db).await,
    );
    // only the event made for the name
    rows_after.2.retain(|row| !row.contains("\"taken\""));
    assert_eq!(rows_after, rows, "no refusal wrote anything");

    // a campaign and malware by name: found if they're there, and malware found gains the types it lacks
    let emotet = malware_named(db, "Emotet").await;
    let (rat, wiper) = (
        threat_type_id(db, "rat").await,
        threat_type_id(db, "wiper").await,
    );
    sqlx::query("INSERT INTO events.malware_threats VALUES ($1, $2)")
        .bind(emotet)
        .bind(rat)
        .execute(db.pool())
        .await
        .expect("a threat");
    sqlx::query("INSERT INTO events.campaigns (name) VALUES ('APT-x')")
        .execute(db.pool())
        .await
        .expect("a campaign");
    let edited = service
        .edit_event(
            &actor,
            EventRef::Id(id),
            &EventEdit {
                campaign: CampaignChoice::New("APT-x".to_owned()),
                malware: vec![MalwareChoice::New {
                    name: "Emotet".to_owned(),
                    threat_types: vec![rat, wiper],
                }],
                times: EventTimes {
                    event_time: Some(at("2026-01-01T00:00:00Z")),
                    alert_time: Some(at("2026-01-01T00:00:00Z")),
                    ..EventTimes::default()
                },
                ..base.clone()
            },
        )
        .await
        .expect("edits: two equal times are in order, as ace3's sort has it");
    assert_eq!(edited.campaign.as_deref(), Some("APT-x"));
    assert_eq!(edited.malware.len(), 1);
    assert_eq!(edited.malware[0].id, emotet);
    assert_eq!(edited.malware[0].threat_types, ["rat", "wiper"]);
    assert_eq!(
        sqlx_count(db, "SELECT count(*) FROM events.campaigns").await,
        1,
        "found, not made"
    );
    let details = last_audit(db).await.details;
    assert_eq!(
        details,
        json!({
            "uuid": edited.uuid,
            "made_campaign": null,
            "made_malware": [],
            "added_threats": [{"malware": "Emotet", "threat_type": wiper}],
        })
    );

    // an edit is drawn from a version: one the event has left is a conflict, and writes nothing
    assert!(matches!(
        refused(service.edit_event(&actor, EventRef::Id(id), &base).await),
        ServiceError::Conflict(_)
    ));
    // adding an alert or a tag doesn't change the version
    let version = edited.edit_version();
    service
        .add_event_tags(&actor, EventRef::Id(id), &["kit".to_owned()])
        .await
        .expect("tags");
    let root = alert_at(db, "2026-01-01T00:00:00Z").await;
    service
        .add_to_event(&actor, &EventChoice::Existing(EventRef::Id(id)), &[root])
        .await
        .expect("adds");
    assert_eq!(read().await.edit_version(), version);

    // taking malware and the campaign off
    let cleared = service
        .edit_event(
            &actor,
            EventRef::Id(id),
            &EventEdit {
                campaign: CampaignChoice::None,
                malware: Vec::new(),
                ..edit_of(db, &read().await).await
            },
        )
        .await
        .expect("edits");
    assert_eq!(cleared.campaign, None);
    assert!(cleared.malware.is_empty());
    assert_eq!(
        sqlx_count(
            db,
            "SELECT count(*) FROM events.malware WHERE name = 'Emotet'"
        )
        .await,
        1,
        "the malware stays, only the event's mapping goes"
    );

    // a closed event: its times don't change, it keeps CLOSED or is reopened
    let closed = service
        .set_event_status(&actor, EventRef::Id(id), "CLOSED")
        .await
        .expect("closes");
    let kept = service
        .edit_event(
            &actor,
            EventRef::Id(id),
            &EventEdit {
                comment: Some("after the fact".to_owned()),
                times: EventTimes {
                    // out of order too, and ignored, as ace3 ignores a closed event's times
                    event_time: Some(at("2027-01-01T00:00:00Z")),
                    contain_time: Some(at("2020-01-01T00:00:00Z")),
                    ..EventTimes::default()
                },
                ..edit_of(db, &closed).await
            },
        )
        .await
        .expect("edits a closed event");
    assert_eq!(kept.status, "CLOSED");
    assert_eq!(kept.comment.as_deref(), Some("after the fact"));
    assert_eq!(kept.event_time, closed.event_time);
    assert_eq!(kept.contain_time, None);
    let reopened = service
        .edit_event(
            &actor,
            EventRef::Id(id),
            &EventEdit {
                status: "OPEN".to_owned(),
                times: EventTimes {
                    contain_time: Some(at("2027-01-01T00:00:00Z")),
                    ..EventTimes::default()
                },
                ..edit_of(db, &kept).await
            },
        )
        .await
        .expect("reopens");
    assert_eq!(reopened.status, "OPEN");
    assert_eq!(
        reopened.contain_time, None,
        "the status before the edit decides, as in ace3"
    );
}

/// Two analysts saving one event's edit at once, from the version they both opened: the event's lock
/// lets one through and the other gets a conflict, where ace3's last save wins and undoes the first's.
/// Two making one new campaign and one new malware at once in different events both get the one made.
#[tokio::test]
async fn two_edits_at_once_one_saves_and_the_other_is_told() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    for round in 0..4 {
        let id = event_with(db, &format!("contested {round}"), &[]).await;
        let opened = service
            .event(&actor, EventRef::Id(id))
            .await
            .expect("reads");
        let base = edit_of(db, &opened).await;
        let saves = ["first", "second"].map(|comment| {
            let (service, actor) = (service.clone(), actor.clone());
            let edit = EventEdit {
                comment: Some(comment.to_owned()),
                ..base.clone()
            };
            tokio::spawn(async move { service.edit_event(&actor, EventRef::Id(id), &edit).await })
        });
        let mut saved = Vec::new();
        let mut told = 0;
        for save in saves {
            match save.await.expect("runs") {
                Ok(event) => saved.push(event.comment),
                Err(ServiceError::Conflict(_)) => told += 1,
                Err(error) => panic!("{error}"),
            }
        }
        assert_eq!((saved.len(), told), (1, 1), "round {round}");
        let now = service
            .event(&actor, EventRef::Id(id))
            .await
            .expect("reads");
        assert_eq!(now.comment, saved[0]);
    }

    let mut ids = Vec::new();
    for n in 0..6 {
        ids.push(event_with(db, &format!("shared {n}"), &[]).await);
    }
    let rat = threat_type_id(db, "rat").await;
    let mut edits = Vec::new();
    for id in &ids {
        let event = service
            .event(&actor, EventRef::Id(*id))
            .await
            .expect("reads");
        edits.push((
            *id,
            EventEdit {
                campaign: CampaignChoice::New("APT-shared".to_owned()),
                malware: vec![MalwareChoice::New {
                    name: "Shared".to_owned(),
                    threat_types: vec![rat],
                }],
                ..edit_of(db, &event).await
            },
        ));
    }
    let writes: Vec<_> = edits
        .into_iter()
        .map(|(id, edit)| {
            let (service, actor) = (service.clone(), actor.clone());
            tokio::spawn(async move { service.edit_event(&actor, EventRef::Id(id), &edit).await })
        })
        .collect();
    for write in writes {
        let event = write.await.expect("runs").expect("edits");
        assert_eq!(event.campaign.as_deref(), Some("APT-shared"));
        assert_eq!(event.malware[0].threat_types, ["rat"]);
    }
    assert_eq!(
        sqlx_count(
            db,
            "SELECT count(*) FROM events.campaigns WHERE name = 'APT-shared'"
        )
        .await,
        1
    );
    assert_eq!(
        sqlx_count(
            db,
            "SELECT count(*) FROM events.malware WHERE name = 'Shared'"
        )
        .await,
        1
    );
    let made: Vec<Value> = audit_rows(db)
        .await
        .into_iter()
        .filter(|row| row.action == "edit_event")
        .filter_map(|row| row.details.get("made_campaign").cloned())
        .filter(|made| !made.is_null())
        .collect();
    assert_eq!(made, [json!("APT-shared")], "one edit made it");
}

async fn remove_alerts_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (one, two, other) = (alert(db).await, alert(db).await, alert(db).await);
    let id = event_with(db, "<b>remove</b>", &[one, two]).await;
    let removed = service
        .remove_alerts(&actor, EventRef::Id(id), &[two, other, two])
        .await
        .expect("removes");
    assert_eq!(removed.removed, [two]);
    assert_eq!(removed.not_in, [other]);
    assert_eq!(in_event(db, id).await, BTreeSet::from([one]));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "remove_alerts".to_owned(),
            target: ("event".to_owned(), id.to_string()),
            before: Some(json!({"alerts": [two]})),
            after: None,
            details: json!({"uuid": removed.event.uuid, "name": "<b>remove</b>"}),
        }
    );
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.roots WHERE id = $1")
        .bind(two)
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(still, 1, "the alert stays, only its mapping goes");

    // none in it, too many, no such event and a refusal have no row
    let rows = audit_rows(db).await.len();
    let none = service
        .remove_alerts(&actor, EventRef::Id(id), &[other])
        .await
        .expect("removes nothing");
    assert!(none.removed.is_empty());
    assert!(matches!(
        service
            .remove_alerts(
                &actor,
                EventRef::Id(id),
                &vec![one; ace_service::MAX_EVENT_ALERTS + 1]
            )
            .await,
        Err(ServiceError::TooLarge(_))
    ));
    assert!(matches!(
        service
            .remove_alerts(&actor, EventRef::Id(i64::MAX), &[one])
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .remove_alerts(&no_events(db).await, EventRef::Id(id), &[one])
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    assert_eq!(in_event(db, id).await, BTreeSet::from([one]));
    row.action
}

async fn add_event_tags_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = event_with(db, "<b>tags</b>", &[]).await;
    let tags = |list: &[&str]| list.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>();
    service
        .add_event_tags(&actor, EventRef::Id(id), &tags(&["old"]))
        .await
        .expect("tags");
    let event = service
        .add_event_tags(
            &actor,
            EventRef::Id(id),
            &tags(&["<b>new</b>", "old", "<b>new</b>", "Kit"]),
        )
        .await
        .expect("tags");
    assert_eq!(event.tags, ["<b>new</b>", "Kit", "old"]);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_event_tags".to_owned(),
            target: ("event".to_owned(), id.to_string()),
            before: None,
            after: Some(json!({"tags": ["<b>new</b>", "Kit"]})),
            details: json!({"uuid": event.uuid, "name": "<b>tags</b>"}),
        }
    );

    // tags it has, tags that aren't, none, too many, no such event and a refusal have no row
    let rows = audit_rows(db).await.len();
    service
        .add_event_tags(&actor, EventRef::Id(id), &tags(&["old", "Kit"]))
        .await
        .expect("changes nothing");
    for bad in [
        tags(&[]),
        tags(&["two words"]),
        tags(&["tab\there"]),
        tags(&["nul\0"]),
        tags(&[""]),
        vec!["x".repeat(ace_service::MAX_EVENT_TAG_CHARS + 1)],
    ] {
        assert!(
            matches!(
                service.add_event_tags(&actor, EventRef::Id(id), &bad).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        service
            .add_event_tags(
                &actor,
                EventRef::Id(id),
                &vec!["t".to_owned(); ace_service::MAX_EVENT_TAGS + 1]
            )
            .await,
        Err(ServiceError::TooLarge(_))
    ));
    assert!(matches!(
        service
            .add_event_tags(&actor, EventRef::Id(i64::MAX), &tags(&["x"]))
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .add_event_tags(&no_events(db).await, EventRef::Id(id), &tags(&["x"]))
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:write"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// The edit form's lists: each reference table by value, the campaigns and malware with its threat
/// types, the threat types, and the enabled users only; under event:read.
#[tokio::test]
async fn an_edit_s_choices_are_ace3_s_lists() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let emotet = malware_named(db, "Emotet").await;
    sqlx::query("INSERT INTO events.malware_threats VALUES ($1, $2)")
        .bind(emotet)
        .bind(threat_type_id(db, "rat").await)
        .execute(db.pool())
        .await
        .expect("a threat");
    malware_named(db, "Alpha").await;
    let disabled = UserId(Uuid::from_u128(0xD15));
    exists(db, &Holder::User(disabled)).await;
    sqlx::query("UPDATE service.users SET enabled = false WHERE id = $1")
        .bind(disabled.0)
        .execute(db.pool())
        .await
        .expect("disables");
    let choices = service.event_edit_choices(&actor).await.expect("reads");
    let values =
        |list: &[ace_service::EventValue]| list.iter().map(|v| v.value.clone()).collect::<Vec<_>>();
    assert_eq!(values(&choices.statuses), ["CLOSED", "IGNORE", "OPEN"]);
    assert_eq!(values(&choices.risk_levels), ["0", "1", "2", "3"]);
    assert_eq!(choices.remediations.len(), 10);
    assert_eq!(choices.threat_types.len(), 13);
    assert_eq!(
        choices
            .malware
            .iter()
            .map(|m| (m.name.as_str(), m.threat_types.clone()))
            .collect::<Vec<_>>(),
        [("Alpha", vec![]), ("Emotet", vec!["rat".to_owned()])]
    );
    assert_eq!(
        choices.users.iter().map(|u| u.id).collect::<Vec<_>>(),
        [actor_id(&actor)],
        "enabled users only"
    );
    assert!(matches!(
        service.event_edit_choices(&no_events(db).await).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "event:read"
    ));
}

async fn sqlx_count(db: &Db, query: &'static str) -> i64 {
    sqlx::query_scalar(query)
        .fetch_one(db.pool())
        .await
        .expect("counts")
}

/// ace-service, ace-api and ace-gui turn their library tests off (each Cargo.toml's `[lib] test = false`,
/// PLAN.md 2.33), so a `#[cfg(test)]` module in their source would never run, as events.rs's didn't.
/// Their tests go in their test binaries.
#[test]
fn no_library_test_module_hides_where_library_tests_are_off() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for name in ["ace-service", "ace-api", "ace-gui"] {
        let manifest = std::fs::read_to_string(crates.join(name).join("Cargo.toml"))
            .expect("reads the manifest");
        assert!(manifest.contains("[lib]\ntest = false"), "{name}");
        let mut dirs = vec![crates.join(name).join("src")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("reads the source") {
                let path = entry.expect("an entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let source = std::fs::read_to_string(&path).expect("reads the source");
                    assert!(
                        !source.contains("#[cfg(test)]"),
                        "{} has a test module that never runs: move it to the crate's tests/",
                        path.display()
                    );
                }
            }
        }
    }
}

// PLAN.md 5.12: commands analysts run from the GUI, ace3's `cli` router, queued for a pool.

async fn command_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar("SELECT row_to_json(c)::text FROM queue.commands c ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads")
}

/// A user holding nothing to do with commands.
async fn no_commands(db: &Db) -> Actor {
    let id = UserId(Uuid::from_u128(0xC0));
    exists(db, &Holder::User(id)).await;
    user(id)
}

fn admin_username() -> String {
    format!("u{}", Uuid::from_u128(0xAD).simple())
}

async fn start_command_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let started = service
        .start_command(
            &actor,
            "ace yara scan --rules '/a b' \"<script>\"",
            Some(30),
        )
        .await
        .expect("starts");
    assert_eq!(started.run.state, CommandState::Queued);
    assert_eq!(started.run.command, "yara scan --rules '/a b' '<script>'");
    let id = started.run.id;
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "start_command".to_owned(),
            target: ("command".to_owned(), id.to_string()),
            before: None,
            after: Some(json!({
                "command": "yara scan --rules '/a b' '<script>'",
                "timeout_seconds": 30,
                "username": admin_username(),
            })),
            details: json!({}),
        }
    );

    // a line that isn't one, a timeout out of range, a key with no owner and a refusal have no row
    let ownerless = ApiKeyId(Uuid::from_u128(0xC1));
    exists(db, &Holder::ApiKey(ownerless)).await;
    grant(
        db,
        &Holder::ApiKey(ownerless),
        "cli",
        "execute",
        Effect::Allow,
    )
    .await;
    let rows = audit_rows(db).await.len();
    for line in ["", "ace", "-c /etc/x node list", "'open", "a\nb"] {
        assert!(
            matches!(
                service.start_command(&actor, line, None).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{line:?}"
        );
    }
    for timeout in [0, 3601] {
        assert!(matches!(
            service.start_command(&actor, "--help", Some(timeout)).await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    let key = Actor::ApiKey {
        id: ownerless,
        name: "triage".to_owned(),
        owner: None,
    };
    assert!(matches!(
        service.start_command(&key, "--help", None).await,
        Err(ServiceError::Forbidden(_))
    ));
    assert!(matches!(
        service.start_command(&no_commands(db).await, "--help", None).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "cli:execute"
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn cancel_command_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = service
        .start_command(&actor, "--help", None)
        .await
        .expect("starts")
        .run
        .id;
    let cancelled = service.cancel_command(&actor, id).await.expect("cancels");
    assert_eq!(cancelled.run.state, CommandState::Cancelled);
    assert_eq!(
        cancelled.run.error.as_deref(),
        Some("cancelled before a pool took it")
    );
    assert_eq!(
        cancelled.run.cancelled_by.map(|by| by.id),
        Some(Uuid::from_u128(0xAD).to_string())
    );
    assert!(cancelled.run.finished_at.is_some());
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "cancel_command".to_owned(),
            target: ("command".to_owned(), id.to_string()),
            before: Some(json!({"state": "queued", "cancel_requested": false})),
            after: Some(json!({"state": "cancelled", "cancel_requested": true})),
            details: json!({"command": "--help"}),
        }
    );

    // a running command is asked to stop once, with a row; asking again changes nothing
    let running = service
        .start_command(&actor, "--version", None)
        .await
        .expect("starts")
        .run
        .id;
    let worker =
        ace_core::commands::CommandWorker::new(db.clone(), "test/w", Duration::from_secs(30));
    // the oldest is claimed first, and earlier tests here left theirs queued
    while worker.claim().await.expect("claims").expect("a command").id != running {}
    let asked = service.cancel_command(&actor, running).await.expect("asks");
    assert_eq!(
        (asked.run.state, asked.run.cancel_requested),
        (CommandState::Running, true)
    );
    let row = last_audit(db).await;
    assert_eq!(
        row.before,
        Some(json!({"state": "running", "cancel_requested": false}))
    );
    assert_eq!(
        row.after,
        Some(json!({"state": "running", "cancel_requested": true}))
    );
    let rows = audit_rows(db).await.len();
    service
        .cancel_command(&actor, running)
        .await
        .expect("changes nothing");
    assert!(
        worker.report(running, "", false).await.expect("reports"),
        "the pool learns"
    );

    // one that has ended, no such command and a refusal have no row
    assert!(matches!(
        service.cancel_command(&actor, id).await,
        Err(ServiceError::Conflict(_))
    ));
    assert!(matches!(
        service.cancel_command(&actor, i64::MAX).await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .cancel_command(&no_commands(db).await, running)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// The command line as ace3's `parse_command` takes it: split as a shell would, `ace` dropped, and no
/// leading option but help or version.
#[test]
fn a_command_line_splits_as_a_shell_would() {
    for (line, words) in [
        ("--help", vec!["--help"]),
        ("ace --help", vec!["--help"]),
        (
            "  ace   yara scan --json 'a b' \"c d\"",
            vec!["yara", "scan", "--json", "a b", "c d"],
        ),
        ("-V", vec!["-V"]),
        ("schema check\tx.json", vec!["schema", "check", "x.json"]),
    ] {
        assert_eq!(
            ace_service::parse_command(line).expect(line),
            words,
            "{line:?}"
        );
    }
    let long = "x".repeat(ace_service::MAX_COMMAND_CHARS + 1);
    let many = "x ".repeat(ace_service::MAX_COMMAND_WORDS + 1);
    for line in [
        "",
        "  ",
        "ace",
        "-c x",
        "--config=x",
        "'x",
        "x\0y",
        "x\ny",
        &long,
        &many,
    ] {
        assert!(
            matches!(
                ace_service::parse_command(line),
                Err(ServiceError::InvalidRequest(_))
            ),
            "{line:?}"
        );
    }
}

/// The runs read under `cli:execute`, newest first a page at a time, and one with its output; the core
/// keeps what a pool reports, bounded, and its end; the reaper ends what nothing will finish.
#[tokio::test]
async fn commands_are_read_with_their_output_and_reaped_when_nothing_finishes_them() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let mut ids = Vec::new();
    for n in 0..3 {
        ids.push(
            service
                .start_command(&actor, &format!("--help {n}"), Some(60))
                .await
                .expect("starts")
                .run
                .id,
        );
    }
    let page = service
        .commands(&actor, Some(2), None)
        .await
        .expect("lists");
    assert_eq!(
        page.commands.iter().map(|run| run.id).collect::<Vec<_>>(),
        [ids[2], ids[1]]
    );
    assert_eq!(page.next, Some(ids[1]));
    let page = service
        .commands(&actor, Some(2), page.next)
        .await
        .expect("lists");
    assert_eq!(
        page.commands.iter().map(|run| run.id).collect::<Vec<_>>(),
        [ids[0]]
    );
    assert_eq!(page.next, None);
    for limit in [0, 201] {
        assert!(matches!(
            service.commands(&actor, Some(limit), None).await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    let outsider = no_commands(db).await;
    assert!(matches!(
        service.commands(&outsider, None, None).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.command(&outsider, ids[0]).await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(matches!(
        service.command(&actor, i64::MAX).await,
        Err(ServiceError::NotFound(_))
    ));

    // a pool claims the oldest, its clock starting then, and its output is text with NUL as U+FFFD
    let worker =
        ace_core::commands::CommandWorker::new(db.clone(), "test/w", Duration::from_secs(30));
    let claimed = worker.claim().await.expect("claims").expect("a command");
    assert_eq!(
        (claimed.id, claimed.argv.clone()),
        (ids[0], vec!["--help".to_owned(), "0".to_owned()])
    );
    assert!(claimed.deadline_in <= Duration::from_secs(60));
    assert!(claimed.deadline_in > Duration::from_secs(55));
    assert!(
        !worker
            .report(ids[0], "<b>so far</b>\0", false)
            .await
            .expect("reports")
    );
    let read = service.command(&actor, ids[0]).await.expect("reads");
    assert_eq!(read.run.state, CommandState::Running);
    assert_eq!(read.output, "<b>so far</b>\u{fffd}");
    let deadline = read.run.deadline_at.expect("a deadline");
    assert_eq!(
        deadline - read.run.started_at.expect("started"),
        chrono::Duration::seconds(60)
    );
    let other =
        ace_core::commands::CommandWorker::new(db.clone(), "test/other", Duration::from_secs(30));
    assert!(
        other.report(ids[0], "not mine", false).await.is_err(),
        "only its holder reports"
    );
    worker
        .end(
            ids[0],
            CommandState::Completed,
            Some(0),
            None,
            "all of it",
            false,
        )
        .await
        .expect("ends");
    let read = service.command(&actor, ids[0]).await.expect("reads");
    assert_eq!(
        (read.run.state, read.run.exit_code),
        (CommandState::Completed, Some(0))
    );
    assert_eq!(read.output, "all of it");
    assert!(
        worker
            .end(ids[0], CommandState::Failed, None, Some("again"), "", false)
            .await
            .is_err()
    );

    // a running command whose lease ran out and a queued one past its timeout are abandoned
    let claimed = worker.claim().await.expect("claims").expect("a command");
    sqlx::query(
        "UPDATE queue.commands SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(claimed.id)
    .execute(db.pool())
    .await
    .expect("expires the lease");
    sqlx::query("ALTER TABLE queue.commands DISABLE TRIGGER commands_keep_their_record")
        .execute(db.pool())
        .await
        .expect("lets the test age the row");
    sqlx::query(
        "UPDATE queue.commands SET created_at = now() - interval '2 minutes' WHERE id = $1",
    )
    .bind(ids[2])
    .execute(db.pool())
    .await
    .expect("ages it");
    sqlx::query("ALTER TABLE queue.commands ENABLE TRIGGER commands_keep_their_record")
        .execute(db.pool())
        .await
        .expect("restores the trigger");
    let reaped = ace_core::commands::reap_commands(db).await.expect("reaps");
    assert_eq!((reaped.unreported, reaped.untaken), (1, 1));
    for (id, why) in [
        (
            claimed.id,
            "its pool stopped reporting on it before it ended",
        ),
        (ids[2], "no pool took it within its timeout"),
    ] {
        let read = service.command(&actor, id).await.expect("reads");
        assert_eq!(read.run.state, CommandState::Abandoned);
        assert_eq!(read.run.error.as_deref(), Some(why));
    }
    assert!(
        worker.report(claimed.id, "late", false).await.is_err(),
        "its lease is gone"
    );

    // an ended run's record doesn't change
    let changed = sqlx::query("UPDATE queue.commands SET state = 'queued' WHERE id = $1")
        .bind(ids[0])
        .execute(db.pool())
        .await;
    assert!(changed.is_err(), "an ended command stays ended");
}

// ---- PLAN.md 5.13: the relationship graph ----

use ace_service::{
    Addition, Alert, AlertFile, AlertObservable, AlertSummary, AlertTree, AnalysisState,
    MAX_GRAPH_EDGES, MAX_GRAPH_NODES, MAX_LABEL_CHARS, ModuleResult, Relationship, graph_of,
};

fn graph_observable(id: i64, kind: &str, value: &str) -> AlertObservable {
    AlertObservable {
        id,
        kind: kind.to_owned(),
        value: value.to_owned(),
        time: None,
        tags: Vec::new(),
        directives: Vec::new(),
        exclude_modules: Vec::new(),
        redirection: None,
        display_type: None,
        display_value: None,
        ignored: false,
        files: Vec::new(),
        relationships: Vec::new(),
        results: Vec::new(),
        detections: Vec::new(),
    }
}

fn graph_result(id: i64, module: &str) -> ModuleResult {
    ModuleResult {
        id,
        module: module.to_owned(),
        analysis_type: module.to_owned(),
        schema_version: 1,
        summary: None,
        tags: Vec::new(),
        details: serde_json::json!({}),
        created_at: chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time"),
    }
}

fn graph_tree(
    observables: Vec<AlertObservable>,
    top: Vec<i64>,
    additions: &[(i64, i64)],
) -> AlertTree {
    let at = chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time");
    AlertTree {
        alert: Alert {
            summary: AlertSummary {
                id: uuid::Uuid::from_u128(0x513),
                title: "<img src=x onerror=alert(1)>".to_owned(),
                analysis_mode: "correlation".to_owned(),
                event_time: None,
                event_time_source: "unset".to_owned(),
                created_at: at,
                alerted_at: at,
                disposition: None,
                dispositioned_at: None,
                dispositioned_by: None,
                submitted_by: None,
                analysis: AnalysisState::Complete,
                queue: "default".to_owned(),
            },
            observables: i64::try_from(observables.len()).expect("a count"),
            files: 0,
            detections: 0,
        },
        observables,
        top,
        additions: additions
            .iter()
            .map(|&(result, observable)| Addition { result, observable })
            .collect(),
        root_detections: Vec::new(),
        truncated: false,
    }
}

/// The email of 2.30, in small: the email, its result, what that added, the archive's result, a
/// relationship and tags.
fn email_graph_tree() -> AlertTree {
    let mut email = graph_observable(1, "file", "aa");
    email.files.push(AlertFile {
        path: "email.rfc822".to_owned(),
        yara_meta: Vec::new(),
    });
    email.results.push(graph_result(10, "email_analyzer"));
    let mut zip = graph_observable(2, "file", "bb");
    zip.files.push(AlertFile {
        path: "email.rfc822.parts/invoice.zip".to_owned(),
        yara_meta: Vec::new(),
    });
    zip.tags = vec!["<b>email.attachment</b>".to_owned()];
    zip.relationships.push(Relationship {
        kind: "extracted_from".to_owned(),
        target_type: "file".to_owned(),
        target_value: "aa".to_owned(),
    });
    let mut archive = graph_result(11, "archive");
    archive.tags = vec!["<b>email.attachment</b>".to_owned()];
    zip.results.push(archive);
    let domain = graph_observable(3, "fqdn", "example.com");
    // a relationship to something that isn't in the alert draws nothing
    let mut orphan = graph_observable(4, "url", "https://example.com/");
    orphan.relationships.push(Relationship {
        kind: "related_to".to_owned(),
        target_type: "fqdn".to_owned(),
        target_value: "elsewhere.example".to_owned(),
    });
    graph_tree(
        vec![email, zip, domain, orphan],
        vec![1],
        &[(10, 2), (10, 3), (10, 2), (11, 1)],
    )
}

#[test]
fn a_graph_has_the_alert_its_observables_results_tags_and_relationships() {
    let graph = graph_of(&email_graph_tree(), MAX_GRAPH_NODES, MAX_GRAPH_EDGES);
    let nodes: Vec<(&str, &str, &str)> = graph
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.kind.as_str(), n.label.as_str()))
        .collect();
    assert_eq!(
        nodes,
        [
            ("alert", "alert", "<img src=x onerror=alert(1)>"),
            ("o1", "observable", "file: email.rfc822"),
            ("r10", "result", "email_analyzer"),
            ("o2", "observable", "file: email.rfc822.parts/invoice.zip"),
            ("o3", "observable", "fqdn: example.com"),
            ("t0", "tag", "<b>email.attachment</b>"),
            ("r11", "result", "archive"),
            ("o4", "observable", "url: https://example.com/"),
        ]
    );
    assert_eq!(graph.nodes[1].observable, Some(1));
    assert_eq!(graph.nodes[2].result, Some(10));
    let edges: Vec<(&str, &str, &str, Option<&str>)> = graph
        .edges
        .iter()
        .map(|e| {
            (
                e.from.as_str(),
                e.to.as_str(),
                e.kind.as_str(),
                e.relationship.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        edges,
        [
            ("alert", "o1", "observed", None),
            ("o1", "r10", "analyzed", None),
            ("r10", "o2", "added", None),
            ("r10", "o3", "added", None),
            ("o2", "t0", "tagged", None),
            ("o2", "r11", "analyzed", None),
            ("r11", "t0", "tagged", None),
            // the archive's result names the email again: an edge back, not a second node
            ("r11", "o1", "added", None),
            ("o2", "o1", "related", Some("extracted_from")),
        ]
    );
    assert!(!graph.truncated);
    assert_eq!(graph.note, None);
}

#[test]
fn a_graph_past_its_bounds_keeps_what_is_nearest_the_alert_and_says_so() {
    let graph = graph_of(&email_graph_tree(), 4, 3);
    let ids: Vec<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids, ["alert", "o1", "r10", "o2"]);
    assert_eq!(graph.edges.len(), 3);
    for edge in &graph.edges {
        assert!(ids.contains(&edge.from.as_str()) && ids.contains(&edge.to.as_str()));
    }
    assert!(graph.truncated);
    assert_eq!(
        graph.note.as_deref(),
        Some(
            "The graph was cut short: it shows 4 of 8 nodes and 3 of 9 edges, those nearest the alert."
        )
    );

    let mut cut = email_graph_tree();
    cut.truncated = true;
    let graph = graph_of(&cut, MAX_GRAPH_NODES, MAX_GRAPH_EDGES);
    assert!(graph.truncated);
    assert_eq!(
        graph.note.as_deref(),
        Some("The alert has more than 5000 observables, and this has the first 5000.")
    );
}

#[test]
fn a_long_label_is_cut_and_every_observable_is_in_the_graph() {
    let long = "a".repeat(200);
    // nothing added these, and neither is the submission's: each still has its node
    let graph = graph_of(
        &graph_tree(
            vec![
                graph_observable(1, "fqdn", &long),
                graph_observable(2, "ip", "192.0.2.1"),
            ],
            vec![],
            &[],
        ),
        MAX_GRAPH_NODES,
        MAX_GRAPH_EDGES,
    );
    assert_eq!(graph.nodes.len(), 3);
    let label = &graph.nodes[1].label;
    assert_eq!(label.chars().count(), MAX_LABEL_CHARS);
    assert!(label.starts_with("fqdn: aaa") && label.ends_with('…'));
    assert!(graph.edges.is_empty());
}

// PLAN.md 5.14: the analyst-edited lists.

fn list_entry(kind: MatchKind, value: &str) -> NewListEntry {
    NewListEntry {
        kind,
        value: value.to_owned(),
        ignore_case: true,
        observable_type: None,
        note: String::new(),
        expires_at: None,
    }
}

/// Every list entry's id, list, match and value, and the lists' version.
async fn list_rows(db: &Db) -> (Vec<(i64, String, String, String)>, i64) {
    let rows = sqlx::query_as("SELECT id, list, match, value FROM lists.entries ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads");
    let version = sqlx::query_scalar("SELECT version FROM lists.version")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    (rows, version)
}

async fn add_list_entry_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (_, version) = list_rows(db).await;
    let entry = NewListEntry {
        note: "<b>the partner's relay</b>".to_owned(),
        ..list_entry(MatchKind::Regex, r"^relay-\d+@partner\.example$")
    };
    let added = service
        .add_list_entry(&actor, TEST_LIST.name, &entry)
        .await
        .expect("adds");
    assert_eq!(added.list, TEST_LIST.name);
    assert_eq!(added.created_by.id, Uuid::from_u128(0xAD).to_string());
    assert_eq!(added.updated_by, added.created_by);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "add_list_entry".to_owned(),
            target: ("list_entry".to_owned(), added.id.to_string()),
            before: None,
            after: Some(json!({
                "list": "test_whitelist",
                "match": "regex",
                "value": r"^relay-\d+@partner\.example$",
                "ignore_case": true,
                "observable_type": null,
                "note": "<b>the partner's relay</b>",
                "expires_at": null,
            })),
            details: json!({}),
        }
    );
    assert_eq!(
        list_rows(db).await.1,
        version + 1,
        "the write raised the version"
    );

    // a refusal, an unknown list, or an entry the service won't take, has no row
    let rows = audit_rows(db).await.len();
    let reader = UserId(Uuid::from_u128(0xC1));
    exists(db, &Holder::User(reader)).await;
    assert!(matches!(
        service
            .add_list_entry(&user(reader), TEST_LIST.name, &list_entry(MatchKind::Exact, "x"))
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "list:write"
    ));
    assert!(matches!(
        service
            .add_list_entry(&actor, "no_such_list", &list_entry(MatchKind::Exact, "x"))
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service
            .add_list_entry(&actor, TEST_LIST.name, &list_entry(MatchKind::Regex, "(unclosed"))
            .await,
        Err(ServiceError::InvalidRequest(why)) if why.starts_with("the pattern doesn't compile")
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn edit_list_entry_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let added = service
        .add_list_entry(
            &actor,
            TEST_LIST.name,
            &list_entry(MatchKind::Substring, "@old.example"),
        )
        .await
        .expect("adds");
    let key_id = ApiKeyId(Uuid::from_u128(0x1157));
    exists(db, &Holder::ApiKey(key_id)).await;
    grant(db, &Holder::ApiKey(key_id), "list", "write", Effect::Allow).await;
    let editor = key(key_id, None);
    let edited = service
        .edit_list_entry(
            &editor,
            TEST_LIST.name,
            added.id,
            &NewListEntry {
                ignore_case: false,
                note: "moved".to_owned(),
                ..list_entry(MatchKind::Exact, "relay@new.example")
            },
        )
        .await
        .expect("edits");
    assert_eq!(edited.created_by, added.created_by);
    assert_eq!(edited.updated_by.kind, "api_key");
    let row = last_audit(db).await;
    assert_eq!(row.action, "edit_list_entry");
    assert_eq!(row.actor["kind"], "api_key");
    assert_eq!(row.actor["id"], key_id.0.to_string());
    assert_eq!(row.target, ("list_entry".to_owned(), added.id.to_string()));
    assert_eq!(
        (row.before, row.after),
        (
            Some(json!({
                "list": "test_whitelist", "match": "substring", "value": "@old.example",
                "ignore_case": true, "observable_type": null, "note": "", "expires_at": null,
            })),
            Some(json!({
                "list": "test_whitelist", "match": "exact", "value": "relay@new.example",
                "ignore_case": false, "observable_type": null, "note": "moved", "expires_at": null,
            })),
        )
    );

    // the same again changes nothing and has no row; another list's entry isn't this list's
    let rows = audit_rows(db).await.len();
    let (_, version) = list_rows(db).await;
    service
        .edit_list_entry(
            &editor,
            TEST_LIST.name,
            added.id,
            &NewListEntry {
                ignore_case: false,
                note: "moved".to_owned(),
                ..list_entry(MatchKind::Exact, "relay@new.example")
            },
        )
        .await
        .expect("changes nothing");
    assert!(matches!(
        service
            .edit_list_entry(
                &actor,
                TYPED_LIST.name,
                added.id,
                &list_entry(MatchKind::Exact, "x")
            )
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    assert_eq!(
        list_rows(db).await.1,
        version,
        "an edit that changed nothing wrote nothing"
    );
    row.action
}

async fn delete_list_entry_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let added = service
        .add_list_entry(
            &actor,
            TEST_LIST.name,
            &list_entry(MatchKind::Substring, "doomed"),
        )
        .await
        .expect("adds");
    service
        .delete_list_entry(&actor, TEST_LIST.name, added.id)
        .await
        .expect("deletes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_list_entry".to_owned(),
            target: ("list_entry".to_owned(), added.id.to_string()),
            before: Some(json!({
                "list": "test_whitelist",
                "match": "substring",
                "value": "doomed",
                "ignore_case": true,
                "observable_type": null,
                "note": "",
                "expires_at": null,
                "created_by": boss_json(),
                "created_at": row.before.as_ref().expect("a before")["created_at"],
            })),
            after: None,
            details: json!({}),
        }
    );
    assert!(matches!(
        service
            .delete_list_entry(&actor, TEST_LIST.name, added.id)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    row.action
}

fn new_detection(kind: &str, value: &str) -> NewDetection {
    NewDetection {
        observable_type: kind.to_owned(),
        value: value.to_owned(),
        expires: DetectionExpiry::Default,
        context: None,
    }
}

/// A detection's entry as its audit row records it.
fn detection_entry(value: &str, expires_at: &Value, note: &str) -> Value {
    json!({
        "list": "observable_detection",
        "match": "exact",
        "value": value,
        "ignore_case": false,
        "observable_type": "fqdn",
        "note": note,
        "expires_at": expires_at,
    })
}

async fn create_detection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (_, version) = list_rows(db).await;
    let created = service
        .create_detection(&actor, &new_detection("fqdn", "audited.example"))
        .await
        .expect("adds");
    let row = last_audit(db).await;
    let expires = row.after.as_ref().expect("an after")["expires_at"].clone();
    assert!(
        expires.is_string(),
        "fqdn has ace3's default lifetime: {expires}"
    );
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_detection".to_owned(),
            target: ("list_entry".to_owned(), created.id.to_string()),
            before: None,
            after: Some(detection_entry(
                "audited.example",
                &expires,
                "manually added by alice"
            )),
            details: json!({}),
        }
    );
    assert_eq!(
        list_rows(db).await.1,
        version + 1,
        "the write raised the version"
    );

    // a refusal, a duplicate or a value that isn't one has no row
    let rows = audit_rows(db).await.len();
    let reader = UserId(Uuid::from_u128(0xD1));
    grant(
        db,
        &Holder::User(reader),
        "detection",
        "read",
        Effect::Allow,
    )
    .await;
    let rows = rows + 1;
    assert!(matches!(
        service
            .create_detection(&user(reader), &new_detection("fqdn", "x.example"))
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "detection:write"
    ));
    assert!(matches!(
        service
            .create_detection(&actor, &new_detection("fqdn", "audited.example"))
            .await,
        Err(ServiceError::Conflict(_))
    ));
    assert!(matches!(
        service
            .create_detection(&actor, &new_detection("file", "not a hash"))
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn delete_detection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let created = service
        .create_detection(
            &actor,
            &NewDetection {
                expires: DetectionExpiry::Never,
                context: Some("<b>doomed</b>".to_owned()),
                ..new_detection("fqdn", "doomed.example")
            },
        )
        .await
        .expect("adds");
    let removed = service
        .delete_detection(&actor, created.id)
        .await
        .expect("deletes");
    assert_eq!(removed.value, "doomed.example");
    let row = last_audit(db).await;
    let mut before = detection_entry("doomed.example", &Value::Null, "<b>doomed</b>");
    before["created_by"] = boss_json();
    before["created_at"] = row.before.as_ref().expect("a before")["created_at"].clone();
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_detection".to_owned(),
            target: ("list_entry".to_owned(), created.id.to_string()),
            before: Some(before),
            after: None,
            details: json!({}),
        }
    );
    assert!(matches!(
        service.delete_detection(&actor, created.id).await,
        Err(ServiceError::NotFound(why)) if why == format!("no detection {}", created.id)
    ));
    row.action
}

async fn set_detection_expiration_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let created = service
        .create_detection(&actor, &new_detection("fqdn", "expiring.example"))
        .await
        .expect("adds");
    let edited = service
        .set_detection_expiration(&actor, created.id, None)
        .await
        .expect("sets it");
    assert_eq!(edited.expires_at, None);
    let row = last_audit(db).await;
    assert_eq!(row.action, "set_detection_expiration");
    assert_eq!(
        row.target,
        ("list_entry".to_owned(), created.id.to_string())
    );
    let note = "manually added by alice";
    assert_eq!(
        (row.before.clone(), row.after.clone()),
        (
            Some(detection_entry(
                "expiring.example",
                &row.before.as_ref().expect("a before")["expires_at"],
                note
            )),
            Some(detection_entry("expiring.example", &Value::Null, note)),
        )
    );

    // the same again has no row; a past expiry and a missing detection are refused
    let rows = audit_rows(db).await.len();
    service
        .set_detection_expiration(&actor, created.id, None)
        .await
        .expect("changes nothing");
    assert!(matches!(
        service
            .set_detection_expiration(
                &actor,
                created.id,
                Some(chrono::Utc::now() - chrono::Duration::days(1))
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .set_detection_expiration(&actor, i64::MAX, None)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// PLAN.md 7.6: the detection router's listing, as ace3's: search, type and status filters, ordered by
/// type, value and id, paged and clamped, each with its comments; its types; ace3's default lifetimes;
/// and a detection is an `observable_detection` list entry the list's readers see.
#[tokio::test]
async fn detections_list_search_and_page_as_ace3_s_do() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let sha = "AB".repeat(32);
    for (kind, value) in [
        ("fqdn", "evil.example.ru"),
        ("fqdn", "100%_off.example"),
        ("fqdn", "EVIL.example.com"),
        ("ipv4", "192.0.2.1"),
        ("file", sha.as_str()),
        ("sha256", "cafe"),
    ] {
        service
            .create_detection(&actor, &new_detection(kind, value))
            .await
            .unwrap_or_else(|e| panic!("{kind} {value}: {e}"));
    }
    let expired = service
        .create_detection(&actor, &new_detection("fqdn", "expired.example"))
        .await
        .expect("adds");
    sqlx::query("UPDATE lists.entries SET expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(expired.id)
        .execute(db.pool())
        .await
        .expect("expires it");
    service
        .add_observable_comment(&actor, "ipv4", "192.0.2.1", "seen at the edge")
        .await
        .expect("comments");

    let page = |filter: DetectionFilter| {
        let service = &service;
        let actor = &actor;
        async move { service.detections(actor, &filter).await.expect("lists") }
    };
    let values = |page: &DetectionPage| -> Vec<String> {
        page.items
            .iter()
            .map(|d| format!("{}:{}", d.observable_type, d.value))
            .collect()
    };
    let all = page(DetectionFilter::default()).await;
    assert_eq!(
        values(&all),
        [
            format!("file:{}", sha.to_ascii_lowercase()),
            "fqdn:100%_off.example".to_owned(),
            "fqdn:EVIL.example.com".to_owned(),
            "fqdn:evil.example.ru".to_owned(),
            "ipv4:192.0.2.1".to_owned(),
            "sha256:cafe".to_owned(),
        ],
        "ordered by type and value, a file's sha256 lowercased"
    );
    assert_eq!(all.total, 6, "the expired one isn't active");
    let ipv4 = all
        .items
        .iter()
        .find(|d| d.observable_type == "ipv4")
        .expect("the ip");
    assert_eq!(ipv4.comments.len(), 1);
    assert_eq!(ipv4.comments[0].comment, "seen at the edge");
    let file = all
        .items
        .iter()
        .find(|d| d.observable_type == "file")
        .expect("the file");
    assert!(
        file.expires_at.is_some(),
        "ace3 lists only sha256 and md5 as never expiring"
    );
    let hash = all
        .items
        .iter()
        .find(|d| d.observable_type == "sha256")
        .expect("the hash");
    assert_eq!(hash.expires_at, None, "a sha256 never expires by default");
    let fqdn = all
        .items
        .iter()
        .find(|d| d.value == "evil.example.ru")
        .expect("the fqdn");
    let lifetime = fqdn.expires_at.expect("an expiry") - fqdn.created_at;
    assert!(
        (lifetime - chrono::Duration::days(90)).num_seconds().abs() < 60,
        "90 days: {lifetime}"
    );

    let search = |text: &str| DetectionFilter {
        search: Some(text.to_owned()),
        ..DetectionFilter::default()
    };
    assert_eq!(
        values(&page(search("evil")).await),
        ["fqdn:EVIL.example.com", "fqdn:evil.example.ru"],
        "a substring, ignoring case"
    );
    assert_eq!(
        values(&page(search("*.ru")).await),
        ["fqdn:evil.example.ru"]
    );
    assert_eq!(
        values(&page(search("evil.*")).await).len(),
        2,
        "anchored at the start"
    );
    assert_eq!(values(&page(search("*.ru*x")).await).len(), 0);
    assert_eq!(
        values(&page(search("100%_")).await),
        ["fqdn:100%_off.example"]
    );
    assert_eq!(values(&page(search("0%")).await).len(), 1, "% is itself");
    assert_eq!(values(&page(search("_")).await).len(), 1, "_ is itself");
    let typed = page(DetectionFilter {
        observable_type: Some("ipv4".to_owned()),
        ..DetectionFilter::default()
    })
    .await;
    assert_eq!(values(&typed), ["ipv4:192.0.2.1"]);
    let gone = page(DetectionFilter {
        status: DetectionStatus::Expired,
        ..DetectionFilter::default()
    })
    .await;
    assert_eq!(values(&gone), ["fqdn:expired.example"]);
    assert!(gone.items[0].expired);
    assert_eq!(
        page(DetectionFilter {
            status: DetectionStatus::All,
            ..DetectionFilter::default()
        })
        .await
        .total,
        7
    );

    // a page past the last is the last; a page size ace3 doesn't offer is 50
    let paged = page(DetectionFilter {
        page: 99,
        page_size: 25,
        ..DetectionFilter::default()
    })
    .await;
    assert_eq!(
        (paged.page, paged.total_pages, paged.items.len()),
        (1, 1, 6)
    );
    assert_eq!(paged.first_index(), 1);
    assert_eq!(paged.last_index(), 6);
    assert!(!paged.has_next() && !paged.has_prev());
    assert_eq!(
        page(DetectionFilter {
            page_size: 7,
            ..DetectionFilter::default()
        })
        .await
        .page_size,
        50
    );
    let empty = page(search("nothing matches this")).await;
    assert_eq!((empty.total, empty.page, empty.first_index()), (0, 1, 0));

    let types = service.detection_types(&actor).await.expect("types");
    assert_eq!(types.present, ["file", "fqdn", "ipv4", "sha256"]);
    assert!(types.all.contains(&"fqdn".to_owned()) && types.all.len() > types.present.len());

    // each is an exact, case-sensitive entry of the list the module reads, with its context as its note
    let list = service
        .list(&actor, ace_service::DETECTION_LIST)
        .await
        .expect("the list");
    let entry = list
        .entries
        .iter()
        .find(|e| e.value == "evil.example.ru")
        .expect("the entry");
    assert_eq!(
        (
            entry.kind,
            entry.ignore_case,
            entry.observable_type.as_deref(),
            entry.note.as_str()
        ),
        (
            MatchKind::Exact,
            false,
            Some("fqdn"),
            "manually added by alice"
        )
    );

    // reading needs detection:read, and a binary whose modules don't read the list has none
    let outsider = user(UserId(Uuid::from_u128(0xD2)));
    assert!(matches!(
        service.detections(&outsider, &DetectionFilter::default()).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "detection:read"
    ));
    let bare = Service::new(
        db.clone(),
        Orchestrator::new(Catalog::new(vec![]), Modes::ace3()),
    );
    assert!(matches!(
        bare.detections(&actor, &DetectionFilter::default()).await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        bare.create_detection(&actor, &new_detection("fqdn", "x.example"))
            .await,
        Err(ServiceError::NotFound(_))
    ));
}

/// What the service refuses, so a module never gets a list it can't compile: each entry's own checks,
/// a duplicate, a typed list's type, an expiry that passed, and the whole list's count and patterns.
#[tokio::test]
async fn a_list_takes_only_entries_a_module_can_compile() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let add = |list: &'static str, entry: NewListEntry| {
        let service = service.clone();
        let actor = actor.clone();
        async move { service.add_list_entry(&actor, list, &entry).await }
    };
    let invalid = |result: Result<ListEntry, ServiceError>| match result {
        Err(ServiceError::InvalidRequest(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    };

    add(
        TEST_LIST.name,
        list_entry(MatchKind::Substring, "@partner.example"),
    )
    .await
    .expect("adds");
    assert!(matches!(
        add(
            TEST_LIST.name,
            list_entry(MatchKind::Substring, "@partner.example")
        )
        .await,
        Err(ServiceError::Conflict(_))
    ));
    // the same value matched another way, or with case, is another entry
    add(
        TEST_LIST.name,
        NewListEntry {
            ignore_case: false,
            ..list_entry(MatchKind::Substring, "@partner.example")
        },
    )
    .await
    .expect("adds");
    assert_eq!(
        invalid(add(TEST_LIST.name, list_entry(MatchKind::Regex, r"\w{100}")).await),
        "the pattern compiles to more than 1048576 bytes; make it simpler, such as with fewer repetitions or narrower classes"
    );
    assert!(
        invalid(add(TEST_LIST.name, list_entry(MatchKind::Regex, r"(?=x)")).await)
            .starts_with("the pattern doesn't compile")
    );
    assert_eq!(
        invalid(add(TEST_LIST.name, list_entry(MatchKind::Exact, "")).await),
        "an entry's value can't be empty"
    );
    assert_eq!(
        invalid(
            add(
                TEST_LIST.name,
                NewListEntry {
                    observable_type: Some("ipv4".to_owned()),
                    ..list_entry(MatchKind::Exact, "192.0.2.1")
                }
            )
            .await
        ),
        "list test_whitelist doesn't take an observable type"
    );
    assert_eq!(
        invalid(add(TYPED_LIST.name, list_entry(MatchKind::Exact, "192.0.2.1")).await),
        "an entry on list test_typed_list has to name an observable type"
    );
    assert_eq!(
        invalid(
            add(
                TYPED_LIST.name,
                NewListEntry {
                    observable_type: Some("no_such_type".to_owned()),
                    ..list_entry(MatchKind::Exact, "192.0.2.1")
                }
            )
            .await
        ),
        "no observable type \"no_such_type\""
    );
    let typed = add(
        TYPED_LIST.name,
        NewListEntry {
            observable_type: Some("ipv4".to_owned()),
            ..list_entry(MatchKind::Exact, "192.0.2.1")
        },
    )
    .await
    .expect("adds");
    assert_eq!(typed.observable_type.as_deref(), Some("ipv4"));
    assert_eq!(
        invalid(
            add(
                TEST_LIST.name,
                NewListEntry {
                    expires_at: Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
                    ..list_entry(MatchKind::Exact, "late")
                }
            )
            .await
        ),
        "an entry's expiry has to be in the future"
    );

    // each \w{10} compiles alone, and twenty of them together pass the list's limit
    for i in 0..16 {
        add(
            TEST_LIST.name,
            list_entry(MatchKind::Regex, &format!(r"\w{{10}}{i}")),
        )
        .await
        .expect("adds a pattern");
    }
    assert_eq!(
        invalid(add(TEST_LIST.name, list_entry(MatchKind::Regex, r"\w{10}z")).await),
        "the list's patterns would compile to more than 8388608 bytes together; remove or simplify some"
    );

    // a list holds at most MAX_ENTRIES, counted as committed
    let room = MAX_ENTRIES as i64
        - sqlx::query_scalar::<_, i64>("SELECT count(*) FROM lists.entries WHERE list = $1")
            .bind(TEST_LIST.name)
            .fetch_one(db.pool())
            .await
            .expect("counts");
    sqlx::query(
        "INSERT INTO lists.entries (list, match, value, ignore_case, created_by, updated_by)
         SELECT $1, 'exact', 'filler-' || n, true, $2::jsonb, $2::jsonb FROM generate_series(1, $3) n",
    )
    .bind(TEST_LIST.name)
    .bind(boss_json())
    .bind(room)
    .execute(db.pool())
    .await
    .expect("fills the list");
    assert_eq!(
        invalid(add(TEST_LIST.name, list_entry(MatchKind::Exact, "one more")).await),
        "list test_whitelist holds at most 1000 entries"
    );

    // the list reads back in order, and the lists count their entries
    let summaries = service.lists(&actor).await.expect("lists");
    let names: Vec<(&str, i64)> = summaries.iter().map(|s| (s.spec.name, s.entries)).collect();
    assert_eq!(
        names,
        [
            ("observable_detection", 0),
            ("test_typed_list", 1),
            ("test_whitelist", 1000)
        ]
    );
    let list = service.list(&actor, TEST_LIST.name).await.expect("reads");
    assert_eq!(list.entries.len(), 1000);
    assert_eq!(list.entries[0].value, "@partner.example");
    assert!(list.entries.windows(2).all(|w| w[0].id < w[1].id));
    assert!(matches!(
        service.list(&actor, "no_such_list").await,
        Err(ServiceError::NotFound(_))
    ));
    let nobody = UserId(Uuid::from_u128(0xC2));
    exists(db, &Holder::User(nobody)).await;
    assert!(matches!(
        service.lists(&user(nobody)).await,
        Err(ServiceError::PermissionDenied { ref permission, .. }) if permission.to_string() == "list:read"
    ));
}

/// The hunter, as `ace hunter` acts: the component migration 0034 grants.
fn hunter() -> Actor {
    Actor::Internal {
        id: Component::new("hunter").expect("valid"),
    }
}

fn hunter_json() -> Value {
    json!({"kind": "internal", "id": "hunter"})
}

fn loaded_hunt(path: &str) -> LoadedHuntRow {
    LoadedHuntRow {
        kind: "splunk".to_owned(),
        path: path.to_owned(),
        name: Some("hunt".to_owned()),
        uuid: Some("00000000-0000-0000-0000-00000000a001".to_owned()),
        enabled: Some(true),
        frequency: Some("00:10:00".to_owned()),
        error: None,
    }
}

fn hunt_time(text: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(text)
        .expect("a time")
        .with_timezone(&chrono::Utc)
}

fn hunt_run(read: HuntState, submissions: Vec<HuntSubmission>) -> HuntRun {
    HuntRun {
        kind: "splunk".to_owned(),
        name: "hunt".to_owned(),
        uuid: "00000000-0000-0000-0000-00000000a001".to_owned(),
        at: hunt_time("2026-11-01T12:00:00Z"),
        read,
        state: HuntState {
            last_executed_time: Some(hunt_time("2026-11-01T12:00:00Z")),
            last_end_time: Some(hunt_time("2026-11-01T12:00:00Z")),
            last_alert_time: Some(hunt_time("2026-11-01T12:00:00Z")),
            last_alert_times: Default::default(),
        },
        window_start: Some(hunt_time("2026-11-01T11:50:00Z")),
        window_end: Some(hunt_time("2026-11-01T12:00:00Z")),
        submissions,
        suppressed: vec![],
    }
}

/// A hunt's submission as the hunter makes one: its detection on its signature_id observable.
fn hunt_submission() -> HuntSubmission {
    let mut signature = NewObservable::new(
        ObservableKind::SignatureId,
        "00000000-0000-0000-0000-00000000a001",
    );
    signature.detections.push(ace_results::Detection {
        description: "hunt hunt (splunk) matched".to_owned(),
        details: None,
        queue: None,
        signature_uuid: Some("00000000-0000-0000-0000-00000000a001".to_owned()),
        signature_version: Some("unknown".to_owned()),
        signature_family: Some("hunt".to_owned()),
    });
    let mut ip = NewObservable::new(ObservableKind::Ip, "10.1.2.3");
    ip.display_type = Some("Source IP".to_owned());
    HuntSubmission {
        submission: Submission {
            description: "hunt: vpn".to_owned(),
            analysis_mode: Some("correlation".to_owned()),
            event_time: Some(hunt_time("2026-11-01T11:55:00Z")),
            observables: vec![],
            file_yara_meta: Default::default(),
        },
        origin: ace_core::submit::Origin {
            event_time_from_query: true,
            observables: vec![ip, signature],
            details: Some(json!({"alert_type": "hunter - splunk", "queue": "default"})),
            queue: None,
        },
        dedup_key: None,
        suppression_key: None,
        group_value: None,
        events: 1,
    }
}

async fn sync_hunts_records_its_row(db: &Db) -> String {
    let service = service(db);
    let failed = LoadedHuntRow {
        name: None,
        uuid: None,
        enabled: None,
        frequency: None,
        error: Some("ValueError: nope".to_owned()),
        ..loaded_hunt("b.yaml")
    };
    service
        .sync_hunts(
            &hunter(),
            "splunk",
            &[failed.clone(), loaded_hunt("a.yaml")],
        )
        .await
        .expect("records");
    let row = last_audit(db).await;
    let hunt = json!({"type": "splunk", "path": "a.yaml", "name": "hunt", "uuid": "00000000-0000-0000-0000-00000000a001",
                      "enabled": true, "frequency": "00:10:00", "error": null});
    let bad = json!({"type": "splunk", "path": "b.yaml", "name": null, "uuid": null, "enabled": null,
                     "frequency": null, "error": "ValueError: nope"});
    assert_eq!(
        row,
        AuditRow {
            actor: hunter_json(),
            action: "sync_hunts".to_owned(),
            target: ("hunt_type".to_owned(), "splunk".to_owned()),
            before: Some(json!({"hunts": []})),
            after: Some(json!({"hunts": [hunt, bad]})),
            details: json!({}),
        }
    );
    // the same hunts again change nothing, so no row
    let rows = audit_rows(db).await.len();
    service
        .sync_hunts(&hunter(), "splunk", &[loaded_hunt("a.yaml"), failed])
        .await
        .expect("records");
    assert_eq!(audit_rows(db).await.len(), rows);
    let listed = service.hunts(&admin(db).await).await.expect("lists");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].state, None, "it hasn't run");
    row.action
}

async fn record_hunt_run_records_its_row(db: &Db) -> String {
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let recorded = service
        .record_hunt_run(
            &hunter(),
            &bucket,
            &hunt_run(HuntState::default(), vec![hunt_submission()]),
        )
        .await
        .expect("records");
    assert_eq!(recorded.roots.len(), 1);
    let root = recorded.roots[0];
    let row = last_audit(db).await;
    let after = json!({
        "last_executed_time": "2026-11-01T12:00:00Z",
        "last_end_time": "2026-11-01T12:00:00Z",
        "last_alert_time": "2026-11-01T12:00:00Z",
        "last_alert_times": {},
    });
    assert_eq!(
        row,
        AuditRow {
            actor: hunter_json(),
            action: "record_hunt_run".to_owned(),
            target: ("hunt".to_owned(), "splunk/hunt".to_owned()),
            before: Some(
                json!({"last_executed_time": null, "last_end_time": null, "last_alert_time": null, "last_alert_times": {}})
            ),
            after: Some(after),
            details: json!({
                "window_start": "2026-11-01T11:50:00Z",
                "window_end": "2026-11-01T12:00:00Z",
                "roots": [root],
                "suppressed": 0,
                "duplicates": 0,
            }),
        }
    );
    row.action
}

/// A run's roots and its state commit together, and a run that read a state another run has since
/// moved writes nothing: so no window is searched twice or skipped.
#[tokio::test]
async fn a_hunt_run_commits_its_roots_with_its_state() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let recorded = service
        .record_hunt_run(
            &hunter(),
            &bucket,
            &hunt_run(HuntState::default(), vec![hunt_submission()]),
        )
        .await
        .expect("records");
    let root = recorded.roots[0];
    let (alerted, origin, source): (Option<chrono::DateTime<chrono::Utc>>, Option<Value>, String) =
        sqlx::query_as(
            "SELECT alerted_at, origin, event_time_source::text FROM analysis.roots WHERE id = $1",
        )
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("the root");
    assert!(alerted.is_some(), "the hunt's detection makes it an alert");
    assert_eq!(
        origin,
        Some(json!({"alert_type": "hunter - splunk", "queue": "default"}))
    );
    assert_eq!(source, "query_time");
    let (description, signature): (String, Option<String>) = sqlx::query_as(
        "SELECT d.description, d.signature_family FROM analysis.detections d
         JOIN analysis.observables o ON o.id = d.observable_id WHERE d.root_id = $1 AND o.type = 'signature_id'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the detection");
    assert_eq!(
        (description.as_str(), signature.as_deref()),
        ("hunt hunt (splunk) matched", Some("hunt"))
    );
    let stored = service
        .hunt_state(&hunter(), "splunk", "hunt")
        .await
        .expect("reads");
    assert_eq!(stored, hunt_run(HuntState::default(), vec![]).state);

    // a second run that read the state before the first committed: nothing written
    let roots = root_count(db).await;
    let stale = service
        .record_hunt_run(
            &hunter(),
            &bucket,
            &hunt_run(HuntState::default(), vec![hunt_submission()]),
        )
        .await;
    assert!(matches!(stale, Err(ServiceError::Conflict(_))), "{stale:?}");
    assert_eq!(root_count(db).await, roots);
    assert_eq!(
        service
            .hunt_state(&hunter(), "splunk", "hunt")
            .await
            .expect("reads"),
        stored
    );

    // and a component without the grant can't record one
    let other = Actor::Internal {
        id: Component::new("not-the-hunter").expect("valid"),
    };
    assert!(matches!(
        service
            .record_hunt_run(&other, &bucket, &hunt_run(stored.clone(), vec![]))
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
}

/// A grouped hunt's submission for one source address, keyed by its user.
fn grouped_hit(ip: &str, user: &str) -> HuntSubmission {
    let mut hit = hunt_submission();
    hit.submission.description = format!("hunt: {ip}");
    hit.dedup_key = Some(format!("00000000-0000-0000-0000-00000000a001:{user}"));
    hit.suppression_key = Some(ip.to_owned());
    hit.group_value = Some(json!(ip));
    hit.events = 2;
    hit
}

fn alerted(
    keys: &[&str],
    at: &str,
) -> std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>> {
    keys.iter()
        .map(|k| ((*k).to_owned(), hunt_time(at)))
        .collect()
}

/// PLAN.md 6.5: each hit a hunt drops is a row, in the run's transaction: a group its suppression
/// drops, pointing at the root that group alerted with, and a duplicate of a live dedup key, pointing at
/// the root that made the key. A hit neither drops leaves no row, and a key past its 4 hours drops
/// nothing. The rows read back through `hunt_suppressions`, a page at a time.
#[tokio::test]
async fn a_suppressed_hit_leaves_a_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    service
        .sync_hunts(&hunter(), "splunk", &[loaded_hunt("a.yaml")])
        .await
        .expect("records");
    let uuid = "00000000-0000-0000-0000-00000000a001";
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hunts.suppressions")
            .fetch_one(db.pool())
            .await
            .expect("counts")
    };

    // 12:00: two groups alert; the third hit repeats the first's dedup key in the same run
    let mut first = hunt_run(
        HuntState::default(),
        vec![
            grouped_hit("10.9.9.9", "alice"),
            grouped_hit("10.8.8.8", "bob"),
            grouped_hit("10.7.7.7", "alice"),
        ],
    );
    first.state.last_alert_time = None;
    first.state.last_alert_times = alerted(
        &["10.9.9.9", "10.8.8.8", "10.7.7.7"],
        "2026-11-01T12:00:00Z",
    );
    let one = service
        .record_hunt_run(&hunter(), &bucket, &first)
        .await
        .expect("records");
    assert_eq!(one.roots.len(), 2, "the duplicate makes no root");
    assert_eq!(one.suppressions.len(), 1);
    let page = service
        .hunt_suppressions(&hunter(), uuid, None, None)
        .await
        .expect("reads");
    let duplicate = &page.suppressions[0];
    assert_eq!(duplicate.reason, SuppressionReason::Duplicate);
    assert_eq!(duplicate.key, "00000000-0000-0000-0000-00000000a001:alice");
    assert_eq!(duplicate.group_value, Some(json!("10.7.7.7")));
    assert_eq!(duplicate.description, "hunt: 10.7.7.7");
    assert_eq!(duplicate.events, 2);
    assert_eq!(
        duplicate.cause_root,
        Some(one.roots[0]),
        "the root that made the key"
    );
    assert_eq!(
        (duplicate.window_start, duplicate.window_end),
        (
            hunt_time("2026-11-01T12:00:00Z"),
            hunt_time("2026-11-01T16:00:00Z")
        )
    );
    assert_eq!(duplicate.decided_at, hunt_time("2026-11-01T12:00:00Z"));
    assert_eq!(
        duplicate.search_start,
        Some(hunt_time("2026-11-01T11:50:00Z"))
    );
    assert_eq!(page.next, None);

    // 12:10: 10.9.9.9 alerted at 12:00 and its suppression lasts an hour; 10.6.6.6 is new
    let read = service
        .hunt_state(&hunter(), "splunk", "hunt")
        .await
        .expect("reads");
    let mut second = hunt_run(read.clone(), vec![grouped_hit("10.6.6.6", "carol")]);
    second.at = hunt_time("2026-11-01T12:10:00Z");
    second.state.last_alert_time = None;
    second.state.last_alert_times = read.last_alert_times.clone();
    second
        .state
        .last_alert_times
        .insert("10.6.6.6".to_owned(), hunt_time("2026-11-01T12:10:00Z"));
    second.suppressed = vec![GroupSuppressed {
        key: "10.9.9.9".to_owned(),
        group_value: Some(json!("10.9.9.9")),
        description: "hunt: 10.9.9.9".to_owned(),
        event_time: hunt_time("2026-11-01T12:05:00Z"),
        events: 1,
        since: hunt_time("2026-11-01T12:00:00Z"),
        until: hunt_time("2026-11-01T13:00:00Z"),
    }];
    // the same run, but read before the first committed, writes neither its roots nor its rows
    let stale = HuntRun {
        read: HuntState::default(),
        ..second.clone()
    };
    let (roots, rows) = (root_count(db).await, count().await);
    assert!(matches!(
        service.record_hunt_run(&hunter(), &bucket, &stale).await,
        Err(ServiceError::Conflict(_))
    ));
    assert_eq!((root_count(db).await, count().await), (roots, rows));
    let two = service
        .record_hunt_run(&hunter(), &bucket, &second)
        .await
        .expect("records");
    assert_eq!(
        two.roots.len(),
        1,
        "the new group alerts, and leaves no row"
    );
    assert_eq!(two.suppressions.len(), 1);
    let page = service
        .hunt_suppressions(&hunter(), uuid, None, None)
        .await
        .expect("reads");
    assert_eq!(page.suppressions.len(), 2);
    let group = &page.suppressions[0];
    assert_eq!(group.reason, SuppressionReason::Group);
    assert_eq!(group.key, "10.9.9.9");
    assert_eq!(
        group.cause_root,
        Some(one.roots[0]),
        "the root 10.9.9.9 alerted with"
    );
    assert_eq!(
        (group.window_start, group.window_end),
        (
            hunt_time("2026-11-01T12:00:00Z"),
            hunt_time("2026-11-01T13:00:00Z")
        )
    );
    assert_eq!(group.event_time, hunt_time("2026-11-01T12:05:00Z"));
    assert_eq!(group.decided_at, hunt_time("2026-11-01T12:10:00Z"));
    let audit = last_audit(db).await;
    assert_eq!(audit.details["suppressed"], 1);
    assert_eq!(audit.details["duplicates"], 0);

    // a page at a time, newest first
    let first_page = service
        .hunt_suppressions(&hunter(), uuid, Some(1), None)
        .await
        .expect("reads");
    assert_eq!(first_page.suppressions[0].id, group.id);
    let next = first_page.next.expect("another page");
    let last_page = service
        .hunt_suppressions(&hunter(), uuid, Some(1), Some(next))
        .await
        .expect("reads");
    assert_eq!(last_page.suppressions[0].id, duplicate.id);
    assert_eq!(last_page.next, None);
    for (limit, after) in [(Some(0), None), (Some(501), None), (None, Some(i64::MAX))] {
        assert!(matches!(
            service
                .hunt_suppressions(&hunter(), uuid, limit, after)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    assert!(matches!(
        service
            .hunt_suppressions(&hunter(), "no-such", None, None)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    let other = Actor::Internal {
        id: Component::new("not-the-hunter").expect("valid"),
    };
    assert!(matches!(
        service.hunt_suppressions(&other, uuid, None, None).await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    // 16:05: alice's key was made at 12:00, so it's gone, and her hit alerts with no row; the groups'
    // alert times have expired, so the roots they pointed to go too
    let read = service
        .hunt_state(&hunter(), "splunk", "hunt")
        .await
        .expect("reads");
    let mut third = hunt_run(read, vec![grouped_hit("10.5.5.5", "alice")]);
    third.at = hunt_time("2026-11-01T16:05:00Z");
    third.state.last_alert_time = None;
    third.state.last_alert_times = alerted(&["10.5.5.5"], "2026-11-01T16:05:00Z");
    let three = service
        .record_hunt_run(&hunter(), &bucket, &third)
        .await
        .expect("records");
    assert_eq!((three.roots.len(), three.suppressions.len()), (1, 0));
    let keys: Vec<(String, Uuid)> =
        sqlx::query_as("SELECT key, root FROM hunts.alert_keys ORDER BY key")
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(keys, vec![("10.5.5.5".to_owned(), three.roots[0])]);
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM hunts.dedup_keys")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(
        live, 2,
        "alice's new key and carol's of 12:10; bob's expired"
    );

    // 31 days on, the rows are past their retention and go with the next run
    let read = service
        .hunt_state(&hunter(), "splunk", "hunt")
        .await
        .expect("reads");
    let mut later = hunt_run(read, vec![]);
    later.at = hunt_time("2026-12-02T16:05:00Z");
    later.state.last_alert_time = None;
    service
        .record_hunt_run(&hunter(), &bucket, &later)
        .await
        .expect("records");
    assert_eq!(count().await, 0);
}

fn validation() -> HuntValidation {
    HuntValidation {
        target: "hunts/splunk/x.yaml".to_owned(),
        kind: Some("splunk".to_owned()),
        name: Some("x".to_owned()),
        uuid: Some("u".to_owned()),
        valid: true,
        error: None,
        events: Some(2),
        roots: 1,
    }
}

async fn validate_hunt_records_its_row(db: &Db) -> String {
    let service = service(db);
    let answer = service
        .validate_hunt(&admin(db).await, &|| (validation(), 7))
        .await
        .expect("validates");
    assert_eq!(answer, 7);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "validate_hunt".to_owned(),
            target: ("hunt_type".to_owned(), "splunk".to_owned()),
            before: None,
            after: None,
            details: json!({"target": "hunts/splunk/x.yaml", "type": "splunk", "name": "x", "uuid": "u",
                            "valid": true, "error": null, "events": 2, "roots": 1}),
        }
    );
    // one without hunt:write is refused before the validation runs
    let ran = std::sync::atomic::AtomicBool::new(false);
    let nobody = Actor::Internal {
        id: Component::new("nobody").expect("valid"),
    };
    assert!(matches!(
        service
            .validate_hunt(&nobody, &|| {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                (validation(), ())
            })
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    row.action
}

// PLAN.md 7.6: the detection service's helpers, ace3's search pattern, lifetimes, page sizes and
// value checks.

#[test]
fn a_detection_search_is_ace3_s_pattern() {
    use ace_service::detection_search_pattern as search_pattern;
    assert_eq!(search_pattern("evil"), "%evil%");
    assert_eq!(search_pattern("100%_a\\b"), "%100\\%\\_a\\\\b%");
    assert_eq!(search_pattern("*.ru"), "%.ru");
    assert_eq!(search_pattern("evil.*"), "evil.%");
}

#[test]
fn hashes_never_expire_by_default_and_the_rest_take_90_days() {
    use ace_service::default_detection_expiry;
    let now = chrono::Utc::now();
    let kind = |name: &str| name.parse::<ace_results::ObservableKind>().expect("a type");
    assert_eq!(default_detection_expiry(kind("sha256"), now), None);
    assert_eq!(default_detection_expiry(kind("md5"), now), None);
    assert_eq!(
        default_detection_expiry(kind("fqdn"), now),
        Some(now + chrono::Duration::days(90))
    );
}

#[test]
fn a_detection_page_size_is_one_ace3_offers() {
    assert_eq!(ace_service::clamp_detection_page_size(100), 100);
    assert_eq!(ace_service::clamp_detection_page_size(7), 50);
}

#[test]
fn a_detection_value_is_checked_for_its_type() {
    use ace_service::detection_identity as identity;
    let sha = "AB".repeat(32);
    assert_eq!(
        identity("file", &format!(" {sha} ")).expect("a file").1,
        sha.to_ascii_lowercase()
    );
    assert!(identity("file", "not a hash").is_err());
    assert!(identity("no_such_type", "x").is_err());
    assert!(identity("fqdn", "").is_err());
    assert_eq!(
        identity("fqdn", " Evil.example ").expect("an fqdn").1,
        " Evil.example "
    );
}

// PLAN.md 7.9: remediations and file collections.

fn test_target(value: &str) -> TargetKey {
    TargetKey {
        remediator: "test".to_owned(),
        observable_type: "test".to_owned(),
        observable_value: value.to_owned(),
    }
}

/// Every action's row and its tries, for a write that must change nothing.
async fn action_rows(db: &Db) -> (Vec<(i64, String, Option<String>)>, i64, i64) {
    let rows = sqlx::query_as("SELECT id, status, result FROM queue.actions ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads");
    let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM queue.action_attempts")
        .fetch_one(db.pool())
        .await
        .expect("reads");
    let holds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM store.holds WHERE holder_kind = 'file_collection'",
    )
    .fetch_one(db.pool())
    .await
    .expect("reads");
    (rows, attempts, holds)
}

/// Ends an action's try as a pool would have, by hand.
async fn complete(db: &Db, id: i64, result: &str) {
    sqlx::query(
        "UPDATE queue.actions SET status = 'COMPLETED', result = $2, updated_at = now(),
                attempts = attempts + 1, restore_key = CASE WHEN kind = 'remediation' THEN 'key-' || id END
         WHERE id = $1",
    )
    .bind(id)
    .bind(result)
    .execute(db.pool())
    .await
    .expect("completes");
}

struct ActionFixtures {
    pending: i64,
    removed: i64,
    collection: i64,
}

/// A pending remediation, a removal that succeeded, a pending collection, and a collection past its
/// retention whose file a prune would let go.
async fn action_fixtures(db: &Db, service: &Service, actor: &Actor) -> ActionFixtures {
    let queued = service
        .queue_remediations(
            actor,
            RemediationAction::Remove,
            &[test_target("DELAYED"), test_target("SUCCESS")],
        )
        .await
        .expect("queues");
    complete(db, queued[1].id, "SUCCESS").await;
    let collection = collection(db, None, "h1@C:\\a.exe").await;
    let old = collection_with_file(db, "h2@C:\\b.exe", &"c".repeat(64), 8).await;
    let _ = old;
    ActionFixtures {
        pending: queued[0].id,
        removed: queued[1].id,
        collection,
    }
}

/// A file collection requested by `root`, or by no alert.
async fn collection(db: &Db, root: Option<Uuid>, value: &str) -> i64 {
    let mut tx = db.begin().await.expect("begins");
    let requested = ace_core::actions::request_collection(
        &mut tx,
        &test_actions(),
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
    requested.id()
}

/// A collection that completed `days` ago with a file it and nothing else holds.
async fn collection_with_file(db: &Db, value: &str, sha256: &str, days: i32) -> i64 {
    let id = collection(db, None, value).await;
    sqlx::query(
        "INSERT INTO store.objects (pool, sha256, size, mime_type) VALUES ('alert_files', $1, 1, 'x')
         ON CONFLICT DO NOTHING",
    )
    .bind(sha256)
    .execute(db.pool())
    .await
    .expect("an object");
    sqlx::query(
        "UPDATE queue.actions SET status = 'COMPLETED', result = 'SUCCESS', attempts = 1,
                updated_at = now() - make_interval(days => $2), file_sha256 = $3, file_size = 1,
                file_name = 'b.exe'
         WHERE id = $1",
    )
    .bind(id)
    .bind(days)
    .bind(sha256)
    .execute(db.pool())
    .await
    .expect("completes");
    sqlx::query(
        "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id)
         VALUES ('alert_files', $1, 'file_collection', $2)",
    )
    .bind(sha256)
    .bind(id.to_string())
    .execute(db.pool())
    .await
    .expect("a hold");
    id
}

fn action_state_json(action: &str, status: &str, result: Option<&str>, value: &str) -> Value {
    json!({
        "kind": "remediation", "handler": "test", "observable_type": "test",
        "observable_value": value, "action": action, "status": status, "result": result,
    })
}

async fn queue_remediations_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let queued = service
        .queue_remediations(
            &actor,
            RemediationAction::Remove,
            &[test_target("SUCCESS"), test_target("FAILED")],
        )
        .await
        .expect("queues");
    assert_eq!(queued.len(), 2);
    assert_eq!(
        (queued[0].status.as_str(), queued[0].action.as_deref()),
        ("NEW", Some("remove"))
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "queue_remediations".to_owned(),
            target: (
                "actions".to_owned(),
                format!("{},{}", queued[0].id, queued[1].id)
            ),
            before: None,
            after: Some(json!({"action": "remove", "remediations": [
                {"id": queued[0].id, "remediator": "test", "observable_type": "test", "observable_value": "SUCCESS"},
                {"id": queued[1].id, "remediator": "test", "observable_type": "test", "observable_value": "FAILED"},
            ]})),
            details: json!({}),
        }
    );
    // attributed to the person who asked
    let attributed: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM queue.actions WHERE id = $1")
            .bind(queued[0].id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(attributed, Some(Uuid::from_u128(0xAD)));

    // a refusal, a remediator this server hasn't, a type it doesn't remediate or a key with no owner has
    // no row and queues nothing
    let rows = audit_rows(db).await.len();
    let reader = UserId(Uuid::from_u128(0x7E));
    grant(
        db,
        &Holder::User(reader),
        "remediation",
        "read",
        Effect::Allow,
    )
    .await;
    let rows = rows + 1;
    let before = action_rows(db).await;
    assert!(matches!(
        service
            .queue_remediations(&user(reader), RemediationAction::Remove, &[test_target("SUCCESS")])
            .await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "remediation:write"
    ));
    let nobody = TargetKey {
        remediator: "office365_email".to_owned(),
        ..test_target("x")
    };
    assert!(matches!(
        service
            .queue_remediations(
                &actor,
                RemediationAction::Remove,
                &[test_target("SUCCESS"), nobody]
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    let wrong_type = TargetKey {
        observable_type: "fqdn".to_owned(),
        ..test_target("x")
    };
    assert!(matches!(
        service
            .queue_remediations(&actor, RemediationAction::Remove, &[wrong_type])
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    let made = service
        .create_api_key(&actor, "service", None, &[])
        .await
        .expect("makes a key");
    grant(
        db,
        &Holder::ApiKey(made.id),
        "remediation",
        "write",
        Effect::Allow,
    )
    .await;
    let rows = rows + 2;
    let ownerless = Actor::ApiKey {
        id: made.id,
        name: "service".to_owned(),
        owner: None,
    };
    assert!(matches!(
        service
            .queue_remediations(
                &ownerless,
                RemediationAction::Remove,
                &[test_target("SUCCESS")]
            )
            .await,
        Err(ServiceError::Forbidden(_))
    ));
    assert_eq!(action_rows(db).await, before);
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn cancel_remediation_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let queued = service
        .queue_remediations(&actor, RemediationAction::Remove, &[test_target("DELAYED")])
        .await
        .expect("queues");
    let id = queued[0].id;
    let cancelled = service
        .cancel_remediation(&actor, id)
        .await
        .expect("cancels");
    assert_eq!(
        (cancelled.status.as_str(), cancelled.result.as_deref()),
        ("COMPLETED", Some("CANCELLED"))
    );
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "cancel_remediation".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(action_state_json("remove", "NEW", None, "DELAYED")),
            after: Some(action_state_json(
                "remove",
                "COMPLETED",
                Some("CANCELLED"),
                "DELAYED"
            )),
            details: json!({}),
        }
    );
    let history = service
        .remediation_history(&actor, id, 10)
        .await
        .expect("reads");
    assert_eq!(history[0].message, "cancelled by alice");
    // a completed one is a conflict, and a missing one isn't found
    assert!(matches!(
        service.cancel_remediation(&actor, id).await,
        Err(ServiceError::Conflict(_))
    ));
    assert!(matches!(
        service.cancel_remediation(&actor, i64::MAX).await,
        Err(ServiceError::NotFound(_))
    ));
    row.action
}

async fn retry_remediation_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let queued = service
        .queue_remediations(&actor, RemediationAction::Remove, &[test_target("ERROR")])
        .await
        .expect("queues");
    let id = queued[0].id;
    assert!(matches!(
        service.retry_remediation(&actor, id).await,
        Err(ServiceError::Conflict(_))
    ));
    complete(db, id, "ERROR").await;
    let retried = service
        .retry_remediation(&actor, id)
        .await
        .expect("retries");
    assert_eq!((retried.status.as_str(), retried.result), ("NEW", None));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "retry_remediation".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(action_state_json(
                "remove",
                "COMPLETED",
                Some("ERROR"),
                "ERROR"
            )),
            after: Some(action_state_json("remove", "NEW", None, "ERROR")),
            details: json!({}),
        }
    );
    row.action
}

async fn restore_remediation_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let queued = service
        .queue_remediations(&actor, RemediationAction::Remove, &[test_target("SUCCESS")])
        .await
        .expect("queues");
    let id = queued[0].id;
    assert!(matches!(
        service.restore_remediation(&actor, id).await,
        Err(ServiceError::Conflict(_))
    ));
    complete(db, id, "SUCCESS").await;
    let restore = service
        .restore_remediation(&actor, id)
        .await
        .expect("restores");
    assert_eq!(restore.action.as_deref(), Some("restore"));
    let key: Option<String> =
        sqlx::query_scalar("SELECT restore_key FROM queue.actions WHERE id = $1")
            .bind(restore.id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(key, Some(format!("key-{id}")), "the removal's restore key");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "restore_remediation".to_owned(),
            target: ("action".to_owned(), restore.id.to_string()),
            before: None,
            after: Some(json!({"action": "restore", "remediations": [
                {"id": restore.id, "remediator": "test", "observable_type": "test", "observable_value": "SUCCESS"},
            ]})),
            details: json!({"removal": id}),
        }
    );
    // queueing a restore of the target takes the same key
    let again = service
        .queue_remediations(
            &actor,
            RemediationAction::Restore,
            &[test_target("SUCCESS")],
        )
        .await
        .expect("queues");
    let key: Option<String> =
        sqlx::query_scalar("SELECT restore_key FROM queue.actions WHERE id = $1")
            .bind(again[0].id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(key, Some(format!("key-{id}")));
    row.action
}

async fn delete_remediation_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let queued = service
        .queue_remediations(&actor, RemediationAction::Remove, &[test_target("IGNORE")])
        .await
        .expect("queues");
    let id = queued[0].id;
    service
        .delete_remediation(&actor, id)
        .await
        .expect("deletes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_remediation".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(action_state_json("remove", "NEW", None, "IGNORE")),
            after: None,
            details: json!({}),
        }
    );
    assert!(matches!(
        service.delete_remediation(&actor, id).await,
        Err(ServiceError::NotFound(_))
    ));
    row.action
}

fn collection_state_json(status: &str, result: Option<&str>, value: &str) -> Value {
    json!({
        "kind": "file_collection", "handler": "edr", "observable_type": "file_location",
        "observable_value": value, "action": null, "status": status, "result": result,
    })
}

fn collection_ask(value: &str, alerts: &[Uuid]) -> ace_service::CollectionAsk {
    ace_service::CollectionAsk {
        collector: "edr".to_owned(),
        observable_type: "file_location".to_owned(),
        observable_value: value.to_owned(),
        alerts: alerts.to_vec(),
    }
}

/// `alert`, made an alert.
async fn an_alert(db: &Db) -> Uuid {
    let root = alert(db).await;
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    root
}

/// The owner's decision of 2026-11-13: someone asks a collector for a file. A request for a file a
/// pending collection is fetching joins it, the alerts it names belonging to it as well (#1101), and each
/// is audited; one after that collection completed queues another; what isn't a request is refused with no
/// row.
async fn request_file_collection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (first, second) = (an_alert(db).await, an_alert(db).await);
    let value = "h8@C:\\r.exe";
    let queued = service
        .request_file_collection(&actor, &collection_ask(value, &[]))
        .await
        .expect("queues");
    assert!(queued.queued);
    assert_eq!(
        (
            queued.status.as_str(),
            queued.result.as_deref(),
            queued.alerts.len()
        ),
        ("NEW", None, 0)
    );
    let id = queued.id;
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "request_file_collection".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: None,
            after: Some(json!({
                "collector": "edr", "observable_type": "file_location", "observable_value": value,
                "alerts": [],
            })),
            details: json!({}),
        }
    );
    let (by, user): (Value, Option<Uuid>) =
        sqlx::query_as("SELECT requested_by, user_id FROM queue.actions WHERE id = $1")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!((by, user), (boss_json(), Some(Uuid::from_u128(0xAD))));

    // the same file again joins it, for the alerts named, a repeated one once
    let joined = service
        .request_file_collection(&actor, &collection_ask(value, &[first, first]))
        .await
        .expect("joins");
    assert_eq!((joined.id, joined.queued), (id, false));
    assert_eq!(joined.alerts, [first]);
    let joined = service
        .request_file_collection(&actor, &collection_ask(value, &[second, first]))
        .await
        .expect("joins");
    assert_eq!((joined.id, joined.queued), (id, false));
    assert_eq!(joined.alerts, [first, second], "in the order they asked");
    let joined_row = last_audit(db).await;
    let state = |alerts: Value| {
        json!({
            "collector": "edr", "observable_type": "file_location", "observable_value": value,
            "alerts": alerts,
        })
    };
    assert_eq!(
        (
            joined_row.action.as_str(),
            joined_row.before,
            joined_row.after
        ),
        (
            "request_file_collection",
            Some(state(json!([first]))),
            Some(state(json!([first, second]))),
        )
    );
    // a module's request for one of those alerts joins it too
    let by_module = collection(db, Some(first), value).await;
    assert_eq!(by_module, id);

    // once it completed, a request queues another, where a module would get its own back
    complete(db, id, "SUCCESS").await;
    let again = service
        .request_file_collection(&actor, &collection_ask(value, &[first]))
        .await
        .expect("queues");
    assert!(again.queued);
    assert_ne!(again.id, id);

    // refusals, with no row
    let rows = audit_rows(db).await.len();
    let not_an_alert = alert(db).await;
    let refusals: Vec<(ace_service::CollectionAsk, &str)> = vec![
        (
            ace_service::CollectionAsk {
                collector: "endpoint".to_owned(),
                ..collection_ask(value, &[])
            },
            "invalid",
        ),
        (
            ace_service::CollectionAsk {
                observable_type: "hostname".to_owned(),
                ..collection_ask("h8", &[])
            },
            "invalid",
        ),
        (collection_ask("no-at-sign", &[]), "invalid"),
        (collection_ask("@C:\\x", &[]), "invalid"),
        (collection_ask("h8@  ", &[]), "invalid"),
        (collection_ask("", &[]), "invalid"),
        (collection_ask("h8@C:\\nul\0", &[]), "invalid"),
        (
            collection_ask(
                value,
                &(0..=ace_service::MAX_COLLECTION_ALERTS as u128)
                    .map(Uuid::from_u128)
                    .collect::<Vec<_>>(),
            ),
            "invalid",
        ),
        (collection_ask(value, &[Uuid::from_u128(0xDEAD)]), "missing"),
        (collection_ask(value, &[first, not_an_alert]), "missing"),
    ];
    for (ask, why) in refusals {
        let refused = service.request_file_collection(&actor, &ask).await;
        match why {
            "invalid" => assert!(
                matches!(refused, Err(ServiceError::InvalidRequest(_))),
                "{ask:?}: {refused:?}"
            ),
            _ => assert!(
                matches!(refused, Err(ServiceError::NotFound(_))),
                "{ask:?}: {refused:?}"
            ),
        }
    }
    assert_eq!(
        audit_rows(db).await.len(),
        rows,
        "nothing refused has a row"
    );
    let attached: i64 =
        sqlx::query_scalar("SELECT count(*) FROM queue.action_roots WHERE action_id = $1")
            .bind(again.id)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(attached, 1, "a refused request attached nothing");
    row.action
}

async fn cancel_file_collection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = collection(db, None, "h3@C:\\c.exe").await;
    service
        .cancel_file_collection(&actor, id)
        .await
        .expect("cancels");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "cancel_file_collection".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(collection_state_json("NEW", None, "h3@C:\\c.exe")),
            after: Some(collection_state_json(
                "COMPLETED",
                Some("CANCELLED"),
                "h3@C:\\c.exe"
            )),
            details: json!({}),
        }
    );
    assert!(matches!(
        service.cancel_file_collection(&actor, id).await,
        Err(ServiceError::Conflict(_))
    ));
    // a remediation isn't a collection
    let remediation = service
        .queue_remediations(&actor, RemediationAction::Remove, &[test_target("SUCCESS")])
        .await
        .expect("queues");
    assert!(matches!(
        service
            .cancel_file_collection(&actor, remediation[0].id)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    row.action
}

async fn retry_file_collection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let id = collection(db, None, "h4@C:\\d.exe").await;
    complete(db, id, "HOST_OFFLINE").await;
    let retried = service
        .retry_file_collection(&actor, id)
        .await
        .expect("retries");
    assert_eq!((retried.status.as_str(), retried.result), ("NEW", None));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "retry_file_collection".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(collection_state_json(
                "COMPLETED",
                Some("HOST_OFFLINE"),
                "h4@C:\\d.exe"
            )),
            after: Some(collection_state_json("NEW", None, "h4@C:\\d.exe")),
            details: json!({}),
        }
    );
    let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM queue.actions WHERE id = $1")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(attempts, 0, "a retry starts over");
    row.action
}

async fn delete_file_collection_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let sha256 = "d".repeat(64);
    let id = collection_with_file(db, "h5@C:\\e.exe", &sha256, 1).await;
    service
        .delete_file_collection(&actor, id)
        .await
        .expect("deletes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_file_collection".to_owned(),
            target: ("action".to_owned(), id.to_string()),
            before: Some(collection_state_json(
                "COMPLETED",
                Some("SUCCESS"),
                "h5@C:\\e.exe"
            )),
            after: None,
            details: json!({}),
        }
    );
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM store.holds WHERE sha256 = $1")
        .bind(&sha256)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(held, 0, "its own hold went with it");
    row.action
}

async fn prune_file_collections_records_its_row(db: &Db) -> String {
    let service = service(db);
    let pruner = component("scheduler:file_collection_prune");
    let sha256 = "e".repeat(64);
    let old = collection_with_file(db, "h6@C:\\f.exe", &sha256, 8).await;
    let fresh = collection_with_file(db, "h7@C:\\g.exe", &"f".repeat(64), 1).await;
    let pruned = service
        .prune_file_collections(&pruner)
        .await
        .expect("prunes");
    assert!(pruned.released >= 1 && pruned.batches == 1, "{pruned:?}");
    let row = last_audit(db).await;
    assert_eq!(
        (row.actor.clone(), row.action.as_str(), row.target.clone()),
        (
            json!({"kind": "internal", "id": "scheduler:file_collection_prune"}),
            "prune_file_collections",
            ("file_collections".to_owned(), "expired".to_owned())
        )
    );
    let before = row.before.clone().expect("a before");
    assert_eq!(before["retention_days"], 7);
    assert!(
        before["collections"]
            .as_array()
            .expect("a list")
            .iter()
            .any(|c| c["id"] == old && c["sha256"] == sha256.as_str())
    );
    let held: Vec<String> = sqlx::query_scalar(
        "SELECT holder_id FROM store.holds WHERE holder_kind = 'file_collection' ORDER BY holder_id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert!(held.contains(&fresh.to_string()) && !held.contains(&old.to_string()));
    // nothing left to prune is no row; an analyst can't prune
    let rows = audit_rows(db).await.len();
    assert_eq!(
        service
            .prune_file_collections(&pruner)
            .await
            .expect("prunes"),
        ace_service::CollectionsPruned::default()
    );
    assert!(matches!(
        service
            .prune_file_collections(&user(UserId(Uuid::from_u128(0x7D))))
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

/// PLAN.md 7.9: the remediations and the file collections are listed newest first through their screens'
/// filters, each filter and its inverse, with the filters' total and a keyset; the targets of an alert are
/// its observables of a remediator's type; and coverage sums up ACE's removals and the checks' findings.
#[tokio::test]
async fn remediations_and_collections_list_through_their_screens_filters() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let queued = service
        .queue_remediations(
            &actor,
            RemediationAction::Remove,
            &[
                test_target("SUCCESS"),
                test_target("FAILED"),
                test_target("evil%_\\"),
            ],
        )
        .await
        .expect("queues");
    complete(db, queued[0].id, "SUCCESS").await;
    let query = |filters: Vec<ace_service::FilterEntry>| ActionQuery {
        filters,
        ..ActionQuery::default()
    };
    let ids = |page: ace_service::RemediationPage| {
        page.remediations.iter().map(|r| r.id).collect::<Vec<_>>()
    };
    let all = service
        .remediations(&actor, &query(vec![]), None, None)
        .await
        .expect("lists");
    assert_eq!(all.total, 3);
    assert_eq!(
        ids(all.clone()),
        [queued[2].id, queued[1].id, queued[0].id],
        "newest first"
    );
    assert_eq!(
        all.remediations[0].display_name.as_deref(),
        Some("Test Remediator")
    );
    assert_eq!(
        all.remediations[0].analyst.as_deref(),
        Some(&*format!("u{}", Uuid::from_u128(0xAD).simple()))
    );
    let first = service
        .remediations(&actor, &query(vec![]), Some(2), None)
        .await
        .expect("lists");
    assert_eq!((first.total, first.next), (3, Some(queued[1].id)));
    let second = service
        .remediations(&actor, &query(vec![]), Some(2), first.next)
        .await
        .expect("lists");
    assert_eq!(ids(second), [queued[0].id]);
    for (entry, expected) in [
        (text("Result", false, &["SUCCESS"]), vec![queued[0].id]),
        (
            text("Result", true, &["SUCCESS"]),
            vec![queued[2].id, queued[1].id],
        ),
        (
            text("Status", false, &["new"]),
            vec![queued[2].id, queued[1].id],
        ),
        (text("Value", false, &["%_\\"]), vec![queued[2].id]),
        (
            text("Value", true, &["fail"]),
            vec![queued[2].id, queued[0].id],
        ),
        (
            text("ID", false, &[&queued[1].id.to_string()]),
            vec![queued[1].id],
        ),
        (text("Action", false, &["restore"]), vec![]),
        (
            text("Remediator", false, &["TES"]),
            vec![queued[2].id, queued[1].id, queued[0].id],
        ),
        (text("Analyst", true, &["u"]), vec![]),
        (
            text("Created", false, &["-1d"]),
            vec![queued[2].id, queued[1].id, queued[0].id],
        ),
        (text("Created", true, &["-1d"]), vec![]),
    ] {
        let name = format!("{entry:?}");
        assert_eq!(
            ids(service
                .remediations(&actor, &query(vec![entry]), None, None)
                .await
                .expect("lists")),
            expected,
            "{name}"
        );
    }
    for bad in [
        text("Result", false, &["HOST_OFFLINE"]),
        text("ID", false, &["x"]),
        text("Collector", false, &["x"]),
    ] {
        assert!(matches!(
            service
                .remediations(&actor, &query(vec![bad]), None, None)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));
    }
    assert_eq!(
        service
            .remediation(&actor, queued[0].id)
            .await
            .expect("reads")
            .result
            .as_deref(),
        Some("SUCCESS")
    );
    // remediation:read is what reads them
    let outsider = user(UserId(Uuid::from_u128(0x7C)));
    assert!(matches!(
        service
            .remediations(&outsider, &query(vec![]), None, None)
            .await,
        Err(ServiceError::PermissionDenied { .. })
    ));

    // an alert's targets are its observables of a remediator's type, each with its latest remediation
    let root = alert(db).await;
    let mut tx = db.begin().await.expect("begins");
    for (kind, value) in [
        (ObservableKind::Test, "SUCCESS"),
        (ObservableKind::Test, "NEW_ONE"),
        (ObservableKind::EmailDelivery, "<a@b>|x@example.com"),
        (ObservableKind::EmailDelivery, "<c@d>|y@example.com"),
    ] {
        tree::upsert_observable(&mut tx, root, &NewObservable::new(kind, value))
            .await
            .expect("adds");
    }
    tx.commit().await.expect("commits");
    assert!(matches!(
        service.remediation_targets_of_alerts(&actor, &[root]).await,
        Err(ServiceError::NotFound(_))
    ));
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    let targets = service
        .remediation_targets_of_alerts(&actor, &[root])
        .await
        .expect("finds them");
    let found: Vec<(&str, Option<i64>)> = targets
        .iter()
        .map(|t| {
            (
                t.key.observable_value.as_str(),
                t.current.as_ref().map(|c| c.id),
            )
        })
        .collect();
    assert_eq!(found, [("NEW_ONE", None), ("SUCCESS", Some(queued[0].id))]);
    let looked_up = service
        .remediation_targets_of_observables(
            &actor,
            &[
                ("test".to_owned(), "SUCCESS".to_owned()),
                ("fqdn".to_owned(), "x.example".to_owned()),
            ],
        )
        .await
        .expect("finds them");
    assert_eq!(looked_up.len(), 1);
    assert!(matches!(
        service
            .remediation_targets_of_observables(
                &actor,
                &[("no_such_type".to_owned(), "x".to_owned())]
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));

    // coverage: one delivery ACE removed, one a check is still watching
    sqlx::query(
        "INSERT INTO queue.actions (kind, handler, observable_type, observable_value, action, status, result)
         VALUES ('remediation', 'test', 'email_delivery', '<a@b>|x@example.com', 'remove', 'COMPLETED', 'SUCCESS')",
    )
    .execute(db.pool())
    .await
    .expect("a removal");
    let check: i64 = sqlx::query_scalar(
        "INSERT INTO queue.actions (kind, handler, observable_type, observable_value)
         VALUES ('remediation_check', 'vendor', 'email_delivery', '<c@d>|y@example.com') RETURNING id",
    )
    .fetch_one(db.pool())
    .await
    .expect("a check");
    sqlx::query("INSERT INTO queue.action_roots (action_id, root_id) VALUES ($1, $2)")
        .bind(check)
        .bind(root)
        .execute(db.pool())
        .await
        .expect("attaches");
    let other = alert(db).await;
    let coverage = service
        .remediation_coverage(&actor, &[root, other])
        .await
        .expect("reads");
    assert_eq!(coverage[&root].state(), CoverageState::Partial);
    assert_eq!(coverage[&root].label(), "remediated 1/2 · ACE");
    assert_eq!(
        coverage[&root].tooltip(),
        "x@example.com: ACE\ny@example.com: watching"
    );
    assert_eq!(coverage[&other].state(), CoverageState::None);

    // the file collections, and the alerts each belongs to
    let shared = collection(db, Some(root), "h@C:\\x.exe").await;
    assert_eq!(
        collection(db, Some(other), "h@C:\\x.exe").await,
        shared,
        "joined"
    );
    let lone = collection(db, None, "h@C:\\y.exe").await;
    let collections = |filters| {
        let service = service.clone();
        let actor = actor.clone();
        async move {
            service
                .file_collections(&actor, &query(filters), None, None)
                .await
                .expect("lists")
        }
    };
    let page = collections(vec![]).await;
    assert_eq!(page.total, 2);
    assert_eq!(page.collections[1].alerts, [root, other]);
    assert_eq!(
        page.collections[1].display_name.as_deref(),
        Some("Test EDR")
    );
    let by_alert = collections(vec![text("Alert", false, &[&other.to_string()])]).await;
    assert_eq!(
        by_alert
            .collections
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>(),
        [shared]
    );
    let not_alert = collections(vec![text("Alert", true, &[&other.to_string()])]).await;
    assert_eq!(
        not_alert
            .collections
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>(),
        [lone]
    );
    assert!(matches!(
        service
            .file_collections(
                &actor,
                &query(vec![text("Alert", false, &["not-a-uuid"])]),
                None,
                None
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service.file_collection_history(&actor, shared, 0).await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(
        service
            .file_collection_history(&actor, shared, 10)
            .await
            .expect("reads")
            .is_empty()
    );
}

// PLAN.md 7.9: the coverage badge's sums, from ace3's coverage tests.

fn ace(action: &str, status: &str, result: Option<&str>) -> ace_service::CoverageRemediation {
    ace_service::CoverageRemediation {
        action: Some(action.to_owned()),
        status: status.to_owned(),
        result: result.map(str::to_owned),
    }
}

/// ace3's `tests/saq/remediation/test_coverage.py` cases, over rows rather than ORM objects.
#[test]
fn coverage_sums_up_as_ace3_s() {
    let values = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<BTreeSet<_>>();
    let none = ace_service::assemble_coverage(
        values(&["<a>|x@y"]),
        &std::collections::BTreeMap::new(),
        &[],
    );
    assert_eq!(none.state(), CoverageState::None);
    assert!(!none.visible());

    let mut rows = std::collections::BTreeMap::new();
    rows.insert(
        "<a>|x@y".to_owned(),
        vec![ace("remove", "COMPLETED", Some("SUCCESS"))],
    );
    let done = ace_service::assemble_coverage(values(&["<a>|x@y"]), &rows, &[]);
    assert_eq!(done.state(), CoverageState::Remediated);
    assert_eq!(done.label(), "remediated 1/1 · ACE");
    assert_eq!(done.tooltip(), "x@y: ACE");

    // a restore after the removal puts it back
    rows.get_mut("<a>|x@y")
        .expect("a row")
        .push(ace("restore", "COMPLETED", Some("SUCCESS")));
    let restored = ace_service::assemble_coverage(values(&["<a>|x@y", "<b>|z@y"]), &rows, &[]);
    assert_eq!(restored.state(), CoverageState::Unremediated);
    assert_eq!(restored.status_label(), "not remediated 0/2");

    let check = |value: &str, status: &str, result: Option<&str>, events: Option<Value>| {
        ace_service::CoverageCheck {
            value: value.to_owned(),
            handler: "mail_vendor".to_owned(),
            status: status.to_owned(),
            result: result.map(str::to_owned),
            result_message: None,
            events,
        }
    };
    let watching = ace_service::assemble_coverage(
        values(&["<b>|z@y"]),
        &std::collections::BTreeMap::new(),
        &[check("<b>|z@y", "NEW", None, None)],
    );
    assert_eq!(watching.state(), CoverageState::Pending);
    assert_eq!(watching.status_label(), "watching 0/1");
    let events = serde_json::json!([{
        "source": "MailVendor", "event_type": "remediated", "timestamp": "2026-11-01T00:00:00Z",
        "description": "moved"
    }]);
    let partial = ace_service::assemble_coverage(
        values(&["<b>|z@y", "<c>|w@y"]),
        &std::collections::BTreeMap::new(),
        &[check(
            "<b>|z@y",
            "COMPLETED",
            Some("CONFIRMED"),
            Some(events),
        )],
    );
    assert_eq!(partial.state(), CoverageState::Partial);
    assert_eq!(partial.label(), "remediated 1/2 · MailVendor");

    let mut failed = std::collections::BTreeMap::new();
    failed.insert(
        "<c>|w@y".to_owned(),
        vec![ace("remove", "COMPLETED", Some("ERROR"))],
    );
    assert_eq!(
        ace_service::assemble_coverage(values(&["<c>|w@y"]), &failed, &[]).state(),
        CoverageState::Failed
    );
    let mut missing = std::collections::BTreeMap::new();
    missing.insert(
        "<c>|w@y".to_owned(),
        vec![ace("remove", "COMPLETED", Some("NOT_FOUND"))],
    );
    let not_found = ace_service::assemble_coverage(values(&["<c>|w@y"]), &missing, &[]);
    assert_eq!(not_found.state(), CoverageState::NotFound);
    assert_eq!(not_found.label(), "not in mailbox 1/1");
    let mut pending = std::collections::BTreeMap::new();
    pending.insert(
        "<c>|w@y".to_owned(),
        vec![ace("remove", "IN_PROGRESS", Some("DELAYED"))],
    );
    assert_eq!(
        ace_service::assemble_coverage(values(&["<c>|w@y"]), &pending, &[]).status_label(),
        "remediating 0/1"
    );
    let superseded = ace_service::CoverageCheck {
        result_message: Some(ace_core::actions::probe_supersede_reason(
            "msmail_filter",
            None,
        )),
        ..check("<c>|w@y", "COMPLETED", Some("SUPERSEDED"), None)
    };
    assert_eq!(
        ace_service::assemble_coverage(
            values(&["<c>|w@y"]),
            &std::collections::BTreeMap::new(),
            &[superseded]
        )
        .label(),
        "remediated 1/1 · msmail_filter"
    );
    let many: Vec<String> = (0..30).map(|i| format!("<m>|u{i}@y")).collect();
    let many = ace_service::assemble_coverage(
        many.iter().cloned().collect(),
        &std::collections::BTreeMap::new(),
        &[check("<m>|u0@y", "NEW", None, None)],
    );
    assert!(
        many.tooltip().ends_with("... and 5 more"),
        "{}",
        many.tooltip()
    );
}

// PLAN.md 7.14: detection verdicts. Each test below is one of ace3's `tests/saq/detection_verdicts/`
// cases, named for it; the module docs of `ace_service`'s `detection_verdicts` say what differs.

use ace_service::{
    BatchRules, DispositionClass, DispositionClasses, Dispositions, SkipCause, Verdict,
    VerdictSource, effective_verdict,
};

const SIG_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const SIG_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

/// A detection of a fixture: the fqdn it's on, None for one on the alert itself, its signature and its
/// description.
type Detected = (Option<&'static str>, &'static str, &'static str);

/// test_store.py's `MULTI`: one generic rule on two fqdns, and a phish kit's on the alert itself.
const MULTI: &[Detected] = &[
    (Some("one.example.com"), SIG_A, "generic logo rule"),
    (Some("two.example.com"), SIG_A, "generic logo rule"),
    (None, SIG_B, "phish kit"),
];
/// test_effective.py's `SINGLE` and `MULTI`.
const ONE_SIGNATURE: &[Detected] = &[
    (Some("one.example.com"), SIG_A, "d1"),
    (Some("two.example.com"), SIG_A, "d1"),
];
const TWO_SIGNATURES: &[Detected] = &[(Some("one.example.com"), SIG_A, "d1"), (None, SIG_B, "d2")];

const TEST_ACTOR_JSON: &str = r#"{"kind": "internal", "id": "test"}"#;

/// ace3's `insert_alert_with_detections`: an alert with these detections, in order, and this disposition.
async fn verdict_alert(
    db: &Db,
    detections: &[Detected],
    disposition: Option<&str>,
) -> (Uuid, Vec<i64>) {
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let mut ids = Vec::new();
    for (fqdn, signature, description) in detections {
        let observable = match fqdn {
            Some(fqdn) => Some(
                tree::upsert_observable(
                    &mut tx,
                    root.id,
                    &NewObservable::new(ObservableKind::Fqdn, *fqdn),
                )
                .await
                .expect("adds")
                .id
                .0,
            ),
            None => None,
        };
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO analysis.detections (root_id, observable_id, description, signature_uuid)
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(root.id)
        .bind(observable)
        .bind(description)
        .bind(signature)
        .fetch_one(tx.conn())
        .await
        .expect("a detection");
        ids.push(id);
    }
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root.id)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    set_disposition_row(db, root.id, disposition).await;
    (root.id, ids)
}

/// Sets a disposition as a row, without the service, for a fixture.
async fn set_disposition_row(db: &Db, root: Uuid, disposition: Option<&str>) {
    sqlx::query(
        "UPDATE analysis.roots SET disposition = $2,
             dispositioned_by = CASE WHEN $2::text IS NULL THEN NULL ELSE $3::jsonb END
         WHERE id = $1",
    )
    .bind(root)
    .bind(disposition)
    .bind(TEST_ACTOR_JSON)
    .execute(db.pool())
    .await
    .expect("sets the disposition");
}

/// ace3's `_override`: a stored verdict written directly, past every check.
async fn store_verdict(db: &Db, root: Uuid, detection: i64, verdict: &str) {
    sqlx::query(
        "INSERT INTO analysis.detection_verdicts (detection_id, root_id, signature_uuid, verdict, set_by)
         VALUES ($1, $2, 'x', $3, $4::jsonb)",
    )
    .bind(detection)
    .bind(root)
    .bind(verdict)
    .bind(TEST_ACTOR_JSON)
    .execute(db.pool())
    .await
    .expect("stores a verdict");
}

/// ace3's `_stored`: the alert's stored verdicts by detection.
async fn stored_verdicts(db: &Db, root: Uuid) -> BTreeSet<(i64, String)> {
    sqlx::query_as(
        "SELECT detection_id, verdict FROM analysis.detection_verdicts WHERE root_id = $1",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("reads")
    .into_iter()
    .collect()
}

/// ace3's `_history`: (detection, old, new) in order.
async fn verdict_history(db: &Db, root: Uuid) -> Vec<(i64, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT detection_id, old_verdict, new_verdict FROM analysis.detection_verdict_history
         WHERE root_id = $1 ORDER BY id",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// ace3's `list_alert_detection_points`.
async fn verdict_rows(
    service: &Service,
    actor: &Actor,
    root: Uuid,
) -> Vec<ace_service::DetectionPoint> {
    service
        .detection_points(
            actor,
            &DetectionPointFilter {
                alert: Some(root),
                ..DetectionPointFilter::default()
            },
            None,
            None,
        )
        .await
        .expect("lists")
        .detections
}

fn targets(root: Uuid, ids: &[i64]) -> Vec<(Uuid, i64)> {
    ids.iter().map(|id| (root, *id)).collect()
}

fn conflict(result: Result<impl std::fmt::Debug, ServiceError>) -> String {
    match result {
        Err(ServiceError::Conflict(why)) => why,
        other => panic!("not a conflict: {other:?}"),
    }
}

/// test_effective.py's `test_compute_effective`, every case of its table.
#[test]
fn compute_effective() {
    use DispositionClass::{Fp, Tp};
    use VerdictSource::{Explicit, InheritedMulti, InheritedSingle};
    let (tp, fp) = (Some(Verdict::Tp), Some(Verdict::Fp));
    for (class, stored, multi, unreviewed, expected) in [
        // unclassified: no verdict, stored ones included
        (None, None, false, false, (None, None)),
        (None, fp, true, false, (None, None)),
        // a test run that isn't reviewed: no verdict
        (Some(Tp), fp, true, true, (None, None)),
        (Some(Fp), None, false, true, (None, None)),
        // FP alert: every detection FP, stored verdicts masked, never unconfirmed
        (Some(Fp), None, false, false, (fp, Some(InheritedSingle))),
        (Some(Fp), None, true, false, (fp, Some(InheritedSingle))),
        (Some(Fp), tp, true, false, (fp, Some(InheritedSingle))),
        // TP alert: a stored verdict wins
        (Some(Tp), fp, true, false, (fp, Some(Explicit))),
        (Some(Tp), tp, true, false, (tp, Some(Explicit))),
        (Some(Tp), fp, false, false, (fp, Some(Explicit))),
        // TP alert, inherited: by the number of signatures
        (Some(Tp), None, false, false, (tp, Some(InheritedSingle))),
        (Some(Tp), None, true, false, (tp, Some(InheritedMulti))),
    ] {
        assert_eq!(
            effective_verdict(class, stored, multi, unreviewed),
            expected,
            "{class:?} {stored:?} {multi} {unreviewed}"
        );
    }
}

/// test_effective.py's `test_disposition_class_lists_follow_the_configuration`.
#[test]
fn disposition_class_lists_follow_the_configuration() {
    let (tp, fp) = DispositionClasses::ace3().lists();
    assert!(fp.contains(&"FALSE_POSITIVE".to_owned()) && tp.contains(&"DELIVERY".to_owned()));
    assert!(!tp.contains(&"OPEN".to_owned()) && !fp.contains(&"OPEN".to_owned()));
    let mut classes: Vec<(String, DispositionClass)> = tp
        .into_iter()
        .map(|name| (name, DispositionClass::Tp))
        .chain(fp.into_iter().map(|name| (name, DispositionClass::Fp)))
        .collect();
    classes.push(("REVIEWED".to_owned(), DispositionClass::Fp));
    let (_, fp) = DispositionClasses::new(classes, []).lists();
    assert!(fp.contains(&"REVIEWED".to_owned()));
}

/// test_effective.py's `test_sql_agrees_with_python`: the SQL the list reads agrees with
/// `effective_verdict` for one disposition of each class (and none), one and two signatures, with and
/// without a stored verdict, and with no test run, an unreviewed one and a reviewed one (7.10).
#[tokio::test]
async fn sql_agrees_with_rust() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let classes = DispositionClasses::ace3();
    for disposition in [None, Some("OPEN"), Some("FALSE_POSITIVE"), Some("DELIVERY")] {
        for detections in [ONE_SIGNATURE, TWO_SIGNATURES] {
            for with_override in [false, true] {
                for run_state in [None, Some(RunState::Ended), Some(RunState::Reviewed)] {
                    let (root, ids) = verdict_alert(db, detections, disposition).await;
                    if let Some(state) = run_state {
                        attribute_to_run(db, root, ids[0], state).await;
                    }
                    if with_override {
                        store_verdict(db, root, ids[0], "fp").await;
                    }
                    let rows = verdict_rows(&service, &actor, root).await;
                    assert_eq!(rows.len(), 2);
                    let multi = rows
                        .iter()
                        .map(|row| row.signature_uuid.clone())
                        .collect::<BTreeSet<_>>()
                        .len()
                        > 1;
                    for row in rows {
                        let expected = effective_verdict(
                            classes.class(disposition),
                            row.override_verdict,
                            multi,
                            run_state == Some(RunState::Ended),
                        );
                        assert_eq!(
                            (row.verdict, row.verdict_source),
                            expected,
                            "{disposition:?} {detections:?} {with_override} {run_state:?} {row:?}"
                        );
                        assert_eq!(
                            row.override_verdict,
                            (with_override && row.id == ids[0]).then_some(Verdict::Fp),
                            "a stored verdict is listed even where it's masked"
                        );
                    }
                }
            }
        }
    }
}

/// test_effective.py's `test_a_removed_attribution_gives_the_verdicts_back` (7.10): an alert attributed to
/// a run that isn't reviewed has no verdicts, its other detections included, until the attribution no
/// longer holds.
#[tokio::test]
async fn a_removed_attribution_gives_the_verdicts_back() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, ONE_SIGNATURE, Some("DELIVERY")).await;
    let run = attribute_to_run(db, root, ids[0], RunState::Ended).await;
    let verdicts = |rows: Vec<ace_service::DetectionPoint>| {
        rows.into_iter()
            .map(|row| row.verdict)
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        verdicts(verdict_rows(&service(db), &actor, root).await),
        BTreeSet::from([None])
    );
    sqlx::query(
        "UPDATE svs.attributions SET removed_at = now(), removed_by = $2::jsonb WHERE run_id = $1",
    )
    .bind(run.id)
    .bind(r#"{"kind": "user", "id": "alice"}"#)
    .execute(db.pool())
    .await
    .expect("removes the attribution");
    assert_eq!(
        verdicts(verdict_rows(&service(db), &actor, root).await),
        BTreeSet::from([Some(Verdict::Tp)])
    );
}

/// test_effective.py's `test_a_classification_change_relabels_at_read_time`.
#[tokio::test]
async fn a_classification_change_relabels_at_read_time() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (root, _) = verdict_alert(db, ONE_SIGNATURE, Some("REVIEWED")).await;
    let verdicts = |rows: Vec<ace_service::DetectionPoint>| {
        rows.into_iter()
            .map(|row| row.verdict)
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        verdicts(verdict_rows(&service(db), &actor, root).await),
        BTreeSet::from([None])
    );
    let (tp, fp) = DispositionClasses::ace3().lists();
    let classes = DispositionClasses::new(
        tp.into_iter()
            .map(|name| (name, DispositionClass::Tp))
            .chain(fp.into_iter().map(|name| (name, DispositionClass::Fp)))
            .chain([("REVIEWED".to_owned(), DispositionClass::Fp)]),
        [],
    );
    // the site overlay's sections, merged over ace3's
    let overlay =
        ace_sdk::Overlay::from_yaml("disposition_classification: {REVIEWED: fp}").expect("parses");
    let configured = Dispositions::configured(&overlay).expect("a good section");
    assert_eq!(configured.classes().lists(), classes.lists());
    assert_eq!(configured.classes().set_by_ace_list(), ["SIMULATED"]);
    let relabelled = service(db).with_dispositions(configured);
    assert_eq!(
        verdicts(verdict_rows(&relabelled, &actor, root).await),
        BTreeSet::from([Some(Verdict::Fp)])
    );
    // and moving a TP disposition to FP relabels its alerts' detections, a stored verdict masked
    let (delivery, ids) = verdict_alert(db, TWO_SIGNATURES, Some("DELIVERY")).await;
    store_verdict(db, delivery, ids[0], "tp").await;
    let sources = |rows: Vec<ace_service::DetectionPoint>| {
        rows.into_iter()
            .map(|row| (row.verdict, row.verdict_source))
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        sources(verdict_rows(&service(db), &actor, delivery).await),
        BTreeSet::from([
            (Some(Verdict::Tp), Some(VerdictSource::Explicit)),
            (Some(Verdict::Tp), Some(VerdictSource::InheritedMulti)),
        ])
    );
    let overlay =
        ace_sdk::Overlay::from_yaml("disposition_classification: {DELIVERY: fp}").expect("parses");
    let relabelled =
        service(db).with_dispositions(Dispositions::configured(&overlay).expect("good"));
    assert_eq!(
        sources(verdict_rows(&relabelled, &actor, delivery).await),
        BTreeSet::from([(Some(Verdict::Fp), Some(VerdictSource::InheritedSingle))])
    );
}

/// The overlay's disposition sections: ace3's dispositions and classification with none, each entry merged
/// over them, a site's own disposition added after ace3's in the file's order, and a bad section refused, as
/// `ace serve` refuses to start on it.
#[test]
fn the_overlay_configures_the_dispositions() {
    let configured =
        |yaml: &str| Dispositions::configured(&ace_sdk::Overlay::from_yaml(yaml).expect("parses"));
    let ace3 = Dispositions::ace3();
    assert_eq!(configured(""), Ok(ace3.clone()));
    assert_eq!(
        configured("disposition_classification: {}\ndispositions: {}"),
        Ok(ace3.clone())
    );
    assert_eq!(ace3.classes(), &DispositionClasses::ace3());
    assert_eq!(ace3.names().len(), 16);
    assert_eq!(
        ace3.selectable(),
        ace3.names()
            .into_iter()
            .filter(|name| name != "SIMULATED")
            .collect::<Vec<_>>()
    );
    let delivery = ace3.get("DELIVERY").expect("ace3's");
    assert_eq!(
        (
            delivery.rank,
            delivery.css.as_str(),
            delivery.show_save_to_event
        ),
        (100, "danger", true)
    );
    assert_eq!(ace3.css(None), "light", "OPEN's");
    assert_eq!(ace3.css(Some("GONE")), ace_service::DEFAULT_BADGE);
    // a merge: what isn't named keeps ace3's
    let site = configured(
        "disposition_classification: {GRAYWARE: fp, REVIEWED: tp, SITE_BAD: tp}\n\
         dispositions:\n  \
           SIMULATED: {analyst_selectable: true}\n  \
           DAMAGE: {analyst_selectable: false, css: dark}\n  \
           EXFIL: {}\n  \
           SITE_BAD: {rank: 170, css: site-Alarm_2, show_save_to_event: true}\n  \
           SITE_ARCHIVED: {rank: 1, css: light, analyst_selectable: false}\n  \
           OPEN: {css: secondary, rank: 0}\n",
    )
    .expect("good sections");
    let classes = site.classes();
    assert_eq!(classes.class(Some("GRAYWARE")), Some(DispositionClass::Fp));
    assert_eq!(classes.class(Some("REVIEWED")), Some(DispositionClass::Tp));
    assert_eq!(classes.class(Some("SITE_BAD")), Some(DispositionClass::Tp));
    assert_eq!(classes.class(Some("DELIVERY")), Some(DispositionClass::Tp));
    assert_eq!(
        classes.class(Some("FALSE_POSITIVE")),
        Some(DispositionClass::Fp)
    );
    assert_eq!(classes.class(Some("IGNORE")), None);
    assert_eq!(classes.class(Some("SITE_ARCHIVED")), None);
    assert_eq!(classes.set_by_ace_list(), ["DAMAGE", "SITE_ARCHIVED"]);
    assert!(!classes.set_by_ace(Some("SIMULATED")) && !classes.set_by_ace(Some("EXFIL")));
    assert_eq!(classes.refusal(Some("SIMULATED"), true), None);
    assert!(classes.refusal(Some("DAMAGE"), true).is_some());
    // the menus: in order, a site's own after ace3's in the file's order, without what only ACE sets
    let names = site.names();
    assert_eq!(names[names.len() - 2..], ["SITE_BAD", "SITE_ARCHIVED"]);
    let selectable = site.selectable();
    assert!(
        selectable.contains(&"SIMULATED".to_owned()) && selectable.contains(&"SITE_BAD".to_owned())
    );
    assert!(
        !selectable.contains(&"DAMAGE".to_owned())
            && !selectable.contains(&"SITE_ARCHIVED".to_owned())
    );
    assert_eq!(site.css(Some("DAMAGE")), "dark");
    assert_eq!(site.css(None), "secondary");
    // css is any class token, as ace3 takes any text: not only the stylesheet's eight
    assert_eq!(site.css(Some("SITE_BAD")), "site-Alarm_2");
    assert!(!ace_service::BADGE_STYLES.contains(&"site-Alarm_2"));
    assert_eq!(site.class("SITE_BAD"), Some(DispositionClass::Tp));
    assert_eq!(site.class("IGNORE"), None);
    assert_eq!(site.class("OPEN"), None);
    for css in ["red", "9", "-", "_", "text-bg-danger", &"a".repeat(64)] {
        assert!(ace_service::is_badge_class(css), "{css}");
    }
    assert!(site.show_save_to_event("SITE_BAD") && !site.show_save_to_event("SITE_ARCHIVED"));
    assert!(site.is_frozen(Some("DAMAGE")) && !site.is_frozen(Some("SIMULATED")));
    assert!(!site.is_frozen(None) && !site.is_frozen(Some("GONE")));
    assert_eq!(site.rank("SITE_BAD"), Some(170));
    for (yaml, said) in [
        (
            "disposition_classification: {BENIGN: fp}",
            "disposition_classification.BENIGN: not a disposition in dispositions",
        ),
        (
            "disposition_classification: {delivery: tp}",
            "disposition_classification.delivery: not a disposition in dispositions",
        ),
        (
            "disposition_classification: {OPEN: fp}",
            "disposition_classification.OPEN: OPEN is an alert with no disposition",
        ),
        (
            "dispositions: {OPEN: {analyst_selectable: false}}",
            "dispositions.OPEN.analyst_selectable: OPEN is an alert with no disposition",
        ),
        (
            "dispositions: {OPEN: {rank: 5}}",
            "dispositions.OPEN.rank: OPEN is an alert with no disposition",
        ),
        (
            "dispositions: {MALICIOUS: {analyst_selectable: false}}",
            "dispositions.MALICIOUS: a new disposition needs a rank and a css",
        ),
        (
            "dispositions: {MALICIOUS: {rank: 10}}",
            "dispositions.MALICIOUS: a new disposition needs a rank and a css",
        ),
        (
            "dispositions: {malicious: {rank: 10, css: danger}}",
            "dispositions.malicious: a disposition's name is up to 64",
        ),
        (
            "dispositions: {MAL-ICIOUS: {rank: 10, css: danger}}",
            "dispositions.MAL-ICIOUS: a disposition's name is up to 64",
        ),
        // css is one class token: nothing that ends the class, the attribute or the tag, or adds a class
        (
            "dispositions: {MALICIOUS: {rank: 10, css: 'danger current'}}",
            "dispositions.MALICIOUS.css: \"danger current\" isn't a badge class",
        ),
        (
            "dispositions: {MALICIOUS: {rank: 10, css: ''}}",
            "dispositions.MALICIOUS.css: \"\" isn't a badge class",
        ),
        (
            "dispositions: {DELIVERY: {css: 'x\" onmouseover=\"alert(1)'}}",
            "dispositions.DELIVERY.css: \"x\\\" onmouseover=\\\"alert(1)\" isn't a badge class",
        ),
        (
            "dispositions: {DELIVERY: {css: '\"><script>'}}",
            "dispositions.DELIVERY.css: ",
        ),
        (
            "dispositions: {DELIVERY: {css: \"a\\tb\"}}",
            "dispositions.DELIVERY.css: ",
        ),
        (
            "dispositions: {DELIVERY: {css: dangér}}",
            "dispositions.DELIVERY.css: ",
        ),
        (
            "dispositions: {DELIVERY: {css: 'a.b'}}",
            "dispositions.DELIVERY.css: ",
        ),
        (
            "dispositions: {DELIVERY: {rank: -1}}",
            "dispositions.DELIVERY.rank: -1 isn't a rank",
        ),
        (
            "dispositions: {DELIVERY: {rank: 1000000000}}",
            "dispositions.DELIVERY.rank: 1000000000 isn't a rank",
        ),
        // a classification names the configured set, a site's own included only once it's configured
        (
            "disposition_classification: {SITE_BAD: tp}",
            "disposition_classification.SITE_BAD: not a disposition in dispositions",
        ),
    ] {
        let err = configured(yaml).expect_err(yaml);
        assert!(err.starts_with(said), "{yaml}: {err}");
    }
    let long = "A".repeat(65);
    let err = configured(&format!("dispositions: {{{long}: {{rank: 1, css: info}}}}"))
        .expect_err("too long");
    assert!(err.contains("up to 64"), "{err}");
    let long = "a".repeat(65);
    let err = configured(&format!("dispositions: {{DELIVERY: {{css: {long}}}}}"))
        .expect_err("too long a css");
    assert!(err.contains("isn't a badge class"), "{err}");
    // a disposition can't be both TP and FP: it's one key, and a key written twice doesn't parse; and one
    // can't be removed, since an entry is a mapping
    for yaml in [
        "disposition_classification:\n  DELIVERY: tp\n  DELIVERY: fp\n",
        "dispositions: {DELIVERY: null}",
    ] {
        ace_sdk::Overlay::from_yaml(yaml).expect_err(yaml);
    }
}

/// The write takes the site's dispositions: one of its own, and not one it doesn't have; from an analyst,
/// not one only ACE sets, nor a change to an alert that has one, which ACE's own components can do (ace3's
/// `is_selectable_disposition` and `is_frozen_disposition`).
#[tokio::test]
async fn the_disposition_write_takes_the_sites_set() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let overlay = ace_sdk::Overlay::from_yaml(
        "dispositions:\n  SITE_OWN: {rank: 45, css: info}\n  \
         SITE_SWEEP: {rank: 5, css: dark, analyst_selectable: false}\n",
    )
    .expect("parses");
    let service = service(db).with_dispositions(Dispositions::configured(&overlay).expect("good"));
    let analyst = admin(db).await;
    let ace = component("svs:maintenance");
    may_disposition(
        db,
        &[Holder::Component(
            Component::new("svs:maintenance").expect("valid"),
        )],
    )
    .await;
    let root = alert(db).await;
    service
        .disposition(&analyst, root, "SITE_OWN")
        .await
        .expect("the site's own");
    assert_eq!(row(db, root).await.disposition.as_deref(), Some("SITE_OWN"));
    for (disposition, said) in [
        (
            "MALICIOUS",
            "MALICIOUS isn't one of this site's dispositions",
        ),
        ("SIMULATED", "only ACE sets the disposition SIMULATED"),
        ("SITE_SWEEP", "only ACE sets the disposition SITE_SWEEP"),
    ] {
        match service.disposition(&analyst, root, disposition).await {
            Err(ServiceError::InvalidRequest(why)) => assert!(why.starts_with(said), "{why}"),
            other => panic!("{disposition}: {other:?}"),
        }
    }
    // ace3's default isn't taken from ACE either when the site doesn't have it
    assert!(matches!(
        service.disposition(&ace, root, "MALICIOUS").await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert_eq!(row(db, root).await.disposition.as_deref(), Some("SITE_OWN"));
    // ACE sets one only it sets, and then an analyst can't change the alert, but ACE can
    service
        .disposition(&ace, root, "SITE_SWEEP")
        .await
        .expect("ACE sets it");
    match service.disposition(&analyst, root, "FALSE_POSITIVE").await {
        Err(ServiceError::Conflict(why)) => assert!(why.contains("SITE_SWEEP"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        row(db, root).await.disposition.as_deref(),
        Some("SITE_SWEEP")
    );
    service
        .disposition(&ace, root, "IGNORE")
        .await
        .expect("ACE changes it");
    service
        .disposition(&analyst, root, "FALSE_POSITIVE")
        .await
        .expect("an analyst can again");
    // a disposition the site has stopped configuring stays on its alert, and an analyst can replace it
    sqlx::query("UPDATE analysis.roots SET disposition = 'RETIRED' WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("an old value");
    service
        .disposition(&analyst, root, "DELIVERY")
        .await
        .expect("replaces it");
}

/// test_effective.py's `test_override_survives_an_fp_round_trip`: TP to FP masks the stored verdict without
/// deleting it, and back to TP restores it.
#[tokio::test]
async fn an_override_survives_an_fp_round_trip() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, TWO_SIGNATURES, Some("DELIVERY")).await;
    store_verdict(db, root, ids[0], "fp").await;
    for (disposition, expected) in [
        ("FALSE_POSITIVE", VerdictSource::InheritedSingle),
        ("DELIVERY", VerdictSource::Explicit),
    ] {
        service
            .disposition(&actor, root, disposition)
            .await
            .expect("dispositions");
        let first = verdict_rows(&service, &actor, root).await.remove(0);
        assert_eq!(
            (first.verdict, first.verdict_source),
            (Some(Verdict::Fp), Some(expected))
        );
        assert_eq!(first.override_verdict, Some(Verdict::Fp));
    }
}

/// test_store.py's `test_set_change_and_clear_record_history`.
#[tokio::test]
async fn set_change_and_clear_record_history() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let id = ids[0];
    assert!(
        service
            .set_detection_verdict(&actor, root, id, Verdict::Fp)
            .await
            .expect("sets")
    );
    assert_eq!(
        stored_verdicts(db, root).await,
        BTreeSet::from([(id, "fp".to_owned())])
    );
    let (signature, by): (Option<String>, Value) = sqlx::query_as(
        "SELECT signature_uuid, set_by::jsonb FROM analysis.detection_verdicts WHERE detection_id = $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(signature.as_deref(), Some(SIG_A));
    assert_eq!(by, boss_json());
    // writing what's stored changes nothing and records nothing
    assert!(
        !service
            .set_detection_verdict(&actor, root, id, Verdict::Fp)
            .await
            .expect("finds it")
    );
    assert!(
        service
            .set_detection_verdict(&actor, root, id, Verdict::Tp)
            .await
            .expect("changes")
    );
    assert!(
        service
            .clear_detection_verdict(&actor, root, id)
            .await
            .expect("clears")
    );
    assert!(
        !service
            .clear_detection_verdict(&actor, root, id)
            .await
            .expect("finds none")
    );
    assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
    let some = |v: &str| Some(v.to_owned());
    assert_eq!(
        verdict_history(db, root).await,
        [
            (id, None, some("fp")),
            (id, some("fp"), some("tp")),
            (id, some("tp"), None),
        ]
    );
}

/// test_store.py's `test_the_effective_verdict_follows_the_override`, on a detection on the alert itself
/// too, which has no observable (7.6).
#[tokio::test]
async fn the_effective_verdict_follows_the_override() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    for id in [ids[0], ids[2]] {
        service
            .set_detection_verdict(&actor, root, id, Verdict::Fp)
            .await
            .expect("sets");
        let row = service
            .detection_point(&actor, root, id)
            .await
            .expect("reads");
        assert_eq!(
            (row.verdict, row.verdict_source, row.override_verdict),
            (
                Some(Verdict::Fp),
                Some(VerdictSource::Explicit),
                Some(Verdict::Fp)
            )
        );
        assert_eq!(
            row.override_by.and_then(|by| by.name).as_deref(),
            Some("alice")
        );
        assert!(row.override_set_at.is_some());
    }
    assert!(
        service
            .detection_point(&actor, root, ids[2])
            .await
            .expect("reads")
            .observable
            .is_none(),
        "the phish kit's is on the alert itself"
    );
}

/// test_store.py's `test_only_a_tp_alert_takes_verdicts`, for an FP alert and an open one.
#[tokio::test]
async fn only_a_tp_alert_takes_verdicts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    for (disposition, why) in [
        (Some("FALSE_POSITIVE"), "correct its disposition"),
        (None, "the alert's disposition OPEN is unclassified"),
    ] {
        let (root, ids) = verdict_alert(db, MULTI, disposition).await;
        let refused = conflict(
            service
                .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
                .await,
        );
        assert!(refused.contains(why), "{refused}");
        conflict(service.confirm_detections(&actor, root).await);
        assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
        assert_eq!(verdict_history(db, root).await, []);
    }
}

/// test_store.py's `test_a_disposition_only_ace_sets_is_not_for_analysts`: ACE itself, here a component,
/// may.
#[tokio::test]
async fn a_disposition_only_ace_sets_is_not_for_analysts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("SIMULATED")).await;
    let refused = conflict(
        service
            .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
            .await,
    );
    assert!(refused.contains("set by ACE, not by analysts"), "{refused}");
    let svs = Holder::Component(Component::new("svs").expect("a name"));
    grant(db, &svs, "alert", "write", Effect::Allow).await;
    assert!(
        service
            .set_detection_verdict(&component("svs"), root, ids[0], Verdict::Fp)
            .await
            .expect("ACE may")
    );
}

/// test_store.py's `test_unknown_detection`. A verdict that isn't one can't be passed; its text isn't one.
#[tokio::test]
async fn unknown_detection() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let (other, _) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    for (alert, id) in [(root, i64::MAX), (other, ids[0]), (Uuid::nil(), ids[0])] {
        assert!(
            matches!(
                service
                    .set_detection_verdict(&actor, alert, id, Verdict::Fp)
                    .await,
                Err(ServiceError::NotFound(_))
            ),
            "{alert} {id}"
        );
    }
    assert!(matches!(
        service.confirm_detections(&actor, Uuid::nil()).await,
        Err(ServiceError::NotFound(_))
    ));
    assert_eq!(Verdict::parse("maybe"), None);
    assert_eq!(Verdict::parse("fp"), Some(Verdict::Fp));
}

/// test_store.py's `test_a_failed_write_leaves_nothing_behind`: the history's insert fails, and the verdict
/// written before it in the transaction goes with it.
#[tokio::test]
async fn a_failed_write_leaves_nothing_behind() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    sqlx::raw_sql(
        "ALTER TABLE analysis.detection_verdict_history ADD CONSTRAINT broken CHECK (false) NOT VALID",
    )
    .execute(db.pool())
    .await
    .expect("breaks the history");
    let audits = audit_rows(db).await.len();
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect_err("fails");
    assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
    assert_eq!(audit_rows(db).await.len(), audits);
}

/// test_store.py's `test_confirm_upgrades_every_unconfirmed_detection`.
#[tokio::test]
async fn confirm_upgrades_every_unconfirmed_detection() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    assert_eq!(ids.len(), 3);
    let sources = |rows: Vec<ace_service::DetectionPoint>| {
        rows.into_iter()
            .map(|row| (row.id, (row.verdict, row.verdict_source)))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert!(
        sources(verdict_rows(&service, &actor, root).await)
            .values()
            .all(|v| *v == (Some(Verdict::Tp), Some(VerdictSource::InheritedMulti)))
    );
    // one was marked as noise: confirm leaves it alone
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect("sets");
    assert_eq!(
        service
            .confirm_detections(&actor, root)
            .await
            .expect("confirms"),
        2
    );
    assert_eq!(
        service
            .confirm_detections(&actor, root)
            .await
            .expect("confirms"),
        0
    );
    let rows = sources(verdict_rows(&service, &actor, root).await);
    assert_eq!(
        rows[&ids[0]],
        (Some(Verdict::Fp), Some(VerdictSource::Explicit))
    );
    for id in &ids[1..] {
        assert_eq!(rows[id], (Some(Verdict::Tp), Some(VerdictSource::Explicit)));
    }
    let tp = Some("tp".to_owned());
    assert_eq!(
        verdict_history(db, root).await,
        [
            (ids[0], None, Some("fp".to_owned())),
            (ids[1], None, tp.clone()),
            (ids[2], None, tp)
        ]
    );
}

/// test_store.py's `test_confirm_on_a_single_signature_alert_confirms_nothing`.
#[tokio::test]
async fn confirm_on_a_single_signature_alert_confirms_nothing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, _) = verdict_alert(db, &MULTI[..2], Some("DELIVERY")).await;
    let audits = audit_rows(db).await.len();
    assert_eq!(
        service
            .confirm_detections(&actor, root)
            .await
            .expect("confirms"),
        0
    );
    assert_eq!(verdict_history(db, root).await, []);
    assert_eq!(audit_rows(db).await.len(), audits, "nothing changed");
}

/// test_store.py's `test_verdicts_and_history_go_with_the_alert`.
#[tokio::test]
async fn verdicts_and_history_go_with_the_alert() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect("sets");
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deletes the alert");
    let left: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM analysis.detection_verdicts WHERE root_id = $1),
                (SELECT count(*) FROM analysis.detection_verdict_history WHERE root_id = $1)",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(left, (0, 0));
}

/// test_store.py's `test_a_batch_writes_what_it_can_and_says_why_not_the_rest`.
#[tokio::test]
async fn a_batch_writes_what_it_can_and_says_why_not_the_rest() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let rules = BatchRules::default();
    let (tp_alert, tp_ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let (fp_alert, fp_ids) = verdict_alert(db, &MULTI[..1], Some("FALSE_POSITIVE")).await;
    let gone = (tp_alert, i64::MAX);
    let mut all = targets(fp_alert, &fp_ids);
    all.extend(targets(tp_alert, &tp_ids));
    all.push(gone);
    let batch = service
        .set_detection_verdicts(&actor, &all, Some(Verdict::Fp), &rules)
        .await
        .expect("writes");
    assert_eq!((batch.changed, batch.unchanged), (3, 0));
    let mut skipped: Vec<_> = batch.skipped.iter().map(|s| (s.alert, s.cause)).collect();
    skipped.sort();
    let mut expected = vec![(tp_alert, SkipCause::Gone), (fp_alert, SkipCause::Alert)];
    expected.sort();
    assert_eq!(skipped, expected);
    let refused = batch
        .skipped
        .iter()
        .find(|s| s.cause == SkipCause::Alert)
        .expect("the FP alert's");
    assert!(
        refused.reason.contains("correct its disposition"),
        "{refused:?}"
    );
    assert!(
        stored_verdicts(db, tp_alert)
            .await
            .iter()
            .all(|(_, v)| v == "fp")
    );
    assert_eq!(stored_verdicts(db, tp_alert).await.len(), 3);
    assert_eq!(stored_verdicts(db, fp_alert).await, BTreeSet::new());

    // again: nothing changes, and nothing is recorded twice
    let batch = service
        .set_detection_verdicts(
            &actor,
            &targets(tp_alert, &tp_ids),
            Some(Verdict::Fp),
            &rules,
        )
        .await
        .expect("writes");
    assert_eq!((batch.changed, batch.unchanged), (0, 3));
    assert_eq!(verdict_history(db, tp_alert).await.len(), 3);

    // None clears
    let batch = service
        .set_detection_verdicts(&actor, &targets(tp_alert, &tp_ids), None, &rules)
        .await
        .expect("clears");
    assert_eq!(batch.changed, 3);
    assert_eq!(stored_verdicts(db, tp_alert).await, BTreeSet::new());

    // a batch is bounded
    let many = vec![(tp_alert, 1); ace_service::MAX_VERDICT_TARGETS + 1];
    assert!(matches!(
        service
            .set_detection_verdicts(&actor, &many, None, &rules)
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
}

/// test_store.py's `test_a_failed_batch_writes_nothing`: the fourth write fails, and the three before it go.
#[tokio::test]
async fn a_failed_batch_writes_nothing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (first, first_ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let (second, second_ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let mut all = targets(first, &first_ids);
    all.extend(targets(second, &second_ids));
    // the batch writes in (alert, id) order, so the fourth is the first detection of the later alert
    let mut ordered = all.clone();
    ordered.sort();
    let fourth = ordered[3].1;
    // the id is a number this test read, so it can't inject anything
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE analysis.detection_verdict_history
         ADD CONSTRAINT broken CHECK (detection_id <> {fourth}) NOT VALID"
    )))
    .execute(db.pool())
    .await
    .expect("breaks the fourth write");
    service
        .set_detection_verdicts(&actor, &all, Some(Verdict::Fp), &BatchRules::default())
        .await
        .expect_err("fails");
    for root in [first, second] {
        assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
        assert_eq!(verdict_history(db, root).await, []);
    }
}

/// test_store.py's `test_only_source_never_overwrites_a_verdict_set_meanwhile`.
#[tokio::test]
async fn only_source_never_overwrites_a_verdict_set_meanwhile() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    // the caller read the three as unconfirmed; one was marked as noise before the batch locked it
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect("sets");
    let rules = BatchRules {
        only_source: Some(VerdictSource::InheritedMulti),
        ..BatchRules::default()
    };
    let batch = service
        .set_detection_verdicts(&actor, &targets(root, &ids), Some(Verdict::Tp), &rules)
        .await
        .expect("writes");
    assert_eq!(batch.changed, 2);
    let skipped: Vec<_> = batch
        .skipped
        .iter()
        .map(|s| (s.detection, s.cause, s.reason.clone()))
        .collect();
    assert_eq!(
        skipped,
        [(
            ids[0],
            SkipCause::Source,
            "its verdict source is explicit, not inherited_multi".to_owned()
        )]
    );
    assert!(
        stored_verdicts(db, root)
            .await
            .contains(&(ids[0], "fp".to_owned()))
    );
}

/// test_store.py's `test_a_refused_cause_fails_the_whole_batch`, with the alert's disposition as the cause,
/// since ace4 has no detection that predates detection identity (the module's docs).
#[tokio::test]
async fn a_refused_cause_fails_the_whole_batch() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let (open, open_ids) = verdict_alert(db, &MULTI[..1], None).await;
    let mut all = targets(root, &ids);
    all.extend(targets(open, &open_ids));
    let refuse = BatchRules {
        refuse: BTreeSet::from([SkipCause::Alert]),
        ..BatchRules::default()
    };
    conflict(
        service
            .set_detection_verdicts(&actor, &all, Some(Verdict::Fp), &refuse)
            .await,
    );
    assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
    let batch = service
        .set_detection_verdicts(&actor, &all, Some(Verdict::Fp), &BatchRules::default())
        .await
        .expect("writes");
    assert_eq!(batch.changed, 3);
    let skipped: Vec<_> = batch
        .skipped
        .iter()
        .map(|s| (s.detection, s.cause))
        .collect();
    assert_eq!(skipped, [(open_ids[0], SkipCause::Alert)]);
}

/// The detection points screen's verdict filters, each and its inverse, the alert list's Unconfirmed
/// Detections, and `changed_since` catching a verdict's change.
#[tokio::test]
async fn verdict_filters_match_what_they_say() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    // a multi-signature TP alert with one detection marked FP, an FP alert and an open one
    let (multi, multi_ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let (fp, fp_ids) = verdict_alert(db, &MULTI[..1], Some("FALSE_POSITIVE")).await;
    let (open, open_ids) = verdict_alert(db, &MULTI[..1], None).await;
    let before = Utc::now();
    service
        .set_detection_verdict(&actor, multi, multi_ids[0], Verdict::Fp)
        .await
        .expect("sets");
    let listed = |filters: Vec<FilterEntry>, changed_since: Option<chrono::DateTime<Utc>>| {
        let service = &service;
        let actor = &actor;
        async move {
            let filter = DetectionPointFilter {
                filters,
                changed_since,
                ..DetectionPointFilter::default()
            };
            let ids: BTreeSet<i64> = service
                .detection_points(actor, &filter, None, None)
                .await
                .expect("lists")
                .detections
                .into_iter()
                .map(|d| d.id)
                .collect();
            let count = service
                .detection_point_count(actor, &filter, 100)
                .await
                .expect("counts");
            assert_eq!(count, ids.len() as i64, "{filter:?}");
            ids
        }
    };
    let every: BTreeSet<i64> = multi_ids
        .iter()
        .chain(&fp_ids)
        .chain(&open_ids)
        .copied()
        .collect();
    let set = |ids: &[i64]| ids.iter().copied().collect::<BTreeSet<_>>();
    for (name, values, matched) in [
        ("Verdict", vec!["TP"], set(&multi_ids[1..])),
        ("Verdict", vec!["fp"], set(&[multi_ids[0], fp_ids[0]])),
        ("Verdict", vec!["none"], set(&open_ids)),
        (
            "Verdict",
            vec!["fp", "none"],
            set(&[multi_ids[0], fp_ids[0], open_ids[0]]),
        ),
        ("Source", vec!["explicit"], set(&multi_ids[..1])),
        ("Source", vec!["inherited_multi"], set(&multi_ids[1..])),
        ("Source", vec!["inherited_single"], set(&fp_ids)),
        ("Has Override", vec!["true"], set(&multi_ids[..1])),
        (
            "Has Override",
            vec!["false"],
            &every - &set(&multi_ids[..1]),
        ),
        ("Has Override", vec!["true", "false"], every.clone()),
    ] {
        assert_eq!(
            listed(vec![text(name, false, &values)], None).await,
            matched,
            "{name} {values:?}"
        );
        let inverted = listed(vec![text(name, true, &values)], None).await;
        let expected = if values.len() == 2 && name == "Has Override" {
            // ace3's: both values match everything, so the inverse matches nothing
            BTreeSet::new()
        } else {
            &every - &matched
        };
        assert_eq!(inverted, expected, "!{name} {values:?}");
    }
    assert!(matches!(
        service
            .detection_point_count(
                &actor,
                &filtered_points(vec![text("Verdict", false, &["maybe"])]),
                10
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    // changed_since: a verdict's change counts, and so does a disposition
    assert_eq!(listed(Vec::new(), Some(Utc::now())).await, BTreeSet::new());
    let since = Utc::now();
    service
        .clear_detection_verdict(&actor, multi, multi_ids[0])
        .await
        .expect("clears");
    assert_eq!(
        listed(Vec::new(), Some(since)).await,
        set(&multi_ids[..1]),
        "a cleared verdict has only its history to say so"
    );
    let since = Utc::now();
    service
        .disposition(&actor, open, "DELIVERY")
        .await
        .expect("dispositions");
    assert_eq!(listed(Vec::new(), Some(since)).await, set(&open_ids));
    assert!(
        listed(Vec::new(), Some(before))
            .await
            .is_superset(&set(&multi_ids[..1]))
    );

    // the alert list's Unconfirmed Detections: the multi-signature alert has two
    let alerts = |values: &[&str], inverted: bool| {
        let service = &service;
        let actor = &actor;
        let filters = vec![text("Unconfirmed Detections", inverted, values)];
        async move {
            matching(service, actor, filters)
                .await
                .into_iter()
                .collect::<BTreeSet<_>>()
        }
    };
    let roots = BTreeSet::from([multi, fp, open]);
    assert_eq!(alerts(&["True"], false).await, BTreeSet::from([multi]));
    assert_eq!(alerts(&["false"], false).await, BTreeSet::from([fp, open]));
    assert_eq!(alerts(&["True", "False"], false).await, roots);
    assert_eq!(alerts(&["True"], true).await, BTreeSet::from([fp, open]));
    service
        .confirm_detections(&actor, multi)
        .await
        .expect("confirms");
    assert_eq!(alerts(&["True"], false).await, BTreeSet::new());
}

fn filtered_points(filters: Vec<FilterEntry>) -> DetectionPointFilter {
    DetectionPointFilter {
        filters,
        ..DetectionPointFilter::default()
    }
}

async fn set_detection_verdict_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect("sets");
    let row = last_audit(db).await;
    let state = |verdict: Value| json!({"detection": ids[0], "alert": root, "signature_uuid": SIG_A, "verdict": verdict});
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "set_detection_verdict".to_owned(),
            target: ("detection".to_owned(), ids[0].to_string()),
            before: Some(state(Value::Null)),
            after: Some(state(json!("fp"))),
            details: json!({}),
        }
    );
    // what's stored already has no row
    let rows = audit_rows(db).await.len();
    service
        .set_detection_verdict(&actor, root, ids[0], Verdict::Fp)
        .await
        .expect("finds it");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn clear_detection_verdict_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    service
        .set_detection_verdict(&actor, root, ids[2], Verdict::Tp)
        .await
        .expect("sets");
    service
        .clear_detection_verdict(&actor, root, ids[2])
        .await
        .expect("clears");
    let row = last_audit(db).await;
    let state = |verdict: Value| json!({"detection": ids[2], "alert": root, "signature_uuid": SIG_B, "verdict": verdict});
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "clear_detection_verdict".to_owned(),
            target: ("detection".to_owned(), ids[2].to_string()),
            before: Some(state(json!("tp"))),
            after: Some(state(Value::Null)),
            details: json!({}),
        }
    );
    row.action
}

async fn set_detection_verdicts_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let mut all = targets(root, &ids[..2]);
    all.push((root, i64::MAX));
    service
        .set_detection_verdicts(&actor, &all, Some(Verdict::Fp), &BatchRules::default())
        .await
        .expect("writes");
    let row = last_audit(db).await;
    let states = |verdict: Value| {
        json!({"verdicts": ids[..2].iter().map(|id| json!({
            "detection": id, "alert": root, "signature_uuid": SIG_A, "verdict": verdict,
        })).collect::<Vec<_>>()})
    };
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "set_detection_verdicts".to_owned(),
            target: ("detections".to_owned(), format!("{},{}", ids[0], ids[1])),
            before: Some(states(Value::Null)),
            after: Some(states(json!("fp"))),
            details: json!({"unchanged": 0, "skipped": 1}),
        }
    );
    row.action
}

async fn confirm_detections_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    assert_eq!(
        service
            .confirm_detections(&actor, root)
            .await
            .expect("confirms"),
        3
    );
    let row = last_audit(db).await;
    let states = |verdict: Value| {
        json!({"verdicts": ids.iter().zip([SIG_A, SIG_A, SIG_B]).map(|(id, signature)| json!({
            "detection": id, "alert": root, "signature_uuid": signature, "verdict": verdict,
        })).collect::<Vec<_>>()})
    };
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "confirm_detections".to_owned(),
            target: ("root".to_owned(), root.to_string()),
            before: Some(states(Value::Null)),
            after: Some(states(json!("tp"))),
            details: json!({}),
        }
    );
    row.action
}

/// Every verdict write needs `alert:write`, as ace3's routes do: a reader is refused before anything is
/// read, with no row, and learns nothing of the alert.
#[tokio::test]
async fn verdict_writes_need_alert_write() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (root, ids) = verdict_alert(db, MULTI, Some("DELIVERY")).await;
    let reader = Holder::User(UserId(Uuid::from_u128(0x7E1)));
    grant(db, &reader, "alert", "read", Effect::Allow).await;
    let reader = user(UserId(Uuid::from_u128(0x7E1)));
    let audits = audit_rows(db).await.len();
    for alert in [root, Uuid::nil()] {
        let refusals = [
            service
                .set_detection_verdict(&reader, alert, ids[0], Verdict::Fp)
                .await
                .map(|_| ()),
            service
                .clear_detection_verdict(&reader, alert, ids[0])
                .await
                .map(|_| ()),
            service
                .set_detection_verdicts(
                    &reader,
                    &targets(alert, &ids),
                    Some(Verdict::Fp),
                    &BatchRules::default(),
                )
                .await
                .map(|_| ()),
            service.confirm_detections(&reader, alert).await.map(|_| ()),
        ];
        for refused in refusals {
            assert!(
                matches!(
                    &refused,
                    Err(ServiceError::PermissionDenied { permission, .. }) if *permission == ALERT_WRITE
                ),
                "{refused:?}"
            );
        }
    }
    assert_eq!(audit_rows(db).await.len(), audits);
    assert_eq!(stored_verdicts(db, root).await, BTreeSet::new());
    assert_eq!(verdict_history(db, root).await, []);
    // the reader still reads them
    assert_eq!(verdict_rows(&service, &reader, root).await.len(), 3);
}

// PLAN.md 7.10 batch 1: SVS's foundation, ace3's tests/saq/svs/ test_hosts.py, test_alert_status.py and
// test_config.py's unknown keys; test_markers.py, test_log_search.py and test_hosts.py's pure cases are
// ace-core's unit tests.

use std::collections::BTreeMap;

use ace_core::svs::hosts::{HostFields, match_target};
use ace_core::svs::{AttributionConfidence, MARKER_MISMATCH_SIGNATURE, RunState, SvsStatus};
use ace_service::{AlertSvsView, MarkerMismatch, RunRef, TestHost};

/// conftest.py's `attribute_to_run`'s test.
const SVS_TEST_GUID: &str = "dddddddd-4444-4444-8444-444444444444";

/// A run as a fixture names it.
#[derive(Debug, Clone)]
struct TestRun {
    id: i64,
    uuid: Uuid,
    marker: String,
}

/// conftest.py's `add_catalog_test`: a test in the Atomic Red Team catalog, as the catalog stores one.
async fn add_catalog_test(db: &Db, guid: &str, name: &str) {
    sqlx::query(
        "INSERT INTO svs.catalog_tests
             (guid, repository, technique, technique_name, name, description, platforms, executor,
              test, content_hash, commit, path)
         VALUES ($1::uuid, 'atomic-red-team', 'T1059.001', 'T1059.001 name', $2, $2 || ' does a thing',
                 '{windows}', 'powershell', '{}', repeat('0', 64), repeat('a', 40),
                 'atomics/T1059.001/T1059.001.yaml')
         ON CONFLICT (guid) DO NOTHING",
    )
    .bind(guid)
    .bind(name)
    .execute(db.pool())
    .await
    .expect("adds a catalog test");
}

/// conftest.py's `attribute_to_run`: a new run in `state` of its test, with `detection` of `root`
/// attributed to it by a marker, as the core's SVS hook would have.
async fn attribute_to_run(db: &Db, root: Uuid, detection: i64, state: RunState) -> TestRun {
    add_catalog_test(db, SVS_TEST_GUID, "PowerShell download").await;
    let marker = ace_core::svs::markers::new_marker();
    let (id, uuid): (i64, Uuid) = sqlx::query_as(
        "INSERT INTO svs.runs
             (uuid, test_guid, platform, test_content_hash, catalog_commit, state, marker, launcher,
              observation_seconds, attribution_seconds)
         VALUES (gen_random_uuid(), $1::uuid, 'windows', repeat('0', 64), repeat('a', 40), $2, $3,
                 'art', 3600, 90000)
         RETURNING id, uuid",
    )
    .bind(SVS_TEST_GUID)
    .bind(state)
    .bind(&marker)
    .fetch_one(db.pool())
    .await
    .expect("adds a run");
    attribute(db, id, root, detection, false).await;
    TestRun { id, uuid, marker }
}

/// test_alert_status.py's `_attribute`: another attribution of `detection` to the run, held or removed.
async fn attribute(db: &Db, run: i64, root: Uuid, detection: i64, removed: bool) {
    sqlx::query(
        "INSERT INTO svs.attributions
             (run_id, root_id, detection_id, confidence, source, actor, removed_at, removed_by)
         VALUES ($1, $2, $3, 'marker', 'router', '{\"kind\": \"internal\", \"id\": \"svs\"}',
                 CASE WHEN $4 THEN now() END,
                 CASE WHEN $4 THEN '{\"kind\": \"internal\", \"id\": \"svs\"}'::jsonb END)",
    )
    .bind(run)
    .bind(root)
    .bind(detection)
    .bind(removed)
    .execute(db.pool())
    .await
    .expect("attributes");
}

/// test_alert_status.py's `_mismatch`: a marker mismatch detection on the alert, its details naming the
/// marker and how it disagrees unless `details` says otherwise.
async fn mismatch_detection(
    db: &Db,
    root: Uuid,
    marker: &str,
    result: &str,
    details: Option<Value>,
) {
    let details = details.unwrap_or_else(|| json!({"marker": marker, "result": result}));
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, description, details, signature_uuid)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(root)
    .bind(format!(
        "SVS test run marker {marker} does not match its run"
    ))
    .bind(details)
    .bind(MARKER_MISMATCH_SIGNATURE)
    .execute(db.pool())
    .await
    .expect("adds a mismatch");
}

const SVS_SIGNATURE: &str = "6f3a1b2c-1111-2222-3333-444455556666";

/// An alert with `count` detections on itself, test_alert_status.py's `_detections`.
async fn svs_alert(db: &Db, count: usize) -> (Uuid, Vec<i64>) {
    const ONE: &[Detected] = &[(None, SVS_SIGNATURE, "detection a")];
    const TWO: &[Detected] = &[
        (None, SVS_SIGNATURE, "detection a"),
        (None, SVS_SIGNATURE, "detection b"),
    ];
    verdict_alert(db, if count == 1 { ONE } else { TWO }, None).await
}

fn run_ref(run: &TestRun, state: RunState) -> RunRef {
    RunRef {
        uuid: run.uuid,
        state,
        test_guid: SVS_TEST_GUID.parse().expect("a uuid"),
        test_name: Some("PowerShell download".to_owned()),
    }
}

async fn svs_view(db: &Db, root: Uuid) -> Option<AlertSvsView> {
    service(db)
        .alert_svs_view(&admin(db).await, root)
        .await
        .expect("reads")
}

/// test_alert_status.py's `test_an_alert_svs_never_touched`.
#[tokio::test]
async fn an_alert_svs_never_touched() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, _) = svs_alert(db, 1).await;
    assert_eq!(svs_view(db, root).await, None);
    assert!(
        service(db)
            .alert_svs_statuses(&admin(db).await, &[root])
            .await
            .expect("reads")
            .is_empty()
    );
    // a root that isn't an alert has no page
    let not_an_alert = NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &not_an_alert)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    assert!(matches!(
        service(db)
            .alert_svs_view(&admin(db).await, not_an_alert.id)
            .await,
        Err(ServiceError::NotFound(_))
    ));
    // the alert's readers read it
    let reader = UserId(Uuid::from_u128(0xC2));
    exists(db, &Holder::User(reader)).await;
    assert!(matches!(
        service(db).alert_svs_view(&user(reader), root).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "alert:read"
    ));
}

/// test_alert_status.py's `test_a_test_alert_held_by_two_runs`.
#[tokio::test]
async fn a_test_alert_held_by_two_runs() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = svs_alert(db, 2).await;
    let (a, b) = (ids[0], ids[1]);
    let run = attribute_to_run(db, root, a, RunState::Started).await;
    let other = attribute_to_run(db, root, b, RunState::Closed).await;
    attribute(db, run.id, root, b, false).await;

    assert_eq!(
        svs_view(db, root).await,
        Some(AlertSvsView {
            status: SvsStatus::Test,
            runs: vec![
                run_ref(&run, RunState::Started),
                run_ref(&other, RunState::Closed)
            ],
            detections: BTreeMap::from([(a, vec![run.uuid]), (b, vec![run.uuid, other.uuid])]),
            mismatches: vec![],
        })
    );
    let statuses = service(db)
        .alert_svs_statuses(&admin(db).await, &[root])
        .await
        .expect("reads");
    assert_eq!(statuses[&root].status, SvsStatus::Test);
    assert_eq!(statuses[&root].runs, [run.uuid, other.uuid]);
}

/// test_alert_status.py's `test_a_partial_alert_names_only_what_holds`.
#[tokio::test]
async fn a_partial_alert_names_only_what_holds() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = svs_alert(db, 2).await;
    let run = attribute_to_run(db, root, ids[0], RunState::Started).await;
    attribute(db, run.id, root, ids[1], true).await;

    let view = svs_view(db, root).await.expect("a view");
    assert_eq!(
        (view.status, view.runs, view.detections),
        (
            SvsStatus::Partial,
            vec![run_ref(&run, RunState::Started)],
            BTreeMap::from([(ids[0], vec![run.uuid])])
        )
    );
}

/// test_alert_status.py's `test_a_test_alert_by_context`.
#[tokio::test]
async fn a_test_alert_by_context() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = svs_alert(db, 1).await;
    attribute_to_run(db, root, ids[0], RunState::Started).await;
    sqlx::query("UPDATE svs.attributions SET confidence = $2 WHERE root_id = $1")
        .bind(root)
        .bind(AttributionConfidence::Context)
        .execute(db.pool())
        .await
        .expect("updates");
    assert_eq!(
        svs_view(db, root).await.expect("a view").status,
        SvsStatus::TestContext
    );
}

/// test_alert_status.py's `test_a_run_whose_test_left_the_catalog_has_no_name`.
#[tokio::test]
async fn a_run_whose_test_left_the_catalog_has_no_name() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = svs_alert(db, 1).await;
    let run = attribute_to_run(db, root, ids[0], RunState::Started).await;
    let gone: Uuid = "eeeeeeee-5555-4555-8555-555555555555"
        .parse()
        .expect("a uuid");
    sqlx::query("UPDATE svs.runs SET test_guid = $2 WHERE id = $1")
        .bind(run.id)
        .bind(gone)
        .execute(db.pool())
        .await
        .expect("updates");
    let view = svs_view(db, root).await.expect("a view");
    let [found] = view.runs.as_slice() else {
        panic!("one run: {view:?}");
    };
    assert_eq!((found.test_guid, found.test_name.as_deref()), (gone, None));
}

/// test_alert_status.py's `test_markers_that_disagree_name_their_run`.
#[tokio::test]
async fn markers_that_disagree_name_their_run() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (elsewhere, elsewhere_ids) = svs_alert(db, 1).await;
    let run = attribute_to_run(db, elsewhere, elsewhere_ids[0], RunState::Started).await;

    let (root, _) = svs_alert(db, 1).await;
    // a marker may be in any case in an alert; runs store it lower case
    let upper = run.marker.to_uppercase();
    mismatch_detection(db, root, &upper, "other host", None).await;
    let unknown = format!("svs-{}", "q".repeat(26));
    mismatch_detection(db, root, &unknown, "unknown", None).await;
    // a detection whose details can't be read is left out
    mismatch_detection(db, root, "", "", Some(json!("not json"))).await;

    let view = svs_view(db, root).await.expect("a view");
    assert_eq!(
        (view.status, view.runs, view.detections),
        (SvsStatus::Mismatch, vec![], BTreeMap::new())
    );
    assert_eq!(
        view.mismatches,
        [
            MarkerMismatch {
                marker: upper,
                result: "other host".to_owned(),
                run: Some(run_ref(&run, RunState::Started)),
            },
            MarkerMismatch {
                marker: unknown,
                result: "unknown".to_owned(),
                run: None,
            },
        ]
    );
    let statuses = service(db)
        .alert_svs_statuses(&admin(db).await, &[root, elsewhere])
        .await
        .expect("reads");
    assert_eq!(statuses[&root].status, SvsStatus::Mismatch);
    assert!(statuses[&root].runs.is_empty());
    assert_eq!(statuses[&elsewhere].status, SvsStatus::Test);
}

/// test_config.py's `test_unknown_svs_keys_are_rejected`: the overlay's `svs:` section refuses a key this
/// build doesn't have, as ace3's schema does. `samples` comes with batch 2, so it's unknown here too.
#[test]
fn unknown_svs_keys_are_rejected() {
    assert!(ace_sdk::Overlay::from_yaml("svs: {samples: {pool: svs_samples, nope: 1}}").is_err());
    assert!(ace_sdk::Overlay::from_yaml("svs: {nope: {}}").is_err());
    let overlay = ace_sdk::Overlay::from_yaml(
        "svs: {log_search_url: 'https://logs.example/?q=svs_run%3D{run_uuid}'}",
    )
    .expect("parses");
    assert_eq!(
        overlay.svs.log_search_url.as_deref(),
        Some("https://logs.example/?q=svs_run%3D{run_uuid}")
    );
    assert_eq!(
        ace_sdk::Overlay::from_yaml("")
            .expect("parses")
            .svs
            .log_search_url,
        None
    );
}

/// Every test host's row, for the audit failure test.
async fn test_host_rows(db: &Db) -> Vec<(i64, String, Vec<String>)> {
    sqlx::query_as("SELECT id, hostname, usernames FROM svs.test_hosts ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("reads")
}

fn host_fields(hostname: &str, usernames: &[&str], platform: Option<&str>) -> HostFields {
    HostFields {
        usernames: usernames.iter().map(|name| (*name).to_owned()).collect(),
        platform: platform.map(str::to_owned),
        ..HostFields::new(hostname)
    }
}

/// test_hosts.py's `test_match_target`, every case of its table, over its lab: a host that lists its
/// users, one that doesn't, and one without an fqdn.
#[tokio::test]
async fn match_target_finds_the_test_host() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    for fields in [
        host_fields("win10-01.corp.example", &["CORP\\svc_art"], Some("windows")),
        host_fields("ubuntu-01.corp.example", &[], Some("linux")),
        host_fields("mac-01", &[], None),
    ] {
        service
            .create_test_host(&actor, &fields)
            .await
            .expect("adds a host");
    }
    let mut conn = db.pool().acquire().await.expect("a connection");
    for (hostname, username, matched, reason) in [
        ("win10-01", Some("svc_art"), true, None),
        ("WIN10-01.CORP.EXAMPLE", Some("CORP\\SVC_ART"), true, None),
        (
            "win10-01",
            Some("administrator"),
            false,
            Some("administrator is not a user of test host win10-01"),
        ),
        (
            "win10-01",
            None,
            false,
            Some("lists its users and no user was given"),
        ),
        (
            "win10-01.prod.example",
            Some("svc_art"),
            false,
            Some("win10-01.prod.example is not test host win10-01.corp.example"),
        ),
        ("ubuntu-01", None, true, None),
        ("mac-01.anything.example", Some("anyone"), true, None),
        (
            "dc-01",
            Some("svc_art"),
            false,
            Some("dc-01 is not a test host"),
        ),
        (
            "not a host",
            Some("svc_art"),
            false,
            Some("is not a host name"),
        ),
    ] {
        let found = match_target(&mut conn, hostname, username)
            .await
            .expect("matches");
        assert_eq!(
            found.matched(),
            matched,
            "{hostname} {username:?}: {found:?}"
        );
        if let Some(reason) = reason {
            let given = found.reason.unwrap_or_default();
            assert!(given.contains(reason), "{hostname}: {given}");
        }
    }
}

/// test_hosts.py's `test_create_update_delete_are_audited`, by a key with no owner, ace3's config key: no
/// user, so the key is all that says who it was.
#[tokio::test]
async fn create_update_delete_are_audited() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let key_id = ApiKeyId(Uuid::from_u128(0x5A));
    exists(db, &Holder::ApiKey(key_id)).await;
    service
        .grant(
            &admin(db).await,
            &Holder::ApiKey(key_id),
            &pattern("svs", "admin"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    let key = key(key_id, None);
    let before = audit_rows(db).await.len();
    let host = service
        .create_test_host(&key, &host_fields("win10-01", &["a"], None))
        .await
        .expect("adds");
    service
        .update_test_host(
            &key,
            host.id,
            &host_fields("win10-01", &["b"], Some("windows")),
        )
        .await
        .expect("changes");
    service
        .delete_test_host(&key, host.id)
        .await
        .expect("removes");
    let rows = audit_rows(db).await.split_off(before);
    let key_json = json!({"kind": "api_key", "id": key_id.0, "name": "triage", "owner": null});
    assert_eq!(
        rows.iter()
            .map(|row| (row.action.as_str(), &row.actor))
            .collect::<Vec<_>>(),
        [
            ("create_test_host", &key_json),
            ("update_test_host", &key_json),
            ("delete_test_host", &key_json),
        ]
    );
    assert_eq!(
        rows[0].after.as_ref().expect("an after")["usernames"],
        json!(["a"])
    );
    assert_eq!(
        rows[1].before.as_ref().expect("a before")["usernames"],
        json!(["a"])
    );
    assert_eq!(
        rows[1].after.as_ref().expect("an after")["usernames"],
        json!(["b"])
    );
    assert_eq!(
        rows[2].before.as_ref().expect("a before")["hostname"],
        "win10-01"
    );
    assert_eq!(test_host_rows(db).await, []);
}

/// test_hosts.py's `test_stored_fields`.
#[tokio::test]
async fn stored_fields() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let fields = HostFields {
        ips: vec!["10.0.0.5".to_owned()],
        ..host_fields("win10-01.corp.example", &["CORP\\Alice"], None)
    };
    let host = service
        .create_test_host(&actor, &fields)
        .await
        .expect("adds");
    let row = service.test_host(&actor, host.id).await.expect("reads");
    assert_eq!(
        (row.hostname.as_str(), row.fqdn.as_deref()),
        ("win10-01", Some("win10-01.corp.example"))
    );
    assert_eq!(
        (row.usernames, row.ips),
        (vec!["alice".to_owned()], vec!["10.0.0.5".to_owned()])
    );
    assert_eq!(
        row.created_by.expect("who").id,
        Uuid::from_u128(0xAD).to_string()
    );
    assert_eq!(
        service
            .test_hosts(&actor)
            .await
            .expect("lists")
            .into_iter()
            .map(|host| host.hostname)
            .collect::<Vec<_>>(),
        ["win10-01"]
    );
    // reading needs svs:run_read
    let reader = UserId(Uuid::from_u128(0xC3));
    exists(db, &Holder::User(reader)).await;
    assert!(matches!(
        service.test_hosts(&user(reader)).await,
        Err(ServiceError::PermissionDenied { ref permission, .. })
            if permission.to_string() == "svs:run_read"
    ));
}

/// test_hosts.py's `test_a_host_is_never_created_after_it_was_updated`: ace3 rounded a fraction up past
/// the server's updated_at. Here both are the transaction's time, and an update moves only updated_at.
#[tokio::test]
async fn a_host_is_never_created_after_it_was_updated() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let host: TestHost = service
        .create_test_host(&actor, &HostFields::new("win10-07"))
        .await
        .expect("adds");
    assert!(host.created_at <= host.updated_at);
    let changed = service
        .update_test_host(&actor, host.id, &host_fields("win10-07", &["a"], None))
        .await
        .expect("changes");
    assert_eq!(changed.created_at, host.created_at);
    assert!(changed.updated_at > host.updated_at);
}

/// test_hosts.py's `test_a_short_name_is_one_host`.
#[tokio::test]
async fn a_short_name_is_one_host() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    service
        .create_test_host(&actor, &HostFields::new("win10-01.corp.example"))
        .await
        .expect("adds");
    assert!(matches!(
        service
            .create_test_host(&actor, &HostFields::new("WIN10-01.lab.example"))
            .await,
        Err(ServiceError::Conflict(why)) if why == "win10-01 is already a test host"
    ));
    let other = service
        .create_test_host(&actor, &HostFields::new("win10-02"))
        .await
        .expect("adds");
    assert!(matches!(
        service
            .update_test_host(&actor, other.id, &HostFields::new("win10-01"))
            .await,
        Err(ServiceError::Conflict(_))
    ));
    // a field that can't be used is refused before anything is written
    assert!(matches!(
        service
            .create_test_host(&actor, &HostFields::new("not a host"))
            .await,
        Err(ServiceError::InvalidRequest(why)) if why == "'not a host' is not a host name"
    ));
}

/// test_hosts.py's `test_unknown_host`.
#[tokio::test]
async fn unknown_host() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    assert!(matches!(
        service
            .update_test_host(&actor, 12345, &HostFields::new("x"))
            .await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service.delete_test_host(&actor, 12345).await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service.test_host(&actor, 12345).await,
        Err(ServiceError::NotFound(_))
    ));
}

async fn create_test_host_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let fields = HostFields {
        ips: vec!["::1".to_owned(), "10.0.0.5".to_owned()],
        notes: Some("  lab 3  ".to_owned()),
        ..host_fields(
            "Audit-01.corp.example",
            &["CORP\\Bob", "alice"],
            Some("Windows"),
        )
    };
    let host = service(db)
        .create_test_host(&actor, &fields)
        .await
        .expect("adds");
    assert_eq!(host.notes.as_deref(), Some("lab 3"));
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_test_host".to_owned(),
            target: ("svs_test_host".to_owned(), host.id.to_string()),
            before: None,
            after: Some(json!({
                "hostname": "audit-01",
                "fqdn": "audit-01.corp.example",
                "usernames": ["alice", "bob"],
                "ips": ["10.0.0.5", "::1"],
                "platform": "windows",
            })),
            details: json!({}),
        }
    );
    row.action
}

async fn update_test_host_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let host = service
        .create_test_host(&actor, &HostFields::new("audit-02"))
        .await
        .expect("adds");
    let fields = host_fields("audit-02", &["svc_art"], Some("linux"));
    service
        .update_test_host(&actor, host.id, &fields)
        .await
        .expect("changes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "update_test_host".to_owned(),
            target: ("svs_test_host".to_owned(), host.id.to_string()),
            before: Some(json!({
                "hostname": "audit-02", "fqdn": null, "usernames": [], "ips": [], "platform": null,
            })),
            after: Some(json!({
                "hostname": "audit-02", "fqdn": null, "usernames": ["svc_art"], "ips": [],
                "platform": "linux",
            })),
            details: json!({}),
        }
    );
    // the same fields again change nothing, and have no row
    let rows = audit_rows(db).await.len();
    service
        .update_test_host(&actor, host.id, &fields)
        .await
        .expect("changes nothing");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn delete_test_host_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let service = service(db);
    let host = service
        .create_test_host(&actor, &host_fields("audit-03", &["svc_art"], None))
        .await
        .expect("adds");
    service
        .delete_test_host(&actor, host.id)
        .await
        .expect("removes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_test_host".to_owned(),
            target: ("svs_test_host".to_owned(), host.id.to_string()),
            before: Some(json!({
                "hostname": "audit-03", "fqdn": null, "usernames": ["svc_art"], "ips": [],
                "platform": null,
            })),
            after: None,
            details: json!({}),
        }
    );
    row.action
}

// ---- SVS's samples (PLAN.md 7.10 batch 2): ace3's tests/saq/svs/test_labels.py, test_samples.py,
// test_capture.py's integration cases and test_actions.py ----

use ace_core::svs::samples::{
    self as svs_samples, CaptureResult, CaptureStatus, Label, SVS_SAMPLES, Strength,
    aggregate_label, capture_hold,
};
use ace_sdk::writes::SvsCaptureCandidate;
use ace_service::{SampleQuery, SampleSort};

const RULE_UUID: &str = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f";
const OTHER_RULE_UUID: &str = "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b";
const SVS_COMMIT: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The detection the YARA module leaves on a file for one match, with its structured details.
async fn yara_detection(
    db: &Db,
    root: Uuid,
    observable: i64,
    sha256: &str,
    rule: &str,
    rule_uuid: &str,
    version: &str,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO analysis.detections
             (root_id, observable_id, description, details, signature_uuid, signature_version,
              signature_family)
         VALUES ($1, $2, $3, $4, $5, $6, 'yara') RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(format!("{sha256} matched yara rule {rule}"))
    .bind(json!({"sha256": sha256, "rule": rule, "namespace": "unittest", "rule_uuid": rule_uuid}))
    .bind(rule_uuid)
    .bind(version)
    .fetch_one(db.pool())
    .await
    .expect("a detection")
}

/// A file observable of `sha256` at `path` in a root, without its bytes.
async fn file_observable(db: &Db, root: Uuid, path: &str, sha256: &str) -> i64 {
    let mut tx = db.begin().await.expect("begins");
    let id = tree::upsert_observable(
        &mut tx,
        root,
        &NewObservable::new(ObservableKind::File, sha256),
    )
    .await
    .expect("adds")
    .id;
    tree::add_file_at(&mut tx, root, id, path, &[], 1)
        .await
        .expect("adds its path");
    tx.commit().await.expect("commits");
    id.0
}

/// How a fixture capture differs from a stored one with a record.
#[derive(Debug, Clone)]
struct CaptureRow {
    state: &'static str,
    missing_reason: Option<&'static str>,
    rule_name: &'static str,
    file_path: &'static str,
    file_size: Option<i64>,
    signature_version: &'static str,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl Default for CaptureRow {
    fn default() -> Self {
        CaptureRow {
            state: "stored",
            missing_reason: None,
            rule_name: "svs_rule",
            file_path: "sample.bin",
            file_size: Some(10),
            signature_version: SVS_COMMIT,
            created_at: chrono::Utc::now(),
        }
    }
}

/// ace3's `insert_capture`: a capture row as a capture would leave it, with no bytes in the pool unless
/// the caller put them. Returns its id.
async fn insert_capture(
    db: &Db,
    root: Uuid,
    sha256: &str,
    rule_uuid: &str,
    row: CaptureRow,
) -> i64 {
    let stored = row.state == "stored";
    let record = (stored && row.missing_reason.is_none()).then(|| json!({"rule": row.rule_name}));
    sqlx::query_scalar(
        "INSERT INTO svs.yara_captures
             (root_id, sha256, rule_uuid, rule_name, namespace, signature_version, file_path,
              file_size, state, missing_reason, record, created_at, stored_at)
         VALUES ($1, $2, $3, $4, 'unittest', $5, $6, $7, $8, $9, $10, $11,
                 CASE WHEN $8 = 'stored' THEN $11 END)
         RETURNING id",
    )
    .bind(root)
    .bind(sha256)
    .bind(rule_uuid)
    .bind(row.rule_name)
    .bind(row.signature_version)
    .bind(row.file_path)
    .bind(row.file_size)
    .bind(row.state)
    .bind(row.missing_reason)
    .bind(record)
    .bind(row.created_at)
    .fetch_one(db.pool())
    .await
    .expect("a capture")
}

/// ace3's `graded_alert`: an alert whose files YARA matched, its disposition set and, unless `capture` is
/// false, a capture row per (file, rule). `files` names each file and the rules that matched it;
/// `contents` gives a file's bytes (the same bytes under two names are one sha256). Returns the alert and
/// each file's sha256 by name.
async fn graded_alert(
    db: &Db,
    disposition: Option<&str>,
    files: &[(&'static str, &[&str])],
    contents: &[(&str, &[u8])],
    capture: bool,
) -> (Uuid, BTreeMap<&'static str, String>) {
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let mut shas = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (name, rules) in files {
        let bytes = contents
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.to_vec())
            .unwrap_or_else(|| format!("svs sample {}", Uuid::new_v4()).into_bytes());
        let sha256 = sha256_hex(&bytes);
        let observable = file_observable(db, root.id, name, &sha256).await;
        for (index, rule_uuid) in rules.iter().enumerate() {
            // a second name of the same bytes is the same observable, which the YARA module scans once
            if seen.insert((sha256.clone(), (*rule_uuid).to_owned())) {
                yara_detection(
                    db,
                    root.id,
                    observable,
                    &sha256,
                    &format!("svs_rule_{index}"),
                    rule_uuid,
                    SVS_COMMIT,
                )
                .await;
                if capture {
                    insert_capture(
                        db,
                        root.id,
                        &sha256,
                        rule_uuid,
                        CaptureRow {
                            file_path: name,
                            ..CaptureRow::default()
                        },
                    )
                    .await;
                }
            }
        }
        shas.insert(*name, sha256);
    }
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root.id)
        .execute(db.pool())
        .await
        .expect("makes it an alert");
    set_disposition_row(db, root.id, disposition).await;
    (root.id, shas)
}

/// The detection of `rule_uuid` on the file of `sha256` in `root`: ace3's `_hash_of`.
async fn detection_of(db: &Db, root: Uuid, sha256: &str, rule_uuid: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT d.id FROM analysis.detections d
         JOIN analysis.observables o ON o.root_id = d.root_id AND o.id = d.observable_id
         WHERE d.root_id = $1 AND o.value = $2 AND d.signature_uuid = $3",
    )
    .bind(root)
    .bind(sha256)
    .bind(rule_uuid)
    .fetch_one(db.pool())
    .await
    .expect("the detection")
}

async fn sample_of(db: &Db, sha256: &str, rule_uuid: &str) -> Option<ace_service::Sample> {
    match service(db)
        .svs_sample(&admin(db).await, sha256, rule_uuid)
        .await
    {
        Ok(detail) => Some(detail.sample),
        Err(ServiceError::NotFound(_)) => None,
        Err(e) => panic!("reads the sample: {e}"),
    }
}

async fn label_of(db: &Db, sha256: &str, rule_uuid: &str) -> (Option<Label>, Option<Strength>) {
    let sample = sample_of(db, sha256, rule_uuid).await.expect("a sample");
    (sample.label, sample.label_source)
}

/// ace3's `_assert_sql_agrees`: the SQL's label is what `aggregate_label` makes of the SQL's votes.
fn assert_sql_agrees(sample: &ace_service::Sample) {
    assert_eq!(
        (sample.label, sample.label_source),
        aggregate_label(&sample.votes),
        "{sample:?}"
    );
}

/// test_labels.py's `test_an_fp_alert_labels_its_samples_fp`.
#[tokio::test]
async fn an_fp_alert_labels_its_samples_fp() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (_, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Fp), Some(Strength::InheritedSingle))
    );
    assert_eq!(sample.votes.fp_inherited_single, 1);
    assert_sql_agrees(&sample);
}

/// test_labels.py's `test_a_tp_alert_with_one_signature_labels_inherited_single`.
#[tokio::test]
async fn a_tp_alert_with_one_signature_labels_inherited_single() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (_, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Tp), Some(Strength::InheritedSingle))
    );
    assert_sql_agrees(&sample);
}

/// test_labels.py's `test_a_tp_alert_with_several_signatures_labels_inherited_multi`.
#[tokio::test]
async fn a_tp_alert_with_several_signatures_labels_inherited_multi() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (_, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    for rule in [RULE_UUID, OTHER_RULE_UUID] {
        let sample = sample_of(db, &files["a.bin"], rule)
            .await
            .expect("a sample");
        assert_eq!(
            (sample.label, sample.label_source),
            (Some(Label::Tp), Some(Strength::InheritedMulti))
        );
        assert_sql_agrees(&sample);
    }
}

/// test_labels.py's `test_an_explicit_override_decides`.
#[tokio::test]
async fn an_explicit_override_decides() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (root, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let detection = detection_of(db, root, &files["a.bin"], RULE_UUID).await;
    service(db)
        .set_detection_verdict(&actor, root, detection, Verdict::Fp)
        .await
        .expect("sets");
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Fp), Some(Strength::Explicit))
    );
    assert_sql_agrees(&sample);
    // the other rule's sample is untouched
    assert_eq!(
        label_of(db, &files["a.bin"], OTHER_RULE_UUID).await.1,
        Some(Strength::InheritedMulti)
    );
}

/// test_labels.py's `test_disagreeing_votes_of_one_strength_conflict`.
#[tokio::test]
async fn disagreeing_votes_of_one_strength_conflict() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let content = format!("conflicted {}", Uuid::new_v4()).into_bytes();
    let (first, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("b.bin", &[RULE_UUID])],
        &[("b.bin", &content)],
        true,
    )
    .await;
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(sample.capture_count, 2);
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Conflicted), Some(Strength::InheritedSingle))
    );
    assert_sql_agrees(&sample);
    // an explicit vote outweighs both
    let detection = detection_of(db, first, &files["a.bin"], RULE_UUID).await;
    service(db)
        .set_detection_verdict(&actor, first, detection, Verdict::Tp)
        .await
        .expect("sets");
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Tp), Some(Strength::Explicit))
    );
    assert_sql_agrees(&sample);
}

/// test_labels.py's `test_an_fp_alert_outweighs_an_unconfirmed_tp`.
#[tokio::test]
async fn an_fp_alert_outweighs_an_unconfirmed_tp() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let content = format!("precedence {}", Uuid::new_v4()).into_bytes();
    let (_, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("b.bin", &[RULE_UUID])],
        &[("b.bin", &content)],
        true,
    )
    .await;
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(
        (
            sample.votes.tp_inherited_multi,
            sample.votes.fp_inherited_single
        ),
        (1, 1)
    );
    assert_eq!(
        (sample.label, sample.label_source),
        (Some(Label::Fp), Some(Strength::InheritedSingle))
    );
}

/// test_labels.py's `test_an_unclassified_alert_casts_no_vote`.
#[tokio::test]
async fn an_unclassified_alert_casts_no_vote() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (_, files) =
        graded_alert(db, Some("REVIEWED"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(sample.capture_count, 1);
    assert_eq!((sample.label, sample.label_source), (None, None));
    assert_eq!(sample.votes, ace_core::svs::samples::Votes::default());
}

/// test_labels.py's `test_a_deleted_alert_casts_no_vote`.
#[tokio::test]
async fn a_deleted_alert_casts_no_vote() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID])],
        &[],
        true,
    )
    .await;
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deletes the alert");
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(sample.capture_count, 1);
    assert_eq!(sample.label, None);
}

/// test_labels.py's `test_the_same_bytes_under_two_names_are_two_votes`. Here the same bytes under two
/// names are one file observable with two paths, which the YARA module scans once, so one detection and
/// one vote, where ace3 has a node and a detection for each name (`ace_core::svs::samples`' docs).
#[tokio::test]
async fn the_same_bytes_under_two_names_are_one_vote() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let content = format!("twice {}", Uuid::new_v4()).into_bytes();
    let (_, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID]), ("b.bin", &[RULE_UUID])],
        &[("a.bin", &content), ("b.bin", &content)],
        true,
    )
    .await;
    assert_eq!(files["a.bin"], files["b.bin"]);
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(sample.capture_count, 1);
    assert_eq!(sample.votes.fp_inherited_single, 1);
}

/// test_labels.py's `test_a_detection_of_another_rule_or_file_does_not_vote`.
#[tokio::test]
async fn a_detection_of_another_rule_or_file_does_not_vote() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID]), ("b.bin", &[OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    // a capture of b.bin's bytes for a rule that never matched it
    insert_capture(db, root, &files["b.bin"], RULE_UUID, CaptureRow::default()).await;
    assert_eq!(label_of(db, &files["b.bin"], RULE_UUID).await.0, None);
    let sample = sample_of(db, &files["a.bin"], RULE_UUID)
        .await
        .expect("a sample");
    assert_eq!(sample.votes.fp_inherited_single, 1);
}

/// test_labels.py's `test_an_unreviewed_test_run_casts_no_vote`.
#[tokio::test]
async fn an_unreviewed_test_run_casts_no_vote() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let detection = detection_of(db, root, &files["a.bin"], RULE_UUID).await;
    let run = attribute_to_run(db, root, detection, RunState::Ended).await;
    assert_eq!(label_of(db, &files["a.bin"], RULE_UUID).await.0, None);
    sqlx::query("UPDATE svs.runs SET state = 'reviewed' WHERE id = $1")
        .bind(run.id)
        .execute(db.pool())
        .await
        .expect("reviews the run");
    assert_eq!(
        label_of(db, &files["a.bin"], RULE_UUID).await.0,
        Some(Label::Tp)
    );
}

/// test_labels.py's `test_a_disposition_change_relabels_at_read_time`.
#[tokio::test]
async fn a_disposition_change_relabels_at_read_time() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID])],
        &[],
        true,
    )
    .await;
    assert_eq!(
        label_of(db, &files["a.bin"], RULE_UUID).await.0,
        Some(Label::Fp)
    );
    set_disposition_row(db, root, Some("DELIVERY")).await;
    assert_eq!(
        label_of(db, &files["a.bin"], RULE_UUID).await.0,
        Some(Label::Tp)
    );
}

async fn all_samples(db: &Db, query: &SampleQuery) -> Vec<ace_service::Sample> {
    let service = service(db);
    let actor = admin(db).await;
    let mut samples = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = service
            .svs_samples(&actor, query, cursor.as_deref(), Some(2))
            .await
            .expect("lists");
        samples.extend(page.samples);
        match page.next {
            Some(next) => cursor = Some(next),
            None => return samples,
        }
    }
}

/// test_labels.py's `test_sql_agrees_with_python_over_the_whole_corpus`.
#[tokio::test]
async fn sql_agrees_with_rust_over_the_whole_corpus() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let content = format!("corpus {}", Uuid::new_v4()).into_bytes();
    let (first, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[
            ("a.bin", &[RULE_UUID, OTHER_RULE_UUID]),
            ("c.bin", &[RULE_UUID]),
        ],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("b.bin", &[RULE_UUID])],
        &[("b.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("REVIEWED"),
        &[("d.bin", &[OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let detection = detection_of(db, first, &files["a.bin"], OTHER_RULE_UUID).await;
    service(db)
        .set_detection_verdict(&actor, first, detection, Verdict::Fp)
        .await
        .expect("sets");
    let samples = all_samples(db, &SampleQuery::default()).await;
    assert_eq!(samples.len(), 4);
    for sample in &samples {
        assert_sql_agrees(sample);
    }
}

/// test_samples.py's `test_a_sample_aggregates_its_captures`.
#[tokio::test]
async fn a_sample_aggregates_its_captures() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let sha256 = "ab".repeat(32);
    let now = chrono::Utc::now();
    let day = chrono::Duration::days(1);
    let first = insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow {
            created_at: now - day * 2,
            file_path: "old.bin",
            rule_name: "old_name",
            ..CaptureRow::default()
        },
    )
    .await;
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow {
            created_at: now - day,
            state: "missing",
            missing_reason: Some("file"),
            ..CaptureRow::default()
        },
    )
    .await;
    let latest = insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow {
            created_at: now,
            file_path: "dir/new.bin",
            rule_name: "new_name",
            file_size: Some(99),
            missing_reason: Some("match_record"),
            signature_version: "unknown",
            ..CaptureRow::default()
        },
    )
    .await;
    // another rule's sample of the same file is its own sample
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        OTHER_RULE_UUID,
        CaptureRow::default(),
    )
    .await;

    let detail = service(db)
        .svs_sample(&admin(db).await, &sha256, RULE_UUID)
        .await
        .expect("reads");
    let sample = &detail.sample;
    assert_eq!(sample.capture_count, 3);
    assert_eq!(sample.stored, 2);
    assert_eq!(sample.missing, 1);
    assert_eq!(sample.missing_data, 2);
    assert_eq!(sample.unknown_version, 1);
    let micros = |t: chrono::DateTime<chrono::Utc>| t.timestamp_micros();
    assert_eq!(micros(sample.first_captured), micros(now - day * 2));
    assert_eq!(micros(sample.last_captured), micros(now));
    assert_eq!(sample.latest_capture_id, latest);
    assert_eq!(
        (
            sample.rule_name.as_str(),
            sample.file_path.as_str(),
            sample.file_size
        ),
        ("new_name", "dir/new.bin", Some(99))
    );
    assert_eq!(sample.label, None);
    assert_eq!(detail.captures.last().map(|c| c.id), Some(first));
    assert_eq!(
        sample_of(db, &sha256, OTHER_RULE_UUID)
            .await
            .expect("a sample")
            .capture_count,
        1
    );
    assert_eq!(sample_of(db, &sha256, "no-such-rule").await, None);
}

/// test_samples.py's `test_missing_by_rule`.
#[tokio::test]
async fn missing_by_rule() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let sha256 = "ab".repeat(32);
    for reason in ["file", "file", "storage"] {
        insert_capture(
            db,
            Uuid::new_v4(),
            &sha256,
            RULE_UUID,
            CaptureRow {
                state: "missing",
                missing_reason: Some(reason),
                ..CaptureRow::default()
            },
        )
        .await;
    }
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        OTHER_RULE_UUID,
        CaptureRow {
            missing_reason: Some("match_record"),
            rule_name: "other_rule",
            ..CaptureRow::default()
        },
    )
    .await;
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow::default(),
    )
    .await;
    let missing: Vec<(String, String, &str, i64)> = service(db)
        .svs_missing(&admin(db).await)
        .await
        .expect("reads")
        .into_iter()
        .map(|m| (m.rule_uuid, m.rule_name, m.reason.as_str(), m.count))
        .collect();
    assert_eq!(
        missing,
        [
            (RULE_UUID.to_owned(), "svs_rule".to_owned(), "file", 2),
            (
                OTHER_RULE_UUID.to_owned(),
                "other_rule".to_owned(),
                "match_record",
                1
            ),
            (RULE_UUID.to_owned(), "svs_rule".to_owned(), "storage", 1),
        ]
    );
}

/// test_samples.py's `test_contributing_detections_of_each_capture`.
#[tokio::test]
async fn contributing_detections_of_each_capture() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    let orphan = insert_capture(db, Uuid::new_v4(), sha256, RULE_UUID, CaptureRow::default()).await;
    let detail = service(db)
        .svs_sample(&admin(db).await, sha256, RULE_UUID)
        .await
        .expect("reads");
    let ours = detail
        .captures
        .iter()
        .find(|c| c.alert == root)
        .expect("the alert's capture");
    let [detection] = ours.detections.as_slice() else {
        panic!("one contributing detection: {:?}", ours.detections);
    };
    assert_eq!(
        detection.detection,
        detection_of(db, root, sha256, RULE_UUID).await
    );
    assert_eq!(
        (detection.verdict, detection.verdict_source),
        (Some(Verdict::Fp), Some(VerdictSource::InheritedSingle))
    );
    let lonely = detail
        .captures
        .iter()
        .find(|c| c.id == orphan)
        .expect("the orphan");
    assert_eq!(lonely.detections, []);
}

/// test_config.py's `test_the_sample_pool_is_defined`: the pool is the bucket's, held. ace3's is a
/// node-local, encrypted directory; ace4's bucket is one, shared, and unencrypted, as every pool of it is.
#[test]
fn the_sample_pool_is_defined() {
    let settings = BucketSettings::default();
    assert_eq!(
        settings.pools.get(SVS_SAMPLES).map(|p| p.retention),
        Some(ace_core::bucket::Retention::Held {
            grace: ace_core::bucket::DEFAULT_GRACE
        })
    );
}

// ---- capture ----

fn svs_candidate(sha256: &str, path: &str, record: bool, version: &str) -> SvsCaptureCandidate {
    SvsCaptureCandidate {
        sha256: sha256.to_owned(),
        rule_uuid: RULE_UUID.to_owned(),
        rule_name: "svs_rule".to_owned(),
        namespace: Some("unittest".to_owned()),
        signature_version: version.to_owned(),
        file_path: path.to_owned(),
        yara_meta_tags: Vec::new(),
        match_record: record.then(|| {
            json!({
                "rule": "svs_rule", "namespace": "unittest", "meta": {"uuid": RULE_UUID},
                "tags": ["unittest"], "commit": version, "target": path,
                "strings": [[0, "$a", "abc"], [10, "$a", "abc"], [5, "$b", "x"]],
            })
        }),
    }
}

/// A root with a file whose bytes the bucket holds for it, and the file's observable and sha256.
async fn captured_file(db: &Db, bucket: &Bucket) -> (Uuid, i64, String) {
    let bytes = format!("svs sample {}", Uuid::new_v4()).into_bytes();
    let (root, observable) = file_alert_with(db, bucket, &bytes).await;
    (root, observable, sha256_hex(&bytes))
}

/// ace3's `capture` of one candidate: its bytes found, then its row written in a transaction.
async fn capture_one(
    db: &Db,
    bucket: &Bucket,
    root: Uuid,
    observable: Option<i64>,
    candidate: SvsCaptureCandidate,
) -> CaptureResult {
    let prepared = svs_samples::prepare(db, bucket, root, observable, vec![candidate])
        .await
        .expect("prepares");
    let mut tx = db.begin().await.expect("begins");
    let [result] = svs_samples::land(&mut tx, bucket, &prepared)
        .await
        .expect("lands")
        .try_into()
        .expect("one result");
    tx.commit().await.expect("commits");
    result
}

#[derive(Debug, sqlx::FromRow)]
struct CaptureView {
    id: i64,
    root_id: Uuid,
    observable_id: Option<i64>,
    sha256: String,
    rule_uuid: String,
    rule_name: String,
    namespace: Option<String>,
    signature_version: String,
    file_path: String,
    file_size: Option<i64>,
    yara_meta_tags: Vec<String>,
    state: String,
    missing_reason: Option<String>,
    record: Option<Value>,
    match_summary: Option<Value>,
    yara_version: Option<String>,
    stored_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// ace3's `capture_rows`, of one file.
async fn capture_rows(db: &Db, sha256: &str) -> Vec<CaptureView> {
    sqlx::query_as(
        "SELECT id, root_id, observable_id, sha256, rule_uuid, rule_name, namespace,
                signature_version, file_path, file_size, yara_meta_tags, state, missing_reason,
                record, match_summary, yara_version, stored_at
         FROM svs.yara_captures WHERE sha256 = $1 ORDER BY id",
    )
    .bind(sha256)
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

/// The holds on a file in the samples pool, as (kind, id).
async fn sample_holds(db: &Db, sha256: &str) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2
         ORDER BY holder_kind, holder_id",
    )
    .bind(SVS_SAMPLES)
    .bind(sha256)
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

fn hold_of(capture: i64) -> (String, String) {
    let hold = capture_hold(capture);
    (hold.kind, hold.id)
}

/// A subscriber of this thread's own that keeps what's logged, as ace3's `caplog`.
fn log_capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

/// ace3's `_extras`: the ERROR lines that hold `message`.
fn errors_with(captured: &Captured, message: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(&captured.0.lock().expect("a lock")).into_owned();
    text.lines()
        .filter(|line| line.contains(" ERROR ") && line.contains(message))
        .map(str::to_owned)
        .collect()
}

fn clear(captured: &Captured) {
    captured.0.lock().expect("a lock").clear();
}

/// A bucket whose store can't be reached: a backend that's down.
fn broken_bucket(db: &Db) -> (Bucket, tempfile::TempDir) {
    let cache = tempfile::tempdir().expect("a cache directory");
    let mut config = BucketConfig::from_env().expect("the ACE4_BUCKET_* variables");
    config.endpoint = Some("http://127.0.0.1:9".to_owned());
    config.path_style = true;
    let store = Store::new(
        &config,
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    );
    (
        Bucket::new(db.clone(), store, BucketSettings::default()),
        cache,
    )
}

/// test_capture.py's `test_capture_stores_the_file_and_the_record`.
#[tokio::test]
async fn capture_stores_the_file_and_the_record() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let (captured, _logs) = log_capture();

    let result = capture_one(
        db,
        &bucket,
        root,
        Some(observable),
        svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT),
    )
    .await;

    assert_eq!(result.status, CaptureStatus::Stored);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(Some(row.id), result.capture);
    assert_eq!(row.root_id, root);
    assert_eq!(row.observable_id, Some(observable));
    assert_eq!(row.sha256, sha256);
    assert_eq!(row.rule_uuid, RULE_UUID);
    assert_eq!(row.rule_name, "svs_rule");
    assert_eq!(row.namespace.as_deref(), Some("unittest"));
    assert_eq!(row.signature_version, SVS_COMMIT);
    assert_eq!(row.file_path, "mail/a.txt");
    assert_eq!(row.file_size, Some(47));
    assert_eq!(row.yara_meta_tags, Vec::<String>::new());
    assert_eq!((row.state.as_str(), row.missing_reason), ("stored", None));
    assert!(row.stored_at.is_some());
    assert!(row.yara_version.is_some());
    assert_eq!(
        row.match_summary.as_ref().expect("a summary")["string_match_count"],
        3
    );
    assert_eq!(row.record.as_ref().expect("a record")["rule"], "svs_rule");
    // its signature version is known, so it isn't reported
    assert_eq!(
        errors_with(&captured, "unknown signature version"),
        Vec::<String>::new()
    );
    // the hold is on the file in the samples pool, by the capture's id
    assert_eq!(sample_holds(db, &sha256).await, [hold_of(row.id)]);
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    let kept = bucket.get(SVS_SAMPLES, &parsed).await.expect("kept");
    assert_eq!(kept.size, 47);
}

/// test_capture.py's `test_capture_is_idempotent`.
#[tokio::test]
async fn capture_is_idempotent() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let first = capture_one(db, &bucket, root, Some(observable), candidate.clone()).await;
    let second = capture_one(db, &bucket, root, Some(observable), candidate).await;
    assert_eq!(second.status, CaptureStatus::Already);
    assert_eq!(second.capture, first.capture);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(sample_holds(db, &sha256).await, [hold_of(row.id)]);
}

/// test_capture.py's `test_a_file_already_in_the_pool_is_captured_without_its_file`: another alert of the
/// same bytes takes only a hold on what the pool has. The bucket is one, shared by every node, so there's
/// no node to record.
#[tokio::test]
async fn a_file_already_in_the_pool_is_captured_without_its_file() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let first = capture_one(db, &bucket, root, Some(observable), candidate.clone()).await;
    assert_eq!(first.status, CaptureStatus::Stored);
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    let put = bucket
        .object(SVS_SAMPLES, &parsed)
        .await
        .expect("reads")
        .expect("kept");
    // another alert names the same bytes, and the broken bucket shows nothing is read or put for it
    let (other, _) = alert_with_file(db, &sha256).await;
    let (broken, _broken_cache) = broken_bucket(db);
    let prepared = svs_samples::prepare(db, &bucket, other, None, vec![candidate])
        .await
        .expect("prepares");
    let mut tx = db.begin().await.expect("begins");
    let [result] = svs_samples::land(&mut tx, &broken, &prepared)
        .await
        .expect("lands")
        .try_into()
        .expect("one result");
    tx.commit().await.expect("commits");
    assert_eq!(result.status, CaptureStatus::Stored);
    let capture = result.capture.expect("a row");
    assert!(sample_holds(db, &sha256).await.contains(&hold_of(capture)));
    let again = bucket
        .object(SVS_SAMPLES, &parsed)
        .await
        .expect("reads")
        .expect("kept");
    assert_eq!(
        again.created_at, put.created_at,
        "the object wasn't put again"
    );
}

/// Another alert with a file observable of `sha256`, and the observable.
async fn alert_with_file(db: &Db, sha256: &str) -> (Uuid, i64) {
    let root = NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let observable = file_observable(db, root.id, "mail/a.txt", sha256).await;
    (root.id, observable)
}

/// test_capture.py's `test_a_missing_file_is_recorded_and_reported_once`.
#[tokio::test]
async fn a_missing_file_is_recorded_and_reported_once() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    // a file whose bytes the bucket never had
    let sha256 = sha256_hex(format!("never kept {}", Uuid::new_v4()).as_bytes());
    let (root, observable) = alert_with_file(db, &sha256).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let (captured, _logs) = log_capture();

    let result = capture_one(db, &bucket, root, Some(observable), candidate.clone()).await;

    assert_eq!(result.status, CaptureStatus::Missing);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(
        (row.state.as_str(), row.missing_reason.as_deref()),
        ("missing", Some("file"))
    );
    let [line] = errors_with(&captured, "its file is gone")
        .try_into()
        .expect("reported once");
    assert!(line.contains(&root.to_string()), "{line}");
    assert!(line.contains(&format!("sha256={sha256}")), "{line}");
    assert!(line.contains(&format!("rule_uuid={RULE_UUID}")), "{line}");
    assert!(line.contains("missing_reason=\"file\""), "{line}");

    // the next pass tries again, and doesn't report it again
    clear(&captured);
    let again = capture_one(db, &bucket, root, Some(observable), candidate).await;
    assert_eq!(again.status, CaptureStatus::Missing);
    assert_eq!(
        errors_with(&captured, "its file is gone"),
        Vec::<String>::new()
    );
    assert_eq!(capture_rows(db, &sha256).await.len(), 1);
}

/// Bytes that aren't `sha256`'s under its key in the root's files: a file written again since it was
/// hashed.
async fn rewrite_root_copy(bucket: &Bucket, sha256: &str) {
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    let key = Store::key(ALERT_FILES, &parsed).expect("a key");
    bucket
        .store()
        .put_raw(&key, b"and more bytes".to_vec())
        .await
        .expect("rewrites");
}

/// test_capture.py's `test_a_file_that_no_longer_has_its_sha256_is_missing_and_reported_once`.
#[tokio::test]
async fn a_file_that_no_longer_has_its_sha256_is_missing_and_reported_once() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    rewrite_root_copy(&bucket, &sha256).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let (captured, _logs) = log_capture();

    let result = capture_one(db, &bucket, root, Some(observable), candidate.clone()).await;

    assert_eq!(result.status, CaptureStatus::Missing);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(
        (row.state.as_str(), row.missing_reason.as_deref()),
        ("missing", Some("file"))
    );
    assert_eq!(sample_holds(db, &sha256).await, []);
    assert_eq!(
        errors_with(&captured, "unable to store svs capture"),
        Vec::<String>::new()
    );
    let [line] = errors_with(&captured, "its file now hashes to")
        .try_into()
        .expect("reported once");
    assert!(line.contains("missing_reason=\"file\""), "{line}");

    clear(&captured);
    assert_eq!(
        capture_one(db, &bucket, root, Some(observable), candidate)
            .await
            .status,
        CaptureStatus::Missing
    );
    assert_eq!(
        errors_with(&captured, "unable to capture svs sample"),
        Vec::<String>::new()
    );
}

/// test_capture.py's `test_a_file_that_no_longer_has_its_sha256_is_held_from_another_alert`.
#[tokio::test]
async fn a_file_that_no_longer_has_its_sha256_is_held_from_another_alert() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    assert_eq!(
        capture_one(db, &bucket, root, Some(observable), candidate.clone())
            .await
            .status,
        CaptureStatus::Stored
    );
    // another alert names the same sha256, but the root's copy has other bytes now
    rewrite_root_copy(&bucket, &sha256).await;
    let (other, other_observable) = alert_with_file(db, &sha256).await;
    let result = capture_one(db, &bucket, other, Some(other_observable), candidate).await;
    assert_eq!(result.status, CaptureStatus::Stored);
    assert!(
        sample_holds(db, &sha256)
            .await
            .contains(&hold_of(result.capture.expect("a row")))
    );
}

/// test_capture.py's `test_a_capture_without_its_record_keeps_the_file`.
#[tokio::test]
async fn a_capture_without_its_record_keeps_the_file() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let (captured, _logs) = log_capture();

    let result = capture_one(
        db,
        &bucket,
        root,
        Some(observable),
        svs_candidate(&sha256, "mail/a.txt", false, SVS_COMMIT),
    )
    .await;

    assert_eq!(result.status, CaptureStatus::Stored);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(
        (row.state.as_str(), row.missing_reason.as_deref()),
        ("stored", Some("match_record"))
    );
    assert_eq!(row.record, None);
    assert_eq!(sample_holds(db, &sha256).await, [hold_of(row.id)]);
    let [line] = errors_with(&captured, "without its match record")
        .try_into()
        .expect("reported");
    assert!(line.contains("missing_reason=\"match_record\""), "{line}");

    // a later pass that has the record adds it
    let again = capture_one(
        db,
        &bucket,
        root,
        Some(observable),
        svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT),
    )
    .await;
    assert_eq!(again.status, CaptureStatus::Stored);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(row.missing_reason, None);
    assert!(row.record.is_some());
    assert_eq!(sample_holds(db, &sha256).await, [hold_of(row.id)]);
}

/// test_capture.py's `test_a_storage_failure_releases_the_holds_and_is_retried`: the bucket is down when
/// the bytes go in. The record is the row's here, so it can't fail apart from the file.
#[tokio::test]
async fn a_storage_failure_releases_the_holds_and_is_retried() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (broken, _broken_cache) = broken_bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let (captured, _logs) = log_capture();

    let prepared =
        svs_samples::prepare(db, &bucket, root, Some(observable), vec![candidate.clone()])
            .await
            .expect("prepares");
    let mut tx = db.begin().await.expect("begins");
    let [result] = svs_samples::land(&mut tx, &broken, &prepared)
        .await
        .expect("lands")
        .try_into()
        .expect("one result");
    tx.commit().await.expect("commits");

    assert_eq!(result.status, CaptureStatus::Missing);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!(
        (row.state.as_str(), row.missing_reason.as_deref()),
        ("missing", Some("storage"))
    );
    assert_eq!(sample_holds(db, &sha256).await, []);
    let [line] = errors_with(&captured, "unable to store svs capture")
        .try_into()
        .expect("reported");
    assert!(line.contains("missing_reason=\"storage\""), "{line}");

    let again = capture_one(db, &bucket, root, Some(observable), candidate).await;
    assert_eq!(again.status, CaptureStatus::Stored);
    let [row] = capture_rows(db, &sha256).await.try_into().expect("one row");
    assert_eq!((row.state.as_str(), row.missing_reason), ("stored", None));
}

/// test_capture.py's `test_an_unknown_signature_version_is_reported`.
#[tokio::test]
async fn an_unknown_signature_version_is_reported() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, "unknown");
    let (captured, _logs) = log_capture();

    capture_one(db, &bucket, root, Some(observable), candidate.clone()).await;

    let [line] = errors_with(&captured, "unknown signature version")
        .try_into()
        .expect("reported");
    assert!(line.contains(&root.to_string()), "{line}");
    assert!(line.contains(&format!("sha256={sha256}")), "{line}");
    assert!(line.contains(&format!("rule_uuid={RULE_UUID}")), "{line}");

    // reported when it's stored, not on every pass
    clear(&captured);
    capture_one(db, &bucket, root, Some(observable), candidate).await;
    assert_eq!(
        errors_with(&captured, "unknown signature version"),
        Vec::<String>::new()
    );
}

// ---- actions ----

/// test_actions.py's `test_relabel_writes_an_explicit_verdict_on_every_contributing_detection`.
#[tokio::test]
async fn relabel_writes_an_explicit_verdict_on_every_contributing_detection() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let content = format!("svs relabel sample {}", Uuid::new_v4()).into_bytes();
    let (_, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    assert_eq!(
        label_of(db, sha256, RULE_UUID).await,
        (Some(Label::Tp), Some(Strength::InheritedSingle))
    );

    let change = service(db)
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");

    assert_eq!(
        (change.changed, change.unchanged, change.skipped),
        (2, 0, vec![])
    );
    assert_eq!(
        (change.label, change.label_source),
        (Some(Label::Fp), Some(Strength::Explicit))
    );
    assert_eq!(
        sample_of(db, sha256, RULE_UUID)
            .await
            .expect("a sample")
            .votes
            .fp_explicit,
        2
    );
    // the other rule's sample of the same file is untouched
    assert_eq!(
        label_of(db, sha256, OTHER_RULE_UUID).await,
        (Some(Label::Tp), Some(Strength::InheritedMulti))
    );
    // again: nothing to change
    let change = service(db)
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
    assert_eq!((change.changed, change.unchanged), (0, 2));
}

/// test_actions.py's `test_relabel_skips_the_detections_on_a_false_positive_alert`.
#[tokio::test]
async fn relabel_skips_the_detections_on_a_false_positive_alert() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let content = format!("svs relabel across classes {}", Uuid::new_v4()).into_bytes();
    let (fp_alert, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    assert_eq!(
        label_of(db, sha256, RULE_UUID).await,
        (Some(Label::Conflicted), Some(Strength::InheritedSingle))
    );

    let change = service(db)
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Tp)
        .await
        .expect("relabels");

    assert_eq!(change.changed, 1);
    let [skipped] = change.skipped.as_slice() else {
        panic!("one skipped: {:?}", change.skipped);
    };
    assert_eq!(skipped.alert, fp_alert);
    assert!(
        skipped.reason.contains("correct its disposition"),
        "{}",
        skipped.reason
    );
    // the explicit vote outweighs the FP alert's inherited one
    assert_eq!(
        (change.label, change.label_source),
        (Some(Label::Tp), Some(Strength::Explicit))
    );
}

/// test_actions.py's `test_relabel_with_nothing_writable_is_refused`.
#[tokio::test]
async fn relabel_with_nothing_writable_is_refused() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (_, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID])],
        &[],
        true,
    )
    .await;
    let why = conflict(
        service(db)
            .relabel_svs_sample(&actor, &files["a.bin"], RULE_UUID, Verdict::Tp)
            .await,
    );
    assert!(why.contains("correct its disposition"), "{why}");
    assert_eq!(
        label_of(db, &files["a.bin"], RULE_UUID).await,
        (Some(Label::Fp), Some(Strength::InheritedSingle))
    );
}

/// test_actions.py's `test_relabel_skips_alerts_whose_disposition_only_ace_sets`.
#[tokio::test]
async fn relabel_skips_alerts_whose_disposition_only_ace_sets() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (_, files) =
        graded_alert(db, Some("SIMULATED"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let why = conflict(
        service(db)
            .relabel_svs_sample(&actor, &files["a.bin"], RULE_UUID, Verdict::Fp)
            .await,
    );
    assert!(why.contains("set by ACE"), "{why}");
}

/// test_actions.py's `test_relabel_of_a_sample_whose_alerts_are_gone_is_refused`.
#[tokio::test]
async fn relabel_of_a_sample_whose_alerts_are_gone_is_refused() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (root, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deletes the alert");
    let why = conflict(
        service(db)
            .relabel_svs_sample(&actor, &files["a.bin"], RULE_UUID, Verdict::Fp)
            .await,
    );
    assert!(why.contains("deleted"), "{why}");
}

fn not_found<T: std::fmt::Debug>(result: Result<T, ServiceError>) -> String {
    match result {
        Err(ServiceError::NotFound(why)) => why,
        other => panic!("not a NotFound: {other:?}"),
    }
}

/// test_actions.py's `test_an_unknown_sample`.
#[tokio::test]
async fn an_unknown_sample() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let sha256 = "ab".repeat(32);
    not_found(
        service(db)
            .relabel_svs_sample(&actor, &sha256, RULE_UUID, Verdict::Fp)
            .await,
    );
    not_found(
        service(db)
            .confirm_svs_sample(&actor, &sha256, RULE_UUID)
            .await,
    );
}

/// test_actions.py's `test_reset_clears_the_explicit_verdicts`.
#[tokio::test]
async fn reset_clears_the_explicit_verdicts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sha256 = &files["a.bin"];
    service
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");

    let change = service
        .reset_svs_sample_label(&actor, sha256, RULE_UUID)
        .await
        .expect("resets");
    assert_eq!(change.changed, 1);
    assert_eq!(
        (change.label, change.label_source),
        (Some(Label::Tp), Some(Strength::InheritedSingle))
    );
    // again: nothing to reset, which isn't an error
    let change = service
        .reset_svs_sample_label(&actor, sha256, RULE_UUID)
        .await
        .expect("resets");
    assert_eq!(
        (change.changed, change.unchanged, change.skipped),
        (0, 0, vec![])
    );
}

/// test_actions.py's `test_reset_leaves_out_the_detections_on_a_false_positive_alert`.
#[tokio::test]
async fn reset_leaves_out_the_detections_on_a_false_positive_alert() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let content = format!("svs reset across classes {}", Uuid::new_v4()).into_bytes();
    let (_, files) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID])],
        &[("a.bin", &content)],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    service
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Tp)
        .await
        .expect("relabels");

    let change = service
        .reset_svs_sample_label(&actor, sha256, RULE_UUID)
        .await
        .expect("resets");
    // the FP alert's detection had nothing to clear, so it isn't listed as skipped
    assert_eq!((change.changed, change.skipped), (1, vec![]));
    assert_eq!(
        (change.label, change.label_source),
        (Some(Label::Conflicted), Some(Strength::InheritedSingle))
    );
}

/// test_actions.py's `test_confirm_upgrades_only_the_unconfirmed_detections`.
#[tokio::test]
async fn confirm_upgrades_only_the_unconfirmed_detections() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    assert_eq!(
        label_of(db, sha256, RULE_UUID).await,
        (Some(Label::Tp), Some(Strength::InheritedMulti))
    );

    let change = service
        .confirm_svs_sample(&actor, sha256, RULE_UUID)
        .await
        .expect("confirms");
    assert_eq!(change.changed, 1);
    assert_eq!(
        (change.label, change.label_source),
        (Some(Label::Tp), Some(Strength::Explicit))
    );
    assert_eq!(
        label_of(db, sha256, OTHER_RULE_UUID).await,
        (Some(Label::Tp), Some(Strength::InheritedMulti))
    );
    // nothing left to confirm isn't an error
    assert_eq!(
        service
            .confirm_svs_sample(&actor, sha256, RULE_UUID)
            .await
            .expect("confirms")
            .changed,
        0
    );
}

/// test_actions.py's `test_confirm_leaves_an_fp_override_alone`.
#[tokio::test]
async fn confirm_leaves_an_fp_override_alone() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let sha256 = &files["a.bin"];
    service
        .relabel_svs_sample(&actor, sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
    assert_eq!(
        service
            .confirm_svs_sample(&actor, sha256, RULE_UUID)
            .await
            .expect("confirms")
            .changed,
        0
    );
    assert_eq!(
        label_of(db, sha256, RULE_UUID).await,
        (Some(Label::Fp), Some(Strength::Explicit))
    );
}

/// test_actions.py's `test_retire_and_unretire`.
#[tokio::test]
async fn retire_and_unretire() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sha256 = &files["a.bin"];
    assert!(
        !sample_of(db, sha256, RULE_UUID)
            .await
            .expect("a sample")
            .retired
    );

    let row = service
        .retire_svs_sample(
            &actor,
            sha256,
            RULE_UUID,
            "  the rule no longer targets this family  ",
        )
        .await
        .expect("retires");
    assert_eq!(row.reason, "the rule no longer targets this family");
    let sample = sample_of(db, sha256, RULE_UUID).await.expect("a sample");
    assert!(sample.retired);
    assert_eq!(
        sample.retired_by.map(|by| by.name),
        Some(Some("alice".to_owned()))
    );
    assert_eq!(
        sample.retired_reason.as_deref(),
        Some("the rule no longer targets this family")
    );
    assert_eq!(
        service.svs_retired_pairs(&actor).await.expect("reads"),
        [(sha256.clone(), RULE_UUID.to_owned())]
    );

    // retiring a retired sample keeps the first reason
    service
        .retire_svs_sample(&actor, sha256, RULE_UUID, "another reason")
        .await
        .expect("retires");
    assert_eq!(
        sample_of(db, sha256, RULE_UUID)
            .await
            .expect("a sample")
            .retired_reason
            .as_deref(),
        Some("the rule no longer targets this family")
    );

    let row = service
        .unretire_svs_sample(&actor, sha256, RULE_UUID)
        .await
        .expect("unretires");
    assert!(row.unretired_at.is_some() && !row.retired);
    assert!(
        !sample_of(db, sha256, RULE_UUID)
            .await
            .expect("a sample")
            .retired
    );
    assert_eq!(service.svs_retired_pairs(&actor).await.expect("reads"), []);
    not_found(service.unretire_svs_sample(&actor, sha256, RULE_UUID).await);

    // the row is reused, so there's one per pair
    service
        .retire_svs_sample(&actor, sha256, RULE_UUID, "retired again")
        .await
        .expect("retires");
    assert_eq!(
        sample_of(db, sha256, RULE_UUID)
            .await
            .expect("a sample")
            .retired_reason
            .as_deref(),
        Some("retired again")
    );
    let rows: Vec<(Option<chrono::DateTime<chrono::Utc>>,)> =
        sqlx::query_as("SELECT unretired_at FROM svs.sample_retirements")
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(rows, [(None,)]);
}

/// test_actions.py's `test_retire_needs_a_reason_and_a_sample`.
#[tokio::test]
async fn retire_needs_a_reason_and_a_sample() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sha256 = &files["a.bin"];
    assert!(matches!(
        service
            .retire_svs_sample(&actor, sha256, RULE_UUID, "   ")
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    not_found(
        service
            .retire_svs_sample(&actor, sha256, OTHER_RULE_UUID, "no such sample")
            .await,
    );
    not_found(service.unretire_svs_sample(&actor, sha256, RULE_UUID).await);
}

/// test_actions.py's `test_retirements_are_seen_by_changed_since`.
#[tokio::test]
async fn retirements_are_seen_by_changed_since() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (_, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sha256 = files["a.bin"].clone();
    let changed = |since: chrono::DateTime<chrono::Utc>| {
        let sha256 = sha256.clone();
        async move {
            let query = SampleQuery {
                changed_since: Some(since),
                filters: vec![FilterEntry::text("SHA256", false, &[&sha256])],
                ..SampleQuery::default()
            };
            !all_samples(db, &query).await.is_empty()
        }
    };
    // nothing else about the sample changed lately
    // the triggers set updated_at on every change, so a row is aged with its trigger off
    sqlx::raw_sql(
        "ALTER TABLE svs.yara_captures DISABLE TRIGGER yara_captures_touch;
         UPDATE svs.yara_captures SET updated_at = '2020-01-01';
         ALTER TABLE svs.yara_captures ENABLE TRIGGER yara_captures_touch;
         UPDATE analysis.roots SET dispositioned_at = '2020-01-01';",
    )
    .execute(db.pool())
    .await
    .expect("ages it");
    let since = chrono::Utc::now() - chrono::Duration::minutes(1);
    assert!(!changed(since).await);

    service
        .retire_svs_sample(&actor, &sha256, RULE_UUID, "retired")
        .await
        .expect("retires");
    assert!(changed(since).await);
    sqlx::raw_sql(
        "ALTER TABLE svs.sample_retirements DISABLE TRIGGER sample_retirements_touch;
         UPDATE svs.sample_retirements SET updated_at = '2020-01-01';
         ALTER TABLE svs.sample_retirements ENABLE TRIGGER sample_retirements_touch;",
    )
    .execute(db.pool())
    .await
    .expect("ages it");
    assert!(!changed(since).await);
    service
        .unretire_svs_sample(&actor, &sha256, RULE_UUID)
        .await
        .expect("unretires");
    assert!(changed(since).await);
}

/// A file captured for each rule, its bytes in the pool held by each capture as capture holds them, as
/// ace3's `_stored_sample`. Returns its sha256.
async fn stored_sample(db: &Db, bucket: &Bucket, rules: &[&str], content: &[u8]) -> String {
    let (root, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", rules)],
        &[("a.bin", content)],
        true,
    )
    .await;
    let sha256 = files["a.bin"].clone();
    let spooled = bucket.store().spool_bytes(content).await.expect("spools");
    for row in capture_rows(db, &sha256).await {
        if row.root_id != root {
            continue;
        }
        let mut tx = db.begin().await.expect("begins");
        bucket
            .put_in(&mut tx, SVS_SAMPLES, &spooled, Some(&capture_hold(row.id)))
            .await
            .expect("puts");
        tx.commit().await.expect("commits");
    }
    sha256
}

async fn pool_has(bucket: &Bucket, sha256: &str) -> bool {
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    bucket
        .object(SVS_SAMPLES, &parsed)
        .await
        .expect("reads")
        .is_some()
}

/// test_actions.py's `test_delete_removes_the_file_from_svs`.
#[tokio::test]
async fn delete_removes_the_file_from_svs() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let content = format!("svs delete sample {}", Uuid::new_v4()).into_bytes();
    let sha256 = stored_sample(db, &bucket, &[RULE_UUID, OTHER_RULE_UUID], &content).await;
    service
        .retire_svs_sample(&actor, &sha256, RULE_UUID, "retired")
        .await
        .expect("retires");
    let other_content = format!("another svs sample {}", Uuid::new_v4()).into_bytes();
    let other = stored_sample(db, &bucket, &[RULE_UUID], &other_content).await;

    let deletion = service
        .delete_svs_sample(&actor, &bucket, &sha256, "legal request 42")
        .await
        .expect("deletes");

    assert_eq!(deletion.sha256, sha256);
    let mut rules = vec![RULE_UUID.to_owned(), OTHER_RULE_UUID.to_owned()];
    rules.sort();
    assert_eq!(deletion.rule_uuids, rules);
    assert_eq!(deletion.capture_count, 2);
    assert_eq!(deletion.reason, "legal request 42");
    assert!(deletion.purged_at.is_some());
    assert_eq!(capture_rows(db, &sha256).await.len(), 0);
    let retired: i64 =
        sqlx::query_scalar("SELECT count(*) FROM svs.sample_retirements WHERE sha256 = $1")
            .bind(&sha256)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(retired, 0);
    // the file is purged, and the bucket has no key for it
    assert!(!pool_has(&bucket, &sha256).await);
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    assert!(
        !bucket
            .store()
            .exists(SVS_SAMPLES, &parsed)
            .await
            .expect("asks")
    );
    // the deletion's audit row is the purge's record
    let row = last_audit(db).await;
    assert_eq!(row.action, "delete_svs_sample");
    // nothing else is touched
    assert_eq!(capture_rows(db, &other).await.len(), 1);
    assert!(pool_has(&bucket, &other).await);

    // deleting again returns the first deletion's row
    assert_eq!(
        service
            .delete_svs_sample(&actor, &bucket, &sha256, "again")
            .await
            .expect("deletes")
            .reason,
        "legal request 42"
    );
}

/// test_actions.py's `test_a_match_record_another_capture_holds_is_kept`. A record is its capture's row
/// here, so another sample of the same record keeps its row, its record and its hold on its own file.
#[tokio::test]
async fn another_sample_keeps_its_record_and_its_hold() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let one = format!("svs delete one {}", Uuid::new_v4()).into_bytes();
    let keep = format!("svs keep the other {}", Uuid::new_v4()).into_bytes();
    let sha256 = stored_sample(db, &bucket, &[RULE_UUID], &one).await;
    let other = stored_sample(db, &bucket, &[RULE_UUID], &keep).await;
    let [kept] = capture_rows(db, &other).await.try_into().expect("one row");

    service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "privacy")
        .await
        .expect("deletes");

    let [still] = capture_rows(db, &other).await.try_into().expect("one row");
    assert_eq!(still.record, kept.record);
    assert_eq!(sample_holds(db, &other).await, [hold_of(kept.id)]);
}

/// test_actions.py's `test_an_unfinished_purge_is_retried`: the bucket is down when the bytes go.
#[tokio::test]
async fn an_unfinished_purge_is_retried() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let (broken, _broken_cache) = broken_bucket(db);
    let content = format!("svs purge fails {}", Uuid::new_v4()).into_bytes();
    let sha256 = stored_sample(db, &bucket, &[RULE_UUID], &content).await;
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");

    let deletion = service
        .delete_svs_sample(&actor, &broken, &sha256, "privacy")
        .await
        .expect("deletes");
    assert_eq!(deletion.purged_at, None);
    assert_eq!(capture_rows(db, &sha256).await.len(), 0);
    assert!(
        bucket
            .store()
            .exists(SVS_SAMPLES, &parsed)
            .await
            .expect("asks")
    );

    let deletion = service
        .delete_svs_sample(&actor, &bucket, &sha256, "a second reason")
        .await
        .expect("deletes");
    assert!(deletion.purged_at.is_some());
    assert_eq!(deletion.reason, "privacy");
    assert!(
        !bucket
            .store()
            .exists(SVS_SAMPLES, &parsed)
            .await
            .expect("asks")
    );
    assert!(!pool_has(&bucket, &sha256).await);
}

/// test_actions.py's `test_delete_needs_a_reason_and_a_sample`.
#[tokio::test]
async fn delete_needs_a_reason_and_a_sample() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let sha256 = "ab".repeat(32);
    assert!(matches!(
        service(db)
            .delete_svs_sample(&actor, &bucket, &sha256, " ")
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    not_found(
        service(db)
            .delete_svs_sample(&actor, &bucket, &sha256, "privacy")
            .await,
    );
}

/// test_actions.py's `test_a_missing_capture_is_deleted_too`.
#[tokio::test]
async fn a_missing_capture_is_deleted_too() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let sha256 = "cd".repeat(32);
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow {
            state: "missing",
            missing_reason: Some("file"),
            ..CaptureRow::default()
        },
    )
    .await;
    let deletion = service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "privacy")
        .await
        .expect("deletes");
    assert_eq!(deletion.capture_count, 1);
    assert!(deletion.purged_at.is_some());
    assert_eq!(capture_rows(db, &sha256).await.len(), 0);
}

/// test_actions.py's `test_deletions_page`.
#[tokio::test]
async fn deletions_page() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    for name in ["first deleted", "second deleted", "third deleted"] {
        let content = format!("{name} {}", Uuid::new_v4()).into_bytes();
        let (_, files) = graded_alert(
            db,
            Some("DELIVERY"),
            &[("a.bin", &[RULE_UUID])],
            &[("a.bin", &content)],
            true,
        )
        .await;
        service
            .delete_svs_sample(&actor, &bucket, &files["a.bin"], "privacy")
            .await
            .expect("deletes");
    }
    let first = service
        .svs_sample_deletions(&actor, None, None, Some(2))
        .await
        .expect("pages");
    assert_eq!(first.len(), 2);
    let last = first.last().expect("a row");
    let rest = service
        .svs_sample_deletions(&actor, None, Some((last.updated_at, last.id)), Some(2))
        .await
        .expect("pages");
    assert_eq!(rest.len(), 1);
    let all: BTreeSet<String> = service
        .svs_sample_deletions(&actor, None, None, Some(10))
        .await
        .expect("pages")
        .into_iter()
        .map(|d| d.sha256)
        .collect();
    assert_eq!(
        first
            .iter()
            .chain(&rest)
            .map(|d| d.sha256.clone())
            .collect::<BTreeSet<_>>(),
        all
    );
    assert_eq!(
        service
            .svs_sample_deletions(
                &actor,
                Some(chrono::Utc::now() + chrono::Duration::days(1)),
                None,
                Some(10)
            )
            .await
            .expect("pages"),
        []
    );
}

/// test_actions.py's `test_a_deleted_file_is_not_captured_again`.
#[tokio::test]
async fn a_deleted_file_is_not_captured_again() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    assert_eq!(
        capture_one(db, &bucket, root, Some(observable), candidate.clone())
            .await
            .status,
        CaptureStatus::Stored
    );
    service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "privacy")
        .await
        .expect("deletes");

    let (other, other_observable) = alert_with_file(db, &sha256).await;
    let result = capture_one(db, &bucket, other, Some(other_observable), candidate).await;

    assert_eq!(
        (result.status, result.capture),
        (CaptureStatus::Deleted, None)
    );
    assert_eq!(capture_rows(db, &sha256).await.len(), 0);
    assert!(!pool_has(&bucket, &sha256).await);
}

/// test_actions.py's `test_a_capture_that_raced_a_deletion_removes_what_it_wrote`: the deletion commits
/// after the capture read the bytes and before it lands, so it writes nothing.
#[tokio::test]
async fn a_capture_that_raced_a_deletion_writes_nothing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let (root, observable, sha256) = captured_file(db, &bucket).await;
    // another capture of the file, so there's a sample to delete
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        RULE_UUID,
        CaptureRow::default(),
    )
    .await;
    let candidate = svs_candidate(&sha256, "mail/a.txt", true, SVS_COMMIT);
    let prepared = svs_samples::prepare(db, &bucket, root, Some(observable), vec![candidate])
        .await
        .expect("prepares");

    service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "privacy")
        .await
        .expect("deletes");
    let mut tx = db.begin().await.expect("begins");
    let [result] = svs_samples::land(&mut tx, &bucket, &prepared)
        .await
        .expect("lands")
        .try_into()
        .expect("one result");
    tx.commit().await.expect("commits");

    assert_eq!(result.status, CaptureStatus::Deleted);
    assert_eq!(capture_rows(db, &sha256).await.len(), 0);
    assert!(!pool_has(&bucket, &sha256).await);
}

// ---- the samples' audit rows ----

/// A DELIVERY alert's sample of two rules, and the detection of `RULE_UUID` on its file.
async fn audited_sample(db: &Db) -> (Uuid, String, i64) {
    let (root, files) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("a.bin", &[RULE_UUID, OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let sha256 = files["a.bin"].clone();
    let detection = detection_of(db, root, &sha256, RULE_UUID).await;
    (root, sha256, detection)
}

fn sample_states(root: Uuid, detection: i64, verdict: Value) -> Value {
    json!({"verdicts": [{
        "detection": detection, "alert": root, "signature_uuid": RULE_UUID, "verdict": verdict,
    }]})
}

async fn relabel_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (root, sha256, detection) = audited_sample(db).await;
    service(db)
        .relabel_svs_sample(&actor, &sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "relabel_svs_sample".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: Some(sample_states(root, detection, Value::Null)),
            after: Some(sample_states(root, detection, json!("fp"))),
            details: json!({
                "action": "relabel", "verdict": "fp", "changed": 1, "unchanged": 0, "skipped": 0,
                "detections": [detection],
            }),
        }
    );
    // again changes nothing, and has no row
    let rows = audit_rows(db).await.len();
    service(db)
        .relabel_svs_sample(&actor, &sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn reset_svs_sample_label_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (root, sha256, detection) = audited_sample(db).await;
    service(db)
        .relabel_svs_sample(&actor, &sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
    service(db)
        .reset_svs_sample_label(&actor, &sha256, RULE_UUID)
        .await
        .expect("resets");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "reset_svs_sample_label".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: Some(sample_states(root, detection, json!("fp"))),
            after: Some(sample_states(root, detection, Value::Null)),
            details: json!({
                "action": "reset", "verdict": null, "changed": 1, "unchanged": 0, "skipped": 0,
                "detections": [detection],
            }),
        }
    );
    row.action
}

async fn confirm_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (root, sha256, detection) = audited_sample(db).await;
    service(db)
        .confirm_svs_sample(&actor, &sha256, RULE_UUID)
        .await
        .expect("confirms");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "confirm_svs_sample".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: Some(sample_states(root, detection, Value::Null)),
            after: Some(sample_states(root, detection, json!("tp"))),
            details: json!({
                "action": "confirm", "verdict": "tp", "changed": 1, "unchanged": 0, "skipped": 0,
                "detections": [detection],
            }),
        }
    );
    row.action
}

async fn retire_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (_, sha256, _) = audited_sample(db).await;
    service(db)
        .retire_svs_sample(&actor, &sha256, RULE_UUID, " a stale sample ")
        .await
        .expect("retires");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "retire_svs_sample".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: None,
            after: Some(json!({"retired": true, "reason": "a stale sample"})),
            details: json!({}),
        }
    );
    // retiring it again changes nothing, and has no row
    let rows = audit_rows(db).await.len();
    service(db)
        .retire_svs_sample(&actor, &sha256, RULE_UUID, "again")
        .await
        .expect("retires");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn unretire_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (_, sha256, _) = audited_sample(db).await;
    service(db)
        .retire_svs_sample(&actor, &sha256, RULE_UUID, "stale")
        .await
        .expect("retires");
    service(db)
        .unretire_svs_sample(&actor, &sha256, RULE_UUID)
        .await
        .expect("unretires");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "unretire_svs_sample".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: Some(json!({"retired": true, "reason": "stale"})),
            after: Some(json!({"retired": false, "reason": "stale"})),
            details: json!({}),
        }
    );
    row.action
}

async fn delete_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (bucket, _cache) = bucket(db);
    let (_, sha256, _) = audited_sample(db).await;
    let ids: Vec<i64> = capture_rows(db, &sha256)
        .await
        .iter()
        .map(|r| r.id)
        .collect();
    service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "legal request 7")
        .await
        .expect("deletes");
    let row = last_audit(db).await;
    let mut rules = vec![RULE_UUID, OTHER_RULE_UUID];
    rules.sort_unstable();
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "delete_svs_sample".to_owned(),
            target: ("svs_sample_file".to_owned(), sha256.clone()),
            before: Some(json!({
                "reason": "legal request 7", "rule_uuids": rules, "capture_count": 2,
                "captures": ids,
            })),
            after: None,
            details: json!({}),
        }
    );
    // deleting it again only retries the purge, and has no row
    let rows = audit_rows(db).await.len();
    service(db)
        .delete_svs_sample(&actor, &bucket, &sha256, "again")
        .await
        .expect("deletes");
    assert_eq!(audit_rows(db).await.len(), rows);
    row.action
}

async fn download_svs_sample_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (_, sha256, _) = audited_sample(db).await;
    let download = service(db)
        .download_svs_sample(&actor, &sha256, RULE_UUID)
        .await
        .expect("downloads");
    assert_eq!(download.files.len(), 1);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_svs_sample".to_owned(),
            target: ("svs_sample".to_owned(), format!("{sha256}/{RULE_UUID}")),
            before: None,
            after: None,
            details: json!({"filters": null, "rule_uuid": RULE_UUID, "sha256s": [sha256]}),
        }
    );
    row.action
}

async fn download_svs_samples_records_its_row(db: &Db) -> String {
    let actor = admin(db).await;
    let (_, sha256, _) = audited_sample(db).await;
    let query = SampleQuery {
        filters: vec![FilterEntry::text("SHA256", false, &[&sha256])],
        ..SampleQuery::default()
    };
    let download = service(db)
        .download_svs_samples(&actor, &query)
        .await
        .expect("downloads");
    // the file once, whatever the number of rules it matched
    let [file] = download.files.as_slice() else {
        panic!("one file: {download:?}");
    };
    assert_eq!(file.rule_uuids.len(), 2);
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_svs_samples".to_owned(),
            target: ("svs_samples".to_owned(), "download".to_owned()),
            before: None,
            after: None,
            details: json!({
                "filters": [{"name": "SHA256", "inverted": false, "values": [sha256]}],
                "rule_uuid": null, "sha256s": [sha256],
            }),
        }
    );
    row.action
}

/// Every sample's captures, retirements and deletions, and the verdicts on detections, as text.
async fn sample_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'capture ' || row_to_json(c)::text FROM svs.yara_captures c
         UNION ALL SELECT 'retirement ' || row_to_json(r)::text FROM svs.sample_retirements r
         UNION ALL SELECT 'deletion ' || row_to_json(d)::text FROM svs.sample_deletions d
         UNION ALL SELECT 'verdict ' || row_to_json(v)::text FROM analysis.detection_verdicts v
         UNION ALL SELECT 'hold ' || row_to_json(h)::text FROM store.holds h WHERE h.pool = 'svs_samples'
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

fn denied<T: std::fmt::Debug>(result: Result<T, ServiceError>) -> String {
    match result {
        Err(ServiceError::PermissionDenied { permission, .. }) => permission.to_string(),
        other => panic!("not refused: {other:?}"),
    }
}

/// The samples' permissions, ace3's: `signature:read` reads them and isn't downloading
/// (`signature:download`); relabel, reset and confirm need `alert:write` and `signature:read`, and
/// retire and delete `svs:admin`. A refusal writes nothing and has no row.
#[tokio::test]
async fn sample_actions_follow_their_permissions() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let (bucket, _cache) = bucket(db);
    let (_, sha256, _) = audited_sample(db).await;
    let reader = holding(&service, db, "reader", &[("signature", "read")]).await;
    let writer = holding(&service, db, "writer", &[("alert", "write")]).await;
    let grader = holding(
        &service,
        db,
        "grader",
        &[("alert", "write"), ("signature", "read")],
    )
    .await;
    let rows = audit_rows(db).await.len();

    service
        .svs_sample(&reader, &sha256, RULE_UUID)
        .await
        .expect("reads");
    service
        .svs_samples(&reader, &SampleQuery::default(), None, None)
        .await
        .expect("lists");
    service.svs_missing(&reader).await.expect("reads");
    assert_eq!(
        denied(
            service
                .download_svs_sample(&reader, &sha256, RULE_UUID)
                .await
        ),
        "signature:download"
    );
    assert_eq!(
        denied(
            service
                .download_svs_samples(&reader, &SampleQuery::default())
                .await
        ),
        "signature:download"
    );
    assert_eq!(
        denied(
            service
                .relabel_svs_sample(&reader, &sha256, RULE_UUID, Verdict::Fp)
                .await
        ),
        "alert:write"
    );
    assert_eq!(
        denied(
            service
                .relabel_svs_sample(&writer, &sha256, RULE_UUID, Verdict::Fp)
                .await
        ),
        "signature:read"
    );
    assert_eq!(
        denied(
            service
                .reset_svs_sample_label(&writer, &sha256, RULE_UUID)
                .await
        ),
        "signature:read"
    );
    assert_eq!(
        denied(
            service
                .confirm_svs_sample(&writer, &sha256, RULE_UUID)
                .await
        ),
        "signature:read"
    );
    assert_eq!(
        denied(service.svs_sample(&writer, &sha256, RULE_UUID).await),
        "signature:read"
    );
    for actor in [&reader, &grader] {
        assert_eq!(
            denied(
                service
                    .retire_svs_sample(actor, &sha256, RULE_UUID, "stale")
                    .await
            ),
            "svs:admin"
        );
        assert_eq!(
            denied(service.unretire_svs_sample(actor, &sha256, RULE_UUID).await),
            "svs:admin"
        );
        assert_eq!(
            denied(
                service
                    .delete_svs_sample(actor, &bucket, &sha256, "privacy")
                    .await
            ),
            "svs:admin"
        );
    }
    assert_eq!(audit_rows(db).await.len(), rows, "no refusal has a row");
    service
        .relabel_svs_sample(&grader, &sha256, RULE_UUID, Verdict::Fp)
        .await
        .expect("relabels");
}

/// A listing pages in every order without skipping or repeating a sample, a cursor belongs to its order,
/// and a sample captured again between pages is neither skipped nor repeated: ace3's API cases of
/// `TestPaging`.
#[tokio::test]
async fn every_sort_pages_without_skip_or_repeat() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = service(db);
    let actor = admin(db).await;
    let mut expected = BTreeSet::new();
    for (index, disposition) in ["DELIVERY", "FALSE_POSITIVE", "REVIEWED", "DELIVERY"]
        .into_iter()
        .enumerate()
    {
        let rules: &[&str] = if index % 2 == 0 {
            &[RULE_UUID, OTHER_RULE_UUID]
        } else {
            &[RULE_UUID]
        };
        let (_, files) = graded_alert(db, Some(disposition), &[("a.bin", rules)], &[], true).await;
        for rule in rules {
            expected.insert((files["a.bin"].clone(), (*rule).to_owned()));
        }
    }
    for sort in SampleSort::ALL {
        for descending in [false, true] {
            let query = SampleQuery {
                sort,
                descending,
                ..SampleQuery::default()
            };
            let seen: Vec<(String, String)> = all_samples(db, &query)
                .await
                .into_iter()
                .map(|s| (s.sha256, s.rule_uuid))
                .collect();
            assert_eq!(seen.len(), expected.len(), "{sort:?} {descending}");
            assert_eq!(
                seen.iter().cloned().collect::<BTreeSet<_>>(),
                expected,
                "{sort:?} {descending}"
            );
        }
    }
    // a cursor belongs to its order
    let first = service
        .svs_samples(&actor, &SampleQuery::default(), None, Some(2))
        .await
        .expect("lists");
    let cursor = first.next.expect("more");
    let other = SampleQuery {
        sort: SampleSort::Rule,
        ..SampleQuery::default()
    };
    assert!(matches!(
        service
            .svs_samples(&actor, &other, Some(&cursor), Some(2))
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    assert!(matches!(
        service
            .svs_samples(
                &actor,
                &SampleQuery::default(),
                Some("not a cursor"),
                Some(2)
            )
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    // a sample captured again between pages: newest first, so the first page's samples would move
    let listed: Vec<ace_service::Sample> = first.samples;
    insert_capture(
        db,
        Uuid::new_v4(),
        &listed[0].sha256,
        &listed[0].rule_uuid,
        CaptureRow::default(),
    )
    .await;
    let mut seen: Vec<(String, String)> = listed
        .iter()
        .map(|s| (s.sha256.clone(), s.rule_uuid.clone()))
        .collect();
    let mut next = Some(cursor);
    while let Some(cursor) = next {
        let page = service
            .svs_samples(&actor, &SampleQuery::default(), Some(&cursor), Some(2))
            .await
            .expect("lists");
        seen.extend(page.samples.into_iter().map(|s| (s.sha256, s.rule_uuid)));
        next = page.next;
    }
    assert_eq!(seen.len(), expected.len());
    assert_eq!(seen.into_iter().collect::<BTreeSet<_>>(), expected);
}

/// The samples screen's filters, ace3's `TestFilters`: each one, inverted, and the ones over captures.
#[tokio::test]
async fn sample_filters_match_what_they_say() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let (fp_alert, fp) = graded_alert(
        db,
        Some("FALSE_POSITIVE"),
        &[("fp.bin", &[RULE_UUID])],
        &[],
        true,
    )
    .await;
    let (_, tp) = graded_alert(
        db,
        Some("DELIVERY"),
        &[("dir/tp.doc", &[OTHER_RULE_UUID])],
        &[],
        true,
    )
    .await;
    let (_, open) = graded_alert(db, None, &[("open.exe", &[RULE_UUID])], &[], true).await;
    insert_capture(
        db,
        Uuid::new_v4(),
        &open["open.exe"],
        RULE_UUID,
        CaptureRow {
            state: "missing",
            missing_reason: Some("file"),
            signature_version: "unknown",
            file_path: "open.exe",
            ..CaptureRow::default()
        },
    )
    .await;
    service(db)
        .retire_svs_sample(&actor, &tp["dir/tp.doc"], OTHER_RULE_UUID, "stale")
        .await
        .expect("retires");
    let names = |filters: Vec<FilterEntry>| async move {
        let query = SampleQuery {
            filters,
            sort: SampleSort::Sha256,
            descending: false,
            ..SampleQuery::default()
        };
        all_samples(db, &query)
            .await
            .into_iter()
            .map(|s| s.file_path)
            .collect::<BTreeSet<_>>()
    };
    let set = |names: &[&str]| {
        names
            .iter()
            .map(|n| (*n).to_owned())
            .collect::<BTreeSet<_>>()
    };
    let f = FilterEntry::text;
    assert_eq!(
        names(vec![f("Label", false, &["fp"])]).await,
        set(&["fp.bin"])
    );
    assert_eq!(
        names(vec![f("Label", false, &["none"])]).await,
        set(&["open.exe"])
    );
    assert_eq!(
        names(vec![f("Label", true, &["none"])]).await,
        set(&["fp.bin", "dir/tp.doc"])
    );
    assert_eq!(
        names(vec![f("Label Source", false, &["inherited_single"])]).await,
        set(&["fp.bin", "dir/tp.doc"])
    );
    assert_eq!(
        names(vec![f("Signature", false, &[OTHER_RULE_UUID])]).await,
        set(&["dir/tp.doc"])
    );
    assert_eq!(
        names(vec![f("Signature", true, &[OTHER_RULE_UUID])]).await,
        set(&["fp.bin", "open.exe"])
    );
    assert_eq!(
        names(vec![f("SHA256", false, &[&fp["fp.bin"].to_uppercase()])]).await,
        set(&["fp.bin"])
    );
    assert_eq!(
        names(vec![f("Alert", false, &[&fp_alert.to_string()])]).await,
        set(&["fp.bin"])
    );
    assert_eq!(
        names(vec![f("File Name", false, &["TP.d"])]).await,
        set(&["dir/tp.doc"])
    );
    assert_eq!(
        names(vec![f("Rule", false, &["SVS_RULE"])]).await,
        set(&["fp.bin", "dir/tp.doc", "open.exe"])
    );
    assert_eq!(
        names(vec![f("Retired", false, &["true"])]).await,
        set(&["dir/tp.doc"])
    );
    assert_eq!(
        names(vec![f("Retired", true, &["true"])]).await,
        set(&["fp.bin", "open.exe"])
    );
    assert_eq!(
        names(vec![f("Retired", false, &["true", "false"])])
            .await
            .len(),
        3
    );
    assert_eq!(
        names(vec![f("Retired", true, &["true", "false"])]).await,
        set(&[])
    );
    assert_eq!(
        names(vec![f("Missing Data", false, &["true"])]).await,
        set(&["open.exe"])
    );
    assert_eq!(
        names(vec![f("Unknown Version", false, &["true"])]).await,
        set(&["open.exe"])
    );
    assert_eq!(names(vec![f("Stored", false, &["false"])]).await, set(&[]));
    assert_eq!(
        names(vec![f("Last Captured", false, &["-7d"])]).await.len(),
        3
    );
    assert_eq!(
        names(vec![f("Last Captured", true, &["-7d"])]).await,
        set(&[])
    );
    for bad in [
        f("SHA256", false, &["not a sha"]),
        f("Signature", false, &["has space"]),
        f("Alert", false, &["not-a-uuid"]),
        f("Label", false, &["maybe"]),
        f("Last Captured", false, &["yesterday-ish"]),
        f("Nope", false, &["x"]),
    ] {
        let query = SampleQuery {
            filters: vec![bad.clone()],
            ..SampleQuery::default()
        };
        assert!(
            matches!(
                service(db).svs_samples(&actor, &query, None, None).await,
                Err(ServiceError::InvalidRequest(_))
            ),
            "{bad:?}"
        );
    }
}

// ---- PLAN.md 7.10 batch 3: YARA validation ----
//
// ace3's tests/saq/svs/yara/ cases that need the database, the bucket or a rule repository: the corpus
// (test_corpus.py), whole replays (test_replay.py), the queue (test_validations.py) and its workers
// (test_service.py), and test_config.py's lease and defaults. The pure ones are ace-core's and ace-yara's.

use ace_core::svs::validations as svs_queue;
use ace_core::svs::yara as svs_yara;
use ace_core::svs::yara::diff::{Category as ValidationCategory, Outcome as ValidationOutcome};
use ace_core::svs::yara::replay::{
    Child as ReplayChild, Replay, ReplayError, ReplayRequest, ReplayResult, Replayer,
};
use ace_core::testing::rule_repo::{RuleRepo, rule};
use ace_service::{ResultSelection, ValidationAsk, ValidationQuery};
use tokio_util::sync::CancellationToken;

const REPOSITORY: &str = "svs_rules";

fn validation_base() -> String {
    "a".repeat(40)
}

fn validation_head() -> String {
    "b".repeat(40)
}

/// ace3's `svs_repository`: a rule repository SVS may validate, its rules in its `yara` directory, and the
/// settings that name it, with a mirror and a work directory of their own.
struct SvsRepository {
    repo: RuleRepo,
    config: svs_yara::ValidationConfig,
    tmp: tempfile::TempDir,
}

fn svs_repository_with(change: impl FnOnce(&mut ace_sdk::SvsYaraSection)) -> SvsRepository {
    // the work directory has no '.' in its path
    let tmp = tempfile::Builder::new()
        .prefix("svsrepo")
        .tempdir_in("/tmp")
        .expect("a directory");
    let repo = RuleRepo::new(&tmp.path().join("repo"));
    let mut section = ace_sdk::SvsYaraSection {
        repositories: [(
            REPOSITORY.to_owned(),
            ace_sdk::SvsRepository {
                url: repo.origin.to_string_lossy().into_owned(),
                branch: "main".to_owned(),
                signature_dir: "yara".to_owned(),
                ssh_key: None,
            },
        )]
        .into(),
        mirror_dir: Some(tmp.path().join("mirrors")),
        work_dir: Some(tmp.path().join("work")),
        ..ace_sdk::SvsYaraSection::default()
    };
    change(&mut section);
    let config = svs_yara::ValidationConfig::from_section(&section).expect("valid settings");
    SvsRepository { repo, config, tmp }
}

fn svs_repository() -> SvsRepository {
    svs_repository_with(|_| {})
}

impl SvsRepository {
    fn work_dirs(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(self.tmp.path().join("work")) {
            Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn commit(&self, files: &[(&str, &str)], branch: &str) -> String {
        self.repo.commit(files, branch)
    }
}

fn classes() -> (Vec<String>, Vec<String>) {
    ace_service::Dispositions::ace3().classes().lists()
}

fn validating(db: &Db, repo: &SvsRepository) -> Service {
    service(db).with_validation(repo.config.clone())
}

fn replayer(db: &Db, bucket: &Bucket, repo: &SvsRepository) -> Replayer {
    let (tp, fp) = classes();
    Replayer {
        db: db.clone(),
        bucket: bucket.clone(),
        config: repo.config.clone(),
        tp,
        fp,
        child: ReplayChild::InProcess,
    }
}

fn workers(db: &Db, repo: &SvsRepository, replay: Arc<dyn Replay>) -> svs_queue::Workers {
    let (tp, fp) = classes();
    svs_queue::Workers {
        db: db.clone(),
        config: repo.config.clone(),
        replay,
        tp,
        fp,
        node: "node1".to_owned(),
    }
}

/// ace3's `stored_sample`: a file YARA matched for each of `rules` on an alert with this disposition,
/// captured as `name`, its bytes in the `svs_samples` pool held by each capture. Returns its sha256.
async fn sample_named(
    db: &Db,
    bucket: &Bucket,
    disposition: &str,
    content: &[u8],
    rules: &[&str],
    name: &'static str,
) -> String {
    let (_, files) = graded_alert(
        db,
        Some(disposition),
        &[(name, rules)],
        &[(name, content)],
        true,
    )
    .await;
    let sha256 = files[name].clone();
    put_held(db, bucket, content, &sha256).await;
    sha256
}

/// The bytes in the pool, held by every capture of their sha256 that holds nothing yet.
async fn put_held(db: &Db, bucket: &Bucket, content: &[u8], sha256: &str) {
    let spooled = bucket.store().spool_bytes(content).await.expect("spools");
    for row in capture_rows(db, sha256).await {
        let mut tx = db.begin().await.expect("begins");
        bucket
            .put_in(
                &mut tx,
                ace_core::svs::samples::SVS_SAMPLES,
                &spooled,
                Some(&ace_core::svs::samples::capture_hold(row.id)),
            )
            .await
            .expect("puts");
        tx.commit().await.expect("commits");
    }
}

fn ask(base: &str, head: &str) -> ValidationAsk {
    ValidationAsk {
        repository: REPOSITORY.to_owned(),
        base_sha: base.to_owned(),
        head_sha: head.to_owned(),
        branch: "feature".to_owned(),
        pr_url: Some("https://git.example/pr/1".to_owned()),
    }
}

async fn request_validation(db: &Db, repo: &SvsRepository, base: &str, head: &str) -> (Uuid, bool) {
    let (status, created) = validating(db, repo)
        .request_svs_validation(&admin(db).await, &ask(base, head))
        .await
        .expect("requests");
    (status.uuid, created)
}

#[derive(Debug, sqlx::FromRow)]
struct ValidationView {
    state: String,
    repository: String,
    branch: String,
    requested_by: Value,
    active_key: Option<String>,
    claim_token: Option<Uuid>,
    claimed_by: Option<String>,
    attempts: i32,
    error: Option<String>,
    corpus_version: Option<String>,
    engine_fingerprint: Option<String>,
    counts: Option<Value>,
    report: Option<Value>,
    regressions: Option<i32>,
    new_fps: Option<i32>,
    compile_errors: Option<i32>,
    diffed: Option<bool>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn validation_view(db: &Db, uuid: Uuid) -> ValidationView {
    sqlx::query_as(
        "SELECT state::text, repository, branch, requested_by::jsonb, active_key, claim_token, claimed_by,
                attempts, error, corpus_version, engine_fingerprint, counts, report, regressions,
                new_fps, compile_errors, diffed, finished_at
         FROM svs.validations WHERE uuid = $1",
    )
    .bind(uuid)
    .fetch_one(db.pool())
    .await
    .expect("reads the validation")
}

async fn result_rows(db: &Db) -> Vec<(String, String, String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT sha256, category, base, head, label FROM svs.validation_results ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

const LEASE: Duration = Duration::from_secs(300);

async fn claim_one(db: &Db, node: &str) -> Option<svs_queue::Claim> {
    svs_queue::claim(db, node, LEASE, 3).await.expect("claims")
}

/// Claims `uuid`, whatever else waits: it's made the oldest first.
async fn claim_this(db: &Db, uuid: Uuid) -> svs_queue::Claim {
    sqlx::query(
        "UPDATE svs.validations SET created_at = created_at - interval '100 years' WHERE uuid = $1",
    )
    .bind(uuid)
    .execute(db.pool())
    .await
    .expect("makes it the oldest");
    let claimed = claim_one(db, "node1").await.expect("a claim");
    assert_eq!(claimed.uuid, uuid);
    claimed
}

fn result_row(category: ValidationCategory, sha256: &str) -> svs_yara::diff::ResultRow {
    svs_yara::diff::ResultRow {
        sha256: sha256.to_owned(),
        rule_uuid: RULE_UUID.to_owned(),
        rule_name: "svs_rule".to_owned(),
        namespace: Some("acme".to_owned()),
        label: Some("tp".to_owned()),
        label_source: Some("inherited_single".to_owned()),
        base: ValidationOutcome::Match,
        head: ValidationOutcome::Miss,
        raw_base: true,
        raw_head: false,
        category,
        note: None,
    }
}

/// A replay result as the replay returns one, compared, with `rows`.
fn replay_result(
    rows: Vec<svs_yara::diff::ResultRow>,
    file_errors: Vec<svs_yara::replay::FileError>,
) -> ReplayResult {
    let mut result = ReplayResult::new(REPOSITORY, &validation_base(), &validation_head());
    let mut counts = BTreeMap::new();
    for row in &rows {
        *counts.entry(row.category).or_default() += 1;
    }
    result.counts = ReplayResult::all_counts(&counts);
    result.rows = rows;
    result.head.file_errors = file_errors;
    result.diffed = true;
    result
}

async fn complete_claimed(
    db: &Db,
    repo: &SvsRepository,
    uuid: Uuid,
    rows: Vec<svs_yara::diff::ResultRow>,
) {
    let claimed = claim_this(db, uuid).await;
    let (tp, fp) = classes();
    svs_queue::complete(
        db,
        &claimed,
        &replay_result(rows, vec![]),
        &svs_queue::corpus_version(db).await.expect("a version"),
        &svs_queue::engine_fingerprint(&repo.config, REPOSITORY, &tp, &fp).expect("a fingerprint"),
    )
    .await
    .expect("completes");
}

async fn expire_lease(db: &Db, uuid: Uuid) {
    sqlx::query(
        "UPDATE svs.validations SET heartbeat_at = now() - interval '1 hour' WHERE uuid = $1",
    )
    .bind(uuid)
    .execute(db.pool())
    .await
    .expect("expires it");
}

/// test_validations.py's `test_an_identical_request_shares_the_queued_validation`.
#[tokio::test]
async fn an_identical_request_shares_the_queued_validation() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, created) =
        request_validation(db, &repo, &validation_base(), &validation_head()).await;
    assert!(created);
    let row = validation_view(db, uuid).await;
    assert_eq!(
        (
            row.state.as_str(),
            row.repository.as_str(),
            row.branch.as_str(),
            &row.requested_by
        ),
        ("queued", REPOSITORY, "feature", &boss_json())
    );

    assert_eq!(
        request_validation(db, &repo, &validation_base(), &validation_head()).await,
        (uuid, false)
    );
    // an upper case id is the same commit
    assert_eq!(
        request_validation(
            db,
            &repo,
            &validation_base().to_uppercase(),
            &validation_head()
        )
        .await,
        (uuid, false)
    );
    assert!(
        request_validation(db, &repo, &validation_base(), &"c".repeat(40))
            .await
            .1
    );
    // the key every process shares: the sha256 of the JSON ["svs_rules", "a" * 40, "b" * 40]
    assert_eq!(
        row.active_key.as_deref(),
        Some("e59ce04f87ba60c144f48f4908d4ff0b8772decf7fc1cbc807136670b50d2a6b")
    );
}

/// test_validations.py's `test_a_completed_validation_answers_until_the_corpus_changes`.
#[tokio::test]
async fn a_completed_validation_answers_until_the_corpus_changes() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    complete_claimed(db, &repo, uuid, vec![]).await;
    assert_eq!(validation_view(db, uuid).await.active_key, None);

    assert_eq!(
        request_validation(db, &repo, &validation_base(), &validation_head()).await,
        (uuid, false)
    );

    // a new sample changes the corpus: the next request runs again
    graded_alert(
        db,
        Some("DELIVERY"),
        &[("new.bin", &[RULE_UUID])],
        &[],
        true,
    )
    .await;
    let (again, created) =
        request_validation(db, &repo, &validation_base(), &validation_head()).await;
    assert!(created && again != uuid);
}

/// test_validations.py's `test_a_failed_validation_is_never_reused`.
#[tokio::test]
async fn a_failed_validation_is_never_reused() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let claimed = claim_one(db, "node1").await.expect("a claim");
    assert!(
        svs_queue::fail(db, &claimed, "the scan failed")
            .await
            .expect("fails")
    );
    assert_eq!(validation_view(db, uuid).await.state, "failed");

    let (again, created) =
        request_validation(db, &repo, &validation_base(), &validation_head()).await;
    assert!(created && again != uuid);
}

/// test_validations.py's `test_concurrent_identical_requests_share_one_validation`: two requests at once
/// make one validation, the second answered with the first's.
#[tokio::test]
async fn concurrent_identical_requests_share_one_validation() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let actor = admin(db).await;
    let service = validating(db, &repo);
    let asked = ask(&validation_base(), &validation_head());
    let (first, second) = tokio::join!(
        service.request_svs_validation(&actor, &asked),
        service.request_svs_validation(&actor, &asked),
    );
    let (first, second) = (first.expect("requests"), second.expect("requests"));
    assert_eq!(first.0.uuid, second.0.uuid);
    assert_eq!(u8::from(first.1) + u8::from(second.1), 1, "one made it");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM svs.validations")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(count, 1);
}

/// test_validations.py's `test_the_corpus_version_follows_every_input`.
#[tokio::test]
async fn the_corpus_version_follows_every_input() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let actor = admin(db).await;
    let service = service(db);
    let (root, files) =
        graded_alert(db, Some("DELIVERY"), &[("a.bin", &[RULE_UUID])], &[], true).await;
    let sha256 = files["a.bin"].clone();
    let mut versions = vec![svs_queue::corpus_version(db).await.expect("a version")];
    async fn changed(db: &Db, versions: &mut Vec<String>, what: &str) {
        versions.push(svs_queue::corpus_version(db).await.expect("a version"));
        assert_ne!(
            versions[versions.len() - 1],
            versions[versions.len() - 2],
            "{what}"
        );
    }

    service
        .relabel_svs_sample(&actor, &sha256, RULE_UUID, ace_service::Verdict::Fp)
        .await
        .expect("relabels");
    changed(db, &mut versions, "a relabel").await;
    // clearing a verdict bumps no change time; the history's count catches it
    service
        .reset_svs_sample_label(&actor, &sha256, RULE_UUID)
        .await
        .expect("resets");
    changed(db, &mut versions, "a reset").await;
    service
        .retire_svs_sample(&actor, &sha256, RULE_UUID, "intended")
        .await
        .expect("retires");
    changed(db, &mut versions, "a retirement").await;
    set_disposition_row(db, root, Some("FALSE_POSITIVE")).await;
    changed(db, &mut versions, "a disposition").await;
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deletes the alert");
    changed(db, &mut versions, "a deleted alert").await;
    assert_eq!(
        &svs_queue::corpus_version(db).await.expect("a version"),
        versions.last().unwrap()
    );
}

/// test_validations.py's `test_the_engine_fingerprint_follows_the_disposition_classification`.
#[test]
fn the_engine_fingerprint_follows_the_disposition_classification() {
    let repo = svs_repository();
    let (tp, mut fp) = classes();
    let fingerprint =
        svs_queue::engine_fingerprint(&repo.config, REPOSITORY, &tp, &fp).expect("a fingerprint");
    assert_eq!(
        svs_queue::engine_fingerprint(&repo.config, REPOSITORY, &tp, &fp).unwrap(),
        fingerprint
    );
    fp.push("REVIEWED".to_owned());
    assert_ne!(
        svs_queue::engine_fingerprint(&repo.config, REPOSITORY, &tp, &fp).unwrap(),
        fingerprint
    );
    assert!(svs_queue::engine_fingerprint(&repo.config, "elsewhere", &tp, &fp).is_err());
}

/// test_validations.py's `test_only_one_worker_claims_a_validation`: claims racing for one validation, one
/// wins.
#[tokio::test]
async fn only_one_worker_claims_a_validation() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let claims = futures_join_all(db, 8).await;
    let won: Vec<&svs_queue::Claim> = claims.iter().flatten().collect();
    let [first] = won[..] else {
        panic!("one claim wins: {claims:?}")
    };
    assert_eq!((first.uuid, first.attempts), (uuid, 1));
    assert!(claim_one(db, "node2").await.is_none());
    let row = validation_view(db, uuid).await;
    assert_eq!(row.state, "running");
    assert_eq!(row.claim_token, Some(first.token));
    assert!(svs_queue::heartbeat(db, first).await.expect("heartbeats"));
}

async fn futures_join_all(db: &Db, n: usize) -> Vec<Option<svs_queue::Claim>> {
    let mut set = tokio::task::JoinSet::new();
    for index in 0..n {
        let db = db.clone();
        set.spawn(async move {
            svs_queue::claim(&db, &format!("node{index}"), LEASE, 3)
                .await
                .expect("claims")
        });
    }
    let mut claims = Vec::new();
    while let Some(claim) = set.join_next().await {
        claims.push(claim.expect("joins"));
    }
    claims
}

/// test_validations.py's `test_an_expired_lease_is_taken_over`.
#[tokio::test]
async fn an_expired_lease_is_taken_over() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let first = claim_one(db, "node1").await.expect("a claim");
    expire_lease(db, uuid).await;

    let second = claim_one(db, "node2").await.expect("taken over");
    assert_eq!((second.uuid, second.attempts), (uuid, 2));
    // the first worker's work is void
    assert!(!svs_queue::heartbeat(db, &first).await.expect("heartbeats"));
    let lost = svs_queue::complete(
        db,
        &first,
        &replay_result(
            vec![result_row(ValidationCategory::Regression, &"ab".repeat(32))],
            vec![],
        ),
        "v",
        "f",
    )
    .await;
    assert!(
        matches!(lost, Err(svs_queue::CompleteError::LeaseLost(_))),
        "{lost:?}"
    );
    assert!(result_rows(db).await.is_empty());
    assert!(!svs_queue::fail(db, &first, "late").await.expect("fails"));
    assert_eq!(validation_view(db, uuid).await.state, "running");
}

/// test_validations.py's `test_a_validation_abandoned_too_often_fails`.
#[tokio::test]
async fn a_validation_abandoned_too_often_fails() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    for _ in 0..3 {
        assert!(claim_one(db, "node1").await.is_some());
        expire_lease(db, uuid).await;
    }
    assert!(claim_one(db, "node1").await.is_none());
    assert_eq!(
        svs_queue::fail_abandoned(db, LEASE, 3)
            .await
            .expect("fails"),
        1
    );
    let row = validation_view(db, uuid).await;
    assert_eq!((row.state.as_str(), row.active_key), ("failed", None));
    assert!(row.error.unwrap().contains("stopped 3 times"));
}

/// test_validations.py's `test_a_released_validation_returns_to_the_queue`.
#[tokio::test]
async fn a_released_validation_returns_to_the_queue() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let claimed = claim_one(db, "node1").await.expect("a claim");
    assert!(svs_queue::release(db, &claimed).await.expect("releases"));

    let row = validation_view(db, uuid).await;
    assert_eq!(
        (
            row.state.as_str(),
            row.attempts,
            row.claim_token,
            row.claimed_by
        ),
        ("queued", 0, None, None)
    );
    assert!(row.active_key.is_some());
    assert_eq!(claim_one(db, "node2").await.expect("a claim").uuid, uuid);
}

/// test_validations.py's `test_complete_stores_the_report_and_its_rows`.
#[tokio::test]
async fn complete_stores_the_report_and_its_rows() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let claimed = claim_one(db, "node1").await.expect("a claim");
    let result = replay_result(
        vec![
            result_row(ValidationCategory::Regression, &"ab".repeat(32)),
            result_row(ValidationCategory::NewFpOtherRule, &"cd".repeat(32)),
        ],
        vec![svs_yara::replay::FileError {
            file: "yara/acme/broken.yar".to_owned(),
            namespace: "acme".to_owned(),
            error: "syntax error".to_owned(),
            dropped: vec![],
        }],
    );

    svs_queue::complete(db, &claimed, &result, &"v".repeat(64), &"f".repeat(64))
        .await
        .expect("completes");

    let row = validation_view(db, uuid).await;
    assert_eq!(
        (
            row.state.as_str(),
            row.claim_token,
            row.active_key.as_deref(),
            row.diffed
        ),
        ("completed", None, None, Some(true))
    );
    assert_eq!(
        (row.regressions, row.new_fps, row.compile_errors),
        (Some(1), Some(1), Some(1))
    );
    assert_eq!(row.counts.as_ref().unwrap()["regression"], 1);
    let report = row.report.expect("a report");
    assert!(report.get("rows").is_none());
    assert_eq!(
        report["head"]["file_errors"][0]["file"],
        "yara/acme/broken.yar"
    );
    assert!(row.finished_at.is_some());
    assert_eq!(
        result_rows(db).await,
        [
            (
                "ab".repeat(32),
                "regression".to_owned(),
                "match".to_owned(),
                "miss".to_owned(),
                Some("tp".to_owned())
            ),
            (
                "cd".repeat(32),
                "new_fp_other_rule".to_owned(),
                "match".to_owned(),
                "miss".to_owned(),
                Some("tp".to_owned())
            ),
        ]
    );
}

/// test_validations.py's `test_prune_removes_old_finished_validations_with_their_results`, in batches of
/// one.
#[tokio::test]
async fn prune_removes_old_finished_validations_with_their_results() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository_with(|s| s.prune_batch_size = 1);
    let (old, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    complete_claimed(
        db,
        &repo,
        old,
        vec![result_row(ValidationCategory::Regression, &"ab".repeat(32))],
    )
    .await;
    let (recent, _) = request_validation(db, &repo, &validation_base(), &"c".repeat(40)).await;
    complete_claimed(db, &repo, recent, vec![]).await;
    let (queued, _) = request_validation(db, &repo, &validation_base(), &"d".repeat(40)).await;
    sqlx::query(
        "UPDATE svs.validations SET finished_at = CASE WHEN finished_at IS NULL THEN NULL ELSE now() - interval '200 days' END,
                created_at = now() - interval '200 days'
         WHERE uuid = ANY ($1)",
    )
    .bind(vec![old, queued])
    .execute(db.pool())
    .await
    .expect("ages them");
    let actor = Actor::Internal {
        id: Component::new("scheduler:svs_validations_prune").expect("a component"),
    };
    let service = validating(db, &repo);

    assert_eq!(
        service
            .prunable_svs_validations(&actor)
            .await
            .expect("counts"),
        1
    );
    let pruned = service.prune_svs_validations(&actor).await.expect("prunes");
    assert_eq!((pruned.removed, pruned.batches), (1, 1));
    let left: BTreeSet<Uuid> = sqlx::query_scalar("SELECT uuid FROM svs.validations")
        .fetch_all(db.pool())
        .await
        .expect("reads")
        .into_iter()
        .collect();
    assert_eq!(left, BTreeSet::from([recent, queued]));
    assert!(result_rows(db).await.is_empty());
    // only the scheduler's task holds the grant
    let refused = service
        .prune_svs_validations(&user(UserId(Uuid::from_u128(77))))
        .await;
    assert!(
        matches!(refused, Err(ServiceError::PermissionDenied { .. })),
        "{refused:?}"
    );
}

/// test_validations.py's `test_deleting_a_sample_removes_it_from_every_report`.
#[tokio::test]
async fn deleting_a_sample_removes_it_from_every_report() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let content = format!("svs validation delete {}", Uuid::new_v4()).into_bytes();
    let sha256 = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &content,
        &[RULE_UUID],
        "sample.bin",
    )
    .await;
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    complete_claimed(
        db,
        &repo,
        uuid,
        vec![
            result_row(ValidationCategory::Regression, &sha256),
            result_row(ValidationCategory::Regression, &"ab".repeat(32)),
        ],
    )
    .await;

    service(db)
        .delete_svs_sample(&admin(db).await, &bucket, &sha256, "privacy request")
        .await
        .expect("deletes");

    let left: Vec<String> = result_rows(db).await.into_iter().map(|r| r.0).collect();
    assert_eq!(left, ["ab".repeat(32)]);
}

// ---- the corpus ----

/// test_corpus.py's `test_units_are_distinct_scans_and_samples_carry_labels`.
#[tokio::test]
async fn units_are_distinct_scans_and_samples_carry_labels() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let content = format!("replay me {}", Uuid::new_v4()).into_bytes();
    let sha256 = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &content,
        &[RULE_UUID],
        "invoice.pdf",
    )
    .await;
    // the same bytes under another name, and again under the same name and tags, and other tags
    for file_path in ["renamed.pdf", "invoice.pdf", "invoice.pdf"] {
        insert_capture(
            db,
            Uuid::new_v4(),
            &sha256,
            OTHER_RULE_UUID,
            CaptureRow {
                file_path,
                ..CaptureRow::default()
            },
        )
        .await;
    }
    let tagged = insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        OTHER_RULE_UUID,
        CaptureRow {
            file_path: "invoice.pdf",
            ..CaptureRow::default()
        },
    )
    .await;
    sqlx::query("UPDATE svs.yara_captures SET yara_meta_tags = '{kind=email}' WHERE id = $1")
        .bind(tagged)
        .execute(db.pool())
        .await
        .expect("tags it");
    // a capture that was never stored is no unit, and its file no sample
    insert_capture(
        db,
        Uuid::new_v4(),
        &"f".repeat(64),
        RULE_UUID,
        CaptureRow {
            state: "missing",
            missing_reason: Some("file"),
            ..CaptureRow::default()
        },
    )
    .await;

    let (tp, fp) = classes();
    let corpus = svs_yara::corpus::read_corpus(db, &tp, &fp)
        .await
        .expect("reads");

    let mut units: Vec<(String, Vec<String>)> = corpus
        .units
        .iter()
        .map(|u| (u.file_path.clone(), u.meta_tags.clone()))
        .collect();
    units.sort();
    assert_eq!(
        units,
        [
            ("invoice.pdf".to_owned(), vec![]),
            ("invoice.pdf".to_owned(), vec!["kind=email".to_owned()]),
            ("renamed.pdf".to_owned(), vec![]),
        ]
    );
    assert_eq!(
        corpus.samples.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (sha256.clone(), RULE_UUID.to_owned()),
            (sha256.clone(), OTHER_RULE_UUID.to_owned())
        ])
    );
    assert_eq!(
        corpus.samples[&(sha256.clone(), RULE_UUID.to_owned())]
            .label
            .as_deref(),
        Some("tp")
    );
    assert_eq!(
        corpus.samples[&(sha256, OTHER_RULE_UUID.to_owned())].label,
        None
    );
}

/// test_corpus.py's `test_units_are_copied_out_of_the_pool`.
#[tokio::test]
async fn units_are_copied_out_of_the_pool() {
    use std::os::unix::fs::MetadataExt;
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let content = format!("copy me {}", Uuid::new_v4()).into_bytes();
    let sha256 = sample_named(
        db,
        &bucket,
        "FALSE_POSITIVE",
        &content,
        &[RULE_UUID],
        "dir/a.txt",
    )
    .await;
    insert_capture(
        db,
        Uuid::new_v4(),
        &sha256,
        OTHER_RULE_UUID,
        CaptureRow {
            file_path: "b.txt",
            ..CaptureRow::default()
        },
    )
    .await;
    let (tp, fp) = classes();
    let mut corpus = svs_yara::corpus::read_corpus(db, &tp, &fp)
        .await
        .expect("reads");
    let dir = tempfile::tempdir().expect("a directory");

    svs_yara::corpus::write_units(
        &mut corpus,
        &bucket,
        &dir.path().join("u"),
        svs_yara::ValidationConfig::default().corpus_limits,
        &CancellationToken::new(),
    )
    .await
    .expect("writes");

    let paths: BTreeMap<&str, &PathBuf> = corpus
        .units
        .iter()
        .map(|u| (u.file_path.as_str(), u.path.as_ref().expect("written")))
        .collect();
    assert!(paths["dir/a.txt"].ends_with("files/dir/a.txt"));
    for path in paths.values() {
        assert_eq!(std::fs::read(path).expect("reads"), content);
        // the two units share one copy, and nothing of the node's cache is linked in: the scan could
        // change what the bucket serves
        assert_eq!(std::fs::metadata(path).expect("a file").nlink(), 2);
    }
    assert_eq!(corpus.replayed_sha256s(), BTreeSet::from([sha256]));
    assert_eq!(corpus.bytes, content.len() as u64);
    assert!(corpus.skipped.is_empty());
}

/// test_corpus.py's `test_what_cannot_be_replayed_is_skipped`. ace3's `wrong_node` has no counterpart: the
/// bucket is one, shared by every node.
#[tokio::test]
async fn what_cannot_be_replayed_is_skipped() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let content = format!("unsafe {}", Uuid::new_v4()).into_bytes();
    let unsafe_sha = sample_named(db, &bucket, "DELIVERY", &content, &[RULE_UUID], "ok.bin").await;
    for file_path in ["../../escape.bin", "/etc/escape.bin"] {
        insert_capture(
            db,
            Uuid::new_v4(),
            &unsafe_sha,
            OTHER_RULE_UUID,
            CaptureRow {
                file_path,
                ..CaptureRow::default()
            },
        )
        .await;
    }
    // stored, but the pool doesn't have the bytes
    insert_capture(
        db,
        Uuid::new_v4(),
        &"2".repeat(64),
        RULE_UUID,
        CaptureRow::default(),
    )
    .await;
    // cut to the column's width when it was stored
    let long_content = format!("long {}", Uuid::new_v4()).into_bytes();
    let long_sha = sha256_hex(&long_content);
    let long_path: &'static str =
        Box::leak(("d/".repeat(1024)[..1023].to_owned() + "x").into_boxed_str());
    insert_capture(
        db,
        Uuid::new_v4(),
        &long_sha,
        RULE_UUID,
        CaptureRow {
            file_path: long_path,
            ..CaptureRow::default()
        },
    )
    .await;
    put_held(db, &bucket, &long_content, &long_sha).await;
    let (tp, fp) = classes();
    let mut corpus = svs_yara::corpus::read_corpus(db, &tp, &fp)
        .await
        .expect("reads");
    let dir = tempfile::tempdir().expect("a directory");

    svs_yara::corpus::write_units(
        &mut corpus,
        &bucket,
        &dir.path().join("u"),
        svs_yara::ValidationConfig::default().corpus_limits,
        &CancellationToken::new(),
    )
    .await
    .expect("writes");

    let skipped: BTreeMap<(String, Option<String>), String> = corpus
        .skipped
        .iter()
        .map(|s| ((s.sha256.clone(), s.file_path.clone()), s.reason.clone()))
        .collect();
    assert_eq!(
        skipped[&(unsafe_sha.clone(), Some("../../escape.bin".to_owned()))],
        "unsafe_path"
    );
    assert_eq!(
        skipped[&(unsafe_sha.clone(), Some("/etc/escape.bin".to_owned()))],
        "unsafe_path"
    );
    assert_eq!(
        skipped[&("2".repeat(64), Some("sample.bin".to_owned()))],
        "unreadable"
    );
    assert_eq!(
        corpus.replayed_sha256s(),
        BTreeSet::from([unsafe_sha, long_sha.clone()])
    );
    assert!(!dir.path().join("escape.bin").exists());
    assert_eq!(
        corpus
            .units
            .iter()
            .filter(|u| u.sha256 == long_sha)
            .map(|u| u.truncated)
            .collect::<Vec<_>>(),
        [true]
    );
}

/// The corpus's bounds (new in ace4): past `max_corpus_files` or `max_corpus_bytes` the validation fails,
/// rather than reporting on part of the corpus.
#[tokio::test]
async fn the_corpus_is_bounded() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    for name in ["one.bin", "two.bin"] {
        let content = format!("bounded {name} {}", Uuid::new_v4()).into_bytes();
        sample_named(db, &bucket, "DELIVERY", &content, &[RULE_UUID], name).await;
    }
    let (tp, fp) = classes();
    for (limits, message) in [
        (
            svs_yara::corpus::CorpusLimits {
                max_files: 1,
                max_bytes: 1 << 20,
            },
            "more than 1 files",
        ),
        (
            svs_yara::corpus::CorpusLimits {
                max_files: 10,
                max_bytes: 60,
            },
            "larger than 60 bytes",
        ),
    ] {
        let mut corpus = svs_yara::corpus::read_corpus(db, &tp, &fp)
            .await
            .expect("reads");
        let dir = tempfile::tempdir().expect("a directory");
        let error = svs_yara::corpus::write_units(
            &mut corpus,
            &bucket,
            &dir.path().join("u"),
            limits,
            &CancellationToken::new(),
        )
        .await
        .expect_err("too large");
        assert!(error.to_string().contains(message), "{error}");
    }
}

// ---- whole replays ----

fn rules(parts: &[String]) -> String {
    parts.concat()
}

fn replay_request(base: &str, head: &str, branch: Option<&str>) -> ReplayRequest {
    ReplayRequest {
        repository: REPOSITORY.to_owned(),
        base_sha: base.to_owned(),
        head_sha: head.to_owned(),
        branch: branch.map(str::to_owned),
        retired: BTreeSet::new(),
    }
}

fn rows_by_pair(result: &ReplayResult) -> BTreeMap<(String, String), &svs_yara::diff::ResultRow> {
    result
        .rows
        .iter()
        .map(|r| ((r.sha256.clone(), r.rule_uuid.clone()), r))
        .collect()
}

fn sample_pair(sha256: &str, rule: &str) -> (String, String) {
    (sha256.to_owned(), rule.to_owned())
}

fn uuids(n: usize) -> Vec<String> {
    (0..n).map(|_| Uuid::new_v4().to_string()).collect()
}

/// test_replay.py's `test_a_branch_gone_from_the_remote_still_validates`: CI running again on a merged pull
/// request, whose branch was deleted, or on one from a fork.
#[tokio::test]
async fn a_branch_gone_from_the_remote_still_validates() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let r1 = Uuid::new_v4().to_string();
    let a = sample_named(db, &bucket, "DELIVERY", b"alpha evil", &[&r1], "sample.bin").await;
    let base = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&r1), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let head = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule(
                "one",
                Some(&r1),
                "$a = \"nothing here\"",
                "any of them",
                &[],
            ),
        )],
        "main",
    );

    let result = replayer(db, &bucket, &repo)
        .run(
            &replay_request(&base, &head, Some("feature-deleted-on-merge")),
            &CancellationToken::new(),
        )
        .await
        .expect("replays");

    assert!(result.diffed);
    assert_eq!(
        rows_by_pair(&result)[&sample_pair(&a, &r1)].category,
        ValidationCategory::Regression
    );
}

/// test_replay.py's `test_a_validation_reports_what_the_change_does`.
#[tokio::test]
async fn a_validation_reports_what_the_change_does() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let ids = uuids(8);
    let (r1, r2, r3, r4, r5, r6, r7, broken) = (
        &ids[0], &ids[1], &ids[2], &ids[3], &ids[4], &ids[5], &ids[6], &ids[7],
    );
    let a = sample_named(db, &bucket, "DELIVERY", b"alpha evil", &[r1], "sample.bin").await;
    let b = sample_named(
        db,
        &bucket,
        "FALSE_POSITIVE",
        b"beta bad",
        &[r2],
        "sample.bin",
    )
    .await;
    let c = sample_named(db, &bucket, "DELIVERY", b"gamma", &[r3], "sample.bin").await;
    // two rules fired on the alert: their TP labels are unconfirmed (inherited_multi)
    let d = sample_named(db, &bucket, "DELIVERY", b"delta", &[r6, r7], "sample.bin").await;
    let r =
        |name: &str, uuid: &str, strings: &str| rule(name, Some(uuid), strings, "any of them", &[]);

    let base = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rules(&[
                r("one", r1, "$a = \"evil\""),
                r("two", r2, "$a = \"bad\""),
                r("three", r3, "$a = \"gamma\""),
                r("six", r6, "$a = \"delta\""),
                r("seven", r7, "$a = \"delta\""),
            ]),
        )],
        "main",
    );
    let head = repo.commit(
        &[
            (
                "yara/acme/rules.yar",
                &rules(&[
                    r("one", r1, "$a = \"nothing here\""),
                    r("two", r2, "$a = \"zzz\""),
                    r("three", r3, "$a = \"gamma\""),
                    r("four", r4, "$a = \"bad\""),
                    r("seven", r7, "$a = \"epsilon\""),
                ]),
            ),
            ("yara/beta/new.yar", &r("five", r5, "$a = \"evil\"")),
            (
                "yara/acme/broken.yar",
                &rule("broken", Some(broken), "$a = \"x\"", "nope", &[]),
            ),
            (
                "yara/acme/deeper/nested.yar",
                &r("nested", &Uuid::new_v4().to_string(), "$a = \"x\""),
            ),
            (
                "yara/acme/no_uuid.yar",
                &rule("anonymous", None, "$a = \"x\"", "any of them", &[]),
            ),
        ],
        "feature",
    );

    let result = replayer(db, &bucket, &repo)
        .run(
            &replay_request(&base, &head, Some("feature")),
            &CancellationToken::new(),
        )
        .await
        .expect("replays");

    assert!(result.diffed);
    let rows = rows_by_pair(&result);
    let category = |sha: &str, rule: &str| rows[&sample_pair(sha, rule)].category;
    assert_eq!(category(&a, r1), ValidationCategory::Regression);
    assert_eq!(
        (
            rows[&sample_pair(&a, r1)].base,
            rows[&sample_pair(&a, r1)].head
        ),
        (ValidationOutcome::Match, ValidationOutcome::Miss)
    );
    assert_eq!(category(&b, r2), ValidationCategory::Improvement);
    assert_eq!(category(&b, r4), ValidationCategory::NewFpOtherRule);
    assert_eq!(category(&a, r5), ValidationCategory::NewMatchRealHit);
    assert_eq!(
        rows[&sample_pair(&a, r5)].namespace.as_deref(),
        Some("beta")
    );
    assert_eq!(category(&d, r6), ValidationCategory::RuleRemoved);
    assert_eq!(category(&d, r7), ValidationCategory::RegressionUnconfirmed);
    assert!(!rows.contains_key(&sample_pair(&c, r3)));
    assert_eq!(result.counts["unchanged"], 1);
    assert_eq!(result.counts.values().sum::<u64>(), 7);

    let [error] = &result.head.file_errors[..] else {
        panic!("one file error: {:?}", result.head.file_errors)
    };
    assert_eq!(
        (
            error.file.as_str(),
            error
                .dropped
                .iter()
                .map(|d| d.uuid.clone().unwrap())
                .collect::<Vec<_>>()
        ),
        ("yara/acme/broken.yar", vec![broken.clone()])
    );
    assert_eq!(
        result
            .head
            .not_loaded
            .iter()
            .map(|n| n.path.as_str())
            .collect::<Vec<_>>(),
        ["yara/acme/deeper/nested.yar"]
    );
    assert_eq!(result.base.namespaces, ["acme"]);
    assert_eq!(result.head.namespaces, ["acme", "beta"]);
    // a rule in a file that doesn't compile is still in head's source
    let set = |refs: &[svs_yara::replay::RuleRef]| {
        refs.iter()
            .map(|r| r.uuid.clone().unwrap())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        set(&result.added_rules),
        BTreeSet::from([r4.clone(), r5.clone(), broken.clone()])
    );
    assert_eq!(set(&result.removed_rules), BTreeSet::from([r6.clone()]));
    assert_eq!(
        set(&result.changed_rules),
        BTreeSet::from([r1.clone(), r2.clone(), r7.clone()])
    );
    assert_eq!(
        result
            .not_testable
            .iter()
            .map(|n| (n.name.as_str(), n.reason.as_str()))
            .collect::<Vec<_>>(),
        [("anonymous", "no uuid")]
    );
    assert_eq!((result.files, result.samples), (4, 5));
    assert_eq!(
        result
            .head
            .timings
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["acme", "beta"]
    );
    assert!(repo.work_dirs().is_empty());
}

/// test_replay.py's `test_retired_samples_are_only_counted`.
#[tokio::test]
async fn retired_samples_are_only_counted() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let r1 = Uuid::new_v4().to_string();
    let a = sample_named(db, &bucket, "DELIVERY", b"alpha evil", &[&r1], "sample.bin").await;
    let base = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&r1), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let head = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&r1), "$a = \"nothing\"", "any of them", &[]),
        )],
        "main",
    );
    let mut request = replay_request(&base, &head, None);
    request.retired = BTreeSet::from([sample_pair(&a, &r1)]);

    let result = replayer(db, &bucket, &repo)
        .run(&request, &CancellationToken::new())
        .await
        .expect("replays");

    assert!(result.rows.is_empty());
    assert_eq!(result.counts["retired"], 1);
}

/// test_replay.py's `test_a_head_that_would_not_load_is_not_compared`. The report's line for it is
/// ace-app's `the_report_says_a_ruleset_would_not_load`.
#[tokio::test]
async fn a_head_that_would_not_load_is_not_compared() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let (r1, r2) = (Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    sample_named(db, &bucket, "DELIVERY", b"alpha evil", &[&r1], "sample.bin").await;
    let base = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&r1), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let head = repo.commit(
        &[(
            "yara/acme/again.yar",
            &rule("one", Some(&r2), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );

    let result = replayer(db, &bucket, &repo)
        .run(
            &replay_request(&base, &head, None),
            &CancellationToken::new(),
        )
        .await
        .expect("replays");

    assert!(!result.diffed);
    let error = result
        .head
        .ruleset_error
        .as_deref()
        .expect("a ruleset error");
    assert!(error.contains("duplicate"), "{error}");
    assert!(result.base.loads && !result.head.loads && result.rows.is_empty());
}

/// test_replay.py's `test_the_working_directory_is_deleted_when_the_scan_fails`: the scan is a program
/// that fails.
#[tokio::test]
async fn the_working_directory_is_deleted_when_the_scan_fails() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let r1 = Uuid::new_v4().to_string();
    sample_named(db, &bucket, "DELIVERY", b"alpha evil", &[&r1], "sample.bin").await;
    let sha = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&r1), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let mut failing = replayer(db, &bucket, &repo);
    failing.child = ReplayChild::Exec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo the scan failed >&2; exit 3".into()],
    };

    let error = failing
        .run(&replay_request(&sha, &sha, None), &CancellationToken::new())
        .await
        .expect_err("fails");

    assert!(
        matches!(&error, ReplayError::Failed(m) if m.contains("exited with 3") && m.contains("the scan failed")),
        "{error:?}"
    );
    assert!(repo.work_dirs().is_empty());
}

/// test_replay.py's `test_an_unknown_commit_fails`.
#[tokio::test]
async fn an_unknown_commit_fails() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let sha = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some("r1"), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let replayer = replayer(db, &bucket, &repo);
    let cancel = CancellationToken::new();
    let failed = |request: ReplayRequest| {
        let (replayer, cancel) = (&replayer, &cancel);
        async move {
            match replayer.run(&request, cancel).await {
                Err(ReplayError::Failed(message)) => message,
                other => panic!("{other:?}"),
            }
        }
    };

    assert!(
        failed(replay_request(&sha, &"0".repeat(40), None))
            .await
            .contains("is not in repository")
    );
    assert!(
        failed(replay_request(&sha, "main", None))
            .await
            .contains("not a commit id")
    );
    let mut elsewhere = replay_request(&sha, &sha, None);
    elsewhere.repository = "elsewhere".to_owned();
    assert!(
        failed(elsewhere)
            .await
            .contains("not in svs.yara.repositories")
    );
}

/// test_replay.py's `test_a_cancelled_replay_stops_and_leaves_nothing`.
#[tokio::test]
async fn a_cancelled_replay_stops_and_leaves_nothing() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let sha = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some("r1"), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = replayer(db, &bucket, &repo)
        .run(&replay_request(&sha, &sha, None), &cancel)
        .await;

    assert_eq!(error, Err(ReplayError::Cancelled));
    assert!(repo.work_dirs().is_empty());
}

/// test_replay.py's `test_a_replay_cancelled_during_the_scan_stops_it`: the scan is a program that would
/// run for a minute, and the cancel stops it.
#[tokio::test]
async fn a_replay_cancelled_during_the_scan_stops_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    sample_named(
        db,
        &bucket,
        "DELIVERY",
        b"alpha evil",
        &["r1"],
        "sample.bin",
    )
    .await;
    let sha = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some("r1"), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let mut slow = replayer(db, &bucket, &repo);
    slow.child = ReplayChild::Exec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "sleep 60".into()],
    };
    let cancel = CancellationToken::new();
    let canceller = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cancel.cancel();
        })
    };
    let started = Instant::now();

    let error = slow.run(&replay_request(&sha, &sha, None), &cancel).await;

    canceller.await.expect("cancels");
    assert_eq!(error, Err(ReplayError::Cancelled));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert!(repo.work_dirs().is_empty());
}

// ---- the workers ----

/// A stand-in for the replay, as ace3's tests patch `run_replay`.
struct FakeReplay {
    calls: Mutex<Vec<ReplayRequest>>,
    outcome: Box<dyn Fn() -> Result<ReplayResult, ReplayError> + Send + Sync>,
    /// Waits for the cancel, then answers Cancelled.
    until_cancelled: bool,
    started: tokio::sync::Notify,
}

impl Replay for FakeReplay {
    fn replay<'a>(
        &'a self,
        request: &'a ReplayRequest,
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ReplayResult, ReplayError>> + Send + 'a>,
    > {
        self.calls.lock().unwrap().push(request.clone());
        Box::pin(async move {
            self.started.notify_one();
            if self.until_cancelled {
                tokio::select! {
                    () = cancel.cancelled() => return Err(ReplayError::Cancelled),
                    () = tokio::time::sleep(Duration::from_secs(30)) => panic!("the replay was never cancelled"),
                }
            }
            (self.outcome)()
        })
    }
}

fn fake_replay(
    outcome: impl Fn() -> Result<ReplayResult, ReplayError> + Send + Sync + 'static,
) -> Arc<FakeReplay> {
    Arc::new(FakeReplay {
        calls: Mutex::new(Vec::new()),
        outcome: Box::new(outcome),
        until_cancelled: false,
        started: tokio::sync::Notify::new(),
    })
}

fn waiting_replay() -> Arc<FakeReplay> {
    Arc::new(FakeReplay {
        calls: Mutex::new(Vec::new()),
        outcome: Box::new(|| -> Result<ReplayResult, ReplayError> {
            unreachable!("it waits for the cancel")
        }),
        until_cancelled: true,
        started: tokio::sync::Notify::new(),
    })
}

/// test_service.py's `test_the_config_refuses_timings_that_cannot_work`: the defaults, and a heartbeat
/// that a lease can't keep. ace3's `shutdown_deadline_seconds` has no counterpart: `ace serve` stops its
/// workers within 10 seconds, killing a running scan and returning its validation to the queue.
#[test]
fn the_config_refuses_timings_that_cannot_work() {
    let config = svs_yara::ValidationConfig::default();
    assert_eq!(
        (config.heartbeat_interval, config.lease),
        (Duration::from_secs(30), Duration::from_secs(300))
    );
    let error = ace_sdk::Overlay::from_yaml("svs: {yara: {heartbeat_interval_seconds: 200}}")
        .expect_err("refused");
    assert!(
        error.to_string().contains("must not exceed lease_seconds"),
        "{error}"
    );
}

/// test_config.py's `test_a_lease_its_heartbeat_cannot_keep_is_refused_when_the_configuration_is_read`:
/// not only when `ace serve` starts, but by every process that reads the overlay.
#[test]
fn a_lease_its_heartbeat_cannot_keep_is_refused_when_the_overlay_is_read() {
    let error = ace_sdk::Overlay::from_yaml(
        "svs: {yara: {lease_seconds: 60, heartbeat_interval_seconds: 30}}",
    )
    .expect_err("refused");
    assert!(
        error.to_string().contains("must not exceed lease_seconds"),
        "{error}"
    );
    ace_sdk::Overlay::from_yaml("svs: {yara: {lease_seconds: 90, heartbeat_interval_seconds: 30}}")
        .expect("fits");
}

/// test_config.py's `test_yara_validation_defaults`.
#[test]
fn yara_validation_defaults() {
    let section = ace_sdk::Overlay::from_yaml("").expect("parses").svs.yara;
    assert!(section.repositories.is_empty());
    assert_eq!(section.max_concurrent_validations, 1);
    // the export of a commit is uncapped unless a site sets a limit
    assert_eq!(
        (section.max_archive_bytes, section.max_archive_members),
        (None, None)
    );
    assert!(ace_sdk::Overlay::from_yaml("svs: {yara: {nope: 1}}").is_err());
    for key in ["max_archive_bytes", "max_archive_members"] {
        let overlay =
            ace_sdk::Overlay::from_yaml(&format!("svs: {{yara: {{{key}: 10}}}}")).expect("parses");
        let value = if key == "max_archive_bytes" {
            overlay.svs.yara.max_archive_bytes
        } else {
            overlay.svs.yara.max_archive_members
        };
        assert_eq!(value, Some(10));
        assert!(ace_sdk::Overlay::from_yaml(&format!("svs: {{yara: {{{key}: 0}}}}")).is_err());
    }
    // the scan gets no network at all: its profile allows no port (`ace yara replay --contained`)
    let config = svs_yara::ValidationConfig::default();
    assert_eq!(config.retention_days, 90);
    assert!(config.corpus_limits.max_files > 0 && config.corpus_limits.max_bytes > 0);
}

/// test_service.py's `test_the_service_runs_a_queued_validation`.
#[tokio::test]
async fn the_workers_run_a_queued_validation() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let content = format!("svs service sample {}", Uuid::new_v4()).into_bytes();
    let sha256 = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &content,
        &[RULE_UUID],
        "sample.bin",
    )
    .await;
    service(db)
        .retire_svs_sample(&admin(db).await, &sha256, RULE_UUID, "intended")
        .await
        .expect("retires");
    let replay = fake_replay(|| Ok(replay_result(vec![], vec![])));

    let ran = workers(db, &repo, replay.clone())
        .drain(&CancellationToken::new())
        .await
        .expect("drains");

    assert_eq!(ran, 1);
    let row = validation_view(db, uuid).await;
    assert_eq!(
        (row.state.as_str(), row.attempts, row.claim_token),
        ("completed", 1, None)
    );
    assert!(row.corpus_version.is_some() && row.engine_fingerprint.is_some());
    let calls = replay.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        [ReplayRequest {
            repository: REPOSITORY.to_owned(),
            base_sha: validation_base(),
            head_sha: validation_head(),
            branch: Some("feature".to_owned()),
            retired: BTreeSet::from([sample_pair(&sha256, RULE_UUID)]),
        }]
    );
}

/// test_service.py's `test_a_replay_error_fails_the_validation_with_its_message`: neither commit is in the
/// repository.
#[tokio::test]
async fn a_replay_error_fails_the_validation_with_its_message() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some("r1"), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;

    workers(db, &repo, Arc::new(replayer(db, &bucket, &repo)))
        .drain(&CancellationToken::new())
        .await
        .expect("drains");

    let row = validation_view(db, uuid).await;
    assert_eq!((row.state.as_str(), row.active_key), ("failed", None));
    let error = row.error.expect("an error");
    assert!(
        error.starts_with(&format!(
            "commit {} is not in repository {REPOSITORY}",
            validation_base()
        )),
        "{error}"
    );
}

/// test_service.py's `test_an_unexpected_error_fails_the_validation_without_its_details`.
#[tokio::test]
async fn an_unexpected_error_fails_the_validation_without_its_details() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let replay = fake_replay(|| {
        Err(ReplayError::Internal(
            "/secret/path: no space left".to_owned(),
        ))
    });

    workers(db, &repo, replay)
        .drain(&CancellationToken::new())
        .await
        .expect("drains");

    let row = validation_view(db, uuid).await;
    assert_eq!(
        (row.state.as_str(), row.error.as_deref()),
        ("failed", Some(svs_queue::INTERNAL_ERROR))
    );
}

/// test_service.py's `test_stopping_returns_the_running_validation_to_the_queue`.
#[tokio::test]
async fn stopping_returns_the_running_validation_to_the_queue() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let replay = waiting_replay();
    let workers = workers(db, &repo, replay.clone());
    let claimed = claim_one(db, "node1").await.expect("a claim");
    let stop = CancellationToken::new();
    let running = {
        let (workers, stop) = (workers.clone(), stop.clone());
        tokio::spawn(async move { workers.execute(&claimed, &stop).await })
    };
    replay.started.notified().await;

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(30), running)
        .await
        .expect("stops")
        .expect("joins");

    let row = validation_view(db, uuid).await;
    assert_eq!(
        (row.state.as_str(), row.attempts, row.claim_token),
        ("queued", 0, None)
    );
}

/// test_service.py's `test_a_worker_that_loses_its_lease_stops`.
#[tokio::test]
async fn a_worker_that_loses_its_lease_stops() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository_with(|s| {
        s.heartbeat_interval_seconds = 1;
    });
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let replay = waiting_replay();
    let workers = workers(db, &repo, replay.clone());
    let claimed = claim_one(db, "node1").await.expect("a claim");
    let running = {
        let workers = workers.clone();
        tokio::spawn(async move { workers.execute(&claimed, &CancellationToken::new()).await })
    };
    replay.started.notified().await;
    // another worker took the validation over
    let other = Uuid::new_v4();
    sqlx::query(
        "UPDATE svs.validations SET claim_token = $2, claimed_by = 'node2' WHERE uuid = $1",
    )
    .bind(uuid)
    .bind(other)
    .execute(db.pool())
    .await
    .expect("takes it over");

    tokio::time::timeout(Duration::from_secs(30), running)
        .await
        .expect("stops")
        .expect("joins");

    let row = validation_view(db, uuid).await;
    assert_eq!(
        (
            row.state.as_str(),
            row.claim_token,
            row.claimed_by.as_deref()
        ),
        ("running", Some(other), Some("node2"))
    );
}

/// test_service.py's `test_the_service_starts_its_workers_and_stops_them`. ace3's
/// `test_the_service_stays_idle_off_the_primary_node` has no counterpart: ace4 has no primary node, and
/// every replica's workers share the queue through the claim (`only_one_worker_claims_a_validation`).
#[tokio::test]
async fn the_workers_start_and_stop() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository_with(|s| {
        s.max_concurrent_validations = 2;
        s.poll_interval_seconds = 0.05;
    });
    let (first, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let replay = fake_replay(|| Ok(replay_result(vec![], vec![])));
    let stop = CancellationToken::new();
    let running = tokio::spawn(workers(db, &repo, replay).run(stop.clone()));
    // a validation queued while they run is run too
    let deadline = Instant::now() + Duration::from_secs(20);
    while validation_view(db, first).await.state != "completed" {
        assert!(Instant::now() < deadline, "never ran");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (second, _) = request_validation(db, &repo, &validation_base(), &"c".repeat(40)).await;
    while validation_view(db, second).await.state != "completed" {
        assert!(Instant::now() < deadline, "never ran the second");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("stops")
        .expect("joins");
}

/// test_service.py's `test_a_whole_validation_through_the_service`.
#[tokio::test]
async fn a_whole_validation_through_the_workers() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let rule_uuid = Uuid::new_v4().to_string();
    let sha256 = sample_named(
        db,
        &bucket,
        "DELIVERY",
        b"alpha evil",
        &[&rule_uuid],
        "sample.bin",
    )
    .await;
    let base = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule("one", Some(&rule_uuid), "$a = \"evil\"", "any of them", &[]),
        )],
        "main",
    );
    let head = repo.commit(
        &[(
            "yara/acme/rules.yar",
            &rule(
                "one",
                Some(&rule_uuid),
                "$a = \"nothing\"",
                "any of them",
                &[],
            ),
        )],
        "feature",
    );
    let (uuid, _) = request_validation(db, &repo, &base, &head).await;

    workers(db, &repo, Arc::new(replayer(db, &bucket, &repo)))
        .drain(&CancellationToken::new())
        .await
        .expect("drains");

    let row = validation_view(db, uuid).await;
    assert_eq!(row.state, "completed", "{:?}", row.error);
    assert_eq!(
        (row.regressions, row.new_fps, row.compile_errors, row.diffed),
        (Some(1), Some(0), Some(0), Some(true))
    );
    assert_eq!(row.counts.unwrap()["regression"], 1);
    let rows: Vec<(String, String, String, Option<String>)> =
        sqlx::query_as("SELECT sha256, rule_uuid, category, label FROM svs.validation_results")
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        rows,
        [(
            sha256,
            rule_uuid,
            "regression".to_owned(),
            Some("tp".to_owned())
        )]
    );
}

// ---- the routes' service: the status, the list, the reports and their downloads ----

/// A completed validation of BASE..head whose report lists `rows`, as ace3's API tests make one.
async fn completed_validation(
    db: &Db,
    repo: &SvsRepository,
    head: &str,
    rows: Vec<svs_yara::diff::ResultRow>,
) -> Uuid {
    let (uuid, _) = request_validation(db, repo, &validation_base(), head).await;
    let claimed = claim_this(db, uuid).await;
    let mut result = replay_result(
        rows,
        vec![svs_yara::replay::FileError {
            file: "yara/acme/broken.yar".to_owned(),
            namespace: "acme".to_owned(),
            error: "syntax error".to_owned(),
            dropped: vec![],
        }],
    );
    result.head_sha = head.to_owned();
    result.skipped = vec![svs_yara::corpus::Skipped {
        sha256: "ef".repeat(32),
        file_path: Some("files/payroll-2026.xlsm".to_owned()),
        reason: "unsafe_path".to_owned(),
        detail: String::new(),
    }];
    svs_queue::complete(db, &claimed, &result, "v", "f")
        .await
        .expect("completes");
    uuid
}

/// tests/aceapi_v2/svs/test_validations.py's `test_the_status_names_rules_and_never_a_sample`.
#[tokio::test]
async fn the_status_names_rules_and_never_a_sample() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let shas = ["11".repeat(32), "22".repeat(32), "33".repeat(32)];
    let mut other = result_row(ValidationCategory::NewFpOtherRule, &shas[2]);
    other.rule_uuid = OTHER_RULE_UUID.to_owned();
    other.rule_name = "other_rule".to_owned();
    let uuid = completed_validation(
        db,
        &repo,
        &validation_head(),
        vec![
            result_row(ValidationCategory::Regression, &shas[0]),
            result_row(ValidationCategory::Regression, &shas[1]),
            other,
        ],
    )
    .await;
    // another validation's rows aren't this one's
    completed_validation(
        db,
        &repo,
        &"c".repeat(40),
        vec![result_row(ValidationCategory::Regression, &"44".repeat(32))],
    )
    .await;

    let status = validating(db, &repo)
        .svs_validation_status(&admin(db).await, uuid)
        .await
        .expect("reads");

    assert_eq!(status.state, svs_queue::ValidationState::Completed);
    assert_eq!(status.counts.as_ref().unwrap()["regression"], 2);
    type RuleCounts = Vec<(String, String, i64)>;
    let rules: Vec<(String, RuleCounts)> = status
        .rules
        .iter()
        .map(|(c, r)| {
            (
                c.clone(),
                r.iter()
                    .map(|r| (r.rule_uuid.clone(), r.rule_name.clone(), r.count))
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        rules,
        [
            (
                "new_fp_other_rule".to_owned(),
                vec![(OTHER_RULE_UUID.to_owned(), "other_rule".to_owned(), 1)]
            ),
            (
                "regression".to_owned(),
                vec![(RULE_UUID.to_owned(), "svs_rule".to_owned(), 2)]
            ),
        ]
    );
    assert_eq!(status.compile_errors[0].file, "yara/acme/broken.yar");
    assert_eq!(
        status.report_path,
        format!("/signatures/validations/{uuid}")
    );
    let text = format!("{status:?}");
    for secret in shas
        .iter()
        .map(String::as_str)
        .chain(["efef", "payroll-2026.xlsm"])
    {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
}

/// tests/aceapi_v2/svs/test_validations.py's `test_bad_requests` and `test_unknown_and_malformed_validations`,
/// at the service: a repository not configured, an abbreviated commit and a pr_url that isn't http are
/// refused, and an unknown validation is NotFound.
#[tokio::test]
async fn bad_validation_requests() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let actor = admin(db).await;
    let service = validating(db, &repo);
    let refused = |result: Result<_, ServiceError>| match result {
        Err(ServiceError::InvalidRequest(message)) => message,
        other => panic!("{other:?}"),
    };
    let mut elsewhere = ask(&validation_base(), &validation_head());
    elsewhere.repository = "elsewhere".to_owned();
    assert!(
        refused(service.request_svs_validation(&actor, &elsewhere).await)
            .contains("svs.yara.repositories")
    );
    // abbreviated commits wouldn't be recognized as the same commit
    refused(
        service
            .request_svs_validation(&actor, &ask(&validation_base(), &"b".repeat(12)))
            .await,
    );
    let mut script = ask(&validation_base(), &validation_head());
    script.pr_url = Some("javascript:alert(1)".to_owned());
    refused(service.request_svs_validation(&actor, &script).await);
    assert!(matches!(
        service.svs_validation_status(&actor, Uuid::new_v4()).await,
        Err(ServiceError::NotFound(_))
    ));
    assert!(matches!(
        service.svs_validation(&actor, Uuid::new_v4()).await,
        Err(ServiceError::NotFound(_))
    ));
}

/// tests/aceapi_v2/svs/test_validations.py's `test_filters_pages_and_exports`, at the service: the filters,
/// an inverse that keeps a validation with no counts, keyset pages newest first, and a bad cursor.
#[tokio::test]
async fn validation_filters_and_pages() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let actor = admin(db).await;
    let service = validating(db, &repo);
    let regressed = completed_validation(
        db,
        &repo,
        &validation_head(),
        vec![result_row(ValidationCategory::Regression, &"11".repeat(32))],
    )
    .await;
    let clean = completed_validation(db, &repo, &"c".repeat(40), vec![]).await;
    request_validation(db, &repo, &validation_base(), &"d".repeat(40)).await;
    let failed = claim_one(db, "node1").await.expect("a claim");
    svs_queue::fail(db, &failed, "the scan failed")
        .await
        .expect("fails");
    let listed = |filters: Vec<FilterEntry>| {
        let service = &service;
        let actor = &actor;
        async move {
            let page = service
                .svs_validations(
                    actor,
                    &ValidationQuery {
                        filters,
                        ..ValidationQuery::default()
                    },
                    None,
                    None,
                )
                .await
                .expect("lists");
            page.validations
                .into_iter()
                .map(|v| v.uuid)
                .collect::<Vec<_>>()
        }
    };

    assert_eq!(
        listed(vec![FilterEntry::text("Has Regressions", false, &["true"])]).await,
        [regressed]
    );
    // the inverse keeps the failed validation, which has no counts
    assert_eq!(
        listed(vec![FilterEntry::text("Has Regressions", true, &["true"])])
            .await
            .len(),
        2
    );
    // both values filter nothing, as ace3's flag_condition, and so their inverse matches nothing
    assert_eq!(
        listed(vec![FilterEntry::text(
            "Has Regressions",
            false,
            &["true", "false"]
        )])
        .await
        .len(),
        3
    );
    assert!(
        listed(vec![FilterEntry::text(
            "Has Regressions",
            true,
            &["true", "false"]
        )])
        .await
        .is_empty()
    );
    assert_eq!(
        listed(vec![FilterEntry::text("Compile Errors", false, &["false"])]).await,
        Vec::<Uuid>::new(),
        "both completed validations have a compile error, and the failed one has no count"
    );
    assert_eq!(
        listed(vec![FilterEntry::text("State", false, &["completed"])])
            .await
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([regressed, clean])
    );
    assert_eq!(
        listed(vec![FilterEntry::text("Head", false, &["cccc"])]).await,
        [clean]
    );
    assert_eq!(
        listed(vec![FilterEntry::text("State", false, &["failed"])])
            .await
            .len(),
        1
    );
    assert_eq!(
        listed(vec![FilterEntry::text("Repository", false, &["svs_r"])])
            .await
            .len(),
        3
    );
    assert!(
        listed(vec![FilterEntry::text("Branch", false, &["nope"])])
            .await
            .is_empty()
    );
    let bad = service
        .svs_validations(
            &actor,
            &ValidationQuery {
                filters: vec![FilterEntry::text("State", false, &["done"])],
                ..ValidationQuery::default()
            },
            None,
            None,
        )
        .await;
    assert!(
        matches!(bad, Err(ServiceError::InvalidRequest(_))),
        "{bad:?}"
    );

    // keyset pages, newest first
    let first = service
        .svs_validations(&actor, &ValidationQuery::default(), None, Some(2))
        .await
        .expect("lists");
    let second = service
        .svs_validations(
            &actor,
            &ValidationQuery::default(),
            first.next_cursor.as_deref(),
            Some(2),
        )
        .await
        .expect("lists");
    let paged: Vec<Uuid> = first
        .validations
        .iter()
        .chain(&second.validations)
        .map(|v| v.uuid)
        .collect();
    assert_eq!(paged.iter().collect::<BTreeSet<_>>().len(), 3);
    assert!(second.next_cursor.is_none());
    assert_eq!(paged, listed(vec![]).await);
    assert!(matches!(
        service
            .svs_validations(&actor, &ValidationQuery::default(), Some("junk"), None)
            .await,
        Err(ServiceError::InvalidRequest(_))
    ));
    let row = first
        .validations
        .iter()
        .chain(&second.validations)
        .find(|v| v.uuid == regressed)
        .unwrap();
    assert_eq!(
        (row.regressions, row.new_fps, row.compile_errors),
        (Some(1), Some(0), Some(1))
    );
    assert_eq!(row.requested_by.name.as_deref(), Some("alice"));
}

/// tests/aceapi_v2/svs/test_validations.py's `test_rows_by_category_and_rule`, at the service.
#[tokio::test]
async fn validation_results_by_category_and_rule() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let actor = admin(db).await;
    let service = validating(db, &repo);
    let mut other = result_row(ValidationCategory::NewFp, &"33".repeat(32));
    other.rule_uuid = OTHER_RULE_UUID.to_owned();
    let uuid = completed_validation(
        db,
        &repo,
        &validation_head(),
        vec![
            result_row(ValidationCategory::Regression, &"11".repeat(32)),
            result_row(ValidationCategory::Regression, &"22".repeat(32)),
            other,
        ],
    )
    .await;
    completed_validation(
        db,
        &repo,
        &"c".repeat(40),
        vec![result_row(ValidationCategory::Regression, &"44".repeat(32))],
    )
    .await;
    let shas = |selection: ResultSelection, cursor: Option<String>, limit: Option<u32>| {
        let (service, actor) = (&service, &actor);
        async move {
            let page = service
                .svs_validation_results(actor, uuid, &selection, cursor.as_deref(), limit)
                .await
                .expect("reads");
            (
                page.results
                    .into_iter()
                    .map(|r| r.sha256)
                    .collect::<Vec<_>>(),
                page.next_cursor,
            )
        }
    };

    let (all, _) = shas(ResultSelection::default(), None, None).await;
    assert_eq!(all, ["11".repeat(32), "22".repeat(32), "33".repeat(32)]);
    let only = |categories: &[&str], rules: &[&str]| ResultSelection {
        categories: categories.iter().map(|c| (*c).to_owned()).collect(),
        rule_uuids: rules.iter().map(|r| (*r).to_owned()).collect(),
    };
    assert_eq!(
        shas(only(&["regression"], &[]), None, None).await.0.len(),
        2
    );
    assert_eq!(
        shas(only(&[], &[OTHER_RULE_UUID]), None, None).await.0,
        ["33".repeat(32)]
    );
    let (_, cursor) = shas(ResultSelection::default(), None, Some(2)).await;
    assert_eq!(
        shas(ResultSelection::default(), cursor, Some(2)).await.0,
        ["33".repeat(32)]
    );
    let counted = service
        .svs_validation_results(&actor, uuid, &only(&["known_fp"], &[]), None, None)
        .await;
    assert!(
        matches!(counted, Err(ServiceError::InvalidRequest(_))),
        "{counted:?}"
    );
    let detail = service.svs_validation(&actor, uuid).await.expect("reads");
    assert_eq!(
        (
            detail.validation.state,
            detail.attempts,
            detail.claimed_by.as_deref()
        ),
        (svs_queue::ValidationState::Completed, 1, Some("node1"))
    );
    let report = detail.report.expect("a report");
    assert_eq!(report["skipped"][0]["file_path"], "files/payroll-2026.xlsm");
    assert_eq!(
        report["head"]["file_errors"][0]["file"],
        "yara/acme/broken.yar"
    );
}

/// tests/aceapi_v2/svs/test_validations.py's `test_the_selection_downloads_as_an_encrypted_zip`, at the
/// service: the files of the selected rows, with every sample's records, and nothing when none is stored.
#[tokio::test]
async fn a_report_s_selection_downloads() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let actor = admin(db).await;
    let content = format!("svs validation download {}", Uuid::new_v4()).into_bytes();
    let stored = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &content,
        &[RULE_UUID],
        "sample.bin",
    )
    .await;
    let mut other = result_row(ValidationCategory::NewFpOtherRule, &stored);
    other.rule_uuid = OTHER_RULE_UUID.to_owned();
    let uuid = completed_validation(
        db,
        &repo,
        &validation_head(),
        vec![
            result_row(ValidationCategory::Regression, &stored),
            // another rule's pair: the file still downloads, with its own samples' records
            other,
            result_row(ValidationCategory::NewFp, &"99".repeat(32)),
        ],
    )
    .await;
    let service = validating(db, &repo);
    let selection = ResultSelection {
        categories: vec!["regression".to_owned(), "new_fp_other_rule".to_owned()],
        rule_uuids: vec![],
    };

    let download = service
        .download_svs_validation(&actor, uuid, &selection)
        .await
        .expect("downloads");

    let [file] = &download.files[..] else {
        panic!("one file: {download:?}")
    };
    assert_eq!(file.sha256, stored);
    assert_eq!(file.rule_uuids, [RULE_UUID]);
    // nothing of the selection is stored
    let nothing = service
        .download_svs_validation(
            &actor,
            uuid,
            &ResultSelection {
                categories: vec!["new_fp".to_owned()],
                rule_uuids: vec![],
            },
        )
        .await;
    assert!(
        matches!(nothing, Err(ServiceError::NotFound(_))),
        "{nothing:?}"
    );
}

/// tests/aceapi_v2/svs/test_validations.py's `TestAccess`, at the service: the CI's `svs:validate` requests
/// and reads the status only, and `signature:read` reads the rest but can't request or download.
#[tokio::test]
async fn validations_follow_their_permissions() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let repo = svs_repository();
    let uuid = completed_validation(
        db,
        &repo,
        &validation_head(),
        vec![result_row(ValidationCategory::Regression, &"11".repeat(32))],
    )
    .await;
    let service = validating(db, &repo);
    let granted = |id: u128, major: &'static str, minor: &'static str| async move {
        let holder = UserId(Uuid::from_u128(id));
        exists(db, &Holder::User(holder)).await;
        sqlx::query(
            "INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
             VALUES ($1, $2, $3, 'allow', '{\"kind\": \"internal\", \"id\": \"test\"}')",
        )
        .bind(holder.0)
        .bind(major)
        .bind(minor)
        .execute(db.pool())
        .await
        .expect("grants");
        user(holder)
    };
    let ci = granted(0xC1, "svs", "validate").await;
    let reader = granted(0xC2, "signature", "read").await;
    let denied = |result: Result<(), ServiceError>| {
        matches!(result, Err(ServiceError::PermissionDenied { .. }))
    };

    assert!(
        service
            .request_svs_validation(&ci, &ask(&validation_base(), &"c".repeat(40)))
            .await
            .expect("requests")
            .1
    );
    service
        .svs_validation_status(&ci, uuid)
        .await
        .expect("reads the status");
    assert!(denied(
        service
            .svs_validations(&ci, &ValidationQuery::default(), None, None)
            .await
            .map(|_| ())
    ));
    assert!(denied(service.svs_validation(&ci, uuid).await.map(|_| ())));
    assert!(denied(
        service
            .svs_validation_results(&ci, uuid, &ResultSelection::default(), None, None)
            .await
            .map(|_| ())
    ));
    assert!(denied(
        service
            .download_svs_validation(&ci, uuid, &ResultSelection::default())
            .await
            .map(|_| ())
    ));

    assert!(denied(
        service
            .request_svs_validation(&reader, &ask(&validation_base(), &"d".repeat(40)))
            .await
            .map(|_| ())
    ));
    assert!(denied(
        service
            .svs_validation_status(&reader, uuid)
            .await
            .map(|_| ())
    ));
    service
        .svs_validations(&reader, &ValidationQuery::default(), None, None)
        .await
        .expect("lists");
    assert!(denied(
        service
            .download_svs_validation(&reader, uuid, &ResultSelection::default())
            .await
            .map(|_| ())
    ));
}

// ---- their audit rows ----

/// Every validation and result row, as text, for the audit failure test.
async fn validation_rows(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'validation ' || row_to_json(v)::text FROM svs.validations v
         UNION ALL SELECT 'result ' || row_to_json(r)::text FROM svs.validation_results r
         ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads")
}

async fn request_svs_validation_records_its_row(db: &Db) -> String {
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "request_svs_validation".to_owned(),
            target: ("svs_validation".to_owned(), uuid.to_string()),
            before: None,
            after: Some(json!({
                "repository": REPOSITORY, "base_sha": validation_base(), "head_sha": validation_head(),
                "branch": "feature", "pr_url": "https://git.example/pr/1", "answered_by": "queued",
            })),
            details: json!({}),
        }
    );
    // a request answered by it has a row too, as ace3 logs both
    request_validation(db, &repo, &validation_base(), &validation_head()).await;
    let again = last_audit(db).await;
    assert_eq!(
        again.target,
        ("svs_validation".to_owned(), uuid.to_string())
    );
    assert_eq!(again.after, None);
    assert_eq!(
        again.details["answered_by"],
        "an existing queued validation"
    );
    row.action
}

async fn download_svs_validation_records_its_row(db: &Db) -> String {
    let (bucket, _cache) = bucket(db);
    let repo = svs_repository();
    let content = format!("svs validation audit {}", Uuid::new_v4()).into_bytes();
    let sha256 = sample_named(
        db,
        &bucket,
        "DELIVERY",
        &content,
        &[RULE_UUID],
        "sample.bin",
    )
    .await;
    let uuid = completed_validation(
        db,
        &repo,
        &"e".repeat(40),
        vec![result_row(ValidationCategory::Regression, &sha256)],
    )
    .await;
    let selection = ResultSelection {
        categories: vec!["regression".to_owned()],
        rule_uuids: vec![],
    };
    validating(db, &repo)
        .download_svs_validation(&admin(db).await, uuid, &selection)
        .await
        .expect("downloads");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "download_svs_validation".to_owned(),
            target: ("svs_validation".to_owned(), uuid.to_string()),
            before: None,
            after: None,
            details: json!({"categories": ["regression"], "rule_uuids": [], "sha256s": [sha256]}),
        }
    );
    row.action
}

async fn prune_svs_validations_records_its_row(db: &Db) -> String {
    let repo = svs_repository();
    let (uuid, _) = request_validation(db, &repo, &validation_base(), &"f".repeat(40)).await;
    let claimed = claim_this(db, uuid).await;
    svs_queue::fail(db, &claimed, "failed")
        .await
        .expect("fails");
    sqlx::query(
        "UPDATE svs.validations SET finished_at = now() - interval '100 days' WHERE uuid = $1",
    )
    .bind(uuid)
    .execute(db.pool())
    .await
    .expect("ages it");
    let actor = Actor::Internal {
        id: Component::new("scheduler:svs_validations_prune").expect("a component"),
    };
    validating(db, &repo)
        .prune_svs_validations(&actor)
        .await
        .expect("prunes");
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: json!({"kind": "internal", "id": "scheduler:svs_validations_prune"}),
            action: "prune_svs_validations".to_owned(),
            target: ("svs_validations".to_owned(), "expired".to_owned()),
            before: Some(json!({"retention_days": 90, "validations": [uuid]})),
            after: None,
            details: json!({}),
        }
    );
    row.action
}

// PLAN.md 7.13: ace3's `tests/saq/alert_routing/` as Rust tests, each named `routing_` and its case. Where an
// alert's routing runs here, after its pass completes, the tests complete a pass and route what's due, as
// `ace serve`'s worker does. The cases and where they went:
//
// test_detection_queue.py (8): routing_single_routed_detection_sets_queue,
//   routing_routed_plus_plain_detection_keeps_default, routing_explicit_queue_not_clobbered,
//   routing_no_detections_leaves_default, routing_conflicting_queues_pick_sorted_first,
//   routing_routed_detection_on_observable, routing_a_plain_detection_on_the_root_keeps_the_default_queue,
//   routing_only_when_the_alert_is_created.
// test_registry.py: TestOrder: routing_the_built_in_router_is_always_present (with the site crate's
//   the_shipped_routers_are_the_built_in_one), routing_lowest_priority_runs_first_and_the_first_decision_wins,
//   routing_ahead_of_the_detection_queue_router, routing_stages_are_passed_through, routing_names_are_unique,
//   routing_the_decision_is_logged; test_final_is_passed_through has no case: there's no `final` flag
//   (`ace_service::routing`'s docs), and TestFinalPass's cases below cover when routing runs.
//   TestFailures: routing_a_raising_router_is_reported_and_skipped (and a panicking one),
//   routing_a_router_returning_something_else_is_skipped (a decision that can't be made: Rust's types leave
//   nothing else to return), routing_a_decision_needs_a_usable_queue.
//   TestConfiguration: routing_configured_routers_are_loaded, routing_one_broken_entry_is_named_and_stops_startup
//   (ace3 loads the others; ace4 stops, as the rest of the overlay does), routing_unknown_settings_are_a_load_error;
//   test_the_shipped_configuration_loads is the site crate's the_shipped_routers_are_the_built_in_one, until
//   7.10 batch 7 adds svs_marker; test_loading_never_leaves_an_empty_registry has no case, as the routers are
//   built once at startup and never reloaded. TestExampleIntegration is the site crate's
//   the_example_router_loads_and_routes_only_tagged_alerts.
// test_alert_routing.py: TestPreInsert: routing_a_decision_becomes_the_alert_s_queue,
//   routing_no_decision_no_change_row, routing_the_detection_queue_router_runs_for_every_alert_path,
//   routing_a_raising_router_never_breaks_the_routing. TestMoveAlertToQueue:
//   routing_a_move_records_who_made_it_and_its_audit_row, routing_moving_back_restores_through_the_record,
//   routing_the_same_queue_is_not_a_move, routing_a_move_judges_the_row_as_it_is_written (the disposition
//   case; the two owner cases wait for alert ownership, 7.10 batch 7), routing_a_bad_queue_is_refused;
//   test_a_given_root_carries_the_queue has no case: the root's row is the alert's one queue.
//   TestPostAnalysis: routing_an_open_alert_is_moved_after_a_later_pass,
//   routing_a_dispositioned_alert_is_not_moved; the owned and automation-user cases wait for ownership.
//   TestReconcile has no case, for the same reason as a given root's. TestFinalPass:
//   routing_the_first_routing_is_the_alerted_stage_once, routing_runs_when_the_pass_completes,
//   routing_waits_while_a_task_is_delayed, routing_runs_after_a_cancelled_pass. TestEngine:
//   routing_a_detection_queue_routes_the_alert_a_landing_makes. Beyond ace3's:
//   routing_runs_on_the_completion_event, through `run_worker`.

mod routing_tests {
    use super::*;
    use ace_sdk::AlertRouterSection;
    use ace_service::DEFAULT_QUEUE;
    use ace_service::routing::{
        Alert as RoutedAlert, DETECTION_QUEUE, Decision, DetectionPoint, DetectionQueue,
        RouteFuture, RouteOutcome, Router, RouterTypes, Routers, Stage, Tx, routing_actor,
    };
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An orchestrator with no modules, so a pass ends as soon as it starts.
    fn bare_service(db: &Db) -> Service {
        Service::new(
            db.clone(),
            Orchestrator::new(Catalog::new(vec![]), Modes::ace3()),
        )
    }

    /// Decides `queue` at `stages`, and counts its calls.
    struct Fixed {
        queue: &'static str,
        stages: &'static [Stage],
        calls: AtomicUsize,
    }

    fn fixed(queue: &'static str, stages: &'static [Stage]) -> Arc<Fixed> {
        Arc::new(Fixed {
            queue,
            stages,
            calls: AtomicUsize::new(0),
        })
    }

    const ALERTED: &[Stage] = &[Stage::Alerted];
    const ANALYZED: &[Stage] = &[Stage::Analyzed];

    impl Router for Fixed {
        fn route<'a>(
            &'a self,
            _: &'a RoutedAlert,
            stage: Stage,
            _: &'a mut Tx<'_>,
        ) -> RouteFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if !self.stages.contains(&stage) {
                    return Ok(None);
                }
                Decision::new(self.queue, format!("{} says so", self.queue)).map(Some)
            })
        }
    }

    /// Records each stage it's called at, and decides nothing.
    #[derive(Default)]
    struct Recording(Mutex<Vec<Stage>>);

    impl Router for Recording {
        fn route<'a>(
            &'a self,
            _: &'a RoutedAlert,
            stage: Stage,
            _: &'a mut Tx<'_>,
        ) -> RouteFuture<'a> {
            Box::pin(async move {
                self.0.lock().expect("a lock").push(stage);
                Ok(None)
            })
        }
    }

    /// Writes a row of its own, then fails: its write has to be undone.
    struct Failing;

    impl Router for Failing {
        fn route<'a>(
            &'a self,
            alert: &'a RoutedAlert,
            _: Stage,
            tx: &'a mut Tx<'_>,
        ) -> RouteFuture<'a> {
            Box::pin(async move {
                sqlx::query(
                    "UPDATE analysis.roots SET description = 'changed by a router' WHERE id = $1",
                )
                .bind(alert.root)
                .execute(tx.conn())
                .await
                .map_err(|e| e.to_string())?;
                Err("router is broken".to_owned())
            })
        }
    }

    struct Panicking;

    impl Router for Panicking {
        fn route<'a>(&'a self, _: &'a RoutedAlert, _: Stage, _: &'a mut Tx<'_>) -> RouteFuture<'a> {
            Box::pin(async move { panic!("router panicked") })
        }
    }

    /// Asks for a queue no decision can name, ace3's `BadReturnRouter`'s nearest kin here.
    struct BadQueue;

    impl Router for BadQueue {
        fn route<'a>(&'a self, _: &'a RoutedAlert, _: Stage, _: &'a mut Tx<'_>) -> RouteFuture<'a> {
            Box::pin(async move { Decision::new("q".repeat(65), "too long").map(Some) })
        }
    }

    /// At the later stage, sends the alert back where its newest move took it from, as SVS's marker router
    /// does when an alert is no longer attributed.
    struct Back;

    impl Router for Back {
        fn route<'a>(
            &'a self,
            alert: &'a RoutedAlert,
            stage: Stage,
            _: &'a mut Tx<'_>,
        ) -> RouteFuture<'a> {
            Box::pin(async move {
                if stage != Stage::Analyzed {
                    return Ok(None);
                }
                match &alert.last_change {
                    Some(change) => {
                        Decision::new(change.from_queue.clone(), "disassociated").map(Some)
                    }
                    None => Ok(None),
                }
            })
        }
    }

    /// Decides the queue the alert is in.
    struct Same;

    impl Router for Same {
        fn route<'a>(
            &'a self,
            alert: &'a RoutedAlert,
            _: Stage,
            _: &'a mut Tx<'_>,
        ) -> RouteFuture<'a> {
            Box::pin(async move { Decision::new(alert.queue.clone(), "no-op").map(Some) })
        }
    }

    fn routers(added: Vec<(&str, i32, Arc<dyn Router>)>) -> Routers {
        let mut routers = Routers::builtin();
        for (name, priority, router) in added {
            routers = routers.with(name, priority, router).expect("adds");
        }
        routers
    }

    /// An alert, not yet routed, in correlation mode, with an fqdn.
    async fn new_alert(db: &Db) -> (Uuid, i64) {
        let root = NewRoot::new("correlation");
        let mut tx = db.begin().await.expect("begins");
        tree::create_root(&mut tx, &root).await.expect("creates");
        let observable = tree::upsert_observable(
            &mut tx,
            root.id,
            &NewObservable::new(ObservableKind::Fqdn, "evil.example.com"),
        )
        .await
        .expect("adds");
        tx.commit().await.expect("commits");
        sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
            .bind(root.id)
            .execute(db.pool())
            .await
            .expect("makes it an alert");
        (root.id, observable.id.0)
    }

    /// A detection on the observable, or on the root with None, asking for `queue`.
    async fn detect(db: &Db, root: Uuid, observable: Option<i64>, queue: Option<&str>) {
        sqlx::query(
            "INSERT INTO analysis.detections (root_id, observable_id, description, queue)
             VALUES ($1, $2, 'a detection', $3)",
        )
        .bind(root)
        .bind(observable)
        .bind(queue)
        .execute(db.pool())
        .await
        .expect("a detection");
    }

    /// Ends a pass over the root, as the last task of one does.
    async fn complete_pass(db: &Db, root: Uuid) -> Option<i32> {
        let mut tx = db.begin().await.expect("begins");
        queue::begin_pass(&mut tx, root)
            .await
            .expect("begins a pass");
        let pass = queue::check_completion(&mut tx, root)
            .await
            .expect("completes");
        tx.commit().await.expect("commits");
        pass
    }

    /// Routes everything due, as the worker does.
    async fn route_all(service: &Service) -> Vec<RouteOutcome> {
        let mut outcomes = Vec::new();
        while let Some(outcome) = service.route_due(&routing_actor()).await.expect("routes") {
            outcomes.push(outcome);
        }
        outcomes
    }

    async fn queue_of(db: &Db, root: Uuid) -> String {
        sqlx::query_scalar("SELECT queue::text FROM analysis.roots WHERE id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads")
    }

    /// Each move as (from, to, router, moved_by, reason).
    async fn changes(db: &Db, root: Uuid) -> Vec<(String, String, Option<String>, Value, String)> {
        sqlx::query_as(
            "SELECT from_queue::text, to_queue::text, router, moved_by::jsonb, reason
             FROM analysis.queue_changes WHERE root_id = $1 ORDER BY id",
        )
        .bind(root)
        .fetch_all(db.pool())
        .await
        .expect("reads")
    }

    async fn due(db: &Db) -> Vec<(Uuid, i32)> {
        sqlx::query_as("SELECT root_id, pass FROM queue.routing_due ORDER BY root_id, pass")
            .fetch_all(db.pool())
            .await
            .expect("reads")
    }

    fn routing_json() -> Value {
        json!({"kind": "internal", "id": "alert_routing"})
    }

    /// An alert as a router reads it, for the cases that need no database.
    fn alert_with(queue: &str, detections: &[Option<&str>]) -> RoutedAlert {
        RoutedAlert {
            root: Uuid::from_u128(7),
            description: "an alert".to_owned(),
            pass: 1,
            queue: queue.to_owned(),
            disposition: None,
            alerted_at: chrono::Utc::now(),
            detections: detections
                .iter()
                .map(|queue| DetectionPoint {
                    description: "a detection".to_owned(),
                    queue: queue.map(str::to_owned),
                    signature_uuid: None,
                    observable: None,
                })
                .collect(),
            tags: BTreeSet::new(),
            last_change: None,
        }
    }

    fn decided(alert: &RoutedAlert, stage: Stage) -> Option<String> {
        DetectionQueue::decide(alert, stage)
            .expect("decides")
            .map(|decision| decision.queue.as_str().to_owned())
    }

    // test_detection_queue.py

    #[test]
    fn routing_single_routed_detection_sets_queue() {
        let alert = alert_with(DEFAULT_QUEUE, &[Some("experimental")]);
        assert_eq!(
            decided(&alert, Stage::Alerted).as_deref(),
            Some("experimental")
        );
        // a router never changes the alert; the routing applies its decision
        assert_eq!(alert.queue, DEFAULT_QUEUE);
    }

    #[test]
    fn routing_routed_plus_plain_detection_keeps_default() {
        let alert = alert_with(DEFAULT_QUEUE, &[Some("experimental"), None]);
        assert_eq!(decided(&alert, Stage::Alerted), None);
    }

    #[test]
    fn routing_explicit_queue_not_clobbered() {
        let alert = alert_with("incoming", &[Some("experimental")]);
        assert_eq!(decided(&alert, Stage::Alerted), None);
    }

    #[test]
    fn routing_no_detections_leaves_default() {
        assert_eq!(
            decided(&alert_with(DEFAULT_QUEUE, &[]), Stage::Alerted),
            None
        );
    }

    #[test]
    fn routing_conflicting_queues_pick_sorted_first() {
        let alert = alert_with(DEFAULT_QUEUE, &[Some("bravo"), Some("alpha")]);
        assert_eq!(decided(&alert, Stage::Alerted).as_deref(), Some("alpha"));
    }

    /// Detections on observables, the real YARA path, are read, through the routing itself.
    #[tokio::test]
    async fn routing_routed_detection_on_observable() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db);
        let (root, observable) = new_alert(db).await;
        detect(db, root, Some(observable), Some("experimental")).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(queue_of(db, root).await, "experimental");
    }

    /// The alert's detections include the root's own (ace3's FR-24), so a plain one there keeps the default
    /// queue though an observable's asks for one.
    #[tokio::test]
    async fn routing_a_plain_detection_on_the_root_keeps_the_default_queue() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db);
        let (root, observable) = new_alert(db).await;
        detect(db, root, Some(observable), Some("experimental")).await;
        detect(db, root, None, None).await;
        complete_pass(db, root).await;
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].decision, None);
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
    }

    #[test]
    fn routing_only_when_the_alert_is_created() {
        let alert = alert_with(DEFAULT_QUEUE, &[Some("experimental")]);
        assert_eq!(decided(&alert, Stage::Analyzed), None);
    }

    // test_registry.py

    #[test]
    fn routing_the_built_in_router_is_always_present() {
        assert_eq!(Routers::builtin().names(), [(DETECTION_QUEUE, 500)]);
        let configured = Routers::builtin()
            .configured(&RouterTypes::new(), &BTreeMap::new())
            .expect("nothing to build");
        assert_eq!(configured.names(), [(DETECTION_QUEUE, 500)]);
        let added = routers(vec![("added", 100, fixed("x", ALERTED))]);
        assert_eq!(added.names(), [("added", 100), (DETECTION_QUEUE, 500)]);
    }

    #[tokio::test]
    async fn routing_lowest_priority_runs_first_and_the_first_decision_wins() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let late = fixed("late", ALERTED);
        let early = fixed("early", ALERTED);
        let routers = routers(vec![
            ("late", 300, late.clone()),
            ("early", 100, early.clone()),
        ]);
        assert_eq!(
            routers.names(),
            [("early", 100), ("late", 300), (DETECTION_QUEUE, 500)]
        );
        let mut tx = db.begin().await.expect("begins");
        let decision = routers
            .decide(&alert_with(DEFAULT_QUEUE, &[]), Stage::Alerted, &mut tx)
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(decision.queue.as_str(), "early");
        // the registry names the router that decided
        assert_eq!(decision.router, "early");
        assert_eq!(late.calls.load(Ordering::SeqCst), 0);
    }

    /// A router ahead of 500 decides before a detection's queue does (ace3's FR-2: the SVS marker router must
    /// see an alert before a YARA rule's `queue` meta takes it).
    #[tokio::test]
    async fn routing_ahead_of_the_detection_queue_router() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let routers = routers(vec![("marker", 100, fixed("svs", ALERTED))]);
        let mut tx = db.begin().await.expect("begins");
        let decision = routers
            .decide(
                &alert_with(DEFAULT_QUEUE, &[Some("experimental")]),
                Stage::Alerted,
                &mut tx,
            )
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(
            (decision.queue.as_str(), decision.router.as_str()),
            ("svs", "marker")
        );
    }

    #[tokio::test]
    async fn routing_stages_are_passed_through() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let routers = routers(vec![("post_only", 100, fixed("moved", ANALYZED))]);
        let alert = alert_with(DEFAULT_QUEUE, &[]);
        let mut tx = db.begin().await.expect("begins");
        assert_eq!(
            routers
                .decide(&alert, Stage::Alerted, &mut tx)
                .await
                .expect("decides"),
            None
        );
        let decision = routers
            .decide(&alert, Stage::Analyzed, &mut tx)
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(decision.queue.as_str(), "moved");
    }

    #[test]
    fn routing_names_are_unique() {
        let routers = routers(vec![("twice", 100, Arc::new(Recording::default()))]);
        assert!(
            routers
                .clone()
                .with("twice", 200, Arc::new(Recording::default()))
                .is_err()
        );
        let error = routers
            .with(DETECTION_QUEUE, 200, Arc::new(Recording::default()))
            .expect_err("a built-in's name");
        assert!(error.contains("built-in"), "{error}");
    }

    /// The log line ace3 asserts, through a subscriber of this thread's own: the test runtime polls
    /// everything on this thread.
    #[tokio::test(flavor = "current_thread")]
    async fn routing_the_decision_is_logged() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let routers = routers(vec![("logged", 100, fixed("logged_queue", ALERTED))]);
        let alert = alert_with(DEFAULT_QUEUE, &[]);
        let mut tx = db.begin().await.expect("begins");
        routers
            .decide(&alert, Stage::Alerted, &mut tx)
            .await
            .expect("decides");
        let log = String::from_utf8(captured.0.lock().expect("a lock").clone()).expect("UTF-8");
        let line = log
            .lines()
            .find(|line| line.contains("alert router decided a queue"))
            .unwrap_or_else(|| panic!("no decision line in {log}"));
        for field in [
            format!("alert_uuid={}", alert.root),
            "stage=\"alerted\"".to_owned(),
            "router=\"logged\"".to_owned(),
            "queue=\"logged_queue\"".to_owned(),
        ] {
            assert!(line.contains(&field), "{field} in {line}");
        }
    }

    /// A router that fails, or panics, is skipped and the next one decides; what it wrote is undone.
    #[tokio::test]
    async fn routing_a_raising_router_is_reported_and_skipped() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let (root, _) = new_alert(db).await;
        let routers = routers(vec![
            ("broken", 100, Arc::new(Failing)),
            ("panics", 110, Arc::new(Panicking)),
            ("fallback", 200, fixed("fallback", ALERTED)),
        ]);
        let alert = RoutedAlert {
            root,
            ..alert_with(DEFAULT_QUEUE, &[])
        };
        let mut tx = db.begin().await.expect("begins");
        let decision = routers
            .decide(&alert, Stage::Alerted, &mut tx)
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(decision.router, "fallback");
        let description: String =
            sqlx::query_scalar("SELECT description FROM analysis.roots WHERE id = $1")
                .bind(root)
                .fetch_one(tx.conn())
                .await
                .expect("the transaction still works");
        assert_eq!(description, "", "the failed router's write was rolled back");
    }

    #[tokio::test]
    async fn routing_a_router_returning_something_else_is_skipped() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let routers = routers(vec![
            ("bad", 100, Arc::new(BadQueue)),
            ("fallback", 200, fixed("fallback", ALERTED)),
        ]);
        let mut tx = db.begin().await.expect("begins");
        let decision = routers
            .decide(&alert_with(DEFAULT_QUEUE, &[]), Stage::Alerted, &mut tx)
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(decision.queue.as_str(), "fallback");
    }

    #[test]
    fn routing_a_decision_needs_a_usable_queue() {
        for queue in ["", "   ", &"q".repeat(65), "a\u{7}bell"] {
            assert!(Decision::new(queue, "x").is_err(), "{queue:?}");
        }
        assert!(Decision::new("q".repeat(64), "x").is_ok());
        assert!(
            Decision::new("ok", "r".repeat(1025)).is_err(),
            "a reason fits its column"
        );
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixedSettings {
        queue: String,
    }

    fn types() -> RouterTypes {
        RouterTypes::new()
            .with(
                "fixed",
                Arc::new(|settings: &Value| {
                    let settings: FixedSettings = ace_service::routing::settings(settings)?;
                    let queue: &'static str = Box::leak(settings.queue.into_boxed_str());
                    Ok(fixed(queue, ALERTED) as Arc<dyn Router>)
                }),
            )
            .with(
                "cannot_build",
                Arc::new(|_: &Value| Err("cannot build".to_owned())),
            )
    }

    fn entry(kind: &str, priority: i32, settings: Option<Value>) -> AlertRouterSection {
        AlertRouterSection {
            kind: kind.to_owned(),
            priority,
            settings,
        }
    }

    #[tokio::test]
    async fn routing_configured_routers_are_loaded() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let section = BTreeMap::from([(
            "from_config".to_owned(),
            entry("fixed", 150, Some(json!({"queue": "configured"}))),
        )]);
        let routers = Routers::builtin()
            .configured(&types(), &section)
            .expect("loads");
        assert_eq!(
            routers.names(),
            [("from_config", 150), (DETECTION_QUEUE, 500)]
        );
        let mut tx = db.begin().await.expect("begins");
        let decision = routers
            .decide(&alert_with(DEFAULT_QUEUE, &[]), Stage::Alerted, &mut tx)
            .await
            .expect("decides")
            .expect("a decision");
        assert_eq!(decision.queue.as_str(), "configured");
    }

    /// ace3 logs a broken entry and loads the others; here each is named and startup stops.
    #[test]
    fn routing_one_broken_entry_is_named_and_stops_startup() {
        let section = BTreeMap::from([
            ("cannot_build".to_owned(), entry("cannot_build", 100, None)),
            ("missing_type".to_owned(), entry("no_such_type", 110, None)),
            (
                "detection_queue".to_owned(),
                entry("fixed", 140, Some(json!({"queue": "q"}))),
            ),
            (
                "works".to_owned(),
                entry("fixed", 200, Some(json!({"queue": "works"}))),
            ),
        ]);
        let error = Routers::builtin()
            .configured(&types(), &section)
            .expect_err("refused");
        for broken in ["cannot_build", "missing_type", "detection_queue"] {
            assert!(
                error.contains(&format!("alert_routers.{broken}:")),
                "{broken}: {error}"
            );
        }
        assert!(!error.contains("alert_routers.works"), "{error}");
    }

    #[test]
    fn routing_unknown_settings_are_a_load_error() {
        let section = BTreeMap::from([(
            "typo".to_owned(),
            entry("fixed", 100, Some(json!({"queue": "q", "colour": "red"}))),
        )]);
        let error = Routers::builtin()
            .configured(&types(), &section)
            .expect_err("refused");
        assert!(
            error.contains("alert_routers.typo") && error.contains("colour"),
            "{error}"
        );
        // the overlay's own parse refuses an unknown key in an entry
        assert!(
            ace_sdk::Overlay::from_yaml(
                "alert_routers:\n  r:\n    type: fixed\n    priority: 1\n    kwargs: {}\n"
            )
            .is_err()
        );
    }

    // test_alert_routing.py

    #[tokio::test]
    async fn routing_a_decision_becomes_the_alert_s_queue() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service =
            bare_service(db).with_routers(routers(vec![("pre", 100, fixed("routed", ALERTED))]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].stage, Some(Stage::Alerted));
        assert_eq!(
            outcomes[0].moved,
            Some((DEFAULT_QUEUE.to_owned(), "routed".to_owned()))
        );
        assert_eq!(queue_of(db, root).await, "routed");
        assert_eq!(
            changes(db, root).await,
            [(
                DEFAULT_QUEUE.to_owned(),
                "routed".to_owned(),
                Some("pre".to_owned()),
                routing_json(),
                "routed says so".to_owned()
            )]
        );
        let last = service
            .last_queue_change(&admin(db).await, root)
            .await
            .expect("reads")
            .expect("a move");
        assert_eq!(
            (
                last.from_queue.as_str(),
                last.to_queue.as_str(),
                last.router.as_deref()
            ),
            (DEFAULT_QUEUE, "routed", Some("pre"))
        );
        assert_eq!(due(db).await, [], "the routing is done");
    }

    #[tokio::test]
    async fn routing_no_decision_no_change_row() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db);
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
        assert_eq!(changes(db, root).await, []);
        assert_eq!(
            service
                .last_queue_change(&admin(db).await, root)
                .await
                .expect("reads"),
            None
        );
    }

    /// An alert made by a submitter (the hunter's path, a detection in its `Origin`) routes as one a
    /// landing made does (`routing_a_detection_queue_routes_the_alert_a_landing_makes`). ace3 says this used to
    /// run only when the engine converted a root.
    #[tokio::test]
    async fn routing_the_detection_queue_router_runs_for_every_alert_path() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db);
        let (bucket, _cache) = bucket(db);
        let submission: Submission = serde_json::from_value(json!({
            "description": "hunt: routed",
            "analysis_mode": "correlation",
        }))
        .expect("a submission");
        let mut signature = NewObservable::new(ObservableKind::SignatureId, "rule-1");
        signature.detections.push(ace_results::Detection {
            description: "yara hit".to_owned(),
            details: None,
            queue: Some("experimental".to_owned()),
            signature_uuid: Some("rule-1".to_owned()),
            signature_version: None,
            signature_family: None,
        });
        let origin = ace_core::submit::Origin {
            observables: vec![signature],
            ..ace_core::submit::Origin::default()
        };
        let orchestrator = Orchestrator::new(Catalog::new(vec![]), Modes::ace3());
        let new_root =
            ace_core::submit::prepare(&orchestrator, &submission, &origin, &[]).expect("prepares");
        let mut tx = db.begin().await.expect("begins");
        ace_core::submit::create(
            &mut tx,
            &bucket,
            &orchestrator,
            &new_root,
            &submission,
            &origin,
            &[],
        )
        .await
        .expect("creates");
        tx.commit().await.expect("commits");
        route_all(&service).await;
        assert_eq!(queue_of(db, new_root.id).await, "experimental");
        assert_eq!(
            changes(db, new_root.id).await[0].2.as_deref(),
            Some(DETECTION_QUEUE)
        );
    }

    #[tokio::test]
    async fn routing_a_raising_router_never_breaks_the_routing() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service =
            bare_service(db).with_routers(routers(vec![("broken", 100, Arc::new(Failing))]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].decision, None);
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
        assert_eq!(due(db).await, []);
    }

    #[tokio::test]
    async fn routing_a_move_records_who_made_it_and_its_audit_row() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service =
            bare_service(db).with_routers(routers(vec![("triage", 100, fixed("triage", ALERTED))]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(queue_of(db, root).await, "triage");
        assert_eq!(
            last_audit(db).await,
            AuditRow {
                actor: routing_json(),
                action: "route_due".to_owned(),
                target: ("root".to_owned(), root.to_string()),
                before: Some(json!({"queue": DEFAULT_QUEUE})),
                after: Some(json!({"queue": "triage"})),
                details: json!({"router": "triage", "reason": "triage says so", "stage": "alerted", "pass": 1}),
            }
        );
    }

    /// The newest move says what queue the alert came from, which is how a move is reversed.
    #[tokio::test]
    async fn routing_moving_back_restores_through_the_record() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db).with_routers(routers(vec![
            ("svs_marker", 100, fixed("svs", ALERTED)),
            ("back", 110, Arc::new(Back)),
        ]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        let previous = service
            .last_queue_change(&admin(db).await, root)
            .await
            .expect("reads")
            .expect("a move");
        assert_eq!(previous.router.as_deref(), Some("svs_marker"));
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
        let moves: Vec<String> = changes(db, root).await.into_iter().map(|c| c.1).collect();
        assert_eq!(moves, ["svs", DEFAULT_QUEUE]);
    }

    #[tokio::test]
    async fn routing_the_same_queue_is_not_a_move() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db).with_routers(routers(vec![("same", 100, Arc::new(Same))]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        let audits = audit_rows(db).await.len();
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes[0].moved, None);
        assert_eq!(changes(db, root).await, []);
        assert_eq!(
            audit_rows(db).await.len(),
            audits,
            "a no-op has no audit row"
        );
    }

    /// ace3's conditional move: the alert was read OPEN and someone changed it since. Here the routing locks
    /// the root and reads it then, so a disposition made after the pass ended keeps the alert where it is.
    #[tokio::test]
    async fn routing_a_move_judges_the_row_as_it_is_written() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db).with_routers(routers(vec![(
            "svs_marker",
            100,
            fixed("svs", ALERTED),
        )]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        sqlx::query(
            "UPDATE analysis.roots SET disposition = 'FALSE_POSITIVE', dispositioned_at = now(),
                    dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}' WHERE id = $1",
        )
        .bind(root)
        .execute(db.pool())
        .await
        .expect("dispositions it");
        let outcomes = route_all(&service).await;
        assert_eq!(
            outcomes[0].decision.as_ref().map(|d| d.router.as_str()),
            Some("svs_marker")
        );
        assert_eq!(outcomes[0].moved, None);
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
        assert_eq!(changes(db, root).await, []);
    }

    #[tokio::test]
    async fn routing_a_bad_queue_is_refused() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service =
            bare_service(db).with_routers(routers(vec![("bad", 100, Arc::new(BadQueue))]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
        // and the database holds the same rule
        for queue in ["", "   ", &"q".repeat(65)] {
            assert!(
                sqlx::query("UPDATE analysis.roots SET queue = $2 WHERE id = $1")
                    .bind(root)
                    .bind(queue)
                    .execute(db.pool())
                    .await
                    .is_err(),
                "{queue:?}"
            );
        }
    }

    #[tokio::test]
    async fn routing_an_open_alert_is_moved_after_a_later_pass() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db).with_routers(routers(vec![(
            "post",
            100,
            fixed("post_queue", ANALYZED),
        )]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(
            queue_of(db, root).await,
            DEFAULT_QUEUE,
            "not at the first routing"
        );
        complete_pass(db, root).await;
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes[0].stage, Some(Stage::Analyzed));
        assert_eq!(queue_of(db, root).await, "post_queue");
        assert_eq!(changes(db, root).await[0].2.as_deref(), Some("post"));
    }

    /// Through the service's own disposition, whose pass in dispositioned mode completes and routes.
    #[tokio::test]
    async fn routing_a_dispositioned_alert_is_not_moved() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = bare_service(db).with_routers(routers(vec![(
            "post",
            100,
            fixed("post_queue", ANALYZED),
        )]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        service
            .disposition(&admin(db).await, root, "FALSE_POSITIVE")
            .await
            .expect("dispositions");
        if due(db).await.is_empty() {
            complete_pass(db, root).await;
        }
        let outcomes = route_all(&service).await;
        assert_eq!(outcomes.last().and_then(|o| o.stage), Some(Stage::Analyzed));
        assert_eq!(queue_of(db, root).await, DEFAULT_QUEUE);
    }

    #[tokio::test]
    async fn routing_the_first_routing_is_the_alerted_stage_once() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let recording = Arc::new(Recording::default());
        let service =
            bare_service(db).with_routers(routers(vec![("final", 100, recording.clone())]));
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(*recording.0.lock().expect("a lock"), [Stage::Alerted]);
        complete_pass(db, root).await;
        route_all(&service).await;
        // two passes that end before the worker gets to them route once, after the later
        complete_pass(db, root).await;
        complete_pass(db, root).await;
        route_all(&service).await;
        assert_eq!(
            *recording.0.lock().expect("a lock"),
            [Stage::Alerted, Stage::Analyzed, Stage::Analyzed]
        );
    }

    /// A root that isn't an alert has nothing due when its pass completes; an alert's is due once per pass.
    #[tokio::test]
    async fn routing_runs_when_the_pass_completes() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let (root, _) = new_alert(db).await;
        let (plain, _) = new_alert(db).await;
        sqlx::query("UPDATE analysis.roots SET alerted_at = NULL WHERE id = $1")
            .bind(plain)
            .execute(db.pool())
            .await
            .expect("not an alert");
        let pass = complete_pass(db, root).await.expect("a pass");
        complete_pass(db, plain).await.expect("a pass");
        assert_eq!(due(db).await, [(root, pass)]);
    }

    /// ace3's pass with delayed analysis isn't final; here it doesn't complete, so nothing routes yet.
    #[tokio::test]
    async fn routing_waits_while_a_task_is_delayed() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let recording = Arc::new(Recording::default());
        let service =
            bare_service(db).with_routers(routers(vec![("final", 100, recording.clone())]));
        let (root, observable) = new_alert(db).await;
        let mut tx = db.begin().await.expect("begins");
        queue::enqueue(
            &mut tx,
            root,
            tree::ObservableId(observable),
            "rdap_analyzer",
        )
        .await
        .expect("queues");
        tx.commit().await.expect("commits");
        sqlx::query("UPDATE queue.tasks SET state = 'delayed', run_after = now() + interval '1 hour' WHERE root_id = $1")
            .bind(root)
            .execute(db.pool())
            .await
            .expect("delays it");
        let mut tx = db.begin().await.expect("begins");
        assert_eq!(
            queue::check_completion(&mut tx, root)
                .await
                .expect("checks"),
            None
        );
        tx.commit().await.expect("commits");
        assert_eq!(route_all(&service).await, []);
        assert!(recording.0.lock().expect("a lock").is_empty());
    }

    /// ace3's aborted pass is final; here a cancelled pass completes, and routes.
    #[tokio::test]
    async fn routing_runs_after_a_cancelled_pass() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let recording = Arc::new(Recording::default());
        let service =
            bare_service(db).with_routers(routers(vec![("final", 100, recording.clone())]));
        let (root, observable) = new_alert(db).await;
        let mut tx = db.begin().await.expect("begins");
        queue::enqueue(
            &mut tx,
            root,
            tree::ObservableId(observable),
            "rdap_analyzer",
        )
        .await
        .expect("queues");
        // which ends the pass, its one task cancelled
        queue::cancel_root(&mut tx, root).await.expect("cancels");
        tx.commit().await.expect("commits");
        assert_eq!(queue::completions(db, root).await.expect("reads").len(), 1);
        route_all(&service).await;
        assert_eq!(*recording.0.lock().expect("a lock"), [Stage::Alerted]);
    }

    /// ace3's TestEngine: a module's detection with a queue makes the root an alert, its pass completes, and
    /// the detection queue router routes it.
    #[tokio::test]
    async fn routing_a_detection_queue_routes_the_alert_a_landing_makes() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service = service(db);
        let orchestrator = orchestrator();
        let root = NewRoot::new("analysis");
        let mut tx = db.begin().await.expect("begins");
        tree::create_root(&mut tx, &root).await.expect("creates");
        tree::upsert_observable(
            &mut tx,
            root.id,
            &NewObservable::new(ObservableKind::Fqdn, "evil.example.com"),
        )
        .await
        .expect("adds");
        orchestrator.start(&mut tx, root.id).await.expect("starts");
        tx.commit().await.expect("commits");
        let worker = queue::Worker::new(
            db.clone(),
            "test/routing",
            vec!["rdap_analyzer".to_owned()],
            Duration::from_secs(60),
        );
        let task = worker.claim().await.expect("claims").expect("a task");
        let result: ace_results::ResultEnvelope<Value> = serde_json::from_value(json!({
            "analysis_type": "test_stub",
            "schema_version": 1,
            "details": {"note": "a hit"},
            "detections": [{"description": "yara hit", "queue": "experimental"}],
        }))
        .expect("a result");
        let mut tx = db.begin().await.expect("begins");
        let landed = orchestrator
            .land_result(&mut tx, &worker, &task, &result)
            .await
            .expect("lands");
        tx.commit().await.expect("commits");
        assert_eq!(landed.mode_changed_to.as_deref(), Some("correlation"));
        assert!(
            queue::root_is_idle(db, root.id).await.expect("reads"),
            "the pass completed"
        );
        route_all(&service).await;
        assert_eq!(queue_of(db, root.id).await, "experimental");
        let moves = changes(db, root.id).await;
        assert_eq!(
            (
                moves[0].0.as_str(),
                moves[0].1.as_str(),
                moves[0].2.as_deref()
            ),
            (DEFAULT_QUEUE, "experimental", Some(DETECTION_QUEUE))
        );
    }

    /// The worker routes on 2.11's completion event, as `ace serve` runs it.
    #[tokio::test]
    async fn routing_runs_on_the_completion_event() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let service =
            bare_service(db).with_routers(routers(vec![("pre", 100, fixed("routed", ALERTED))]));
        let stop = tokio_util::sync::CancellationToken::new();
        // a long poll, so only the notification can wake it in time
        let worker = tokio::spawn(ace_service::routing::run_worker(
            service,
            Duration::from_secs(600),
            stop.clone(),
        ));
        // the worker listens once it finds nothing due
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (root, _) = new_alert(db).await;
        complete_pass(db, root).await;
        let started = Instant::now();
        while queue_of(db, root).await != "routed" {
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "routed on the event"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        stop.cancel();
        worker.await.expect("the worker stops");
    }

    /// The service's audit tests' case for `route_due`.
    pub(super) async fn routable(db: &Db) -> Uuid {
        let (root, observable) = new_alert(db).await;
        detect(db, root, Some(observable), Some("audited_queue")).await;
        complete_pass(db, root).await;
        root
    }

    pub(super) async fn route_due_records_its_row(db: &Db) -> String {
        let root = routable(db).await;
        let service = bare_service(db);
        let outcomes = route_all(&service).await;
        assert!(outcomes.iter().any(|o| o.root == root && o.moved.is_some()));
        let row = audit_rows(db)
            .await
            .into_iter()
            .rfind(|row| row.target == ("root".to_owned(), root.to_string()))
            .expect("its row");
        assert_eq!(
            row,
            AuditRow {
                actor: routing_json(),
                action: "route_due".to_owned(),
                target: ("root".to_owned(), root.to_string()),
                before: Some(json!({"queue": DEFAULT_QUEUE})),
                after: Some(json!({"queue": "audited_queue"})),
                details: json!({
                    "router": DETECTION_QUEUE,
                    "reason": "every detection point requests this queue",
                    "stage": "alerted",
                    "pass": 1,
                }),
            }
        );
        row.action
    }

    /// What routing keeps of an alert, to compare before and after a failed routing.
    pub(super) async fn routing_rows(db: &Db, root: Uuid) -> (String, usize, Vec<(Uuid, i32)>) {
        let due = due(db)
            .await
            .into_iter()
            .filter(|(r, _)| *r == root)
            .collect();
        (queue_of(db, root).await, changes(db, root).await.len(), due)
    }
}

// PLAN.md 7.10 batch 4: ace3's `tests/saq/svs/test_catalog.py` as Rust tests, with the catalog's cases of
// `tests/aceapi_v2/svs/test_catalog.py` that are the service's. Each repository here is a bare origin a
// working clone pushes to, as ace3's test checkout is one `service_git` keeps, and a refresh fetches it into
// a mirror of its own. The cases and where they went:
//
// test_catalog.py (18):
//   test_parse_atomics: ace-core's svs::catalog parse_atomics_reads_the_tests and
//     the_glob_is_atomics_t_t_yaml.
//   test_the_content_hash_follows_the_test_only: ace-core's the_content_hash_follows_the_test_only.
//   test_refresh_reads_the_tests: refresh_reads_the_tests.
//   test_refresh_reads_again_only_when_the_commit_changes: refresh_reads_again_only_when_the_commit_changes.
//   test_changes_removals_and_returns: changes_removals_and_returns.
//   test_a_repository_taken_out_of_the_config_is_retired: a_repository_taken_out_of_the_config_is_retired.
//   test_retiring_leaves_the_configured_repositories_alone: retiring_leaves_the_configured_repositories_alone.
//   test_a_guid_of_another_repository_is_not_taken: a_guid_of_another_repository_is_not_taken.
//   test_a_commit_that_moves_while_reading_stores_nothing: no counterpart. ace3 reads a working tree
//     `service_git` may pull under it; here a refresh reads one commit's objects from its own mirror, so
//     nothing can move (refresh_reads_the_tests checks every row is that commit's).
//   test_refresh_errors_are_recorded (3 parameters): refresh_errors_are_recorded has `unlisted` and
//     `no_checkout`, which here is a repository that can't be fetched; `no_section` has no counterpart, as
//     the overlay's entry is the repository's whole setting.
//   test_an_error_keeps_the_tests_and_clears_on_the_next_success:
//     an_error_keeps_the_tests_and_clears_on_the_next_success.
//   test_the_service_refreshes_the_catalog, test_the_refresher_runs_until_stopped_and_survives_a_failure:
//     ace-app's scheduler tests, svs_catalog_refresh_reads_the_catalog and
//     svs_catalog_refresh_survives_a_failure.
//   test_the_refresher_stays_idle_off_the_primary_node: no counterpart. ace4 has no primary node: every
//     replica's scheduler shares the task through its claim (6.7's two-replica test).
//   test_cli_refresh_and_status, test_cli_refresh_reports_a_retired_repository,
//     test_cli_refresh_reports_an_error: ace-app's svs tests of the same names.
//   test_repository_status: repository_status.
// test_svs_cli.py: test_catalog_refresh_with_no_repositories: ace-app's
//   catalog_refresh_with_no_repositories.
// tests/aceapi_v2/svs/test_catalog.py: test_ordered_by_technique_then_name, test_filters (9 parameters),
//   test_a_bad_filter_is_422, test_pages and test_detail are catalog_tests_are_listed_filtered_and_paged
//   here and ace-api's svs_catalog tests; test_exports, test_permissions and test_repositories are
//   ace-api's; test_each_tests_state_and_runs waits for the runs and decisions of batches 5 and 8.
mod svs_catalog_tests {
    use super::*;
    use ace_core::svs::catalog::{self, AtomicFile, CatalogConfig, CatalogLimits, RETIRED_ERROR};
    use ace_core::testing::rule_repo::RuleRepo;
    use ace_service::{CatalogRefresh, CatalogTestQuery};

    const REPOSITORY: &str = "art_unittest";
    pub(super) const GUID_A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const GUID_B: &str = "bbbbbbbb-2222-4222-8222-222222222222";
    const GUID_C: &str = "cccccccc-3333-4333-8333-333333333333";
    const T1003: &str = "atomics/T1003/T1003.yaml";
    const T1105: &str = "atomics/T1105/T1105.yaml";

    /// One test of an atomic file, as ace3's test helper `_test` writes it.
    fn atomic_test(name: &str, guid: Option<&str>, command: &str) -> String {
        let guid = guid.map_or(String::new(), |g| format!("  auto_generated_guid: {g}\n"));
        format!(
            "- name: {name}\n{guid}  description: |\n    {name} does a thing\n  supported_platforms:\n  - windows\n  \
             input_arguments:\n    output_file:\n      description: where\n      type: path\n      default: out.txt\n  \
             executor:\n    name: powershell\n    command: {command}\n    elevation_required: false\n"
        )
    }

    fn atomic(technique: &str, display_name: &str, tests: &[String]) -> String {
        format!(
            "attack_technique: {technique}\ndisplay_name: {display_name}\natomic_tests:\n{}",
            tests.concat()
        )
    }

    fn dumping(tests: &[String]) -> String {
        atomic("T1003", "OS Credential Dumping", tests)
    }

    fn transfer(tests: &[String]) -> String {
        atomic("T1105", "Ingress Tool Transfer", tests)
    }

    /// Catalog repositories, each a bare origin a working clone pushes to, and the settings that name
    /// them, with a mirror directory of their own.
    pub(super) struct Art {
        repos: BTreeMap<String, RuleRepo>,
        section: ace_sdk::SvsCatalogSection,
        tmp: tempfile::TempDir,
    }

    pub(super) fn art(names: &[&str]) -> Art {
        let tmp = tempfile::tempdir().expect("a directory");
        let repos: BTreeMap<String, RuleRepo> = names
            .iter()
            .map(|name| ((*name).to_owned(), RuleRepo::new(&tmp.path().join(name))))
            .collect();
        let section = ace_sdk::SvsCatalogSection {
            repositories: repos
                .iter()
                .map(|(name, repo)| {
                    (
                        name.clone(),
                        ace_sdk::SvsCatalogRepository {
                            url: repo.origin.to_string_lossy().into_owned(),
                            branch: "main".to_owned(),
                            ssh_key: None,
                        },
                    )
                })
                .collect(),
            mirror_dir: Some(tmp.path().join("mirrors")),
            ..ace_sdk::SvsCatalogSection::default()
        };
        Art {
            repos,
            section,
            tmp,
        }
    }

    impl Art {
        fn config(&self) -> CatalogConfig {
            CatalogConfig::from_section(&self.section).expect("valid settings")
        }

        pub(super) fn service(&self, db: &Db) -> Service {
            service(db).with_catalog(self.config())
        }

        /// The service with only `names` of the repositories in its overlay.
        fn listing(&self, db: &Db, names: &[&str]) -> Service {
            let mut section = self.section.clone();
            section
                .repositories
                .retain(|name, _| names.contains(&name.as_str()));
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"))
        }

        /// Writes (or, for None, deletes) the files of `repository`, commits and pushes; the commit's id.
        pub(super) fn commit_in(&self, repository: &str, files: &[(&str, Option<&str>)]) -> String {
            let files: Vec<(&str, Option<&[u8]>)> = files
                .iter()
                .map(|(path, content)| (*path, content.map(str::as_bytes)))
                .collect();
            self.repos[repository].commit_with(&files, "main", &[])
        }

        pub(super) fn commit(&self, files: &[(&str, Option<&str>)]) -> String {
            self.commit_in(REPOSITORY, files)
        }
    }

    pub(super) fn refresher() -> Actor {
        component("scheduler:svs_catalog_refresh")
    }

    async fn refresh(service: &Service) -> Vec<CatalogRefresh> {
        service
            .refresh_svs_catalog(&refresher(), None, false)
            .await
            .expect("refreshes")
    }

    async fn refresh_one(service: &Service, repository: &str, force: bool) -> CatalogRefresh {
        service
            .refresh_svs_catalog(&refresher(), Some(repository), force)
            .await
            .expect("refreshes")
            .pop()
            .expect("one result")
    }

    #[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
    struct StoredTest {
        guid: Uuid,
        repository: String,
        technique: String,
        technique_name: Option<String>,
        name: String,
        description: Option<String>,
        platforms: Vec<String>,
        executor: Option<String>,
        test: Value,
        content_hash: String,
        commit: String,
        path: String,
        removed: bool,
        updated_at: chrono::DateTime<Utc>,
    }

    async fn stored_tests(db: &Db) -> BTreeMap<String, StoredTest> {
        sqlx::query_as::<_, StoredTest>(
            "SELECT guid, repository, technique, technique_name, name, description, platforms, executor, test,
                    content_hash, commit, path, removed_at IS NOT NULL AS removed, updated_at
             FROM svs.catalog_tests",
        )
        .fetch_all(db.pool())
        .await
        .expect("reads")
        .into_iter()
        .map(|test| (test.guid.to_string(), test))
        .collect()
    }

    /// A repository's row: its commit, test count, skipped count and error.
    async fn repository(db: &Db, name: &str) -> (Option<String>, i32, i32, Option<String>) {
        sqlx::query_as(
            "SELECT commit, test_count, skipped_count, error FROM svs.catalog_repositories WHERE name = $1",
        )
        .bind(name)
        .fetch_one(db.pool())
        .await
        .expect("the repository's row")
    }

    /// Every catalog row, as text, for the audit failure test.
    pub(super) async fn catalog_rows(db: &Db) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT 'test ' || row_to_json(t)::text FROM svs.catalog_tests t
             UNION ALL SELECT 'repository ' || row_to_json(r)::text FROM svs.catalog_repositories r
             ORDER BY 1",
        )
        .fetch_all(db.pool())
        .await
        .expect("reads")
    }

    async fn audit_count(db: &Db) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM service.audit")
            .fetch_one(db.pool())
            .await
            .expect("counts")
    }

    /// test_catalog.py's `test_refresh_reads_the_tests`: a refresh stores each test of the branch's commit
    /// with its technique, name, platforms, executor and entry, counts the one it skipped, and records the
    /// commit on the repository's row. Every row is that commit's: a refresh reads one commit's objects.
    #[tokio::test]
    async fn refresh_reads_the_tests() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        let commit = art.commit(&[(
            "atomics/T1059.001/T1059.001.yaml",
            Some(&atomic(
                "T1059.001",
                "PowerShell",
                &[
                    atomic_test("Mimikatz", Some(GUID_A), "whoami"),
                    atomic_test("No guid", None, "whoami"),
                ],
            )),
        )]);

        let result = refresh_one(&art.service(db), REPOSITORY, false).await;

        assert!(result.refreshed && result.error.is_none(), "{result:?}");
        assert_eq!(
            (
                result.commit.as_deref(),
                result.tests,
                result.added,
                result.skipped.len()
            ),
            (Some(commit.as_str()), 1, 1, 1)
        );
        assert_eq!(
            (
                result.skipped[0].path.as_str(),
                result.skipped[0].name.as_deref(),
                result.skipped[0].reason.as_str()
            ),
            (
                "atomics/T1059.001/T1059.001.yaml",
                Some("No guid"),
                "no auto_generated_guid"
            )
        );
        let tests = stored_tests(db).await;
        assert_eq!(tests.len(), 1);
        let test = &tests[GUID_A];
        assert_eq!(
            (
                test.repository.as_str(),
                test.technique.as_str(),
                test.technique_name.as_deref(),
                test.name.as_str()
            ),
            (REPOSITORY, "T1059.001", Some("PowerShell"), "Mimikatz")
        );
        assert_eq!(test.platforms, ["windows"]);
        assert_eq!(test.executor.as_deref(), Some("powershell"));
        assert_eq!(test.description.as_deref(), Some("Mimikatz does a thing"));
        assert_eq!(test.test["executor"]["command"], "whoami");
        assert_eq!(
            test.test["input_arguments"]["output_file"]["default"],
            "out.txt"
        );
        assert_eq!(test.path, "atomics/T1059.001/T1059.001.yaml");
        assert!(test.commit == commit && !test.removed);
        assert_eq!(repository(db, REPOSITORY).await, (Some(commit), 1, 1, None));
    }

    /// test_catalog.py's `test_refresh_reads_again_only_when_the_commit_changes`: a refresh of a commit
    /// already read stores nothing, which the repository's row, the tests' rows and the audit table show
    /// (ace3's test counts calls of its parser); `force` reads it anyway.
    #[tokio::test]
    async fn refresh_reads_again_only_when_the_commit_changes() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        let commit = art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        let service = art.service(db);
        assert!(refresh_one(&service, REPOSITORY, false).await.refreshed);
        let (rows, audits) = (catalog_rows(db).await, audit_count(db).await);

        let again = refresh_one(&service, REPOSITORY, false).await;
        assert!(!again.refreshed && again.error.is_none(), "{again:?}");
        assert_eq!(again.commit.as_deref(), Some(commit.as_str()));
        assert_eq!(catalog_rows(db).await, rows, "nothing was written");
        assert_eq!(audit_count(db).await, audits);

        // --force reads it anyway
        let forced = refresh_one(&service, REPOSITORY, true).await;
        assert!(forced.refreshed, "{forced:?}");
        assert_eq!(
            (forced.tests, forced.added, forced.changed, forced.removed),
            (1, 0, 0, 0)
        );
        assert_eq!(audit_count(db).await, audits + 1);
        assert!(!stored_tests(db).await[GUID_A].removed);
    }

    /// test_catalog.py's `test_changes_removals_and_returns`: a test the commit didn't change keeps the
    /// commit it was first read from and its `updated_at`; a test that disappears keeps its row, so its
    /// runs keep their test, and comes back when its file does.
    #[tokio::test]
    async fn changes_removals_and_returns() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        let service = art.service(db);
        let first = art.commit(&[(
            T1003,
            Some(&dumping(&[
                atomic_test("Dump", Some(GUID_A), "whoami"),
                atomic_test("Keep", Some(GUID_B), "whoami"),
            ])),
        )]);
        refresh_one(&service, REPOSITORY, false).await;
        let before = stored_tests(db).await;

        // B unchanged, A changed, C added; then A removed
        let second = art.commit(&[
            (
                T1003,
                Some(&dumping(&[
                    atomic_test("Dump", Some(GUID_A), "id"),
                    atomic_test("Keep", Some(GUID_B), "whoami"),
                ])),
            ),
            (
                T1105,
                Some(&transfer(&[atomic_test("Copy", Some(GUID_C), "whoami")])),
            ),
        ]);
        let result = refresh_one(&service, REPOSITORY, false).await;
        assert_eq!((result.added, result.changed, result.removed), (1, 1, 0));
        let tests = stored_tests(db).await;
        assert_eq!(tests[GUID_A].commit, second);
        assert_ne!(tests[GUID_A].content_hash, before[GUID_A].content_hash);
        assert_eq!(tests[GUID_A].test["executor"]["command"], "id");
        assert!(tests[GUID_A].updated_at > before[GUID_A].updated_at);
        assert_eq!(tests[GUID_B].commit, first);
        assert_eq!(tests[GUID_B].updated_at, before[GUID_B].updated_at);

        art.commit(&[
            (
                T1003,
                Some(&dumping(&[atomic_test("Keep", Some(GUID_B), "whoami")])),
            ),
            (T1105, None),
        ]);
        let result = refresh_one(&service, REPOSITORY, false).await;
        assert_eq!(result.removed, 2);
        let tests = stored_tests(db).await;
        assert!(tests[GUID_A].removed && tests[GUID_C].removed && !tests[GUID_B].removed);
        assert_eq!(repository(db, REPOSITORY).await.1, 1);

        // and comes back
        art.commit(&[(
            T1105,
            Some(&transfer(&[atomic_test("Copy", Some(GUID_C), "whoami")])),
        )]);
        let result = refresh_one(&service, REPOSITORY, false).await;
        assert_eq!((result.added, result.changed, result.removed), (0, 1, 0));
        assert!(!stored_tests(db).await[GUID_C].removed);
    }

    /// test_catalog.py's `test_a_repository_taken_out_of_the_config_is_retired`: its tests keep their rows,
    /// removed; nothing is left to retire next time; and listed again, it is read again although its
    /// commit did not change.
    #[tokio::test]
    async fn a_repository_taken_out_of_the_config_is_retired() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[
                atomic_test("Dump", Some(GUID_A), "whoami"),
                atomic_test("Keep", Some(GUID_B), "whoami"),
            ])),
        )]);
        refresh(&art.service(db)).await;

        let unlisted = art.listing(db, &[]);
        let results = refresh(&unlisted).await;
        let shown: Vec<(&str, bool, i64, Option<&str>)> = results
            .iter()
            .map(|r| {
                (
                    r.repository.as_str(),
                    r.retired,
                    r.removed,
                    r.error.as_deref(),
                )
            })
            .collect();
        assert_eq!(shown, [(REPOSITORY, true, 2, None)]);
        assert!(stored_tests(db).await.values().all(|test| test.removed));
        let (_, count, _, error) = repository(db, REPOSITORY).await;
        assert_eq!((count, error.as_deref()), (0, Some(RETIRED_ERROR)));
        // a retired repository can't be retired while the overlay lists it
        assert!(matches!(
            art.service(db)
                .retire_svs_catalog_repository(&refresher(), REPOSITORY)
                .await,
            Err(ServiceError::InvalidRequest(_))
        ));

        // nothing is left to retire on the next refresh
        assert!(refresh(&unlisted).await.is_empty());

        // listed again, it is read again although its commit did not change
        let results = refresh(&art.service(db)).await;
        assert!(results[0].refreshed, "{results:?}");
        assert!(stored_tests(db).await.values().all(|test| !test.removed));
        assert_eq!(repository(db, REPOSITORY).await.3, None);
    }

    /// test_catalog.py's `test_retiring_leaves_the_configured_repositories_alone`: a test of a repository
    /// that was never configured here, with no repository row, is retired; the configured one's stay.
    #[tokio::test]
    async fn retiring_leaves_the_configured_repositories_alone() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        sqlx::query(
            "INSERT INTO svs.catalog_tests
                 (guid, repository, technique, name, platforms, test, content_hash, commit, path)
             VALUES ($1, 'hand_made', 'T1105', 'Copy', '{}', '{}', repeat('0', 64), repeat('1', 40), $2)",
        )
        .bind(Uuid::parse_str(GUID_C).expect("a uuid"))
        .bind(T1105)
        .execute(db.pool())
        .await
        .expect("a test of a repository with no row");

        let results = refresh(&art.service(db)).await;

        let shown: Vec<(&str, bool, i64)> = results
            .iter()
            .map(|r| (r.repository.as_str(), r.retired, r.removed))
            .collect();
        assert_eq!(shown, [(REPOSITORY, false, 0), ("hand_made", true, 1)]);
        let tests = stored_tests(db).await;
        assert!(!tests[GUID_A].removed && tests[GUID_C].removed);
    }

    /// test_catalog.py's `test_a_guid_of_another_repository_is_not_taken`: the first repository read keeps
    /// the guid, and the other's test is skipped with the reason.
    #[tokio::test]
    async fn a_guid_of_another_repository_is_not_taken() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        // repositories are read in the order of their names
        let art = art(&[REPOSITORY, "custom_atomics"]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        art.commit_in(
            "custom_atomics",
            &[(
                T1003,
                Some(&dumping(&[atomic_test(
                    "Copy of dump",
                    Some(GUID_A),
                    "whoami",
                )])),
            )],
        );

        let results = refresh(&art.service(db)).await;

        let counts: Vec<(&str, i64)> = results
            .iter()
            .map(|r| (r.repository.as_str(), r.tests))
            .collect();
        assert_eq!(counts, [(REPOSITORY, 1), ("custom_atomics", 0)]);
        assert!(
            results[1].skipped[0]
                .reason
                .contains("belongs to a test of art_unittest"),
            "{:?}",
            results[1].skipped
        );
        assert_eq!(stored_tests(db).await[GUID_A].name, "Dump");
        assert_eq!(repository(db, "custom_atomics").await.1, 0);
        assert_eq!(repository(db, "custom_atomics").await.2, 1);
    }

    /// test_catalog.py's `test_refresh_errors_are_recorded`: a repository that isn't in the overlay, and one
    /// that can't be fetched (ace3's checkout that doesn't exist yet), leave their error on a row with no
    /// commit. The error never holds the repository's URL.
    #[tokio::test]
    async fn refresh_errors_are_recorded() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);

        // unlisted
        let result = refresh_one(&art.listing(db, &[]), REPOSITORY, false).await;
        assert!(!result.refreshed);
        let message = "art_unittest is not in svs.catalog.repositories";
        assert_eq!(result.error.as_deref(), Some(message));
        assert_eq!(
            repository(db, REPOSITORY).await,
            (None, 0, 0, Some(message.to_owned()))
        );

        // no checkout: nothing to fetch from
        let mut section = art.section.clone();
        let secret_url = art
            .tmp
            .path()
            .join("missing-ghp_secret")
            .display()
            .to_string();
        section.repositories.insert(
            "nowhere".to_owned(),
            ace_sdk::SvsCatalogRepository {
                url: secret_url.clone(),
                branch: "main".to_owned(),
                ssh_key: None,
            },
        );
        let broken =
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"));
        let result = refresh_one(&broken, "nowhere", false).await;
        let error = result.error.clone().expect("an error");
        assert!(!result.refreshed && result.commit.is_none(), "{result:?}");
        assert!(
            error.starts_with("unable to fetch main of repository nowhere"),
            "{error}"
        );
        assert!(!error.contains("ghp_secret"), "{error}");
        let (commit, _, _, stored) = repository(db, "nowhere").await;
        assert_eq!((commit, stored.as_deref()), (None, Some(error.as_str())));

        // a branch the repository doesn't have, and a repository whose ssh key isn't set
        section.repositories.insert(
            "branchless".to_owned(),
            ace_sdk::SvsCatalogRepository {
                url: art.repos[REPOSITORY].origin.display().to_string(),
                branch: "release".to_owned(),
                ssh_key: None,
            },
        );
        section.repositories.insert(
            "keyed".to_owned(),
            ace_sdk::SvsCatalogRepository {
                url: art.repos[REPOSITORY].origin.display().to_string(),
                branch: "main".to_owned(),
                ssh_key: Some("art_key".to_owned()),
            },
        );
        let broken =
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"));
        let error = refresh_one(&broken, "branchless", false).await.error;
        assert!(
            error
                .as_deref()
                .is_some_and(|e| e.starts_with("unable to fetch release of repository branchless")),
            "{error:?}"
        );
        assert_eq!(
            refresh_one(&broken, "keyed", false).await.error.as_deref(),
            Some("repository keyed: its ssh_key, the secret art_key, isn't set")
        );
        // one repository's failure doesn't stop the others
        let results = refresh(&broken).await;
        let failed: Vec<(&str, bool)> = results
            .iter()
            .map(|r| (r.repository.as_str(), r.error.is_some()))
            .collect();
        assert_eq!(
            failed,
            [
                (REPOSITORY, false),
                ("branchless", true),
                ("keyed", true),
                ("nowhere", true)
            ]
        );
        assert!(stored_tests(db).await.contains_key(GUID_A));
    }

    /// test_catalog.py's `test_an_error_keeps_the_tests_and_clears_on_the_next_success`: a forced read of
    /// the commit already stored fails, so the row keeps that commit with the error; the failed commit is
    /// read on the next refresh, not skipped as already read. The failure here is the store's, as ace3's is
    /// its parser's, and a repeat of it writes no second audit row.
    #[tokio::test]
    async fn an_error_keeps_the_tests_and_clears_on_the_next_success() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        let commit = art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        let service = art.service(db);
        refresh_one(&service, REPOSITORY, false).await;

        sqlx::raw_sql(
            "CREATE FUNCTION svs.on_fire() RETURNS trigger LANGUAGE plpgsql AS
                 $$ BEGIN RAISE EXCEPTION 'disk on fire'; END $$;
             CREATE TRIGGER on_fire BEFORE UPDATE ON svs.catalog_repositories
                 FOR EACH ROW WHEN (NEW.refreshed_at IS DISTINCT FROM OLD.refreshed_at)
                 EXECUTE FUNCTION svs.on_fire()",
        )
        .execute(db.pool())
        .await
        .expect("breaks the store");
        let result = refresh_one(&service, REPOSITORY, true).await;
        let error = result.error.clone().expect("an error");
        assert!(
            error.starts_with("refresh failed: ") && error.contains("disk on fire"),
            "{error}"
        );
        assert_eq!(
            repository(db, REPOSITORY).await,
            (Some(commit.clone()), 1, 0, Some(error.clone()))
        );
        assert!(stored_tests(db).await.contains_key(GUID_A));
        // the same failure again changes nothing, and adds no audit row
        let audits = audit_count(db).await;
        assert_eq!(
            refresh_one(&service, REPOSITORY, false).await.error,
            Some(error)
        );
        assert_eq!(audit_count(db).await, audits);

        sqlx::raw_sql("DROP TRIGGER on_fire ON svs.catalog_repositories")
            .execute(db.pool())
            .await
            .expect("mends it");
        let result = refresh_one(&service, REPOSITORY, false).await;
        assert!(result.refreshed, "{result:?}");
        assert_eq!(repository(db, REPOSITORY).await.3, None);
    }

    /// A repository that breaks a bound fails its refresh, which stores nothing of it and keeps the
    /// catalog as it was; a file over the size limit, a symbolic link named like an atomic file and a file
    /// that isn't YAML are skipped and counted while the rest is read.
    #[tokio::test]
    async fn a_hostile_repository_fails_its_refresh_and_keeps_the_catalog() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let art = art(&[REPOSITORY]);
        let first = art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        let bounded = |change: fn(&mut ace_sdk::SvsCatalogSection)| {
            let mut section = art.section.clone();
            change(&mut section);
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"))
        };
        refresh_one(&art.service(db), REPOSITORY, false).await;
        let rows = catalog_rows(db).await;

        // more files, more bytes and more tests than a refresh may read
        let big = format!("# {}\n", "x".repeat(3000));
        art.repos[REPOSITORY].commit_with(
            &[
                (
                    T1105,
                    Some(
                        transfer(&[
                            atomic_test("Copy", Some(GUID_B), "whoami"),
                            atomic_test("Move", Some(GUID_C), "whoami"),
                        ])
                        .as_bytes(),
                    ),
                ),
                ("atomics/T1106/T1106.yaml", Some(big.as_bytes())),
                ("atomics/T1107/T1107.yaml", Some(b"{not yaml: [")),
            ],
            "main",
            &[("atomics/T1108/T1108.yaml", "../T1003/T1003.yaml")],
        );
        for (service, said) in [
            (
                bounded(|s| s.max_files = 4),
                "the commit has more than 4 atomic files (svs.catalog.max_files)",
            ),
            (
                bounded(|s| s.max_total_bytes = 700),
                "the commit's atomic files are more than 700 bytes (svs.catalog.max_total_bytes)",
            ),
            (
                bounded(|s| s.max_tests = 2),
                "the commit defines more than 2 tests (svs.catalog.max_tests)",
            ),
        ] {
            let result = refresh_one(&service, REPOSITORY, false).await;
            assert_eq!(result.error.as_deref(), Some(said));
            assert!(!result.refreshed);
            let (commit, count, _, error) = repository(db, REPOSITORY).await;
            assert_eq!(
                (commit.as_deref(), count, error.as_deref()),
                (Some(first.as_str()), 1, Some(said))
            );
            let tests = stored_tests(db).await;
            assert_eq!(tests.len(), 1);
            assert!(!tests[GUID_A].removed);
        }
        assert_ne!(
            catalog_rows(db).await,
            rows,
            "only the repository's error changed"
        );

        // within the limits the same commit is read, without what it can't use
        let result = refresh_one(&bounded(|s| s.max_file_bytes = 2000), REPOSITORY, false).await;
        assert!(result.refreshed && result.error.is_none(), "{result:?}");
        assert_eq!((result.tests, result.added), (3, 2));
        let skipped: Vec<(&str, &str)> = result
            .skipped
            .iter()
            .map(|s| {
                (
                    s.path.as_str(),
                    s.reason.split(':').next().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            skipped,
            [
                ("atomics/T1106/T1106.yaml", "larger than 2000 bytes"),
                ("atomics/T1107/T1107.yaml", "unreadable"),
                ("atomics/T1108/T1108.yaml", "a symbolic link"),
            ]
        );
        assert_eq!(repository(db, REPOSITORY).await.2, 3);
        assert_eq!(stored_tests(db).await.len(), 3);
    }

    /// test_catalog.py's `test_repository_status`: every repository in the overlay and every one with a
    /// row, by name, with its URL without credentials, its counts, and its error unless it's retired.
    #[tokio::test]
    async fn repository_status() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let actor = admin(db).await;
        let art = art(&[REPOSITORY]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[
                atomic_test("Dump", Some(GUID_A), "whoami"),
                atomic_test("Gone", Some(GUID_B), "whoami"),
                atomic_test("No guid", None, "whoami"),
            ])),
        )]);
        refresh(&art.service(db)).await;
        let commit = art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        refresh(&art.service(db)).await;

        let mut section = art.section.clone();
        section.repositories.insert(
            "private_art".to_owned(),
            ace_sdk::SvsCatalogRepository {
                url: "https://ghp_secret@git.invalid/org/art.git".to_owned(),
                branch: "main".to_owned(),
                ssh_key: None,
            },
        );
        section.fetch_timeout_seconds = 20;
        let listed =
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"));
        refresh(&listed).await;

        let statuses = listed
            .svs_catalog_repositories(&actor)
            .await
            .expect("lists");
        let names: Vec<&str> = statuses.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, [REPOSITORY, "private_art"]);
        let status = &statuses[0];
        assert_eq!(
            (
                status.configured,
                status.git_url.as_deref(),
                status.branch.as_deref(),
                status.commit.as_deref()
            ),
            (
                true,
                Some(art.repos[REPOSITORY].origin.to_string_lossy().as_ref()),
                Some("main"),
                Some(commit.as_str())
            )
        );
        assert_eq!(
            (
                status.test_count,
                status.skipped_count,
                status.removed_count,
                status.error.as_deref(),
                status.retired
            ),
            (1, 0, 1, None, false)
        );
        assert!(status.refreshed_at.is_some());

        // never read, with the error, and the url without its credentials
        let status = &statuses[1];
        assert_eq!(
            (
                status.git_url.as_deref(),
                status.branch.as_deref(),
                status.commit.as_deref(),
                status.refreshed_at
            ),
            (
                Some("https://git.invalid/org/art.git"),
                Some("main"),
                None,
                None
            )
        );
        let error = status.error.as_deref().expect("an error");
        assert!(
            error.starts_with("unable to fetch main of repository private_art"),
            "{error}"
        );
        assert!(!error.contains("ghp_secret"), "{error}");

        // taken out of the list: retired, with no error, and no settings to show
        let only_private = {
            let mut section = section.clone();
            section.repositories.remove(REPOSITORY);
            service(db).with_catalog(CatalogConfig::from_section(&section).expect("valid"))
        };
        refresh(&only_private).await;
        let statuses = only_private
            .svs_catalog_repositories(&actor)
            .await
            .expect("lists");
        let status = &statuses[0];
        assert_eq!(
            (
                status.name.as_str(),
                status.configured,
                status.retired,
                status.error.as_deref(),
                status.test_count,
                status.commit.as_deref()
            ),
            (REPOSITORY, false, true, None, 0, Some(commit.as_str()))
        );
        assert_eq!(
            (status.git_url.as_deref(), status.branch.as_deref()),
            (None, None)
        );
        assert_eq!(status.removed_count, 2);
    }

    /// The tests of ace3's API cases, seeded as it seeds them.
    /// `custom_removed`: of the repository `custom` and removed, as one of ace3's is; of
    /// `atomic-red-team` otherwise.
    async fn seed(
        db: &Db,
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
        .bind(seeded(n))
        .bind(repository)
        .bind(technique)
        .bind(name)
        .bind(platforms.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>())
        .bind(executor)
        .bind(removed)
        .execute(db.pool())
        .await
        .expect("seeds a test");
    }

    fn seeded(n: u128) -> Uuid {
        Uuid::from_u128((n << 96) | 0x0000_4000_8000_0000_0000_0000)
    }

    /// The catalog's cases of ace3's `tests/aceapi_v2/svs/test_catalog.py`: the order, each filter, a bad
    /// filter, the pages and the detail.
    #[tokio::test]
    async fn catalog_tests_are_listed_filtered_and_paged() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let actor = admin(db).await;
        let service = service(db);
        seed(
            db,
            1,
            "T1059.001",
            "PowerShell download",
            &["windows"],
            "powershell",
            false,
        )
        .await;
        seed(
            db,
            2,
            "T1059",
            "Command interpreter",
            &["linux", "macos"],
            "sh",
            false,
        )
        .await;
        seed(
            db,
            3,
            "T1003",
            "Dump credentials",
            &["windows"],
            "powershell",
            false,
        )
        .await;
        seed(
            db,
            4,
            "T1059.003",
            "Batch file",
            &["windows"],
            "command_prompt",
            true,
        )
        .await;
        seed(
            db,
            5,
            "T10590",
            "Not a sub-technique of T1059",
            &["windows"],
            "powershell",
            false,
        )
        .await;
        let numbers = |tests: &[ace_service::CatalogTest]| -> Vec<u128> {
            tests.iter().map(|t| t.guid.as_u128() >> 96).collect()
        };
        let listed = |filters: Vec<FilterEntry>| {
            let (service, actor) = (&service, &actor);
            async move {
                let query = CatalogTestQuery {
                    filters,
                    ..CatalogTestQuery::default()
                };
                service
                    .svs_catalog_tests(actor, &query, None, None)
                    .await
                    .map(|page| numbers(&page.tests))
            }
        };

        // test_ordered_by_technique_then_name: written after "Dump credentials" on the same technique, so
        // only its name puts it first; T10590 sorts after T1059's sub-techniques
        seed(
            db,
            6,
            "T1003",
            "Archive credentials",
            &["windows"],
            "powershell",
            false,
        )
        .await;
        assert_eq!(listed(vec![]).await.expect("lists"), [6, 3, 2, 1, 4, 5]);
        sqlx::query("DELETE FROM svs.catalog_tests WHERE guid = $1")
            .bind(seeded(6))
            .execute(db.pool())
            .await
            .expect("deletes");

        // test_filters: a technique also finds its sub-techniques, and nothing that only shares its prefix
        let text = FilterEntry::text;
        for (filters, expected) in [
            (vec![text("Technique", false, &["T1059"])], vec![2, 1, 4]),
            (vec![text("Technique", false, &["t1059.001"])], vec![1]),
            (vec![text("Technique", true, &["T1059"])], vec![3, 5]),
            (vec![text("Platform", false, &["linux"])], vec![2]),
            (
                vec![text("Executor", false, &["sh", "command_prompt"])],
                vec![2, 4],
            ),
            (vec![text("Name", false, &["download"])], vec![1]),
            (vec![text("Repository", false, &["custom"])], vec![4]),
            (vec![text("Removed", false, &["true"])], vec![4]),
            (
                vec![
                    text("Removed", false, &["false"]),
                    text("Technique", false, &["T1059"]),
                ],
                vec![2, 1],
            ),
            // and beyond ace3's cases: each inverse, values as they're typed, and a filter holding both
            (vec![text("Platform", true, &["Windows "])], vec![2]),
            (vec![text("Executor", true, &["PowerShell"])], vec![2, 4]),
            (
                vec![text("Name", true, &["DOWNLOAD", "dump"])],
                vec![2, 4, 5],
            ),
            (
                vec![text("Repository", true, &["custom"])],
                vec![3, 2, 1, 5],
            ),
            (vec![text("Removed", true, &["true"])], vec![3, 2, 1, 5]),
            (
                vec![text("Removed", false, &["true", "false"])],
                vec![3, 2, 1, 4, 5],
            ),
            (vec![text("Removed", true, &["true", "false"])], vec![]),
            (
                vec![text("Technique", false, &["T1003", "T1059.003"])],
                vec![3, 4],
            ),
            (vec![text("Name", false, &["100%", "_"])], vec![]),
        ] {
            let shown = format!("{filters:?}");
            assert_eq!(listed(filters).await.expect("lists"), expected, "{shown}");
        }

        // test_a_bad_filter_is_422
        for filters in [
            vec![text("Technique", false, &["mimikatz"])],
            vec![text("Nonsense", false, &["x"])],
            vec![text("Removed", false, &["maybe"])],
            vec![text("Platform", false, &[" "])],
        ] {
            assert!(
                matches!(
                    listed(filters.clone()).await,
                    Err(ServiceError::InvalidRequest(_))
                ),
                "{filters:?}"
            );
        }

        // test_pages
        let query = CatalogTestQuery::default();
        let mut cursor: Option<String> = None;
        let mut pages = Vec::new();
        loop {
            let page = service
                .svs_catalog_tests(&actor, &query, cursor.as_deref(), Some(2))
                .await
                .expect("a page");
            pages.push(numbers(&page.tests));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(pages, [vec![3, 2], vec![1, 4], vec![5]]);
        for (cursor, limit) in [(Some("zz"), Some(2)), (None, Some(0)), (None, Some(1001))] {
            assert!(matches!(
                service
                    .svs_catalog_tests(&actor, &query, cursor, limit)
                    .await,
                Err(ServiceError::InvalidRequest(_))
            ));
        }
        assert_eq!(
            service
                .svs_catalog_test_count(&actor, &query, 3)
                .await
                .expect("counts"),
            4,
            "counted to one past the most"
        );

        // changed_since: a row's own change, which a later refresh that leaves it alone doesn't move
        let before: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(db.pool())
            .await
            .expect("now");
        sqlx::query("UPDATE svs.catalog_tests SET removed_at = now() WHERE guid = $1")
            .bind(seeded(3))
            .execute(db.pool())
            .await
            .expect("removes one");
        let changed = CatalogTestQuery {
            changed_since: Some(before),
            ..CatalogTestQuery::default()
        };
        let page = service
            .svs_catalog_tests(&actor, &changed, None, None)
            .await
            .expect("lists");
        assert_eq!(numbers(&page.tests), [3]);
        assert!(page.tests[0].removed_at.is_some());

        // test_detail: a guid in any case; one that isn't a uuid; one the catalog doesn't have
        let detail = service
            .svs_catalog_test(&actor, &seeded(1).to_string().to_uppercase())
            .await
            .expect("the test");
        assert_eq!(
            (detail.test.name.as_str(), detail.test.technique.as_str()),
            ("PowerShell download", "T1059.001")
        );
        assert_eq!(
            detail.description.as_deref(),
            Some("PowerShell download does a thing")
        );
        assert_eq!(detail.entry["executor"]["command"], "whoami");
        assert_eq!(detail.test.platforms, ["windows"]);
        assert_eq!(detail.platform_slugs, ["windows"]);
        assert!(detail.test.removed_at.is_none());
        assert_eq!(
            service
                .svs_catalog_test(&actor, &seeded(2).to_string())
                .await
                .expect("the test")
                .platform_slugs,
            ["linux", "macos"]
        );
        assert!(matches!(
            service.svs_catalog_test(&actor, "not-a-guid").await,
            Err(ServiceError::InvalidRequest(why)) if why == "invalid test guid \"not-a-guid\""
        ));
        assert!(matches!(
            service
                .svs_catalog_test(&actor, &seeded(99).to_string())
                .await,
            Err(ServiceError::NotFound(_))
        ));
    }

    /// The catalog's reads need `svs:run_read`, and its refresh and each of its writes
    /// `svs:catalog_refresh`, which the scheduler's component holds and nothing else of it: the component
    /// can't read through the service, and a reader can't refresh.
    #[tokio::test]
    async fn the_catalog_reads_need_run_read_and_the_refresh_its_permission() {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let boss = admin(db).await;
        let art = art(&[REPOSITORY]);
        art.commit(&[(
            T1003,
            Some(&dumping(&[atomic_test("Dump", Some(GUID_A), "whoami")])),
        )]);
        let service = art.service(db);
        let reader_id = UserId(Uuid::from_u128(0x5C));
        exists(db, &Holder::User(reader_id)).await;
        service
            .grant(
                &boss,
                &Holder::User(reader_id),
                &pattern("svs", "run_read"),
                Effect::Allow,
            )
            .await
            .expect("grants");
        let reader = user(reader_id);
        let outsider = user(UserId(Uuid::from_u128(0x5D)));
        let query = CatalogTestQuery::default();
        let parsed = catalog::ParseResult::default();
        let denied = |result: Result<(), ServiceError>| {
            assert!(
                matches!(result, Err(ServiceError::PermissionDenied { .. })),
                "{result:?}"
            );
        };

        refresh(&service).await;
        for actor in [&reader, &boss] {
            service
                .svs_catalog_tests(actor, &query, None, None)
                .await
                .expect("lists");
            service
                .svs_catalog_test_count(actor, &query, 10)
                .await
                .expect("counts");
            service
                .svs_catalog_test(actor, GUID_A)
                .await
                .expect("reads");
            service
                .svs_catalog_repositories(actor)
                .await
                .expect("lists");
        }
        for actor in [&outsider, &refresher()] {
            denied(
                service
                    .svs_catalog_tests(actor, &query, None, None)
                    .await
                    .map(|_| ()),
            );
            denied(
                service
                    .svs_catalog_test_count(actor, &query, 10)
                    .await
                    .map(|_| ()),
            );
            denied(service.svs_catalog_test(actor, GUID_A).await.map(|_| ()));
            // a guid that isn't one says so only to someone who may read
            denied(service.svs_catalog_repositories(actor).await.map(|_| ()));
        }
        let rows = catalog_rows(db).await;
        for actor in [&outsider, &reader] {
            denied(
                service
                    .refresh_svs_catalog(actor, None, true)
                    .await
                    .map(|_| ()),
            );
            denied(
                service
                    .store_svs_catalog(actor, REPOSITORY, &"c".repeat(40), &parsed)
                    .await
                    .map(|_| ()),
            );
            denied(
                service
                    .record_svs_catalog_error(actor, REPOSITORY, "it failed")
                    .await
                    .map(|_| ()),
            );
            denied(
                service
                    .retire_svs_catalog_repository(actor, "gone")
                    .await
                    .map(|_| ()),
            );
        }
        assert_eq!(
            catalog_rows(db).await,
            rows,
            "a refused write wrote nothing"
        );
        // the migration's grant is the component's only one
        let grants: Vec<(String, String)> = sqlx::query_as(
            "SELECT major, minor FROM service.permissions WHERE component = 'scheduler:svs_catalog_refresh'",
        )
        .fetch_all(db.pool())
        .await
        .expect("reads");
        assert_eq!(grants, [("svs".to_owned(), "catalog_refresh".to_owned())]);
    }

    /// One parsed test, for the writes' audit tests.
    pub(super) fn one_parsed(guid: &str) -> catalog::ParseResult {
        catalog::parse_atomics(
            vec![AtomicFile {
                path: T1003.to_owned(),
                content: Ok(dumping(&[
                    atomic_test("Dump", Some(guid), "whoami"),
                    atomic_test("No guid", None, "whoami"),
                ])
                .into_bytes()),
            }],
            &CatalogLimits::default(),
        )
        .expect("parses")
    }

    pub(super) async fn store_svs_catalog_records_its_row(db: &Db) -> String {
        let art = art(&[REPOSITORY]);
        let (first, second) = ("c".repeat(40), "d".repeat(40));
        let service = art.service(db);
        service
            .store_svs_catalog(&refresher(), REPOSITORY, &first, &one_parsed(GUID_A))
            .await
            .expect("stores");
        let row = last_audit(db).await;
        let skipped =
            json!([{"path": T1003, "name": "No guid", "reason": "no auto_generated_guid"}]);
        assert_eq!(
            row,
            AuditRow {
                actor: json!({"kind": "internal", "id": "scheduler:svs_catalog_refresh"}),
                action: "store_svs_catalog".to_owned(),
                target: ("svs_catalog_repository".to_owned(), REPOSITORY.to_owned()),
                before: Some(json!({"commit": null, "tests": 0})),
                after: Some(json!({
                    "commit": first, "tests": 1, "added": 1, "changed": 0, "removed": 0, "skipped": 1,
                    "skipped_first": skipped,
                })),
                details: json!({}),
            }
        );
        // the next commit's row has the one before it
        service
            .store_svs_catalog(
                &refresher(),
                REPOSITORY,
                &second,
                &catalog::ParseResult::default(),
            )
            .await
            .expect("stores");
        let next = last_audit(db).await;
        assert_eq!(next.before, Some(json!({"commit": first, "tests": 1})));
        assert_eq!(
            next.after,
            Some(json!({
                "commit": second, "tests": 0, "added": 0, "changed": 0, "removed": 1, "skipped": 0,
                "skipped_first": [],
            }))
        );
        row.action
    }

    pub(super) async fn record_svs_catalog_error_records_its_row(db: &Db) -> String {
        let art = art(&[REPOSITORY]);
        let service = art.service(db);
        let changed = service
            .record_svs_catalog_error(&refresher(), "failing", "it failed")
            .await
            .expect("records");
        assert!(changed);
        let row = last_audit(db).await;
        assert_eq!(
            row,
            AuditRow {
                actor: json!({"kind": "internal", "id": "scheduler:svs_catalog_refresh"}),
                action: "record_svs_catalog_error".to_owned(),
                target: ("svs_catalog_repository".to_owned(), "failing".to_owned()),
                before: Some(json!({"error": null})),
                after: Some(json!({"error": "it failed"})),
                details: json!({}),
            }
        );
        // the same failure again writes nothing; another one is a change
        let audits = audit_count(db).await;
        assert!(
            !service
                .record_svs_catalog_error(&refresher(), "failing", "it failed")
                .await
                .expect("records")
        );
        assert_eq!(audit_count(db).await, audits);
        assert!(
            service
                .record_svs_catalog_error(&refresher(), "failing", &"x".repeat(5000))
                .await
                .expect("records")
        );
        let after = last_audit(db).await.after.expect("an after");
        assert_eq!(after["error"].as_str().map(str::len), Some(4096));
        row.action
    }

    pub(super) async fn retire_svs_catalog_repository_records_its_row(db: &Db) -> String {
        let art = art(&[REPOSITORY]);
        art.service(db)
            .store_svs_catalog(
                &refresher(),
                "dropped",
                &"c".repeat(40),
                &one_parsed(GUID_B),
            )
            .await
            .expect("stores");
        let result = art
            .service(db)
            .retire_svs_catalog_repository(&refresher(), "dropped")
            .await
            .expect("retires");
        assert!(result.retired && result.removed == 1, "{result:?}");
        let row = last_audit(db).await;
        assert_eq!(
            row,
            AuditRow {
                actor: json!({"kind": "internal", "id": "scheduler:svs_catalog_refresh"}),
                action: "retire_svs_catalog_repository".to_owned(),
                target: ("svs_catalog_repository".to_owned(), "dropped".to_owned()),
                before: Some(json!({"removed": 1})),
                after: None,
                details: json!({}),
            }
        );
        row.action
    }
}
