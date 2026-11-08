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
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{
    ALERT_WRITE, Actor, ApiKeyId, CATALOG, CampaignChoice, CommandState, Component, CrashFilter,
    CrashInput, DetectionPointFilter, Effect, EventChoice, EventEdit, EventRef, EventTimes,
    GroupId, Holder, MAX_CRASHES_PAGE, MIN_PASSWORD_CHARS, MalwareChoice, NewEvent, NewSession,
    Password, PermissionName, PermissionPattern, PreferenceKey, PreferenceValue, Profile, QaPurge,
    QaRuleFilter, QaSort, QaStatus, RequestParts, SESSION_LIFETIME_SECONDS, Service, ServiceError,
    SessionCookie, Theme, ThemePreference, Transport, USER_SELF, USER_WRITE, UserId, Username,
    with_source_ip,
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

fn orchestrator() -> Orchestrator {
    let catalog = Catalog::new(vec![
        Manifest::lookup::<CorrelationStub>(),
        Manifest::lookup::<DispositionedStub>(),
    ]);
    Orchestrator::new(catalog, Modes::ace3())
}

fn service(db: &Db) -> Service {
    Service::new(db.clone(), orchestrator())
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
        "SELECT count(*) FROM service.permissions WHERE component IS DISTINCT FROM 'bootstrap'",
    )
    .fetch_one(db.pool())
    .await
    .expect("counts");
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
        download_qa_match_records_its_row(db).await,
        download_qa_matches_records_its_row(db).await,
        purge_qa_matches_records_its_row(db).await,
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
        (
            listed.observable_type.as_str(),
            listed.observable_value.as_str()
        ),
        ("fqdn", "evil.example.com")
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
    ];
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
    assert_eq!(command_rows(db).await, commands_before);
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
    let writes = ["A", "B", "C", "D", "E", "F"].map(|disposition| {
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
            after: Some(json!({"username": "root", "enabled": true, "timezone": "UTC"})),
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
            before: Some(json!({"display_name": null, "email": null, "timezone": "UTC"})),
            after: Some(json!({
                "display_name": "Audited",
                "email": "a@example.com",
                "timezone": "Asia/Tokyo",
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
            before: Some(json!({"display_name": null, "email": null, "timezone": "UTC"})),
            after: Some(json!({
                "display_name": "Me",
                "email": null,
                "timezone": "America/New_York",
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
        "alert:* covers alert:create, alert:write, which you don't hold"
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
        (
            vec![text("Queue", false, &["default"])],
            "alert routing (7.13)",
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
    let old = ["queue:default".to_owned(), "disposition:OPEN".to_owned()];
    let (decoded, warnings) = filter_model::decode(screen, &old, false).expect("decodes");
    assert_eq!(decoded, [text("Disposition", false, &["OPEN"])]);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("7.13"), "{warnings:?}");
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
            .detection_point_count(&actor, &filtered(vec![text("Verdict", false, &["tp"])]), 10)
            .await,
        Err(ServiceError::InvalidRequest(why)) if why.contains("7.14")
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
        ["date", "description", "disposition", "status"]
    );
    assert!(normal.hidden.is_empty());
    let parsed = PreferenceKey::ManageColumns
        .parse(json!({
            "order": ["status", "queue", "status", "description"],
            "hidden": ["description", "date", "owner", "date"],
        }))
        .expect("parses");
    let PreferenceValue::ManageColumns(columns) = parsed else {
        panic!("manage_columns")
    };
    assert_eq!(
        columns.order,
        ["status", "description", "date", "disposition"]
    );
    assert_eq!(columns.hidden, ["date"], "description is always shown");
    assert_eq!(
        columns
            .visible()
            .iter()
            .map(|column| column.id)
            .collect::<Vec<_>>(),
        ["status", "description", "disposition"]
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

// The events module's own checks, which were a `#[cfg(test)]` module in src/events.rs that never ran:
// this crate's library tests are off (Cargo.toml), so they're here.

#[test]
fn an_event_rolls_its_alerts_dispositions_up_as_ace3_does() {
    use ace_service::rolled_up;
    assert_eq!(rolled_up([]), "DELIVERY", "no alerts");
    assert_eq!(rolled_up([None, Some("OPEN")]), "OPEN");
    assert_eq!(rolled_up([Some("IGNORE")]), "IGNORE");
    assert_eq!(
        rolled_up([Some("DAMAGE"), Some("FALSE_POSITIVE"), None]),
        "DAMAGE"
    );
    assert_eq!(
        rolled_up([Some("GRAYWARE"), Some("SIMULATED"), Some("REVIEWED")]),
        "GRAYWARE"
    );
    assert_eq!(rolled_up([Some("SITE_OWN")]), "OPEN", "no rank never wins");
    assert_eq!(rolled_up([Some("SITE_OWN"), Some("IGNORE")]), "IGNORE");
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
