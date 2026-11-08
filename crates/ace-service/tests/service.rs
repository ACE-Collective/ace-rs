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
    ALERT_WRITE, Actor, ApiKeyId, CATALOG, Component, CrashFilter, CrashInput, Effect, GroupId,
    Holder, MAX_CRASHES_PAGE, MIN_PASSWORD_CHARS, NewSession, Password, PermissionName,
    PermissionPattern, Profile, QaPurge, QaRuleFilter, QaSort, QaStatus, RequestParts,
    SESSION_LIFETIME_SECONDS, Service, ServiceError, SessionCookie, Transport, USER_SELF,
    USER_WRITE, UserId, Username, with_source_ip,
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
        service(db).alerts(&outsider, None, None).await,
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
    let before = (
        row(db, root).await,
        tasks(db, root).await,
        permission_rows(db).await,
        audit_rows(db).await,
        credential_rows(db).await,
        root_count(db).await,
        group_rows(db).await,
        qa_state(db).await,
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
    );
    assert_eq!(after, before);
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
    let (auth, users) = (source("auth.rs"), source("users.rs"));
    let found: BTreeSet<&str> = calls
        .captures_iter(&auth)
        .chain(calls.captures_iter(&users))
        .map(|call| call.get(1).expect("a name").as_str())
        .collect();
    assert_eq!(
        found,
        BTreeSet::from([
            "change_own_password",
            "login",
            "logout",
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
/// pattern covering something ACE checks that they hold, and never `user:self`. A key can't make one.
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
