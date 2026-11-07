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

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::{Orchestrator, OrchestratorError};
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot};
use ace_core::{Db, queue};
use ace_results::{AnalysisType, NewObservable, ObservableKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{
    ALERT_WRITE, Actor, ApiKeyId, Component, Effect, GroupId, Holder, MIN_PASSWORD_CHARS,
    NewSession, Password, PermissionName, PermissionPattern, RequestParts,
    SESSION_LIFETIME_SECONDS, Service, ServiceError, SessionCookie, Transport, USER_SELF,
    USER_WRITE, UserId, Username,
};
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
    assert!(error.to_string().contains("group_id"), "{error}");
    // the same for the holders 5.4 gave a foreign key
    for (holder, column) in [
        (Holder::User(UserId(Uuid::from_u128(1))), "user_exists"),
        (
            Holder::ApiKey(ApiKeyId(Uuid::from_u128(1))),
            "api_key_exists",
        ),
    ] {
        let error = service(db)
            .grant(&admin(db).await, &holder, &pattern("*", "*"), Effect::Allow)
            .await
            .expect_err("refused");
        assert!(error.to_string().contains(column), "{error}");
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
    ]);
    assert_eq!(covered, write_functions(), "{WRITES_NEED_A_TEST}");
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
        .create_api_key(&actor, "triage", None)
        .await
        .expect("makes a key");
    let before = (
        row(db, root).await,
        tasks(db, root).await,
        permission_rows(db).await,
        audit_rows(db).await,
        credential_rows(db).await,
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
                .create_user(&actor, &username("carol"), Password::new(PASSWORD))
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
                .create_api_key(&actor, "another", None)
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
        .create_user(actor, &username(name), Password::new(PASSWORD))
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
        .create_api_key(&boss, "triage", Some(alice))
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
        .create_api_key(&boss, "collector", None)
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
        .create_api_key(&boss, "triage", Some(alice))
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
        .create_api_key(&boss, "triage", None)
        .await
        .expect("makes a key");
    let other = service
        .create_api_key(&boss, "other", None)
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
        .create_api_key(&boss, "owned", Some(alice))
        .await
        .expect("makes a key");
    let unowned = service
        .create_api_key(&boss, "unowned", None)
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
        .create_api_key(&boss, "owned", Some(alice))
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
            .create_user(&nobody, &username("bob"), Password::new(PASSWORD))
            .await
            .map(|_| ()),
        service
            .set_user_enabled(&nobody, alice, false)
            .await
            .map(|_| ()),
        service
            .create_api_key(&nobody, "mine", None)
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
            .create_user(&boss, &username("ALICE"), Password::new(PASSWORD))
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
                    .create_user(&boss, &username("carol"), Password::new(weak))
                    .await,
                Err(ServiceError::WeakPassword)
            ),
            "{} bytes",
            weak.len()
        );
    }
    for name in ["", "   ", &"x".repeat(256)] {
        assert!(matches!(
            service.create_api_key(&boss, name, None).await,
            Err(ServiceError::InvalidKeyName)
        ));
    }
    assert!(matches!(
        service
            .create_api_key(&boss, "orphan", Some(UserId(Uuid::from_u128(77))))
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
        .create_api_key(&boss, "alices", Some(alice))
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
        .create_api_key(&boss, "triage", None)
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
        .create_api_key(&boss, "triage", Some(alice))
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
            after: Some(json!({"username": "root", "enabled": true})),
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
    let id = new_user(&service, &admin(db).await, "audited-user").await;
    let row = last_audit(db).await;
    assert_eq!(
        row,
        AuditRow {
            actor: boss_json(),
            action: "create_user".to_owned(),
            target: ("user".to_owned(), id.0.to_string()),
            before: None,
            after: Some(json!({"username": "audited-user", "enabled": true})),
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
        .create_api_key(&boss, "  audited key  ", Some(owner))
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
            after: Some(json!({"name": "audited key", "owner": owner.0})),
            details: json!({}),
        }
    );
    row.action
}

async fn revoke_api_key_records_its_row(db: &Db) -> String {
    let service = service(db);
    let boss = admin(db).await;
    let key = service
        .create_api_key(&boss, "audited revoke", None)
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
            before: Some(json!({"name": "audited revoke", "owner": null})),
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
    let auth = source("auth.rs");
    let found: BTreeSet<&str> = calls
        .captures_iter(&auth)
        .map(|call| call.get(1).expect("a name").as_str())
        .collect();
    assert_eq!(
        found,
        BTreeSet::from(["change_own_password", "login", "logout"])
    );
    assert!(!source("lib.rs").contains(".write_own("));
    assert!(!source("permission.rs").contains(".write_own("));
}
