//! PLAN.md 5.1: one actor type, carried by every write. Each kind of actor writes through the same
//! function: the analysis it stops and starts is the same, and only who is recorded differs.
//!
//! PLAN.md 5.2: one case rule for permissions, and a check every write goes through. A permission
//! behaves the same in any case when stored and when checked, for every kind of actor.

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::{Orchestrator, OrchestratorError};
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot};
use ace_core::{Db, queue};
use ace_results::{AnalysisType, NewObservable, ObservableKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{
    ALERT_WRITE, Actor, ApiKeyId, Component, Effect, GroupId, Holder, PermissionName,
    PermissionPattern, Service, ServiceError, USER_SELF, USER_WRITE, UserId,
};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
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

/// An admin, as 5.4's first admin will be: `*:*` on a row the service didn't write, since nothing
/// can grant until someone holds `user:write`.
async fn admin(db: &Db) -> Actor {
    let id = UserId(Uuid::from_u128(0xAD));
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
    let (rows,): (i64,) = sqlx::query_as("SELECT count(*) FROM service.permissions")
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
}

/// A row written outside the type can't break the rule. This is the database's half of it.
#[tokio::test]
async fn the_database_refuses_a_row_that_breaks_the_rule() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let by = json!({"kind": "internal", "id": "test"});
    let user_id = Uuid::from_u128(1);
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
