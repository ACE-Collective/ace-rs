//! PLAN.md 5.1: one actor type, carried by every write. Each kind of actor writes through the same
//! function: the analysis it stops and starts is the same, and only who is recorded differs.

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::{Orchestrator, OrchestratorError};
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot};
use ace_core::{Db, queue};
use ace_results::{AnalysisType, NewObservable, ObservableKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
use ace_service::{Actor, ApiKeyId, Component, Service, ServiceError, UserId};
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
