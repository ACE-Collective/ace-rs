//! What the queue's tests share: a root with observables, and workers on their own pools.

#![allow(dead_code)]

use std::time::Duration;

use ace_core::db::Db;
use ace_core::queue::Worker;
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot, ObservableId, upsert_observable};
use ace_results::{NewObservable, ObservableKind};
use uuid::Uuid;

/// A root in `mode` with these observables, committed.
pub async fn root_with(
    db: &Db,
    mode: &str,
    observables: &[(ObservableKind, &str)],
) -> (Uuid, Vec<ObservableId>) {
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new(mode);
    tree::create_root(&mut tx, &root).await.expect("creates");
    let mut ids = Vec::new();
    for (kind, value) in observables {
        let upserted = upsert_observable(&mut tx, root.id, &NewObservable::new(*kind, *value))
            .await
            .expect("adds");
        ids.push(upserted.id);
    }
    tx.commit().await.expect("commits");
    (root.id, ids)
}

/// A worker with its own connection pool, as a worker in another process would have.
pub async fn worker(test_db: &TestDb, name: &str, modules: &[&str], lease: Duration) -> Worker {
    let db = Db::connect(test_db.config()).await.expect("connects");
    Worker::new(
        db,
        name,
        modules.iter().map(|m| (*m).to_owned()).collect(),
        lease,
    )
}

/// Modules that do nothing, for eligibility's tests: one that depends on `archive`, and a
/// stand-in for ace3's `alert_added_to_event`, which runs in dispositioned mode.
pub mod stubs {
    use ace_results::{AnalysisType, ObservableKind};
    use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct StubOutput {
        pub note: String,
    }

    impl AnalysisType for StubOutput {
        const NAME: &'static str = "test_stub";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "test_stub";
    }

    macro_rules! stub {
        ($ty:ident, $name:literal, $inputs:expr, $depends:expr) => {
            pub struct $ty;

            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = $inputs;
                const DEPENDS_ON: &'static [&'static str] = $depends;
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

    stub!(
        DependsOnArchive,
        "test_depends_on_archive",
        &[ObservableKind::File],
        &["archive"]
    );
    stub!(
        AlertAddedToEvent,
        "alert_added_to_event",
        ObservableKind::BUILTIN,
        &[]
    );

    pub const DEPENDS_ON_ARCHIVE: Manifest = Manifest::lookup::<DependsOnArchive>();
    pub const ALERT_ADDED_TO_EVENT: Manifest = Manifest::lookup::<AlertAddedToEvent>();
}

/// The five ported modules' manifests and the stubs.
pub fn manifests() -> Vec<ace_sdk::Manifest> {
    vec![
        ace_mod_email::MANIFEST,
        ace_mod_rdap::MANIFEST,
        ace_mod_archive::MANIFEST,
        ace_mod_yara::MANIFEST,
        ace_mod_splunk::MANIFEST,
        stubs::DEPENDS_ON_ARCHIVE,
        stubs::ALERT_ADDED_TO_EVENT,
    ]
}

/// A result envelope from JSON, as a worker would send it.
pub fn result(value: serde_json::Value) -> ace_results::ResultEnvelope<serde_json::Value> {
    serde_json::from_value(value).expect("a result envelope")
}

/// The root's tasks as (module, observable value, state) in a stable order.
pub async fn tasks_of(db: &Db, root: Uuid) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT t.module, o.value, t.state::text FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.module, o.value",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("lists tasks")
}
