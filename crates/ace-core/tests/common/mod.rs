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

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct SetsRootOutput {}

    impl AnalysisType for SetsRootOutput {
        const NAME: &'static str = "test_sets_root";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "test_sets_root";
    }

    /// A module that changes its root, as ace3's mailbox module does, walks the tree, may add the
    /// tag `x` and the directive `crawl` to other observables, and may limit what it adds to
    /// `alert_added_to_event`, and adds links to its root's.
    pub struct SetsRoot;

    impl Module for SetsRoot {
        const NAME: &'static str = "test_sets_root";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const READS_TREE: bool = true;
        const SETS_ROOT: bool = true;
        const LIMITS_ANALYSIS_TO: &'static [&'static str] = &["alert_added_to_event"];
        const ADDS_ROOT_PIVOT_LINKS: bool = true;
        const ADDS_TO_OTHERS: Option<ace_sdk::OtherAdditionsAllowed> =
            Some(ace_sdk::OtherAdditionsAllowed {
                tags: &["x"],
                directives: &["crawl"],
                detections: false,
                relationships: false,
            });
        type Output = SetsRootOutput;
        type Settings = ();

        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(SetsRoot)
        }
    }

    impl Lookup for SetsRoot {
        const TCP_PORTS: &'static [u16] = &[];

        async fn analyze(
            &self,
            _: &TaskContext<()>,
        ) -> Result<Outcome<SetsRootOutput>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    /// A stand-in for SVS's `svs_yara_sample_capture`, which runs in dispositioned mode and stores no
    /// result.
    pub struct SampleCapture;

    impl Module for SampleCapture {
        const NAME: &'static str = "svs_yara_sample_capture";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const STORES_RESULTS: bool = false;
        type Output = StubOutput;
        type Settings = ();

        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(SampleCapture)
        }
    }

    impl Lookup for SampleCapture {
        const TCP_PORTS: &'static [u16] = &[];

        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    pub const SAMPLE_CAPTURE: Manifest = Manifest::lookup::<SampleCapture>();
    pub const SETS_ROOT: Manifest = Manifest::lookup::<SetsRoot>();
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
        ace_mod_brocess::logger::MANIFEST,
        stubs::DEPENDS_ON_ARCHIVE,
        stubs::ALERT_ADDED_TO_EVENT,
    ]
}

/// file_type's result on `on`, calling it an email, which the email module's declaration of what it
/// takes reads (`ace_sdk::takes`, PLAN.md decision 23). These tests' catalogs haven't file_type, so
/// nothing else lands one, and without it the email module takes no file.
pub async fn file_type_says_email(db: &Db, root: Uuid, on: ObservableId) {
    let mut tx = db.begin().await.expect("begins");
    let envelope = result(serde_json::json!({
        "analysis_type": "file_type_analysis", "schema_version": 1,
        "details": {"type": "RFC 822 mail, ASCII text", "mime": "message/rfc822",
                    "is_email_file": true},
    }));
    tree::insert_result(&mut tx, root, on, "file_type", &envelope)
        .await
        .expect("inserts");
    tx.commit().await.expect("commits");
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

/// The records a test's thread logs, with their fields.
#[derive(Clone, Default)]
pub struct Records(std::sync::Arc<std::sync::Mutex<Vec<Record>>>);

#[derive(Clone, Debug)]
pub struct Record {
    pub level: tracing::Level,
    pub fields: std::collections::BTreeMap<String, String>,
}

impl Records {
    /// Sends this thread's records here until the guard drops. A test on a current-thread runtime
    /// sees its own records and no other test's.
    pub fn on_this_thread(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(tracing_subscriber::layer::SubscriberExt::with(
            tracing_subscriber::registry(),
            self.clone(),
        ))
    }

    /// The first record whose message is `message`.
    pub fn find(&self, message: &str) -> Option<Record> {
        self.0
            .lock()
            .expect("the records")
            .iter()
            .find(|r| r.fields.get("message").is_some_and(|m| m == message))
            .cloned()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Records {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(std::collections::BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(std::collections::BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().expect("the records").push(Record {
            level: *event.metadata().level(),
            fields: fields.0,
        });
    }
}
