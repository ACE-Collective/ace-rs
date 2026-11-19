//! PLAN.md 2.4: roots with an event time and its source, observables unique on (root, type,
//! value), and results unique on (root, observable, module) with JSONB details under a GIN index.

use ace_core::normal::{normal_form, to_text};
use ace_core::testing::TestDb;
use ace_core::tree::{
    self, EventTime, EventTimeSource, NewRoot, insert_result, observables, upsert_observable,
};
use ace_results::{
    Detection, NewObservable, ObservableAdditions, ObservableKind, ObservableRef, Relationship,
    RelationshipKind, ResultEnvelope, YaraMeta,
};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

fn result(details: Value) -> ResultEnvelope<Value> {
    serde_json::from_value(json!({
        "analysis_type": "example_line_stats",
        "schema_version": 1,
        "details": details,
        "summary": "3 lines",
    }))
    .expect("a result envelope")
}

#[tokio::test]
async fn upserting_an_observable_twice_leaves_one_row() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");

    let mut first = NewObservable::new(ObservableKind::Fqdn, "evil.example.com");
    first.tags = vec!["phish".to_owned()];
    first.directives = vec!["crawl".to_owned()];
    let mut again = NewObservable::new(ObservableKind::Fqdn, "evil.example.com");
    again.tags = vec!["phish".to_owned(), "newly_registered".to_owned()];
    again.exclude_modules = vec!["rdap_analyzer".to_owned()];

    let a = upsert_observable(&mut tx, root.id, &first)
        .await
        .expect("adds");
    let b = upsert_observable(&mut tx, root.id, &again)
        .await
        .expect("merges");
    assert!(a.inserted);
    assert!(!b.inserted);
    assert_eq!(a.id, b.id);
    tx.commit().await.expect("commits");

    let stored = observables(db.pool(), root.id).await.expect("reads");
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0].tags, ["phish", "newly_registered"]);
    assert_eq!(stored[0].directives, ["crawl"]);
    assert_eq!(stored[0].exclude_modules, ["rdap_analyzer"]);
}

/// PLAN.md 5.8: a display type is ace3's `_display_type` on its one observable per type and value, so
/// one that names a label replaces the stored one, and one that names none leaves it.
#[tokio::test]
async fn the_last_display_type_given_is_the_observable_s() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let labelled = |label: Option<&str>| {
        let mut observable = NewObservable::new(ObservableKind::Ip, "192.0.2.10");
        observable.display_type = label.map(str::to_owned);
        observable
    };
    upsert_observable(&mut tx, root.id, &labelled(None))
        .await
        .expect("adds");
    assert_eq!(stored_display_type(&mut tx, root.id).await, None);
    for (given, kept) in [
        (Some("Source IP"), Some("Source IP")),
        (None, Some("Source IP")),
        (Some("Destination IP"), Some("Destination IP")),
    ] {
        upsert_observable(&mut tx, root.id, &labelled(given))
            .await
            .expect("merges");
        assert_eq!(
            stored_display_type(&mut tx, root.id).await.as_deref(),
            kept,
            "after {given:?}"
        );
    }
    tx.commit().await.expect("commits");
}

async fn stored_display_type(tx: &mut ace_core::db::Tx<'_>, root: uuid::Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT display_type FROM analysis.observables WHERE root_id = $1")
        .bind(root)
        .fetch_one(tx.conn())
        .await
        .expect("reads")
}

#[tokio::test]
async fn type_value_and_root_each_make_an_observable_distinct() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let one = NewRoot::new("analysis");
    let two = NewRoot::new("analysis");
    tree::create_root(&mut tx, &one).await.expect("creates");
    tree::create_root(&mut tx, &two).await.expect("creates");
    // longer than a btree entry may be, so uniqueness has to be on the hash
    let long_url = format!("data:text/html,{}", "A".repeat(100_000));
    for (root, kind, value) in [
        (one.id, ObservableKind::Fqdn, "example.com"),
        (
            one.id,
            ObservableKind::EmailDkimSigningDomain,
            "example.com",
        ),
        (one.id, ObservableKind::Fqdn, "example.org"),
        (two.id, ObservableKind::Fqdn, "example.com"),
        (one.id, ObservableKind::Url, long_url.as_str()),
        (one.id, ObservableKind::Url, long_url.as_str()),
    ] {
        upsert_observable(&mut tx, root, &NewObservable::new(kind, value))
            .await
            .expect("upserts");
    }
    tx.commit().await.expect("commits");
    assert_eq!(
        observables(db.pool(), one.id).await.expect("reads").len(),
        4
    );
    assert_eq!(
        observables(db.pool(), two.id).await.expect("reads").len(),
        1
    );
}

#[tokio::test]
async fn a_root_keeps_its_event_time_and_where_it_came_from() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let when = Utc
        .with_ymd_and_hms(2026, 10, 29, 12, 0, 0)
        .single()
        .expect("a time");
    let mut tx = db.begin().await.expect("begins");
    let mut ids = Vec::new();
    for event_time in [
        EventTime::Event(when),
        EventTime::QueryTime(when),
        EventTime::Now(when),
        EventTime::Unset,
    ] {
        let mut root = NewRoot::new("analysis");
        root.event_time = event_time;
        tree::create_root(&mut tx, &root).await.expect("creates");
        ids.push((root.id, event_time));
    }
    tx.commit().await.expect("commits");
    for (id, event_time) in ids {
        let root = tree::root(db.pool(), id)
            .await
            .expect("reads")
            .expect("exists");
        assert_eq!(root.event_time, event_time);
    }

    // a time with no source, or a source with no time, doesn't fit the table
    let mismatched = sqlx::query(
        "INSERT INTO analysis.roots (id, analysis_mode, event_time, event_time_source)
         VALUES (gen_random_uuid(), 'analysis', now(), $1)",
    )
    .bind(EventTimeSource::Unset)
    .execute(db.pool())
    .await;
    assert!(mismatched.is_err());
}

#[tokio::test]
async fn one_result_per_module_with_details_under_a_gin_index() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let file = upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(
            ObservableKind::File,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    )
    .await
    .expect("adds");
    let details = json!({"lines": 3, "longest_line": 12, "rule": {"name": "x"}});
    insert_result(
        &mut tx,
        root.id,
        file.id,
        "example_line_counter",
        &result(details),
    )
    .await
    .expect("stores");
    tx.commit().await.expect("commits");

    // a second result from the same module for the same observable is refused
    let mut tx = db.begin().await.expect("begins");
    let second = insert_result(
        &mut tx,
        root.id,
        file.id,
        "example_line_counter",
        &result(json!({"lines": 4})),
    )
    .await;
    assert!(second.is_err());
    drop(tx);

    // details are queryable, through the GIN index
    let mut conn = db.pool().acquire().await.expect("connects");
    sqlx::raw_sql("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .expect("sets");
    let query = r#"SELECT module FROM analysis.results WHERE details @> '{"rule": {"name": "x"}}'"#;
    let modules: Vec<String> = sqlx::query_scalar(query)
        .fetch_all(&mut *conn)
        .await
        .expect("queries");
    assert_eq!(modules, ["example_line_counter"]);
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN {query}")))
        .fetch_all(&mut *conn)
        .await
        .expect("explains");
    let plan = plan.join("\n");
    assert!(plan.contains("results_details"), "{plan}");
}

/// A module that ran to its end and says it failed (ace3's `Analysis.error`): the reason is stored
/// beside the summary, the normal form holds it on that result alone, a module that depends on
/// the result reads it, and a failure with no reason is refused.
#[tokio::test]
async fn a_failed_result_keeps_its_reason_outside_its_details() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let file = upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::File, ZIP),
    )
    .await
    .expect("adds");
    let mut failed = result(json!({"lines": 3}));
    failed.error = Some("the tool exited with status 2: bad header".to_owned());
    insert_result(&mut tx, root.id, file.id, "failing", &failed)
        .await
        .expect("stores");
    insert_result(
        &mut tx,
        root.id,
        file.id,
        "fine",
        &result(json!({"lines": 3})),
    )
    .await
    .expect("stores");
    tx.commit().await.expect("commits");

    let stored: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT module, error FROM analysis.results ORDER BY module")
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        stored,
        [
            (
                "failing".to_owned(),
                Some("the tool exited with status 2: bad header".to_owned())
            ),
            ("fine".to_owned(), None),
        ]
    );

    // the normal form: the reason on the result that failed, and no key on the other, so a tree
    // made before the mark is still of this form
    let form = normal_form(db.pool(), root.id)
        .await
        .expect("reads")
        .expect("the root");
    let results = &form["observables"][format!("file:{ZIP}")]["results"];
    assert_eq!(
        results["failing"],
        json!({
            "summary": "3 lines",
            "error": "the tool exited with status 2: bad header",
            "tags": {},
            "details": {"lines": 3},
        })
    );
    assert!(results["fine"].get("error").is_none(), "{results}");

    // a module that depends on them gets each one's details, and the failed one's reason
    let read = tree::results_of(db.pool(), root.id, file.id, &["failing", "fine"])
        .await
        .expect("reads");
    assert_eq!(
        read,
        [
            tree::DependencyResult {
                module: "failing".to_owned(),
                details: json!({"lines": 3}),
                error: Some("the tool exited with status 2: bad header".to_owned()),
            },
            tree::DependencyResult {
                module: "fine".to_owned(),
                details: json!({"lines": 3}),
                error: None,
            },
        ]
    );

    // migration 0065 moves the reason a stored result kept in its details: its UPDATE, run here
    // on rows as the modules wrote them before it
    let migration = include_str!("../migrations/0065_result_error.sql");
    let start = migration
        .find("UPDATE analysis.results r")
        .expect("the migration's move");
    let end = start + migration[start..].find(';').expect("its end");
    let mut tx = db.begin().await.expect("begins");
    for (module, analysis_type, details) in [
        (
            "rdap_analyzer",
            "rdap_analysis",
            json!({"error": "rdap: no RDAP service", "lookup_protocol": null}),
        ),
        (
            "nrd_analyzer",
            "nrd_analysis",
            json!({"is_nrd": true, "lookup_error": null}),
        ),
        (
            "exif",
            "exif_analysis",
            json!({"error": " ", "exifdata": {}}),
        ),
        (
            "java_class_decompiler",
            "java_class_decompiler_analysis",
            json!({"decompiled_files": [], "stopped": "cfr did not finish: a timeout"}),
        ),
        // another type's key of the same name is its own
        ("other", "example_line_stats", json!({"error": "kept"})),
    ] {
        sqlx::query(
            "INSERT INTO analysis.results
                 (root_id, observable_id, module, analysis_type, schema_version, details)
             VALUES ($1, $2, $3, $4, 1, $5)",
        )
        .bind(root.id)
        .bind(file.id.0)
        .bind(module)
        .bind(analysis_type)
        .bind(details)
        .execute(tx.conn())
        .await
        .expect("an old row");
    }
    sqlx::raw_sql(&migration[start..=end])
        .execute(tx.conn())
        .await
        .expect("the move runs");
    let moved: Vec<(String, Option<String>, Value)> = sqlx::query_as(
        "SELECT module, error, details FROM analysis.results
         WHERE module NOT IN ('failing', 'fine') ORDER BY module",
    )
    .fetch_all(tx.conn())
    .await
    .expect("reads");
    assert_eq!(
        moved,
        [
            ("exif".to_owned(), None, json!({"exifdata": {}})),
            (
                "java_class_decompiler".to_owned(),
                Some("cfr did not finish: a timeout".to_owned()),
                json!({"decompiled_files": []})
            ),
            ("nrd_analyzer".to_owned(), None, json!({"is_nrd": true})),
            ("other".to_owned(), None, json!({"error": "kept"})),
            (
                "rdap_analyzer".to_owned(),
                Some("rdap: no RDAP service".to_owned()),
                json!({"lookup_protocol": null})
            ),
        ]
    );
    drop(tx);

    // a failure needs a reason: the table refuses a blank one, whatever wrote it
    for blank in ["", " \n\t"] {
        let mut tx = db.begin().await.expect("begins");
        let mut no_reason = result(json!({}));
        no_reason.error = Some(blank.to_owned());
        let refused = insert_result(&mut tx, root.id, file.id, "blank", &no_reason).await;
        let error = refused.expect_err("a blank reason is refused").to_string();
        assert!(error.contains("results_error_has_a_reason"), "{error}");
    }
}

const ZIP: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
const PART: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

/// One root with a file extracted from another, a detection and a result, written in the order
/// `reversed` says, so a test can see the order not matter.
async fn sample_root(db: &ace_core::Db, reversed: bool) -> uuid::Uuid {
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");

    let archive = NewObservable::new(ObservableKind::File, ZIP);
    let mut part = NewObservable::new(ObservableKind::File, PART);
    part.tags = vec!["z".to_owned(), "a".to_owned()];
    part.directives = vec!["sandbox".to_owned()];
    part.exclude_modules = vec!["archive".to_owned()];
    part.time = Some(
        Utc.with_ymd_and_hms(2026, 11, 1, 12, 0, 0)
            .single()
            .expect("a time"),
    );
    part.redirection = Some(ObservableRef::new(ObservableKind::File, ZIP));
    part.relationships = vec![Relationship::new(
        RelationshipKind::ExtractedFrom,
        ObservableRef::new(ObservableKind::File, ZIP),
    )];
    let order = if reversed {
        [part, archive]
    } else {
        [archive, part]
    };
    for observable in &order {
        upsert_observable(&mut tx, root.id, observable)
            .await
            .expect("adds");
    }
    let find = |value: &str| ObservableRef::new(ObservableKind::File, value);
    let zip = tree::find_observable(tx.conn(), root.id, &find(ZIP))
        .await
        .expect("finds")
        .expect("is there");
    let part = tree::find_observable(tx.conn(), root.id, &find(PART))
        .await
        .expect("finds")
        .expect("is there");

    tree::add_file(&mut tx, root.id, zip, "a.zip", &[])
        .await
        .expect("adds");
    tree::add_file(&mut tx, root.id, part, "a.zip.extracted/b", &[])
        .await
        .expect("adds");
    let additions = ObservableAdditions {
        yara_meta: vec![YaraMeta::new("type", "archive").expect("a tag")],
        ..ObservableAdditions::default()
    };
    tree::add_to_observable(&mut tx, root.id, zip, &additions)
        .await
        .expect("adds");

    let mut envelope = result(json!({"z": 1, "a": [{"y": 2, "b": 3}]}));
    envelope.tags = vec!["single_file_zip".to_owned()];
    let result_id = insert_result(&mut tx, root.id, zip, "archive", &envelope)
        .await
        .expect("stores");
    let detection = |details: Value| Detection {
        details: Some(details),
        ..Detection::new("a rule matched")
    };
    let details = [json!({"n": 2}), json!({"n": 1})];
    let details = if reversed {
        [details[1].clone(), details[0].clone()]
    } else {
        details
    };
    for d in details {
        tree::add_detection(&mut tx, root.id, zip, Some(result_id), &detection(d))
            .await
            .expect("adds");
    }
    tx.commit().await.expect("commits");
    root.id
}

#[tokio::test]
async fn the_normal_form_holds_the_tree_in_a_fixed_order() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let one = sample_root(db, false).await;
    let two = sample_root(db, true).await;

    let form = normal_form(db.pool(), one)
        .await
        .expect("reads")
        .expect("exists");
    assert_eq!(
        form,
        json!({
            "form": 1,
            "observables": {
                format!("file:{ZIP}"): {
                    "tags": {},
                    "directives": {},
                    "excluded_analysis": {},
                    "relationships": {},
                    "detections": {"a rule matched": [{"n": 1}, {"n": 2}]},
                    "paths": {"a.zip": {"type=archive": true}},
                    "results": {
                        "archive": {
                            "summary": "3 lines",
                            "tags": {"single_file_zip": true},
                            "details": {"z": 1, "a": [{"y": 2, "b": 3}]},
                        },
                    },
                },
                format!("file:{PART}"): {
                    "tags": {"a": true, "z": true},
                    "directives": {"sandbox": true},
                    "excluded_analysis": {"archive": true},
                    "relationships": {format!("extracted_from file:{ZIP}"): true},
                    "detections": {},
                    "time": "2026-11-01T12:00:00Z",
                    "redirection": format!("file:{ZIP}"),
                    "paths": {"a.zip.extracted/b": {}},
                    "results": {},
                },
            },
        })
    );

    // the same tree written in another order, in another root, is the same text: no id or time
    // of the run reaches it
    let text = to_text(&form).expect("writes");
    let other = normal_form(db.pool(), two)
        .await
        .expect("reads")
        .expect("exists");
    assert_eq!(text, to_text(&other).expect("writes"));
    assert!(!text.contains(&one.to_string()), "{text}");
    assert!(
        text.find("\"a\": [").expect("details") < text.find("\"z\": 1").expect("details"),
        "keys are sorted inside details: {text}"
    );
    assert!(text.ends_with("}\n"), "{text}");

    assert_eq!(
        normal_form(db.pool(), uuid::Uuid::new_v4())
            .await
            .expect("reads"),
        None
    );
}

/// Modules that do nothing themselves, for the tests of a file's path: two that write the same part
/// of a file under their own paths, as `mhtml` and `hidden_mime` do, and one that names what it
/// writes after the path it read its file under, as most parsers do. The tests play each one's part.
mod path_stubs {
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
        ($ty:ident, $name:literal, $required:expr) => {
            pub struct $ty;

            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
                const REQUIRED_DIRECTIVES: &'static [&'static str] = $required;
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

    // the writers run only on the file the test gives them
    stub!(WriterA, "test_writer_a", &["test_write"]);
    stub!(WriterB, "test_writer_b", &["test_write"]);
    stub!(Namer, "test_namer", &[]);

    pub const WRITER_A: Manifest = Manifest::lookup::<WriterA>();
    pub const WRITER_B: Manifest = Manifest::lookup::<WriterB>();
    pub const NAMER: Manifest = Manifest::lookup::<Namer>();
}

const PATHS_TOKEN: &str = "a-pool-token";

/// The core with the stubs' catalog, its lease API serving the namer's pool, and the stack's
/// bucket, which a file task's lease needs its bytes in.
struct PathStack {
    test_db: TestDb,
    bucket: ace_core::bucket::Bucket,
    orchestrator: ace_core::orchestrator::Orchestrator,
    url: String,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    _cache: tempfile::TempDir,
}

impl Drop for PathStack {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn path_stack() -> PathStack {
    use ace_core::api::{Api, ApiConfig, PoolAccess};
    use ace_core::bucket::{Bucket, BucketSettings};
    use ace_core::eligibility::Catalog;
    use ace_core::modes::{AnalysisMode, Modes};
    use ace_store::{BucketConfig, NodeCache, Store};

    let test_db = TestDb::new().await;
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
    let modes = Modes::ace3().with_mode(AnalysisMode {
        name: "paths".to_owned(),
        module_groups: Vec::new(),
        enabled_modules: vec![
            "test_writer_a".to_owned(),
            "test_writer_b".to_owned(),
            "test_namer".to_owned(),
        ],
        disabled_modules: Vec::new(),
    });
    let orchestrator = ace_core::orchestrator::Orchestrator::new(
        Catalog::new([
            path_stubs::WRITER_A,
            path_stubs::WRITER_B,
            path_stubs::NAMER,
        ]),
        modes,
    );
    let api = Api::new(
        test_db.db().clone(),
        bucket.clone(),
        orchestrator.clone(),
        ApiConfig::new(vec![PoolAccess::new(
            "test",
            PATHS_TOKEN,
            vec!["test_namer".to_owned()],
        )]),
    )
    .await
    .expect("the API starts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let server = tokio::spawn(ace_core::api::serve(listener, api, std::future::pending()));
    PathStack {
        test_db,
        bucket,
        orchestrator,
        url,
        server,
        _cache: cache,
    }
}

fn sha256_of(bytes: &[u8]) -> ace_results::Sha256 {
    use sha2::Digest as _;
    ace_results::Sha256(sha2::Sha256::digest(bytes).into())
}

/// What the namer writes from a file: the same bytes whatever path it read the file under.
fn named_bytes(sha256: &str) -> Vec<u8> {
    format!("named {sha256}").into_bytes()
}

impl PathStack {
    /// Lands `result` for a task `worker` owns.
    async fn land(
        &self,
        worker: &ace_core::queue::Worker,
        task: &ace_core::queue::Task,
        result: Value,
    ) {
        let mut tx = self.test_db.db().begin().await.expect("begins");
        self.orchestrator
            .land_result(
                &mut tx,
                worker,
                task,
                &serde_json::from_value(result).expect("a result envelope"),
            )
            .await
            .expect("lands");
        tx.commit().await.expect("commits");
    }

    /// Runs the namer through the lease API until it's given nothing, waiting up to `wait` seconds
    /// each time, and until the root is done when `until_done`. Returns the paths it read files
    /// under. It writes `<path>.named` from each file it didn't write itself.
    async fn run_namer(&self, root: uuid::Uuid, wait: u64, until_done: bool) -> Vec<String> {
        let worker = ace_core::queue::Worker::new(
            self.test_db.db().clone(),
            "test/namer",
            vec!["test_namer".to_owned()],
            std::time::Duration::from_secs(60),
        );
        let client = reqwest::Client::new();
        let mut paths = Vec::new();
        loop {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT FROM queue.tasks WHERE root_id = $1
                                 AND state IN ('queued', 'delayed', 'running'))",
            )
            .bind(root)
            .fetch_one(self.test_db.db().pool())
            .await
            .expect("reads");
            if until_done && !active {
                return paths;
            }
            let response = client
                .post(format!("{}{}", self.url, ace_sdk::wire::paths::LEASE))
                .bearer_auth(PATHS_TOKEN)
                .json(&json!({"worker": "namer", "wait_seconds": wait}))
                .send()
                .await
                .expect("answers");
            if response.status() == 204 {
                if until_done {
                    continue;
                }
                return paths;
            }
            assert_eq!(response.status(), 200);
            let mut leased: Vec<ace_sdk::wire::LeasedTask> =
                response.json().await.expect("its tasks");
            assert_eq!(leased.len(), 1, "it asked for one");
            let leased = leased.remove(0);
            let file = leased.observable.file.expect("a file task");
            let path = file.path.as_str().to_owned();
            let task = worker
                .owned(ace_core::queue::TaskId(leased.id))
                .await
                .expect("reads")
                .expect("the namer owns it");
            let files = if path.ends_with(".named") {
                json!([])
            } else {
                let bytes = named_bytes(&file.sha256.to_hex());
                json!([{
                    "path": format!("{path}.named"),
                    "sha256": sha256_of(&bytes).to_hex(),
                    "size": bytes.len(),
                }])
            };
            self.land(
                &worker,
                &task,
                json!({
                    "analysis_type": "test_stub",
                    "schema_version": 1,
                    "details": {"note": path},
                    "files": files,
                }),
            )
            .await;
            paths.push(path);
        }
    }

    /// One root: `outer.bin`, from which both writers write the same part, each under its own path,
    /// `first` landing first. The namer runs between the two and after them. Returns the root's
    /// normal form and the paths the namer read files under, sorted.
    async fn analyze(&self, first: &str) -> (Value, Vec<String>) {
        use ace_core::bucket::{ALERT_FILES, Hold};
        let db = self.test_db.db();
        let (outer, part) = (b"outer".as_slice(), b"part".as_slice());
        let root = NewRoot::new("paths");
        let mut tx = db.begin().await.expect("begins");
        tree::create_root(&mut tx, &root).await.expect("creates");
        tx.commit().await.expect("commits");
        let hold = Hold::root(root.id);
        for bytes in [
            outer.to_vec(),
            part.to_vec(),
            named_bytes(&sha256_of(outer).to_hex()),
            named_bytes(&sha256_of(part).to_hex()),
        ] {
            self.bucket
                .put_bytes(ALERT_FILES, &bytes, Some(&hold))
                .await
                .expect("puts");
        }
        let mut tx = db.begin().await.expect("begins");
        let mut file = NewObservable::new(ObservableKind::File, sha256_of(outer).to_hex());
        file.directives = vec!["test_write".to_owned()];
        let id = upsert_observable(&mut tx, root.id, &file)
            .await
            .expect("adds")
            .id;
        tree::add_file(&mut tx, root.id, id, "outer.bin", &[])
            .await
            .expect("adds");
        self.orchestrator
            .start(&mut tx, root.id)
            .await
            .expect("starts");
        tx.commit().await.expect("commits");

        let writers = ace_core::queue::Worker::new(
            db.clone(),
            "writers",
            vec!["test_writer_a".to_owned(), "test_writer_b".to_owned()],
            std::time::Duration::from_secs(60),
        );
        let one = writers.claim().await.expect("claims").expect("a task");
        let two = writers.claim().await.expect("claims").expect("a task");
        let (first, second) = if one.module == first {
            (one, two)
        } else {
            (two, one)
        };
        let write = |task: &ace_core::queue::Task| {
            let path = if task.module == "test_writer_a" {
                "outer.bin.a/part"
            } else {
                "outer.bin.b/part"
            };
            json!({
                "analysis_type": "test_stub",
                "schema_version": 1,
                "details": {"note": ""},
                "files": [{"path": path, "sha256": sha256_of(part).to_hex(), "size": part.len()}],
            })
        };
        self.land(&writers, &first, write(&first)).await;

        // the outer file is analyzed; the part waits for the writer still running, and so does
        // what the namer wrote from the outer file, which is as deep
        let mut paths = self.run_namer(root.id, 0, false).await;
        assert_eq!(paths, ["outer.bin"]);
        let part_state: Vec<(String, String)> = sqlx::query_as(
            "SELECT o.value, t.state::text FROM queue.tasks t
             JOIN analysis.observables o ON o.id = t.observable_id
             WHERE t.root_id = $1 AND t.module = 'test_namer' AND o.depth = 1
             ORDER BY o.value",
        )
        .bind(root.id)
        .fetch_all(db.pool())
        .await
        .expect("reads");
        assert_eq!(part_state.len(), 2, "{part_state:?}");
        assert!(
            part_state.iter().all(|(_, state)| state == "delayed"),
            "{part_state:?}"
        );

        self.land(&writers, &second, write(&second)).await;
        paths.extend(self.run_namer(root.id, 5, true).await);
        paths.sort();
        let form = normal_form(db.pool(), root.id)
            .await
            .expect("reads")
            .expect("exists");
        (form, paths)
    }
}

/// PLAN.md decision 15: a file two results write under two paths is analyzed once, under the same
/// path whichever lands first, so what's written from it is named the same on every run. The
/// writer whose path sorts last lands first half the time, and the namer is leased between the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_written_under_two_paths_is_analyzed_under_the_same_one_whichever_lands_first() {
    let stack = path_stack().await;
    let mut seen = std::collections::BTreeMap::new();
    for run in 0..20 {
        let first = if run % 2 == 0 {
            "test_writer_a"
        } else {
            "test_writer_b"
        };
        let (form, paths) = stack.analyze(first).await;
        assert_eq!(
            paths,
            [
                "outer.bin",
                "outer.bin.a/part",
                "outer.bin.a/part.named",
                "outer.bin.named",
            ],
            "run {run}, {first} first"
        );
        let text = to_text(&form).expect("writes");
        seen.entry(text).or_insert_with(Vec::new).push(first);
    }
    assert_eq!(seen.len(), 1, "{seen:#?}");
    let form: Value = serde_json::from_str(seen.keys().next().expect("a form")).expect("reads");
    let part = &form["observables"][format!("file:{}", sha256_of(b"part"))];
    // both paths are the file's; only one was analyzed, so only one has what's written from it
    assert_eq!(
        part["paths"],
        json!({"outer.bin.a/part": {}, "outer.bin.b/part": {}})
    );
    let named = &form["observables"][format!(
        "file:{}",
        sha256_of(&named_bytes(&sha256_of(b"part").to_hex()))
    )];
    assert_eq!(named["paths"], json!({"outer.bin.a/part.named": {}}));
}

/// The rule itself: the shallowest of a file's paths, by the results that wrote them, then the
/// first in byte order, settled once. A path written from deeper in the tree isn't taken even when
/// it sorts first, and a task as deep as the file doesn't hold it.
#[tokio::test]
async fn a_file_is_analyzed_under_its_shallowest_path_then_the_first_in_byte_order() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let file = NewObservable::new(ObservableKind::File, "ab".repeat(32));
    let mut tx = db.begin().await.expect("begins");
    let root = NewRoot::new("analysis");
    tree::create_root(&mut tx, &root).await.expect("creates");
    let id = tree::upsert_observable_at(&mut tx, root.id, &file, 2)
        .await
        .expect("adds")
        .id;
    tree::add_file_at(&mut tx, root.id, id, "b/z", &[], None, 2)
        .await
        .expect("adds");
    // the same file written from itself, a level down, where it sorts first
    tree::add_file_at(&mut tx, root.id, id, "a/a", &[], None, 3)
        .await
        .expect("adds");
    // and at its own depth by another writer: upper case sorts before lower in bytes, not in
    // every collation
    tree::add_file_at(&mut tx, root.id, id, "b/Z", &[], None, 2)
        .await
        .expect("adds");
    // an observable added again from deeper keeps its depth
    tree::upsert_observable_at(&mut tx, root.id, &file, 5)
        .await
        .expect("merges");
    tx.commit().await.expect("commits");
    assert_eq!(tree::depth(db.pool(), root.id, id).await.expect("reads"), 2);
    let path = |record: Option<tree::FileRecord>| record.expect("a path").path;
    assert_eq!(
        path(
            tree::analysis_file(db.pool(), root.id, id)
                .await
                .expect("reads")
        ),
        "b/Z"
    );
    let (chosen, _) = tree::analysis_file_state(db.pool(), root.id, id)
        .await
        .expect("reads");
    assert!(!chosen);

    let mut tx = db.begin().await.expect("begins");
    let chosen = tree::choose_analysis_file(&mut tx, root.id, id)
        .await
        .expect("chooses");
    assert_eq!(path(chosen), "b/Z");
    // a path that would sort first, arriving after the choice, changes nothing
    tree::add_file_at(&mut tx, root.id, id, "b/A", &[], None, 2)
        .await
        .expect("adds");
    assert_eq!(
        path(
            tree::choose_analysis_file(&mut tx, root.id, id)
                .await
                .expect("chooses")
        ),
        "b/Z"
    );
    tx.commit().await.expect("commits");
    let (chosen, _) = tree::analysis_file_state(db.pool(), root.id, id)
        .await
        .expect("reads");
    assert!(chosen);
    assert_eq!(
        path(
            tree::analysis_file(db.pool(), root.id, id)
                .await
                .expect("reads")
        ),
        "b/Z"
    );

    // what holds a file: a task nearer the root, not one as deep, nor one of a module left out
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root.id, id, "archive")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let held = |depth| async move {
        tree::pending_above(db.pool(), root.id, depth, &[])
            .await
            .expect("reads")
    };
    assert!(!held(2).await);
    assert!(held(3).await);
    assert!(
        !tree::pending_above(db.pool(), root.id, 3, &["archive".to_owned()])
            .await
            .expect("reads")
    );
}
