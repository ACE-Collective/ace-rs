//! PLAN.md 2.14's Done check: a worker with only an API token runs a task end to end. The
//! worker is the test pool binary, started with an empty environment plus the lease API's URL
//! and its pool's token, so it holds no database URL and no bucket key.

use crate::common;

use std::path::Path;
use std::time::Duration;

use ace_core::bucket::ALERT_FILES;
use ace_results::Sha256;
use ace_store::Store;
use sha2::Digest as _;

use common::{Core, test_pool};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_with_only_an_api_token_runs_a_task_end_to_end() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, zip) = core
        .root_with_file("file", "ace3/archive/test.zip", "test.zip")
        .await;
    assert_eq!(
        core.tasks(root).await,
        [("archive".to_owned(), zip.to_hex(), "queued".to_owned())]
    );

    let mut worker = test_pool(&core, &["once"]);
    let output = tokio::task::spawn_blocking(move || worker.output())
        .await
        .expect("joins")
        .expect("the worker runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(stdout.contains("(archive): done"), "{stdout}");

    let db = core.test_db.db();
    // the result is stored, and the file it extracted is in the tree, the bucket and the queue
    let result: (String, i32) = sqlx::query_as(
        "SELECT analysis_type, jsonb_array_length(details->'extracted_files')
         FROM analysis.results WHERE root_id = $1 AND module = 'archive'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("a result");
    assert_eq!(result, ("archive_analysis".to_owned(), 1));
    let (path, member): (String, String) = sqlx::query_as(
        "SELECT f.path, o.value FROM analysis.files f
         JOIN analysis.observables o ON o.id = f.observable_id
         WHERE f.root_id = $1 AND f.path <> 'test.zip'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("the extracted file");
    assert_eq!(
        path,
        "test.zip.extracted/Faktura.FS.17.9.20_2018_2_13_AI02668779.pdf.js"
    );
    let member: Sha256 = member.parse().expect("a sha256");
    let object = core
        .bucket
        .object(ALERT_FILES, &member)
        .await
        .expect("reads")
        .expect("the member is in the bucket");
    assert_eq!(object.size, 23405);
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2",
    )
    .bind(ALERT_FILES)
    .bind(member.to_hex())
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(holds, [("root".to_owned(), root.to_string())]);
    // the upload is gone once the core checked it and moved it into the pool
    let uploads = core.bucket.store().list("uploads/").await.expect("lists");
    assert!(
        !uploads.iter().any(|key| key.ends_with(&member.to_hex())),
        "{uploads:?}"
    );
    assert_eq!(
        core.tasks(root).await,
        [
            ("archive".to_owned(), zip.to_hex(), "done".to_owned()),
            ("archive".to_owned(), member.to_hex(), "queued".to_owned()),
        ]
    );
    // tidy the shared bucket
    for sha in [zip, member] {
        core.bucket
            .store()
            .delete(ALERT_FILES, &sha)
            .await
            .expect("deletes");
    }
    assert!(Store::key(ALERT_FILES, &member).is_ok());
}

/// A zero-byte output, such as a zip's empty member, is uploaded like any other: its presigned URL
/// signs `content-length`, so a request without that header is refused with a 403.
#[tokio::test]
async fn an_empty_file_uploads_to_its_presigned_url() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let client = ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w").expect("client");
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("empty");
    std::fs::write(&path, b"").expect("writes");
    let sha256 = Sha256(sha2::Sha256::digest(b"").into());
    let key = format!(
        "uploads/test-{}/{}",
        uuid::Uuid::new_v4().simple(),
        sha256.to_hex()
    );
    let store = core.bucket.store();
    let url = store
        .presign_put(&key, 0, Duration::from_secs(60))
        .await
        .expect("presigns");
    let url = ace_sdk::wire::Presigned {
        url: url.url,
        headers: url.headers,
    };
    client.upload(&url, &path).await.expect("uploads");
    let spooled = store.spool_key(&key, &sha256).await.expect("the object");
    assert_eq!(spooled.size, 0);
    store.delete_key(&key).await.expect("deletes");
}

/// evil.zip's one member is empty. The module's task ends done, the member reaches the tree and
/// the bucket, and its own task can download it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_archive_with_an_empty_member_runs_end_to_end() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, _, zip) = core
        .root_with_file("file", "ace3/archive/evil.zip", "evil.zip")
        .await;
    let empty = Sha256(sha2::Sha256::digest(b"").into());
    for _ in 0..2 {
        let mut worker = test_pool(&core, &["once"]);
        let output = tokio::task::spawn_blocking(move || worker.output())
            .await
            .expect("joins")
            .expect("the worker runs");
        assert!(
            output.status.success(),
            "{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        core.tasks(root).await,
        [
            ("archive".to_owned(), zip.to_hex(), "done".to_owned()),
            ("archive".to_owned(), empty.to_hex(), "done".to_owned()),
        ]
    );
    let object = core
        .bucket
        .object(ALERT_FILES, &empty)
        .await
        .expect("reads")
        .expect("the empty member is in the bucket");
    assert_eq!(object.size, 0);
}

#[tokio::test]
async fn a_request_without_the_pools_token_is_refused() {
    let core = Core::start(
        vec![ace_mod_archive::MANIFEST],
        &["archive"],
        Duration::from_secs(30),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, "not-the-token", "w").expect("a client");
    let refused = client.lease(&[], Duration::ZERO).await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 401, .. })
        ),
        "{refused:?}"
    );
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w").expect("a client");
    let other = client
        .lease(&["email_analyzer".to_owned()], Duration::ZERO)
        .await;
    assert!(
        matches!(
            &other,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{other:?}"
    );
    assert!(
        client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .is_none()
    );
}

/// The rules ace3's snort reference dumps read (PLAN.md 7.4).
fn snort_rules() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/snort/snort.rules")
}

/// A core whose test pool runs the modules with reads and archive, which declares none, and a
/// second pool, `other`, that runs the same.
async fn reads_core(rules: std::path::PathBuf) -> Core {
    let modules = [
        "snort_signature_analysis_v1",
        "email_conversation_frequency_analyzer",
        "nrd_analyzer",
        "user_defined_tagging",
        "archive",
    ];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_snort::MANIFEST,
            ace_mod_brocess::frequency::MANIFEST,
            ace_mod_nrd::MANIFEST,
            ace_mod_tag::user::MANIFEST,
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config.snort_rules(rules)
        },
    )
    .await
}

const OTHER_TOKEN: &str = "ace-rs-test-other-pool-token";

/// A root with a snort_sig observable for each value, and a task of `module` on the first.
async fn snort_root(core: &Core, values: &[&str], module: &str) -> uuid::Uuid {
    root_of(core, ace_results::ObservableKind::SnortSig, values, module).await
}

/// A root with an observable of `kind` for each value, and a task of `module` on the first.
async fn root_of(
    core: &Core,
    kind: ace_results::ObservableKind,
    values: &[&str],
    module: &str,
) -> uuid::Uuid {
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    for (i, value) in values.iter().enumerate() {
        let id = ace_core::tree::upsert_observable(
            &mut tx,
            root.id,
            &ace_results::NewObservable::new(kind, *value),
        )
        .await
        .expect("adds")
        .id;
        if i == 0 {
            ace_core::queue::enqueue(&mut tx, root.id, id, module)
                .await
                .expect("queues");
        }
    }
    tx.commit().await.expect("commits");
    root.id
}

fn subject(value: &str) -> serde_json::Value {
    serde_json::json!({"subject": {"type": "snort_sig", "value": value}})
}

/// What ace3's reference dump for `value` shows: the rule, or None for "unknown signature".
fn ace3_rule(value: &str) -> Option<String> {
    let dump = ace_testkit::reference::Dump::load(&format!(
        "snort_signature_analysis_v1/snort_sig_{value}"
    ))
    .expect("the dump reads");
    let details = &dump
        .analysis("SnortSignatureAnalysis_v1")
        .expect("an analysis")["details"];
    details["signature_id"]
        .is_string()
        .then(|| details["signature"].as_str().expect("a rule").to_owned())
}

fn status(result: &Result<serde_json::Value, ace_sdk::reads::ReadError>) -> Option<u16> {
    match result {
        Err(ace_sdk::reads::ReadError::Refused { status, .. }) => Some(*status),
        Err(ace_sdk::reads::ReadError::LeaseLost(_)) => Some(409),
        Err(ace_sdk::reads::ReadError::Unavailable { .. }) => Some(503),
        Err(_) => Some(0),
        Ok(_) => None,
    }
}

/// PLAN.md 7.2's contract for the first read built, `snort-signature` (7.4): the task's worker gets
/// the rule while it holds the lease, as ace3's dumps show it, and every other caller is refused.
#[tokio::test]
async fn a_read_answers_the_task_s_worker_while_it_holds_the_lease_and_refuses_the_rest() {
    let core = reads_core(snort_rules()).await;
    let values = [
        "1:9000001:3",
        "1:9000003:2",
        "1:9000002:2",
        "1:9000004:1",
        "9000001",
    ];
    let root = snort_root(&core, &values, "snort_signature_analysis_v1").await;
    let elsewhere = snort_root(&core, &["1:9000005:1"], "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["snort_signature_analysis_v1".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(task.root, root);
    let read = |client: &ace_pool::client::LeaseClient, body: serde_json::Value| {
        let client = client.clone();
        async move { client.read(task.id, "snort-signature", &body, false).await }
    };

    // the task's own observable, and the others in its root: the core's index of the rules file
    // answers as ace3's index did in its dumps
    let own = read(&client, serde_json::json!({})).await.expect("answers");
    assert_eq!(
        own["rule"].as_str().map(str::to_owned),
        ace3_rule(values[0])
    );
    for value in values {
        let answer = read(&client, subject(value)).await.expect("answers");
        assert_eq!(
            answer["rule"].as_str().map(str::to_owned),
            ace3_rule(value),
            "{value}"
        );
    }

    // a subject from another root, one in no root, and one that isn't a snort signature
    assert_eq!(
        status(&read(&client, subject("1:9000005:1")).await),
        Some(403)
    );
    assert_eq!(
        status(&read(&client, subject("1:9000099:1")).await),
        Some(403)
    );
    let not_snort = read(
        &client,
        serde_json::json!({"subject": {"type": "fqdn", "value": "1:9000003:2"}}),
    )
    .await;
    assert_eq!(status(&not_snort), Some(403));
    // a body that isn't the read's
    assert_eq!(
        status(&read(&client, serde_json::json!({"subject": 5})).await),
        Some(400)
    );
    // an unknown token, another worker of the pool, and another pool
    let unknown =
        ace_pool::client::LeaseClient::new(&core.url, "not-a-token", "w1").expect("a client");
    assert_eq!(
        status(&read(&unknown, serde_json::json!({})).await),
        Some(401)
    );
    assert_eq!(
        status(&read(&client.as_worker("w2"), serde_json::json!({})).await),
        Some(409)
    );
    let other_pool =
        ace_pool::client::LeaseClient::new(&core.url, OTHER_TOKEN, "w1").expect("a client");
    assert_eq!(
        status(&read(&other_pool, serde_json::json!({})).await),
        Some(409)
    );

    // a module that doesn't declare the read
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(archive_task.root, elsewhere);
    let undeclared = client
        .read(
            archive_task.id,
            "snort-signature",
            &serde_json::json!({}),
            false,
        )
        .await;
    assert_eq!(status(&undeclared), Some(403));
    // a read nobody declares
    let unknown_read = client
        .read(task.id, "no-such-read", &serde_json::json!({}), false)
        .await;
    assert_eq!(status(&unknown_read), Some(403));

    // the replay route takes the admin token and no lease
    let admin = ace_pool::client::LeaseClient::new(&core.url, common::ADMIN_TOKEN, "replay")
        .expect("a client");
    let replayed = admin
        .read(task.id, "snort-signature", &serde_json::json!({}), true)
        .await
        .expect("answers");
    assert_eq!(replayed, own);
    assert_eq!(
        status(
            &client
                .read(task.id, "snort-signature", &serde_json::json!({}), true)
                .await
        ),
        Some(401)
    );

    // a lease past its expiry reads nothing, though no one has claimed the task yet
    sqlx::query(
        "UPDATE queue.tasks SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(task.id)
    .execute(core.test_db.db().pool())
    .await
    .expect("expires the lease");
    assert_eq!(
        status(&read(&client, serde_json::json!({})).await),
        Some(409)
    );
    // the replay still reads it
    assert!(
        admin
            .read(task.id, "snort-signature", &serde_json::json!({}), true)
            .await
            .is_ok()
    );
}

/// A rules file that can't be read is the store behind the read being down: 503, and the module
/// fails the task as unavailable, so it runs again later.
#[tokio::test]
async fn a_read_whose_store_is_down_answers_503() {
    let dir = tempfile::tempdir().expect("a directory");
    // a directory where the file should be: it's there, and reading it fails
    let core = reads_core(dir.path().to_owned()).await;
    snort_root(&core, &["1:9000001:3"], "snort_signature_analysis_v1").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let answer = client
        .read(task.id, "snort-signature", &serde_json::json!({}), false)
        .await;
    assert_eq!(status(&answer), Some(503));
}

/// The snort module run by a pool, as the lookups pool runs it: its read goes through the pool's
/// client and its result lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_snort_module_reads_its_rule_through_the_lease_api() {
    let core = reads_core(snort_rules()).await;
    let root = snort_root(&core, &["1:9000001:3"], "snort_signature_analysis_v1").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_snort::SnortSignatureAnalyzer>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
        "{end:?}"
    );
    let (summary, id): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT summary, details->>'signature_id' FROM analysis.results
         WHERE root_id = $1 AND module = 'snort_signature_analysis_v1'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a result");
    assert_eq!(id.as_deref(), Some("9000001 rev 3"));
    assert!(
        summary
            .expect("a summary")
            .starts_with("Signature Analysis - (9000001 rev 3) alert http"),
    );
    // its end said how long its analyze took, and no CPU, since a lookup shares its process
    let (analyze, cpu) = run_cost(&core, root, "snort_signature_analysis_v1").await;
    assert!(analyze.is_some_and(|s| s >= 0.0), "{analyze:?}");
    assert_eq!(cpu, None);
}

/// What a task's runs cost in its pool, as its row keeps them (PLAN.md 3.6).
async fn run_cost(core: &Core, root: uuid::Uuid, module: &str) -> (Option<f64>, Option<f64>) {
    sqlx::query_as(
        "SELECT analyze_seconds, cpu_seconds FROM queue.tasks WHERE root_id = $1 AND module = $2",
    )
    .bind(root)
    .bind(module)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task")
}

/// A task's end carries what its run cost in its request's headers, beside a body that is the end
/// alone, and the core keeps each number that can be one: a negative time is a pool's bug, and one
/// past a day a hostile process's, so it's dropped and the end still lands, with a WARN naming the
/// task and the number.
#[tokio::test]
async fn an_ends_run_cost_is_kept_and_one_that_cant_be_a_time_is_dropped() {
    let logs = crate::secrets::Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    // the core serves on this test's one thread, so its log is caught here too
    let _logging = tracing::subscriber::set_default(subscriber);
    let core = reads_core(snort_rules()).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let skipped = || ace_sdk::wire::TaskEnd::Skipped {
        reason: "nothing to do".to_owned(),
        writes: Vec::new(),
    };
    for (analyze, cpu, kept) in [
        (Some(0.5), Some(0.25), (Some(0.5), Some(0.25))),
        (Some(-1.0), Some(0.25), (None, Some(0.25))),
        (None, None, (None, None)),
        // a hostile task process's, which float8 sums would overflow; a day is the most kept
        (Some(f64::MAX), Some(86_400.5), (None, None)),
        (Some(86_400.0), Some(f64::MAX), (Some(86_400.0), None)),
    ] {
        let root = snort_root(&core, &["1:9000001:3"], "snort_signature_analysis_v1").await;
        let task = client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let cost = ace_sdk::wire::RunCost {
            analyze_seconds: analyze,
            cpu_seconds: cpu,
        };
        client
            .end_timed(task.id, &skipped(), cost)
            .await
            .expect("ends");
        let (state, _) = common::task_of(&core, root, "snort_signature_analysis_v1").await;
        assert_eq!(state, "done");
        assert_eq!(
            run_cost(&core, root, "snort_signature_analysis_v1").await,
            kept,
            "{analyze:?} {cpu:?}"
        );
        let log = std::mem::take(&mut *logs.0.lock().expect("the log"));
        let log = String::from_utf8(log).expect("text");
        for (field, sent, kept) in [
            ("analyze_seconds", analyze, kept.0),
            ("cpu_seconds", cpu, kept.1),
        ] {
            let warned = log.lines().any(|line| {
                line.contains("WARN")
                    // the event's own field, not the request span's
                    && line.contains(&format!("task={}", ace_core::queue::TaskId(task.id)))
                    && line.contains(&format!("field=\"{field}\""))
            });
            assert_eq!(warned, sent.is_some() && kept.is_none(), "{field}: {log}");
        }
    }
}

/// The refusals every read shares, which the core makes before it reads anything: an unknown token
/// (401), another worker of the pool and another pool (409), a body that isn't the read's (400), a
/// subject from another root (403), a module that doesn't declare it (403, on `undeclared`), and,
/// last, since it ends the lease, a lease past its expiry (409). `ok` is a request the read answers.
async fn assert_refusals(
    core: &Core,
    task: i64,
    read: &'static str,
    ok: serde_json::Value,
    foreign: serde_json::Value,
    undeclared: i64,
) {
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    assert!(client.read(task, read, &ok, false).await.is_ok(), "{read}");
    let unknown =
        ace_pool::client::LeaseClient::new(&core.url, "not-a-token", "w1").expect("a client");
    assert_eq!(
        status(&unknown.read(task, read, &ok, false).await),
        Some(401),
        "{read}"
    );
    let w2 = client.as_worker("w2");
    assert_eq!(
        status(&w2.read(task, read, &ok, false).await),
        Some(409),
        "{read}"
    );
    let other = ace_pool::client::LeaseClient::new(&core.url, OTHER_TOKEN, "w1").expect("a client");
    assert_eq!(
        status(&other.read(task, read, &ok, false).await),
        Some(409),
        "{read}"
    );
    let bad = serde_json::json!({"subject": 5});
    assert_eq!(
        status(&client.read(task, read, &bad, false).await),
        Some(400),
        "{read}"
    );
    assert_eq!(
        status(&client.read(task, read, &foreign, false).await),
        Some(403),
        "{read}"
    );
    assert_eq!(
        status(&client.read(undeclared, read, &ok, false).await),
        Some(403),
        "{read}"
    );
    sqlx::query(
        "UPDATE queue.tasks SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(task)
    .execute(core.test_db.db().pool())
    .await
    .expect("expires the lease");
    assert_eq!(
        status(&client.read(task, read, &ok, false).await),
        Some(409),
        "{read}"
    );
}

/// The smtplog rows ace3's conversation frequency dumps counted from.
async fn insert_smtplog_fixture(core: &Core) {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/ace3/dumps/fixtures/brocess/smtplog.json"),
        )
        .expect("the fixture reads"),
    )
    .expect("JSON");
    for row in fixture["smtplog"].as_array().expect("rows") {
        sqlx::query(
            "INSERT INTO brocess.smtplog (source, destination, numconnections) VALUES ($1, $2, $3)",
        )
        .bind(row[0].as_str().expect("a source").as_bytes())
        .bind(row[1].as_str().expect("a destination").as_bytes())
        .bind(row[2].as_i64())
        .execute(core.test_db.db().pool())
        .await
        .expect("inserts");
    }
}

/// `smtp-counts` (PLAN.md 7.4): brocess's counts for each conversation ace3's dumps have, as ace3
/// counted them from the same rows, and the refusals every read makes.
#[tokio::test]
async fn smtp_counts_answers_as_ace3_counted_and_refuses_the_rest() {
    let core = reads_core(snort_rules()).await;
    insert_smtplog_fixture(&core).await;
    let values = [
        "sender@example.com|recipient@example.com",
        "sender@example.com|new@example.com",
        "once@example.org|recipient@example.com",
        "once@example.org|nobody@example.com",
        "stranger@example.net|recipient@example.com",
        "Sender@Example.com|other@example.com",
        "no-pipe@example.com",
        "a@example.com|b@example.com|c@example.com",
    ];
    let kind = ace_results::ObservableKind::EmailConversation;
    root_of(
        &core,
        kind,
        &values,
        "email_conversation_frequency_analyzer",
    )
    .await;
    let elsewhere = root_of(&core, kind, &["x@example.com|y@example.com"], "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(
            &["email_conversation_frequency_analyzer".to_owned()],
            Duration::ZERO,
        )
        .await
        .expect("leases")
        .expect("a task");
    for value in values {
        let answer = client
            .read(
                task.id,
                "smtp-counts",
                &serde_json::json!({"subject": {"type": "email_conversation", "value": value}}),
                false,
            )
            .await
            .expect("answers");
        let dump = ace_testkit::reference::Dump::load(&format!(
            "email_conversation_frequency_analyzer/email_conversation_{value}"
        ))
        .expect("the dump reads");
        let ace3 = &dump
            .analysis("EmailConversationFrequencyAnalysis")
            .expect("an analysis")["details"];
        assert_eq!(answer["source_count"], ace3["source_count"], "{value}");
        if !ace3["dest_count"].is_null() {
            assert_eq!(answer["conversation_count"], ace3["dest_count"], "{value}");
        }
    }
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(archive_task.root, elsewhere);
    let not_a_conversation =
        serde_json::json!({"subject": {"type": "snort_sig", "value": values[0]}});
    assert_eq!(
        status(
            &client
                .read(task.id, "smtp-counts", &not_a_conversation, false)
                .await
        ),
        Some(403)
    );
    assert_refusals(
        &core,
        task.id,
        "smtp-counts",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "email_conversation", "value": "x@example.com|y@example.com"}}),
        archive_task.id,
    )
    .await;
}

/// The conversation frequency module run as the lookups pool runs it: its read goes through the
/// pool's client, and its result and tag land.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_frequency_module_reads_its_counts_through_the_lease_api() {
    let core = reads_core(snort_rules()).await;
    insert_smtplog_fixture(&core).await;
    let root = root_of(
        &core,
        ace_results::ObservableKind::EmailConversation,
        &["sender@example.com|recipient@example.com"],
        "email_conversation_frequency_analyzer",
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_brocess::EmailConversationFrequencyAnalyzer>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
        "{end:?}"
    );
    let summary: Option<String> = sqlx::query_scalar(
        "SELECT summary FROM analysis.results
         WHERE root_id = $1 AND module = 'email_conversation_frequency_analyzer'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a result");
    assert_eq!(
        summary.as_deref(),
        Some("Email Conversation Frequency Analysis - 10 emails received before, 7 to this user")
    );
}

// ---- nrd_analyzer: the newly-registered read ----

/// The domains ace3's first refresh left in the list its nrd_analyzer dumps read
/// (tools/ace3/dumps/reference/nrd/reference.json), in the core's list.
async fn insert_nrd_fixture(core: &Core) {
    let reference: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(ace_testkit::reference::dumps_dir().join("nrd/reference.json"))
            .expect("the reference reads"),
    )
    .expect("JSON");
    let domains: Vec<String> = reference["refresh"][0]["database"]["domains"]
        .as_array()
        .expect("domains")
        .iter()
        .map(|d| d.as_str().expect("a domain").to_owned())
        .collect();
    sqlx::query("INSERT INTO nrd.domains (domain) SELECT unnest($1::text[])")
        .bind(&domains)
        .execute(core.test_db.db().pool())
        .await
        .expect("inserts");
}

/// `newly-registered` (PLAN.md 7.4): for each value ace3's nrd_analyzer dumps have, the core finds
/// it in the list, or doesn't, as ace3's `is_newly_registered` did over the same domains; it
/// answers only for the task's own observable; and the refusals every read makes.
#[tokio::test]
async fn newly_registered_answers_as_ace3_s_list_did_and_only_for_the_task_s_own_observable() {
    let core = reads_core(snort_rules()).await;
    insert_nrd_fixture(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let dumps = ace_testkit::reference::Dump::all("nrd_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 10);
    for dump in dumps {
        let input = &dump.value["input"]["observable"];
        let kind: ace_results::ObservableKind = input["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let value = input["value"].as_str().expect("a value");
        root_of(&core, kind, &[value], "nrd_analyzer").await;
        let task = client
            .lease(&["nrd_analyzer".to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let answer = client
            .read(task.id, "newly-registered", &serde_json::json!({}), false)
            .await
            .expect("answers");
        // ace3 made an analysis for every hit but example.com and its subdomain, a hit by its
        // parent, which RDAP said was registered in 1995, so it dropped them
        let ace3_listed = dump.analysis("NRDAnalysis").is_some()
            || ["fqdn_example.com", "fqdn_not-listed.example.com"].contains(&dump.short_name());
        assert_eq!(
            answer,
            serde_json::json!({"listed": ace3_listed}),
            "{value}"
        );
        client
            .end(
                task.id,
                &ace_sdk::wire::TaskEnd::Skipped {
                    reason: "checked".into(),
                    writes: Vec::new(),
                },
            )
            .await
            .expect("ends");
    }

    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["ace4-fresh.com", "ace4-second.org"],
        "nrd_analyzer",
    )
    .await;
    let elsewhere = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["x.example.com"],
        "archive",
    )
    .await;
    let task = client
        .lease(&["nrd_analyzer".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(task.root, root);
    let own = serde_json::json!({"subject": {"type": "fqdn", "value": "ace4-fresh.com"}});
    assert_eq!(
        client
            .read(task.id, "newly-registered", &own, false)
            .await
            .expect("answers"),
        serde_json::json!({"listed": true})
    );
    // another observable of its own root, listed or not, isn't the task's own
    let sibling = serde_json::json!({"subject": {"type": "fqdn", "value": "ace4-second.org"}});
    assert_eq!(
        status(
            &client
                .read(task.id, "newly-registered", &sibling, false)
                .await
        ),
        Some(403)
    );
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(archive_task.root, elsewhere);
    assert_refusals(
        &core,
        task.id,
        "newly-registered",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "fqdn", "value": "x.example.com"}}),
        archive_task.id,
    )
    .await;
}

/// The newly registered domains module run as the lookups pool runs it, with verification off:
/// its read goes through the pool's client, and its result and tag land.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_nrd_module_reads_the_list_through_the_lease_api() {
    let core = reads_core(snort_rules()).await;
    insert_nrd_fixture(&core).await;
    let root = root_of(
        &core,
        ace_results::ObservableKind::Url,
        &["https://login.ACE4-fresh.com/x"],
        "nrd_analyzer",
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let settings = serde_json::json!({"max_registration_age_days": 0});
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_nrd::NrdAnalyzer>::lookup(
                Some(&settings),
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
        "{end:?}"
    );
    let summary: Option<String> = sqlx::query_scalar(
        "SELECT summary FROM analysis.results WHERE root_id = $1 AND module = 'nrd_analyzer'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a result");
    assert_eq!(
        summary.as_deref(),
        Some("Newly Registered Domain: present in local NRD list")
    );
}

// ---- user_defined_tagging: the observable-tags read ----

/// The tag mappings ace3's user_defined_tagging dumps read (tools/ace3/dumps/fixtures/tag), in the
/// core's table, in the order the fixture lists them.
async fn insert_observable_tags_fixture(core: &Core) {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/ace3/dumps/fixtures/tag/observable_tags.json"),
        )
        .expect("the fixture reads"),
    )
    .expect("JSON");
    for mapping in fixture["tags"].as_array().expect("tags") {
        sqlx::query("INSERT INTO analysis.observable_tags (type, value, tag) VALUES ($1, $2, $3)")
            .bind(mapping["type"].as_str())
            .bind(mapping["value"].as_str())
            .bind(mapping["tag"].as_str())
            .execute(core.test_db.db().pool())
            .await
            .expect("inserts");
    }
}

/// `observable-tags` (PLAN.md 7.6): for each observable and file ace3's user_defined_tagging dumps
/// have, the core answers the tags ace3's database gave it, in their order; it answers only for the
/// task's own observable; it says when it cut an answer at its bound; and the refusals every read
/// makes.
#[tokio::test]
async fn observable_tags_answers_as_ace3_s_database_did_and_only_for_the_task_s_own_observable() {
    let core = reads_core(snort_rules()).await;
    insert_observable_tags_fixture(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let dumps = ace_testkit::reference::Dump::all("user_defined_tagging").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let input = &dump.value["input"]["observable"];
        let kind: ace_results::ObservableKind = input["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let value = input["value"].as_str().expect("a value");
        if kind == ace_results::ObservableKind::File {
            let path = ace_testkit::samples_dir().join("ace3/pcap/sslkeylog.txt");
            file_root(&core, &path, "sslkeylog.txt", "user_defined_tagging").await;
        } else {
            root_of(&core, kind, &[value], "user_defined_tagging").await;
        }
        let task = client
            .lease(&["user_defined_tagging".to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let answer = client
            .read(task.id, "observable-tags", &serde_json::json!({}), false)
            .await
            .expect("answers");
        let ace3 = &dump
            .analysis("UserDefinedTaggingAnalysis")
            .expect("an analysis")["details"]["tags_added"];
        assert_eq!(
            answer,
            serde_json::json!({"tags": ace3, "truncated": false}),
            "{value}"
        );
        client
            .end(
                task.id,
                &ace_sdk::wire::TaskEnd::Skipped {
                    reason: "checked".into(),
                    writes: Vec::new(),
                },
            )
            .await
            .expect("ends");
    }

    // past the bound, the first MAX_OBSERVABLE_TAGS, said to be cut
    sqlx::query(
        "INSERT INTO analysis.observable_tags (type, value, tag)
         SELECT 'fqdn', 'many.example', 'tag_' || lpad(n::text, 4, '0') FROM generate_series(1, $1) n",
    )
    .bind(i32::try_from(ace_sdk::reads::MAX_OBSERVABLE_TAGS + 1).expect("small"))
    .execute(core.test_db.db().pool())
    .await
    .expect("inserts");
    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["many.example", "tagged.example"],
        "user_defined_tagging",
    )
    .await;
    let elsewhere = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["x.example.com"],
        "archive",
    )
    .await;
    let task = client
        .lease(&["user_defined_tagging".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(task.root, root);
    let answer = client
        .read(task.id, "observable-tags", &serde_json::json!({}), false)
        .await
        .expect("answers");
    let tags = answer["tags"].as_array().expect("tags");
    assert_eq!(tags.len(), ace_sdk::reads::MAX_OBSERVABLE_TAGS);
    assert_eq!(tags[0], "tag_0001");
    assert_eq!(answer["truncated"], true);
    // another observable of its own root, tagged or not, isn't the task's own
    let sibling = serde_json::json!({"subject": {"type": "fqdn", "value": "tagged.example"}});
    assert_eq!(
        status(
            &client
                .read(task.id, "observable-tags", &sibling, false)
                .await
        ),
        Some(403)
    );
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(archive_task.root, elsewhere);
    assert_refusals(
        &core,
        task.id,
        "observable-tags",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "fqdn", "value": "x.example.com"}}),
        archive_task.id,
    )
    .await;
}

/// The user defined tagging module run as the lookups pool runs it: its read goes through the pool's
/// client, and its result and the tags land on its observable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_user_defined_tagging_module_reads_its_tags_through_the_lease_api() {
    let core = reads_core(snort_rules()).await;
    insert_observable_tags_fixture(&core).await;
    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["tagged.example"],
        "user_defined_tagging",
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_tag::UserDefinedTagging>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
        "{end:?}"
    );
    let row: (Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT r.summary, o.tags FROM analysis.results r
         JOIN analysis.observables o ON o.root_id = r.root_id AND o.id = r.observable_id
         WHERE r.root_id = $1 AND r.module = 'user_defined_tagging'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a result");
    assert_eq!(row.0.as_deref(), Some("User Defined Tagging: added 3 tags"));
    assert_eq!(row.1, ["phish_infra", "watchlist", "phish_infra2"]);
}

// ---- email_logger: the email-thread-domains read and the smtp-log and email-thread writes ----

/// A core whose pools run the email logger and archive, which declares no read or write.
async fn logger_core() -> Core {
    let modules = ["email_logger", "archive"];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_brocess::logger::MANIFEST,
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config
        },
    )
    .await
}

fn logger_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/email_logger")
        .join(name)
}

/// The email module's result for the email at `path`, as ace-rs parses it.
fn parsed_email(path: &std::path::Path) -> ace_results::ResultEnvelope<serde_json::Value> {
    let harness = ace_testkit::Harness::<ace_mod_email::EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let observable = harness
        .file("email.rfc822", path, &[])
        .expect("a file")
        .with_directive("original_email");
    let ace_sdk::Outcome::Done(result) = harness.run_parser(observable).expect("parses") else {
        panic!("{} isn't an email", path.display());
    };
    result.to_raw().expect("JSON")
}

/// A root holding the email at `path` with the email module's result for it, and a task of `module`
/// on it. Returns the root and the email's details.
async fn email_root(
    core: &Core,
    path: &std::path::Path,
    module: &str,
) -> (uuid::Uuid, ace_results::types::email::EmailDetails) {
    use ace_core::tree;
    let result = parsed_email(path);
    let db = core.test_db.db();
    let root = tree::NewRoot::new("email");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_file(
            ALERT_FILES,
            path,
            Some(&ace_core::bucket::Hold::root(root.id)),
        )
        .await
        .expect("puts the email")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let mut observable =
        ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.to_hex());
    observable.directives = vec!["original_email".to_owned()];
    let id = tree::upsert_observable(&mut tx, root.id, &observable)
        .await
        .expect("adds")
        .id;
    tree::add_file(&mut tx, root.id, id, "email.rfc822", &[])
        .await
        .expect("records the file");
    tree::insert_result(&mut tx, root.id, id, "email_analyzer", &result)
        .await
        .expect("stores the email's result");
    ace_core::queue::enqueue(&mut tx, root.id, id, module)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let analysis: ace_results::types::email::EmailAnalysis =
        serde_json::from_value(result.details).expect("an email result");
    (root.id, analysis.email.expect("a parsed email"))
}

/// brocess's thread store as ace3's dumps write it, in id order, without what the store makes of
/// the time it was written.
async fn thread_store(core: &Core) -> serde_json::Value {
    let pool = core.test_db.db().pool();
    let rows = |sql: &'static str| async move {
        sqlx::query_scalar::<_, serde_json::Value>(sql)
            .fetch_one(pool)
            .await
            .expect("reads the store")
    };
    serde_json::json!({
        "email_thread_message": rows(
            "SELECT coalesce(jsonb_agg(jsonb_build_object(
                 'thread_id', thread_id,
                 'thread_id_hash', upper(encode(thread_id_hash, 'hex')),
                 'message_id', message_id,
                 'message_id_hash', upper(encode(message_id_hash, 'hex')),
                 'in_reply_to', in_reply_to,
                 'normalized_subject', normalized_subject,
                 'normalized_subject_hash', upper(encode(normalized_subject_hash, 'hex')),
                 'from_address', from_address,
                 'from_domain', from_domain,
                 'direction', direction,
                 'message_date', to_char(message_date, 'YYYY-MM-DD HH24:MI:SS')) ORDER BY id),
                 '[]')
             FROM brocess.email_thread_message",
        )
        .await,
        "email_thread_domain": rows(
            "SELECT coalesce(jsonb_agg(jsonb_build_object(
                 'thread_id', thread_id,
                 'thread_id_hash', upper(encode(thread_id_hash, 'hex')),
                 'message_id_hash', upper(encode(message_id_hash, 'hex')),
                 'domain', domain,
                 'address', address,
                 'role', role,
                 'entry_hash', upper(encode(entry_hash, 'hex')),
                 'numseen', numseen) ORDER BY id), '[]')
             FROM brocess.email_thread_domain",
        )
        .await,
        "smtplog": rows(
            "SELECT coalesce(jsonb_agg(jsonb_build_array(
                 convert_from(source, 'UTF8'), convert_from(destination, 'UTF8'), numconnections)
                 ORDER BY source, destination), '[]')
             FROM brocess.smtplog",
        )
        .await,
    })
}

/// The same of a dump's `brocess_after`.
fn ace3_store(after: &serde_json::Value) -> serde_json::Value {
    let keep = |rows: &serde_json::Value, keys: &[&str]| -> Vec<serde_json::Value> {
        rows.as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                serde_json::Value::Object(
                    keys.iter()
                        .map(|k| ((*k).to_owned(), row[*k].clone()))
                        .collect(),
                )
            })
            .collect()
    };
    let mut smtplog: Vec<serde_json::Value> = after["smtplog"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| serde_json::json!([r[0], r[1], r[2]]))
        .collect();
    smtplog.sort_by_key(|r| r.to_string());
    serde_json::json!({
        "email_thread_message": keep(&after["email_thread_message"], &[
            "thread_id", "thread_id_hash", "message_id", "message_id_hash", "in_reply_to",
            "normalized_subject", "normalized_subject_hash", "from_address", "from_domain",
            "direction", "message_date",
        ]),
        "email_thread_domain": keep(&after["email_thread_domain"], &[
            "thread_id", "thread_id_hash", "message_id_hash", "domain", "address", "role",
            "entry_hash", "numseen",
        ]),
        "smtplog": smtplog,
    })
}

/// A read's earliest sighting as both stores have it: the seed's own time, or that the store wrote
/// the row while the runs went.
fn sighting(first_seen: &serde_json::Value) -> serde_json::Value {
    match first_seen.as_str() {
        Some("2026-10-01 08:00:00") => first_seen.clone(),
        Some(_) => serde_json::json!("<written>"),
        None => serde_json::Value::Null,
    }
}

fn sightings(established: &serde_json::Value) -> serde_json::Value {
    serde_json::Value::Array(
        established
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| {
                let mut d = d.clone();
                d["first_seen"] = sighting(&d["first_seen"]);
                d
            })
            .collect(),
    )
}

/// The email logger's thread dumps, replayed through the core: each email's
/// `email-thread-domains` read answers what ace3's reads answered, and the writes its end carries
/// leave brocess as ace3 left it, hashes and all, from the seed through the whole conversation.
/// Then a journaled email's recipients land in smtplog.
#[tokio::test]
async fn the_email_logger_s_read_and_writes_replay_ace3_s_thread_dumps() {
    let core = logger_core().await;
    let seed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(logger_fixture("seed.json")).expect("the seed reads"),
    )
    .expect("JSON");
    for row in seed["email_thread_domain"].as_array().expect("rows") {
        let hex = |key: &str| {
            row[key].as_str().map(|h| {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
                    .collect::<Vec<u8>>()
            })
        };
        sqlx::query(
            "INSERT INTO brocess.email_thread_domain
                 (thread_id, thread_id_hash, message_id_hash, domain, address, role, entry_hash,
                  numseen, firstseendate)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamp)",
        )
        .bind(row["thread_id"].as_str())
        .bind(hex("thread_id_hash"))
        .bind(hex("message_id_hash"))
        .bind(row["domain"].as_str())
        .bind(row["address"].as_str())
        .bind(row["role"].as_str())
        .bind(hex("entry_hash"))
        .bind(row["numseen"].as_i64())
        .bind(row["firstseendate"].as_str())
        .execute(core.test_db.db().pool())
        .await
        .expect("seeds");
    }
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let mut runs: Vec<(String, std::path::PathBuf)> = [
        "01_thread_start",
        "02_reply",
        "03_lookalike_reply",
        "04_no_reply_headers",
        "05_calendar_response",
        "06_same_subject_elsewhere",
        "07_no_message_id",
    ]
    .iter()
    .map(|name| {
        (
            format!("email_logger/thread/{name}"),
            logger_fixture(&format!("{name}.email.rfc822")),
        )
    })
    .collect();
    let journaled = "ace3/email/o365_journaled_multi_rcpt.email.rfc822";
    runs.push((
        format!("email_logger/{journaled}"),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples")
            .join(journaled),
    ));
    for (dump_name, path) in runs {
        let dump = ace_testkit::reference::Dump::load(&dump_name).expect("the dump reads");
        let (_, email) = email_root(&core, &path, "email_logger").await;
        let task = client
            .lease(&["email_logger".to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let context = ace_mod_brocess::threads::ThreadContext::of(&email, &[]);
        let reads = dump.value["brocess_reads"].as_array().expect("reads");
        if let Some(established) = reads.iter().find_map(|r| r.get("established")) {
            let request = ace_sdk::reads::EmailThreadDomainsRequest {
                thread_id: context.thread_id.clone(),
                thread_method: context.thread_method.to_owned(),
                normalized_subject: context.normalized_subject.clone(),
                participant_domains: context.participant_domains(),
            };
            let answer = client
                .read(
                    task.id,
                    "email-thread-domains",
                    &serde_json::to_value(&request).expect("JSON"),
                    false,
                )
                .await
                .unwrap_or_else(|e| panic!("{dump_name}: {e}"));
            assert_eq!(
                sightings(&answer["established"]),
                sightings(established),
                "{dump_name}"
            );
            let count = reads
                .iter()
                .find_map(|r| r.get("thread_message_count"))
                .expect("a count");
            assert_eq!(&answer["thread_message_count"], count, "{dump_name}");
            assert_eq!(answer["truncated"], false);
        } else {
            assert!(
                context.record().is_none(),
                "{dump_name}: no read, no thread"
            );
        }
        let mut writes = Vec::new();
        if let Some(rows) = ace_mod_brocess::logger::smtplog_rows(&email.log_entry) {
            writes.push(ace_sdk::writes::WireWrite {
                write: "smtp-log".to_owned(),
                body: serde_json::to_value(rows).expect("JSON"),
            });
        }
        if let Some(record) = context.record() {
            writes.push(ace_sdk::writes::WireWrite {
                write: "email-thread".to_owned(),
                body: serde_json::to_value(record).expect("JSON"),
            });
        }
        client
            .end(
                task.id,
                &ace_sdk::wire::TaskEnd::Skipped {
                    reason: "logged".to_owned(),
                    writes,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{dump_name}: {e}"));
        let mut store = thread_store(&core).await;
        let mut ace3 = ace3_store(&dump.value["brocess_after"]);
        if dump_name.ends_with(journaled) {
            // its dump started from an empty brocess, so only its smtplog rows are its own
            ace3["email_thread_message"] = store["email_thread_message"].clone();
            ace3["email_thread_domain"] = store["email_thread_domain"].clone();
            assert!(!ace3["smtplog"].as_array().expect("rows").is_empty());
        } else {
            store["smtplog"] = ace3["smtplog"].clone();
        }
        assert_eq!(store, ace3, "{dump_name}");
    }
    // another email of the same thread, recorded again, changes nothing: ace3's ON DUPLICATE KEY
    // UPDATE id = id
    let before = thread_store(&core).await;
    let (_, email) = email_root(
        &core,
        &logger_fixture("02_reply.email.rfc822"),
        "email_logger",
    )
    .await;
    let task = client
        .lease(&["email_logger".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let record = ace_mod_brocess::threads::ThreadContext::of(&email, &[])
        .record()
        .expect("a thread");
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "logged".to_owned(),
                writes: vec![ace_sdk::writes::WireWrite {
                    write: "email-thread".to_owned(),
                    body: serde_json::to_value(record).expect("JSON"),
                }],
            },
        )
        .await
        .expect("ends");
    assert_eq!(thread_store(&core).await, before);
}

fn thread_request(email: &ace_results::types::email::EmailDetails) -> serde_json::Value {
    let context = ace_mod_brocess::threads::ThreadContext::of(email, &[]);
    serde_json::to_value(ace_sdk::reads::EmailThreadDomainsRequest {
        thread_id: context.thread_id.clone(),
        thread_method: context.thread_method.to_owned(),
        normalized_subject: context.normalized_subject.clone(),
        participant_domains: context.participant_domains(),
    })
    .expect("JSON")
}

/// `email-thread-domains`' refusals, a thread or subject no email in the root has (403), its bound
/// on the domains asked about (403) and on the rows read (truncated), and the replay route.
#[tokio::test]
async fn email_thread_domains_refuses_what_isn_t_the_root_s_thread_and_says_when_it_truncated() {
    let core = logger_core().await;
    let (_, email) = email_root(
        &core,
        &logger_fixture("02_reply.email.rfc822"),
        "email_logger",
    )
    .await;
    let (_, other) = email_root(
        &core,
        &logger_fixture("06_same_subject_elsewhere.email.rfc822"),
        "archive",
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["email_logger".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let ok = thread_request(&email);
    // a thread the root has, past the bound of rows read
    let thread_hash = ace_core::writes::hash("<inv-1@example.com>");
    sqlx::query(
        "INSERT INTO brocess.email_thread_domain
             (thread_id, thread_id_hash, domain, address, role, entry_hash)
         SELECT '<inv-1@example.com>', $1, 'example.com', 'a' || n || '@example.com', 'to',
                sha256(n::text::bytea)
         FROM generate_series(1, 10001) AS n",
    )
    .bind(&thread_hash)
    .execute(core.test_db.db().pool())
    .await
    .expect("fills the thread");
    let answer = client
        .read(task.id, "email-thread-domains", &ok, false)
        .await
        .expect("answers");
    assert_eq!(answer["truncated"], true);
    assert_eq!(answer["established"].as_array().map(Vec::len), Some(10_000));
    let admin =
        ace_pool::client::LeaseClient::new(&core.url, common::ADMIN_TOKEN, "w1").expect("a client");
    assert!(
        admin
            .read(task.id, "email-thread-domains", &ok, true)
            .await
            .is_ok()
    );
    let mut wrong_subject = ok.clone();
    wrong_subject["normalized_subject"] = serde_json::json!("another subject");
    assert_eq!(
        status(
            &client
                .read(task.id, "email-thread-domains", &wrong_subject, false)
                .await
        ),
        Some(403)
    );
    let mut too_many = ok.clone();
    too_many["participant_domains"] = serde_json::json!(
        (0..101)
            .map(|n| format!("d{n}.example"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        status(
            &client
                .read(task.id, "email-thread-domains", &too_many, false)
                .await
        ),
        Some(403)
    );
    assert_refusals(
        &core,
        task.id,
        "email-thread-domains",
        ok,
        thread_request(&other),
        archive_task.id,
    )
    .await;
}

/// A task's writes land with its end and only then: a write the module doesn't declare, one about
/// another email, one past its bound or one that doesn't read is refused and fails the task with
/// nothing written; a lost lease writes nothing; and a module's own write lands once.
#[tokio::test]
async fn a_task_s_writes_land_with_its_end_or_not_at_all() {
    let core = logger_core().await;
    let journaled = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/ace3/email/o365_journaled_multi_rcpt.email.rfc822");
    let smtplog = |source: &str| serde_json::json!({"rows": [{"source": source, "destination": "x@example.org"}]});
    let write = |name: &str, body: serde_json::Value| ace_sdk::writes::WireWrite {
        write: name.to_owned(),
        body,
    };
    let rows = |core: &Core| {
        let pool = core.test_db.db().pool().clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM brocess.smtplog")
                .fetch_one(&pool)
                .await
                .expect("counts")
        }
    };
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let skipped = |writes| ace_sdk::wire::TaskEnd::Skipped {
        reason: "logged".to_owned(),
        writes,
    };
    let refusals = [
        // archive declares no write
        (
            "archive",
            vec![write("smtp-log", smtplog("a@example.com"))],
            403,
        ),
        (
            "email_logger",
            vec![write("no-such-write", serde_json::json!({}))],
            403,
        ),
        (
            "email_logger",
            vec![write("smtp-log", serde_json::json!({"rows": 5}))],
            400,
        ),
        (
            "email_logger",
            vec![write(
                "smtp-log",
                serde_json::json!({"rows": (0..1001).map(|n| serde_json::json!(
                    {"source": "a@example.com", "destination": format!("{n}@example.org")}
                )).collect::<Vec<_>>()}),
            )],
            403,
        ),
        (
            "email_logger",
            vec![
                write("smtp-log", smtplog("a@example.com")),
                write(
                    "email-thread",
                    serde_json::json!({
                        "thread_id": "<someone-else@example.com>",
                        "message_id": "<someone-else@example.com>",
                        "in_reply_to": null, "normalized_subject": null, "from_address": null,
                        "from_domain": null, "direction": null, "message_date": null,
                        "participants": [],
                    }),
                ),
            ],
            403,
        ),
    ];
    for (module, writes, expected) in refusals {
        let (root, _) = email_root(&core, &journaled, module).await;
        let task = client
            .lease(&[module.to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let refused = client.end(task.id, &skipped(writes)).await;
        assert!(
            matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
            "{module}: {refused:?}"
        );
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "failed", "{module}");
        assert!(error.is_some(), "{module}");
        assert_eq!(rows(&core).await, 0, "{module}: nothing written");
    }
    // a lease lost before the end writes nothing
    let (_, _) = email_root(&core, &journaled, "email_logger").await;
    let task = client
        .lease(&["email_logger".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let w2 = client.as_worker("w2");
    let lost = w2
        .end(
            task.id,
            &skipped(vec![write("smtp-log", smtplog("a@example.com"))]),
        )
        .await;
    assert!(
        matches!(lost, Err(ace_pool::client::ClientError::LeaseLost(_))),
        "{lost:?}"
    );
    assert_eq!(rows(&core).await, 0);
    // its own worker's end lands it, and the same pair again counts twice, as in ace3
    client
        .end(
            task.id,
            &skipped(vec![write(
                "smtp-log",
                serde_json::json!({"rows": [
                    {"source": "a@example.com", "destination": "x@example.org"},
                    {"source": "a@example.com", "destination": "x@example.org"},
                ]}),
            )]),
        )
        .await
        .expect("ends");
    let counted: (i64, f64) = sqlx::query_as(
        "SELECT numconnections, firstconnectdate FROM brocess.smtplog WHERE source = 'a@example.com'::bytea",
    )
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a row");
    assert_eq!(counted.0, 2);
    assert_eq!(
        counted.1.fract(),
        0.0,
        "whole seconds, as UNIX_TIMESTAMP(NOW())"
    );
    // a second end of the same task is refused, and writes nothing more
    let again = client
        .end(
            task.id,
            &skipped(vec![write("smtp-log", smtplog("a@example.com"))]),
        )
        .await;
    assert!(again.is_err());
    let count: i64 = sqlx::query_scalar(
        "SELECT numconnections FROM brocess.smtplog WHERE source = 'a@example.com'::bytea",
    )
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("a row");
    assert_eq!(count, 2);
}

/// The email logger run as the lookups pool runs it, on an email whose thread an earlier one
/// started: its read goes through the pool's client, its writes land with its skip, and no result
/// is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_email_logger_runs_through_the_lease_api() {
    let core = logger_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_brocess::EmailLogger>::lookup(
                // no fluent-bit here: what goes to it is the reference test's
                Some(&serde_json::json!({"fluent_bit_logging_enabled": false})),
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    for name in ["01_thread_start", "02_reply"] {
        let (root, _) = email_root(
            &core,
            &logger_fixture(&format!("{name}.email.rfc822")),
            "email_logger",
        )
        .await;
        let task = client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let end = ace_pool::run::run_in_process(
            &client,
            &modules,
            task,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .expect("runs");
        assert!(
            matches!(&end, ace_sdk::wire::TaskEnd::Skipped { writes, .. } if writes.len() == 1),
            "{end:?}"
        );
        let (state, _) = common::task_of(&core, root, "email_logger").await;
        assert_eq!(state, "done");
        let results: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM analysis.results WHERE root_id = $1 AND module = 'email_logger'",
        )
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("counts");
        assert_eq!(results, 0);
    }
    let messages: i64 = sqlx::query_scalar("SELECT count(*) FROM brocess.email_thread_message")
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("counts");
    assert_eq!(messages, 2);
}

// ---- email_thread_analyzer: the email-thread read ----

fn unhex(value: &serde_json::Value) -> Option<Vec<u8>> {
    let h = value.as_str()?;
    Some(
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
            .collect(),
    )
}

/// brocess's thread store as a dump's brocess has it, rows in order, times and all.
async fn seed_thread_store(core: &Core, store: &serde_json::Value) {
    let pool = core.test_db.db().pool();
    for m in store["email_thread_message"].as_array().expect("rows") {
        sqlx::query(
            "INSERT INTO brocess.email_thread_message
                 (insert_date, thread_id, thread_id_hash, message_id, message_id_hash, in_reply_to,
                  normalized_subject, normalized_subject_hash, from_address, from_domain,
                  direction, message_date)
             VALUES ($1::timestamp, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamp)",
        )
        .bind(m["insert_date"].as_str())
        .bind(m["thread_id"].as_str())
        .bind(unhex(&m["thread_id_hash"]))
        .bind(m["message_id"].as_str())
        .bind(unhex(&m["message_id_hash"]))
        .bind(m["in_reply_to"].as_str())
        .bind(m["normalized_subject"].as_str())
        .bind(unhex(&m["normalized_subject_hash"]))
        .bind(m["from_address"].as_str())
        .bind(m["from_domain"].as_str())
        .bind(m["direction"].as_i64().map(|d| d as i16))
        .bind(m["message_date"].as_str())
        .execute(pool)
        .await
        .expect("seeds a message");
    }
    for d in store["email_thread_domain"].as_array().expect("rows") {
        sqlx::query(
            "INSERT INTO brocess.email_thread_domain
                 (thread_id, thread_id_hash, message_id_hash, domain, address, role, entry_hash,
                  numseen, firstseendate)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamp)",
        )
        .bind(d["thread_id"].as_str())
        .bind(unhex(&d["thread_id_hash"]))
        .bind(unhex(&d["message_id_hash"]))
        .bind(d["domain"].as_str())
        .bind(d["address"].as_str())
        .bind(d["role"].as_str())
        .bind(unhex(&d["entry_hash"]))
        .bind(d["numseen"].as_i64())
        .bind(d["firstseendate"].as_str())
        .execute(pool)
        .await
        .expect("seeds a participant");
    }
}

/// Participants in the order ace3's `Conversation` keeps them, which the dumps record: those tied to
/// no message, then each message's, in the order the first of each was read.
fn as_ace3_keeps_them(participants: &serde_json::Value) -> serde_json::Value {
    let rows = participants.as_array().cloned().unwrap_or_default();
    let mut order: Vec<serde_json::Value> = Vec::new();
    for row in &rows {
        if !row["message_id_hex"].is_null() && !order.contains(&row["message_id_hex"]) {
            order.push(row["message_id_hex"].clone());
        }
    }
    let unattributed = rows
        .iter()
        .filter(|r| r["message_id_hex"].is_null())
        .cloned();
    let attributed = order.iter().flat_map(|hex| {
        rows.iter()
            .filter(move |r| &r["message_id_hex"] == hex)
            .cloned()
    });
    serde_json::Value::Array(unattributed.chain(attributed).collect())
}

/// A core whose pools run the thread module and archive, which declares no read.
async fn thread_core() -> Core {
    let modules = ["email_thread_analyzer", "archive"];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_brocess::thread::MANIFEST,
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config
        },
    )
    .await
}

/// `email-thread` over the brocess the logger's thread runs left: for each of the thread module's
/// dumps, the core answers what ace3's `get_conversation` answered, with the dump's caps.
#[tokio::test]
async fn email_thread_answers_what_ace3_s_get_conversation_did() {
    let core = thread_core().await;
    let store = ace_testkit::reference::Dump::load("email_logger/thread/07_no_message_id")
        .expect("the dump reads")
        .value["brocess_after"]
        .clone();
    seed_thread_store(&core, &store).await;
    let dumps = ace_testkit::reference::Dump::all("email_thread_analyzer").expect("the dumps");
    let values: Vec<String> = dumps
        .iter()
        .map(|d| {
            d.value["input"]["observable"]["value"]
                .as_str()
                .expect("a value")
                .to_owned()
        })
        .collect();
    let value_refs: Vec<&str> = values.iter().map(String::as_str).collect();
    root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &value_refs,
        "email_thread_analyzer",
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["email_thread_analyzer".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    for (dump, value) in dumps.iter().zip(&values) {
        let name = dump.short_name();
        let (max_messages, max_threads) = if name.ends_with(".capped") {
            (2, 1)
        } else {
            (50, 50)
        };
        let answer = client
            .read(
                task.id,
                "email-thread",
                &serde_json::json!({
                    "subject": {"type": "message_id", "value": value},
                    "max_messages": max_messages, "max_threads": max_threads,
                }),
                false,
            )
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let ace3 = dump.value["brocess_reads"]
            .as_array()
            .and_then(|reads| reads.iter().find_map(|r| r.get("conversation")))
            .expect("ace3 read it");
        let mut ace_rs = answer["conversation"].clone();
        if let Some(participants) = ace_rs.get_mut("participants") {
            *participants = as_ace3_keeps_them(participants);
        }
        assert_eq!(&ace_rs, ace3, "{name}");
    }
}

/// `email-thread`'s refusals, a subject that isn't a message_id (403), its caps, and the cut it
/// says it made of the rows the roles come from.
#[tokio::test]
async fn email_thread_refuses_the_rest_and_says_when_it_cut_the_roles() {
    let core = thread_core().await;
    let store = ace_testkit::reference::Dump::load("email_logger/thread/07_no_message_id")
        .expect("the dump reads")
        .value["brocess_after"]
        .clone();
    seed_thread_store(&core, &store).await;
    let kind = ace_results::ObservableKind::MessageId;
    root_of(
        &core,
        kind,
        &["<inv-4@example.com>"],
        "email_thread_analyzer",
    )
    .await;
    let elsewhere = root_of(&core, kind, &["<inv-1@example.com>"], "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["email_thread_analyzer".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(archive_task.root, elsewhere);
    let ok = serde_json::json!({"max_messages": 100000, "max_threads": 100000});
    let answer = client
        .read(task.id, "email-thread", &ok, false)
        .await
        .expect("caps past 500 are cut to it");
    assert_eq!(answer["conversation"]["roles_truncated"], false);
    // a same-subject thread past the bound of rows read
    sqlx::query(
        "INSERT INTO brocess.email_thread_domain
             (thread_id, thread_id_hash, domain, address, role, entry_hash)
         SELECT '<inv-4@example.com>', $1, 'example.com', 'a' || n || '@example.com', 'to',
                sha256(n::text::bytea)
         FROM generate_series(1, 10001) AS n",
    )
    .bind(ace_core::writes::hash("<inv-4@example.com>"))
    .execute(core.test_db.db().pool())
    .await
    .expect("fills the thread");
    let answer = client
        .read(task.id, "email-thread", &ok, false)
        .await
        .expect("answers");
    assert_eq!(answer["conversation"]["roles_truncated"], true);
    let not_a_message_id = serde_json::json!({
        "subject": {"type": "fqdn", "value": "example.com"}, "max_messages": 1, "max_threads": 1,
    });
    assert_eq!(
        status(
            &client
                .read(task.id, "email-thread", &not_a_message_id, false)
                .await
        ),
        Some(403)
    );
    let never = client
        .read(
            task.id,
            "email-thread",
            &serde_json::json!({"max_messages": 1, "max_threads": 1}),
            false,
        )
        .await
        .expect("answers");
    assert!(never["conversation"].is_object());
    assert_refusals(
        &core,
        task.id,
        "email-thread",
        ok,
        serde_json::json!({"subject": {"type": "message_id", "value": "<inv-1@example.com>"},
                           "max_messages": 1, "max_threads": 1}),
        archive_task.id,
    )
    .await;
}

/// The thread module run as the lookups pool runs it: its read goes through the pool's client and
/// its result lands; a message never recorded gets none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_thread_module_reads_its_conversation_through_the_lease_api() {
    let core = thread_core().await;
    let store = ace_testkit::reference::Dump::load("email_logger/thread/07_no_message_id")
        .expect("the dump reads")
        .value["brocess_after"]
        .clone();
    seed_thread_store(&core, &store).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_brocess::EmailThreadAnalyzer>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    for (value, stored) in [("<inv-3@examp1e.com>", 1), ("<never@example.com>", 0)] {
        let root = root_of(
            &core,
            ace_results::ObservableKind::MessageId,
            &[value],
            "email_thread_analyzer",
        )
        .await;
        let task = client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        ace_pool::run::run_in_process(
            &client,
            &modules,
            task,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .expect("runs");
        let results: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM analysis.results
             WHERE root_id = $1 AND module = 'email_thread_analyzer'",
        )
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("counts");
        assert_eq!(results, stored, "{value}");
    }
}

/// A lookup that asks the thread store which of its own message id and two others it holds, and
/// fails with the answer, so a test reads what reached it through the pool's client.
mod recorded {
    use ace_results::ObservableKind;
    use ace_sdk::example::LineStats;
    use ace_sdk::reads::{Read, ReadKind, RecordedMessageIds, RecordedMessageIdsRequest};
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    pub struct AsksTheStore;

    impl Module for AsksTheStore {
        const NAME: &'static str = "test_recorded_message_ids";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::MessageId];
        const READS: &'static [Read] = &[RecordedMessageIds::READ];
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(AsksTheStore)
        }
    }

    impl Lookup for AsksTheStore {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            let answer = ctx
                .read::<RecordedMessageIds>(&RecordedMessageIdsRequest {
                    message_ids: vec![
                        ctx.observable().value.clone(),
                        "never@example.com".to_owned(),
                        String::new(),
                    ],
                })
                .await?;
            Err(ModuleError::other(format!(
                "recorded: {}",
                answer.recorded.join(" ")
            )))
        }
    }
}

/// Two messages in the thread store, in threads of their own.
async fn seed_recorded_messages(core: &Core) {
    sqlx::query(
        "INSERT INTO brocess.email_thread_message
             (thread_id, thread_id_hash, message_id, message_id_hash)
         SELECT id, sha256(convert_to(id, 'UTF8')), id, sha256(convert_to(id, 'UTF8'))
         FROM unnest(ARRAY['<scanned@example.com>', '<other@example.org>']) AS id",
    )
    .execute(core.test_db.db().pool())
    .await
    .expect("seeds the store");
    // the same message recorded in a second thread is one answer
    sqlx::query(
        "INSERT INTO brocess.email_thread_message
             (thread_id, thread_id_hash, message_id, message_id_hash)
         VALUES ('<parent@example.com>', sha256(convert_to('<parent@example.com>', 'UTF8')),
                 '<scanned@example.com>', sha256(convert_to('<scanned@example.com>', 'UTF8')))",
    )
    .execute(core.test_db.db().pool())
    .await
    .expect("seeds the second thread");
}

/// `recorded-message-ids` (PLAN.md decision 29), ace3's `get_recorded_message_ids`: which of the
/// ids the store holds in any thread, normalized as the logger records them, each once; an empty
/// id is dropped; past 500 ids, or for a task whose observable isn't a message_id, it refuses
/// (403); and the rest of the contract's refusals.
#[tokio::test]
async fn recorded_message_ids_answers_what_the_store_holds_and_refuses_the_rest() {
    let modules = ["test_recorded_message_ids", "archive"];
    let core = Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_sdk::Manifest::lookup::<recorded::AsksTheStore>(),
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config
        },
    )
    .await;
    seed_recorded_messages(&core).await;
    let kind = ace_results::ObservableKind::MessageId;
    root_of(
        &core,
        kind,
        &["<anchor@example.com>"],
        "test_recorded_message_ids",
    )
    .await;
    root_of(&core, kind, &["<elsewhere@example.com>"], "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = lease_one(&client, "test_recorded_message_ids").await;
    let archive_task = lease_one(&client, "archive").await;

    let asked = serde_json::json!({"message_ids": [
        "scanned@example.com", " <other@example.org> ", "<never@example.com>", "",
        "<scanned@example.com>",
    ]});
    let answer = client
        .read(task.id, "recorded-message-ids", &asked, false)
        .await
        .expect("answers");
    assert_eq!(
        answer,
        serde_json::json!({"recorded": ["<other@example.org>", "<scanned@example.com>"]})
    );
    let none = client
        .read(
            task.id,
            "recorded-message-ids",
            &serde_json::json!({"message_ids": []}),
            false,
        )
        .await
        .expect("answers");
    assert_eq!(none, serde_json::json!({"recorded": []}));
    let at_the_bound: Vec<String> = (0..500).map(|n| format!("<{n}@example.com>")).collect();
    assert!(
        client
            .read(
                task.id,
                "recorded-message-ids",
                &serde_json::json!({"message_ids": at_the_bound}),
                false,
            )
            .await
            .is_ok()
    );
    let past_the_bound: Vec<String> = (0..501).map(|n| format!("<{n}@example.com>")).collect();
    assert_refusals(
        &core,
        task.id,
        "recorded-message-ids",
        asked,
        serde_json::json!({"message_ids": past_the_bound}),
        archive_task.id,
    )
    .await;
}

/// The read refuses a task whose observable isn't a message_id, and the module that declares it
/// gets its answer through the pool's client, as the lookups pool runs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recorded_message_ids_reaches_a_module_through_the_lease_api() {
    let names = ["test_recorded_message_ids"];
    let core = Core::start(
        vec![ace_sdk::Manifest::lookup::<recorded::AsksTheStore>()],
        &names,
        Duration::from_secs(30),
    )
    .await;
    seed_recorded_messages(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    // a task of the module on what isn't a message_id, which only a hand-made queue holds
    root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["example.com"],
        "test_recorded_message_ids",
    )
    .await;
    let task = lease_one(&client, "test_recorded_message_ids").await;
    assert_eq!(
        status(
            &client
                .read(
                    task.id,
                    "recorded-message-ids",
                    &serde_json::json!({"message_ids": ["<scanned@example.com>"]}),
                    false,
                )
                .await
        ),
        Some(403)
    );
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<recorded::AsksTheStore>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let root = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &["scanned@example.com"],
        "test_recorded_message_ids",
    )
    .await;
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(task.root, root);
    ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    let (state, error) = common::task_of(&core, root, "test_recorded_message_ids").await;
    assert_eq!(state, "failed");
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("recorded: <scanned@example.com>") && !e.contains("never")),
        "{error:?}"
    );
}

/// `email-thread` says the root's email is still to be recorded while a module that writes
/// `email-thread` has a task in the root that hasn't finished, and not once it has.
#[tokio::test]
async fn email_thread_says_while_the_root_s_email_is_still_to_be_recorded() {
    let modules = ["email_thread_analyzer", "email_logger"];
    let core = Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_brocess::thread::MANIFEST,
            ace_mod_brocess::logger::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |config| config,
    )
    .await;
    let (root, _) = email_root(
        &core,
        &logger_fixture("01_thread_start.email.rfc822"),
        "email_logger",
    )
    .await;
    {
        let db = core.test_db.db();
        let mut tx = db.begin().await.expect("begins");
        let id = ace_core::tree::upsert_observable(
            &mut tx,
            root,
            &ace_results::NewObservable::new(
                ace_results::ObservableKind::MessageId,
                "<inv-1@example.com>",
            ),
        )
        .await
        .expect("adds")
        .id;
        ace_core::queue::enqueue(&mut tx, root, id, "email_thread_analyzer")
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    }
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let thread = client
        .lease(&["email_thread_analyzer".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let request = serde_json::json!({"max_messages": 50, "max_threads": 50});
    let answer = client
        .read(thread.id, "email-thread", &request, false)
        .await
        .expect("answers");
    assert_eq!(answer["recording"], true);
    let logger = client
        .lease(&["email_logger".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    client
        .end(
            logger.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "logged".to_owned(),
                writes: Vec::new(),
            },
        )
        .await
        .expect("ends");
    let answer = client
        .read(thread.id, "email-thread", &request, false)
        .await
        .expect("answers");
    assert_eq!(answer["recording"], false);
}

// ---- the email archive: archived-email and email-archive (PLAN.md 7.5 batch 9) ----

fn archive_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/email_archive")
        .join(name)
}

/// The test-only key ace3's archive dumps were sealed with.
fn archive_key() -> ace_core::email_archive::ArchiveKey {
    let hex = std::fs::read_to_string(archive_fixture("key")).expect("the key reads");
    ace_core::email_archive::ArchiveKey::from_hex(&hex).expect("a key")
}

const ARCHIVE_MODULES: [&str; 3] = ["message_id_analyzer_v2", "email_archiver", "archive"];

/// A core whose pools run the archive's modules and archive, with the archive's key, or none.
async fn archive_core(key: bool) -> Core {
    let mut archive = ace_core::email_archive::ArchiveConfig::default();
    if key {
        archive = archive.with_key(archive_key());
    }
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_emailarchive::message_id::MANIFEST,
            ace_mod_emailarchive::archiver::MANIFEST,
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &ARCHIVE_MODULES,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                ARCHIVE_MODULES.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config.archive(archive)
        },
    )
    .await
}

fn email_archive(core: &Core) -> ace_core::email_archive::EmailArchive {
    ace_core::email_archive::EmailArchive::new(
        core.test_db.db().clone(),
        core.bucket.clone(),
        ace_core::email_archive::ArchiveConfig::default().with_key(archive_key()),
    )
}

/// The archive ace3's Message-ID dumps read: fixtures/email_archive/store.json, each email archived at
/// its insert_date, and missing-object's object gone from the bucket's index.
async fn seed_archive_store(core: &Core) {
    let store: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(archive_fixture("store.json")).expect("reads"),
    )
    .expect("JSON");
    let archive = email_archive(core);
    for email in store["emails"].as_array().expect("emails") {
        let bytes =
            std::fs::read(archive_fixture(email["file"].as_str().expect("a file"))).expect("reads");
        let insert_date = chrono::NaiveDateTime::parse_from_str(
            email["insert_date"].as_str().expect("a date"),
            "%Y-%m-%d %H:%M:%S",
        )
        .expect("a date");
        let (_, object) = archive
            .seed(&ace_core::email_archive::Seed {
                email: &bytes,
                message_id: email["message_id"].as_str().expect("an id"),
                insert_date,
            })
            .await
            .expect("archives");
        if email["delete_file"] == true {
            sqlx::query("DELETE FROM store.objects WHERE pool = 'email_archive' AND sha256 = $1")
                .bind(object.to_hex())
                .execute(core.test_db.db().pool())
                .await
                .expect("loses the object");
        }
    }
}

/// Leases the next task of `module`, which is on the root just made.
async fn lease_one(
    client: &ace_pool::client::LeaseClient,
    module: &str,
) -> ace_sdk::wire::LeasedTask {
    client
        .lease(&[module.to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task")
}

/// `archived-email` answers each Message-ID ace3's dumps asked about as ace3's archive did: the newer
/// of two archives, the plaintext in the root's files held by the root, and nothing for an object
/// gone or one never archived, as ace3's `find_archived_email`; and it answers only the task's own
/// Message-ID.
#[tokio::test]
async fn archived_email_answers_as_ace3_s_archive_did_and_refuses_the_rest() {
    let core = archive_core(true).await;
    seed_archive_store(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let kind = ace_results::ObservableKind::MessageId;
    let dumps =
        ace_testkit::reference::Dump::all("message_id_analyzer_v2").expect("the dumps read");
    assert_eq!(dumps.len(), 6);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value");
        let root = root_of(&core, kind, &[value], "message_id_analyzer_v2").await;
        let task = lease_one(&client, "message_id_analyzer_v2").await;
        let answer = client
            .read(task.id, "archived-email", &serde_json::json!({}), false)
            .await
            .expect("answers");
        match dump.analysis("MessageIDAnalysisV2") {
            Some(ace3) => {
                let file = &ace3["observables"][0];
                assert_eq!(answer["email"]["sha256"], file["value"], "{value}");
                assert_eq!(answer["email"]["size"], file["size"], "{value}");
                let held: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM store.holds WHERE pool = 'alert_files'
                                    AND sha256 = $1 AND holder_kind = 'root' AND holder_id = $2)",
                )
                .bind(answer["email"]["sha256"].as_str())
                .bind(root.to_string())
                .fetch_one(core.test_db.db().pool())
                .await
                .expect("reads");
                assert!(held, "{value}: the root holds the email");
            }
            None if value.contains("empty") => assert_eq!(answer["email"]["size"], 0, "{value}"),
            None => assert_eq!(
                answer,
                serde_json::json!({"email": null, "error": null}),
                "{value}"
            ),
        }
    }
    root_of(
        &core,
        kind,
        &["<archived-1@example.com>", "<archived-2@example.com>"],
        "message_id_analyzer_v2",
    )
    .await;
    let task = lease_one(&client, "message_id_analyzer_v2").await;
    let sibling =
        serde_json::json!({"subject": {"type": "message_id", "value": "<archived-2@example.com>"}});
    assert_eq!(
        status(
            &client
                .read(task.id, "archived-email", &sibling, false)
                .await
        ),
        Some(403)
    );
    root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["x.example.com"],
        "archive",
    )
    .await;
    let archive_task = lease_one(&client, "archive").await;
    assert_refusals(
        &core,
        task.id,
        "archived-email",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "message_id", "value": "<elsewhere@example.com>"}}),
        archive_task.id,
    )
    .await;
}

/// A root holding the fixture `name` at the path `name`, with a task of `module` on it.
async fn file_root(core: &Core, path: &std::path::Path, name: &str, module: &str) -> uuid::Uuid {
    use ace_core::tree;
    let db = core.test_db.db();
    let root = tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_file(
            ALERT_FILES,
            path,
            Some(&ace_core::bucket::Hold::root(root.id)),
        )
        .await
        .expect("puts the file")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let observable =
        ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.to_hex());
    let id = tree::upsert_observable(&mut tx, root.id, &observable)
        .await
        .expect("adds")
        .id;
    tree::add_file(&mut tx, root.id, id, name, &[])
        .await
        .expect("records the file");
    ace_core::queue::enqueue(&mut tx, root.id, id, module)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    root.id
}

/// The Message-ID module runs as the lookups pool runs it: it adds the email the core put in the root,
/// with no upload, and its result lands; a result that adds a file no read put there, or from a
/// module that declares no such read, is refused as a missing upload is (400).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archive_readers_add_the_email_the_core_opened() {
    let core = archive_core(true).await;
    seed_archive_store(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_emailarchive::MessageIdAnalyzer>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let pulled = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &["<archived-2@example.com>"],
        "message_id_analyzer_v2",
    )
    .await;
    {
        let task = client
            .lease(&[], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let end = ace_pool::run::run_in_process(
            &client,
            &modules,
            task,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .expect("runs");
        assert!(
            matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
            "{end:?}"
        );
    }
    let plain = |name: &str| {
        Sha256(sha2::Sha256::digest(std::fs::read(archive_fixture(name)).expect("reads")).into())
            .to_hex()
    };
    for (root, module, sha256, path) in [(
        pulled,
        "message_id_analyzer_v2",
        plain("archived_2_resent.email.rfc822"),
        ace_mod_emailarchive::message_id::file_name("<archived-2@example.com>"),
    )] {
        // the email it added gets a task of its own
        let first: String = sqlx::query_scalar(
            "SELECT state::text FROM queue.tasks WHERE root_id = $1 AND module = $2 ORDER BY id LIMIT 1",
        )
        .bind(root)
        .bind(module)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the task");
        assert_eq!(first, "done", "{module}");
        let (value, file_path, tags): (String, String, Vec<String>) = sqlx::query_as(
            "SELECT o.value, f.path, o.tags FROM analysis.observables o
             JOIN analysis.files f ON f.root_id = o.root_id AND f.observable_id = o.id
             WHERE o.root_id = $1 AND o.type = 'file' AND f.path = $2",
        )
        .bind(root)
        .bind(&path)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the added email");
        assert_eq!((value, file_path), (sha256, path), "{module}");
        assert_eq!(tags, ["decrypted_email"], "{module}");
    }

    // a result naming a file nobody uploaded and the root doesn't hold is refused, and its task fails
    let root = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &["<forged@example.com>"],
        "message_id_analyzer_v2",
    )
    .await;
    let task = lease_one(&client, "message_id_analyzer_v2").await;
    assert_eq!(task.root, root);
    let forged = Sha256(sha2::Sha256::digest(b"never put anywhere").into());
    let mut result = ace_results::ResultEnvelope::new(
        ace_results::types::email_archive::MessageIdAnalysis::default(),
    );
    result.files.push(ace_results::NewFile::new(
        ace_results::AlertPath::new("forged.rfc822").expect("a path"),
        forged,
        18,
    ));
    let raw = result.to_raw().expect("JSON");
    let refused = client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: raw,
                writes: Vec::new(),
                probes: Default::default(),
                keep: true,
            },
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 400, .. })
        ),
        "{refused:?}"
    );
    // as for any upload that's missing: it could still be put right, so nothing lands and the task
    // stays the worker's
    let (state, _) = common::task_of(&core, root, "message_id_analyzer_v2").await;
    assert_eq!(state, "running");
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("counts");
    assert_eq!(files, 0);

    // nor may a module that declares no read putting a file there name one, even one its root holds
    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["y.example.com"],
        "email_archiver",
    )
    .await;
    let held = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            b"a file the root holds",
            Some(&ace_core::bucket::Hold::root(root)),
        )
        .await
        .expect("puts")
        .object;
    let task = lease_one(&client, "email_archiver").await;
    assert_eq!(task.root, root);
    let mut result = ace_results::ResultEnvelope::new(
        ace_results::types::email_archive::EmailArchiveResults::default(),
    );
    result.files.push(ace_results::NewFile::new(
        ace_results::AlertPath::new("held.txt").expect("a path"),
        held.sha256,
        held.size,
    ));
    let refused = client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result.to_raw().expect("JSON"),
                writes: Vec::new(),
                probes: Default::default(),
                keep: true,
            },
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 400, .. })
        ),
        "{refused:?}"
    );
    let (state, _) = common::task_of(&core, root, "email_archiver").await;
    assert_eq!(state, "running");
    let results: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("counts");
    assert_eq!(results, 0);
}

/// The archive's row for an email, by its sha256, as ace3's dumps write `archived_messages`: the
/// Message-ID's hash in upper-case hex and the email's digest in lower-case. Two samples with the same
/// bytes and Message-ID archived in the same second are one row, as ace3's `INSERT IGNORE` makes them.
async fn archive_row(core: &Core, email: &str) -> (i64, serde_json::Value) {
    let (archive_id, message_id_hash, hash): (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT archive_id, message_id_hash, hash FROM email_archive.archive
         WHERE encode(hash, 'hex') = $1 ORDER BY archive_id DESC LIMIT 1",
    )
    .bind(email)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the row");
    let upper = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    (
        archive_id,
        serde_json::json!([{
            "message_id_hash": upper(&message_id_hash),
            "digest": hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        }]),
    )
}

/// The same rows from ace3's dump.
fn ace3_archive_rows(dump: &ace_testkit::reference::Dump) -> serde_json::Value {
    dump.value["email_archive_after"]["archived_messages"]
        .as_array()
        .expect("rows")
        .iter()
        .map(
            |m| serde_json::json!({"message_id_hash": m["message_id_hash"], "digest": m["digest"]}),
        )
        .collect()
}

/// The archiver run as the lookups pool runs it, on each email ace3 archived: its write lands with its
/// result, the email is sealed in the archive's pool held by its row, and the row is ace3's: the
/// Message-ID to the email.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archiver_s_write_lands_ace3_s_rows() {
    let core = archive_core(true).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_emailarchive::EmailArchiver>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    let mut archived = 0;
    for dump in ace_testkit::reference::Dump::all("email_archiver").expect("the dumps read") {
        if dump.analysis("EmailArchiveResults").is_none() || dump.short_name().starts_with("local/")
        {
            continue;
        }
        archived += 1;
        let path = samples.join(dump.short_name());
        let (root, _) = email_root(&core, &path, "email_archiver").await;
        let email =
            Sha256(sha2::Sha256::digest(std::fs::read(&path).expect("reads")).into()).to_hex();
        let task = lease_one(&client, "email_archiver").await;
        let end = ace_pool::run::run_in_process(
            &client,
            &modules,
            task,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .expect("runs");
        assert!(
            matches!(&end, ace_sdk::wire::TaskEnd::Done { writes, .. } if writes.len() == 1),
            "{end:?}"
        );
        // the root's analysis is done once the tasks the result made eligible end, which this pool
        // doesn't run
        while let Some(task) = client.lease(&[], Duration::ZERO).await.expect("leases") {
            assert_ne!(task.module, "email_archiver");
            client
                .end(
                    task.id,
                    &ace_sdk::wire::TaskEnd::Skipped {
                        reason: "not here".into(),
                        writes: Vec::new(),
                    },
                )
                .await
                .expect("ends");
        }
        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM analysis.results WHERE root_id = $1 AND module = 'email_archiver'",
        )
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the result");
        assert_eq!(details["hash"], email.as_str());
        assert_eq!(
            details,
            dump.analysis("EmailArchiveResults").expect("ace3's")["details"],
            "{}",
            dump.name
        );
        let (archive_id, rows) = archive_row(&core, &email).await;
        assert_eq!(rows, ace3_archive_rows(&dump), "{}", dump.name);
        let (object, holds): (String, i64) = sqlx::query_as(
            "SELECT a.object_sha256, (SELECT count(*) FROM store.holds h WHERE h.pool = 'email_archive'
                 AND h.sha256 = a.object_sha256 AND h.holder_kind = 'email_archive'
                 AND h.holder_id = a.archive_id::text AND h.expires_at > now() + interval '30 days')
             FROM email_archive.archive a WHERE a.archive_id = $1",
        )
        .bind(archive_id)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the row");
        assert_eq!(holds, 1, "the row holds its object past retention");
        let sealed = core
            .bucket
            .get("email_archive", &object.parse().expect("a sha256"))
            .await
            .expect("in the bucket");
        let sealed = std::fs::read(&sealed.path).expect("reads");
        assert!(
            sealed.starts_with(b"ACE-GCM\x01"),
            "sealed in ace3's v1 layout"
        );
        assert_eq!(
            ace_core::email_archive::open(&archive_key(), &sealed).expect("opens"),
            std::fs::read(&path).expect("reads")
        );
    }
    assert!(archived >= 10, "{archived}");
}

/// The archive write is refused, failing its task and writing nothing, from a module that doesn't
/// declare it, with a body that doesn't read (a field it hasn't, as the recipients it once had),
/// about another Message-ID, twice in one end, or to a core with no key; and a lease lost before the
/// end writes nothing.
#[tokio::test]
async fn the_archive_write_is_refused_unless_it_s_the_task_s_own_email() {
    let journaled = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/ace3/email/o365_journaled_multi_rcpt.email.rfc822");
    let write = |body: serde_json::Value| ace_sdk::writes::WireWrite {
        write: "email-archive".to_owned(),
        body,
    };
    let own = |message_id: &str| write(serde_json::json!({ "message_id": message_id }));
    let result = || {
        ace_results::ResultEnvelope::new(
            ace_results::types::email_archive::EmailArchiveResults::default(),
        )
        .to_raw()
        .expect("JSON")
    };
    let rows = |core: &Core| {
        let pool = core.test_db.db().pool().clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM email_archive.archive")
                .fetch_one(&pool)
                .await
                .expect("counts")
        }
    };
    let core = archive_core(true).await;
    let (_, email) = email_root(&core, &journaled, "archive").await;
    let mine = email.message_id.clone().expect("a Message-ID");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let refusals = [
        ("archive", vec![own(&mine)], 403),
        (
            "email_archiver",
            vec![write(serde_json::json!({"message_id": 5}))],
            400,
        ),
        (
            "email_archiver",
            vec![write(
                serde_json::json!({"message_id": mine, "recipients": ["r@example.com"]}),
            )],
            400,
        ),
        (
            "email_archiver",
            vec![own("<someone-else@example.com>")],
            403,
        ),
        ("email_archiver", vec![own(&mine), own(&mine)], 403),
    ];
    let mut first = true;
    for (module, writes, expected) in refusals {
        let root = if first {
            first = false;
            let task = client
                .lease(&[module.to_owned()], Duration::ZERO)
                .await
                .expect("leases")
                .expect("a task");
            let refused = client
                .end(
                    task.id,
                    &ace_sdk::wire::TaskEnd::Done {
                        result: result(),
                        writes,
                        probes: Default::default(),
                        keep: true,
                    },
                )
                .await;
            assert!(
                matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
                "{module}: {refused:?}"
            );
            task.root
        } else {
            let (root, _) = email_root(&core, &journaled, module).await;
            let task = client
                .lease(&[module.to_owned()], Duration::ZERO)
                .await
                .expect("leases")
                .expect("a task");
            let refused = client
                .end(
                    task.id,
                    &ace_sdk::wire::TaskEnd::Done {
                        result: result(),
                        writes,
                        probes: Default::default(),
                        keep: true,
                    },
                )
                .await;
            assert!(
                matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
                "{module}: {refused:?}"
            );
            root
        };
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "failed", "{module}");
        assert!(error.is_some(), "{module}");
        assert_eq!(rows(&core).await, 0, "{module}: nothing written");
    }
    // a lease lost before the end writes nothing; its own worker's end lands it
    email_root(&core, &journaled, "email_archiver").await;
    let task = client
        .lease(&["email_archiver".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let lost = client
        .as_worker("w2")
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result(),
                writes: vec![own(&mine)],
                probes: Default::default(),
                keep: true,
            },
        )
        .await;
    assert!(
        matches!(lost, Err(ace_pool::client::ClientError::LeaseLost(_))),
        "{lost:?}"
    );
    assert_eq!(rows(&core).await, 0);
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result(),
                writes: vec![own(&mine)],
                probes: Default::default(),
                keep: true,
            },
        )
        .await
        .expect("lands");
    assert_eq!(rows(&core).await, 1);

    // a core with no key can't archive, and the task fails saying so
    let keyless = archive_core(false).await;
    let (root, _) = email_root(&keyless, &journaled, "email_archiver").await;
    let client =
        ace_pool::client::LeaseClient::new(&keyless.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["email_archiver".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let refused = client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result(),
                writes: vec![own(&mine)],
                probes: Default::default(),
                keep: true,
            },
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
    let (state, error) = common::task_of(&keyless, root, "email_archiver").await;
    assert_eq!(state, "failed");
    assert!(error.expect("why").contains("no encryption key"));
    assert_eq!(rows(&keyless).await, 0);
}

// ---- PLAN.md 7.5 batch 13: files a result stores for its root, which another module adds ----

const PCAP_MODULES: [&str; 3] = ["pcap_analyzer", "pcap_files", "pcap_dns"];

/// pcap_analyzer stores the objects and certificates it carves for the root without adding them
/// (`ResultEnvelope::stored`), and pcap_files adds them with no upload, which the core takes from a
/// module that declares `Module::ADDS_STORED_FILES` when the root holds the file, giving it the
/// bucket's size; a module that doesn't declare it, or a file the root doesn't hold, is refused as a
/// missing upload is (400), and nothing lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcap_files_adds_what_pcap_analyzer_stored() {
    let core = Core::start(
        vec![
            ace_sdk::Manifest::parser::<ace_mod_pcap::PcapAnalyzer>(),
            ace_sdk::Manifest::parser::<ace_mod_pcap::PcapFiles>(),
            ace_sdk::Manifest::parser::<ace_mod_pcap::PcapDns>(),
        ],
        &PCAP_MODULES,
        Duration::from_secs(60),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new()
            .with_tools(ace_sdk::tools::SANDBOX_TOOLS)
            .with_parser(
                ace_pool::modules::Entry::<ace_mod_pcap::PcapAnalyzer>::parser(
                    None,
                    &ace_sdk::Secrets::new(),
                )
                .expect("the module"),
            )
            .with_parser(
                ace_pool::modules::Entry::<ace_mod_pcap::PcapFiles>::parser(
                    None,
                    &ace_sdk::Secrets::new(),
                )
                .expect("the module"),
            ),
    );
    let sample = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/ace3/pcap/http_tls.pcapng");
    let root = file_root(&core, &sample, "http_tls.pcapng", "pcap_analyzer").await;
    let run = |module: &'static str| {
        let (client, modules) = (&client, &modules);
        async move {
            let task = lease_one(client, module).await;
            let end = ace_pool::run::run_in_process(
                client,
                modules,
                task,
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect("runs");
            assert!(
                matches!(end, ace_sdk::wire::TaskEnd::Done { .. }),
                "{module}: {end:?}"
            );
        }
    };
    run("pcap_analyzer").await;
    // what it stored is the root's, and no file of the alert yet
    let payload = Sha256(sha2::Sha256::digest(b"plaintext payload carried over http\n").into());
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM store.holds WHERE pool = $1 AND holder_kind = 'root' AND holder_id = $2",
    )
    .bind(ALERT_FILES)
    .bind(root.to_string())
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("counts");
    // the capture, its payload and its certificate
    assert_eq!(held, 3);
    let files = |root: uuid::Uuid| {
        let pool = core.test_db.db().pool().clone();
        async move {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT f.path, o.value FROM analysis.files f
                 JOIN analysis.observables o ON o.root_id = f.root_id AND o.id = f.observable_id
                 WHERE f.root_id = $1 ORDER BY f.path",
            )
            .bind(root)
            .fetch_all(&pool)
            .await
            .expect("the files");
            rows
        }
    };
    assert_eq!(files(root).await.len(), 1);
    let pcap: (i64,) =
        sqlx::query_as("SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'file'")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the capture");
    let mut tx = core.test_db.db().begin().await.expect("begins");
    for module in ["pcap_files", "pcap_dns"] {
        ace_core::queue::enqueue(&mut tx, root, ace_core::tree::ObservableId(pcap.0), module)
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    run("pcap_files").await;
    let added = files(root).await;
    assert_eq!(
        added,
        [
            ("http_tls.pcapng".to_owned(), added[0].1.clone()),
            (
                "http_tls.pcapng.pcap_objects/http/payload.txt".to_owned(),
                payload.to_hex()
            ),
        ]
    );
    // the size is the bucket's, which pcap_files gave as 0
    let size: i64 =
        sqlx::query_scalar("SELECT size FROM store.objects WHERE pool = $1 AND sha256 = $2")
            .bind(ALERT_FILES)
            .bind(payload.to_hex())
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the object");
    assert_eq!(size, 36);

    // pcap_dns doesn't declare that it adds stored files
    let task = lease_one(&client, "pcap_dns").await;
    let mut result =
        ace_results::ResultEnvelope::new(ace_results::types::pcap::PcapDnsAnalysis::default());
    result.files.push(ace_results::NewFile::new(
        ace_results::AlertPath::new("http_tls.pcapng.pcap_objects/http/copy.txt").expect("a path"),
        payload,
        0,
    ));
    let refused = client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result.to_raw().expect("JSON"),
                writes: Vec::new(),
                probes: Default::default(),
                keep: true,
            },
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 400, .. })
        ),
        "{refused:?}"
    );
    assert_eq!(common::task_of(&core, root, "pcap_dns").await.0, "running");
    assert_eq!(files(root).await.len(), 2);
}

// ---- PLAN.md 7.7: scans ----

/// A core whose test pool runs the JavaScript deobfuscator and its scanner.
async fn scans_core(lease: Duration) -> Core {
    Core::start(
        vec![ace_sdk::Manifest::parser::<
            ace_mod_scanners::JavaScriptDeobfuscationAnalyzer,
        >()],
        &["javascript_deobfuscation", "@scan/js-deobfuscator"],
        lease,
    )
    .await
}

/// The deobfuscator, as a pool runs it.
fn js_modules() -> std::sync::Arc<ace_pool::modules::Modules> {
    use ace_pool::modules::{Entry, Modules};
    std::sync::Arc::new(
        Modules::new().with_parser(
            Entry::<ace_mod_scanners::JavaScriptDeobfuscationAnalyzer>::parser(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("builds"),
        ),
    )
}

/// Leases the root's deobfuscator task and runs it in this process, as a pool would.
async fn run_js_task(core: &Core, worker: &str) -> ace_sdk::wire::TaskEnd {
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, worker).expect("a client");
    let task = client
        .lease(
            &["javascript_deobfuscation".to_owned()],
            Duration::from_secs(5),
        )
        .await
        .expect("leases")
        .expect("a task");
    ace_pool::run::run_in_process(
        &client,
        &js_modules(),
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs")
}

/// An output archive as the scanner pool packs one: Docker's tar of the output directory, and the two
/// log streams in Docker's frames.
fn scan_archive(files: &[(&str, &[u8])], stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
    let tar_of = |entries: &[(String, Vec<u8>)]| {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, name, &bytes[..])
                .expect("appends");
        }
        builder.into_inner().expect("a tar")
    };
    let framed = |stream: u8, bytes: &[u8]| {
        let mut out = vec![stream, 0, 0, 0];
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    };
    let output: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(name, bytes)| (format!("output/{name}"), bytes.to_vec()))
        .collect();
    tar_of(&[
        ("output.tar".to_owned(), tar_of(&output)),
        ("stdout".to_owned(), framed(1, stdout)),
        ("stderr".to_owned(), framed(2, stderr)),
    ])
}

/// PLAN.md 7.7: a module's task delays with a scan and holds no slot while it waits; a scanner pool
/// leases the scan with its inputs, ends it with its output archive, and that wakes the task, whose
/// next run reads the archive and lands the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_runs_between_a_tasks_two_runs() {
    let core = scans_core(Duration::from_secs(30)).await;
    let (root, _, js) = core
        .root_with_file("file", "ace-rs/js/dropper.js", "dropper.js")
        .await;
    let end = run_js_task(&core, "parser").await;
    let ace_sdk::wire::TaskEnd::Delay {
        scan: Some(request),
        after_seconds,
        ..
    } = &end
    else {
        panic!("a delay with a scan: {end:?}");
    };
    assert_eq!(*after_seconds, 60.0);
    assert_eq!(request.scanner, "js-deobfuscator");
    assert_eq!(
        core.tasks(root).await,
        [(
            "javascript_deobfuscation".to_owned(),
            js.to_hex(),
            "delayed".to_owned()
        )]
    );

    let scanner =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "scanner").expect("a client");
    let scan = scanner
        .lease_scan(Duration::from_secs(5))
        .await
        .expect("leases")
        .expect("a scan");
    assert_eq!(scan.scanner, "js-deobfuscator");
    assert_eq!(scan.timeout_seconds, 30);
    assert!(scan.deadline_seconds > 29.0 && scan.deadline_seconds <= 30.0);
    // the module asked for no proxy (PLAN.md decision 64)
    assert!(!scan.proxy);
    let [input] = &scan.inputs[..] else {
        panic!("one input: {:?}", scan.inputs);
    };
    let (job, name) = input.name.split_once('/').expect("<job>/<name>");
    assert_eq!(name, "dropper.js");
    assert_eq!(input.sha256, js);
    assert_eq!(
        scan.args,
        [
            format!("/js-deobfuscator/input/{job}/dropper.js"),
            "/js-deobfuscator/output/deobfuscated.js".to_owned(),
        ]
    );
    let dir = tempfile::tempdir().expect("a directory");
    let fetched = dir.path().join("input");
    scanner
        .download(&input.download, &fetched)
        .await
        .expect("downloads");
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/ace-rs/js/dropper.js");
    assert_eq!(
        std::fs::read(&fetched).expect("reads"),
        std::fs::read(&sample).expect("reads")
    );
    assert!(
        !scanner
            .renew_scan(scan.id)
            .await
            .expect("renews")
            .cancel_requested
    );
    // nothing else to lease meanwhile: the task waits, delayed, for the scan
    let idle = ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "other")
        .expect("a client")
        .lease(
            &["javascript_deobfuscation".to_owned()],
            Duration::from_secs(1),
        )
        .await
        .expect("asks");
    assert!(idle.is_none(), "{idle:?}");

    let report = br#"{"status": "ok", "event_count": 2, "secondary_script_count": 0, "error": null, "error_type": null, "webcrack_status": "applied", "webcrack_error": null, "blob_files": ["blob_0.html"], "dom_snapshot": false}"#;
    let archive = scan_archive(
        &[
            (
                "deobfuscated.js",
                b"window.location.href = \"https://x.example/\";\n",
            ),
            ("blob_0.html", b"<p>hi</p>"),
        ],
        report,
        b"",
    );
    let path = dir.path().join("scan.tar");
    std::fs::write(&path, &archive).expect("writes");
    let sha256 = Sha256(sha2::Sha256::digest(&archive).into());
    let url = scanner
        .scan_upload_url(scan.id, &sha256, archive.len() as u64)
        .await
        .expect("a URL");
    scanner.upload(&url, &path).await.expect("uploads");
    scanner
        .end_scan(
            scan.id,
            &ace_sdk::scanners::ScanEnd {
                outcome: ace_sdk::scanners::ScanOutcome::Completed { exit_code: 0 },
                output: Some(ace_sdk::scanners::ScanOutputRecord {
                    sha256,
                    size: archive.len() as u64,
                }),
                image_id: None,
                proxied: Some("http://proxy.example.com:3128".to_owned()),
            },
        )
        .await
        .expect("ends");

    // the end woke the task, well before its 60-second delay
    let end = run_js_task(&core, "parser").await;
    let ace_sdk::wire::TaskEnd::Done { result, .. } = &end else {
        panic!("a result: {end:?}");
    };
    assert_eq!(
        result.details["extracted_files"],
        serde_json::json!(["deobfuscated-dropper.js", "dropper.js.blob_0.html"])
    );
    assert_eq!(result.details["event_count"], 2);
    assert_eq!(
        result.details["stdout"],
        String::from_utf8_lossy(report).as_ref()
    );
    assert_eq!(result.analyzed.tags, ["js"]);
    let db = core.test_db.db();
    let stored: (String, i64, Option<String>) =
        sqlx::query_as("SELECT state::text, output_size, proxied FROM queue.scans WHERE id = $1")
            .bind(scan.id)
            .fetch_one(db.pool())
            .await
            .expect("the scan");
    assert_eq!(
        stored,
        (
            "completed".to_owned(),
            archive.len() as i64,
            // the route the pool reported, which the module's next run reads (`Scan::proxied`)
            Some("http://proxy.example.com:3128".to_owned())
        )
    );
    // the archive is the root's, held as its files are
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2",
    )
    .bind(ALERT_FILES)
    .bind(sha256.to_hex())
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(holds, [("root".to_owned(), root.to_string())]);
    assert_eq!(
        core.tasks(root).await.first().map(|t| t.2.clone()),
        Some("done".to_owned())
    );
}

/// PLAN.md 7.7: cancelling a root asks its running scan to stop through the scan's lease, and ends a
/// queued one; a scan whose pool stops renewing it is abandoned by the reaper, and wakes its task,
/// whose module says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_ends_at_a_cancellation_and_at_a_lost_lease() {
    let core = scans_core(Duration::from_secs(2)).await;
    let db = core.test_db.db();
    let scanner =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "scanner").expect("a client");

    // cancelled while it runs
    let (root, _, _) = core
        .root_with_file("file", "ace-rs/js/dropper.js", "dropper.js")
        .await;
    run_js_task(&core, "parser").await;
    let scan = scanner
        .lease_scan(Duration::from_secs(5))
        .await
        .expect("leases")
        .expect("a scan");
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, root)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    assert!(
        scanner
            .renew_scan(scan.id)
            .await
            .expect("renews")
            .cancel_requested
    );
    scanner
        .end_scan(
            scan.id,
            &ace_sdk::scanners::ScanEnd {
                outcome: ace_sdk::scanners::ScanOutcome::Cancelled,
                output: None,
                image_id: None,
                proxied: None,
            },
        )
        .await
        .expect("ends");
    let scans = ace_core::scans::for_root(db, root).await.expect("reads");
    assert_eq!(scans[0].state, ace_core::scans::ScanRowState::Cancelled);

    // cancelled before a pool took it
    let (queued, _, _) = core
        .root_with_file("file", "ace-rs/js/dropper.js", "dropper.js")
        .await;
    run_js_task(&core, "parser").await;
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, queued)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    let scans = ace_core::scans::for_root(db, queued).await.expect("reads");
    assert_eq!(scans[0].state, ace_core::scans::ScanRowState::Cancelled);
    assert!(
        scanner
            .lease_scan(Duration::from_secs(1))
            .await
            .expect("asks")
            .is_none()
    );

    // its pool stops renewing it, as when the pool crashes
    let (lost, _, _) = core
        .root_with_file("file", "ace-rs/js/dropper.js", "dropper.js")
        .await;
    run_js_task(&core, "parser").await;
    let scan = scanner
        .lease_scan(Duration::from_secs(5))
        .await
        .expect("leases")
        .expect("a scan");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let reaped = ace_core::scans::reap_scans(db).await.expect("reaps");
    assert_eq!(reaped.unreported, 1);
    // the pool's end comes too late
    let late = scanner
        .end_scan(
            scan.id,
            &ace_sdk::scanners::ScanEnd {
                outcome: ace_sdk::scanners::ScanOutcome::Completed { exit_code: 0 },
                output: None,
                image_id: None,
                proxied: None,
            },
        )
        .await;
    assert!(
        matches!(late, Err(ace_pool::client::ClientError::LeaseLost(_))),
        "{late:?}"
    );
    let end = run_js_task(&core, "parser").await;
    let ace_sdk::wire::TaskEnd::Done { result, .. } = &end else {
        panic!("a result: {end:?}");
    };
    assert_eq!(
        result.error.as_deref(),
        Some("js deobfuscator call failed: its pool stopped reporting on it before it ended")
    );
    let scans = ace_core::scans::for_root(db, lost).await.expect("reads");
    assert_eq!(scans[0].state, ace_core::scans::ScanRowState::Abandoned);
}

/// PLAN.md 7.7: a scan the module doesn't declare, or past its scanner's limits, fails the task, and
/// a pool that runs no scanner can't lease one.
#[tokio::test]
async fn a_scan_request_outside_the_modules_declaration_fails_its_task() {
    let core = scans_core(Duration::from_secs(30)).await;
    let (root, _, js) = core
        .root_with_file("file", "ace-rs/js/dropper.js", "dropper.js")
        .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "parser").expect("a client");
    let task = client
        .lease(&[], Duration::from_secs(5))
        .await
        .expect("leases")
        .expect("a task");
    let request = ace_sdk::scanners::ScanRequest::new("phishkit", Duration::from_secs(30)).input(
        ace_sdk::scanners::ScanInput {
            name: "x/dropper.js".to_owned(),
            sha256: js,
            size: 1,
        },
    );
    let refused = client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Delay {
                after_seconds: 10.0,
                state: serde_json::Value::Null,
                scan: Some(request),
                writes: Vec::new(),
            },
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
    let (state, error) = common::task_of(&core, root, "javascript_deobfuscation").await;
    assert_eq!(state, "failed");
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("doesn't declare the scanner \"phishkit\"")),
        "{error:?}"
    );

    let other = Core::start(vec![], &["archive"], Duration::from_secs(30)).await;
    let refused = ace_pool::client::LeaseClient::new(&other.url, common::TOKEN, "scanner")
        .expect("a client")
        .lease_scan(Duration::from_secs(1))
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
}

/// A Docker daemon on a Unix socket that answers the calls a scanner pool makes, keeping the
/// containers it creates in memory. A container started with `forever` in its command runs until it's
/// stopped or killed; any other exits at once with 0.
mod fake_docker {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, get, post, put};
    use serde_json::{Value, json};

    #[derive(Debug, Clone, Default)]
    pub struct Container {
        pub labels: BTreeMap<String, String>,
        pub body: Value,
        pub running: bool,
        pub exit_code: Option<i64>,
        pub input: Vec<u8>,
    }

    #[derive(Default)]
    pub struct Daemon {
        pub containers: BTreeMap<String, Container>,
        /// Each call, as `<verb> <container>`.
        pub calls: Vec<String>,
        next: u32,
    }

    pub type Shared = Arc<Mutex<Daemon>>;

    /// Serves the daemon on a socket in `dir` and returns the socket's path.
    pub fn serve(dir: &std::path::Path, daemon: Shared) -> std::path::PathBuf {
        let socket = dir.join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("binds");
        let app = Router::new()
            .route("/containers/create", post(create))
            .route("/containers/json", get(list))
            .route(
                "/containers/{id}/archive",
                put(put_archive).get(get_archive),
            )
            .route("/containers/{id}/json", get(inspect))
            .route("/containers/{id}/start", post(start))
            .route("/containers/{id}/wait", post(wait))
            .route("/containers/{id}/stop", post(stop))
            .route("/containers/{id}/kill", post(kill))
            .route("/containers/{id}/logs", get(logs))
            .route("/containers/{id}", delete(remove))
            .route("/images/{*name}", get(image))
            .with_state(daemon);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("the fake daemon stopped: {e}");
            }
        });
        socket
    }

    pub fn add(daemon: &Shared, id: &str, labels: &[(&str, &str)]) {
        daemon.lock().expect("a lock").containers.insert(
            id.to_owned(),
            Container {
                labels: labels
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                running: true,
                ..Default::default()
            },
        );
    }

    fn call(daemon: &Shared, what: &str, id: &str) {
        daemon
            .lock()
            .expect("a lock")
            .calls
            .push(format!("{what} {id}"));
    }

    async fn create(
        State(daemon): State<Shared>,
        Json(body): axum::Json<Value>,
    ) -> axum::Json<Value> {
        let mut d = daemon.lock().expect("a lock");
        d.next += 1;
        let id = format!("c{}", d.next);
        let labels = body["Labels"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        d.containers.insert(
            id.clone(),
            Container {
                labels,
                body,
                ..Default::default()
            },
        );
        d.calls.push(format!("create {id}"));
        axum::Json(json!({"Id": id}))
    }
    use axum::Json;

    async fn put_archive(
        State(daemon): State<Shared>,
        Path(id): Path<String>,
        body: Bytes,
    ) -> StatusCode {
        call(&daemon, "put_archive", &id);
        match daemon.lock().expect("a lock").containers.get_mut(&id) {
            Some(c) => {
                c.input = body.to_vec();
                StatusCode::OK
            }
            None => StatusCode::NOT_FOUND,
        }
    }

    async fn start(State(daemon): State<Shared>, Path(id): Path<String>) -> StatusCode {
        call(&daemon, "start", &id);
        let mut d = daemon.lock().expect("a lock");
        let Some(c) = d.containers.get_mut(&id) else {
            return StatusCode::NOT_FOUND;
        };
        let forever = c.body["Cmd"].as_array().is_some_and(|cmd| {
            cmd.iter()
                .any(|a| a.as_str().is_some_and(|a| a.contains("forever")))
        });
        if forever {
            c.running = true;
        } else {
            c.exit_code = Some(0);
        }
        StatusCode::NO_CONTENT
    }

    async fn wait(State(daemon): State<Shared>, Path(id): Path<String>) -> Json<Value> {
        loop {
            {
                let d = daemon.lock().expect("a lock");
                match d.containers.get(&id) {
                    Some(c) if c.running => {}
                    Some(c) => return Json(json!({"StatusCode": c.exit_code.unwrap_or(0)})),
                    None => return Json(json!({"StatusCode": -1})),
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn end(daemon: &Shared, id: &str, what: &str, code: i64) -> StatusCode {
        call(daemon, what, id);
        match daemon.lock().expect("a lock").containers.get_mut(id) {
            Some(c) => {
                c.running = false;
                c.exit_code = Some(code);
                StatusCode::NO_CONTENT
            }
            None => StatusCode::NOT_FOUND,
        }
    }

    async fn stop(State(daemon): State<Shared>, Path(id): Path<String>) -> StatusCode {
        end(&daemon, &id, "stop", 143)
    }

    async fn kill(State(daemon): State<Shared>, Path(id): Path<String>) -> StatusCode {
        end(&daemon, &id, "kill", 137)
    }

    async fn get_archive(State(daemon): State<Shared>, Path(id): Path<String>) -> Vec<u8> {
        call(&daemon, "get_archive", &id);
        let mut builder = tar::Builder::new(Vec::new());
        let bytes = b"// trace\nwindow.location = 'https://x.example/';\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, "output/deobfuscated.js", &bytes[..])
            .expect("appends");
        builder.into_inner().expect("a tar")
    }

    async fn logs(
        State(daemon): State<Shared>,
        Path(id): Path<String>,
        Query(query): Query<BTreeMap<String, String>>,
    ) -> Vec<u8> {
        call(&daemon, "logs", &id);
        let text: &[u8] = if query.contains_key("stdout") {
            br#"{"event_count": 1}"#
        } else {
            b""
        };
        let mut out = vec![1, 0, 0, 0];
        out.extend_from_slice(&(text.len() as u32).to_be_bytes());
        out.extend_from_slice(text);
        out
    }

    async fn remove(State(daemon): State<Shared>, Path(id): Path<String>) -> StatusCode {
        call(&daemon, "remove", &id);
        match daemon.lock().expect("a lock").containers.remove(&id) {
            Some(_) => StatusCode::NO_CONTENT,
            None => StatusCode::NOT_FOUND,
        }
    }

    async fn list(
        State(daemon): State<Shared>,
        Query(query): Query<BTreeMap<String, String>>,
    ) -> Json<Value> {
        let filters: Value =
            serde_json::from_str(query.get("filters").map_or("{}", String::as_str))
                .expect("filters");
        let wanted: Vec<(String, String)> = filters["label"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|l| {
                l.as_str()?
                    .split_once('=')
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
            })
            .collect();
        let d = daemon.lock().expect("a lock");
        let found: Vec<Value> = d
            .containers
            .iter()
            .filter(|(_, c)| wanted.iter().all(|(k, v)| c.labels.get(k) == Some(v)))
            .map(|(id, c)| json!({"Id": id, "Labels": c.labels}))
            .collect();
        Json(Value::Array(found))
    }

    async fn image() -> Json<Value> {
        Json(json!({"Id": "sha256:fake"}))
    }

    /// A container's image is the one it was made from: `sha256:fake`, as `image` says.
    async fn inspect(State(daemon): State<Shared>, Path(id): Path<String>) -> Json<Value> {
        let known = daemon.lock().expect("a lock").containers.contains_key(&id);
        Json(json!({"Id": id, "Image": known.then_some("sha256:fake")}))
    }
}

/// A scanner pool on the fake daemon, for `scans_core`'s test pool.
fn scanner_pool(core: &Core, socket: &Path, host: &str) -> ace_pool::scanners::ScannerPool {
    let mut config = ace_pool::scanners::ScannerPoolConfig::new(
        "ace-rs-test",
        host,
        &[ace_sdk::scanners::JS_DEOBFUSCATOR],
        &|_| None,
    );
    config.socket = socket.to_owned();
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "scanners").expect("a client");
    ace_pool::scanners::ScannerPool::new(client, config)
}

/// Runs the deobfuscator's first run with `settings`, as a pool would, so its scan is queued.
async fn queue_js_scan(core: &Core, settings: serde_json::Value) {
    use ace_pool::modules::{Entry, Modules};
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "parser").expect("a client");
    let task = client
        .lease(
            &["javascript_deobfuscation".to_owned()],
            Duration::from_secs(5),
        )
        .await
        .expect("leases")
        .expect("a task");
    let modules = std::sync::Arc::new(
        Modules::new().with_parser(
            Entry::<ace_mod_scanners::JavaScriptDeobfuscationAnalyzer>::parser(
                Some(&settings),
                &ace_sdk::Secrets::new(),
            )
            .expect("builds"),
        ),
    );
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(end, ace_sdk::wire::TaskEnd::Delay { scan: Some(_), .. }),
        "{end:?}"
    );
}

/// Waits until the root's scan is in `state`.
async fn wait_for_scan(core: &Core, root: uuid::Uuid, state: ace_core::scans::ScanRowState) {
    for _ in 0..200 {
        let scans = ace_core::scans::for_root(core.test_db.db(), root)
            .await
            .expect("reads");
        if scans.first().is_some_and(|s| s.state == state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the scan never became {state:?}");
}

/// PLAN.md 7.7: the scanner pool stops a scanner at its deadline (SIGTERM, then the grace), brings
/// back what it wrote and ends the scan timed out; and removes its container.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scanner_pool_stops_a_scanner_at_its_deadline() {
    let core = scans_core(Duration::from_secs(30)).await;
    let dir = tempfile::tempdir().expect("a directory");
    let daemon = fake_docker::Shared::default();
    let socket = fake_docker::serve(dir.path(), daemon.clone());
    // the sample's name is what makes the fake daemon's container run until it's stopped
    let (root, _) = common::root_with_bytes(&core, "file", b"for(;;){}", "forever.js").await;
    queue_js_scan(&core, serde_json::json!({"scanner_timeout": 1})).await;
    let stop = tokio_util::sync::CancellationToken::new();
    let pool = tokio::spawn(scanner_pool(&core, &socket, "host-a").run(stop.clone()));
    wait_for_scan(&core, root, ace_core::scans::ScanRowState::TimedOut).await;
    let scans = ace_core::scans::for_root(core.test_db.db(), root)
        .await
        .expect("reads");
    assert_eq!(scans[0].exit_code, Some(143));
    // the image its container ran, which the analysis cache keys a scanning module's result on
    let image: Option<String> =
        sqlx::query_scalar("SELECT image_id FROM queue.scans WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!(image.as_deref(), Some("sha256:fake"));
    let calls = daemon.lock().expect("a lock").calls.clone();
    assert_eq!(
        calls,
        [
            "create c1",
            "put_archive c1",
            "start c1",
            "stop c1",
            "get_archive c1",
            "logs c1",
            "logs c1",
            "remove c1"
        ]
    );
    assert!(daemon.lock().expect("a lock").containers.is_empty());
    // its task woke, and its module reads the timeout as ace3's manager reported one
    let end = run_js_task(&core, "parser").await;
    let ace_sdk::wire::TaskEnd::Done { result, .. } = &end else {
        panic!("a result: {end:?}");
    };
    assert_eq!(result.details["exit_code"], -1);
    assert_eq!(
        result.details["stderr"],
        "scanner container timed out after 30s"
    );
    stop.cancel();
    pool.await.expect("joins");
}

/// PLAN.md 7.7: a scanner whose root is cancelled is killed and its container removed; and a pool
/// that starts removes the containers its host left, which a crash of the pool leaves, and its sweep
/// those of its stack past their deadline, and nothing that isn't its stack's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scanner_pool_kills_a_cancelled_scanner_and_reaps_what_a_crash_left() {
    let core = scans_core(Duration::from_secs(2)).await;
    let dir = tempfile::tempdir().expect("a directory");
    let daemon = fake_docker::Shared::default();
    let socket = fake_docker::serve(dir.path(), daemon.clone());
    let stack = |host: &str, deadline: &str| {
        vec![
            ("ace-rs.scanner.stack".to_owned(), "ace-rs-test".to_owned()),
            ("ace-rs.scanner.host".to_owned(), host.to_owned()),
            (
                "ace-rs.scanner.name".to_owned(),
                "js-deobfuscator".to_owned(),
            ),
            ("ace-rs.scanner.deadline".to_owned(), deadline.to_owned()),
        ]
    };
    let add = |id: &str, labels: Vec<(String, String)>| {
        let labels: Vec<(&str, &str)> = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        fake_docker::add(&daemon, id, &labels);
    };
    let far = "99999999999";
    add("left-by-a-crash", stack("host-a", far));
    add("another-hosts", stack("host-b", far));
    add("another-hosts-overdue", stack("host-b", "1"));
    add(
        "another-stack",
        vec![
            ("ace-rs.scanner.stack".to_owned(), "ace-rs".to_owned()),
            ("ace-rs.scanner.host".to_owned(), "host-a".to_owned()),
        ],
    );
    add(
        "ace3s-phishkit",
        vec![
            ("phishkit.stack".to_owned(), "ace".to_owned()),
            ("phishkit.job_id".to_owned(), "x".to_owned()),
        ],
    );

    let pool = scanner_pool(&core, &socket, "host-a");
    assert_eq!(pool.reap_own().await.expect("reaps"), 1);
    assert_eq!(pool.sweep().await.expect("sweeps"), 1);
    let left: Vec<String> = daemon
        .lock()
        .expect("a lock")
        .containers
        .keys()
        .cloned()
        .collect();
    assert_eq!(left, ["ace3s-phishkit", "another-hosts", "another-stack"]);

    let (root, _) = common::root_with_bytes(&core, "file", b"for(;;){}", "forever.js").await;
    queue_js_scan(&core, serde_json::json!({})).await;
    let stop = tokio_util::sync::CancellationToken::new();
    let running = tokio::spawn(pool.run(stop.clone()));
    wait_for_scan(&core, root, ace_core::scans::ScanRowState::Running).await;
    let db = core.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, root)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    wait_for_scan(&core, root, ace_core::scans::ScanRowState::Cancelled).await;
    let calls = daemon.lock().expect("a lock").calls.clone();
    let scan_calls: Vec<&str> = calls
        .iter()
        .map(String::as_str)
        .filter(|c| c.ends_with(" c1"))
        .collect();
    assert_eq!(
        scan_calls,
        [
            "create c1",
            "put_archive c1",
            "start c1",
            "kill c1",
            "remove c1"
        ]
    );
    stop.cancel();
    running.await.expect("joins");
}

/// A remediation check whose probe answers pending once and then finds the vendor's event, as ace3's
/// probes do for a vendor that acts minutes later.
struct FakeProbe;

static FAKE_PROBE: ace_sdk::actions::ActionSpec = ace_sdk::actions::ActionSpec::new(
    ace_sdk::actions::ActionKind::RemediationCheck,
    "fake_vendor",
    "Fake Vendor",
    "Answers pending, then confirms.",
    "email_delivery",
)
.retry(ace_sdk::actions::Retry {
    initial_delay_seconds: 1,
    max_delay_seconds: 1,
    max_attempts: Some(5),
    deadline_seconds: Some(3600),
})
.supersede_grace_seconds(0);

impl ace_sdk::actions::RemediationProbe for FakeProbe {
    fn spec(&self) -> &'static ace_sdk::actions::ActionSpec {
        &FAKE_PROBE
    }

    fn probe<'a>(
        &'a self,
        target: &'a ace_sdk::actions::LeasedAction,
    ) -> ace_sdk::actions::ActionFuture<'a, ace_sdk::actions::ProbeOutcome> {
        Box::pin(async move {
            if target.attempts == 0 {
                return ace_sdk::actions::ProbeOutcome::Pending {
                    message: Some("nothing yet".to_owned()),
                };
            }
            ace_sdk::actions::ProbeOutcome::FoundEvents {
                events: vec![ace_sdk::actions::RemediationEvent {
                    source: "Fake Vendor".to_owned(),
                    event_type: "moved_to_junk".to_owned(),
                    timestamp: chrono::Utc::now(),
                    description: format!("moved {}", target.observable_value),
                    event_time: None,
                    actor: None,
                    target: None,
                    folder: Some("Junk".to_owned()),
                    portal_url: None,
                    metadata: serde_json::Map::new(),
                }],
                message: None,
            }
        })
    }
}

/// A file collector whose host is offline at the first try and gives the file at the second.
struct FakeCollector;

static FAKE_COLLECTOR: ace_sdk::actions::ActionSpec = ace_sdk::actions::ActionSpec::new(
    ace_sdk::actions::ActionKind::FileCollection,
    "fake_edr",
    "Fake EDR",
    "Offline, then collects.",
    "file_location",
)
.retry(ace_sdk::actions::Retry {
    initial_delay_seconds: 1,
    max_delay_seconds: 1,
    max_attempts: Some(3),
    deadline_seconds: Some(3600),
});

impl ace_sdk::actions::FileCollector for FakeCollector {
    fn spec(&self) -> &'static ace_sdk::actions::ActionSpec {
        &FAKE_COLLECTOR
    }

    fn collect<'a>(
        &'a self,
        target: &'a ace_sdk::actions::LeasedAction,
        dir: &'a Path,
    ) -> ace_sdk::actions::ActionFuture<'a, ace_sdk::actions::CollectorResult> {
        Box::pin(async move {
            if target.attempts == 0 {
                return ace_sdk::actions::CollectorResult {
                    status: ace_sdk::actions::CollectorStatus::HostOffline,
                    message: Some("the host is offline".to_owned()),
                    file: None,
                };
            }
            let path = dir.join("evil.ps1");
            std::fs::write(&path, format!("collected from {}", target.observable_value))
                .expect("writes");
            ace_sdk::actions::CollectorResult {
                status: ace_sdk::actions::CollectorStatus::Success,
                message: None,
                file: Some(path),
            }
        })
    }
}

/// A core whose test pool runs the test remediator, the fake probe and the fake collector.
async fn actions_core() -> (Core, ace_core::actions::ActionCatalog) {
    let specs: [&'static ace_sdk::actions::ActionSpec; 3] = [
        &ace_sdk::actions::TEST_REMEDIATOR,
        &FAKE_PROBE,
        &FAKE_COLLECTOR,
    ];
    let catalog = ace_core::actions::ActionCatalog::new(&specs).expect("a catalog");
    let entries: Vec<String> = specs.iter().map(|s| s.pool_entry()).collect();
    let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
    let configured = catalog.clone();
    let core = Core::start_configured(
        ace_core::eligibility::Catalog::new([]),
        ace_core::modes::Modes::ace3(),
        &entries,
        Duration::from_secs(30),
        move |config| config.actions(configured),
    )
    .await;
    (core, catalog)
}

fn action_pool(core: &Core) -> ace_pool::actions::ActionPool {
    let handlers = ace_pool::actions::Handlers::new()
        .with(ace_pool::actions::Handler::Remediator(std::sync::Arc::new(
            ace_sdk::actions::TestRemediator,
        )))
        .and_then(|h| {
            h.with(ace_pool::actions::Handler::Probe(std::sync::Arc::new(
                FakeProbe,
            )))
        })
        .and_then(|h| {
            h.with(ace_pool::actions::Handler::Collector(std::sync::Arc::new(
                FakeCollector,
            )))
        })
        .expect("handlers");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "actions").expect("a client");
    ace_pool::actions::ActionPool::new(client, std::sync::Arc::new(handlers), 4)
        .lease_wait(Duration::from_secs(1))
}

async fn plain_root(core: &Core) -> uuid::Uuid {
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = core.test_db.db().begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    root.id
}

/// An action's status, result and tries.
async fn action_state(core: &Core, id: i64) -> (String, Option<String>, i32) {
    sqlx::query_as("SELECT status, result, attempts FROM queue.actions WHERE id = $1")
        .bind(id)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("reads")
}

/// Waits up to 30 seconds for an action to complete, making one that waits for its backoff due at once.
async fn wait_completed(core: &Core, id: i64) -> (String, Option<String>, i32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let state = action_state(core, id).await;
        if state.0 == "COMPLETED" {
            return state;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "action {id} is still {state:?}"
        );
        sqlx::query(
            "UPDATE queue.actions SET run_after = now() WHERE id = $1 AND lease_owner IS NULL",
        )
        .bind(id)
        .execute(core.test_db.db().pool())
        .await
        .expect("updates");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// ace3's aaeef15e: a remediator that resolves its key to another target (an alias to the mailbox that
/// owns it) asks whether that target's own removal covers the message, and its result names what it
/// acted on, which the try's history keeps. Only the remediation's own worker may ask, only of a
/// remediation, and the answer is its own handler's latest remediation of the key, of the same type.
#[tokio::test]
async fn a_remediator_asks_what_another_removal_covers_and_names_what_it_acted_on() {
    let (core, catalog) = actions_core().await;
    let db = core.test_db.db();
    let analyst = serde_json::json!({"kind": "user", "id": uuid::Uuid::new_v4(), "name": "alice"});
    let remove = |value: &'static str| ace_core::actions::NewRemediation {
        handler: "test",
        observable_type: "test",
        observable_value: value,
        action: ace_sdk::actions::RemediationAction::Remove,
        restore_key: None,
        requested_by: &analyst,
        user: None,
    };
    let mut tx = db.begin().await.expect("begins");
    let alias = ace_core::actions::queue_remediation(&mut tx, &catalog, &remove("alias"))
        .await
        .expect("queues");
    let owner = ace_core::actions::queue_remediation(&mut tx, &catalog, &remove("owner"))
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let leased = client
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("an action");
    assert_eq!(leased.id, alias);
    // the owner's removal is queued and not yet tried: it covers the message
    assert!(
        client
            .removal_covers(alias, "owner")
            .await
            .expect("answers")
    );
    assert!(
        !client
            .removal_covers(alias, "nobody")
            .await
            .expect("answers")
    );
    // only the action's own worker may ask, and only with a key
    assert!(matches!(
        client.as_worker("w2").removal_covers(alias, "owner").await,
        Err(ace_pool::client::ClientError::LeaseLost(_))
    ));
    assert!(matches!(
        client.removal_covers(alias, "").await,
        Err(ace_pool::client::ClientError::Api { status: 400, .. })
    ));
    client
        .end_action(
            alias,
            &ace_sdk::actions::ActionEnd::Remediation {
                result: ace_sdk::actions::RemediatorResult::new(
                    ace_sdk::actions::RemediatorStatus::NotFound,
                    "left to the owner's own removal",
                )
                .resolved_to("owner"),
            },
        )
        .await
        .expect("ends");
    let (result, resolved): (String, Option<String>) = sqlx::query_as(
        "SELECT result, resolved_target FROM queue.action_attempts WHERE action_id = $1",
    )
    .bind(alias)
    .fetch_one(db.pool())
    .await
    .expect("its try");
    assert_eq!(
        (result.as_str(), resolved.as_deref()),
        ("NOT_FOUND", Some("owner"))
    );

    // ace3's cases: a finished removal covers only when it removed the message or found it gone, and a
    // restore uncovers it
    for (status, result, covers) in [
        ("IN_PROGRESS", Some("DELAYED"), true),
        ("COMPLETED", Some("SUCCESS"), true),
        ("COMPLETED", Some("NOT_FOUND"), true),
        ("COMPLETED", Some("FAILED"), false),
        ("COMPLETED", Some("ERROR"), false),
        ("COMPLETED", Some("CANCELLED"), false),
    ] {
        sqlx::query(
            "UPDATE queue.actions SET status = $2, result = $3,
                 lease_owner = NULL, lease_expires_at = NULL WHERE id = $1",
        )
        .bind(owner)
        .bind(status)
        .bind(result)
        .execute(db.pool())
        .await
        .expect("updates");
        assert_eq!(
            ace_core::actions::removal_covers(db, "test", "test", "owner")
                .await
                .expect("answers"),
            covers,
            "{status} {result:?}"
        );
    }
    sqlx::query("UPDATE queue.actions SET result = 'SUCCESS' WHERE id = $1")
        .bind(owner)
        .execute(db.pool())
        .await
        .expect("updates");
    let mut tx = db.begin().await.expect("begins");
    let restore = ace_core::actions::queue_remediation(
        &mut tx,
        &catalog,
        &ace_core::actions::NewRemediation {
            action: ace_sdk::actions::RemediationAction::Restore,
            ..remove("owner")
        },
    )
    .await
    .expect("queues");
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE queue.actions SET status = 'COMPLETED', result = 'SUCCESS' WHERE id = $1")
        .bind(restore)
        .execute(db.pool())
        .await
        .expect("restored");
    assert!(
        !ace_core::actions::removal_covers(db, "test", "test", "owner")
            .await
            .expect("answers"),
        "the latest action put it back"
    );
    // another remediator's row for the key, or another type's, isn't this target's
    assert!(
        !ace_core::actions::removal_covers(db, "other", "test", "alias")
            .await
            .expect("answers")
    );
}

/// PLAN.md 7.9's Done check: a remediation, a remediation check and a file collection each run from the
/// queue, through the lease API, on a pool that holds only its token. Two alerts that ask for one file
/// share one collection, which belongs to each of them (#1101).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remediation_checks_and_file_collections_run_from_the_queue() {
    let (core, catalog) = actions_core().await;
    let db = core.test_db.db();
    let (first, second) = (plain_root(&core).await, plain_root(&core).await);
    let analyst = serde_json::json!({"kind": "user", "id": uuid::Uuid::new_v4(), "name": "alice"});
    let mut tx = db.begin().await.expect("begins");
    let remediation = ace_core::actions::queue_remediation(
        &mut tx,
        &catalog,
        &ace_core::actions::NewRemediation {
            handler: "test",
            observable_type: "test",
            observable_value: "SUCCESS",
            action: ace_sdk::actions::RemediationAction::Remove,
            restore_key: None,
            requested_by: &analyst,
            user: None,
        },
    )
    .await
    .expect("queues");
    let context = serde_json::json!({"recipient": "bob@example.com"});
    let (check, new) = ace_core::actions::request_check(
        &mut tx,
        &catalog,
        &ace_core::actions::NewCheck {
            handler: "fake_vendor",
            observable_type: "email_delivery",
            observable_value: "<m@example.com>|bob@example.com",
            root: first,
            context: Some(&context),
        },
    )
    .await
    .expect("queues");
    assert!(new);
    let collection = |root| ace_core::actions::NewCollection {
        handler: "fake_edr",
        observable_type: "file_location",
        observable_value: "host1@C:\\Users\\bob\\evil.ps1",
        root: Some(root),
        requested_by: None,
        user: None,
    };
    let queued = ace_core::actions::request_collection(&mut tx, &catalog, &collection(first))
        .await
        .expect("queues");
    let joined = ace_core::actions::request_collection(&mut tx, &catalog, &collection(second))
        .await
        .expect("joins");
    assert!(matches!(queued, ace_core::actions::Requested::Queued(_)));
    assert_eq!(
        joined,
        ace_core::actions::Requested::Joined(queued.id()),
        "the second alert joins the first's collection"
    );
    // a pending check for the same alert and target isn't queued twice
    let (again, new) = ace_core::actions::request_check(
        &mut tx,
        &catalog,
        &ace_core::actions::NewCheck {
            handler: "fake_vendor",
            observable_type: "email_delivery",
            observable_value: "<m@example.com>|bob@example.com",
            root: first,
            context: None,
        },
    )
    .await
    .expect("finds it");
    assert_eq!((again, new), (check, false));
    // a handler this server hasn't, or a type its handler doesn't act on, is refused
    assert!(
        ace_core::actions::request_collection(
            &mut tx,
            &catalog,
            &ace_core::actions::NewCollection {
                observable_type: "ipv4",
                ..collection(first)
            }
        )
        .await
        .is_err()
    );
    tx.commit().await.expect("commits");

    let stop = tokio_util::sync::CancellationToken::new();
    let pool = action_pool(&core);
    let running = {
        let stop = stop.clone();
        tokio::spawn(async move { pool.run(stop).await })
    };
    assert_eq!(
        wait_completed(&core, remediation).await,
        ("COMPLETED".to_owned(), Some("SUCCESS".to_owned()), 1)
    );
    assert_eq!(
        wait_completed(&core, check).await,
        ("COMPLETED".to_owned(), Some("CONFIRMED".to_owned()), 2)
    );
    assert_eq!(
        wait_completed(&core, queued.id()).await,
        ("COMPLETED".to_owned(), Some("SUCCESS".to_owned()), 2)
    );
    stop.cancel();
    let stats = running.await.expect("joins");
    assert_eq!(stats.errors, 0, "{stats:?}");
    assert_eq!(stats.ended, 5, "{stats:?}");

    // each try is recorded, as ace3's history tables record them
    let attempts: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT action_id, status, result FROM queue.action_attempts ORDER BY action_id, id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(
        attempts,
        [
            (remediation, "COMPLETED".to_owned(), "SUCCESS".to_owned()),
            (check, "NEW".to_owned(), "PENDING".to_owned()),
            (check, "COMPLETED".to_owned(), "CONFIRMED".to_owned()),
            (
                queued.id(),
                "IN_PROGRESS".to_owned(),
                "HOST_OFFLINE".to_owned()
            ),
            (queued.id(), "COMPLETED".to_owned(), "SUCCESS".to_owned()),
        ]
    );
    let events: serde_json::Value =
        sqlx::query_scalar("SELECT events FROM queue.actions WHERE id = $1")
            .bind(check)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(events[0]["source"], "Fake Vendor");
    assert_eq!(events[0]["folder"], "Junk");

    // the collected file is in the bucket, held by the collection and by both alerts
    let (sha256, size, name): (String, i64, String) =
        sqlx::query_as("SELECT file_sha256, file_size, file_name FROM queue.actions WHERE id = $1")
            .bind(queued.id())
            .fetch_one(db.pool())
            .await
            .expect("reads");
    let expected = "collected from host1@C:\\Users\\bob\\evil.ps1".to_owned();
    assert_eq!(sha256, hex(&sha2::Sha256::digest(expected.as_bytes())));
    assert_eq!((size, name.as_str()), (expected.len() as i64, "evil.ps1"));
    let mut holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2",
    )
    .bind(ALERT_FILES)
    .bind(&sha256)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    holds.sort();
    let mut expected_holds = vec![
        ("file_collection".to_owned(), queued.id().to_string()),
        ("root".to_owned(), first.to_string()),
        ("root".to_owned(), second.to_string()),
    ];
    expected_holds.sort();
    assert_eq!(holds, expected_holds);
    // the upload is gone once the core moved it into the pool
    let uploads = core
        .bucket
        .store()
        .list("uploads/actions/")
        .await
        .expect("lists");
    assert!(!uploads.iter().any(|k| k.ends_with(&sha256)), "{uploads:?}");
    // the first alert going leaves the second's collection as it was (#1101)
    sqlx::query("DELETE FROM analysis.roots WHERE id = $1")
        .bind(first)
        .execute(db.pool())
        .await
        .expect("deletes");
    let roots: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT root_id FROM queue.action_roots WHERE action_id = $1")
            .bind(queued.id())
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(roots, [second]);
    // the second alert asking again gets its own collection back
    let mut tx = db.begin().await.expect("begins");
    assert_eq!(
        ace_core::actions::request_collection(&mut tx, &catalog, &collection(second))
            .await
            .expect("finds it"),
        ace_core::actions::Requested::Collected(queued.id())
    );
    tx.rollback().await.expect("rolls back");

    // a prune lets go of the collection's own hold once its retention passed; the alert's stays
    let mut tx = db.begin().await.expect("begins");
    assert!(
        ace_core::actions::prune_collections_in(&mut tx, Duration::from_secs(3600))
            .await
            .expect("prunes")
            .is_empty()
    );
    let pruned = ace_core::actions::prune_collections_in(&mut tx, Duration::ZERO)
        .await
        .expect("prunes");
    tx.commit().await.expect("commits");
    assert_eq!(
        pruned.iter().map(|p| p.id).collect::<Vec<_>>(),
        [queued.id()]
    );
    let holds: Vec<(String, String)> = sqlx::query_as(
        "SELECT holder_kind, holder_id FROM store.holds WHERE pool = $1 AND sha256 = $2
         ORDER BY holder_kind, holder_id",
    )
    .bind(ALERT_FILES)
    .bind(&sha256)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert!(
        holds.contains(&("root".to_owned(), second.to_string())),
        "{holds:?}"
    );
    assert!(
        !holds.iter().any(|(kind, _)| kind == "file_collection"),
        "{holds:?}"
    );
    let sha: Sha256 = sha256.parse().expect("a sha256");
    core.bucket
        .store()
        .delete(ALERT_FILES, &sha)
        .await
        .expect("deletes");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A delayed remediation runs again until it completes, a cancel stops one between tries, and a check past
/// its deadline or confirmed by ACE's own removal ends without a try, as ace3's worker finalizes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_queue_retries_cancels_expires_and_supersedes_actions() {
    let (core, catalog) = actions_core().await;
    let db = core.test_db.db();
    let root = plain_root(&core).await;
    let analyst = serde_json::json!({"kind": "user", "id": uuid::Uuid::new_v4(), "name": "alice"});
    let remove = |value: &'static str| ace_core::actions::NewRemediation {
        handler: "test",
        observable_type: "test",
        observable_value: value,
        action: ace_sdk::actions::RemediationAction::Remove,
        restore_key: None,
        requested_by: &analyst,
        user: None,
    };
    let delivery = "<n@example.com>|carol@example.com";
    let mut tx = db.begin().await.expect("begins");
    let delayed = ace_core::actions::queue_remediation(&mut tx, &catalog, &remove("DELAYED"))
        .await
        .expect("queues");
    let check = |value| ace_core::actions::NewCheck {
        handler: "fake_vendor",
        observable_type: "email_delivery",
        observable_value: value,
        root,
        context: None,
    };
    let (expired, _) = ace_core::actions::request_check(&mut tx, &catalog, &check(delivery))
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE queue.actions SET deadline_at = now() - interval '1 second' WHERE id = $1")
        .bind(expired)
        .execute(db.pool())
        .await
        .expect("updates");

    // a pool gets the remediation, and the next ask ends the expired check without giving it out
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w").expect("a client");
    let leased = client
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("an action");
    assert_eq!(leased.id, delayed);
    assert!(
        client
            .as_worker("w2")
            .lease_action(Duration::ZERO)
            .await
            .expect("leases")
            .is_none()
    );
    assert_eq!(
        action_state(&core, expired).await,
        ("COMPLETED".to_owned(), Some("EXPIRED".to_owned()), 0)
    );
    // another worker can't end or renew it
    let other = client.as_worker("x");
    let end = ace_sdk::actions::ActionEnd::Remediation {
        result: ace_sdk::actions::RemediatorResult::new(
            ace_sdk::actions::RemediatorStatus::Delayed,
            "later",
        ),
    };
    assert!(matches!(
        other.end_action(delayed, &end).await,
        Err(ace_pool::client::ClientError::LeaseLost(_))
    ));
    // a check's end isn't a remediation's
    let wrong = ace_sdk::actions::ActionEnd::RemediationCheck {
        outcome: ace_sdk::actions::ProbeOutcome::Pending { message: None },
    };
    assert!(matches!(
        client.end_action(delayed, &wrong).await,
        Err(ace_pool::client::ClientError::Api { status: 400, .. })
    ));
    client.end_action(delayed, &end).await.expect("ends");
    assert_eq!(
        action_state(&core, delayed).await,
        ("IN_PROGRESS".to_owned(), Some("DELAYED".to_owned()), 1)
    );
    let wait: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM run_after - now())::float8 FROM queue.actions WHERE id = $1",
    )
    .bind(delayed)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert!((55.0..=60.0).contains(&wait), "{wait}");
    // a cancel while it waits completes it, and a pool holding it learns at its renewal
    let mut tx = db.begin().await.expect("begins");
    assert!(
        ace_core::actions::cancel_in(&mut tx, delayed, "cancelled by alice")
            .await
            .expect("cancels")
    );
    assert!(
        !ace_core::actions::cancel_in(&mut tx, delayed, "again")
            .await
            .expect("cancels")
    );
    tx.commit().await.expect("commits");
    assert_eq!(
        action_state(&core, delayed).await,
        ("COMPLETED".to_owned(), Some("CANCELLED".to_owned()), 1)
    );
    // a retry queues it again as it was
    let mut tx = db.begin().await.expect("begins");
    assert!(
        ace_core::actions::retry_in(&mut tx, &catalog, delayed)
            .await
            .expect("retries")
    );
    tx.commit().await.expect("commits");
    let leased = client
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("the retry");
    assert_eq!(leased.id, delayed);
    let mut tx = db.begin().await.expect("begins");
    ace_core::actions::cancel_in(&mut tx, delayed, "cancelled by alice")
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    let renewal = client.renew_action(delayed).await.expect("renews");
    assert!(renewal.cancelled);
    assert!(matches!(
        client.end_action(delayed, &end).await,
        Err(ace_pool::client::ClientError::LeaseLost(_))
    ));

    // what an action acts on doesn't change once it's queued
    let mut tx = db.begin().await.expect("begins");
    let removal = ace_core::actions::queue_remediation(&mut tx, &catalog, &remove("SUCCESS"))
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE queue.actions SET observable_type = 'email_delivery' WHERE id = $1")
        .bind(removal)
        .execute(db.pool())
        .await
        .expect_err("an action's target doesn't change");
    let leased = client
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("the removal");
    assert_eq!(leased.id, removal);
    client
        .end_action(
            removal,
            &ace_sdk::actions::ActionEnd::Remediation {
                result: ace_sdk::actions::RemediatorResult::new(
                    ace_sdk::actions::RemediatorStatus::Success,
                    "removed",
                ),
            },
        )
        .await
        .expect("ends");
    // a check of an email_delivery ACE removed a minute ago, past the probe's grace of none
    sqlx::query(
        "INSERT INTO queue.actions (kind, handler, observable_type, observable_value, action, status, result, updated_at)
         VALUES ('remediation', 'test', 'email_delivery', $1, 'remove', 'COMPLETED', 'SUCCESS', now() - interval '1 minute')",
    )
    .bind(delivery)
    .execute(db.pool())
    .await
    .expect("inserts");
    let mut tx = db.begin().await.expect("begins");
    let (fresh, new) = ace_core::actions::request_check(&mut tx, &catalog, &check(delivery))
        .await
        .expect("queues");
    assert!(new, "the expired one completed, so a new one is queued");
    tx.commit().await.expect("commits");
    assert!(
        client
            .lease_action(Duration::ZERO)
            .await
            .expect("leases")
            .is_none()
    );
    let (status, result, _) = action_state(&core, fresh).await;
    assert_eq!(
        (status.as_str(), result.as_deref()),
        ("COMPLETED", Some("SUPERSEDED"))
    );
    let message: String =
        sqlx::query_scalar("SELECT result_message FROM queue.actions WHERE id = $1")
            .bind(fresh)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        ace_core::actions::superseding_source(Some(&message)).as_deref(),
        Some("ACE")
    );

    // a lease that lapses is taken back and given again
    let mut tx = db.begin().await.expect("begins");
    let lost = ace_core::actions::queue_remediation(&mut tx, &catalog, &remove("SUCCESS"))
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    assert_eq!(
        client
            .lease_action(Duration::ZERO)
            .await
            .expect("leases")
            .map(|a| a.id),
        Some(lost)
    );
    sqlx::query(
        "UPDATE queue.actions SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(lost)
    .execute(db.pool())
    .await
    .expect("updates");
    assert_eq!(ace_core::actions::reap_actions(db).await.expect("reaps"), 1);
    assert_eq!(
        client
            .lease_action(Duration::ZERO)
            .await
            .expect("leases")
            .map(|a| (a.id, a.attempts)),
        Some((lost, 0))
    );
}

// ---- a site module's remediation-check write (PLAN.md decision 32) ----

/// Lookups that declare `remediation-check`, which no module of ace-rs's does: the first alone, the
/// second with `smtp-log` too, so a test can send a write that may not come with a delay.
mod checks {
    use ace_results::ObservableKind;
    use ace_sdk::example::LineStats;
    use ace_sdk::writes::{RemediationCheck, SmtpLog, Write, WriteKind};
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    pub struct AsksForACheck;

    impl Module for AsksForACheck {
        const NAME: &'static str = "test_remediation_check";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::EmailDelivery];
        const WRITES: &'static [Write] = &[RemediationCheck::WRITE];
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(AsksForACheck)
        }
    }

    impl Lookup for AsksForACheck {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Err(ModuleError::other("the tests end its tasks themselves"))
        }
    }

    pub struct AlsoLogs;

    impl Module for AlsoLogs {
        const NAME: &'static str = "test_remediation_check_and_log";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::EmailDelivery];
        const WRITES: &'static [Write] = &[RemediationCheck::WRITE, SmtpLog::WRITE];
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(AlsoLogs)
        }
    }

    impl Lookup for AlsoLogs {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Err(ModuleError::other("the tests end its tasks themselves"))
        }
    }
}

/// A core whose catalog has the test modules that ask for a check and the fake probe.
async fn check_core() -> Core {
    let names = [
        "test_remediation_check",
        "test_remediation_check_and_log",
        "archive",
    ];
    let mut entries: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    entries.push(FAKE_PROBE.pool_entry());
    let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
    let catalog =
        ace_core::actions::ActionCatalog::new(&[&FAKE_PROBE, &ace_sdk::actions::TEST_REMEDIATOR])
            .expect("a catalog");
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_sdk::Manifest::lookup::<checks::AsksForACheck>(),
            ace_sdk::Manifest::lookup::<checks::AlsoLogs>(),
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &entries,
        Duration::from_secs(30),
        move |config| config.actions(catalog),
    )
    .await
}

/// The checks of a root: id, status, result, tries, context and events.
async fn checks_of(
    core: &Core,
    root: uuid::Uuid,
) -> Vec<(
    i64,
    String,
    Option<String>,
    i32,
    Option<serde_json::Value>,
    Option<serde_json::Value>,
)> {
    sqlx::query_as(
        "SELECT a.id, a.status, a.result, a.attempts, a.context, a.events FROM queue.actions a
         JOIN queue.action_roots r ON r.action_id = a.id
         WHERE r.root_id = $1 AND a.kind = 'remediation_check' ORDER BY a.id",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("reads")
}

const DELIVERY: &str = "<m@example.com>|bob@example.com";

fn check_write(body: serde_json::Value) -> ace_sdk::writes::WireWrite {
    ace_sdk::writes::WireWrite {
        write: "remediation-check".to_owned(),
        body,
    }
}

/// PLAN.md decision 32: a module's `remediation-check` queues a check of its own observable for its
/// root, with its context, and records its answer as a try, with a delay as with a skip; the next run
/// finds the pending check again rather than queueing a second, as ace3's module does, and its answer
/// is the check's next try.
#[tokio::test]
async fn a_module_s_remediation_check_is_queued_once_and_its_answers_are_tries() {
    let core = check_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let root = root_of(
        &core,
        ace_results::ObservableKind::EmailDelivery,
        &[DELIVERY],
        "test_remediation_check",
    )
    .await;
    let task = lease_one(&client, "test_remediation_check").await;
    let context = serde_json::json!({"event_time": "2026-11-20T10:00:00+00:00"});
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Delay {
                after_seconds: 0.0,
                state: serde_json::json!({"attempts": 1}),
                scan: None,
                writes: vec![check_write(serde_json::json!({
                    "probe": "fake_vendor",
                    "context": context,
                    "outcome": {"outcome": "pending", "message": "nothing yet"},
                }))],
            },
        )
        .await
        .expect("the delay lands with its write");
    assert_eq!(
        common::task_of(&core, root, "test_remediation_check")
            .await
            .0,
        "delayed"
    );
    let checks = checks_of(&core, root).await;
    assert_eq!(checks.len(), 1);
    let (check, status, result, attempts, kept, _) = checks[0].clone();
    assert_eq!((status.as_str(), result, attempts), ("NEW", None, 1));
    assert_eq!(kept, Some(context));
    let (handler, value): (String, String) =
        sqlx::query_as("SELECT handler, observable_value FROM queue.actions WHERE id = $1")
            .bind(check)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!(
        (handler.as_str(), value.as_str()),
        ("fake_vendor", DELIVERY)
    );

    // the next run finds the pending check and records its answer as the next try
    let task = lease_one(&client, "test_remediation_check").await;
    let event = serde_json::json!({
        "source": "Fake Vendor", "event_type": "moved", "timestamp": "2026-11-20T10:05:00Z",
        "description": "Moved", "target": "bob@example.com",
    });
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "asked".to_owned(),
                writes: vec![check_write(serde_json::json!({
                    "probe": "fake_vendor",
                    "context": {"event_time": "later"},
                    "outcome": {"outcome": "found_events", "events": [event]},
                }))],
            },
        )
        .await
        .expect("ends");
    let checks = checks_of(&core, root).await;
    assert_eq!(checks.len(), 1, "one check for the probe, target and alert");
    let (again, status, result, attempts, kept, events) = checks[0].clone();
    assert_eq!(again, check);
    assert_eq!(
        (status.as_str(), result.as_deref(), attempts),
        ("COMPLETED", Some("CONFIRMED"), 2)
    );
    assert_eq!(
        kept.expect("kept")["event_time"],
        "2026-11-20T10:00:00+00:00",
        "the pending check keeps its own"
    );
    assert_eq!(events.expect("events")[0]["event_type"], "moved");
    let tries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM queue.action_attempts WHERE action_id = $1")
            .bind(check)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("counts");
    assert_eq!(tries, 2);

    // with the check ended, another root's module queues one of its own, for that root alone
    let other = root_of(
        &core,
        ace_results::ObservableKind::EmailDelivery,
        &[DELIVERY],
        "test_remediation_check",
    )
    .await;
    let task = lease_one(&client, "test_remediation_check").await;
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "asked".to_owned(),
                writes: vec![check_write(serde_json::json!({"probe": "fake_vendor"}))],
            },
        )
        .await
        .expect("ends");
    let theirs = checks_of(&core, other).await;
    assert_eq!(theirs.len(), 1);
    assert_ne!(theirs[0].0, check);
    assert_eq!(
        (theirs[0].1.as_str(), theirs[0].3),
        ("NEW", 0),
        "queued, no answer recorded"
    );
    assert_eq!(checks_of(&core, root).await.len(), 1);
}

/// A pool holding the check decides its try: a module's answer then queues nothing new and records
/// nothing.
#[tokio::test]
async fn a_module_s_answer_leaves_a_check_a_pool_holds() {
    let core = check_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let root = root_of(
        &core,
        ace_results::ObservableKind::EmailDelivery,
        &[DELIVERY],
        "test_remediation_check",
    )
    .await;
    let task = lease_one(&client, "test_remediation_check").await;
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Delay {
                after_seconds: 0.0,
                state: serde_json::Value::Null,
                scan: None,
                writes: vec![check_write(serde_json::json!({"probe": "fake_vendor"}))],
            },
        )
        .await
        .expect("delays");
    let probe = client.as_worker("probe");
    let leased = probe
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("the check");
    let task = lease_one(&client, "test_remediation_check").await;
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "asked".to_owned(),
                writes: vec![check_write(serde_json::json!({
                    "probe": "fake_vendor",
                    "outcome": {"outcome": "not_found"},
                }))],
            },
        )
        .await
        .expect("ends");
    let checks = checks_of(&core, root).await;
    assert_eq!(checks.len(), 1);
    assert_eq!(
        (checks[0].0, checks[0].1.as_str(), checks[0].3),
        (leased.id, "NEW", 0)
    );
    probe
        .end_action(
            leased.id,
            &ace_sdk::actions::ActionEnd::RemediationCheck {
                outcome: ace_sdk::actions::ProbeOutcome::Pending { message: None },
            },
        )
        .await
        .expect("the pool's try ends");
    assert_eq!(checks_of(&core, root).await[0].3, 1);
}

/// A `remediation-check` is refused, failing the task with nothing written, from a module that
/// doesn't declare it (403), with a body that doesn't read (400), naming a probe the core hasn't or a
/// handler that isn't a probe (403), with a context past its bound (403), asking twice for one probe
/// (403), or beside a write that can't come with a delay (403).
#[tokio::test]
async fn a_remediation_check_is_refused_as_the_contract_says() {
    let core = check_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let big = "x".repeat(ace_sdk::writes::MAX_CHECK_CONTEXT_BYTES);
    let probe = |body| check_write(body);
    let skip = |writes| ace_sdk::wire::TaskEnd::Skipped {
        reason: "asked".to_owned(),
        writes,
    };
    let delay = |writes| ace_sdk::wire::TaskEnd::Delay {
        after_seconds: 0.0,
        state: serde_json::Value::Null,
        scan: None,
        writes,
    };
    let refusals = [
        (
            "archive",
            skip(vec![probe(serde_json::json!({"probe": "fake_vendor"}))]),
            403,
        ),
        (
            "test_remediation_check",
            skip(vec![probe(serde_json::json!({"probe": 5}))]),
            400,
        ),
        (
            "test_remediation_check",
            skip(vec![probe(
                serde_json::json!({"probe": "fake_vendor", "context": [1]}),
            )]),
            400,
        ),
        (
            "test_remediation_check",
            skip(vec![probe(serde_json::json!({"probe": "no_such_vendor"}))]),
            403,
        ),
        (
            "test_remediation_check",
            skip(vec![probe(serde_json::json!({"probe": "test"}))]),
            403,
        ),
        (
            "test_remediation_check",
            skip(vec![probe(
                serde_json::json!({"probe": "fake_vendor", "context": {"big": big}}),
            )]),
            403,
        ),
        (
            "test_remediation_check",
            skip(vec![
                probe(serde_json::json!({"probe": "fake_vendor"})),
                probe(serde_json::json!({"probe": "fake_vendor"})),
            ]),
            403,
        ),
        (
            "test_remediation_check_and_log",
            delay(vec![
                probe(serde_json::json!({"probe": "fake_vendor"})),
                ace_sdk::writes::WireWrite {
                    write: "smtp-log".to_owned(),
                    body: serde_json::json!({"rows": []}),
                },
            ]),
            403,
        ),
    ];
    for (module, end, expected) in refusals {
        let root = root_of(
            &core,
            ace_results::ObservableKind::EmailDelivery,
            &[DELIVERY],
            module,
        )
        .await;
        let task = lease_one(&client, module).await;
        let refused = client.end(task.id, &end).await;
        assert!(
            matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
            "{module}: {refused:?}"
        );
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "failed", "{module}");
        assert!(error.is_some(), "{module}");
        assert!(
            checks_of(&core, root).await.is_empty(),
            "{module}: nothing written"
        );
    }
    // a probe of another type than the task's observable's is refused too
    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["example.com"],
        "test_remediation_check",
    )
    .await;
    let task = lease_one(&client, "test_remediation_check").await;
    let refused = client
        .end(
            task.id,
            &skip(vec![probe(serde_json::json!({"probe": "fake_vendor"}))]),
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
    assert!(checks_of(&core, root).await.is_empty());
    // a lease lost before the end writes nothing
    let root = root_of(
        &core,
        ace_results::ObservableKind::EmailDelivery,
        &[DELIVERY],
        "test_remediation_check",
    )
    .await;
    let task = lease_one(&client, "test_remediation_check").await;
    let lost = client
        .as_worker("w2")
        .end(
            task.id,
            &skip(vec![probe(serde_json::json!({"probe": "fake_vendor"}))]),
        )
        .await;
    assert!(
        matches!(lost, Err(ace_pool::client::ClientError::LeaseLost(_))),
        "{lost:?}"
    );
    assert!(checks_of(&core, root).await.is_empty());
}

// ---- svs_yara_sample_capture: the svs-capture-state read and the svs-capture write (PLAN.md 7.10
// batch 2) ----

const SVS_RULE: &str = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f";

/// A core whose pools run SVS's capture and archive, which declares no read or write.
async fn svs_core() -> Core {
    let modules = ["svs_yara_sample_capture", "archive"];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([ace_mod_svs::MANIFEST, ace_mod_archive::MANIFEST]),
        ace_core::modes::Modes::ace3(),
        &modules,
        Duration::from_secs(30),
        |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules.iter().map(|m| (*m).to_owned()).collect(),
            ));
            config
        },
    )
    .await
}

/// An alert of `disposition` with a file the bucket holds for it at `dir/invoice.doc`, the YARA module's
/// result and its detection of `SVS_RULE` on the file, and a task of `module` on it. Returns the root and
/// the file's sha256.
async fn svs_root(core: &Core, module: &str, disposition: &str) -> (uuid::Uuid, String) {
    use ace_core::tree;
    let db = core.test_db.db();
    let root = tree::NewRoot::new("dispositioned");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let bytes = format!("svs sample {}", uuid::Uuid::new_v4()).into_bytes();
    let sha256 = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            &bytes,
            Some(&ace_core::bucket::Hold::root(root.id)),
        )
        .await
        .expect("puts the file")
        .object
        .sha256
        .to_hex();
    let mut tx = db.begin().await.expect("begins");
    let id = tree::upsert_observable(
        &mut tx,
        root.id,
        &ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.clone()),
    )
    .await
    .expect("adds")
    .id;
    tree::add_file(
        &mut tx,
        root.id,
        id,
        "dir/invoice.doc",
        &["source=email".to_owned()],
    )
    .await
    .expect("records the file");
    let scan: ace_results::types::yara::ScanResult = serde_json::from_value(serde_json::json!({
        "rule": "svs_rule", "namespace": "unittest", "meta": {"uuid": SVS_RULE},
        "tags": [], "commit": "c", "target": "dir/invoice.doc", "strings": [],
        "context": [], "match_context": [],
    }))
    .expect("a scan result");
    let yara = ace_results::ResultEnvelope::new(ace_results::types::yara::YaraScanResults {
        scan_results: vec![scan],
    })
    .to_raw()
    .expect("JSON");
    tree::insert_result(&mut tx, root.id, id, "yara_scanner_v3_4", &yara)
        .await
        .expect("the YARA result");
    sqlx::query(
        "INSERT INTO analysis.detections
             (root_id, observable_id, description, details, signature_uuid, signature_version,
              signature_family)
         VALUES ($1, $2, 'dir/invoice.doc matched yara rule svs_rule', $3, $4, 'c', 'yara')",
    )
    .bind(root.id)
    .bind(id.0)
    .bind(serde_json::json!({
        "sha256": sha256, "rule": "svs_rule", "namespace": "unittest", "rule_uuid": SVS_RULE,
    }))
    .bind(SVS_RULE)
    .execute(tx.conn())
    .await
    .expect("a detection");
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = now(), disposition = $2,
             dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}'
         WHERE id = $1",
    )
    .bind(root.id)
    .bind(disposition)
    .execute(tx.conn())
    .await
    .expect("dispositions it");
    ace_core::queue::enqueue(&mut tx, root.id, id, module)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    (root.id, sha256)
}

/// `svs-capture-state` answers what ace3's capture reads of its database, for the task's own file only:
/// the disposition and its class, the unreviewed run, the file's paths and detections, the deletion and
/// what's captured; past its bound it says it cut the detections; and the refusals every read makes.
#[tokio::test]
async fn svs_capture_state_answers_for_the_task_s_own_file_and_refuses_the_rest() {
    let core = svs_core().await;
    let (root, sha256) = svs_root(&core, "svs_yara_sample_capture", "DELIVERY").await;
    let (_, elsewhere) = svs_root(&core, "archive", "DELIVERY").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let task = client
        .lease(&["svs_yara_sample_capture".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_eq!(task.root, root);
    let answer = client
        .read(task.id, "svs-capture-state", &serde_json::json!({}), false)
        .await
        .expect("answers");
    assert_eq!(answer["alert"], true);
    assert_eq!(answer["disposition"], "DELIVERY");
    assert_eq!(answer["classified"], true);
    assert_eq!(answer["unreviewed_run"], false);
    assert_eq!(
        answer["paths"],
        serde_json::json!([{"path": "dir/invoice.doc", "yara_meta": ["source=email"]}])
    );
    assert_eq!(answer["detections"][0]["signature_uuid"], SVS_RULE);
    assert_eq!(answer["detections"][0]["details"]["rule"], "svs_rule");
    assert_eq!(answer["detections_truncated"], false);
    assert_eq!(answer["deleted"], false);
    assert_eq!(answer["captures"], serde_json::json!([]));

    // an unclassified disposition, a deletion and a capture show
    let db = core.test_db.db();
    sqlx::query("UPDATE analysis.roots SET disposition = 'REVIEWED' WHERE id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("dispositions it");
    sqlx::query(
        "INSERT INTO svs.yara_captures
             (root_id, sha256, rule_uuid, rule_name, signature_version, file_path, state,
              missing_reason)
         VALUES ($1, $2, $3, 'svs_rule', 'c', 'dir/invoice.doc', 'missing', 'file')",
    )
    .bind(root)
    .bind(&sha256)
    .bind(SVS_RULE)
    .execute(db.pool())
    .await
    .expect("a capture");
    sqlx::query(
        "INSERT INTO svs.sample_deletions (sha256, deleted_by, reason, rule_uuids, capture_count)
         VALUES ($1, '{\"kind\": \"internal\", \"id\": \"test\"}', 'privacy', '{}', 0)",
    )
    .bind(&sha256)
    .execute(db.pool())
    .await
    .expect("a deletion");
    let answer = client
        .read(task.id, "svs-capture-state", &serde_json::json!({}), false)
        .await
        .expect("answers");
    assert_eq!(answer["classified"], false);
    assert_eq!(answer["deleted"], true);
    assert_eq!(
        answer["captures"],
        serde_json::json!([{"rule_uuid": SVS_RULE, "state": "missing", "missing_reason": "file"}])
    );

    // past the bound, the first MAX_SVS_DETECTIONS, said to be cut
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, observable_id, description)
         SELECT $1, o.id, 'more ' || n FROM analysis.observables o, generate_series(1, $2) n
         WHERE o.root_id = $1",
    )
    .bind(root)
    .bind(i32::try_from(ace_sdk::reads::MAX_SVS_DETECTIONS).expect("small"))
    .execute(db.pool())
    .await
    .expect("inserts");
    let answer = client
        .read(task.id, "svs-capture-state", &serde_json::json!({}), false)
        .await
        .expect("answers");
    assert_eq!(
        answer["detections"].as_array().expect("detections").len(),
        ace_sdk::reads::MAX_SVS_DETECTIONS
    );
    assert_eq!(answer["detections_truncated"], true);

    let archive_task = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    assert_refusals(
        &core,
        task.id,
        "svs-capture-state",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "file", "value": elsewhere}}),
        archive_task.id,
    )
    .await;
}

/// The capture run as the lookups pool runs it: its read goes through the pool's client, its write lands
/// with its skip, the file is copied into the `svs_samples` pool held by its capture, and no result is
/// stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sample_capture_runs_through_the_lease_api() {
    let core = svs_core().await;
    let (root, sha256) = svs_root(&core, "svs_yara_sample_capture", "DELIVERY").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new().with_lookup(
            ace_pool::modules::Entry::<ace_mod_svs::YaraSampleCapture>::lookup(
                None,
                &ace_sdk::Secrets::new(),
            )
            .expect("the module"),
        ),
    );
    let task = client
        .lease(&[], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let end = ace_pool::run::run_in_process(
        &client,
        &modules,
        task,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("runs");
    assert!(
        matches!(&end, ace_sdk::wire::TaskEnd::Skipped { writes, .. } if writes.len() == 1),
        "{end:?}"
    );
    let db = core.test_db.db();
    let row: (
        uuid::Uuid,
        String,
        String,
        Vec<String>,
        String,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT root_id, rule_uuid, file_path, yara_meta_tags, state, record
             FROM svs.yara_captures WHERE sha256 = $1",
    )
    .bind(&sha256)
    .fetch_one(db.pool())
    .await
    .expect("a capture");
    assert_eq!(row.0, root);
    assert_eq!(row.1, SVS_RULE);
    assert_eq!(row.2, "dir/invoice.doc");
    assert_eq!(row.3, ["source=email"]);
    assert_eq!(row.4, "stored");
    assert_eq!(row.5.expect("a record")["rule"], "svs_rule");
    let parsed: ace_results::Sha256 = sha256.parse().expect("a sha256");
    assert!(
        core.bucket
            .object(ace_core::svs::samples::SVS_SAMPLES, &parsed)
            .await
            .expect("reads")
            .is_some()
    );
    let results: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis.results WHERE root_id = $1 AND module = 'svs_yara_sample_capture'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(results, 0);
    let (state, _) = common::task_of(&core, root, "svs_yara_sample_capture").await;
    assert_eq!(state, "done");
}

/// The write is refused, failing the task with nothing written, from a module that doesn't declare it,
/// with a body that doesn't read (400), naming another file, a rule no detection on the file is of, a
/// path that isn't the file's, a rule twice, past its bound, or twice in one end (403); a lost lease
/// writes nothing.
#[tokio::test]
async fn the_capture_write_is_refused_unless_it_s_the_task_s_own_file_s_matches() {
    let core = svs_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let write = |body: serde_json::Value| ace_sdk::writes::WireWrite {
        write: "svs-capture".to_owned(),
        body,
    };
    let candidate = |sha256: &str, rule: &str, path: &str| {
        serde_json::json!({
            "sha256": sha256, "rule_uuid": rule, "rule_name": "svs_rule", "namespace": "unittest",
            "signature_version": "c", "file_path": path, "yara_meta_tags": [], "match_record": null,
        })
    };
    let skipped = |writes| ace_sdk::wire::TaskEnd::Skipped {
        reason: "captured".to_owned(),
        writes,
    };
    let rows = |core: &Core| {
        let pool = core.test_db.db().pool().clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM svs.yara_captures")
                .fetch_one(&pool)
                .await
                .expect("counts")
        }
    };
    // archive declares no write, and a body that doesn't read
    for (module, expected) in [("archive", 403), ("svs_yara_sample_capture", 400)] {
        let (root, sha256) = svs_root(&core, module, "DELIVERY").await;
        let task = client
            .lease(&[module.to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let body = if module == "archive" {
            serde_json::json!({"captures": [candidate(&sha256, SVS_RULE, "dir/invoice.doc")]})
        } else {
            serde_json::json!({"captures": 5})
        };
        let refused = client.end(task.id, &skipped(vec![write(body)])).await;
        assert!(
            matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
            "{module}: {refused:?}"
        );
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "failed", "{module}");
        assert!(error.is_some(), "{module}");
        assert_eq!(rows(&core).await, 0, "{module}: nothing written");
    }
    type Bodies<'a> = Box<dyn Fn(&str) -> Vec<serde_json::Value> + 'a>;
    let refusals: Vec<Bodies> = vec![
        // another file
        Box::new(|_| {
            vec![
                serde_json::json!({"captures": [candidate(&"ab".repeat(32), SVS_RULE, "dir/invoice.doc")]}),
            ]
        }),
        // a rule no detection on the file is of
        Box::new(|s| {
            vec![serde_json::json!({"captures": [candidate(s, "another-rule", "dir/invoice.doc")]})]
        }),
        // a path that isn't the file's
        Box::new(|s| {
            vec![serde_json::json!({"captures": [candidate(s, SVS_RULE, "elsewhere.doc")]})]
        }),
        // a rule twice
        Box::new(|s| {
            vec![serde_json::json!({"captures": [
                candidate(s, SVS_RULE, "dir/invoice.doc"), candidate(s, SVS_RULE, "dir/invoice.doc"),
            ]})]
        }),
        // past the bound
        Box::new(|s| {
            vec![
                serde_json::json!({"captures": (0..=ace_sdk::writes::MAX_SVS_CAPTURES)
                .map(|_| candidate(s, SVS_RULE, "dir/invoice.doc")).collect::<Vec<_>>()}),
            ]
        }),
        // twice in one end
        Box::new(|s| {
            let one = serde_json::json!({"captures": [candidate(s, SVS_RULE, "dir/invoice.doc")]});
            vec![one.clone(), one]
        }),
    ];
    for (index, body) in refusals.iter().enumerate() {
        let (root, sha256) = svs_root(&core, "svs_yara_sample_capture", "DELIVERY").await;
        let task = client
            .lease(&["svs_yara_sample_capture".to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .expect("a task");
        let writes = body(&sha256).into_iter().map(write).collect();
        let refused = client.end(task.id, &skipped(writes)).await;
        assert!(
            matches!(
                &refused,
                Err(ace_pool::client::ClientError::Api { status: 403, .. })
            ),
            "case {index}: {refused:?}"
        );
        let (state, _) = common::task_of(&core, root, "svs_yara_sample_capture").await;
        assert_eq!(state, "failed", "case {index}");
        assert_eq!(rows(&core).await, 0, "case {index}: nothing written");
    }
    // a lease lost before the end writes nothing, and its own worker's end lands it
    let (_, sha256) = svs_root(&core, "svs_yara_sample_capture", "DELIVERY").await;
    let task = client
        .lease(&["svs_yara_sample_capture".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("a task");
    let good = || {
        vec![write(
            serde_json::json!({"captures": [candidate(&sha256, SVS_RULE, "dir/invoice.doc")]}),
        )]
    };
    let lost = client.as_worker("w2").end(task.id, &skipped(good())).await;
    assert!(
        matches!(lost, Err(ace_pool::client::ClientError::LeaseLost(_))),
        "{lost:?}"
    );
    assert_eq!(rows(&core).await, 0);
    client.end(task.id, &skipped(good())).await.expect("ends");
    assert_eq!(rows(&core).await, 1);
}

/// A task of a module that runs last is held back while another module's task is left in its root,
/// with a wait that doubles to 32 seconds. The end of the last of them makes it due and wakes the
/// pool waiting for it, so the rest of its wait isn't sat out. The module never hears of the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_that_runs_last_is_leased_when_the_last_other_task_ends() {
    let core = Core::start(
        vec![ace_mod_brocess::thread::MANIFEST, ace_mod_archive::MANIFEST],
        &["email_thread_analyzer", "archive"],
        Duration::from_secs(30),
    )
    .await;
    let message_id = "<a@example.com>";
    let root = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &[message_id],
        "email_thread_analyzer",
    )
    .await;
    common::enqueue(&core, root, message_id, "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let thread = ["email_thread_analyzer".to_owned()];
    assert!(
        client
            .lease(&thread, Duration::ZERO)
            .await
            .expect("leases")
            .is_none(),
        "held back: the archive task is left"
    );
    // as after its seventh ask: half a minute to the next
    let held = sqlx::query(
        "UPDATE queue.tasks
         SET run_after = now() + interval '30 seconds', held_back_step = 6
         WHERE root_id = $1 AND module = 'email_thread_analyzer' AND state = 'delayed'
           AND held_back_by = 'others'",
    )
    .bind(root)
    .execute(core.test_db.db().pool())
    .await
    .expect("updates")
    .rows_affected();
    assert_eq!(held, 1);
    let archive = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the archive task");
    // a pool with a free slot waits for the held task
    let waiting = tokio::spawn({
        let client = client.clone();
        async move { client.lease(&thread, Duration::from_secs(20)).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !waiting.is_finished(),
        "still held back while the archive task runs"
    );
    let ended = std::time::Instant::now();
    client
        .end(
            archive.id,
            &ace_sdk::wire::TaskEnd::Skipped {
                reason: "nothing to do".into(),
                writes: Vec::new(),
            },
        )
        .await
        .expect("ends");
    let task = waiting
        .await
        .expect("joins")
        .expect("leases")
        .expect("the held task");
    assert!(
        ended.elapsed() < Duration::from_secs(5),
        "leased {:?} after the archive task ended: it sat out its wait",
        ended.elapsed()
    );
    assert_eq!(task.module, "email_thread_analyzer");
    assert!(task.delayed.is_none(), "a hold isn't a module's delay");
}

/// What a task's row says of its runs and its module's delays: runs, run seconds, delays, whether
/// it has a first delay, its delay state, attempts and state.
type RunRecord = (i32, f64, i32, bool, Option<serde_json::Value>, i32, String);

async fn run_record(core: &Core, root: uuid::Uuid, module: &str) -> RunRecord {
    sqlx::query_as(
        "SELECT runs, run_seconds, delays, first_delayed_at IS NOT NULL, delay_state, attempts,
                state::text
         FROM queue.tasks WHERE root_id = $1 AND module = $2",
    )
    .bind(root)
    .bind(module)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task's row")
}

/// A root with a task of email_thread_analyzer, which runs last, and an archive task that holds it
/// back, on a core whose lease the thread task has just been held back by.
async fn held_back_thread(core: &Core) -> (uuid::Uuid, ace_pool::client::LeaseClient) {
    let message_id = "<held@example.com>";
    let root = root_of(
        core,
        ace_results::ObservableKind::MessageId,
        &[message_id],
        "email_thread_analyzer",
    )
    .await;
    common::enqueue(core, root, message_id, "archive").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    assert!(
        client
            .lease(&["email_thread_analyzer".to_owned()], Duration::ZERO)
            .await
            .expect("leases")
            .is_none(),
        "held back: the archive task is left"
    );
    (root, client)
}

/// The core holding back a task that runs last isn't a run of its module, nor its module's delay: no
/// pool saw it. Its run count, run time and delay record stay as they were, and the claim isn't an
/// attempt, so once it runs and ends it has run once, and its module's metrics event says one run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn holding_back_a_task_that_runs_last_is_not_a_run() {
    let core = Core::start(
        vec![ace_mod_brocess::thread::MANIFEST, ace_mod_archive::MANIFEST],
        &["email_thread_analyzer", "archive"],
        Duration::from_secs(30),
    )
    .await;
    let (root, client) = held_back_thread(&core).await;
    assert_eq!(
        run_record(&core, root, "email_thread_analyzer").await,
        (0, 0.0, 0, false, None, 0, "delayed".to_owned()),
        "a hold counts nothing and leaves the module's delay alone"
    );
    let archive = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the archive task");
    client.end(archive.id, &skipped()).await.expect("ends");
    let task = client
        .lease(
            &["email_thread_analyzer".to_owned()],
            Duration::from_secs(10),
        )
        .await
        .expect("leases")
        .expect("the held task");
    assert_eq!(task.attempts, 1, "the hold's claim wasn't an attempt");
    assert!(task.delayed.is_none(), "its module never asked for a delay");
    client.end(task.id, &skipped()).await.expect("ends");
    let (runs, _, delays, delayed, _, _, state) =
        run_record(&core, root, "email_thread_analyzer").await;
    assert_eq!(
        (runs, delays, delayed, state.as_str()),
        (1, 0, false, "done")
    );
    let metrics = ace_core::metrics::read_last_pass(core.test_db.db(), root)
        .await
        .expect("reads")
        .expect("the pass completed");
    let thread = metrics
        .modules
        .iter()
        .find(|m| m.module == "email_thread_analyzer")
        .expect("the module's event");
    assert_eq!(thread.exec_count, 1);
}

/// A task that runs last and asks for a delay of its own after the core held it back gets that
/// delay's whole timeout, which counts from its own first delay, and sees only its own state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_held_back_to_run_last_keeps_its_own_delay() {
    let core = Core::start(
        vec![ace_mod_brocess::thread::MANIFEST, ace_mod_archive::MANIFEST],
        &["email_thread_analyzer", "archive"],
        Duration::from_secs(30),
    )
    .await;
    let (_, client) = held_back_thread(&core).await;
    let archive = client
        .lease(&["archive".to_owned()], Duration::ZERO)
        .await
        .expect("leases")
        .expect("the archive task");
    client.end(archive.id, &skipped()).await.expect("ends");
    let thread = ["email_thread_analyzer".to_owned()];
    let task = client
        .lease(&thread, Duration::from_secs(10))
        .await
        .expect("leases")
        .expect("the held task");
    let asked: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("reads the clock");
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Delay {
                after_seconds: 0.0,
                state: serde_json::json!({"asked": 1}),
                scan: None,
                writes: Vec::new(),
            },
        )
        .await
        .expect("delays");
    let again = client
        .lease(&thread, Duration::from_secs(10))
        .await
        .expect("leases")
        .expect("the delayed task");
    let delayed = again.delayed.expect("its own delay");
    assert_eq!(
        (delayed.delays, &delayed.state),
        (1, &serde_json::json!({"asked": 1})),
        "one delay, its own"
    );
    assert!(
        delayed.first_delayed_at >= asked,
        "its timeout counts from {}, before it asked at {asked}",
        delayed.first_delayed_at
    );
}

/// A task's state, attempts, error, delay state, and whether a module ever delayed it.
type TaskState = (String, i32, Option<String>, Option<serde_json::Value>, bool);
/// `TaskState` after the task's observable value and module.
type TaskRow = (
    String,
    String,
    String,
    i32,
    Option<String>,
    Option<serde_json::Value>,
    bool,
);

/// The states of a root's tasks by observable value and module.
async fn task_rows(
    core: &Core,
    root: uuid::Uuid,
) -> std::collections::BTreeMap<(String, String), TaskState> {
    let rows: Vec<TaskRow> = sqlx::query_as(
        "SELECT o.value, t.module, t.state::text, t.attempts, t.error, t.delay_state,
                t.first_delayed_at IS NOT NULL
         FROM queue.tasks t JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the root's tasks");
    rows.into_iter()
        .map(|(value, module, state, attempts, error, delay, delayed)| {
            ((value, module), (state, attempts, error, delay, delayed))
        })
        .collect()
}

/// An observable in `root` with a task of `module`, in the caller's transaction.
async fn observable_with_task(
    tx: &mut ace_core::db::Tx<'_>,
    root: uuid::Uuid,
    kind: ace_results::ObservableKind,
    value: &str,
    module: &str,
) -> (ace_core::tree::ObservableId, i64) {
    let observable =
        ace_core::tree::upsert_observable(tx, root, &ace_results::NewObservable::new(kind, value))
            .await
            .expect("adds")
            .id;
    let task = ace_core::queue::enqueue(tx, root, observable, module)
        .await
        .expect("queues")
        .expect("a new task");
    (observable, task.0)
}

fn skipped() -> ace_sdk::wire::TaskEnd {
    ace_sdk::wire::TaskEnd::Skipped {
        reason: "nothing to do".into(),
        writes: Vec::new(),
    }
}

/// A request for several tasks is answered task by task. Seven are claimed together here, and each
/// lease is decided as when it is claimed alone: a task that runs last is held back for the others
/// and marked for their wake, a file's first task is held for its path while something nearer the
/// root is pending, a file that isn't in the bucket fails its task, and the other four are leased,
/// oldest first, each with what is its own: its observable, its file and download, its delay's
/// state, its attempt. A task that isn't due and one of a cancelled root aren't claimed at all. So
/// one task held back, failed or cancelled keeps no other from being leased. Then the held tasks
/// are leased in their turn, the one that runs last once the rest of its root is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_for_several_tasks_decides_each_lease_alone() {
    use ace_results::ObservableKind as Kind;
    let mut manifests = ace_pool::testing::test_manifests();
    manifests.push(ace_mod_brocess::thread::MANIFEST);
    let core = Core::start(
        manifests,
        &["test_counted", "test_spin", "email_thread_analyzer"],
        Duration::from_secs(30),
    )
    .await;
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let root = root.id;
    let hold = ace_core::bucket::Hold::root(root);
    let mut stored = Vec::new();
    for bytes in [&b"at the root"[..], &b"below the root"[..]] {
        stored.push(
            core.bucket
                .put_bytes(ALERT_FILES, bytes, Some(&hold))
                .await
                .expect("puts the bytes")
                .object
                .sha256
                .to_hex(),
        );
    }
    let (at_root, below) = (stored[0].clone(), stored[1].clone());
    let missing = hex(&sha2::Sha256::digest(b"never stored"));
    let message_id = "<several@example.com>";

    let mut tx = db.begin().await.expect("begins");
    let (_, delayed) = observable_with_task(
        &mut tx,
        root,
        Kind::Fqdn,
        "delayed.example.com",
        "test_counted",
    )
    .await;
    for host in ["one.example.com", "two.example.com"] {
        observable_with_task(&mut tx, root, Kind::Fqdn, host, "test_counted").await;
    }
    observable_with_task(
        &mut tx,
        root,
        Kind::MessageId,
        message_id,
        "email_thread_analyzer",
    )
    .await;
    let mut deep = None;
    for (value, path) in [
        (&at_root, "at-root.txt"),
        (&missing, "missing.txt"),
        (&below, "below.txt"),
    ] {
        let (observable, _) =
            observable_with_task(&mut tx, root, Kind::File, value, "test_spin").await;
        ace_core::tree::add_file(&mut tx, root, observable, path, &[])
            .await
            .expect("records the file");
        deep = Some(observable);
    }
    tx.commit().await.expect("commits");
    // the last file is one level down, so a path nearer the root could still be added for it
    sqlx::query("UPDATE analysis.observables SET depth = 1 WHERE id = $1")
        .bind(deep.expect("the file below").0)
        .execute(db.pool())
        .await
        .expect("moves the file down");
    // a module delayed this one, and its delay is over
    sqlx::query(
        "UPDATE queue.tasks SET state = 'delayed', run_after = now() - interval '1 minute',
                delay_state = '{\"asked\": 1}', first_delayed_at = now(), delays = 1
         WHERE id = $1",
    )
    .bind(delayed)
    .execute(db.pool())
    .await
    .expect("delays it");
    // a root whose task isn't due for an hour, and a cancelled root
    let later =
        common::root_with_tasks(&core, &["later.example.com".to_owned()], "test_counted").await;
    sqlx::query("UPDATE queue.tasks SET run_after = now() + interval '1 hour' WHERE root_id = $1")
        .bind(later)
        .execute(db.pool())
        .await
        .expect("puts it off");
    let cancelled =
        common::root_with_tasks(&core, &["cancelled.example.com".to_owned()], "test_counted").await;
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, cancelled)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");

    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let leased = client
        .lease_up_to(&[], Duration::ZERO, 20)
        .await
        .expect("leases");
    let got: Vec<(&str, &str)> = leased
        .iter()
        .map(|task| (task.observable.value.as_str(), task.module.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("delayed.example.com", "test_counted"),
            ("one.example.com", "test_counted"),
            ("two.example.com", "test_counted"),
            (at_root.as_str(), "test_spin"),
        ],
        "the four that can run now, oldest first"
    );
    for task in &leased {
        assert_eq!((task.root, task.attempts), (root, 1));
    }
    let delay = leased[0].delayed.as_ref().expect("its delay");
    assert_eq!(
        (delay.delays, &delay.state),
        (1, &serde_json::json!({"asked": 1}))
    );
    assert!(leased[1..].iter().all(|task| task.delayed.is_none()));
    assert!(
        leased[..3]
            .iter()
            .all(|task| task.observable.file.is_none())
    );
    let file = leased[3].observable.file.as_ref().expect("its file");
    assert_eq!(
        (file.path.as_str(), file.sha256.to_hex(), file.size),
        ("at-root.txt", at_root.clone(), 11)
    );
    // test_spin is a parser, so it gets the download
    let download = file.download.as_ref().expect("a parser's download");
    let bytes = reqwest::get(&download.url)
        .await
        .expect("downloads")
        .bytes()
        .await
        .expect("the bytes");
    assert_eq!(&bytes[..], b"at the root");

    let rows = task_rows(&core, root).await;
    let row = |value: &str, module: &str| rows[&(value.to_owned(), module.to_owned())].clone();
    for (value, module) in &got {
        assert_eq!(row(value, module).0, "running", "{value}");
    }
    // held back for the other modules, and marked so their end wakes it, which its module never
    // hears of
    let (state, attempts, _, delay, delayed) = row(message_id, "email_thread_analyzer");
    assert_eq!(
        (state.as_str(), attempts, delay, delayed),
        ("delayed", 0, None, false)
    );
    let mark: (Option<String>, Option<i32>) = sqlx::query_as(
        "SELECT held_back_by, held_back_step FROM queue.tasks
         WHERE root_id = $1 AND module = 'email_thread_analyzer'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(mark, (Some("others".to_owned()), Some(0)));
    // held for its path, which its module never hears of
    let (state, attempts, error, delay, delayed) = row(&below, "test_spin");
    assert_eq!(
        (state.as_str(), attempts, error, delay, delayed),
        ("delayed", 0, None, None, false)
    );
    let (state, _, error, _, _) = row(&missing, "test_spin");
    assert_eq!(state, "failed");
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("isn't in the bucket")),
        "{error:?}"
    );
    assert_eq!(
        task_rows(&core, later).await[&("later.example.com".to_owned(), "test_counted".to_owned())]
            .0,
        "queued"
    );
    assert_eq!(
        task_rows(&core, cancelled).await[&(
            "cancelled.example.com".to_owned(),
            "test_counted".to_owned()
        )]
            .0,
        "cancelled"
    );

    // the four end, and the file below is leased once its hold is over: nothing nearer the root
    // is pending but the task that runs last, which waits for it
    for task in &leased {
        client.end(task.id, &skipped()).await.expect("ends");
    }
    let next = client
        .lease_up_to(&[], Duration::from_secs(10), 20)
        .await
        .expect("leases");
    assert_eq!(next.len(), 1, "{next:?}");
    assert_eq!(
        (next[0].observable.value.as_str(), next[0].module.as_str()),
        (below.as_str(), "test_spin")
    );
    let file = next[0].observable.file.as_ref().expect("its file");
    assert_eq!(file.path.as_str(), "below.txt");
    assert!(next[0].delayed.is_none(), "a hold isn't a module's delay");
    client.end(next[0].id, &skipped()).await.expect("ends");
    // and then the one that runs last
    let last = client
        .lease_up_to(&[], Duration::from_secs(10), 20)
        .await
        .expect("leases");
    assert_eq!(last.len(), 1, "{last:?}");
    assert_eq!(last[0].module, "email_thread_analyzer");
    assert!(last[0].delayed.is_none(), "a hold isn't a module's delay");
}

/// The answer holds no more tasks than the request asks for, one when it doesn't say, and no more
/// than the core's own limit whatever it asks. It holds what is due now and doesn't wait for more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_request_is_answered_with_no_more_than_it_asks_for() {
    let most = usize::try_from(ace_sdk::wire::MAX_LEASED_AT_ONCE).expect("fits");
    let core = Core::start(
        ace_pool::testing::test_manifests(),
        &["test_counted"],
        Duration::from_secs(30),
    )
    .await;
    let values: Vec<String> = (0..most + 6)
        .map(|i| format!("host{i}.example.com"))
        .collect();
    let root = common::root_with_tasks(&core, &values, "test_counted").await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");

    // a request that names no number, as the wire had it before a request could
    let response = reqwest::Client::new()
        .post(format!("{}{}", core.url, ace_sdk::wire::paths::LEASE))
        .bearer_auth(common::TOKEN)
        .header("content-type", "application/json")
        .body(r#"{"worker": "pool"}"#)
        .send()
        .await
        .expect("answers");
    assert_eq!(response.status(), 200);
    let one: Vec<ace_sdk::wire::LeasedTask> =
        serde_json::from_str(&response.text().await.expect("a body")).expect("a list of tasks");
    assert_eq!(one.len(), 1);

    let three = client
        .lease_up_to(&[], Duration::ZERO, 3)
        .await
        .expect("leases");
    assert_eq!(three.len(), 3);
    let limit = client
        .lease_up_to(&[], Duration::ZERO, 1000)
        .await
        .expect("leases");
    assert_eq!(limit.len(), most, "the core's limit");
    // two are left: the answer is those two, at once, though it may wait and asked for more
    let asked = std::time::Instant::now();
    let rest = client
        .lease_up_to(&[], Duration::from_secs(10), 1000)
        .await
        .expect("leases");
    assert_eq!(rest.len(), 2);
    assert!(
        asked.elapsed() < Duration::from_secs(5),
        "{:?}",
        asked.elapsed()
    );
    assert!(
        client
            .lease_up_to(&[], Duration::ZERO, 1000)
            .await
            .expect("leases")
            .is_empty()
    );

    // every task once, in the order they were queued
    let ids: Vec<i64> = one
        .iter()
        .chain(&three)
        .chain(&limit)
        .chain(&rest)
        .map(|task| task.id)
        .collect();
    let queued: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM queue.tasks WHERE root_id = $1 ORDER BY id")
            .bind(root)
            .fetch_all(core.test_db.db().pool())
            .await
            .expect("the tasks");
    assert_eq!(ids, queued);
    let leased: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM queue.tasks
         WHERE root_id = $1 AND state = 'running' AND lease_owner = 'test/pool' AND attempts = 1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("counts");
    assert_eq!(usize::try_from(leased).expect("fits"), most + 6);
}

/// A lease request that ends before its answer gives its tasks back. The request here claims three
/// tasks. The first's lease is decided, the second's waits on a row this test has locked, the
/// third's hasn't begun, and then the pool goes away, as when it is stopped or killed while it
/// asks. No pool heard of any of them. The core queues the first and the third again at once with
/// the claim uncounted, so they don't wait out a lease nobody renews. The one whose lease was
/// being decided keeps its lease until it runs out, as a request's one task did before: a request
/// that ends there may have ended because that decision panicked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_request_dropped_before_its_answer_gives_its_tasks_back() {
    use ace_results::ObservableKind as Kind;
    use tokio::io::AsyncWriteExt as _;
    let core = Core::start(
        ace_pool::testing::test_manifests(),
        &["test_counted", "test_spin"],
        Duration::from_secs(600),
    )
    .await;
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let root = root.id;
    let sha256 = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            b"a file",
            Some(&ace_core::bucket::Hold::root(root)),
        )
        .await
        .expect("puts the bytes")
        .object
        .sha256
        .to_hex();
    let mut tx = db.begin().await.expect("begins");
    observable_with_task(
        &mut tx,
        root,
        Kind::Fqdn,
        "first.example.com",
        "test_counted",
    )
    .await;
    let (file, _) = observable_with_task(&mut tx, root, Kind::File, &sha256, "test_spin").await;
    ace_core::tree::add_file(&mut tx, root, file, "file.txt", &[])
        .await
        .expect("records the file");
    observable_with_task(
        &mut tx,
        root,
        Kind::Fqdn,
        "third.example.com",
        "test_counted",
    )
    .await;
    tx.commit().await.expect("commits");

    // the file's lease settles its path under this row's lock, so it waits here
    let mut locked = db.pool().begin().await.expect("begins");
    sqlx::query("SELECT id FROM analysis.observables WHERE id = $1 FOR UPDATE")
        .bind(file.0)
        .execute(&mut *locked)
        .await
        .expect("locks the file's row");

    let body = r#"{"worker": "pool", "max": 8}"#;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", core.port))
        .await
        .expect("connects");
    stream
        .write_all(
            format!(
                "POST {} HTTP/1.1\r\nHost: core\r\nAuthorization: Bearer {}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                ace_sdk::wire::paths::LEASE,
                common::TOKEN,
                body.len(),
            )
            .as_bytes(),
        )
        .await
        .expect("sends the request");
    // each task's state and attempts, by its observable
    let states = || async {
        let rows = task_rows(&core, root).await;
        let state = |value: &str, module: &str| {
            let (state, attempts, ..) = rows[&(value.to_owned(), module.to_owned())].clone();
            (state, attempts)
        };
        [
            state("first.example.com", "test_counted"),
            state(&sha256, "test_spin"),
            state("third.example.com", "test_counted"),
        ]
    };
    let running = ("running".to_owned(), 1);
    let queued = ("queued".to_owned(), 0);
    let started = std::time::Instant::now();
    while states().await != [running.clone(), running.clone(), running.clone()] {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the request never claimed its tasks"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // the request decides the leases one at a time, so once a session waits on the locked row, the
    // second's has begun and the first's is decided; the answer waits for the second. Each test has
    // a database of its own, so a waiting session in it is the request's.
    let started = std::time::Instant::now();
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock')",
        )
        .fetch_one(db.pool())
        .await
        .expect("reads pg_stat_activity");
        if waiting {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the second task's lease never waited on the locked row"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        states().await,
        [running.clone(), running.clone(), running.clone()]
    );
    drop(stream);

    let started = std::time::Instant::now();
    while states().await != [queued.clone(), running.clone(), queued.clone()] {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the tasks weren't given back: {:?}",
            states().await
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    println!("given back {:?} after the request ended", started.elapsed());
    locked.rollback().await.expect("lets the row go");

    // the next request leases the two, and the third still has the lease the request left it
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let leased = client
        .lease_up_to(&[], Duration::from_secs(10), 8)
        .await
        .expect("leases");
    let got: Vec<(&str, i32)> = leased
        .iter()
        .map(|task| (task.observable.value.as_str(), task.attempts))
        .collect();
    assert_eq!(got, [("first.example.com", 1), ("third.example.com", 1)]);
    assert_eq!(states().await[1], running);
}

/// One decision that waits keeps the answer of the tasks decided before it, and their leases began
/// at the claim. Here a file's lease waits on a row this test has locked for longer than a lease
/// lasts, and the reaper takes all three claimed tasks back meanwhile. The request doesn't hand
/// the pool tasks it no longer holds: it leaves them out, claims again and answers with the three
/// on their second claim, each with a whole lease ahead of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_outlasts_its_leases_answers_only_with_tasks_it_holds() {
    use ace_results::ObservableKind as Kind;
    let lease = Duration::from_secs(2);
    let core = Core::start(
        ace_pool::testing::test_manifests(),
        &["test_counted", "test_spin"],
        lease,
    )
    .await;
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let root = root.id;
    let sha256 = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            b"a file",
            Some(&ace_core::bucket::Hold::root(root)),
        )
        .await
        .expect("puts the bytes")
        .object
        .sha256
        .to_hex();
    let mut tx = db.begin().await.expect("begins");
    observable_with_task(
        &mut tx,
        root,
        Kind::Fqdn,
        "first.example.com",
        "test_counted",
    )
    .await;
    let (file, _) = observable_with_task(&mut tx, root, Kind::File, &sha256, "test_spin").await;
    ace_core::tree::add_file(&mut tx, root, file, "file.txt", &[])
        .await
        .expect("records the file");
    observable_with_task(
        &mut tx,
        root,
        Kind::Fqdn,
        "third.example.com",
        "test_counted",
    )
    .await;
    tx.commit().await.expect("commits");

    let mut locked = db.pool().begin().await.expect("begins");
    sqlx::query("SELECT id FROM analysis.observables WHERE id = $1 FOR UPDATE")
        .bind(file.0)
        .execute(&mut *locked)
        .await
        .expect("locks the file's row");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let asking = tokio::spawn({
        let client = client.clone();
        async move { client.lease_up_to(&[], Duration::from_secs(10), 8).await }
    });
    // past the lease: the reaper takes the three back, and then the row is let go
    tokio::time::sleep(lease + Duration::from_millis(500)).await;
    let reaped = ace_core::queue::reap_expired_leases(db, None)
        .await
        .expect("reaps");
    assert_eq!(reaped.requeued.len(), 3, "{reaped:?}");
    assert!(!asking.is_finished(), "the request still waits on the row");
    locked.rollback().await.expect("lets the row go");

    let leased = asking.await.expect("joins").expect("leases");
    let got: Vec<(&str, i32)> = leased
        .iter()
        .map(|task| (task.observable.value.as_str(), task.attempts))
        .collect();
    assert_eq!(
        got,
        [
            ("first.example.com", 2),
            (sha256.as_str(), 2),
            ("third.example.com", 2)
        ],
        "each on the claim made after the reaper took it back"
    );
    let now = chrono::Utc::now();
    for task in &leased {
        let left = (task.lease_expires_at - now).to_std().unwrap_or_default();
        assert!(
            left > lease * 3 / 4,
            "{}'s lease has {left:?} left",
            task.observable.value
        );
    }
    let owned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM queue.tasks
         WHERE root_id = $1 AND state = 'running' AND lease_owner = 'test/pool' AND attempts = 2",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(owned, 3);
}

/// `file_type`'s stand-in: the core ends it itself where the bytes have a kept type.
struct TypeStep;

impl ace_sdk::Module for TypeStep {
    const NAME: &'static str = "file_type";
    const INPUTS: &'static [ace_results::ObservableKind] = &[ace_results::ObservableKind::File];
    type Output = ace_results::types::file_type::TypeFacts;
    type Settings = ();
    fn init(_: &()) -> Result<Self, ace_sdk::ModuleError> {
        Ok(TypeStep)
    }
}

impl ace_sdk::Parser for TypeStep {
    fn analyze(
        &self,
        _: &ace_sdk::TaskContext<()>,
    ) -> Result<ace_sdk::Outcome<ace_results::types::file_type::TypeFacts>, ace_sdk::ModuleError>
    {
        Ok(ace_sdk::Outcome::Skipped("a stub".to_owned()))
    }
}

/// PLAN.md decision 25: a file's type step whose bytes were typed meanwhile, in another root, is
/// leased as any file's first task is, its path settled, and then ended by the core on the kept
/// type: no pool is handed it. Kept from a name that didn't ask about JavaScript, the type doesn't
/// answer a `.js` path, and that step is handed to the pool to run.
#[tokio::test]
async fn a_type_step_on_bytes_typed_meanwhile_ends_in_the_core() {
    let core = Core::start(
        vec![ace_sdk::Manifest::parser::<TypeStep>()],
        &["file_type"],
        Duration::from_secs(30),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let (root, sha256) = common::root_with_bytes(&core, "analysis", b"some text", "a.txt").await;
    assert_eq!(common::task_of(&core, root, "file_type").await.0, "queued");
    let facts = ace_results::types::file_type::TypeFacts {
        description: "ASCII text, with no line terminators".to_owned(),
        mime: "text/plain".to_owned(),
        ..Default::default()
    };
    let mut tx = core.test_db.db().begin().await.expect("begins");
    ace_core::type_step::store_facts(&mut tx, &sha256.to_hex(), &facts)
        .await
        .expect("keeps");
    tx.commit().await.expect("commits");
    let leased = client
        .lease(&["file_type".to_owned()], Duration::ZERO)
        .await
        .expect("leases");
    assert!(leased.is_none(), "{leased:?}");
    assert_eq!(common::task_of(&core, root, "file_type").await.0, "done");
    let shown: bool = sqlx::query_scalar(
        "SELECT type_result FROM analysis.observables WHERE root_id = $1 AND type = 'file'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("reads");
    assert!(
        shown,
        "ace3's file_type result shows, as after a step the pool ran"
    );

    let (root, _) = common::root_with_bytes(&core, "analysis", b"some text", "b.js").await;
    let task = lease_one(&client, "file_type").await;
    assert_eq!(task.root, root);
}

/// Lookups that read the root's event time and where their observable came from, and one whose
/// declaration alone reads that and the mode.
mod lineage {
    use ace_results::ObservableKind;
    use ace_sdk::example::LineStats;
    use ace_sdk::takes::{Condition, Takes};
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    pub struct ReadsLineage;

    impl Module for ReadsLineage {
        const NAME: &'static str = "test_reads_lineage";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const READS_EVENT_TIME: bool = true;
        const READS_ADDED_BY: bool = true;
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(ReadsLineage)
        }
    }

    impl Lookup for ReadsLineage {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Ok(Outcome::Skipped(String::new()))
        }
    }

    pub struct Gated;

    impl Module for Gated {
        const NAME: &'static str = "test_gated";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Gated)
        }
        fn takes(_: &()) -> Takes {
            Takes::everything()
                .and(Condition::AtRoot, "not at the root")
                .and(Condition::Mode("analysis".to_owned()), "not analysis")
                .and(
                    Condition::directive_from(
                        "upload_to_scanner",
                        &[ace_sdk::directives::DirectiveSource::Analyst],
                    ),
                    "no analyst asked",
                )
        }
    }

    impl Lookup for Gated {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Ok(Outcome::Skipped(String::new()))
        }
    }
}

/// A leased task carries the root's event time and where it came from to a module that reads it,
/// whether its observable came with the submission to one that reads where it came from, and to a
/// module whose declaration alone reads those, the mode and where its directives came from
/// (PLAN.md decision 44), only the gate, which its `analyze` never sees.
#[tokio::test]
async fn a_lease_carries_the_event_time_and_the_gate_only_to_what_reads_them() {
    use ace_sdk::directives::{DirectiveSource, SourcedDirective};
    use ace_sdk::wire::{EventTimeSource, Gate, RootEventTime};
    let names = ["test_reads_lineage", "test_gated"];
    let core = Core::start(
        vec![
            ace_sdk::Manifest::lookup::<lineage::ReadsLineage>(),
            ace_sdk::Manifest::lookup::<lineage::Gated>(),
        ],
        &names,
        Duration::from_secs(60),
    )
    .await;
    let db = core.test_db.db();
    let when = chrono::DateTime::parse_from_rfc3339("2026-11-18T09:30:00Z")
        .expect("a time")
        .to_utc();
    let root = ace_core::tree::NewRoot {
        event_time: ace_core::tree::EventTime::Event(when),
        ..ace_core::tree::NewRoot::new("analysis")
    };
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    let stamped = ace_results::NewObservable {
        directives: vec!["upload_to_scanner".to_owned()],
        ..ace_results::NewObservable::new(ace_results::ObservableKind::Fqdn, "a.example")
    };
    let id = ace_core::tree::upsert_observable(&mut tx, root.id, &stamped)
        .await
        .expect("adds")
        .id;
    for from in [
        ace_core::tree::DirectivesFrom::hunt("splunk/hunt"),
        ace_core::tree::DirectivesFrom::analyst("user:1"),
        ace_core::tree::DirectivesFrom::analyst("user:2"),
    ] {
        ace_core::tree::record_directive_sources(&mut tx, root.id, id, &stamped.directives, from)
            .await
            .expect("records");
    }
    for module in names {
        ace_core::queue::enqueue(&mut tx, root.id, id, module)
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let reads = lease_one(&client, "test_reads_lineage").await;
    assert_eq!(
        reads.event_time,
        Some(RootEventTime {
            time: Some(when),
            source: EventTimeSource::Event,
        })
    );
    assert!(reads.at_root, "a submitted observable is at the root");
    assert!(reads.gate.is_empty(), "it declares nothing");
    let gated = lease_one(&client, "test_gated").await;
    assert_eq!(
        gated.gate,
        Gate {
            mode: Some("analysis".to_owned()),
            added_by: Vec::new(),
            at_root: true,
            // each source once, whoever added it
            directive_sources: vec![
                SourcedDirective::new("upload_to_scanner", DirectiveSource::Analyst),
                SourcedDirective::new("upload_to_scanner", DirectiveSource::Hunt),
            ],
        }
    );
    assert!(!gated.at_root && gated.event_time.is_none() && gated.tree.is_none());
}

/// PLAN.md decision 28: the core claims an action only for a handler its catalog has. A remediator
/// the overlay leaves off isn't in `ace serve`'s catalog, so an action queued for it while it was on
/// waits, even for a pool that still lists it; and a pool whose handlers are all off is refused.
#[tokio::test]
async fn an_action_of_a_handler_the_catalog_leaves_out_is_never_claimed() {
    let catalog = ace_core::actions::ActionCatalog::new(&[&ace_sdk::actions::TEST_REMEDIATOR])
        .expect("a catalog");
    let configured = catalog.clone();
    let core = Core::start_configured(
        ace_core::eligibility::Catalog::new([]),
        ace_core::modes::Modes::ace3(),
        &["@remediation/test", "@remediation/off_mailbox"],
        Duration::from_secs(30),
        move |config| config.actions(configured),
    )
    .await;
    let db = core.test_db.db();
    let insert =
        |handler: &'static str| {
            sqlx::query_scalar::<_, i64>(
            "INSERT INTO queue.actions (kind, handler, observable_type, observable_value, action)
             VALUES ('remediation', $1, $2, 'SUCCESS', 'remove') RETURNING id",
        )
        .bind(handler)
        .bind(if handler == "test" { "test" } else { "email_delivery" })
        .fetch_one(db.pool())
        };
    let off = insert("off_mailbox").await.expect("inserts");
    let test = insert("test").await.expect("inserts");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "actions").expect("a client");
    let leased = client
        .lease_action(Duration::ZERO)
        .await
        .expect("leases")
        .expect("an action");
    assert_eq!(leased.id, test);
    assert!(
        client
            .lease_action(Duration::ZERO)
            .await
            .expect("leases")
            .is_none(),
        "the off handler's action isn't claimed"
    );
    let (status,): (String,) = sqlx::query_as("SELECT status FROM queue.actions WHERE id = $1")
        .bind(off)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(status, "NEW");

    // a pool whose every handler is off is refused
    let core = Core::start_configured(
        ace_core::eligibility::Catalog::new([]),
        ace_core::modes::Modes::ace3(),
        &["@remediation/off_mailbox"],
        Duration::from_secs(30),
        move |config| config.actions(catalog),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "actions").expect("a client");
    let refused = client
        .lease_action(Duration::ZERO)
        .await
        .expect_err("refused");
    assert!(
        refused
            .to_string()
            .contains("no action handler this server has on"),
        "{refused}"
    );
}

// ---- PLAN.md decision 34: an incomplete end ----

/// A task's incomplete end (`TaskEnd::Incomplete`) lands its result as a `Done` does, its error
/// and all, and leaves the task done and marked incomplete. The root's mode doesn't run this test's
/// module, so nothing runs it again, as ace3 reruns only what the mode runs.
#[tokio::test]
async fn an_incomplete_end_lands_its_result_and_marks_the_task() {
    let names = ["test_recorded_message_ids"];
    let core = Core::start(
        vec![ace_sdk::Manifest::lookup::<recorded::AsksTheStore>()],
        &names,
        Duration::from_secs(30),
    )
    .await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let root = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &["<incomplete@example.com>"],
        "test_recorded_message_ids",
    )
    .await;
    let task = lease_one(&client, "test_recorded_message_ids").await;
    let result = ace_results::ResultEnvelope::new(ace_sdk::example::LineStats {
        lines: 1,
        longest_line: 4,
        first_line: ace_results::Bytes::from(b"line".to_vec()),
        truncated: false,
    })
    .with_summary("as far as it goes")
    .with_error("the vendor answered 503")
    .to_raw()
    .expect("raw");
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Incomplete {
                result,
                writes: Vec::new(),
                probes: Default::default(),
            },
        )
        .await
        .expect("lands");
    let (state, incomplete): (String, bool) =
        sqlx::query_as("SELECT state::text, incomplete FROM queue.tasks WHERE id = $1")
            .bind(task.id)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!((state.as_str(), incomplete), ("done", true));
    let (summary, error): (String, String) =
        sqlx::query_as("SELECT summary, error FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("its result");
    assert_eq!(
        (summary.as_str(), error.as_str()),
        ("as far as it goes", "the vendor answered 503")
    );
}

/// PLAN.md decision 45: the core sends a file's download to a lookup that reads its input file
/// (`Module::READS_INPUT_FILE`) and to no other lookup, which gets the file's record alone.
#[tokio::test]
async fn only_a_lookup_that_reads_its_file_gets_its_download() {
    let modules = ["test_reads_file", "test_file_record"];
    let core = Core::start(
        ace_pool::testing::test_manifests(),
        &modules,
        Duration::from_secs(60),
    )
    .await;
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            b"to a vendor",
            Some(&ace_core::bucket::Hold::root(root.id)),
        )
        .await
        .expect("puts the bytes")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let id = ace_core::tree::upsert_observable(
        &mut tx,
        root.id,
        &ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.to_hex()),
    )
    .await
    .expect("adds")
    .id;
    ace_core::tree::add_file(&mut tx, root.id, id, "to-vendor.bin", &[])
        .await
        .expect("records the file");
    for module in modules {
        ace_core::queue::enqueue(&mut tx, root.id, id, module)
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let reads = lease_one(&client, "test_reads_file").await;
    let file = reads.observable.file.as_ref().expect("its file");
    let download = file.download.as_ref().expect("its download");
    let bytes = reqwest::get(&download.url)
        .await
        .expect("downloads")
        .bytes()
        .await
        .expect("the bytes");
    assert_eq!(&bytes[..], b"to a vendor");
    let record = lease_one(&client, "test_file_record").await;
    let file = record.observable.file.as_ref().expect("its record");
    assert_eq!(
        (file.path.as_str(), file.sha256, file.download.is_none()),
        ("to-vendor.bin", sha256, true)
    );
}

/// A cacheable lookup, for decision 47's end through the lease API.
mod not_kept {
    use ace_results::ObservableKind;
    use ace_sdk::example::LineStats;
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    pub struct Cached;

    impl Module for Cached {
        const NAME: &'static str = "test_kept_or_not";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const CACHE: Option<ace_sdk::cache::Cache> = Some(ace_sdk::cache::Cache::new(
            1,
            std::time::Duration::from_secs(3600),
        ));
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Cached)
        }
    }

    impl Lookup for Cached {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Ok(Outcome::Skipped(String::new()))
        }
    }
}

/// PLAN.md decision 47: a `Done` end that says not to keep its result lands the result and leaves
/// the analysis cache without it; the same end without the flag is kept.
#[tokio::test]
async fn a_done_end_that_says_not_to_keep_is_landed_and_not_kept() {
    let core = Core::start(
        vec![ace_sdk::Manifest::lookup::<not_kept::Cached>()],
        &["test_kept_or_not"],
        Duration::from_secs(60),
    )
    .await;
    let db = core.test_db.db();
    let root = ace_core::tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    for value in ["unknown.example", "known.example"] {
        let id = ace_core::tree::upsert_observable(
            &mut tx,
            root.id,
            &ace_results::NewObservable::new(ace_results::ObservableKind::Fqdn, value),
        )
        .await
        .expect("adds")
        .id;
        ace_core::queue::enqueue(&mut tx, root.id, id, "test_kept_or_not")
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let kept_rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cache.results")
            .fetch_one(db.pool())
            .await
            .expect("counts")
    };
    for _ in 0..2 {
        let task = lease_one(&client, "test_kept_or_not").await;
        let keep = task.observable.value == "known.example";
        let result = ace_results::ResultEnvelope::new(ace_sdk::example::LineStats {
            lines: 1,
            longest_line: 1,
            first_line: ace_results::Bytes::new(b"x".to_vec()),
            truncated: false,
        })
        .to_raw()
        .expect("raw");
        client
            .end(
                task.id,
                &ace_sdk::wire::TaskEnd::Done {
                    result,
                    writes: Vec::new(),
                    probes: Default::default(),
                    keep,
                },
            )
            .await
            .expect("ends");
        assert_eq!(
            kept_rows().await,
            i64::from(keep),
            "{}",
            task.observable.value
        );
    }
    let landed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis.results WHERE root_id = $1 AND module = 'test_kept_or_not'",
    )
    .bind(root.id)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(landed, 2, "both land in their root");
}

// ---- a module's file collections and sandbox submissions (PLAN.md decisions 49 and 50) ----

mod asks {
    use ace_results::ObservableKind;
    use ace_sdk::example::LineStats;
    use ace_sdk::reads::{FileCollectionState, Read, ReadKind, SandboxSubmissionState};
    use ace_sdk::writes::{
        FileCollection, FileCollectionRelease, SandboxSubmission, Write, WriteKind,
    };
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    /// A stand-in for a site's endpoint file collector, whose tasks the tests end themselves.
    pub struct AsksForAFile;

    impl Module for AsksForAFile {
        const NAME: &'static str = "test_file_collection";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::FileLocation];
        const READS: &'static [Read] = &[FileCollectionState::READ];
        const WRITES: &'static [Write] = &[FileCollection::WRITE, FileCollectionRelease::WRITE];
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(AsksForAFile)
        }
    }

    impl Lookup for AsksForAFile {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Err(ModuleError::other("the tests end its tasks themselves"))
        }
    }

    #[derive(
        Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
    )]
    #[serde(deny_unknown_fields)]
    pub struct SandboxNote {}

    impl ace_results::AnalysisType for SandboxNote {
        const NAME: &'static str = "test_sandbox_note";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "test_sandbox";
    }

    /// A stand-in for a site's sandbox module.
    pub struct Sandboxes;

    impl Module for Sandboxes {
        const NAME: &'static str = "test_sandbox";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File, ObservableKind::Fqdn];
        const READS: &'static [Read] = &[SandboxSubmissionState::READ];
        const WRITES: &'static [Write] = &[SandboxSubmission::WRITE];
        type Output = SandboxNote;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Sandboxes)
        }
    }

    impl Lookup for Sandboxes {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<SandboxNote>, ModuleError> {
            Err(ModuleError::other("the tests end its tasks themselves"))
        }
    }
}

/// A core whose catalog has the test modules that ask for a file and record a sandbox submission,
/// archive, which declares neither, and the fake collector; a second pool's token for the reads'
/// refusals.
async fn asks_core() -> Core {
    let names = ["test_file_collection", "test_sandbox", "archive"];
    let mut entries: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    entries.push(FAKE_COLLECTOR.pool_entry());
    let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
    let catalog =
        ace_core::actions::ActionCatalog::new(&[&FAKE_COLLECTOR, &FAKE_PROBE]).expect("a catalog");
    let modules: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_sdk::Manifest::lookup::<asks::AsksForAFile>(),
            ace_sdk::Manifest::lookup::<asks::Sandboxes>(),
            ace_mod_archive::MANIFEST,
        ]),
        ace_core::modes::Modes::ace3(),
        &entries,
        Duration::from_secs(30),
        move |mut config| {
            config.pools.push(ace_core::api::PoolAccess::new(
                "other",
                OTHER_TOKEN,
                modules,
            ));
            config.actions(catalog)
        },
    )
    .await
}

const LOCATION: &str = "host1@C:\\Users\\bob\\evil.ps1";

fn write(name: &str, body: serde_json::Value) -> ace_sdk::writes::WireWrite {
    ace_sdk::writes::WireWrite {
        write: name.to_owned(),
        body,
    }
}

fn delay_with(writes: Vec<ace_sdk::writes::WireWrite>) -> ace_sdk::wire::TaskEnd {
    ace_sdk::wire::TaskEnd::Delay {
        after_seconds: 0.0,
        state: serde_json::Value::Null,
        scan: None,
        writes,
    }
}

fn skip_with(writes: Vec<ace_sdk::writes::WireWrite>) -> ace_sdk::wire::TaskEnd {
    ace_sdk::wire::TaskEnd::Skipped {
        reason: "asked".to_owned(),
        writes,
    }
}

/// The collections of the fake collector: id, status, result and the roots each is for.
async fn collections(core: &Core) -> Vec<(i64, String, Option<String>, Vec<uuid::Uuid>)> {
    sqlx::query_as(
        "SELECT a.id, a.status, a.result,
                array(SELECT r.root_id FROM queue.action_roots r WHERE r.action_id = a.id
                      ORDER BY r.created_at, r.root_id)
         FROM queue.actions a WHERE a.handler = 'fake_edr' ORDER BY a.id",
    )
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("reads")
}

/// A task of `module` on `value` in `root`, which it adds to the root if it isn't there.
async fn queue_on(
    core: &Core,
    root: uuid::Uuid,
    kind: ace_results::ObservableKind,
    value: &str,
    module: &str,
) {
    let mut tx = core.test_db.db().begin().await.expect("begins");
    let id = ace_core::tree::upsert_observable(
        &mut tx,
        root,
        &ace_results::NewObservable::new(kind, value),
    )
    .await
    .expect("adds")
    .id;
    ace_core::queue::enqueue(&mut tx, root, id, module)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
}

/// PLAN.md decision 49: a module's `file-collection` queues a collection of its own observable for
/// its root, with a delay as with a skip, and another root's joins it; the `file-collection` read
/// says where the root's stands; `file-collection-release` takes a root off it, cancelling it only
/// once nobody else waits, a person who asked included; and a collected file, which the root holds,
/// is added with no upload. One task is pending at a time, so each lease is the one meant.
#[tokio::test]
async fn a_module_asks_for_a_file_reads_its_collection_and_lets_go_of_it() {
    let core = asks_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let kind = ace_results::ObservableKind::FileLocation;
    let module = "test_file_collection";
    let ask = || {
        write(
            "file-collection",
            serde_json::json!({"collector": "fake_edr"}),
        )
    };
    let read = serde_json::json!({"collector": "fake_edr"});
    let release = |value: &str| {
        write(
            "file-collection-release",
            serde_json::json!({"collector": "fake_edr",
                               "observables": [{"type": "file_location", "value": value}]}),
        )
    };
    let on_location = serde_json::json!({"collector": "fake_edr",
                                         "subject": {"type": "file_location", "value": LOCATION}});

    let first = root_of(&core, kind, &[LOCATION], module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(
        client
            .read(task.id, "file-collection", &read, false)
            .await
            .expect("answers"),
        serde_json::json!({"collection": null}),
        "nothing asked yet"
    );
    client
        .end(task.id, &delay_with(vec![ask()]))
        .await
        .expect("the delay lands with its write");
    let queued = collections(&core).await;
    assert_eq!(queued.len(), 1);
    let (id, state, _, roots) = queued[0].clone();
    assert_eq!((state.as_str(), roots.as_slice()), ("NEW", &[first][..]));
    let task = lease_one(&client, module).await;
    let answer = client
        .read(task.id, "file-collection", &read, false)
        .await
        .expect("answers");
    assert_eq!(answer["collection"]["id"], id);
    assert_eq!(answer["collection"]["status"], "NEW");
    assert_eq!(answer["collection"]["file"], serde_json::Value::Null);
    // asking again on the next run is the same collection
    client
        .end(task.id, &skip_with(vec![ask()]))
        .await
        .expect("ends");
    assert_eq!(collections(&core).await.len(), 1);

    // another root's module joins it
    let second = root_of(&core, kind, &[LOCATION], module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(task.root, second);
    client
        .end(task.id, &skip_with(vec![ask()]))
        .await
        .expect("ends");
    assert_eq!(collections(&core).await[0].3, [first, second]);

    // the first lets go of it: the second still waits, so it isn't cancelled, and the first reads
    // nothing
    queue_on(&core, first, kind, "release1@C:\\x", module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(task.root, first);
    client
        .end(task.id, &skip_with(vec![release(LOCATION)]))
        .await
        .expect("ends");
    let after = collections(&core).await;
    assert_eq!(
        (after[0].1.as_str(), after[0].3.as_slice()),
        ("NEW", &[second][..])
    );
    queue_on(&core, first, kind, "read1@C:\\x", module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(
        client
            .read(task.id, "file-collection", &on_location, false)
            .await
            .expect("answers"),
        serde_json::json!({"collection": null})
    );
    client
        .end(task.id, &skip_with(Vec::new()))
        .await
        .expect("ends");

    // a person joins it through the API: when the second lets go, it isn't cancelled either
    let db = core.test_db.db();
    let catalog =
        ace_core::actions::ActionCatalog::new(&[&FAKE_COLLECTOR, &FAKE_PROBE]).expect("a catalog");
    let analyst = serde_json::json!({"kind": "user", "id": uuid::Uuid::new_v4(), "name": "alice"});
    let mut tx = db.begin().await.expect("begins");
    let (joined, _) = ace_core::actions::ask_for_collection(
        &mut tx,
        &catalog,
        &ace_core::actions::CollectionRequest {
            handler: "fake_edr",
            observable_type: "file_location",
            observable_value: LOCATION,
            roots: &[],
            requested_by: &analyst,
            user: None,
        },
    )
    .await
    .expect("joins");
    tx.commit().await.expect("commits");
    assert_eq!(joined, ace_core::actions::Requested::Joined(id));
    queue_on(&core, second, kind, "release2@C:\\x", module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(task.root, second);
    client
        .end(task.id, &skip_with(vec![release(LOCATION)]))
        .await
        .expect("ends");
    let after = collections(&core).await;
    assert_eq!(
        (after[0].1.as_str(), after[0].3.len()),
        ("NEW", 0),
        "the person still waits"
    );

    // nobody waits on a module's own collection once its root lets go: it's cancelled
    let other = "host2@C:\\x.ps1";
    let third = root_of(&core, kind, &[other], module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(task.root, third);
    client
        .end(task.id, &delay_with(vec![ask()]))
        .await
        .expect("delays");
    let task = lease_one(&client, module).await;
    client
        .end(task.id, &skip_with(vec![release(other)]))
        .await
        .expect("ends");
    let cancelled = collections(&core).await;
    assert_eq!(
        (cancelled[1].1.as_str(), cancelled[1].2.as_deref()),
        ("COMPLETED", Some("CANCELLED"))
    );

    // a collected file the root holds: the read gives it, and the result adds it with no upload
    let fourth = root_of(&core, kind, &["host3@C:\\y.ps1"], module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(task.root, fourth);
    client
        .end(task.id, &delay_with(vec![ask()]))
        .await
        .expect("delays");
    let held = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            b"collected from host3",
            Some(&ace_core::bucket::Hold::root(fourth)),
        )
        .await
        .expect("puts")
        .object;
    sqlx::query(
        "UPDATE queue.actions SET status = 'COMPLETED', result = 'SUCCESS', file_sha256 = $1,
                file_size = $2, file_name = 'y.ps1'
         WHERE handler = 'fake_edr' AND observable_value = 'host3@C:\\y.ps1'",
    )
    .bind(held.sha256.to_hex())
    .bind(i64::try_from(held.size).expect("a size"))
    .execute(db.pool())
    .await
    .expect("collects it");
    let task = lease_one(&client, module).await;
    let answer = client
        .read(task.id, "file-collection", &read, false)
        .await
        .expect("answers");
    assert_eq!(answer["collection"]["result"], "SUCCESS");
    assert_eq!(
        answer["collection"]["file"],
        serde_json::json!({"sha256": held.sha256.to_hex(), "size": held.size, "name": "y.ps1"})
    );
    let mut result = ace_results::ResultEnvelope::new(ace_sdk::example::LineStats {
        lines: 1,
        longest_line: 20,
        first_line: ace_results::Bytes::new(b"collected from host3".to_vec()),
        truncated: false,
    });
    result.files.push(ace_results::NewFile::new(
        ace_results::AlertPath::new("y.ps1").expect("a path"),
        held.sha256,
        held.size,
    ));
    client
        .end(
            task.id,
            &ace_sdk::wire::TaskEnd::Done {
                result: result.to_raw().expect("JSON"),
                writes: Vec::new(),
                probes: Default::default(),
                keep: true,
            },
        )
        .await
        .expect("the collected file lands with no upload");
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
        .bind(fourth)
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(files, 1);

    // the read's refusals: a collector the core hasn't, a subject of another type or another root
    root_of(&core, kind, &["host9@C:\\z.ps1"], module).await;
    root_of(&core, kind, &["host9@C:\\z.ps1"], "archive").await;
    let task = lease_one(&client, module).await;
    let archive_task = lease_one(&client, "archive").await;
    for refused in [
        serde_json::json!({"collector": "no_such_edr"}),
        serde_json::json!({"collector": "fake_vendor"}),
    ] {
        assert_eq!(
            status(
                &client
                    .read(task.id, "file-collection", &refused, false)
                    .await
            ),
            Some(403),
            "{refused}"
        );
    }
    assert_refusals(
        &core,
        task.id,
        "file-collection",
        read,
        on_location,
        archive_task.id,
    )
    .await;
}

/// The file collection writes are refused, failing the task with nothing written, from a module
/// that doesn't declare them (403), with a body that doesn't read (400), naming a collector the core
/// hasn't or a handler that isn't a collector (403), twice in one end (403), past the release's
/// bound or naming another type (403), and for an observable of another type than the collector's
/// (403).
#[tokio::test]
async fn the_file_collection_writes_are_refused_as_the_contract_says() {
    let core = asks_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let ask = |collector: serde_json::Value| {
        write(
            "file-collection",
            serde_json::json!({"collector": collector}),
        )
    };
    let release = |observables: serde_json::Value| {
        write(
            "file-collection-release",
            serde_json::json!({"collector": "fake_edr", "observables": observables}),
        )
    };
    let many: Vec<serde_json::Value> = (0..=ace_sdk::writes::MAX_RELEASED)
        .map(|n| serde_json::json!({"type": "file_location", "value": format!("h{n}@c:\\x")}))
        .collect();
    let refusals = [
        ("archive", vec![ask(serde_json::json!("fake_edr"))], 403),
        ("test_file_collection", vec![ask(serde_json::json!(5))], 400),
        (
            "test_file_collection",
            vec![ask(serde_json::json!("no_such_edr"))],
            403,
        ),
        (
            "test_file_collection",
            vec![ask(serde_json::json!("fake_vendor"))],
            403,
        ),
        (
            "test_file_collection",
            vec![
                ask(serde_json::json!("fake_edr")),
                ask(serde_json::json!("fake_edr")),
            ],
            403,
        ),
        (
            "test_file_collection",
            vec![release(serde_json::json!(many))],
            403,
        ),
        (
            "test_file_collection",
            vec![release(
                serde_json::json!([{"type": "fqdn", "value": "example.com"}]),
            )],
            403,
        ),
    ];
    for (module, writes, expected) in refusals {
        let root = root_of(
            &core,
            ace_results::ObservableKind::FileLocation,
            &[LOCATION],
            module,
        )
        .await;
        let task = lease_one(&client, module).await;
        let refused = client.end(task.id, &delay_with(writes)).await;
        assert!(
            matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
            "{module}: {refused:?}"
        );
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "failed", "{module}");
        assert!(error.is_some(), "{module}");
        assert!(collections(&core).await.is_empty(), "{module}");
    }
    // a collector of another type than the task's observable's
    let root = root_of(
        &core,
        ace_results::ObservableKind::Hostname,
        &["host1"],
        "test_file_collection",
    )
    .await;
    let task = lease_one(&client, "test_file_collection").await;
    let refused = client
        .end(
            task.id,
            &delay_with(vec![ask(serde_json::json!("fake_edr"))]),
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        common::task_of(&core, root, "test_file_collection").await.0,
        "failed"
    );
    assert!(collections(&core).await.is_empty());
}

/// A root whose file, `bytes`, the bucket holds for it, with a task of `module` on it.
async fn sandbox_root(core: &Core, bytes: &[u8], module: &str) -> uuid::Uuid {
    use ace_core::tree;
    let db = core.test_db.db();
    let root = tree::NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_bytes(
            ALERT_FILES,
            bytes,
            Some(&ace_core::bucket::Hold::root(root.id)),
        )
        .await
        .expect("puts the file")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let observable =
        ace_results::NewObservable::new(ace_results::ObservableKind::File, sha256.to_hex());
    let id = tree::upsert_observable(&mut tx, root.id, &observable)
        .await
        .expect("adds")
        .id;
    tree::add_file(&mut tx, root.id, id, "sample.exe", &[])
        .await
        .expect("records the file");
    ace_core::queue::enqueue(&mut tx, root.id, id, module)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    root.id
}

/// PLAN.md decision 50: `sandbox-submission` records the task's own file for a sandbox once, from
/// any root, its verdict later, and the read gives the row and how many files were sent today, a
/// file the sandbox already knew not counted; the read and the write refuse what the contract says.
/// One task of the module is pending at a time, so each lease is the one meant.
#[tokio::test]
async fn a_sandbox_submission_is_recorded_once_and_counts_only_what_was_sent() {
    let core = asks_core().await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let module = "test_sandbox";
    let (sent, known) = (
        b"a sample to send".as_slice(),
        b"a sample the sandbox knows".as_slice(),
    );
    let record = |body: serde_json::Value| write("sandbox-submission", body);
    let read = serde_json::json!({"sandbox_type": "example_sandbox"});

    sandbox_root(&core, sent, module).await;
    let task = lease_one(&client, module).await;
    assert_eq!(
        client
            .read(task.id, "sandbox-submission", &read, false)
            .await
            .expect("answers"),
        serde_json::json!({"submission": null, "submitted_today": 0})
    );
    client
        .end(
            task.id,
            &delay_with(vec![record(
                serde_json::json!({"sandbox_type": "example_sandbox", "external_id": "7001", "submitted": true}),
            )]),
        )
        .await
        .expect("the delay lands with its write");
    let task = lease_one(&client, module).await;
    client
        .end(task.id, &skip_with(Vec::new()))
        .await
        .expect("ends");
    // another root with the same file reads the row, and its verdict lands on it
    sandbox_root(&core, sent, module).await;
    let task = lease_one(&client, module).await;
    let answer = client
        .read(task.id, "sandbox-submission", &read, false)
        .await
        .expect("answers");
    assert_eq!(answer["submitted_today"], 1);
    assert_eq!(answer["submission"]["external_id"], "7001");
    assert_eq!(answer["submission"]["verdict"], serde_json::Value::Null);
    assert_eq!(answer["submission"]["submitted"], true);
    client
        .end(
            task.id,
            &skip_with(vec![record(serde_json::json!({
                "sandbox_type": "example_sandbox", "external_id": "9999", "submitted": false,
                "verdict": "malicious", "score": 87,
            }))]),
        )
        .await
        .expect("ends");
    let row: (Option<String>, bool, Option<String>, Option<i32>, bool) = sqlx::query_as(
        "SELECT external_id, submitted, verdict, score, completed_at IS NOT NULL
         FROM analysis.sandbox_submissions WHERE sha256 = $1 AND sandbox_type = 'example_sandbox'",
    )
    .bind(
        sha2::Sha256::digest(sent)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("reads");
    assert_eq!(
        row,
        (
            Some("7001".to_owned()),
            true,
            Some("malicious".to_owned()),
            Some(87),
            true
        ),
        "the first record's row, with the verdict"
    );
    // a file the sandbox already knew is recorded and not counted; another sandbox counts apart
    sandbox_root(&core, known, module).await;
    let task = lease_one(&client, module).await;
    client
        .end(
            task.id,
            &skip_with(vec![record(serde_json::json!({
                "sandbox_type": "example_sandbox", "external_id": "7002", "submitted": false,
                "verdict": "clean", "score": 0,
            }))]),
        )
        .await
        .expect("ends");
    sandbox_root(&core, known, module).await;
    let task = lease_one(&client, module).await;
    let answer = client
        .read(task.id, "sandbox-submission", &read, false)
        .await
        .expect("answers");
    assert_eq!(answer["submitted_today"], 1);
    assert_eq!(answer["submission"]["submitted"], false);
    assert_eq!(
        client
            .read(
                task.id,
                "sandbox-submission",
                &serde_json::json!({"sandbox_type": "other"}),
                false
            )
            .await
            .expect("answers")["submitted_today"],
        0
    );
    client
        .end(task.id, &skip_with(Vec::new()))
        .await
        .expect("ends");

    // the write's refusals, each failing its task with nothing written
    let rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analysis.sandbox_submissions")
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("counts")
    };
    let before = rows().await;
    let long = "x".repeat(257);
    let refusals = [
        (
            "archive",
            vec![record(
                serde_json::json!({"sandbox_type": "example_sandbox", "submitted": true}),
            )],
            403,
        ),
        (
            module,
            vec![record(
                serde_json::json!({"sandbox_type": "example_sandbox"}),
            )],
            400,
        ),
        (
            module,
            vec![record(
                serde_json::json!({"sandbox_type": "Example_Sandbox", "submitted": true}),
            )],
            403,
        ),
        (
            module,
            vec![record(
                serde_json::json!({"sandbox_type": "example_sandbox", "external_id": long, "submitted": true}),
            )],
            403,
        ),
        (
            module,
            vec![
                record(serde_json::json!({"sandbox_type": "example_sandbox", "submitted": true})),
                record(serde_json::json!({"sandbox_type": "example_sandbox", "submitted": true})),
            ],
            403,
        ),
    ];
    for (module, writes, expected) in refusals {
        let root = sandbox_root(&core, b"a sample refused", module).await;
        let task = lease_one(&client, module).await;
        let refused = client.end(task.id, &skip_with(writes)).await;
        assert!(
            matches!(&refused, Err(ace_pool::client::ClientError::Api { status, .. }) if *status == expected),
            "{module}: {refused:?}"
        );
        assert_eq!(common::task_of(&core, root, module).await.0, "failed");
        assert_eq!(rows().await, before, "{module}: nothing written");
    }
    // about anything but a file
    let root = root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["example.com"],
        module,
    )
    .await;
    let task = lease_one(&client, module).await;
    assert_eq!(
        status(
            &client
                .read(task.id, "sandbox-submission", &read, false)
                .await
        ),
        Some(403)
    );
    let refused = client
        .end(
            task.id,
            &skip_with(vec![record(
                serde_json::json!({"sandbox_type": "example_sandbox", "submitted": true}),
            )]),
        )
        .await;
    assert!(
        matches!(
            &refused,
            Err(ace_pool::client::ClientError::Api { status: 403, .. })
        ),
        "{refused:?}"
    );
    assert_eq!(common::task_of(&core, root, module).await.0, "failed");
    assert_eq!(rows().await, before);

    // the read's shared refusals, last, since they end the lease
    sandbox_root(&core, known, module).await;
    sandbox_root(&core, b"for the archive", "archive").await;
    let task = lease_one(&client, module).await;
    let archive_task = lease_one(&client, "archive").await;
    assert_refusals(
        &core,
        task.id,
        "sandbox-submission",
        read,
        serde_json::json!({"sandbox_type": "Not A Name"}),
        archive_task.id,
    )
    .await;
}
