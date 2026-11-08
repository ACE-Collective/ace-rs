//! PLAN.md 2.14's Done check: a worker with only an API token runs a task end to end. The
//! worker is the test pool binary, started with an empty environment plus the lease API's URL
//! and its pool's token, so it holds no database URL and no bucket key.

mod common;

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
        "archive",
    ];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_snort::MANIFEST,
            ace_mod_brocess::frequency::MANIFEST,
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

const OTHER_TOKEN: &str = "ace4-test-other-pool-token";

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
}

/// The refusals every read shares, which the core makes before it reads anything: an unknown token
/// (401), another worker of the pool and another pool (409), a body that isn't the read's (400), a
/// subject from another root (403), a module that doesn't declare it (403, on `undeclared`), and,
/// last, since it ends the lease, a lease past its expiry (409).
async fn assert_refusals(
    core: &Core,
    task: i64,
    read: &'static str,
    foreign: serde_json::Value,
    undeclared: i64,
) {
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let ok = serde_json::json!({});
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
