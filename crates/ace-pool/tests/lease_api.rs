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
        "nrd_analyzer",
        "archive",
    ];
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_snort::MANIFEST,
            ace_mod_brocess::frequency::MANIFEST,
            ace_mod_nrd::MANIFEST,
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

/// The email module's result for the email at `path`, as ace4 parses it.
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
        let mut ace4 = answer["conversation"].clone();
        if let Some(participants) = ace4.get_mut("participants") {
            *participants = as_ace3_keeps_them(participants);
        }
        assert_eq!(&ace4, ace3, "{name}");
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

// ---- the email archive: archived-email, decrypted-archive, archived-url-count and email-archive
// (PLAN.md 7.5 batch 9) ----

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

const ARCHIVE_MODULES: [&str; 5] = [
    "encrypted_archive_analyzer",
    "url_email_pivot_analyzer",
    "message_id_analyzer_v2",
    "email_archiver",
    "archive",
];

/// A core whose pools run the archive's modules and archive, with the archive's key, or none.
async fn archive_core(key: bool) -> Core {
    let mut archive = ace_core::email_archive::ArchiveConfig::default();
    if key {
        archive = archive.with_key(archive_key());
    }
    Core::start_configured(
        ace_core::eligibility::Catalog::new([
            ace_mod_emailarchive::encrypted::MANIFEST,
            ace_mod_emailarchive::pivot::MANIFEST,
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

/// The archive ace3's Message-ID and URL dumps read: fixtures/email_archive/store.json, each email
/// archived at its insert_date, and missing-object's object gone from the bucket's index.
async fn seed_archive_store(core: &Core) {
    let store: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(archive_fixture("store.json")).expect("reads"),
    )
    .expect("JSON");
    let archive = email_archive(core);
    for email in store["emails"].as_array().expect("emails") {
        let bytes =
            std::fs::read(archive_fixture(email["file"].as_str().expect("a file"))).expect("reads");
        let recipients: Vec<&str> = email["recipients"]
            .as_array()
            .expect("recipients")
            .iter()
            .map(|r| r.as_str().expect("a recipient"))
            .collect();
        let urls: Vec<&str> = email["urls"]
            .as_array()
            .expect("urls")
            .iter()
            .map(|u| u.as_str().expect("a url"))
            .collect();
        let insert_date = chrono::NaiveDateTime::parse_from_str(
            email["insert_date"].as_str().expect("a date"),
            "%Y-%m-%d %H:%M:%S",
        )
        .expect("a date");
        let (_, object) = archive
            .seed(&ace_core::email_archive::Seed {
                email: &bytes,
                message_id: email["message_id"].as_str().expect("an id"),
                recipients: &recipients,
                insert_date,
                urls: &urls,
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
/// of two archives, the plaintext in the root's files held by the root, an error for an object gone, and
/// nothing for one never archived; and it answers only the task's own Message-ID.
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
            None if value.contains("missing-object") => {
                assert_eq!(answer["email"], serde_json::Value::Null);
                assert!(
                    answer["error"]
                        .as_str()
                        .expect("an error")
                        .contains("isn't in the bucket")
                );
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

/// `archived-url-count` counts what ace3's archive counted for each URL its dumps asked about, only
/// for the task's own URL.
#[tokio::test]
async fn archived_url_count_counts_as_ace3_did_and_refuses_the_rest() {
    let core = archive_core(true).await;
    seed_archive_store(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let kind = ace_results::ObservableKind::Url;
    let dumps =
        ace_testkit::reference::Dump::all("url_email_pivot_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 4);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value");
        root_of(&core, kind, &[value], "url_email_pivot_analyzer").await;
        let task = lease_one(&client, "url_email_pivot_analyzer").await;
        let answer = client
            .read(task.id, "archived-url-count", &serde_json::json!({}), false)
            .await
            .expect("answers");
        let ace3 = dump.value["email_archive_reads"][0]["count"].clone();
        assert_eq!(answer, serde_json::json!({"count": ace3}), "{value}");
    }
    root_of(
        &core,
        kind,
        &["http://example.com/a", "http://example.com/shared"],
        "url_email_pivot_analyzer",
    )
    .await;
    let task = lease_one(&client, "url_email_pivot_analyzer").await;
    let sibling =
        serde_json::json!({"subject": {"type": "url", "value": "http://example.com/shared"}});
    assert_eq!(
        status(
            &client
                .read(task.id, "archived-url-count", &sibling, false)
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
        "archived-url-count",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "url", "value": "http://elsewhere.example/"}}),
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

/// `decrypted-archive` opens each sealed fixture ace3 opened to the same email, v0 and v1, and answers
/// an error for the others, as ace3 logged them; a file not named .gz.e, another root's file and a core
/// with no key are refused or answered so.
#[tokio::test]
async fn decrypted_archive_opens_what_ace3_opened_and_refuses_the_rest() {
    let core = archive_core(true).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "w1").expect("a client");
    let dumps =
        ace_testkit::reference::Dump::all("encrypted_archive_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 7);
    for dump in dumps {
        let name = dump.short_name().to_owned();
        file_root(
            &core,
            &archive_fixture(&name),
            &name,
            "encrypted_archive_analyzer",
        )
        .await;
        let task = lease_one(&client, "encrypted_archive_analyzer").await;
        let answer = client
            .read(task.id, "decrypted-archive", &serde_json::json!({}), false)
            .await;
        if !name.ends_with(".gz.e") {
            assert_eq!(status(&answer), Some(403), "{name}");
            continue;
        }
        let answer = answer.expect("answers");
        match dump.analysis("EncryptedArchiveAnalysis") {
            Some(ace3) => {
                let file = &ace3["observables"][0];
                assert_eq!(answer["email"]["sha256"], file["value"], "{name}");
                assert_eq!(answer["email"]["size"], file["size"], "{name}");
            }
            None => {
                assert_eq!(answer["email"], serde_json::Value::Null, "{name}");
                assert!(answer["error"].is_string(), "{name}: {answer}");
            }
        }
    }
    let root = file_root(
        &core,
        &archive_fixture("sealed_v1.gz.e"),
        "sealed_v1.gz.e",
        "encrypted_archive_analyzer",
    )
    .await;
    let task = lease_one(&client, "encrypted_archive_analyzer").await;
    assert_eq!(task.root, root);
    root_of(
        &core,
        ace_results::ObservableKind::Fqdn,
        &["x.example.com"],
        "archive",
    )
    .await;
    let archive_task = lease_one(&client, "archive").await;
    let foreign = Sha256(sha2::Sha256::digest(b"another root's file").into()).to_hex();
    assert_refusals(
        &core,
        task.id,
        "decrypted-archive",
        serde_json::json!({}),
        serde_json::json!({"subject": {"type": "file", "value": foreign}}),
        archive_task.id,
    )
    .await;

    // a core with no key opens nothing, and says why
    let keyless = archive_core(false).await;
    let client =
        ace_pool::client::LeaseClient::new(&keyless.url, common::TOKEN, "w1").expect("a client");
    file_root(
        &keyless,
        &archive_fixture("sealed_v0.gz.e"),
        "sealed_v0.gz.e",
        "encrypted_archive_analyzer",
    )
    .await;
    let task = lease_one(&client, "encrypted_archive_analyzer").await;
    let answer = client
        .read(task.id, "decrypted-archive", &serde_json::json!({}), false)
        .await
        .expect("answers");
    assert_eq!(answer["email"], serde_json::Value::Null);
    assert!(
        answer["error"]
            .as_str()
            .expect("why")
            .contains("no encryption key"),
        "{answer}"
    );
}

/// The opener and the Message-ID module run as the lookups pool runs them: each adds the email the
/// core put in the root, with no upload, and its result lands; a result that adds a file no read put
/// there, or from a module that declares no such read, is refused as a missing upload is (400).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_archive_readers_add_the_email_the_core_opened() {
    let core = archive_core(true).await;
    seed_archive_store(&core).await;
    let client =
        ace_pool::client::LeaseClient::new(&core.url, common::TOKEN, "pool").expect("a client");
    let modules = std::sync::Arc::new(
        ace_pool::modules::Modules::new()
            .with_lookup(
                ace_pool::modules::Entry::<ace_mod_emailarchive::EncryptedArchiveAnalyzer>::lookup(
                    None,
                    &ace_sdk::Secrets::new(),
                )
                .expect("the module"),
            )
            .with_lookup(
                ace_pool::modules::Entry::<ace_mod_emailarchive::MessageIdAnalyzer>::lookup(
                    None,
                    &ace_sdk::Secrets::new(),
                )
                .expect("the module"),
            ),
    );
    let opened = file_root(
        &core,
        &archive_fixture("sealed_v0.gz.e"),
        "sealed_v0.gz.e",
        "encrypted_archive_analyzer",
    )
    .await;
    let pulled = root_of(
        &core,
        ace_results::ObservableKind::MessageId,
        &["<archived-2@example.com>"],
        "message_id_analyzer_v2",
    )
    .await;
    for _ in 0..2 {
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
    for (root, module, sha256, path) in [
        (
            opened,
            "encrypted_archive_analyzer",
            plain("archived_1.email.rfc822"),
            "sealed_v0.rfc822".to_owned(),
        ),
        (
            pulled,
            "message_id_analyzer_v2",
            plain("archived_2_resent.email.rfc822"),
            ace_mod_emailarchive::message_id::file_name("<archived-2@example.com>"),
        ),
    ] {
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
        ace_results::ObservableKind::Url,
        &["http://example.com/a"],
        "url_email_pivot_analyzer",
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
    let task = lease_one(&client, "url_email_pivot_analyzer").await;
    assert_eq!(task.root, root);
    let mut result = ace_results::ResultEnvelope::new(
        ace_results::types::email_archive::UrlEmailPivotAnalysis::default(),
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
    let (state, _) = common::task_of(&core, root, "url_email_pivot_analyzer").await;
    assert_eq!(state, "running");
    let results: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("counts");
    assert_eq!(results, 0);
}

/// Adds the URLs ace3's root held to the root as a URL extraction result on the email would, below it.
async fn urls_below(core: &Core, root: uuid::Uuid, email: &str, urls: &[String]) {
    use ace_core::tree;
    let db = core.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let email_id: i64 = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'file' AND value = $2",
    )
    .bind(root)
    .bind(email)
    .fetch_one(tx.conn())
    .await
    .expect("the email");
    let email_id = ace_core::tree::ObservableId(email_id);
    let result = ace_results::ResultEnvelope::new(
        ace_results::types::url_extraction::UrlExtractionAnalysis::default(),
    )
    .to_raw()
    .expect("JSON");
    let added = tree::insert_result(&mut tx, root, email_id, "url_extraction", &result)
        .await
        .expect("a result");
    for url in urls {
        let id = tree::upsert_observable(
            &mut tx,
            root,
            &ace_results::NewObservable::new(ace_results::ObservableKind::Url, url.clone()),
        )
        .await
        .expect("adds")
        .id;
        tree::add_result_addition(&mut tx, root, added, id, None)
            .await
            .expect("below the email");
    }
    tx.commit().await.expect("commits");
}

/// The archive's rows for one email as ace3's dumps write them: its hash, each index row and each
/// recipient, upper-case hex.
async fn archive_rows(core: &Core, archive_id: i64) -> serde_json::Value {
    let pool = core.test_db.db().pool();
    let hash: Vec<u8> =
        sqlx::query_scalar("SELECT hash FROM email_archive.archive WHERE archive_id = $1")
            .bind(archive_id)
            .fetch_one(pool)
            .await
            .expect("the row");
    let index: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT field, hash FROM email_archive.archive_index WHERE archive_id = $1")
            .bind(archive_id)
            .fetch_all(pool)
            .await
            .expect("its index");
    let history: Vec<(String, String)> = sqlx::query_as(
        "SELECT message_id, recipient FROM email_archive.email_history h
         JOIN email_archive.archive a ON a.insert_date = h.insert_date
         WHERE a.archive_id = $1 AND h.message_id_hash IN (
             SELECT hash FROM email_archive.archive_index WHERE archive_id = $1 AND field = 'message_id')
         ORDER BY h.id",
    )
    .bind(archive_id)
    .fetch_all(pool)
    .await
    .expect("its recipients");
    let upper = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let mut index: Vec<serde_json::Value> = index
        .into_iter()
        .map(|(field, hash)| serde_json::json!({"field": field, "hash": upper(&hash)}))
        .collect();
    index.sort_by_key(|i| i.to_string());
    serde_json::json!({
        "hash": upper(&hash),
        "index": index,
        "history": history.into_iter().map(|(m, r)| serde_json::json!([m, r])).collect::<Vec<_>>(),
    })
}

/// The same rows from ace3's dump.
fn ace3_archive_rows(dump: &ace_testkit::reference::Dump) -> serde_json::Value {
    let after = &dump.value["email_archive_after"];
    let mut index: Vec<serde_json::Value> = after["archive_index"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|i| serde_json::json!({"field": i["field"], "hash": i["hash"]}))
        .collect();
    index.sort_by_key(|i| i.to_string());
    serde_json::json!({
        "hash": after["archive"][0]["hash"],
        "index": index,
        "history": after["email_history"].as_array().expect("rows").iter()
            .map(|h| serde_json::json!([h["message_id"], h["recipient"]])).collect::<Vec<_>>(),
    })
}

/// The archiver run as the lookups pool runs it, on each email ace3 archived: its write lands with its
/// result, the result has the archive's id, the email is sealed in the archive's pool held by its row,
/// and once the root's analysis is done the URLs below it are indexed: the same rows as ace3's.
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
        let urls: Vec<String> = dump.value["tree_view"]["observables"]
            .as_array()
            .expect("observables")
            .iter()
            .filter(|o| o["type"] == "url")
            .map(|o| o["value"].as_str().expect("a url").to_owned())
            .collect();
        urls_below(&core, root, &email, &urls).await;
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
        let archive_id = details["archive_id"].as_i64().expect("the archive's id");
        assert_eq!(details["hash"], email.as_str());
        assert_eq!(
            archive_rows(&core, archive_id).await,
            ace3_archive_rows(&dump),
            "{}",
            dump.name
        );
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
/// declare it, with a body that doesn't read, about another Message-ID, past its bound of recipients,
/// twice in one end, or to a core with no key; and a lease lost before the end writes nothing.
#[tokio::test]
async fn the_archive_write_is_refused_unless_it_s_the_task_s_own_email() {
    let journaled = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/ace3/email/o365_journaled_multi_rcpt.email.rfc822");
    let write = |body: serde_json::Value| ace_sdk::writes::WireWrite {
        write: "email-archive".to_owned(),
        body,
    };
    let own = |message_id: &str, recipients: usize| {
        write(serde_json::json!({
            "message_id": message_id,
            "recipients": (0..recipients).map(|n| format!("r{n}@example.com")).collect::<Vec<_>>(),
        }))
    };
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
        ("archive", vec![own(&mine, 1)], 403),
        (
            "email_archiver",
            vec![write(serde_json::json!({"message_id": 5}))],
            400,
        ),
        (
            "email_archiver",
            vec![own("<someone-else@example.com>", 1)],
            403,
        ),
        ("email_archiver", vec![own(&mine, 1001)], 403),
        ("email_archiver", vec![own(&mine, 1), own(&mine, 1)], 403),
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
                writes: vec![own(&mine, 1)],
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
                writes: vec![own(&mine, 1)],
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
                writes: vec![own(&mine, 1)],
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
