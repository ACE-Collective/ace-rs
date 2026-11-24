//! PLAN.md 2.20's Done check: replaying 2.19's hung task reproduces the hang. The replay fetches
//! the task's input through the lease API by its hash and runs the module in its own process,
//! uncontained, so a debugger can attach.

use crate::common;

use std::time::Duration;

use ace_pool::testing;

use common::{
    ADMIN_TOKEN, Core, PoolProcess, enqueue, root_with_bytes, test_pool, wait_until_idle,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replaying_the_hung_task_reproduces_the_hang() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_spin"],
        Duration::from_secs(30),
    )
    .await;
    let (root, sha256) = root_with_bytes(&core, "event", b"spin on this", "spin.bin").await;
    enqueue(&core, root, &sha256.to_hex(), "test_spin").await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &[
            "parsers",
            "--task-user",
            "ace-rs-task",
            "--concurrency",
            "1",
        ],
    ));
    wait_until_idle(&core, root, Duration::from_secs(30)).await;
    pool.stop();
    let (id, state): (i64, String) =
        sqlx::query_as("SELECT id, state::text FROM queue.tasks WHERE root_id = $1")
            .bind(root)
            .fetch_one(core.test_db.db().pool())
            .await
            .expect("the hung task");
    assert_eq!(state, "failed");

    // the replay has the admin token and the API's URL, nothing else
    let mut replay = test_pool(&core, &["replay", &id.to_string()]);
    replay
        .env_remove("ACE_RS_POOL_TOKEN")
        .env("ACE_RS_ADMIN_TOKEN", ADMIN_TOKEN);
    let mut replay = PoolProcess::start(replay);
    let pid = replay.pid();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(replay.running(), "the replay hangs as the task did");
    // outside containment: no no_new_privs, and no seccomp filter beyond the ones every
    // process in the container has (Docker's), so a debugger can attach
    let field = |pid: &str, name: &str| {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("a status");
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .unwrap_or_default()
            .to_owned()
    };
    let pid = pid.to_string();
    assert_eq!(field(&pid, "NoNewPrivs:"), "0");
    assert_eq!(
        field(&pid, "Seccomp_filters:"),
        field("self", "Seccomp_filters:"),
        "the replay has no filter of its own"
    );
    let stderr = replay.stop();
    println!("{stderr}");
    assert!(
        stderr.contains(&format!("replaying task {id} (test_spin on file {sha256})")),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("test_spin: spinning on {sha256}")),
        "{stderr}"
    );
    // and the task's row is as it was
    let state: String = sqlx::query_scalar("SELECT state::text FROM queue.tasks WHERE id = $1")
        .bind(id)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("reads");
    assert_eq!(state, "failed");
}

/// A task whose module reads its carrying email gets it on a replay too, or a password from the body
/// wouldn't be found again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replaying_a_task_reads_the_body_of_its_carrying_email() {
    let core = Core::start(
        vec![
            ace_mod_files::file_type::MANIFEST,
            ace_mod_email::MANIFEST,
            ace_mod_msoffice::MANIFEST,
        ],
        &[
            "file_type",
            "email_analyzer",
            "msoffice_encryption_analyzer",
        ],
        Duration::from_secs(60),
    )
    .await;
    let bytes = std::fs::read(
        ace_testkit::samples_dir().join("ace-rs/email/encrypted_rc4_doc.email.rfc822"),
    )
    .expect("the sample");
    let (root, _) = root_with_bytes(&core, "email", &bytes, "email.rfc822").await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &[
            "parsers",
            "--task-user",
            "ace-rs-task",
            "--concurrency",
            "1",
        ],
    ));
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    pool.stop();
    let id: i64 = sqlx::query_scalar(
        "SELECT t.id FROM queue.tasks t
         JOIN analysis.results r ON r.root_id = t.root_id AND r.observable_id = t.observable_id
         WHERE t.root_id = $1 AND t.module = 'msoffice_encryption_analyzer'
           AND r.analysis_type = 'msoffice_encryption_analysis'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task");
    let mut replay = test_pool(&core, &["replay", &id.to_string()]);
    let output = replay
        .env_remove("ACE_RS_POOL_TOKEN")
        .env("ACE_RS_ADMIN_TOKEN", ADMIN_TOKEN)
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("\"password\":\"R4Binary1\""), "{stdout}");
}
