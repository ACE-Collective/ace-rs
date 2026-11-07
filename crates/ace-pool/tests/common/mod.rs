//! What the pool tests share: a core serving the lease API on a test database and the stack's
//! bucket, and roots with files in them. Needs the stack's postgres and bucket services.

#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use ace_core::api::{Api, ApiConfig, PoolAccess};
use ace_core::bucket::{ALERT_FILES, Bucket, BucketSettings, Hold};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::testing::TestDb;
use ace_core::tree::{self, NewRoot, ObservableId};
use ace_results::{NewObservable, ObservableKind, Sha256};
use ace_sdk::Manifest;
use ace_store::{BucketConfig, NodeCache, Store};
use uuid::Uuid;

/// The test pool's token.
pub const TOKEN: &str = "ace4-test-pool-token";
/// The admin token, for replays.
pub const ADMIN_TOKEN: &str = "ace4-test-admin-token";

/// A core serving the lease API on a test database.
pub struct Core {
    pub test_db: TestDb,
    pub bucket: Bucket,
    pub orchestrator: Orchestrator,
    /// The lease API's base URL.
    pub url: String,
    pub port: u16,
    server: tokio::task::JoinHandle<()>,
    _cache: tempfile::TempDir,
}

impl Drop for Core {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Core {
    /// A core whose catalog is `manifests`, with one pool, `test`, that runs `pool_modules`.
    pub async fn start(manifests: Vec<Manifest>, pool_modules: &[&str], lease: Duration) -> Core {
        Core::start_with(Catalog::new(manifests), Modes::ace3(), pool_modules, lease).await
    }

    /// `start` with a catalog and modes of the test's own.
    pub async fn start_with(
        catalog: Catalog,
        modes: Modes,
        pool_modules: &[&str],
        lease: Duration,
    ) -> Core {
        let test_db = TestDb::new().await;
        let cache = tempfile::tempdir().expect("a cache directory");
        let store = Store::new(
            &BucketConfig::from_env().expect("the ACE4_BUCKET_* variables"),
            NodeCache::new(cache.path(), 1 << 30).expect("a cache"),
        );
        let bucket = Bucket::new(test_db.db().clone(), store, BucketSettings::default());
        let orchestrator = Orchestrator::new(catalog, modes);
        let config = ApiConfig::new(vec![PoolAccess::new(
            "test",
            TOKEN,
            pool_modules.iter().map(|m| (*m).to_owned()).collect(),
        )])
        .admin_token(ADMIN_TOKEN)
        .lease(lease);
        let api = Api::new(
            test_db.db().clone(),
            bucket.clone(),
            orchestrator.clone(),
            config,
        )
        .await
        .expect("the API starts");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let port = listener.local_addr().expect("an address").port();
        let server = tokio::spawn(async move {
            if let Err(e) = ace_core::api::serve(listener, api, std::future::pending()).await {
                eprintln!("the lease API stopped: {e}");
            }
        });
        Core {
            test_db,
            bucket,
            orchestrator,
            url: format!("http://127.0.0.1:{port}"),
            port,
            server,
            _cache: cache,
        }
    }

    /// A root in `mode` with one file, the sample at `samples/<sample>`, at `alert_path`, whose
    /// analysis has started.
    pub async fn root_with_file(
        &self,
        mode: &str,
        sample: &str,
        alert_path: &str,
    ) -> (Uuid, ObservableId, Sha256) {
        let db = self.test_db.db();
        let root = NewRoot::new(mode);
        let mut tx = db.begin().await.expect("begins");
        tree::create_root(&mut tx, &root).await.expect("creates");
        tx.commit().await.expect("commits");
        let local = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples")
            .join(sample);
        let put = self
            .bucket
            .put_file(ALERT_FILES, &local, Some(&Hold::root(root.id)))
            .await
            .expect("puts the sample");
        let sha256 = put.object.sha256;
        let mut tx = db.begin().await.expect("begins");
        let observable = tree::upsert_observable(
            &mut tx,
            root.id,
            &NewObservable::new(ObservableKind::File, sha256.to_hex()),
        )
        .await
        .expect("adds")
        .id;
        tree::add_file(&mut tx, root.id, observable, alert_path, &[])
            .await
            .expect("records the file");
        self.orchestrator
            .start(&mut tx, root.id)
            .await
            .expect("starts");
        tx.commit().await.expect("commits");
        (root.id, observable, sha256)
    }

    /// The root's tasks as (module, observable value, state).
    pub async fn tasks(&self, root: Uuid) -> Vec<(String, String, String)> {
        sqlx::query_as(
            "SELECT t.module, o.value, t.state::text FROM queue.tasks t
             JOIN analysis.observables o ON o.id = t.observable_id
             WHERE t.root_id = $1 ORDER BY t.id",
        )
        .bind(root)
        .fetch_all(self.test_db.db().pool())
        .await
        .expect("lists tasks")
    }
}

/// The test pool binary, run with only the lease API's URL and the pool's token.
pub fn test_pool(core: &Core, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_test-pool"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ACE4_API_URL", &core.url)
        .env("ACE4_POOL_TOKEN", TOKEN)
        .env("ACE4_LOG", "info");
    command
}

/// A root with one fqdn per value, each with a task for `module`, committed. Returns the root.
pub async fn root_with_tasks(core: &Core, values: &[String], module: &str) -> Uuid {
    let db = core.test_db.db();
    let root = NewRoot::new("analysis");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    for value in values {
        let id = tree::upsert_observable(
            &mut tx,
            root.id,
            &NewObservable::new(ObservableKind::Fqdn, value.clone()),
        )
        .await
        .expect("adds")
        .id;
        ace_core::queue::enqueue(&mut tx, root.id, id, module)
            .await
            .expect("queues");
    }
    tx.commit().await.expect("commits");
    root.id
}

/// Waits until none of the root's tasks is queued, delayed or running.
pub async fn wait_until_idle(core: &Core, root: Uuid, within: Duration) {
    let started = std::time::Instant::now();
    loop {
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM queue.tasks
             WHERE root_id = $1 AND state IN ('queued', 'delayed', 'running')",
        )
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("counts");
        if active == 0 {
            return;
        }
        assert!(
            started.elapsed() < within,
            "{active} tasks still active after {within:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A root in `mode` with one file holding `bytes` at `alert_path`, whose analysis has started.
pub async fn root_with_bytes(
    core: &Core,
    mode: &str,
    bytes: &[u8],
    alert_path: &str,
) -> (Uuid, Sha256) {
    let db = core.test_db.db();
    let root = NewRoot::new(mode);
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tx.commit().await.expect("commits");
    let sha256 = core
        .bucket
        .put_bytes(ALERT_FILES, bytes, Some(&Hold::root(root.id)))
        .await
        .expect("puts the bytes")
        .object
        .sha256;
    let mut tx = db.begin().await.expect("begins");
    let observable = tree::upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::File, sha256.to_hex()),
    )
    .await
    .expect("adds")
    .id;
    tree::add_file(&mut tx, root.id, observable, alert_path, &[])
        .await
        .expect("records the file");
    core.orchestrator
        .start(&mut tx, root.id)
        .await
        .expect("starts");
    tx.commit().await.expect("commits");
    (root.id, sha256)
}

/// A task's state and error, by module.
pub async fn task_of(core: &Core, root: Uuid, module: &str) -> (String, Option<String>) {
    sqlx::query_as("SELECT state::text, error FROM queue.tasks WHERE root_id = $1 AND module = $2")
        .bind(root)
        .bind(module)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the task")
}

/// A running pool process, killed and reaped when dropped, whose stderr `stop` returns.
pub struct PoolProcess {
    child: Option<std::process::Child>,
    /// Reads its stderr as it comes. A pipe holds only 8 KiB once the VM's user is past
    /// pipe-user-pages-soft, and a pool that fills one stops taking tasks.
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl PoolProcess {
    pub fn start(mut command: std::process::Command) -> PoolProcess {
        let mut child = command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the pool starts");
        let stderr = child.stderr.take().map(|mut pipe| {
            std::thread::spawn(move || {
                let mut text = Vec::new();
                // what it managed to write is what's returned
                std::io::Read::read_to_end(&mut pipe, &mut text).ok();
                text
            })
        });
        PoolProcess {
            child: Some(child),
            stderr,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, std::process::Child::id)
    }

    /// True while the process runs.
    pub fn running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }

    /// Asks the process to stop with SIGTERM, waits up to `within` for it, and returns what it
    /// wrote to stderr.
    pub fn terminate(&mut self, within: Duration) -> String {
        if let Some(child) = &self.child {
            let pid = i32::try_from(child.id()).unwrap_or_default();
            // SAFETY: kill takes integers only; the pid is this child's, not yet reaped
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let started = std::time::Instant::now();
        while self.running() && started.elapsed() < within {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.stop()
    }

    /// Kills the process and returns what it wrote to stderr.
    pub fn stop(&mut self) -> String {
        let Some(mut child) = self.child.take() else {
            return String::new();
        };
        if let Err(e) = child.kill() {
            eprintln!("killing the pool: {e}");
        }
        if let Err(e) = child.wait() {
            return format!("no output: {e}");
        }
        match self.stderr.take().map(std::thread::JoinHandle::join) {
            Some(Ok(text)) => String::from_utf8_lossy(&text).into_owned(),
            _ => String::new(),
        }
    }
}

impl Drop for PoolProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Queues a task for `module` on the root's observable with this value, committed.
pub async fn enqueue(core: &Core, root: Uuid, value: &str, module: &str) {
    let db = core.test_db.db();
    let observable: i64 =
        sqlx::query_scalar("SELECT id FROM analysis.observables WHERE root_id = $1 AND value = $2")
            .bind(root)
            .bind(value)
            .fetch_one(db.pool())
            .await
            .expect("the observable");
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ObservableId(observable), module)
        .await
        .expect("queues")
        .expect("a new task");
    tx.commit().await.expect("commits");
}
