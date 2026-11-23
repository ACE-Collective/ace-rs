//! Test databases (PLAN.md 2.3): a template database migrated and seeded once, and a copy of
//! it for each test, so tests run in parallel without seeing each other's rows.
//!
//! ```text
//! let test_db = TestDb::new().await;          // a fresh copy of the template
//! let db: &Db = test_db.db();
//! // ... dropping test_db drops its database
//! ```
//!
//! The template is named after a hash of the migrations and the seed, so it is built again
//! only when one of them changes. The first test in a process that needs it takes a Postgres
//! advisory lock, builds it under a temporary name if it is missing, renames it, and drops
//! templates with other hashes and test databases a killed run left behind. Each test then
//! runs `CREATE DATABASE ... TEMPLATE`, which copies the template's files and runs no SQL.
//!
//! The server is the one `ACE_RS_DATABASE_URL` names. The URL's user needs `CREATEDB`.

pub mod rule_repo;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection};
use tokio::sync::OnceCell;

use crate::db::{Db, DbConfig, DbError, MIGRATOR};

/// SQL run on the template after the migrations: rows every test database starts with. It
/// holds none yet.
pub const SEED: &str = include_str!("testing/seed.sql");

const TEMPLATE_PREFIX: &str = "ace_rs_template_";
const BUILD_PREFIX: &str = "ace_rs_build_";
const TEST_PREFIX: &str = "ace_rs_test_";
/// A test database older than this was left by a run that was killed before it could drop it.
const STALE_AFTER: Duration = Duration::from_secs(3600);
/// The advisory lock that serializes template builds across test processes.
const TEMPLATE_LOCK: i64 = 0x0ace_4000_7e57;

static TEMPLATE: OnceCell<String> = OnceCell::const_new();
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A test's own database, a copy of the template. Dropping it drops the database.
pub struct TestDb {
    db: Db,
    config: DbConfig,
    name: String,
}

impl TestDb {
    /// A fresh copy of the template. Panics when Postgres can't be reached, so a test that
    /// needs a database fails rather than passing without one.
    pub async fn new() -> TestDb {
        match TestDb::try_new().await {
            Ok(test_db) => test_db,
            Err(e) => panic!(
                "no test database: {e}. Tests that use Postgres run in the dev container with \
                 the stack's postgres service up (`docker compose up -d --wait`)"
            ),
        }
    }

    pub async fn try_new() -> Result<TestDb, DbError> {
        let config = DbConfig::from_env("ace-core-test")?.max_connections(8);
        let template = TEMPLATE
            .get_or_try_init(|| build_template(&config))
            .await?
            .clone();
        let name = format!(
            "{TEST_PREFIX}{}_{}_{}",
            unix_seconds(),
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = admin(&config).await?;
        sqlx::raw_sql(database_statement(format!(
            r#"CREATE DATABASE "{name}" TEMPLATE "{template}""#
        )))
        .execute(&mut admin)
        .await?;
        admin.close().await?;
        let config = config.database(&name);
        let db = Db::connect(&config).await?;
        Ok(TestDb { db, config, name })
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// The database's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The config the test's pool was built from, to build another pool on the same database,
    /// as a second worker process would.
    pub fn config(&self) -> &DbConfig {
        &self.config
    }
}

impl Drop for TestDb {
    /// Drops the database from a thread of its own, since a destructor can't wait on the
    /// test's runtime. `WITH (FORCE)` ends the pool's connections first.
    fn drop(&mut self) {
        let config = self.config.clone();
        let name = self.name.clone();
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut admin = admin(&config).await?;
                drop_database(&mut admin, &name).await?;
                admin.close().await?;
                Ok::<_, DbError>(())
            })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .join();
        match dropped {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("couldn't drop test database {}: {e}", self.name),
            Err(_) => eprintln!(
                "couldn't drop test database {}: the thread panicked",
                self.name
            ),
        }
    }
}

/// A connection to the server's `postgres` database, for creating and dropping databases.
async fn admin(config: &DbConfig) -> Result<PgConnection, DbError> {
    let options = config.clone().database("postgres").connect_options();
    Ok(PgConnection::connect_with(&options).await?)
}

async fn drop_database(admin: &mut PgConnection, name: &str) -> Result<(), DbError> {
    sqlx::raw_sql(database_statement(format!(
        r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#
    )))
    .execute(admin)
    .await?;
    Ok(())
}

/// The template's name for the current migrations and seed.
pub fn template_name() -> String {
    let mut hasher = Sha256::new();
    for migration in MIGRATOR.iter() {
        hasher.update(migration.version.to_le_bytes());
        hasher.update(&*migration.checksum);
    }
    hasher.update(SEED.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{TEMPLATE_PREFIX}{hex}")
}

/// Builds the template if it is missing, under the advisory lock, and sweeps what earlier runs
/// left behind. Returns the template's name.
async fn build_template(config: &DbConfig) -> Result<String, DbError> {
    let template = template_name();
    let mut admin = admin(config).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(TEMPLATE_LOCK)
        .execute(&mut admin)
        .await?;
    let built = build_locked(config, &mut admin, &template).await;
    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(TEMPLATE_LOCK)
        .execute(&mut admin)
        .await;
    built?;
    unlocked?;
    admin.close().await?;
    Ok(template)
}

async fn build_locked(
    config: &DbConfig,
    admin: &mut PgConnection,
    template: &str,
) -> Result<(), DbError> {
    let databases: Vec<String> = sqlx::query_scalar(
        "SELECT datname::text FROM pg_database WHERE datname LIKE 'ace\\_rs\\_%'",
    )
    .fetch_all(&mut *admin)
    .await?;
    let stale_before = unix_seconds().saturating_sub(STALE_AFTER.as_secs());
    for name in &databases {
        let stale = if name.starts_with(TEMPLATE_PREFIX) {
            name != template
        } else if name.starts_with(BUILD_PREFIX) {
            true
        } else if let Some(rest) = name.strip_prefix(TEST_PREFIX) {
            rest.split('_')
                .next()
                .and_then(|seconds| seconds.parse::<u64>().ok())
                .is_some_and(|created| created < stale_before)
        } else {
            false
        };
        if stale {
            if name.starts_with(TEMPLATE_PREFIX) {
                sqlx::raw_sql(database_statement(format!(
                    r#"ALTER DATABASE "{name}" WITH IS_TEMPLATE false"#
                )))
                .execute(&mut *admin)
                .await?;
            }
            drop_database(admin, name).await?;
        }
    }
    if databases.iter().any(|name| name == template) {
        return Ok(());
    }

    // Build under another name and rename when it's done, so a build that dies halfway never
    // leaves a template that looks finished.
    let building = format!("{BUILD_PREFIX}{}", std::process::id());
    sqlx::raw_sql(database_statement(format!(
        r#"CREATE DATABASE "{building}""#
    )))
    .execute(&mut *admin)
    .await?;
    let db = Db::connect(&config.clone().database(&building).max_connections(1)).await?;
    db.migrate().await?;
    let mut tx = db.begin().await?;
    sqlx::raw_sql(SEED).execute(tx.conn()).await?;
    tx.commit().await?;
    db.close().await;
    sqlx::raw_sql(database_statement(format!(
        r#"ALTER DATABASE "{building}" RENAME TO "{template}""#
    )))
    .execute(&mut *admin)
    .await?;
    sqlx::raw_sql(database_statement(format!(
        r#"ALTER DATABASE "{template}" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false"#
    )))
    .execute(&mut *admin)
    .await?;
    Ok(())
}

/// A statement about databases whose names this module made, from fixed prefixes, numbers and
/// hex, so they need no quoting beyond the double quotes the statements put around them.
fn database_statement(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// ace3's `tests/saq/svs/conftest.py` `ATTACK_EXTRACT`: a small ATT&CK release, v99.0, that SVS's tests
/// read in place of a real one (PLAN.md 7.10).
pub fn attack_extract() -> serde_json::Value {
    use serde_json::json;
    let technique = |name: &str,
                     parent: Option<&str>,
                     tactics: &[&str],
                     platforms: &[&str],
                     deprecated: bool| {
        json!({"name": name, "parent": parent, "tactics": tactics, "platforms": platforms,
               "deprecated": deprecated})
    };
    json!({
        "format": 1,
        "release": "v99.0",
        "domain": "enterprise-attack",
        "source": {"url": "test", "sha256": "0".repeat(64)},
        "platforms": [{"slug": "windows", "name": "Windows"}, {"slug": "macos", "name": "macOS"}],
        "tactics": [
            {"id": "TA0003", "shortname": "persistence", "name": "Persistence"},
            {"id": "TA0002", "shortname": "execution", "name": "Execution"},
        ],
        "techniques": {
            "T1059": technique("Command and Scripting Interpreter", None, &["TA0002"],
                               &["windows", "macos"], false),
            "T1059.001": technique("PowerShell", Some("T1059"), &["TA0002"], &["windows"], false),
            "T1059.002": technique("AppleScript", Some("T1059"), &["TA0002"], &["macos"], false),
            "T1547": technique("Boot or Logon Autostart Execution", None, &["TA0003", "TA0002"],
                               &["windows"], false),
            "T1099": technique("Old Technique", None, &[], &["windows"], true),
        },
        "revoked": {"T1086": "T1059.001", "T1150": "T1099"},
        "renamed": {"T1059": {"from": "Scripting", "previous_release": "v98.0"}},
    })
}

/// The catalog of [`attack_extract`]: ace3's `attack_catalog` fixture.
pub fn attack_catalog() -> crate::svs::attack::AttackCatalog {
    crate::svs::attack::AttackCatalog::load(&attack_extract().to_string(), "v99.0.json")
        .expect("the test extract loads")
}
