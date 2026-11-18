//! The database: the connection pool, migrations and transactions.
//!
//! Every component builds its pool with `Db::connect`, so there is one way to reach Postgres
//! and one place that sets its limits (ace3 #1023). A write goes through a `Tx`, sqlx's
//! transaction as a value: `commit` consumes it, and dropping it without a commit rolls back,
//! so a failed transaction can't leave a connection stuck for the next caller (ace3 #852).
//! Reads that need no transaction go to `Db::pool`. A transaction holds one connection for
//! its whole unit of work, and nothing inside it takes a second (ace3 #1040).
//!
//! `Db::transaction` runs a closure in a transaction and commits it. When Postgres aborts the
//! transaction with a serialization failure or a deadlock, it rolls the whole transaction back
//! and runs the closure again from the start, so a retry never reruns part of one (ace3 #1084).
//! What must happen only if the transaction commits, such as a log record of what it did, is handed
//! to `Tx::after_commit`: it runs after the commit and never for an attempt that was rolled back.
//!
//! Queries are checked against the migrated schema when they compile. With no database set,
//! the checks read the offline data committed in the workspace's `.sqlx/`; `cargo sqlx prepare
//! --workspace` rewrites it from the dev database after a query or a migration changes.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgConnection, PgPool, Postgres};

/// The migrations in `crates/ace-core/migrations`, built into the binary.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The version of the newest migration built into the binary: what a migrated database is at.
pub fn latest_migration() -> i64 {
    MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .max()
        .unwrap_or_default()
}

/// The core's areas, one Postgres schema each.
pub const AREAS: &[&str] = &[
    "analysis",
    "lists",
    "queue",
    "scheduler",
    "service",
    "store",
    "yara",
];

/// The variable that holds the database URL, such as
/// `postgres://ace4:password@postgres:5432/ace4`.
pub const URL_VAR: &str = "ACE4_DATABASE_URL";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("{URL_VAR} isn't set")]
    NoUrl,
    #[error("invalid database URL in {URL_VAR}: {0}")]
    InvalidUrl(#[source] sqlx::Error),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] MigrateError),
    /// A row the code can't read, such as an observable type it doesn't know.
    #[error("unreadable row: {0}")]
    Decode(String),
}

/// SQLSTATE `serialization_failure`.
pub const SERIALIZATION_FAILURE: &str = "40001";
/// SQLSTATE `deadlock_detected`.
pub const DEADLOCK_DETECTED: &str = "40P01";

/// An error that may mean Postgres aborted the transaction so that it can be run again.
pub trait Retryable {
    /// True for a serialization failure or a deadlock: the transaction rolled back, and running
    /// all of it again may succeed.
    fn is_retryable(&self) -> bool;
}

impl Retryable for sqlx::Error {
    fn is_retryable(&self) -> bool {
        self.as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|code| code == SERIALIZATION_FAILURE || code == DEADLOCK_DETECTED)
    }
}

impl Retryable for DbError {
    fn is_retryable(&self) -> bool {
        match self {
            DbError::Sqlx(e) => e.is_retryable(),
            _ => false,
        }
    }
}

/// A transaction's isolation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Postgres's default: each statement sees what committed before it began.
    ReadCommitted,
    /// One snapshot for the whole transaction; a write to a row another transaction changed
    /// since fails with a serialization failure.
    RepeatableRead,
    Serializable,
}

impl Isolation {
    /// The `BEGIN` that opens a transaction at this level. The level is in the `BEGIN` itself, so
    /// a transaction costs no round trip for it: a `SET TRANSACTION` of its own was 270,165
    /// statements in a run of 43,074 tasks (`docs/measurements/lease.md`). READ COMMITTED is named
    /// too, though it is Postgres's default, so a server or role whose
    /// `default_transaction_isolation` differs doesn't change what the code was written for.
    fn begin_statement(self) -> &'static str {
        match self {
            Isolation::ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
            Isolation::RepeatableRead => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            Isolation::Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
        }
    }
}

/// The future a transaction closure returns: it borrows the transaction for as long as it runs.
pub type TxFuture<'t, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 't>>;

/// How many times `Db::transaction` runs a closure that keeps failing to serialize.
pub const TRANSACTION_ATTEMPTS: u32 = 5;

/// How a component connects.
#[derive(Debug, Clone)]
pub struct DbConfig {
    options: PgConnectOptions,
    /// The component's name, which Postgres shows as the connections' `application_name`.
    pub component: String,
    pub max_connections: u32,
    /// How long a caller waits for a free connection before it gets an error.
    pub acquire_timeout: Duration,
    /// How long one statement may run before Postgres cancels it.
    pub statement_timeout: Duration,
    /// Settings each connection opens with, beside the statement timeout: a test's `role`.
    session: Vec<(String, String)>,
}

impl DbConfig {
    /// A config for `url`, such as `postgres://ace4:password@postgres:5432/ace4`, with the
    /// default limits.
    pub fn parse(url: &str, component: impl Into<String>) -> Result<Self, DbError> {
        Ok(DbConfig {
            options: url.parse().map_err(DbError::InvalidUrl)?,
            component: component.into(),
            max_connections: 10,
            acquire_timeout: Duration::from_secs(10),
            statement_timeout: Duration::from_secs(60),
            session: Vec::new(),
        })
    }

    /// The URL from `ACE4_DATABASE_URL`, with the default limits.
    pub fn from_env(component: impl Into<String>) -> Result<Self, DbError> {
        let url = std::env::var(URL_VAR).map_err(|_| DbError::NoUrl)?;
        DbConfig::parse(&url, component)
    }

    pub fn max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// The same server and credentials, another database.
    pub fn database(mut self, name: &str) -> Self {
        self.options = self.options.database(name);
        self
    }

    /// Every connection opens as `role` (`SET ROLE`), so what it may do is what that role may: for a
    /// test of a role's grants, which needs no login made for it. A process that must not hold more
    /// than a role connects as a login that is a member of it, since a session can set its role back.
    #[cfg(feature = "testing")]
    pub fn role(mut self, role: &str) -> Self {
        self.session.push(("role".to_owned(), role.to_owned()));
        self
    }

    /// The database the config connects to.
    pub fn database_name(&self) -> Option<&str> {
        self.options.get_database()
    }

    /// The options each connection opens with.
    pub fn connect_options(&self) -> PgConnectOptions {
        let statement_timeout = self.statement_timeout.as_millis().to_string();
        let mut settings = vec![("statement_timeout", statement_timeout.as_str())];
        settings.extend(
            self.session
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        self.options
            .clone()
            .application_name(&self.component)
            .options(settings)
    }
}

/// A component's connection pool.
#[derive(Debug, Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Builds the pool and opens its first connection, so a bad URL or an unreachable server
    /// fails here rather than at the first query.
    pub async fn connect(config: &DbConfig) -> Result<Db, DbError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(config.connect_options())
            .await?;
        Ok(Db { pool })
    }

    /// Applies the migrations that haven't run. Each runs in its own transaction, so one that
    /// fails leaves no part of itself behind.
    pub async fn migrate(&self) -> Result<(), DbError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// The pool, for reads that need no transaction.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Starts a transaction.
    pub async fn begin(&self) -> Result<Tx<'static>, DbError> {
        Ok(Tx {
            inner: self.pool.begin().await?,
            committed: Vec::new(),
            outer: None,
        })
    }

    /// Runs `body` in a transaction at `isolation` and commits it. If a statement or the commit
    /// fails with a serialization failure or a deadlock, the transaction is rolled back and
    /// `body` runs again from its first statement, up to `TRANSACTION_ATTEMPTS` times in all;
    /// any other error is returned at once. `body` must have no effects outside the
    /// transaction that can't happen twice.
    ///
    /// ```text
    /// db.transaction(Isolation::ReadCommitted, |tx| Box::pin(async move {
    ///     queue::enqueue(tx, root, observable, "rdap_analyzer").await
    /// }))
    /// ```
    pub async fn transaction<'a, T, E, F>(&self, isolation: Isolation, mut body: F) -> Result<T, E>
    where
        // `&'t mut Tx<'a>` implies 'a outlives 't, which lets the closure's future borrow
        // whatever the caller lends it for 'a, such as `&self`
        F: for<'t> FnMut(&'t mut Tx<'a>) -> TxFuture<'t, T, E>,
        E: From<DbError> + Retryable + std::fmt::Display,
    {
        let mut attempt = 1;
        loop {
            let mut tx: Tx<'a> = Tx {
                inner: self
                    .pool
                    .begin_with(isolation.begin_statement())
                    .await
                    .map_err(DbError::from)?,
                committed: Vec::new(),
                outer: None,
            };
            let error = match body(&mut tx).await {
                Ok(value) => match tx.commit().await {
                    Ok(()) => return Ok(value),
                    Err(e) => E::from(e),
                },
                Err(e) => {
                    if let Err(rollback) = tx.rollback().await {
                        tracing::warn!("rolling back a failed transaction failed: {rollback}");
                    }
                    e
                }
            };
            if !error.is_retryable() || attempt >= TRANSACTION_ATTEMPTS {
                return Err(error);
            }
            tracing::info!(
                attempt,
                "the transaction failed to serialize; running it again: {error}"
            );
            // a short, growing pause, so the transactions that collided don't collide again
            tokio::time::sleep(Duration::from_millis(5 << attempt)).await;
            attempt += 1;
        }
    }

    /// The areas whose schemas exist, in name order.
    pub async fn areas(&self) -> Result<Vec<String>, DbError> {
        let names = sqlx::query_scalar!(
            r#"SELECT nspname AS "name!" FROM pg_catalog.pg_namespace
               WHERE nspname = ANY($1) ORDER BY nspname"#,
            AREAS as &[&str],
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(names)
    }

    /// Closes every connection, waiting for the ones in use to come back.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// A transaction. `commit` consumes it; dropping it without a commit rolls back.
///
/// Functions that write take `&mut Tx`, so a write can only happen inside a transaction that
/// the caller ends.
pub struct Tx<'c> {
    inner: sqlx::Transaction<'c, Postgres>,
    /// What `after_commit` was given, in order.
    committed: Vec<AfterCommit>,
    /// A savepoint's enclosing transaction's list, which takes the savepoint's when it commits.
    outer: Option<&'c mut Vec<AfterCommit>>,
}

/// What a transaction does once it has committed.
type AfterCommit = Box<dyn FnOnce() + Send>;

impl std::fmt::Debug for Tx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx")
            .field("inner", &self.inner)
            .field("after_commit", &self.committed.len())
            .finish()
    }
}

impl Tx<'_> {
    /// Commits, then runs what `after_commit` was given, in the order it was given. A savepoint's
    /// commit hands its list to the transaction it is in, which runs it when that commits.
    pub async fn commit(self) -> Result<(), DbError> {
        let Tx {
            inner,
            committed,
            outer,
        } = self;
        inner.commit().await?;
        match outer {
            Some(outer) => outer.extend(committed),
            None => committed.into_iter().for_each(|run| run()),
        }
        Ok(())
    }

    pub async fn rollback(self) -> Result<(), DbError> {
        Ok(self.inner.rollback().await?)
    }

    /// Runs `then` once this transaction has committed, and never if it rolls back, is dropped or
    /// fails to commit: for an effect outside the database that must match what was committed, such
    /// as the log record of a pass's end (`crate::metrics`). `Db::transaction` runs its closure
    /// again after a serialization failure, and what a failed attempt gave is dropped with it.
    /// `then` must not block: it runs on the committing task.
    pub fn after_commit(&mut self, then: impl FnOnce() + Send + 'static) {
        self.committed.push(Box::new(then));
    }

    /// The transaction's connection, to run a statement on.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.inner
    }

    /// A savepoint in this transaction: committing it keeps what it did, and dropping it or rolling it
    /// back undoes only that, so one step that fails needn't fail the whole transaction.
    pub async fn savepoint(&mut self) -> Result<Tx<'_>, DbError> {
        use sqlx::Acquire;
        Ok(Tx {
            inner: (&mut *self.inner).begin().await?,
            committed: Vec::new(),
            outer: Some(&mut self.committed),
        })
    }
}
