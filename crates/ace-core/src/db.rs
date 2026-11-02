//! The database: the connection pool, migrations and transactions.
//!
//! Every component builds its pool with `Db::connect`, so there is one way to reach Postgres
//! and one place that sets its limits (ace3 #1023). A write goes through a `Tx`, sqlx's
//! transaction as a value: `commit` consumes it, and dropping it without a commit rolls back,
//! so a failed transaction can't leave a connection stuck for the next caller (ace3 #852).
//! Reads that need no transaction go to `Db::pool`.
//!
//! Queries are checked against the migrated schema when they compile. With no database set,
//! the checks read the offline data committed in the workspace's `.sqlx/`; `cargo sqlx prepare
//! --workspace` rewrites it from the dev database after a query or a migration changes.

use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgConnection, PgPool, Postgres};

/// The migrations in `crates/ace-core/migrations`, built into the binary.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The core's areas, one Postgres schema each.
pub const AREAS: &[&str] = &["analysis", "queue", "store"];

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
}

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

    /// The database the config connects to.
    pub fn database_name(&self) -> Option<&str> {
        self.options.get_database()
    }

    /// The options each connection opens with.
    pub fn connect_options(&self) -> PgConnectOptions {
        let statement_timeout = self.statement_timeout.as_millis().to_string();
        self.options
            .clone()
            .application_name(&self.component)
            .options([("statement_timeout", statement_timeout.as_str())])
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
        })
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
#[derive(Debug)]
pub struct Tx<'c> {
    inner: sqlx::Transaction<'c, Postgres>,
}

impl Tx<'_> {
    pub async fn commit(self) -> Result<(), DbError> {
        Ok(self.inner.commit().await?)
    }

    pub async fn rollback(self) -> Result<(), DbError> {
        Ok(self.inner.rollback().await?)
    }

    /// The transaction's connection, to run a statement on.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.inner
    }
}
