//! The core: the database schema, the task queue, eligibility, the lease API and submissions.
//!
//! The schema is SQL migrations in `migrations/`, one Postgres schema per area (`db::AREAS`).

pub mod bucket;
pub mod db;
pub mod queue;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tree;

pub use db::{Db, DbConfig, DbError, Tx};
