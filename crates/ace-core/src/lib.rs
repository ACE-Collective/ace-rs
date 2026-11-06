//! The core: the database schema, the task queue, eligibility, the lease API and submissions.
//!
//! The schema is SQL migrations in `migrations/`, one Postgres schema per area (`db::AREAS`).
//! Workers reach the queue through the lease API (`api`), never the database.

pub mod api;
pub mod bucket;
pub mod db;
pub mod eligibility;
pub mod modes;
pub mod normal;
pub mod orchestrator;
pub mod queue;
pub mod rulesets;
pub mod submit;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tree;
pub mod yara_qa;

pub use db::{Db, DbConfig, DbError, Isolation, Retryable, Tx};
