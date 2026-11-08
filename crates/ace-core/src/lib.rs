//! The core: the database schema, the task queue, eligibility, the lease API and what a submission
//! writes.
//!
//! The schema is SQL migrations in `migrations/`, one Postgres schema per area (`db::AREAS`).
//! Workers reach the queue through the lease API (`api`), never the database. The commands analysts run
//! from the GUI (`commands`, PLAN.md 5.12) are leased through it too. A leased task carries the
//! analyst-edited lists its module reads (`lists`, PLAN.md 5.14), as they are when it's leased.
//! `scheduler` holds the tables through which `ace serve`'s replicas share out the scheduled
//! maintenance tasks (PLAN.md 6.7).

pub mod api;
pub mod bucket;
pub mod commands;
pub mod db;
pub mod eligibility;
pub mod lists;
pub mod modes;
pub mod normal;
pub mod orchestrator;
pub mod queue;
pub mod reads;
pub mod rulesets;
pub mod scheduler;
pub mod submit;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tree;
pub mod writes;
pub mod yara_qa;

pub use db::{Db, DbConfig, DbError, Isolation, Retryable, Tx};
