//! The core: the database schema, the task queue, eligibility, the lease API and what a submission
//! writes.
//!
//! The schema is SQL migrations in `migrations/`, one Postgres schema per area (`db::AREAS`).
//! Workers reach the queue through the lease API (`api`), never the database. The commands analysts run
//! from the GUI (`commands`, PLAN.md 5.12) are leased through it too, and so are the scans modules' tasks
//! wait for, which a scanner pool runs (`scans`, 7.7). A leased task carries the
//! analyst-edited lists its module reads (`lists`, PLAN.md 5.14), as they are when it's leased.
//! `scheduler` holds the tables through which `ace serve`'s replicas share out the scheduled
//! maintenance tasks (PLAN.md 6.7). `hooks` runs ace3's `observable_modifier` and
//! `configuration_defined_tagging` in the core, over the whole tree, at the end of a pass (PLAN.md 7.6).
//! `actions` holds remediations, remediation checks and file collections, which network pools lease
//! through the lease API as they lease tasks (PLAN.md 7.9). `svs` is the model of SVS, the Signature
//! Validation System, which the rest of SVS builds on (PLAN.md 7.10). `metrics` is the event a root's
//! pass logs when it ends, ace3's per-root metrics event. `limits` is ace3's automation limit, which
//! eligibility applies. `cleanup` deletes the finished roots that never became alerts in a mode that cleans
//! up (PLAN.md decision 56).

pub mod actions;
pub mod api;
pub mod bucket;
pub mod cache;
pub mod cleanup;
pub mod commands;
pub mod db;
pub mod eligibility;
pub mod email_archive;
pub mod hooks;
pub mod limits;
pub mod lists;
pub mod metrics;
pub mod modes;
pub mod monitoring;
pub mod normal;
pub mod nrd;
pub mod orchestrator;
pub mod queue;
pub mod reads;
pub mod rulesets;
pub mod scans;
pub mod scheduler;
pub mod submit;
pub mod svs;
pub mod takes;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tree;
pub mod type_step;
pub mod writes;
pub mod yara_qa;

pub use db::{Db, DbConfig, DbError, Isolation, Retryable, Tx};
