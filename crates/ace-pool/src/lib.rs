//! The pool runtime: the lease API's client, the modules a pool runs, and containment.
//!
//! A pool holds the lease API's URL and its pool's token, and nothing else: inputs and outputs
//! go to and from the bucket through presigned URLs the API hands out (PLAN.md 2.14).
//! Containment (2.18) is what a parser's task process applies to itself before the module runs.

pub mod client;
pub mod containment;
pub mod modules;
pub mod pool;
pub mod replay;
pub mod run;
pub mod supervisor;
pub mod task_process;
pub mod telemetry;
#[cfg(feature = "test-pools")]
pub mod testing;

pub use containment::{Contained, ContainmentError, SandboxProfile, contain, contain_pool};
