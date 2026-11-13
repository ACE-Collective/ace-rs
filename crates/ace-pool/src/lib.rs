//! The pool runtime: the lease API's client, the modules a pool runs, and containment.
//!
//! A pool holds the lease API's URL, its pool's token and the secrets its modules declare
//! (`secrets`, PLAN.md 2.24), and nothing else: inputs and outputs go to and from the bucket
//! through presigned URLs the API hands out (2.14).
//! Containment (2.18) is what a parser's task process applies to itself before the module runs.
//! A parser pool's supervisor can also run the commands analysts start from the GUI (`commands`, 5.12),
//! each in a contained process of its own. A parser pool whose image carries programs runs them at a task's
//! request in the sandbox runner (`tools`, PLAN.md 7.3). A scanner pool holds the Docker socket and runs
//! the scanner images modules' scans ask for (`scanners`, PLAN.md 7.7). A network pool also runs the
//! remediators, remediation probes and file collectors it hosts (`actions`, PLAN.md 7.9).

pub mod actions;
pub mod client;
pub mod commands;
pub mod containment;
pub mod modules;
pub mod pool;
pub mod replay;
pub mod rulesets;
pub mod run;
pub mod scanners;
pub mod secrets;
pub mod supervisor;
pub mod task_process;
pub mod telemetry;
#[cfg(feature = "test-pools")]
pub mod testing;
pub mod tools;

pub use containment::{
    Contained, ContainmentError, SandboxProfile, ToolProfile, contain, contain_pool, contain_tool,
};
