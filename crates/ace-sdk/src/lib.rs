//! What an analysis module is built on.
//!
//! A module implements `Module` and one of `Parser` (sync, for files) or `Lookup` (async, for
//! network lookups), and returns an `Outcome`: a result, a delay or nothing. The task context
//! gives it the observable, its settings, the secrets it declared, a cancellation token and its
//! deadline.

pub mod context;
#[cfg(any(test, feature = "example-modules"))]
pub mod example;
pub mod module;

pub use context::{DelayedRun, InputFile, Observable, Secret, Secrets, TaskContext};
pub use module::{
    BoxError, Delay, Lookup, Module, ModuleError, Outcome, Parser, Settings, run_lookup, run_parser,
};
