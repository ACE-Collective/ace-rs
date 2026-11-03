//! What an analysis module is built on.
//!
//! A module implements `Module` and one of `Parser` (sync, for files) or `Lookup` (async, for
//! network lookups), and returns an `Outcome`: a result, a delay or nothing. The task context
//! gives it the observable, its settings, the secrets it declared, a cancellation token, its
//! deadline and a place to write files. Each module crate exports a `Manifest` built from its
//! module type. Lookups make HTTP calls through `http::HttpClient`.

pub mod context;
#[cfg(any(test, feature = "example-modules"))]
pub mod example;
pub mod files;
pub mod http;
pub mod ip;
pub mod manifest;
pub mod module;
pub mod wire;

pub use context::{DelayedRun, InputFile, Observable, Secret, Secrets, TaskContext};
pub use files::{FileOutputError, FileStore, LocalFileStore};
pub use manifest::{Manifest, ModuleKind, Resources, Sandbox, SettingsError, load_settings};
pub use module::{
    BoxError, Delay, EXCLUDE_ALL, Lookup, Module, ModuleError, Outcome, Parser, Settings,
    run_lookup, run_parser,
};
