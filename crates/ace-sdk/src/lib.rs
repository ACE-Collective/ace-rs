//! What an analysis module is built on.
//!
//! A module implements `Module` and one of `Parser` (sync, for files) or `Lookup` (async, for
//! network lookups), and returns an `Outcome`: a result, a delay or nothing. The task context
//! gives it the observable, its settings, the secrets it declared, a cancellation token, its
//! deadline and a place to write files. Each module crate exports a `Manifest` built from its
//! module type. Lookups make HTTP calls through `http::HttpClient`. A site's `overlay::Overlay`
//! gives modules their settings and declares named instances of them. A module reads the
//! analyst-edited lists it declares, such as whitelists, through `lists` (PLAN.md 5.14).

pub mod context;
#[cfg(any(test, feature = "example-modules"))]
pub mod example;
pub mod files;
pub mod generation;
pub mod http;
pub mod ip;
pub mod lists;
pub mod manifest;
pub mod module;
pub mod overlay;
pub mod wire;

pub use context::{CarryingEmail, DelayedRun, InputFile, Observable, Secret, Secrets, TaskContext};
pub use files::{FileOutputError, FileStore, LocalFileStore};
pub use lists::{List, ListSpec};
pub use manifest::{Manifest, ModuleKind, Resources, Sandbox, SettingsError, load_settings};
pub use module::{
    BoxError, Delay, EXCLUDE_ALL, Lookup, Module, ModuleError, Outcome, Parser, Settings,
    WHITELISTED, run_lookup, run_parser,
};
pub use overlay::{Component, Overlay, OverlayError, ScheduledTaskSection, SecretSource};
