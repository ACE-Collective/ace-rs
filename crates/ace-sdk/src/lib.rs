//! What an analysis module is built on.
//!
//! A module implements `Module` and one of `Parser` (sync, for files) or `Lookup` (async, for
//! network lookups), and returns an `Outcome`: a result, a delay or nothing. The task context
//! gives it the observable, its settings, the secrets it declared, a cancellation token, its
//! deadline and a place to write files. Each module crate exports a `Manifest` built from its
//! module type. Lookups make HTTP calls through `http::HttpClient`. A site's `overlay::Overlay`
//! gives modules their settings and declares named instances of them. A module reads the
//! analyst-edited lists it declares, such as whitelists, through `lists` (PLAN.md 5.14), and a
//! lookup reads ACE's own data through `reads` and writes it through `writes` (PLAN.md 7.2). A parser
//! runs the programs it declares through `tools` (PLAN.md 7.3), and sends its observable through the
//! scanner images it declares through `scanners` (7.7). `actions` holds what remediators, remediation
//! probes and file collectors are built on (7.9).

pub mod actions;
pub mod context;
pub mod domains;
pub mod email_threads;
#[cfg(any(test, feature = "example-modules"))]
pub mod example;
pub mod files;
pub mod generation;
pub mod hooks;
pub mod http;
pub mod ip;
pub mod lists;
pub mod manifest;
pub mod module;
pub mod nrd;
pub mod overlay;
pub mod reads;
pub mod scanners;
pub mod tools;
pub mod tree;
pub mod wire;
pub mod writes;

pub use context::{CarryingEmail, DelayedRun, InputFile, Observable, Secret, Secrets, TaskContext};
pub use files::{FileOutputError, FileStore, LocalFileStore};
pub use lists::{List, ListSpec};
pub use manifest::{Manifest, ModuleKind, Resources, Sandbox, SettingsError, load_settings};
pub use module::{
    BoxError, Delay, EXCLUDE_ALL, Lookup, Module, ModuleError, OtherAdditionsAllowed, Outcome,
    Parser, Settings, WHITELISTED, run_lookup, run_parser,
};
pub use overlay::{
    ACE3_DISPOSITION_CLASSES, ActionSection, AlertRouterSection, Component, DispositionClass,
    DispositionSection, NrdList, NrdSection, Overlay, OverlayError, ScheduledTaskSection,
    SecretSource, SvsCatalogRepository, SvsCatalogSection, SvsObservationWindow, SvsRepository,
    SvsRunsSection, SvsSection, SvsYaraSection, is_attack_release_name,
};
