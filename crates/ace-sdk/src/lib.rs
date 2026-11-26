//! What an analysis module is built on.
//!
//! A module implements `Module` and one of `Parser` (sync, for files) or `Lookup` (async, for
//! network lookups), and returns an `Outcome`: a result, a delay or nothing. The task context
//! gives it the observable, its settings, the secrets it declared, a cancellation token, its
//! deadline and a place to write files. Each module crate exports a `Manifest` built from its
//! module type. Lookups make HTTP calls through `http::HttpClient`. A site's `overlay::Overlay`
//! gives modules their settings and declares named instances of them. A module reads the
//! analyst-edited lists it declares, such as the observables enabled for detection, through `lists`
//! (PLAN.md 5.14), and a
//! lookup reads ACE's own data through `reads` and writes it through `writes` (PLAN.md 7.2). A parser
//! runs the programs it declares through `tools` (PLAN.md 7.3), and sends its observable through the
//! scanner images it declares through `scanners` (7.7). `actions` holds what remediators, remediation
//! probes and file collectors are built on (7.9).
//!
//! A module states the checks it makes before it does anything, such as "the file's name ends in
//! `.dmg`", in `Module::takes`, as data over facts the core holds (`takes`, PLAN.md decision 23). The
//! core queues no task those checks decline, the pool checks them again before `analyze`, and
//! `analyze` doesn't repeat them. `takes`' docs say how to write one and how to check it with the
//! core's audit setting before relying on it.
//!
//! `directives` lists the directives an analyst may add to an observable, those of ace3's
//! `GUI_DIRECTIVES` an ace-rs module reads, to which a site adds its own (PLAN.md decision 31).
//!
//! A module whose result is worth keeping across roots, such as one that runs OCR or asks a vendor,
//! opts into the analysis cache with `Module::CACHE` (PLAN.md decision 26): `cache`'s docs say what
//! its key holds, what a cacheable module may read, and what is never kept.

pub mod actions;
pub mod alert_automation;
pub mod cache;
pub mod connections;
pub mod context;
pub mod directives;
pub mod domains;
pub mod email_threads;
#[cfg(any(test, feature = "example-modules"))]
pub mod example;
pub mod exclusions;
pub mod files;
pub mod generation;
pub mod hooks;
pub mod http;
pub mod ip;
pub mod iptools;
pub mod layer2;
pub mod lists;
pub mod manifest;
pub mod module;
pub mod nrd;
pub mod observable_rules;
pub mod overlay;
pub mod reads;
pub mod scanners;
pub mod takes;
pub mod tools;
pub mod tree;
pub mod wire;
pub mod writes;

pub use connections::{
    Binding, Connection, ConnectionKind, ConnectionSection, ConnectionSlot, ConnectionType,
    Connections,
};
pub use context::{
    CarryingEmail, DelayedRun, EmailBodyPart, InputFile, Observable, Secret, Secrets, TaskContext,
};
pub use files::{FileOutputError, FileStore, LocalFileStore};
pub use lists::{List, ListSpec};
pub use manifest::{
    DeclarationError, Manifest, ModuleKind, Resources, Sandbox, SettingsError, load_settings,
};
pub use module::{
    BoxError, Delay, EXCLUDE_ALL, Lookup, Module, ModuleError, OtherAdditionsAllowed, Outcome,
    Parser, Settings, run_lookup, run_parser,
};
pub use overlay::{
    ACE3_DISPOSITION_CLASSES, ActionSection, AlertActionSection, AlertRouterSection,
    AnalysisModeSection, CollectorSection, CommandTypeSection, Component, DispositionClass,
    DispositionSection, ExportSection, NrdList, NrdSection, Overlay, OverlayError,
    RootCleanupSection, ScheduledTaskSection, SecretSource, SvsCatalogRepository,
    SvsCatalogSection, SvsObservationWindow, SvsRepository, SvsRunsSection, SvsSection,
    SvsYaraSection, is_attack_release_name,
};
