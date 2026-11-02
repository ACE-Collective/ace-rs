//! What a module sees while it runs one task.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_results::{AlertPath, NewFile, ObservableKind, ObservableRef, Sha256, YaraMeta};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::files::{FileOutputError, FileStore, write_file};
use crate::module::{Module, ModuleError};

/// The observable a task analyzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observable {
    pub kind: ObservableKind,
    /// The value, as ace3 stores it. For a file it is the sha256 in hex.
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    /// Set when `kind` is `file`.
    pub file: Option<InputFile>,
    /// The observable's directives, such as `original_email` or `no_scan`.
    pub directives: Vec<String>,
    /// The observable that stands for this one when something acts on it, as ace3's
    /// `redirection`, such as the Office document a part came out of.
    pub redirection: Option<ObservableRef>,
}

impl Observable {
    pub fn new(kind: ObservableKind, value: impl Into<String>) -> Self {
        Observable {
            kind,
            value: value.into(),
            time: None,
            file: None,
            directives: Vec::new(),
            redirection: None,
        }
    }

    pub fn file(file: InputFile) -> Self {
        Observable {
            kind: ObservableKind::File,
            value: file.sha256.to_hex(),
            time: None,
            file: Some(file),
            directives: Vec::new(),
            redirection: None,
        }
    }

    pub fn with_directive(mut self, directive: impl Into<String>) -> Self {
        self.directives.push(directive.into());
        self
    }

    pub fn has_directive(&self, directive: &str) -> bool {
        self.directives.iter().any(|d| d == directive)
    }
}

impl fmt::Display for Observable {
    /// `kind:value`, or `file:<path inside the alert>` for a file, cut to 200 characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match &self.file {
            Some(file) => file.path.as_str(),
            None => &self.value,
        };
        match value.char_indices().nth(200) {
            Some((end, _)) => write!(f, "{}:{}...", self.kind, &value[..end]),
            None => write!(f, "{}:{value}", self.kind),
        }
    }
}

/// A file observable's record, and where its bytes are on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    /// The file's path inside the alert.
    pub path: AlertPath,
    pub sha256: Sha256,
    pub size: u64,
    pub yara_meta: Vec<YaraMeta>,
    /// libmagic's answer, stored when the file entered the file store.
    pub mime_type: Option<String>,
    /// A local copy of the bytes, which the pool fetched before the task started.
    pub local_path: PathBuf,
}

impl InputFile {
    /// The file's name inside the alert.
    pub fn name(&self) -> &str {
        self.path.name()
    }
}

/// A secret's value. Its `Debug` output hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<hidden>)")
    }
}

/// The secrets a pool resolved, by name.
#[derive(Debug, Clone, Default)]
pub struct Secrets(BTreeMap<String, Secret>);

impl Secrets {
    pub fn new() -> Self {
        Secrets::default()
    }

    pub fn with(mut self, name: impl Into<String>, value: Secret) -> Self {
        self.0.insert(name.into(), value);
        self
    }

    /// Only the secrets named in `declared`.
    fn only(&self, declared: &[&str]) -> Secrets {
        Secrets(
            self.0
                .iter()
                .filter(|(name, _)| declared.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        )
    }
}

/// A task that runs again after a delay, and what the module left for the next run.
#[derive(Debug, Clone, PartialEq)]
pub struct DelayedRun {
    /// The state from the module's last `Delay`.
    pub state: serde_json::Value,
    /// When the module first asked for a delay. A delay's timeout counts from here.
    pub first_delayed_at: DateTime<Utc>,
    /// How many times the module has asked for a delay.
    pub delays: u32,
}

/// What a module gets for one task: the observable, its settings, the secrets it declared, a
/// cancellation token, its deadline, and the state of a delayed run.
pub struct TaskContext<S> {
    root: Uuid,
    observable: Observable,
    settings: Arc<S>,
    secrets: Secrets,
    declared_secrets: &'static [&'static str],
    cancel: CancellationToken,
    deadline: Instant,
    now: DateTime<Utc>,
    delayed: Option<DelayedRun>,
    files: Option<Arc<dyn FileStore>>,
}

impl<S> TaskContext<S> {
    /// A context for a task of module `M`, with no secrets, the deadline from `M::RESOURCES`,
    /// and a fresh cancellation token. Only the secrets `M` declares can be added or read.
    pub fn new<M: Module<Settings = S>>(
        root: Uuid,
        observable: Observable,
        settings: Arc<S>,
    ) -> Self {
        TaskContext {
            root,
            observable,
            settings,
            secrets: Secrets::new(),
            declared_secrets: M::SECRETS,
            cancel: CancellationToken::new(),
            deadline: Instant::now() + M::RESOURCES.timeout,
            now: Utc::now(),
            delayed: None,
            files: None,
        }
    }

    /// The store the task's output files go to.
    pub fn with_file_store(mut self, store: Arc<dyn FileStore>) -> Self {
        self.files = Some(store);
        self
    }

    /// Sets the deadline `timeout` from now.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Instant::now() + timeout;
        self
    }

    /// Keeps only the secrets the module declares.
    pub fn with_secrets(mut self, secrets: &Secrets) -> Self {
        self.secrets = secrets.only(self.declared_secrets);
        self
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Sets the time the task treats as now, for a run with a fixed clock.
    pub fn with_now(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn with_delayed(mut self, delayed: DelayedRun) -> Self {
        self.delayed = Some(delayed);
        self
    }

    /// The root (alert) the observable is in.
    pub fn root(&self) -> Uuid {
        self.root
    }

    pub fn observable(&self) -> &Observable {
        &self.observable
    }

    /// The input file, or an error when the observable isn't a file.
    pub fn input_file(&self) -> Result<&InputFile, ModuleError> {
        self.observable.file.as_ref().ok_or_else(|| {
            ModuleError::other(format!("{} is not a file observable", self.observable))
        })
    }

    pub fn settings(&self) -> &S {
        &self.settings
    }

    /// A secret the module declared in `Module::SECRETS`.
    pub fn secret(&self, name: &str) -> Result<&Secret, ModuleError> {
        if !self.declared_secrets.contains(&name) {
            return Err(ModuleError::UndeclaredSecret(name.to_owned()));
        }
        self.secrets
            .0
            .get(name)
            .ok_or_else(|| ModuleError::MissingSecret(name.to_owned()))
    }

    /// True once the task is cancelled. Blocking code polls this.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// `Err(Cancelled)` once the task is cancelled, for `?` in a loop.
    pub fn check_cancelled(&self) -> Result<(), ModuleError> {
        if self.is_cancelled() {
            Err(ModuleError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Completes when the task is cancelled, for `tokio::select!` in async code.
    pub async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    /// The token itself, to hand to a library call that takes one.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// How long the task has before its deadline.
    pub fn time_left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// The time the task treats as now. Use it instead of the system clock, so a test can fix it.
    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    /// Set when the task is running again after the module asked for a delay.
    pub fn delayed(&self) -> Option<&DelayedRun> {
        self.delayed.as_ref()
    }

    /// The state the module left in its last `Delay`, read as `T`.
    pub fn delay_state<T: DeserializeOwned>(&self) -> Result<Option<T>, ModuleError> {
        self.delayed
            .as_ref()
            .map(|delayed| serde_json::from_value(delayed.state.clone()))
            .transpose()
            .map_err(|e| ModuleError::other(format!("unreadable delay state: {e}")))
    }

    /// Stores a new file at `path` inside the alert, such as
    /// `evil.zip.extracted/docs/invoice.doc`, and returns the record to add to the result. An
    /// absolute path or one with a `.` or `..` part fails before anything is stored.
    pub fn write_file(
        &self,
        path: &str,
        bytes: &[u8],
        yara_meta: &[YaraMeta],
    ) -> Result<NewFile, FileOutputError> {
        self.write_file_from(path, &mut &bytes[..], yara_meta)
    }

    /// `write_file` for bytes that come from a reader, such as an archive member.
    pub fn write_file_from(
        &self,
        path: &str,
        reader: &mut dyn Read,
        yara_meta: &[YaraMeta],
    ) -> Result<NewFile, FileOutputError> {
        let store = self.files.as_deref().ok_or(FileOutputError::NoStore)?;
        write_file(store, path, reader, yara_meta)
    }
}
