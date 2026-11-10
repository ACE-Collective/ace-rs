//! What a module sees while it runs one task.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ace_results::{
    AlertPath, AnalysisType, NewFile, ObservableKind, ObservableRef, Relationship,
    RelationshipKind, Sha256, YaraMeta,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::files::{FileOutputError, FileStore, write_file};
use crate::lists::{List, ListSpec, WireList};
use crate::module::{Module, ModuleError};
use crate::reads::{Read as DeclaredRead, ReadError, ReadKind, Reader};
use crate::tools::{TIMEOUT_MARGIN, ToolError, ToolOutput, ToolRun, ToolRunner};
use crate::tree::TreeView;
use crate::wire::RelatedTags;
use crate::writes::{WireWrite, Write as DeclaredWrite, WriteKind};

/// The observable a task analyzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observable {
    pub kind: ObservableKind,
    /// The value, as ace3 stores it. For a file it is the sha256 in hex.
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    /// Set when `kind` is `file` and the task has its bytes: a parser's.
    pub file: Option<InputFile>,
    /// A file's path inside the alert, which a lookup gets too, without the bytes: its pool can't
    /// reach the bucket.
    pub path: Option<AlertPath>,
    /// The observable's directives, such as `original_email` or `no_scan`.
    pub directives: Vec<String>,
    /// The observable that stands for this one when something acts on it, as ace3's
    /// `redirection`, such as the Office document a part came out of.
    pub redirection: Option<ObservableRef>,
    /// Its relationships to other observables, such as a command line `executed_on` a host.
    pub relationships: Vec<Relationship>,
}

impl Observable {
    pub fn new(kind: ObservableKind, value: impl Into<String>) -> Self {
        Observable {
            kind,
            value: value.into(),
            time: None,
            file: None,
            path: None,
            directives: Vec::new(),
            redirection: None,
            relationships: Vec::new(),
        }
    }

    pub fn file(file: InputFile) -> Self {
        Observable {
            kind: ObservableKind::File,
            value: file.sha256.to_hex(),
            time: None,
            path: Some(file.path.clone()),
            file: Some(file),
            directives: Vec::new(),
            redirection: None,
            relationships: Vec::new(),
        }
    }

    pub fn with_directive(mut self, directive: impl Into<String>) -> Self {
        self.directives.push(directive.into());
        self
    }

    pub fn has_directive(&self, directive: &str) -> bool {
        self.directives.iter().any(|d| d == directive)
    }

    pub fn with_relationship(mut self, relationship: Relationship) -> Self {
        self.relationships.push(relationship);
        self
    }

    /// The first relationship of this kind, as ace3's `get_relationship_by_type`.
    pub fn relationship(&self, kind: RelationshipKind) -> Option<&Relationship> {
        self.relationships.iter().find(|r| r.kind == kind)
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

    /// The secret named `name`, if it was resolved.
    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.0.get(name)
    }

    /// The names of the secrets held, in order.
    pub fn names(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelayedRun {
    /// The state from the module's last `Delay`.
    pub state: serde_json::Value,
    /// When the module first asked for a delay. A delay's timeout counts from here.
    pub first_delayed_at: DateTime<Utc>,
    /// How many times the module has asked for a delay.
    pub delays: u32,
}

/// The email that carried a task's observable, for a module that reads it
/// (`Module::READS_CARRYING_EMAIL`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CarryingEmail {
    /// An email in the root hasn't been parsed yet, and it may be this one. The module delays if it
    /// needs to know.
    Pending,
    /// No email carried it, or the module doesn't read one.
    #[default]
    Absent,
    /// An email carried it, and it has no body.
    NoBody,
    /// An email carried it, and its body's bytes are here on this machine.
    Body(PathBuf),
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
    contained: bool,
    yara_rules_below: Vec<String>,
    task: Option<i64>,
    carrying_email: CarryingEmail,
    /// The lists the module declared, by name, each empty until the task's are added.
    lists: BTreeMap<&'static str, List>,
    declared_reads: &'static [DeclaredRead],
    reader: Option<Arc<dyn Reader>>,
    declared_writes: &'static [DeclaredWrite],
    /// What the task wrote so far, sent with its end.
    writes: Mutex<Vec<WireWrite>>,
    /// The results the observable has from the modules this one depends on, by module.
    dependency_results: BTreeMap<String, serde_json::Value>,
    observables_below: Vec<ObservableRef>,
    added_by: Vec<String>,
    related_tags: Vec<RelatedTags>,
    tree: Option<TreeView>,
    /// Where the pool put the tree's files the module reads, each named by its sha256.
    tree_files: Option<PathBuf>,
    declared_tools: &'static [&'static str],
    /// What runs the module's tools (PLAN.md 7.3).
    tools: Option<Arc<dyn ToolRunner>>,
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
            contained: false,
            yara_rules_below: Vec::new(),
            task: None,
            carrying_email: CarryingEmail::Absent,
            lists: M::LISTS
                .iter()
                .map(|spec| (spec.name, List::empty(spec.name)))
                .collect(),
            declared_reads: M::READS,
            reader: None,
            declared_writes: M::WRITES,
            writes: Mutex::new(Vec::new()),
            dependency_results: BTreeMap::new(),
            observables_below: Vec::new(),
            added_by: Vec::new(),
            related_tags: Vec::new(),
            tree: None,
            tree_files: None,
            declared_tools: M::TOOLS,
            tools: None,
        }
    }

    /// What runs the task's tools: the supervisor, or a `LocalRunner`.
    pub fn with_tool_runner(mut self, runner: Option<Arc<dyn ToolRunner>>) -> Self {
        self.tools = runner;
        self
    }

    /// Runs a tool the module declared in `Module::TOOLS` (PLAN.md 7.3) and waits for it. Its timeout
    /// is cut to the task's time left, less ace3's margin, and is at least a second. A run that was
    /// stopped, at its timeout or for its output, is an `Ok` whose status says so; an `Err` is a tool
    /// the module or the pool doesn't have, or one that couldn't start, which fails the task.
    pub fn run_tool(&self, run: ToolRun) -> Result<ToolOutput, ModuleError> {
        if !self.declared_tools.contains(&run.tool.as_str()) {
            return Err(ModuleError::other(ToolError::Undeclared(run.tool)));
        }
        let runner = self
            .tools
            .as_ref()
            .ok_or_else(|| ModuleError::other(ToolError::NoRunner))?;
        let allowed = self
            .time_left()
            .saturating_sub(TIMEOUT_MARGIN)
            .max(Duration::from_secs(1));
        let run = ToolRun {
            timeout: run.timeout.min(allowed),
            ..run
        };
        runner.run(&run).map_err(ModuleError::other)
    }

    /// The directory where the module puts files it hands to its tools, such as an image it made.
    /// None when the task has no tool runner.
    pub fn scratch_dir(&self) -> Option<&std::path::Path> {
        self.tools.as_deref().map(ToolRunner::scratch)
    }

    /// Writes to ACE's own data (PLAN.md 7.2), a write the module declared in `Module::WRITES`.
    /// Nothing is written yet: the write goes with the task's end, and lands only if that end is a
    /// result or a skip, in the end's transaction.
    pub fn write<W: WriteKind>(&self, body: &W::Body) -> Result<(), ModuleError> {
        let name = W::WRITE.name;
        if !self.declared_writes.contains(&W::WRITE) {
            return Err(ModuleError::other(format!(
                "write {name:?} isn't declared in the module's WRITES"
            )));
        }
        let body = serde_json::to_value(body)
            .map_err(|e| ModuleError::other(format!("write {name:?}: {e}")))?;
        self.writes
            .lock()
            .map_err(|_| ModuleError::other("the task's writes are poisoned"))?
            .push(WireWrite {
                write: name.to_owned(),
                body,
            });
        Ok(())
    }

    /// What the task wrote, in order, for its end. Taking them leaves none.
    pub fn take_writes(&self) -> Vec<WireWrite> {
        self.writes
            .lock()
            .map(|mut writes| std::mem::take(&mut *writes))
            .unwrap_or_default()
    }

    /// The results the core sent with the task: the observable's results from the modules in
    /// `Module::DEPENDS_ON`, by module.
    pub fn with_dependency_results(
        mut self,
        results: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> Self {
        self.dependency_results = results.into_iter().collect();
        self
    }

    /// The details of the observable's result from the module that writes `D`, which this module
    /// depends on. None when it has none.
    pub fn dependency_result<D: AnalysisType>(&self) -> Result<Option<D>, ModuleError> {
        self.dependency_results
            .get(D::MODULE)
            .map(|details| {
                serde_json::from_value(details.clone()).map_err(|e| {
                    ModuleError::other(format!("{}'s result doesn't read: {e}", D::MODULE))
                })
            })
            .transpose()
    }

    /// The observables below the task's one, of the types the module reads there
    /// (`Module::READS_BELOW`).
    pub fn with_observables_below(mut self, observables: Vec<ObservableRef>) -> Self {
        self.observables_below = observables;
        self
    }

    /// The observables of the types in `Module::READS_BELOW` found below the task's observable, for
    /// a module that runs last.
    pub fn observables_below(&self) -> &[ObservableRef] {
        &self.observables_below
    }

    /// The modules whose results added the task's observable (`Module::READS_ADDED_BY`).
    pub fn with_added_by(mut self, modules: Vec<String>) -> Self {
        self.added_by = modules;
        self
    }

    /// The modules whose results added the task's observable, by name, for a module that reads
    /// them: the analyses ace3's `iterate_all_references` finds holding it.
    pub fn added_by(&self) -> &[String] {
        &self.added_by
    }

    /// The tags of the observables the task's observable is related to
    /// (`Module::READS_RELATED_TAGS`).
    pub fn with_related_tags(mut self, related: Vec<RelatedTags>) -> Self {
        self.related_tags = related;
        self
    }

    /// The tags of `observable`, one the task's observable has a relationship to, for a module
    /// that reads them. None for any other.
    pub fn related_tags(&self, observable: &ObservableRef) -> Option<&[String]> {
        self.related_tags
            .iter()
            .find(|r| &r.observable == observable)
            .map(|r| r.tags.as_slice())
    }

    /// The root's tree as the core sent it (`Module::READS_TREE`).
    pub fn with_tree(mut self, tree: Option<TreeView>) -> Self {
        self.tree = tree;
        self
    }

    /// The root's tree when the task was leased, for a module that reads it. None for any other.
    pub fn tree(&self) -> Option<&TreeView> {
        self.tree.as_ref()
    }

    /// The directory where the pool put the tree's files the module reads, each named by its
    /// sha256 (`Module::READS_TREE_FILES`).
    pub fn with_tree_files(mut self, dir: Option<PathBuf>) -> Self {
        self.tree_files = dir;
        self
    }

    /// Where a file of the tree is on this machine, for one the module reads
    /// (`Module::READS_TREE_FILES`) and the core sent. None for any other.
    pub fn tree_file(&self, sha256: &str) -> Option<PathBuf> {
        let valid = sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit());
        let path = self.tree_files.as_ref()?.join(sha256);
        (valid && path.is_file()).then_some(path)
    }

    /// What makes the task's reads (`Module::READS`): the pool's lease API client.
    pub fn with_reader(mut self, reader: Option<Arc<dyn Reader>>) -> Self {
        self.reader = reader;
        self
    }

    /// Reads ACE's own data through the core (PLAN.md 7.2), a read the module declared in
    /// `Module::READS`. A miss is an empty answer, not an error. The core or its store being down
    /// is `Unavailable`, so the task runs again later, and a lost lease is `Cancelled`.
    pub async fn read<R: ReadKind>(&self, request: &R::Request) -> Result<R::Answer, ModuleError> {
        let name = R::READ.name;
        if !self.declared_reads.contains(&R::READ) {
            return Err(ModuleError::other(format!(
                "read {name:?} isn't declared in the module's READS"
            )));
        }
        let (Some(reader), Some(task)) = (&self.reader, self.task) else {
            return Err(ModuleError::other(format!(
                "read {name:?} needs a task leased through the lease API"
            )));
        };
        let request = serde_json::to_value(request)
            .map_err(|e| ModuleError::other(format!("read {name:?}: {e}")))?;
        let answer = reader
            .read(task, name, request)
            .await
            .map_err(|e| match e {
                ReadError::Unavailable { .. } => ModuleError::Unavailable(e.into()),
                ReadError::LeaseLost(_) => ModuleError::Cancelled,
                other => ModuleError::Other(other.into()),
            })?;
        serde_json::from_value(answer)
            .map_err(|e| ModuleError::other(format!("read {name:?}'s answer doesn't read: {e}")))
    }

    /// The lists the core sent with the task. Only those the module declared are kept.
    pub fn with_lists(mut self, lists: Vec<WireList>) -> Self {
        for list in lists {
            if let Some(slot) = self.lists.get_mut(list.name.as_str()) {
                *slot = List::from_wire(list);
            }
        }
        self
    }

    /// An analyst-edited list the module declared in `Module::LISTS`, as it was when the task was
    /// leased. A list with no entries is empty, not missing.
    pub fn list(&self, spec: &ListSpec) -> Result<&List, ModuleError> {
        self.lists.get(spec.name).ok_or_else(|| {
            ModuleError::other(format!(
                "list {:?} isn't declared in the module's LISTS",
                spec.name
            ))
        })
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

    /// The YARA rules that matched below the observable, for a module that runs last.
    pub fn with_yara_rules_below(mut self, rules: Vec<String>) -> Self {
        self.yara_rules_below = rules;
        self
    }

    /// What the core says matched in the file and below it (`Module::RUNS_LAST`), as ace3's
    /// `execute_final_analysis` could look. Empty for any other module.
    pub fn yara_rules_below(&self) -> &[String] {
        &self.yara_rules_below
    }

    /// Marks the task as running contained (PLAN.md 2.18): its process can't start a thread,
    /// so a module skips what would, such as a library's watchdog thread.
    pub fn with_contained(mut self, contained: bool) -> Self {
        self.contained = contained;
        self
    }

    /// True when the task's process is contained and can't start a thread or a process.
    pub fn is_contained(&self) -> bool {
        self.contained
    }

    /// The task's id in the queue, which its span carries (PLAN.md 2.22).
    pub fn with_task_id(mut self, task: i64) -> Self {
        self.task = Some(task);
        self
    }

    pub fn task_id(&self) -> Option<i64> {
        self.task
    }

    pub fn with_carrying_email(mut self, email: CarryingEmail) -> Self {
        self.carrying_email = email;
        self
    }

    /// The email that carried the observable, for a module that reads it.
    pub fn carrying_email(&self) -> &CarryingEmail {
        &self.carrying_email
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
