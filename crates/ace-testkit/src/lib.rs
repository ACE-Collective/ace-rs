//! Runs one analysis module on a fixture observable or file, without the core.
//!
//! ```text
//! let harness = Harness::<EmailAnalyzer>::with_settings(json!({"scan_inbound_only": false}))?;
//! let email = harness.sample("ace3/email/smtp.email.rfc822")?;
//! let outcome = harness.run_parser(email)?;          // checked against its schema
//! ace_testkit::assert_outcome_snapshot!(outcome);    // tests/snapshots/<test>.snap
//! ```
//!
//! Every result the harness returns has passed its type's JSON Schema and read back unchanged
//! from JSON. A module's tools run as plain processes (`ace_sdk::tools::LocalRunner`). The root uuid and the task's clock are fixed, so snapshots are stable. Output files
//! go to a store in a temporary directory, where `read_output` finds them.

pub mod dns;
pub mod ldap;
pub mod library_diff;
pub mod reads;
pub mod reference;
pub mod replay;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_results::{
    AlertPath, AnalysisType, InvalidResult, InvalidSchema, NewFile, ObservableKind, ObservableRef,
    ResultEnvelope, ResultValidator, Sha256, YaraMeta, sort_json_keys,
};
use ace_sdk::lists::{Entry as ListEntry, ListSpec, WireList};
use ace_sdk::reads::Reader;
use ace_sdk::wire::RelatedTags;
use ace_sdk::writes::WireWrite;
use ace_sdk::{
    CarryingEmail, Delay, DelayedRun, FileStore, InputFile, LocalFileStore, Lookup, Module,
    ModuleError, Observable, Outcome, Parser, Secret, Secrets, SettingsError, TaskContext,
    load_settings,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::Digest;
use uuid::Uuid;

#[doc(hidden)]
pub use insta as __insta;

/// The root uuid every harness task runs under.
/// The details of a `file_type` result with this description and mime type and every check
/// false but `is_email_file`, which is true for `message/rfc822`: what a module that depends on
/// file_type is sent for a file in a test that doesn't run file_type itself.
pub fn file_type_details(description: &str, mime: &str) -> Value {
    json!({
        "type": description, "mime": mime, "is_office_ext": false, "is_ole_file": false,
        "is_rtf_file": false, "is_pdf_file": false, "is_pe_file": false, "is_zip_file": false,
        "is_x509": false, "is_lnk_file": false, "is_jar_file": false,
        "is_email_file": mime == "message/rfc822", "is_office_document": false,
    })
}

pub const ROOT: Uuid = Uuid::from_u128(0x00000000_0000_4000_8000_000000000001);

/// The time a harness task treats as now: 2026-01-01T00:00:00Z.
pub fn fixed_now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_767_225_600, 0).unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("settings: {0}")]
    Settings(#[from] SettingsError),
    #[error("the module failed: {0}")]
    Module(#[from] ModuleError),
    #[error("the result fails its schema: {0}")]
    InvalidResult(#[from] InvalidResult),
    #[error(transparent)]
    InvalidSchema(#[from] InvalidSchema),
    #[error("the result doesn't read back from JSON unchanged: {0}")]
    RoundTrip(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<ace_results::differences::UnreadableList> for HarnessError {
    fn from(error: ace_results::differences::UnreadableList) -> Self {
        HarnessError::Fixture(error.to_string())
    }
}

/// One module, its settings and secrets, and a file store, ready to run tasks.
pub struct Harness<M: Module> {
    module: M,
    settings: Arc<M::Settings>,
    secrets: Secrets,
    connections: ace_sdk::Connections,
    now: DateTime<Utc>,
    // the directory goes when the harness does
    _dir: tempfile::TempDir,
    store: Arc<LocalFileStore>,
    carrying_email: CarryingEmail,
    timeout: Option<Duration>,
    lists: Vec<WireList>,
    reader: Option<Arc<dyn Reader>>,
    dependency_results: Vec<(String, Value)>,
    dependency_errors: Vec<(String, String)>,
    observables_below: Vec<ObservableRef>,
    added_by: Vec<String>,
    at_root: bool,
    directive_sources: Vec<ace_sdk::directives::SourcedDirective>,
    mode: Option<String>,
    event_time: Option<ace_sdk::wire::RootEventTime>,
    related_tags: Vec<RelatedTags>,
    tree: Option<ace_sdk::tree::TreeView>,
    scan: Option<ace_sdk::scanners::Scan>,
    typer: Option<Typer>,
}

/// What finds a file's type for a harness, as the core's type step would before the module's task
/// (PLAN.md decision 25): given the file's alert path and its bytes on disk, its `TypeFacts`, or
/// None for a file whose type is unknown. `ace_mod_files::file_type::type_of` is the type step's
/// own; the harness can't depend on it, so a test that needs it passes it.
pub type Typer = fn(&str, &Path) -> Option<ace_results::types::file_type::TypeFacts>;

impl<M: Module> Harness<M> {
    /// A harness with the module's default settings.
    pub fn new() -> Result<Self, HarnessError> {
        Harness::build(None)
    }

    /// A harness with a settings block, loaded as a site overlay's would be: unknown keys fail.
    pub fn with_settings(block: Value) -> Result<Self, HarnessError> {
        Harness::build(Some(&block))
    }

    fn build(block: Option<&Value>) -> Result<Self, HarnessError> {
        let settings: M::Settings = load_settings(block)?;
        let module = M::init(&settings)?;
        let dir = tempfile::tempdir()?;
        let store = Arc::new(LocalFileStore::new(dir.path().join("store"))?);
        Ok(Harness {
            module,
            settings: Arc::new(settings),
            secrets: Secrets::new(),
            connections: ace_sdk::Connections::new(),
            now: fixed_now(),
            _dir: dir,
            store,
            carrying_email: CarryingEmail::Absent,
            timeout: None,
            lists: Vec::new(),
            reader: None,
            dependency_results: Vec::new(),
            dependency_errors: Vec::new(),
            observables_below: Vec::new(),
            added_by: Vec::new(),
            at_root: false,
            directive_sources: Vec::new(),
            mode: None,
            event_time: None,
            related_tags: Vec::new(),
            tree: None,
            scan: None,
            typer: None,
        })
    }

    /// Types each file the harness makes with `typer`, so the module's declaration reads its type
    /// and the module gets its mime type, as in a stack. Without one a file's type is unknown.
    pub fn with_typer(mut self, typer: Typer) -> Self {
        self.typer = Some(typer);
        self
    }

    /// The task's latest scan, as the core sends it after a delay that asked for one (PLAN.md 7.7).
    pub fn scan(mut self, scan: ace_sdk::scanners::Scan) -> Self {
        self.scan = Some(scan);
        self
    }

    /// Where the harness's file store keeps the bytes stored under `sha256`, such as a scan input
    /// the module wrote.
    pub fn stored(&self, sha256: &ace_results::Sha256) -> PathBuf {
        self.store.path_of(sha256)
    }

    /// What a module that reads its carrying email is told of it.
    pub fn carrying_email(mut self, email: CarryingEmail) -> Self {
        self.carrying_email = email;
        self
    }

    /// Entries on one of the lists the module reads, as the core would send them with a task.
    pub fn list(mut self, spec: &ListSpec, entries: Vec<ListEntry>) -> Self {
        self.lists.retain(|list| list.name != spec.name);
        self.lists.push(WireList {
            name: spec.name.to_owned(),
            version: 1,
            entries,
        });
        self
    }

    /// What answers the module's reads of ACE's data (PLAN.md 7.2), such as `FakeReads`. Its tasks
    /// then run as task 1 of the queue.
    pub fn reader(mut self, reader: Arc<dyn Reader>) -> Self {
        self.reader = Some(reader);
        self
    }

    /// The details of the observable's result from a module this one depends on, as the core sends
    /// it with the task (`Module::DEPENDS_ON`).
    pub fn dependency_result(mut self, module: &str, details: Value) -> Self {
        self.dependency_results.retain(|(m, _)| m != module);
        self.dependency_results.push((module.to_owned(), details));
        self
    }

    /// Why a module this one depends on said it failed on the observable, as the core sends it
    /// with the task beside that module's details (`TaskContext::dependency_error`).
    pub fn dependency_error(mut self, module: &str, error: &str) -> Self {
        self.dependency_errors.retain(|(m, _)| m != module);
        self.dependency_errors
            .push((module.to_owned(), error.to_owned()));
        self
    }

    /// What the core finds below the observable for a module that runs last
    /// (`Module::READS_BELOW`).
    pub fn observables_below(mut self, observables: Vec<ObservableRef>) -> Self {
        self.observables_below = observables;
        self
    }

    /// The modules whose results added the observable, as the core holds them: the lease sends
    /// them to the module's declaration when it reads them, and to `analyze` only for a module that
    /// reads them (`Module::READS_ADDED_BY`), as the harness does.
    pub fn added_by(mut self, modules: &[&str]) -> Self {
        self.added_by = modules.iter().map(|m| (*m).to_owned()).collect();
        self
    }

    /// Whether the observable came with its root's submission (`takes::Condition::AtRoot`,
    /// `TaskContext::at_root`), sent as `added_by` is.
    pub fn at_root(mut self, at_root: bool) -> Self {
        self.at_root = at_root;
        self
    }

    /// Where the observable's directives came from, one source for each directive named, as the
    /// core records them (PLAN.md decision 44): the lease sends them to a declaration that reads
    /// them (`takes::Condition::DirectiveFrom`), and never to `analyze`. The observable's own
    /// directives are whatever the observable was built with; a directive named here and missing
    /// there is still sent, as the harness doesn't check the two agree.
    pub fn directive_sources(
        mut self,
        sources: &[(&str, ace_sdk::directives::DirectiveSource)],
    ) -> Self {
        self.directive_sources = sources
            .iter()
            .map(|(directive, source)| {
                ace_sdk::directives::SourcedDirective::new(*directive, *source)
            })
            .collect();
        self.directive_sources.sort();
        self
    }

    /// The root's analysis mode, as the lease sends it to a declaration that reads it. A tree's
    /// mode stands for it when this isn't set.
    pub fn mode(mut self, mode: &str) -> Self {
        self.mode = Some(mode.to_owned());
        self
    }

    /// The root's event time, as the core sends it to a module that reads it
    /// (`Module::READS_EVENT_TIME`), from the event itself.
    pub fn event_time(mut self, time: DateTime<Utc>) -> Self {
        self.event_time = Some(ace_sdk::wire::RootEventTime {
            time: Some(time),
            source: ace_sdk::wire::EventTimeSource::Event,
        });
        self
    }

    /// The root's event time with where it came from, or none.
    pub fn root_event_time(mut self, event_time: ace_sdk::wire::RootEventTime) -> Self {
        self.event_time = Some(event_time);
        self
    }

    /// The tags of an observable the analyzed one is related to, as the core sends them to a module
    /// that reads them (`Module::READS_RELATED_TAGS`).
    pub fn related_tags(mut self, observable: ObservableRef, tags: &[&str]) -> Self {
        self.related_tags.retain(|r| r.observable != observable);
        self.related_tags.push(RelatedTags {
            observable,
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        });
        self
    }

    /// The root's tree, as the core sends it to a module that walks it (`Module::READS_TREE`).
    pub fn tree(mut self, tree: ace_sdk::tree::TreeView) -> Self {
        self.tree = Some(tree);
        self
    }

    /// Puts a file of the tree where a module that reads it finds it (`Module::READS_TREE_FILES`),
    /// by its sha256, as the pool downloads it.
    pub fn tree_file(self, sha256: &str, bytes: &[u8]) -> Result<Self, HarnessError> {
        let dir = self._dir.path().join("tree_files");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(sha256), bytes)?;
        Ok(self)
    }

    /// A deadline in place of the manifest's, for a module that watches its own.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn secret(mut self, name: &str, value: &str) -> Self {
        self.secrets = self.secrets.with(name, Secret::new(value));
        self
    }

    /// Binds the module's slot `slot` to `connection` (`Module::CONNECTIONS`), as its pool gives it
    /// the connection the overlay binds there with its secrets. The connection's settings belong in
    /// the harness's settings block too, under `slot`, as the overlay puts them there.
    pub fn connection(mut self, slot: &str, connection: ace_sdk::Connection) -> Self {
        self.connections = self.connections.with(slot, connection);
        self
    }

    /// Sets the time tasks treat as now.
    pub fn at(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn module(&self) -> &M {
        &self.module
    }

    /// An observable that isn't a file.
    pub fn observable(&self, kind: ObservableKind, value: &str) -> Observable {
        Observable::new(kind, value)
    }

    /// A file observable whose bytes are at `local` on disk, as `alert_path` inside the alert,
    /// with these `yara_meta` tags.
    pub fn file(
        &self,
        alert_path: &str,
        local: impl AsRef<Path>,
        yara_meta: &[&str],
    ) -> Result<Observable, HarnessError> {
        let local = local.as_ref();
        let bytes = fs::read(local)
            .map_err(|e| HarnessError::Fixture(format!("{}: {e}", local.display())))?;
        let yara_meta = yara_meta
            .iter()
            .map(|tag| tag.parse::<YaraMeta>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| HarnessError::Fixture(e.to_string()))?;
        let facts = self.typer.and_then(|typer| typer(alert_path, local));
        let file = InputFile {
            path: AlertPath::new(alert_path).map_err(|e| HarnessError::Fixture(e.to_string()))?,
            sha256: sha256_of(&bytes),
            size: bytes.len() as u64,
            role: yara_meta
                .iter()
                .find_map(ace_results::FileRole::of_yara_meta),
            yara_meta,
            mime_type: facts.as_ref().map(|f| f.mime.clone()),
            facts,
            local_path: local.to_owned(),
        };
        Ok(Observable::file(file))
    }

    /// A file observable holding `bytes`, which the harness writes to its store first.
    pub fn file_bytes(
        &self,
        alert_path: &str,
        bytes: &[u8],
        yara_meta: &[&str],
    ) -> Result<Observable, HarnessError> {
        let (sha256, _) = self.store.put(&mut &bytes[..])?;
        self.file(alert_path, self.store.path_of(&sha256), yara_meta)
    }

    /// A file from the repository's sample set, by its path under `samples/`, with the path
    /// inside the alert and the meta tags `samples/manifest.json` gives it. Fails when the file's
    /// sha256 isn't the manifest's, as when a git-ignored local sample is missing.
    pub fn sample(&self, path: &str) -> Result<Observable, HarnessError> {
        let entry = sample_entry(path)?;
        let local = samples_dir().join(path);
        let observable = self.file(&entry.alert_path, &local, &entry.meta_tags_str())?;
        let actual = observable.value.as_str();
        if actual != entry.sha256 {
            return Err(HarnessError::Fixture(format!(
                "{path} has sha256 {actual}, but samples/manifest.json says {}",
                entry.sha256
            )));
        }
        Ok(observable)
    }

    /// The bytes of a file the module wrote.
    pub fn read_output(&self, file: &NewFile) -> Result<Vec<u8>, HarnessError> {
        Ok(fs::read(self.store.path_of(&file.sha256))?)
    }

    /// What the module left for its next run after `delay`, as if it had first asked for a delay
    /// `waited` ago and had now been delayed `delays` times.
    pub fn after_delay(&self, delay: &Delay, delays: u32, waited: Duration) -> DelayedRun {
        DelayedRun {
            state: delay.state.clone(),
            first_delayed_at: self.now
                - chrono::TimeDelta::from_std(waited).unwrap_or(chrono::TimeDelta::zero()),
            delays,
        }
    }

    /// What the lease would send the module's declaration (`wire::Gate`): only what it reads.
    fn gate(&self) -> ace_sdk::wire::Gate {
        let reads = M::takes(&self.settings).reads();
        ace_sdk::wire::Gate {
            mode: reads
                .mode
                .then(|| {
                    self.mode.clone().or_else(|| {
                        self.tree
                            .as_ref()
                            .and_then(|tree| tree.analysis_mode.clone())
                    })
                })
                .flatten(),
            added_by: if reads.added_by {
                self.added_by.clone()
            } else {
                Vec::new()
            },
            at_root: reads.at_root && self.at_root,
            directive_sources: if reads.directive_sources {
                self.directive_sources.clone()
            } else {
                Vec::new()
            },
        }
    }

    fn context(
        &self,
        observable: Observable,
        delayed: Option<DelayedRun>,
    ) -> TaskContext<M::Settings> {
        let ctx = TaskContext::new::<M>(ROOT, observable, self.settings.clone())
            .with_secrets(&self.secrets)
            .with_connections(self.connections.clone())
            .with_now(self.now)
            .with_file_store(self.store.clone())
            .with_carrying_email(self.carrying_email.clone())
            .with_lists(self.lists.clone())
            .with_reader(self.reader.clone())
            .with_dependency_results(self.dependency_results.clone())
            .with_dependency_errors(self.dependency_errors.clone())
            .with_observables_below(self.observables_below.clone())
            .with_added_by(self.added_by.clone())
            .with_at_root(self.at_root)
            .with_event_time(self.event_time)
            .with_gate(self.gate())
            .with_related_tags(self.related_tags.clone())
            .with_tree(self.tree.clone())
            .with_tree_files(Some(self._dir.path().join("tree_files")))
            .with_tool_runner(tool_runner::<M>())
            .with_scan(self.scan.clone());
        let ctx = match &self.reader {
            Some(_) => ctx.with_task_id(1),
            None => ctx,
        };
        let ctx = match self.timeout {
            Some(timeout) => ctx.with_timeout(timeout),
            None => ctx,
        };
        match delayed {
            Some(delayed) => ctx.with_delayed(delayed),
            None => ctx,
        }
    }
}

impl<M: Parser> Harness<M> {
    /// Runs the parser on `observable` and checks its result.
    pub fn run_parser(&self, observable: Observable) -> Result<Outcome<M::Output>, HarnessError> {
        let outcome = ace_sdk::run_parser(&self.module, &self.context(observable, None))?;
        check_outcome(outcome)
    }

    /// Runs the parser again after a delay.
    pub fn rerun_parser(
        &self,
        observable: Observable,
        delayed: DelayedRun,
    ) -> Result<Outcome<M::Output>, HarnessError> {
        let ctx = self.context(observable, Some(delayed));
        check_outcome(ace_sdk::run_parser(&self.module, &ctx)?)
    }
}

impl<M: Lookup> Harness<M> {
    /// Runs the lookup on `observable` and checks its result.
    pub async fn run_lookup(
        &self,
        observable: Observable,
    ) -> Result<Outcome<M::Output>, HarnessError> {
        let ctx = self.context(observable, None);
        check_outcome(ace_sdk::run_lookup(&self.module, &ctx).await?)
    }

    /// Runs the lookup and returns its result with what it wrote to ACE's data (`Module::WRITES`),
    /// which the core would land with its end.
    pub async fn run_lookup_writing(
        &self,
        observable: Observable,
    ) -> Result<(Outcome<M::Output>, Vec<WireWrite>), HarnessError> {
        let ctx = self.context(observable, None);
        let outcome = check_outcome(ace_sdk::run_lookup(&self.module, &ctx).await?)?;
        Ok((outcome, ctx.take_writes()))
    }

    /// Runs the lookup again after a delay.
    pub async fn rerun_lookup(
        &self,
        observable: Observable,
        delayed: DelayedRun,
    ) -> Result<Outcome<M::Output>, HarnessError> {
        let ctx = self.context(observable, Some(delayed));
        check_outcome(ace_sdk::run_lookup(&self.module, &ctx).await?)
    }
}

/// Checks a result against its type's schema, and that it reads back from JSON unchanged.
pub fn check_result<D: AnalysisType>(result: &ResultEnvelope<D>) -> Result<(), HarnessError> {
    let json = serde_json::to_value(result).map_err(|e| HarnessError::RoundTrip(e.to_string()))?;
    ResultValidator::of::<D>()?.validate(&json)?;
    let back = ResultEnvelope::<D>::from_json(json.clone())
        .map_err(|e| HarnessError::RoundTrip(e.to_string()))?;
    let again = serde_json::to_value(&back).map_err(|e| HarnessError::RoundTrip(e.to_string()))?;
    if again != json {
        return Err(HarnessError::RoundTrip(format!(
            "wrote {json}, read back {again}"
        )));
    }
    Ok(())
}

fn check_outcome<D: AnalysisType>(outcome: Outcome<D>) -> Result<Outcome<D>, HarnessError> {
    if let Outcome::Done(result) | Outcome::DoneNotKept(result) | Outcome::Incomplete(result) =
        &outcome
    {
        check_result(result)?;
    }
    Ok(outcome)
}

/// An outcome as JSON with sorted keys, for a snapshot.
pub fn snapshot_value<D: AnalysisType>(outcome: &Outcome<D>) -> Value {
    let value = match outcome {
        Outcome::Done(result) => json!({
            "outcome": "done",
            "result": serde_json::to_value(result)
                .unwrap_or_else(|e| json!({"unserializable": e.to_string()})),
        }),
        Outcome::Delay(delay) => json!({
            "outcome": "delay",
            "run_after_seconds": delay.run_after.as_secs_f64(),
            "timeout_seconds": delay.timeout.as_secs_f64(),
            "state": delay.state,
        }),
        Outcome::DoneNotKept(result) => json!({
            "outcome": "done_not_kept",
            "result": serde_json::to_value(result)
                .unwrap_or_else(|e| json!({"unserializable": e.to_string()})),
        }),
        Outcome::Incomplete(result) => json!({
            "outcome": "incomplete",
            "result": serde_json::to_value(result)
                .unwrap_or_else(|e| json!({"unserializable": e.to_string()})),
        }),
        Outcome::Skipped(reason) => json!({"outcome": "skipped", "reason": reason}),
    };
    sort_json_keys(value)
}

/// A runner of `M`'s tools as plain processes, the sandbox image's at their paths, which the dev
/// container has (PLAN.md 7.5 batch 10). None for a module that runs none. Each task gets its own,
/// so each counts its runs from none.
fn tool_runner<M: Module>() -> Option<Arc<dyn ace_sdk::tools::ToolRunner>> {
    if M::TOOLS.is_empty() {
        return None;
    }
    let runner = ace_sdk::tools::LocalRunner::new(ace_sdk::tools::SANDBOX_TOOLS, M::TOOLS)
        .expect("a directory for the tools' runs");
    Some(Arc::new(runner))
}

/// Snapshots an outcome with insta, in the calling crate's `snapshots` directory.
#[macro_export]
macro_rules! assert_outcome_snapshot {
    ($outcome:expr) => {
        $crate::__insta::assert_json_snapshot!($crate::snapshot_value(&$outcome))
    };
    ($name:expr, $outcome:expr) => {
        $crate::__insta::assert_json_snapshot!($name, $crate::snapshot_value(&$outcome))
    };
}

/// Checks that `crates/ace-gui/tests/fixtures/<name>.json` is this outcome's result, as JSON, so the
/// GUI's analysis views are drawn from what the module writes (PLAN.md 5.8 and 5.9). With
/// `ACE4_WRITE_FIXTURES=1` it writes the fixture first. Panics unless the outcome is a result and
/// the fixture matches it.
pub fn check_view_fixture<D: AnalysisType>(name: &str, outcome: &Outcome<D>) {
    let Outcome::Done(result) = outcome else {
        panic!("the view fixture {name} needs a result");
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ace-gui/tests/fixtures")
        .join(format!("{name}.json"));
    let written = serde_json::to_string_pretty(&result.to_raw().expect("serializes"))
        .expect("serializes")
        + "\n";
    if std::env::var_os("ACE4_WRITE_FIXTURES").is_some() {
        fs::create_dir_all(path.parent().expect("a directory")).expect("makes it");
        fs::write(&path, &written).expect("writes the fixture");
    }
    // as values, since a workspace build may give serde_json `preserve_order`, which orders the text
    let fixture: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the view fixture {} reads: {e}", path.display())),
    )
    .expect("JSON");
    let written: Value = serde_json::from_str(&written).expect("JSON");
    assert!(
        fixture == written,
        "{} isn't this module's result; ACE4_WRITE_FIXTURES=1 writes it",
        path.display()
    );
}

/// The repository's `samples/` directory.
pub fn samples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples")
}

#[derive(serde::Deserialize)]
struct SampleManifest {
    samples: Vec<SampleEntry>,
}

#[derive(serde::Deserialize)]
struct SampleEntry {
    path: String,
    sha256: String,
    alert_path: String,
    meta_tags: Vec<String>,
}

impl SampleEntry {
    fn meta_tags_str(&self) -> Vec<&str> {
        self.meta_tags.iter().map(String::as_str).collect()
    }
}

fn sample_entry(path: &str) -> Result<SampleEntry, HarnessError> {
    let manifest_path = samples_dir().join("manifest.json");
    let text = fs::read_to_string(&manifest_path)
        .map_err(|e| HarnessError::Fixture(format!("{}: {e}", manifest_path.display())))?;
    let manifest: SampleManifest = serde_json::from_str(&text)
        .map_err(|e| HarnessError::Fixture(format!("samples/manifest.json: {e}")))?;
    manifest
        .samples
        .into_iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| HarnessError::Fixture(format!("{path} isn't in samples/manifest.json")))
}

fn sha256_of(bytes: &[u8]) -> Sha256 {
    Sha256(sha2::Sha256::digest(bytes).into())
}
