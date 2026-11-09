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
//! from JSON. The root uuid and the task's clock are fixed, so snapshots are stable. Output files
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
    now: DateTime<Utc>,
    // the directory goes when the harness does
    _dir: tempfile::TempDir,
    store: Arc<LocalFileStore>,
    carrying_email: CarryingEmail,
    timeout: Option<Duration>,
    lists: Vec<WireList>,
    reader: Option<Arc<dyn Reader>>,
    dependency_results: Vec<(String, Value)>,
    observables_below: Vec<ObservableRef>,
}

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
            now: fixed_now(),
            _dir: dir,
            store,
            carrying_email: CarryingEmail::Absent,
            timeout: None,
            lists: Vec::new(),
            reader: None,
            dependency_results: Vec::new(),
            observables_below: Vec::new(),
        })
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

    /// What the core finds below the observable for a module that runs last
    /// (`Module::READS_BELOW`).
    pub fn observables_below(mut self, observables: Vec<ObservableRef>) -> Self {
        self.observables_below = observables;
        self
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
        let file = InputFile {
            path: AlertPath::new(alert_path).map_err(|e| HarnessError::Fixture(e.to_string()))?,
            sha256: sha256_of(&bytes),
            size: bytes.len() as u64,
            yara_meta,
            mime_type: None,
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

    fn context(
        &self,
        observable: Observable,
        delayed: Option<DelayedRun>,
    ) -> TaskContext<M::Settings> {
        let ctx = TaskContext::new::<M>(ROOT, observable, self.settings.clone())
            .with_secrets(&self.secrets)
            .with_now(self.now)
            .with_file_store(self.store.clone())
            .with_carrying_email(self.carrying_email.clone())
            .with_lists(self.lists.clone())
            .with_reader(self.reader.clone())
            .with_dependency_results(self.dependency_results.clone())
            .with_observables_below(self.observables_below.clone());
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
    if let Outcome::Done(result) = &outcome {
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
        Outcome::Skipped(reason) => json!({"outcome": "skipped", "reason": reason}),
    };
    sort_json_keys(value)
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
