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

pub mod library_diff;
pub mod reference;
pub mod replay;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_results::{
    AlertPath, AnalysisType, InvalidResult, InvalidSchema, NewFile, ObservableKind, ResultEnvelope,
    ResultValidator, Sha256, YaraMeta, sort_json_keys,
};
use ace_sdk::{
    Delay, DelayedRun, FileStore, InputFile, LocalFileStore, Lookup, Module, ModuleError,
    Observable, Outcome, Parser, Secret, Secrets, SettingsError, TaskContext, load_settings,
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
        })
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
            .with_file_store(self.store.clone());
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
