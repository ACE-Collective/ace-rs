//! Replaying the SVS corpus under two commits of a rule repository: ace3's `saq/svs/yara/replay.py` (ace3's
//! `docs/SVS.md`, Part 2, *Validation*).
//!
//! `Replayer::run` does one validation from start to finish:
//!
//! 1. fetches the branches into SVS's mirror of the repository and exports both commits' rules
//!    (`repository`) into a private working directory;
//! 2. reads the corpus and writes a plaintext copy of every sample it can (`corpus`);
//! 3. runs the replay child once per commit, which compiles the rules as the ruleset build does and scans
//!    every sample (`ace_yara::replay`, PLAN.md 1.10). In `ace serve` the child is this binary again, by
//!    exec, contained (`ace yara replay --contained`: one thread, no network, reading only the working
//!    directory and writing only its side's directory, its CPU time and memory held), and killed at
//!    `scan_timeout_seconds` or when the validation is cancelled;
//! 4. reads each commit's rules from source for their uuids and content hashes (`ace_yara::source`);
//! 5. compares the two scans against the labels (`diff`).
//!
//! The working directory holds every sample in plaintext and is removed when the replay ends, whatever
//! happened. Nothing here writes to the database.
//!
//! What differs from ace3: the child is ace4's (the YARA pool's loader, so a file that isn't UTF-8 or has an
//! include that can't be read is left out alone, where ace3 fails the load or compiles the include as
//! empty), and a contained scan has no per-file timeout (`ace_yara::replay::run_with`), so a slow file is
//! held to the whole scan's limit and fails the validation rather than being one unit's scan error. The
//! mime type comes from libmagic in the child, as the YARA pool types a file.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Instant;

use ace_yara::Meta;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::ValidationConfig;
use super::corpus::{Corpus, CorpusError, Skipped, read_corpus, write_units};
use super::diff::{Category, ResultRow, RuleInfo, SideScan, diff, duplicate_uuids};
use super::layout::{NotLoaded, RepoLayout, TreeLayout, tree_layout};
use super::repository::{Mirror, RepositoryError, is_valid_sha};
use crate::bucket::Bucket;
use crate::db::Db;

pub const BASE: &str = "base";
pub const HEAD: &str = "head";

/// Why a replay didn't finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// It couldn't run; the message is safe to show.
    #[error("{0}")]
    Failed(String),
    /// Something unexpected, such as the database; the message is for the log only.
    #[error("{0}")]
    Internal(String),
    /// Its cancel was set; it stopped and its working directory is gone.
    #[error("the validation was cancelled")]
    Cancelled,
}

impl From<RepositoryError> for ReplayError {
    fn from(e: RepositoryError) -> Self {
        ReplayError::Failed(e.0)
    }
}

/// A rule as its source names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleRef {
    pub uuid: Option<String>,
    pub name: String,
    /// Relative to the repository's top.
    pub file: String,
}

/// A rule file that doesn't compile, with the rules (with a uuid) the ruleset build drops with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileError {
    pub file: String,
    pub namespace: String,
    pub error: String,
    #[serde(default)]
    pub dropped: Vec<RuleRef>,
}

/// How long one namespace took.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Timing {
    pub compile_seconds: f64,
    pub scan_seconds: f64,
    pub rules: u64,
}

/// How one commit compiled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SideReport {
    pub sha: String,
    pub namespaces: Vec<String>,
    pub absent_namespaces: Vec<String>,
    pub not_loaded: Vec<NotLoaded>,
    /// What the export didn't write: `(path, reason)`.
    pub skipped_members: Vec<(String, String)>,
    pub file_errors: Vec<FileError>,
    /// Set when the files that compile alone don't compile together: the ruleset build would make no
    /// ruleset of the commit, and the pools would keep the one they have.
    pub ruleset_error: Option<String>,
    pub warnings: Vec<String>,
    pub include_warnings: Vec<Value>,
    pub timings: BTreeMap<String, Timing>,
    pub rule_count: u64,
    /// Whether its rules would load: `ruleset_error` is unset.
    pub loads: bool,
}

impl SideReport {
    pub fn new(sha: &str) -> SideReport {
        SideReport {
            sha: sha.to_owned(),
            loads: true,
            ..SideReport::default()
        }
    }
}

/// A head rule a label can't follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotTestable {
    pub uuid: Option<String>,
    pub name: String,
    pub file: String,
    pub reason: String,
}

/// One validation's result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub repository: String,
    pub base_sha: String,
    pub head_sha: String,
    pub base: SideReport,
    pub head: SideReport,
    /// False when either commit's rules wouldn't load: nothing was compared.
    pub diffed: bool,
    pub rows: Vec<ResultRow>,
    /// Pairs per category, every category included once compared.
    pub counts: BTreeMap<String, u64>,
    pub added_rules: Vec<RuleRef>,
    pub removed_rules: Vec<RuleRef>,
    pub changed_rules: Vec<RuleRef>,
    pub not_testable: Vec<NotTestable>,
    /// Head rules that filter on full_path, which a replay can't reproduce.
    pub full_path_rules: Vec<RuleRef>,
    pub skipped: Vec<Skipped>,
    pub truncated_paths: u64,
    pub units: u64,
    pub samples: u64,
    pub files: u64,
    pub bytes: u64,
    pub duration_seconds: f64,
    pub yara_x_version: Option<String>,
}

impl ReplayResult {
    /// A result with nothing in it, as a test builds one.
    pub fn new(repository: &str, base_sha: &str, head_sha: &str) -> ReplayResult {
        ReplayResult {
            repository: repository.to_owned(),
            base_sha: base_sha.to_owned(),
            head_sha: head_sha.to_owned(),
            base: SideReport::new(base_sha),
            head: SideReport::new(head_sha),
            diffed: false,
            rows: Vec::new(),
            counts: BTreeMap::new(),
            added_rules: Vec::new(),
            removed_rules: Vec::new(),
            changed_rules: Vec::new(),
            not_testable: Vec::new(),
            full_path_rules: Vec::new(),
            skipped: Vec::new(),
            truncated_paths: 0,
            units: 0,
            samples: 0,
            files: 0,
            bytes: 0,
            duration_seconds: 0.0,
            yara_x_version: None,
        }
    }

    /// Every category's count, zero when it has none, as a compared result keeps them.
    pub fn all_counts(counts: &BTreeMap<Category, u64>) -> BTreeMap<String, u64> {
        Category::ALL
            .iter()
            .map(|c| (c.as_str().to_owned(), counts.get(c).copied().unwrap_or(0)))
            .collect()
    }

    /// The report a validation keeps: everything but the rows, which are rows of their own.
    pub fn report(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Some(object) = value.as_object_mut() {
            object.remove("rows");
        }
        value
    }
}

/// Where a commit's scan runs.
#[derive(Debug, Clone)]
pub enum Child {
    /// In this process, uncontained, with the per-file timeout. For tests.
    InProcess,
    /// `program` with `args`, then `--read <workdir> --cpu-seconds <n> --memory-mb <n> <side directory>`:
    /// `ace yara replay --contained` in `ace serve` and `ace svs yara validate`.
    Exec { program: PathBuf, args: Vec<String> },
}

impl Child {
    /// This binary's `ace yara replay --contained`.
    pub fn this_binary() -> Result<Child, String> {
        let program = std::env::current_exe().map_err(|e| format!("this binary's path: {e}"))?;
        Ok(Child::Exec {
            program,
            args: vec!["yara".into(), "replay".into(), "--contained".into()],
        })
    }
}

/// What a validation replays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRequest {
    pub repository: String,
    pub base_sha: String,
    pub head_sha: String,
    /// The branch the head commit is on; the repository's own branch is fetched too.
    pub branch: Option<String>,
    /// `(sha256, rule uuid)` pairs that are only counted.
    pub retired: BTreeSet<(String, String)>,
}

/// Something that runs a replay: `Replayer`, or a test's stand-in.
pub trait Replay: Send + Sync {
    fn replay<'a>(
        &'a self,
        request: &'a ReplayRequest,
        cancel: &'a CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<ReplayResult, ReplayError>> + Send + 'a>>;
}

/// Runs replays against the database's corpus and the bucket's samples.
#[derive(Clone)]
pub struct Replayer {
    pub db: Db,
    pub bucket: Bucket,
    pub config: ValidationConfig,
    /// The dispositions' classes, for the samples' labels.
    pub tp: Vec<String>,
    pub fp: Vec<String>,
    pub child: Child,
}

impl Replay for Replayer {
    fn replay<'a>(
        &'a self,
        request: &'a ReplayRequest,
        cancel: &'a CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<ReplayResult, ReplayError>> + Send + 'a>> {
        Box::pin(self.run(request, cancel))
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), ReplayError> {
    if cancel.is_cancelled() {
        Err(ReplayError::Cancelled)
    } else {
        Ok(())
    }
}

fn internal(what: &str) -> impl Fn(std::io::Error) -> ReplayError + '_ {
    move |e| ReplayError::Internal(format!("{what}: {e}"))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ReplayError> + Send + 'static,
) -> Result<T, ReplayError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ReplayError::Internal(format!("a blocking step panicked: {e}")))?
}

/// The full id of `sha` in the mirror, fetching it by id when no fetched branch has it.
fn resolve(mirror: &Mirror, sha: &str) -> Result<String, ReplayError> {
    if let Some(resolved) = mirror.resolve(sha)? {
        return Ok(resolved);
    }
    // a branch that was rebased or deleted since the request no longer has it
    if let Err(e) = mirror.fetch_commit(sha) {
        tracing::info!("{e}");
    }
    mirror.resolve(sha)?.ok_or_else(|| {
        ReplayError::Failed(format!(
            "commit {sha} is not in repository {}: no fetched branch contains it, and the server \
             would not send it by id",
            mirror.name
        ))
    })
}

/// Removes what a validation that died left in the work directory. `ace serve` calls it before its workers
/// start, so no validation is running then.
pub fn sweep_work_dir(config: &ValidationConfig) {
    let Ok(entries) = std::fs::read_dir(&config.work_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => {
                tracing::info!(path = %path.display(), "removed a validation's leftover work")
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "unable to remove a validation's leftover work: {e}")
            }
        }
    }
}

fn relative(path: &str, root: &Path) -> String {
    let path = Path::new(path);
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The rules with a uuid in a commit's loaded files, read from source: file to rules, and uuid to its
/// content hashes.
type SourceRules = (
    BTreeMap<String, Vec<RuleRef>>,
    BTreeMap<String, BTreeSet<String>>,
);

fn source_rules(layout: &TreeLayout, tree: &Path) -> SourceRules {
    let mut by_file = BTreeMap::new();
    let mut hashes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for namespace in &layout.namespaces {
        for path in &namespace.files {
            let file = relative(&path.to_string_lossy(), tree);
            let Ok(source) = std::fs::read(path) else {
                continue;
            };
            let rules: Vec<_> = ace_yara::source::rules(&source)
                .into_iter()
                .filter_map(|rule| rule.uuid.clone().map(|uuid| (uuid, rule)))
                .collect();
            by_file.insert(
                file.clone(),
                rules
                    .iter()
                    .map(|(uuid, rule)| RuleRef {
                        uuid: Some(uuid.clone()),
                        name: rule.name.clone(),
                        file: file.clone(),
                    })
                    .collect(),
            );
            for (uuid, rule) in rules {
                hashes.entry(uuid).or_default().insert(rule.content_hash);
            }
        }
    }
    (by_file, hashes)
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}

fn meta_of(value: &Value) -> Meta {
    value.as_object().map(Meta::from_json).unwrap_or_default()
}

/// One side's report and scan from the child's output, and its rules without a uuid.
fn side(
    sha: &str,
    tree: &Path,
    layout: &TreeLayout,
    skipped_members: Vec<(String, String)>,
    output: &Value,
    source: &SourceRules,
) -> (SideReport, SideScan, Vec<RuleRef>) {
    let mut report = SideReport::new(sha);
    report.namespaces = layout.namespaces.iter().map(|n| n.name.clone()).collect();
    report.absent_namespaces = layout.absent.clone();
    report.not_loaded = layout.not_loaded.clone();
    report.skipped_members = skipped_members;
    report.ruleset_error = output["ruleset_error"].as_str().map(str::to_owned);
    report.loads = report.ruleset_error.is_none();
    report.warnings = output["warnings"]
        .as_array()
        .map(|w| w.iter().map(text).collect())
        .unwrap_or_default();
    report.include_warnings = output["include_warnings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    report.timings = output["namespaces"]
        .as_object()
        .map(|namespaces| {
            namespaces
                .iter()
                .map(|(name, t)| {
                    (
                        name.clone(),
                        Timing {
                            compile_seconds: t["compile_seconds"].as_f64().unwrap_or_default(),
                            scan_seconds: t["scan_seconds"].as_f64().unwrap_or_default(),
                            rules: t["rules"].as_u64().unwrap_or_default(),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    report.rule_count = report.timings.values().map(|t| t.rules).sum();

    let mut scan = SideScan {
        source_uuids: source.1.keys().cloned().collect(),
        ..SideScan::default()
    };
    let mut no_uuid = Vec::new();
    for entry in output["files"].as_array().into_iter().flatten() {
        let file = relative(&text(&entry["path"]), tree);
        let namespace = text(&entry["namespace"]);
        if let Some(error) = entry["error"].as_str() {
            report.file_errors.push(FileError {
                dropped: source.0.get(&file).cloned().unwrap_or_default(),
                file,
                namespace,
                error: error.to_owned(),
            });
            continue;
        }
        for rule in entry["rules"].as_array().into_iter().flatten() {
            let meta = meta_of(&rule["meta"]);
            let name = text(&rule["name"]);
            match meta.uuid().filter(|u| !u.is_empty()) {
                None => {
                    if !rule["private"].as_bool().unwrap_or(false) {
                        no_uuid.push(RuleRef {
                            uuid: None,
                            name,
                            file: file.clone(),
                        });
                    }
                }
                Some(uuid) => scan.loaded.entry(uuid.clone()).or_default().push(RuleInfo {
                    uuid,
                    name,
                    namespace: namespace.clone(),
                    file: file.clone(),
                    meta,
                }),
            }
        }
    }
    for (unit, outcome) in output["units"].as_object().into_iter().flatten() {
        let Ok(unit) = unit.parse::<u64>() else {
            continue;
        };
        let matches = outcome["matches"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| (text(&m["namespace"]), text(&m["rule"]), meta_of(&m["meta"])))
            .collect();
        scan.matches.insert(unit, matches);
        let errors: BTreeSet<String> = outcome["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| text(&e["namespace"]))
            .collect();
        if !errors.is_empty() {
            scan.errors.insert(unit, errors);
        }
    }
    (report, scan, no_uuid)
}

fn first_ref(uuid: &str, scan: &SideScan, by_file: &BTreeMap<String, Vec<RuleRef>>) -> RuleRef {
    if let Some(rule) = scan.loaded.get(uuid).and_then(|rules| rules.first()) {
        return RuleRef {
            uuid: Some(uuid.to_owned()),
            name: rule.name.clone(),
            file: rule.file.clone(),
        };
    }
    by_file
        .values()
        .flatten()
        .find(|r| r.uuid.as_deref() == Some(uuid))
        .cloned()
        .unwrap_or(RuleRef {
            uuid: Some(uuid.to_owned()),
            name: String::new(),
            file: String::new(),
        })
}

/// The tail of a stopped scan's progress, for its error.
fn progress(side_dir: &Path) -> String {
    let Ok(bytes) = std::fs::read(side_dir.join(ace_yara::replay::PROGRESS_FILE)) else {
        return String::new();
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return String::new();
    };
    let done: Vec<String> = value["namespaces"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, t)| {
            format!(
                "{name} {:.0}s",
                t["scan_seconds"].as_f64().unwrap_or_default()
            )
        })
        .collect();
    if done.is_empty() {
        String::new()
    } else {
        format!(" (namespaces scanned: {})", done.join(", "))
    }
}

impl Replayer {
    /// Validates `request.head_sha` against `request.base_sha` (the module's docs). Fails with
    /// `ReplayError::Cancelled` soon after `cancel` is set: a git fetch under way finishes first, and a
    /// contained scan is killed.
    pub async fn run(
        &self,
        request: &ReplayRequest,
        cancel: &CancellationToken,
    ) -> Result<ReplayResult, ReplayError> {
        let started = Instant::now();
        for sha in [&request.base_sha, &request.head_sha] {
            if !is_valid_sha(sha) {
                return Err(ReplayError::Failed(format!("{sha:?} is not a commit id")));
            }
        }
        let repository = &request.repository;
        let layout = self
            .config
            .layout(repository)
            .map_err(ReplayError::Failed)?;
        let repo_config = self.config.repositories[repository].clone();
        super::check_work_root(&self.config.work_dir).map_err(ReplayError::Failed)?;
        std::fs::create_dir_all(&self.config.work_dir)
            .map_err(internal("making the work directory"))?;
        let workdir = tempfile::Builder::new()
            .prefix("validation-")
            .tempdir_in(&self.config.work_dir)
            .map_err(internal("making the validation's directory"))?;
        let outcome = self
            .run_in(
                request,
                cancel,
                &layout,
                &repo_config,
                workdir.path(),
                started,
            )
            .await;
        let path = workdir.keep();
        // the samples are in plaintext there: it goes whatever happened
        match tokio::task::spawn_blocking(move || std::fs::remove_dir_all(path)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("unable to remove a validation's working directory: {e}"),
            Err(e) => tracing::error!("unable to remove a validation's working directory: {e}"),
        }
        outcome
    }

    async fn run_in(
        &self,
        request: &ReplayRequest,
        cancel: &CancellationToken,
        layout: &RepoLayout,
        repo_config: &ace_sdk::SvsRepository,
        workdir: &Path,
        started: Instant,
    ) -> Result<ReplayResult, ReplayError> {
        check_cancel(cancel)?;
        let mirror = Mirror::new(
            &request.repository,
            &repo_config.url,
            &self.config.mirror_dir,
            self.config.fetch_timeout,
        )
        .with_ssh_key(
            self.config
                .ssh_key(&request.repository)
                .map_err(ReplayError::Failed)?,
        );
        let trees = [
            workdir.join(BASE).join("tree"),
            workdir.join(HEAD).join("tree"),
        ];
        let (resolved, skipped_members) = {
            let mirror = mirror.clone();
            let branch = repo_config.branch.clone();
            let optional = request.branch.clone();
            let shas = [request.base_sha.clone(), request.head_sha.clone()];
            let trees = trees.clone();
            let signature_dir = layout.signature_dir.clone();
            let config = self.config.clone();
            blocking(move || {
                let _lock = mirror.lock()?;
                let optional: Vec<&str> = optional.as_deref().into_iter().collect();
                mirror.ensure(&[&branch], &optional)?;
                let resolved = [resolve(&mirror, &shas[0])?, resolve(&mirror, &shas[1])?];
                let mut skipped = Vec::new();
                for (sha, tree) in resolved.iter().zip(&trees) {
                    std::fs::create_dir_all(tree)
                        .map_err(internal("making the export's directory"))?;
                    let export = mirror.export(
                        sha,
                        tree,
                        &signature_dir,
                        config.max_archive_bytes,
                        config.max_archive_members,
                        config.fetch_timeout,
                    )?;
                    skipped.push(export.skipped);
                }
                Ok((resolved, skipped))
            })
            .await?
        };

        check_cancel(cancel)?;
        let mut corpus = read_corpus(&self.db, &self.tp, &self.fp)
            .await
            .map_err(|e| ReplayError::Internal(format!("reading the corpus: {e}")))?;
        write_units(
            &mut corpus,
            &self.bucket,
            &workdir.join("u"),
            self.config.corpus_limits,
            cancel,
        )
        .await
        .map_err(|e| match e {
            CorpusError::Cancelled => ReplayError::Cancelled,
            CorpusError::TooLarge(message) => ReplayError::Failed(message),
            CorpusError::Db(e) => ReplayError::Internal(format!("reading the corpus: {e}")),
        })?;
        check_cancel(cancel)?;

        let mut reports = Vec::new();
        let mut scans = Vec::new();
        let mut no_uuids = Vec::new();
        let mut sources = Vec::new();
        let mut version = None;
        for (index, name) in [BASE, HEAD].into_iter().enumerate() {
            let tree = &trees[index];
            let tree_layout = tree_layout(layout, tree);
            let side_dir = workdir.join(name);
            let output = self
                .scan(workdir, &side_dir, tree, &tree_layout, &corpus, cancel)
                .await?;
            version = output["yara_x_version"].as_str().map(str::to_owned);
            let source = source_rules(&tree_layout, tree);
            let (report, scan, no_uuid) = side(
                &resolved[index],
                tree,
                &tree_layout,
                skipped_members[index].clone(),
                &output,
                &source,
            );
            reports.push(report);
            scans.push(scan);
            no_uuids.push(no_uuid);
            sources.push(source);
        }

        let head_report = reports.pop().expect("two sides");
        let base_report = reports.pop().expect("two sides");
        let mut result = ReplayResult::new(&request.repository, &resolved[0], &resolved[1]);
        result.base = base_report;
        result.head = head_report;
        result.yara_x_version = version;

        let (base_hashes, head_hashes) = (&sources[0].1, &sources[1].1);
        result.added_rules = head_hashes
            .keys()
            .filter(|u| !base_hashes.contains_key(*u))
            .map(|u| first_ref(u, &scans[1], &sources[1].0))
            .collect();
        result.removed_rules = base_hashes
            .keys()
            .filter(|u| !head_hashes.contains_key(*u))
            .map(|u| first_ref(u, &scans[0], &sources[0].0))
            .collect();
        result.changed_rules = head_hashes
            .iter()
            .filter(|(u, hashes)| base_hashes.get(*u).is_some_and(|b| b != *hashes))
            .map(|(u, _)| first_ref(u, &scans[1], &sources[1].0))
            .collect();

        let mut source_counts: BTreeMap<String, usize> = BTreeMap::new();
        for rule in sources[1].0.values().flatten() {
            if let Some(uuid) = &rule.uuid {
                *source_counts.entry(uuid.clone()).or_default() += 1;
            }
        }
        let duplicates = duplicate_uuids(&scans[1], &source_counts);
        result.not_testable = no_uuids[1]
            .iter()
            .map(|r| NotTestable {
                uuid: None,
                name: r.name.clone(),
                file: r.file.clone(),
                reason: "no uuid".to_owned(),
            })
            .chain(duplicates.iter().flat_map(|uuid| {
                sources[1]
                    .0
                    .values()
                    .flatten()
                    .filter(move |r| r.uuid.as_deref() == Some(uuid.as_str()))
                    .map(|r| NotTestable {
                        uuid: r.uuid.clone(),
                        name: r.name.clone(),
                        file: r.file.clone(),
                        reason: "uuid shared with another rule".to_owned(),
                    })
            }))
            .collect();
        result.full_path_rules = scans[1]
            .loaded
            .values()
            .flatten()
            .filter(|r| {
                r.meta
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("full_path"))
            })
            .map(|r| RuleRef {
                uuid: Some(r.uuid.clone()),
                name: r.name.clone(),
                file: r.file.clone(),
            })
            .collect();

        let replayed = corpus.replayed_sha256s();
        result.skipped = corpus.skipped.clone();
        result.truncated_paths = corpus
            .units
            .iter()
            .filter(|u| u.truncated && u.path.is_some())
            .count() as u64;
        result.units = corpus.units.iter().filter(|u| u.path.is_some()).count() as u64;
        result.files = replayed.len() as u64;
        result.samples = corpus
            .samples
            .keys()
            .filter(|(sha256, _)| replayed.contains(sha256))
            .count() as u64;
        result.bytes = corpus.bytes;

        result.diffed = result.base.loads && result.head.loads;
        if result.diffed {
            let (rows, counts) = diff(&corpus, &scans[0], &scans[1], &request.retired, &duplicates);
            result.rows = rows;
            result.counts = ReplayResult::all_counts(&counts);
        }
        result.duration_seconds = started.elapsed().as_secs_f64();
        Ok(result)
    }

    /// Compiles and scans one commit: writes its job and runs the child.
    async fn scan(
        &self,
        workdir: &Path,
        side_dir: &Path,
        tree: &Path,
        layout: &TreeLayout,
        corpus: &Corpus,
        cancel: &CancellationToken,
    ) -> Result<Value, ReplayError> {
        let job = json!({
            "version": ace_yara::replay::PROTOCOL_VERSION,
            "tree_root": tree.to_string_lossy(),
            "file_timeout": self.config.file_timeout.as_secs_f64(),
            "namespaces": layout.namespaces.iter().map(|n| json!({
                "name": n.name,
                "directory": n.directory,
                "files": n.files,
            })).collect::<Vec<_>>(),
            "units": corpus.units.iter().filter_map(|u| u.path.as_ref().map(|path| json!({
                "id": u.id,
                "path": path.to_string_lossy(),
                "meta_tags": u.meta_tags,
            }))).collect::<Vec<_>>(),
        });
        std::fs::create_dir_all(side_dir).map_err(internal("making the side's directory"))?;
        std::fs::write(
            side_dir.join(ace_yara::replay::JOB_FILE),
            serde_json::to_vec(&job).map_err(|e| ReplayError::Internal(e.to_string()))?,
        )
        .map_err(internal("writing the job"))?;

        match &self.child {
            Child::InProcess => {
                let dir = side_dir.to_path_buf();
                let output = blocking(move || {
                    let typer = ace_yara::mime::MimeTyper::open(Path::new(
                        ace_yara::mime::DEFAULT_DATABASE,
                    ))
                    .map_err(|e| ReplayError::Failed(e.to_string()))?;
                    let result = ace_yara::replay::run_with(&dir, &typer, true)
                        .map_err(|e| ReplayError::Failed(e.to_string()))?;
                    serde_json::to_value(&result).map_err(|e| ReplayError::Internal(e.to_string()))
                })
                .await?;
                check_cancel(cancel)?;
                Ok(output)
            }
            Child::Exec { program, args } => {
                self.exec(program, args, workdir, side_dir, cancel).await
            }
        }
    }

    async fn exec(
        &self,
        program: &Path,
        args: &[String],
        workdir: &Path,
        side_dir: &Path,
        cancel: &CancellationToken,
    ) -> Result<Value, ReplayError> {
        let timeout = self.config.scan_timeout;
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .arg("--read")
            .arg(workdir)
            .arg("--cpu-seconds")
            .arg(timeout.as_secs().to_string())
            .arg("--memory-mb")
            .arg(self.config.scan_memory_mb.to_string())
            .arg(side_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| ReplayError::Internal(format!("starting the scan: {e}")))?;
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut bytes = Vec::new();
            if let Err(e) = (&mut stderr).take(1 << 20).read_to_end(&mut bytes).await {
                tracing::debug!("reading the scan's stderr: {e}");
            }
            bytes
        });
        let status = tokio::select! {
            status = child.wait() => status.map_err(|e| ReplayError::Internal(format!("waiting for the scan: {e}")))?,
            () = tokio::time::sleep(timeout) => {
                if let Err(e) = child.kill().await {
                    tracing::warn!("unable to kill the scan: {e}");
                }
                return Err(ReplayError::Failed(format!(
                    "the scan timed out after {} seconds{}",
                    timeout.as_secs(),
                    progress(side_dir)
                )));
            }
            () = cancel.cancelled() => {
                if let Err(e) = child.kill().await {
                    tracing::warn!("unable to kill the scan: {e}");
                }
                return Err(ReplayError::Cancelled);
            }
        };
        let stderr = reader.await.unwrap_or_default();
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            let stderr = stderr.trim();
            let tail = &stderr[stderr.floor_char_boundary(stderr.len().saturating_sub(2048))..];
            let how = match status.code() {
                Some(code) => format!("exited with {code}"),
                None => {
                    use std::os::unix::process::ExitStatusExt;
                    format!(
                        "was killed by signal {}",
                        status.signal().unwrap_or_default()
                    )
                }
            };
            return Err(ReplayError::Failed(format!(
                "the scan {how}: {tail}{}",
                progress(side_dir)
            )));
        }
        let bytes = std::fs::read(side_dir.join(ace_yara::replay::RESULT_FILE))
            .map_err(|e| ReplayError::Failed(format!("the scan wrote no result: {e}")))?;
        let output: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ReplayError::Failed(format!("the scan's result is unreadable: {e}")))?;
        if output["version"].as_u64() != Some(u64::from(ace_yara::replay::PROTOCOL_VERSION)) {
            return Err(ReplayError::Failed(
                "the scan answered in another protocol version".to_owned(),
            ));
        }
        Ok(output)
    }
}
