//! The SVS replay child on yara-x: ace3's `saq/svs/yara/child.py`, with pattern offsets, as
//! `tools/ace3/yara/child.py` extends it (PLAN.md 1.9 and 1.10).
//!
//! It reads a `job.json` in the shape ace3's `saq/svs/yara/replay.py` writes, and returns the
//! result `child.py` writes to `result.json`:
//!
//! 1. every rule file compiles alone, and the ones that do compile together. If they don't,
//!    the result has a `ruleset_error` and nothing is scanned;
//! 2. each namespace then compiles alone, and every unit is scanned with it, so each
//!    namespace is timed. Namespaces are independent in YARA, so the union of their matches is
//!    what the combined rules match.
//!
//! Each match carries `strings`, `[offset, identifier, length]` for every occurrence of every
//! pattern, and each unit lists the matches the meta filter `dropped` beside the ones it kept.
//!
//! Where ace4 differs from ace3, the result says what ace4 does: a rule file that isn't UTF-8
//! is left out instead of failing the whole load, a `re:` item the regex crate rejects leaves
//! its file out, the mime type comes from libmagic once per unit instead of `file` once per
//! scan, and `combined_compile_seconds` includes compiling each file alone.
//!
//! With the `rules-profiling` feature, the result also lists the slowest rules over the whole
//! replay: yara-x's slowest-rule report, which replaces yara_scanner_v2's timing harness.
//! yara-x lists only rules that took over 100 ms in all, so a fast replay lists none.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::load::{self, FileOutcome, FileReport, LoadError, LoadOptions, Namespace};
use crate::meta::Meta;
use crate::mime::MimeTyper;
use crate::scan::{Match, RuleTime, ScanError, ScanRequest, Scanner};

/// How many rules the slowest-rule report lists.
pub const SLOWEST_RULES: usize = 20;

pub const PROTOCOL_VERSION: u32 = 1;
pub const JOB_FILE: &str = "job.json";
pub const RESULT_FILE: &str = "result.json";
/// Rewritten after each namespace is scanned, so a run that is stopped says how far it got.
pub const PROGRESS_FILE: &str = "progress.json";

/// replay.py's job.
#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub version: u32,
    pub tree_root: String,
    /// Seconds one scan may take: ace3's service_yara.default_timeout.
    pub file_timeout: f64,
    pub namespaces: Vec<JobNamespace>,
    pub units: Vec<JobUnit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JobNamespace {
    pub name: String,
    pub directory: PathBuf,
    pub files: Vec<PathBuf>,
}

/// One way a file was scanned: its path, which sets the path externals and filters, and its
/// meta tags.
#[derive(Debug, Clone, Deserialize)]
pub struct JobUnit {
    pub id: u64,
    pub path: String,
    pub meta_tags: Vec<String>,
}

/// child.py's result, with offsets.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayResult {
    pub version: u32,
    /// Which child wrote it.
    pub child: &'static str,
    pub yara_x_version: &'static str,
    pub files: Vec<FileEntry>,
    pub ruleset_error: Option<String>,
    pub warnings: Vec<String>,
    /// ace3 reports includes that resolve outside the repository; ace4 reports none.
    pub include_warnings: Vec<String>,
    pub namespaces: BTreeMap<String, NamespaceTiming>,
    pub units: BTreeMap<String, UnitOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined_compile_seconds: Option<f64>,
    /// The slowest rules over every unit, slowest first. Only a build with the
    /// `rules-profiling` feature records them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slowest_rules: Option<Vec<RuleTime>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub namespace: String,
    pub error: Option<String>,
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleEntry {
    pub name: String,
    pub meta: Meta,
    pub tags: Vec<String>,
    pub private: bool,
    pub global: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NamespaceTiming {
    pub compile_seconds: f64,
    pub scan_seconds: f64,
    pub rules: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnitOutcome {
    pub matches: Vec<MatchEntry>,
    pub dropped: Vec<MatchEntry>,
    pub errors: Vec<UnitError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchEntry {
    pub namespace: String,
    pub rule: String,
    pub meta: Meta,
    /// `[offset, identifier, length]` for every occurrence of every pattern.
    pub strings: Vec<(usize, String, usize)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnitError {
    pub namespace: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub struct ReplayError(String);

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReplayError {}

/// Reads the job in `workdir`.
pub fn read_job(workdir: &Path) -> Result<Job, ReplayError> {
    let path = workdir.join(JOB_FILE);
    let bytes = std::fs::read(&path)
        .map_err(|e| ReplayError(format!("unable to read {}: {e}", path.display())))?;
    let job: Job = serde_json::from_slice(&bytes)
        .map_err(|e| ReplayError(format!("unable to parse {}: {e}", path.display())))?;
    if job.version != PROTOCOL_VERSION {
        return Err(ReplayError(format!(
            "job protocol version {} is not {PROTOCOL_VERSION}",
            job.version
        )));
    }
    Ok(job)
}

/// Writes `value` as JSON to `workdir/name` through a temporary file, so a reader never sees
/// half of it.
pub fn write_json<T: Serialize>(workdir: &Path, name: &str, value: &T) -> Result<(), ReplayError> {
    let path = workdir.join(name);
    let temporary = workdir.join(format!("{name}.tmp"));
    let bytes = serde_json::to_vec(value)
        .map_err(|e| ReplayError(format!("unable to write {name}: {e}")))?;
    std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, &path))
        .map_err(|e| ReplayError(format!("unable to write {}: {e}", path.display())))
}

fn file_entry(report: &FileReport) -> FileEntry {
    let (error, rules) = match &report.outcome {
        FileOutcome::Included { rules } => (
            None,
            rules
                .iter()
                .map(|r| RuleEntry {
                    name: r.name.clone(),
                    meta: r.meta.clone(),
                    tags: r.tags.clone(),
                    private: r.private,
                    global: r.global,
                })
                .collect(),
        ),
        FileOutcome::LeftOut { error } => (Some(error.clone()), Vec::new()),
    };
    FileEntry {
        path: report.path.to_string_lossy().into_owned(),
        namespace: report.namespace.clone(),
        error,
        rules,
    }
}

fn match_entry(found: &Match) -> MatchEntry {
    MatchEntry {
        namespace: found.namespace.clone(),
        rule: found.rule.clone(),
        meta: found.meta.clone(),
        strings: found
            .patterns
            .iter()
            .map(|p| (p.offset, p.identifier.clone(), p.length))
            .collect(),
    }
}

/// Runs the job in `workdir`, typing each unit's mime type with `typer`. Writes
/// `progress.json` there as it goes; the caller writes the result.
pub fn run(workdir: &Path, typer: &MimeTyper) -> Result<ReplayResult, ReplayError> {
    let job = read_job(workdir)?;
    let mut result = ReplayResult {
        version: PROTOCOL_VERSION,
        child: "ace4",
        yara_x_version: yara_x::VERSION,
        files: Vec::new(),
        ruleset_error: None,
        warnings: Vec::new(),
        include_warnings: Vec::new(),
        namespaces: BTreeMap::new(),
        units: BTreeMap::new(),
        combined_compile_seconds: None,
        slowest_rules: None,
    };

    let namespaces: Vec<Namespace> = job
        .namespaces
        .iter()
        .map(|n| Namespace {
            name: n.name.clone(),
            dir: n.directory.clone(),
            files: n.files.clone(),
        })
        .collect();
    let options = LoadOptions::default();

    // 1. each file alone, then the survivors together
    let started = Instant::now();
    let loaded = match load::compile(&namespaces, &options) {
        Ok(loaded) => loaded,
        Err(LoadError::Combined { path, error, files }) => {
            result.files = files.iter().map(file_entry).collect();
            result.ruleset_error = Some(format!("{}: {error}", path.display()));
            return Ok(result);
        }
        Err(e) => return Err(ReplayError(e.to_string())),
    };
    result.combined_compile_seconds = Some(started.elapsed().as_secs_f64());
    result.files = loaded.files.iter().map(file_entry).collect();
    result.warnings = loaded.warnings.iter().map(|w| w.text.clone()).collect();
    drop(loaded.ruleset);

    // 2. each namespace on its own, scanning every unit
    #[cfg(feature = "rules-profiling")]
    let mut slowest: Vec<RuleTime> = Vec::new();
    let mut mime_types: BTreeMap<u64, Result<String, String>> = BTreeMap::new();
    let timeout = Duration::from_secs_f64(job.file_timeout);
    for namespace in &namespaces {
        let survivors: Vec<PathBuf> = loaded
            .files
            .iter()
            .filter(|f| f.namespace == namespace.name && f.is_included())
            .map(|f| f.path.clone())
            .collect();
        if survivors.is_empty() {
            continue;
        }

        let started = Instant::now();
        let alone = Namespace {
            files: survivors,
            ..namespace.clone()
        };
        let (ruleset, _) = load::compile_together(std::slice::from_ref(&alone), &options)
            .map_err(|e| ReplayError(e.to_string()))?;
        let mut timing = NamespaceTiming {
            compile_seconds: started.elapsed().as_secs_f64(),
            rules: ruleset.rules().iter().count(),
            ..NamespaceTiming::default()
        };

        let started = Instant::now();
        let mut scanner = Scanner::new(&ruleset);
        for unit in &job.units {
            let outcome = result.units.entry(unit.id.to_string()).or_default();
            let error = |kind, message| UnitError {
                namespace: namespace.name.clone(),
                kind,
                message,
            };

            let data = match std::fs::read(&unit.path) {
                Ok(data) => data,
                Err(e) => {
                    outcome
                        .errors
                        .push(error("error", format!("unable to read {}: {e}", unit.path)));
                    continue;
                }
            };
            let mime_type = match mime_types
                .entry(unit.id)
                .or_insert_with(|| typer.mime_type(&data).map_err(|e| e.to_string()))
            {
                Ok(mime_type) => mime_type.clone(),
                Err(e) => {
                    outcome.errors.push(error("error", e.clone()));
                    continue;
                }
            };

            match scanner.scan(&ScanRequest {
                data: &data,
                path: &unit.path,
                mime_type: &mime_type,
                meta_tags: &unit.meta_tags,
                timeout: Some(timeout),
            }) {
                Ok(scanned) => {
                    outcome
                        .matches
                        .extend(scanned.matches.iter().map(match_entry));
                    outcome
                        .dropped
                        .extend(scanned.dropped.iter().map(match_entry));
                }
                Err(ScanError::Timeout) => outcome.errors.push(error("timeout", "timeout".into())),
                Err(e) => outcome.errors.push(error("error", e.to_string())),
            }
        }
        timing.scan_seconds = started.elapsed().as_secs_f64();
        #[cfg(feature = "rules-profiling")]
        slowest.extend(scanner.slowest_rules(SLOWEST_RULES));
        result.namespaces.insert(namespace.name.clone(), timing);
        write_json(
            workdir,
            PROGRESS_FILE,
            &serde_json::json!({"namespaces": result.namespaces}),
        )?;
    }

    #[cfg(feature = "rules-profiling")]
    {
        slowest.sort_by(|a, b| b.total_seconds().total_cmp(&a.total_seconds()));
        slowest.truncate(SLOWEST_RULES);
        result.slowest_rules = Some(slowest);
    }

    Ok(result)
}
