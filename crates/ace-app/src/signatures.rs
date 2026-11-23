//! `ace signatures check`: what a signatures author runs before a push (PLAN.md 6.8).
//!
//! It checks a signatures checkout's working tree, as it is on disk, with the binary alone: no
//! database, bucket or stack. Two parts:
//!
//! - **YARA.** The rule directory (`yara/` by default) compiles as `ace-yara` compiles it for the
//!   ruleset builds (1.1, 2.25): each file alone, then the files together, then the ruleset
//!   serialized. ace3's loader, and ace4's builder after it, log a file that doesn't compile and
//!   leave it out; here that file is a failure, which is the point of the check. So is a file that
//!   compiles alone but not with the others, such as a second rule of one name in a namespace, which
//!   makes the whole load fail in both. yara-x's warnings, such as `deprecated_field` for
//!   `pe.number_of_signatures` (docs/decisions/0001-language.md), are listed against their file and
//!   don't fail the check unless `--deny-warnings` is given.
//! - **Hunts.** Each hunt type the binary has loads its rule directories (`hunts/<type>` by default)
//!   with 6.2's loader, so a hunt fails here with the error ace3's hunter would log for it. A hunt
//!   that loads is then checked for what ace3 only finds when it runs: each template it renders
//!   (6.3) must compile, its syntax and the filters and tests it names, since one that doesn't fails
//!   every render; and each custom correlation command type it names must be one the binary has,
//!   with valid options, as ace3's `ace hunt verify` checks (`check_custom_command_types`).
//!   Templates aren't rendered: their inputs are a search's rows, which a check doesn't have, and a
//!   render against an empty event says only which fields the template reads.
//!
//! - **Against a hunter's overlay**, with `--overlay FILE` (PLAN.md decision 41): the overlay is read
//!   and checked as every `ace` command checks it, and then each correlation `query` command's
//!   `source:` must be one of the query sources it defines (its `query_sources:`, or ace3's default
//!   `splunk`), of a type the binary has and built as `ace serve` builds them, with no secrets; and
//!   each Splunk hunt's `splunk_config` must be one of its Splunk instances, its connections of type
//!   `splunk`, as SplunkHunt looks it up when it is made. Without `--overlay` neither is checked.
//!
//! What it doesn't check: a query against its source, which 6.4's `hunt` router does with a live
//! client; hunt types the binary lacks, so the open-source `ace` checks the Splunk hunts and a site's
//! binary adds its own, such as LogScale; and the signatures repository's own pipelines (UUIDs,
//! observable types, file extensions).
//!
//! The report lists every rule file, then every hunt, in a stable order: namespaces and files by
//! name, hunt types by name and each type's hunts as its loader lists them. Paths are relative to
//! the checkout. The text form lists what failed or warned, with each error, then the counts;
//! `--json` writes the whole report. It exits 1 on any failure.
//!
//! ace3 has no such command. Its `ace signatures` lists the signatures a node loads and where from,
//! and its `ace hunt verify` loads the configured hunts; the signatures repository's
//! `validate-yara.yaml` pipeline compiles its YARA rules with yara_scanner_v2's `scan -c`, and its hunt
//! pipelines validate hunts against a live ACE. Running this check in that repository's CI is
//! Deferred's.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use ace_hunt::correlate::check::{custom_command_types, query_sources};
use ace_hunt::render::Renderer;
use ace_hunt::{HuntType, LoadOptions};
use ace_yara::{FileOutcome, LoadError};
use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::App;

#[derive(Subcommand)]
pub enum SignaturesCommand {
    /// Check a signatures checkout before a push: every YARA rule file compiles with yara-x and
    /// every hunt loads, with its templates. Exits 1 on any failure.
    Check(CheckArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    /// The signatures checkout.
    #[arg(default_value = ".")]
    pub checkout: PathBuf,
    /// The YARA rule directory, relative to the checkout: each subdirectory is a namespace.
    #[arg(long, default_value = "yara")]
    pub yara_dir: PathBuf,
    /// A hunt type's rule directory, relative to the checkout, as TYPE=DIR. Give it more than once
    /// for more. Without it, each hunt type the binary has reads `hunts/<type>`, when it's there.
    #[arg(long = "rule-dir", value_name = "TYPE=DIR")]
    pub rule_dirs: Vec<String>,
    /// Fail on yara-x's warnings too, such as a deprecated field.
    #[arg(long)]
    pub deny_warnings: bool,
    /// Write the whole report as JSON.
    #[arg(long)]
    pub json: bool,
    /// A hunter's site overlay: each correlation query's `source:` is checked against the query
    /// sources it defines, and each Splunk hunt's `splunk_config` against its Splunk instances.
    #[arg(long, value_name = "FILE")]
    pub overlay: Option<PathBuf>,
}

/// What the check found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub checkout: String,
    pub passed: bool,
    pub deny_warnings: bool,
    /// What the hunts were checked against, with `--overlay`.
    pub overlay: Option<OverlayReport>,
    pub counts: Counts,
    pub yara: YaraReport,
    /// Each hunt type's rule directories, by type.
    pub hunt_dirs: Vec<HuntDir>,
    pub hunts: Vec<HuntReport>,
}

/// The overlay a check read (`--overlay`): its path, the query sources it defines that the binary
/// builds, each one that didn't build with why, and its Splunk instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverlayReport {
    pub path: String,
    pub query_sources: Vec<String>,
    pub query_sources_failed: BTreeMap<String, String>,
    pub splunk_instances: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub rule_files: usize,
    pub rule_files_failed: usize,
    pub rules: usize,
    pub warnings: usize,
    pub hunts: usize,
    pub hunts_failed: usize,
    /// Failed rule files, failed hunts, a rule directory or hunt directory that couldn't be read or
    /// a ruleset that couldn't be serialized, and, with `--deny-warnings`, each warning.
    pub failures: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct YaraReport {
    pub dir: String,
    /// The serialized ruleset's key (1.6), when every file compiled together.
    pub ruleset: Option<String>,
    /// What failed for the directory as a whole: it couldn't be listed, or the ruleset couldn't be
    /// serialized.
    pub error: Option<String>,
    pub files: Vec<RuleFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleFile {
    pub path: String,
    pub namespace: String,
    pub rules: usize,
    pub error: Option<String>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HuntDir {
    #[serde(rename = "type")]
    pub kind: String,
    pub dir: String,
    /// Whether it's a directory. A default one that isn't is skipped; one given with
    /// `--rule-dir` fails the check.
    pub found: bool,
    pub given: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HuntReport {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    /// The hunt's name, when it loaded.
    pub name: Option<String>,
    pub errors: Vec<String>,
}

pub fn run(app: &App, command: SignaturesCommand) -> Result<ExitCode> {
    match command {
        SignaturesCommand::Check(args) => execute(app, &args, &mut std::io::stdout().lock()),
    }
}

/// Runs the check and writes its report to `out`.
pub fn execute(app: &App, args: &CheckArgs, out: &mut dyn Write) -> Result<ExitCode> {
    let report = check(app, args)?;
    if args.json {
        serde_json::to_writer_pretty(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        out.write_all(text(&report).as_bytes())?;
    }
    Ok(if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Checks the checkout. An Err is a usage error, such as a hunt type the binary doesn't have.
pub fn check(app: &App, args: &CheckArgs) -> Result<Report> {
    let checkout = &args.checkout;
    if !checkout.is_dir() {
        bail!("{} isn't a directory", checkout.display());
    }
    let dirs = hunt_dirs(app, args)?;
    let overlay = match &args.overlay {
        None => None,
        Some(path) => Some(overlay_report(app, path)?),
    };

    let yara = check_yara(checkout, &args.yara_dir);
    let renderer = Renderer::default();
    let command_types = app.command_types();
    let options = LoadOptions {
        home: checkout.clone(),
        ..LoadOptions::default()
    };
    let mut hunts = Vec::new();
    for (kind, kind_dirs) in dirs.values() {
        let found: Vec<PathBuf> = kind_dirs
            .iter()
            .filter(|d| d.found)
            .map(|d| checkout.join(&d.dir))
            .collect();
        for loaded in ace_hunt::load_hunts(kind.as_ref(), &found, &options) {
            let path = relative(checkout, &loaded.path);
            let (name, errors) = match loaded.result {
                Err(e) => (None, vec![e.to_string()]),
                Ok(hunt) => {
                    let mut errors = Vec::new();
                    for (at, template) in hunt.config.templates() {
                        // ace3 renders a name only when it holds a tag (`_render_name`)
                        if at == "name" && !template.contains("{{") && !template.contains("{%") {
                            continue;
                        }
                        if let Err(e) = renderer.check(template) {
                            errors.push(format!("template {at}: {e}"));
                        }
                    }
                    errors.extend(custom_command_types(
                        hunt.config.correlate.as_ref(),
                        Some(&hunt.commands),
                        &command_types,
                    ));
                    if let Some(overlay) = &overlay {
                        errors.extend(against_overlay(kind.as_ref(), &hunt, overlay));
                    }
                    (Some(hunt.config.name.clone()), errors)
                }
            };
            hunts.push(HuntReport {
                kind: kind.name().to_owned(),
                path,
                name,
                errors,
            });
        }
    }

    let hunt_dirs: Vec<HuntDir> = dirs.into_values().flat_map(|(_, d)| d).collect();
    let warnings: usize = yara.files.iter().map(|f| f.warnings.len()).sum();
    let rule_files_failed = yara.files.iter().filter(|f| f.error.is_some()).count();
    let hunts_failed = hunts.iter().filter(|h| !h.errors.is_empty()).count();
    let failures = rule_files_failed
        + usize::from(yara.error.is_some())
        + hunts_failed
        + hunt_dirs.iter().filter(|d| d.given && !d.found).count()
        + if args.deny_warnings { warnings } else { 0 };
    let counts = Counts {
        rule_files: yara.files.len(),
        rule_files_failed,
        rules: yara.files.iter().map(|f| f.rules).sum(),
        warnings,
        hunts: hunts.len(),
        hunts_failed,
        failures,
    };
    Ok(Report {
        checkout: checkout.display().to_string(),
        passed: failures == 0,
        deny_warnings: args.deny_warnings,
        overlay,
        counts,
        yara,
        hunt_dirs,
        hunts,
    })
}

/// Reads the overlay at `path` and checks it as `ace` does; an error is a usage error. Its query
/// sources are those `ace serve` would build to validate hunts with.
fn overlay_report(app: &App, path: &Path) -> Result<OverlayReport> {
    let overlay = ace_sdk::Overlay::read(path)
        .map_err(|e| anyhow::anyhow!("the overlay {}: {e}", path.display()))?;
    app.check_overlay(&overlay)
        .map_err(|e| anyhow::anyhow!("the overlay {}: {e}", path.display()))?;
    let (sources, failed) = crate::hunter::validation_sources_and_failures(app, &overlay);
    let splunk = <ace_mod_splunk::connection::Splunk as ace_sdk::ConnectionType>::NAME;
    Ok(OverlayReport {
        path: path.display().to_string(),
        query_sources: sources.names().into_iter().map(str::to_owned).collect(),
        query_sources_failed: failed.into_iter().collect(),
        splunk_instances: overlay
            .connections
            .iter()
            .filter(|(_, c)| c.kind == splunk)
            .map(|(name, _)| name.clone())
            .collect(),
    })
}

/// What `overlay` says of a hunt that loaded: its correlation's query sources, and a Splunk hunt's
/// instance.
fn against_overlay(
    kind: &dyn HuntType,
    hunt: &ace_hunt::Hunt,
    overlay: &OverlayReport,
) -> Vec<String> {
    let sources: Vec<&str> = overlay.query_sources.iter().map(String::as_str).collect();
    let mut errors: Vec<String> = query_sources(
        hunt.config.correlate.as_ref(),
        Some(&hunt.commands),
        &sources,
    )
    .into_iter()
    .map(|e| {
        match overlay.query_sources_failed.iter().find(|(name, _)| {
            e.contains(&format!("source {} isn't", ace_hunt::value::py_repr(name)))
        }) {
            Some((name, why)) => format!("{e} ({name} is defined but didn't build: {why})"),
            None => e,
        }
    })
    .collect();
    if kind.name() == "splunk" {
        let splunk = ace_hunt::types::Splunk {
            instances: Some(overlay.splunk_instances.clone()),
        };
        if let Err(e) = splunk.on_load(&hunt.config) {
            errors.push(format!(
                "{e}; the overlay's Splunk instances are {}",
                if overlay.splunk_instances.is_empty() {
                    "none".to_owned()
                } else {
                    overlay.splunk_instances.join(", ")
                }
            ));
        }
    }
    errors
}

/// Each hunt type to check by its name, with its rule directories.
type TypeDirs = BTreeMap<String, (Arc<dyn HuntType>, Vec<HuntDir>)>;

/// Each hunt type to check, by name, with its rule directories: those `--rule-dir` gives, or
/// `hunts/<type>` for each type the binary has.
fn hunt_dirs(app: &App, args: &CheckArgs) -> Result<TypeDirs> {
    let kind_of = |name: &str| -> Result<Arc<dyn HuntType>> {
        match app.hunt_types().iter().find(|k| k.name() == name) {
            Some(kind) => Ok(Arc::clone(kind)),
            None => {
                let mut names: Vec<&str> = app.hunt_types().iter().map(|k| k.name()).collect();
                names.sort_unstable();
                bail!(
                    "this binary has no hunt type {name:?}; it has {}",
                    names.join(", ")
                )
            }
        }
    };
    let found = |dir: &Path| args.checkout.join(dir).is_dir();
    let mut dirs: TypeDirs = BTreeMap::new();
    if args.rule_dirs.is_empty() {
        for kind in app.hunt_types() {
            let dir = Path::new("hunts").join(kind.name());
            dirs.insert(
                kind.name().to_owned(),
                (
                    Arc::clone(kind),
                    vec![HuntDir {
                        kind: kind.name().to_owned(),
                        dir: dir.display().to_string(),
                        found: found(&dir),
                        given: false,
                    }],
                ),
            );
        }
    }
    for spec in &args.rule_dirs {
        let Some((name, dir)) = spec.split_once('=') else {
            bail!("--rule-dir {spec:?} isn't TYPE=DIR");
        };
        let kind = kind_of(name)?;
        let entry = dirs
            .entry(name.to_owned())
            .or_insert_with(|| (kind, Vec::new()));
        entry.1.push(HuntDir {
            kind: name.to_owned(),
            dir: dir.to_owned(),
            found: found(Path::new(dir)),
            given: true,
        });
    }
    Ok(dirs)
}

/// The path relative to the checkout, with `/` between its parts.
fn relative(checkout: &Path, path: &Path) -> String {
    path.strip_prefix(checkout)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn check_yara(checkout: &Path, yara_dir: &Path) -> YaraReport {
    let dir = checkout.join(yara_dir);
    let mut report = YaraReport {
        dir: yara_dir.display().to_string(),
        ruleset: None,
        error: None,
        files: Vec::new(),
    };
    let file = |report: &ace_yara::FileReport| {
        let (rules, error) = match &report.outcome {
            FileOutcome::Included { rules } => (rules.len(), None),
            FileOutcome::LeftOut { error } => (0, Some(error.clone())),
        };
        RuleFile {
            path: relative(checkout, &report.path),
            namespace: report.namespace.clone(),
            rules,
            error,
            warnings: Vec::new(),
        }
    };
    let loaded = match ace_yara::load_dir(&dir, &ace_yara::LoadOptions::default()) {
        Ok(loaded) => loaded,
        Err(LoadError::Combined { path, error, files }) => {
            report.files = files.iter().map(file).collect();
            let at = relative(checkout, &path);
            match report.files.iter_mut().find(|f| f.path == at) {
                Some(f) => {
                    f.error = Some(format!(
                        "it compiles alone but not with the files before it: {error}"
                    ));
                }
                None => {
                    report.error = Some(format!(
                        "the rule files compile alone but not together, at {at}: {error}"
                    ));
                }
            }
            return report;
        }
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };
    report.files = loaded.files.iter().map(file).collect();
    for warning in &loaded.warnings {
        let target = warning.origin.as_deref().and_then(|origin| {
            let (namespace, name) = origin.split_once('/')?;
            report.files.iter_mut().find(|f| {
                f.namespace == namespace
                    && Path::new(&f.path).file_name() == Some(std::ffi::OsStr::new(name))
            })
        });
        let warning = Warning {
            code: warning.code.clone(),
            text: warning.text.clone(),
        };
        match target {
            Some(f) => f.warnings.push(warning),
            // yara-x names every warning's source; this keeps one that names none
            None => {
                if let Some(f) = report.files.first_mut() {
                    f.warnings.push(warning);
                }
            }
        }
    }
    match loaded.ruleset.rules().serialize() {
        Ok(bytes) => report.ruleset = Some(ace_yara::ruleset::key(&bytes)),
        Err(e) => report.error = Some(format!("unable to serialize the ruleset: {e}")),
    }
    report
}

/// The text form: each failure and warning with its error, then the counts.
pub fn text(report: &Report) -> String {
    let mut out = String::new();
    // writing to a String doesn't fail
    write_text(report, &mut out).expect("writing to a String");
    out
}

fn write_text(report: &Report, out: &mut String) -> std::fmt::Result {
    use std::fmt::Write as _;
    let indent = |text: &str| -> String {
        text.trim_end()
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect()
    };
    if let Some(error) = &report.yara.error {
        write!(out, "FAIL {}\n{}", report.yara.dir, indent(error))?;
    }
    let warned = if report.deny_warnings { "FAIL" } else { "WARN" };
    for file in &report.yara.files {
        if let Some(error) = &file.error {
            write!(out, "FAIL {}\n{}", file.path, indent(error))?;
        }
        for warning in &file.warnings {
            write!(
                out,
                "{warned} {} ({})\n{}",
                file.path,
                warning.code,
                indent(&warning.text)
            )?;
        }
    }
    for dir in &report.hunt_dirs {
        if dir.given && !dir.found {
            writeln!(
                out,
                "FAIL {}\n    the {} rule directory isn't a directory",
                dir.dir, dir.kind
            )?;
        }
    }
    for hunt in &report.hunts {
        if hunt.errors.is_empty() {
            continue;
        }
        writeln!(out, "FAIL {}", hunt.path)?;
        for error in &hunt.errors {
            out.push_str(&indent(error));
        }
    }

    let c = &report.counts;
    if !out.is_empty() {
        out.push('\n');
    }
    writeln!(
        out,
        "yara ({}): {}, {} failed, {}, {}{}",
        report.yara.dir,
        count(c.rule_files, "rule file"),
        c.rule_files_failed,
        count(c.rules, "rule"),
        count(c.warnings, "warning"),
        if report.deny_warnings && c.warnings > 0 {
            ", which fail"
        } else {
            ""
        }
    )?;
    let mut checked: Vec<String> = Vec::new();
    for dir in &report.hunt_dirs {
        if dir.found {
            checked.push(format!("{} in {}", dir.kind, dir.dir));
        } else if !dir.given {
            checked.push(format!("{}: no {}", dir.kind, dir.dir));
        }
    }
    writeln!(
        out,
        "hunts ({}): {}, {} failed",
        if checked.is_empty() {
            "no hunt types".to_owned()
        } else {
            checked.join("; ")
        },
        count(c.hunts, "hunt"),
        c.hunts_failed
    )?;
    if let Some(overlay) = &report.overlay {
        let list = |names: &[String]| {
            if names.is_empty() {
                "none".to_owned()
            } else {
                names.join(", ")
            }
        };
        writeln!(
            out,
            "overlay ({}): query sources {}; splunk instances {}",
            overlay.path,
            list(&overlay.query_sources),
            list(&overlay.splunk_instances)
        )?;
        for (name, why) in &overlay.query_sources_failed {
            writeln!(out, "    query source {name} didn't build: {why}")?;
        }
    }
    if report.passed {
        writeln!(out, "signatures check passed")?;
    } else {
        writeln!(
            out,
            "signatures check failed: {}",
            count(c.failures, "failure")
        )?;
    }
    Ok(())
}

/// `1 hunt`, `2 hunts`.
fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

#[cfg(test)]
mod tests;
