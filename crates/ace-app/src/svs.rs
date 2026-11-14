//! `ace svs`: ace3's `saq/cli/commands/svs.py`, as far as SVS is ported (PLAN.md 7.10).
//!
//! `yara validate` replays every stored sample under two commits of a rule repository and prints what
//! changed, synchronously and without storing anything (ace3's `docs/SVS_VALIDATION.md`); the validations a
//! CI requests are run by `ace serve`'s workers instead. Its scans run in this binary again, contained, as
//! the workers' do. `yara layout` prints which directory of each repository in `svs.yara.repositories` the
//! YARA pool loads. `yara prune` removes the validations older than `svs.yara.retention_days`, as the
//! scheduler's `svs_validations_prune` does daily, acting as that task's component.
//!
//! What differs from ace3: ace3's prune skips a node that isn't the primary one unless given `--force`; ace4
//! has no primary node (every replica shares the queue), so there's no `--force`. ace3's catalog and
//! coverage commands come with batches 4 and 8.

use std::process::ExitCode;

use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::db::{Db, DbConfig};
use ace_core::svs::yara::ValidationConfig;
use ace_core::svs::yara::diff::Category;
use ace_core::svs::yara::replay::{
    Child, Replay, ReplayError, ReplayRequest, ReplayResult, Replayer, SideReport,
};
use ace_store::{BucketConfig, NodeCache, Store};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tokio_util::sync::CancellationToken;

/// A line of the report: `format!`'s arguments, and a line break.
macro_rules! put {
    ($out:expr, $($arg:tt)*) => {{
        $out.push_str(&format!($($arg)*));
        $out.push('\n');
    }};
}

#[derive(Subcommand)]
pub enum SvsCommand {
    /// YARA rule validation.
    #[command(subcommand)]
    Yara(SvsYaraCommand),
}

#[derive(Subcommand)]
pub enum SvsYaraCommand {
    /// Replay the samples under two commits and print what changed.
    Validate(ValidateArgs),
    /// Print which directory of each repository the YARA pool loads.
    Layout,
    /// Remove the validations older than svs.yara.retention_days.
    Prune(PruneArgs),
}

#[derive(Args)]
pub struct ValidateArgs {
    /// A repository named in svs.yara.repositories.
    #[arg(long)]
    pub repository: String,
    /// The commit to compare against (the merge base of a pull request).
    #[arg(long)]
    pub base: String,
    /// The commit to validate.
    #[arg(long)]
    pub head: String,
    /// The branch the head commit is on (default: the repository's branch).
    #[arg(long)]
    pub branch: Option<String>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct PruneArgs {
    /// Count them without removing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// The report's bands, most urgent first: ace3's `REPORT_BANDS`.
const REPORT_BANDS: &[(Category, &str)] = &[
    (Category::Regression, "Regressions"),
    (
        Category::RegressionUnconfirmed,
        "Regressions on unconfirmed labels (check that the sample was ever a real hit for the rule)",
    ),
    (Category::NewFp, "New false positives"),
    (
        Category::NewFpOtherRule,
        "New false positives on another rule's sample",
    ),
    (Category::RuleRemoved, "Samples of rules head removed"),
    (Category::ScanError, "Scan errors"),
    (Category::Recovered, "Recovered"),
    (Category::Improvement, "Improvements"),
    (Category::AlreadyBroken, "Already broken on base"),
    (
        Category::NewMatchRealHit,
        "New matches on files that are a real hit for another rule",
    ),
    (Category::UnlabeledChange, "Unlabeled changes"),
];

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

fn side(out: &mut String, name: &str, side: &SideReport) {
    let namespaces = if side.namespaces.is_empty() {
        "none".to_owned()
    } else {
        side.namespaces.join(", ")
    };
    put!(
        out,
        "{name} {}: {} rules in {} namespaces ({namespaces})",
        short(&side.sha),
        side.rule_count,
        side.timings.len()
    );
    for namespace in &side.absent_namespaces {
        put!(out, "  namespace {namespace} does not exist in this commit");
    }
    for error in &side.file_errors {
        put!(
            out,
            "  {} does not compile, its {} rule(s) are dropped: {}",
            error.file,
            error.dropped.len(),
            error.error
        );
    }
    if let Some(error) = &side.ruleset_error {
        put!(
            out,
            "  the ruleset would not load, so production keeps its previous rules: {error}"
        );
    }
    for warning in &side.include_warnings {
        let text = |key: &str| warning[key].as_str().unwrap_or_default().to_owned();
        put!(
            out,
            "  {}: include {}: {}",
            text("file"),
            text("include"),
            text("error")
        );
    }
    for item in &side.not_loaded {
        put!(out, "  not loaded: {} ({})", item.path, item.reason);
    }
    for (path, reason) in &side.skipped_members {
        put!(out, "  not exported: {path} ({reason})");
    }
}

fn none_or(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("None")
}

/// The report ace3's `print_report` prints.
pub fn report(result: &ReplayResult) -> String {
    let mut out = String::new();
    put!(
        out,
        "repository {}: base {}, head {}",
        result.repository,
        short(&result.base_sha),
        short(&result.head_sha)
    );
    put!(
        out,
        "corpus: {} files, {} scans, {} samples, {} bytes ({:.1}s)",
        result.files,
        result.units,
        result.samples,
        result.bytes,
        result.duration_seconds
    );
    if !result.skipped.is_empty() {
        put!(out, "  {} not replayed:", result.skipped.len());
        for skipped in &result.skipped {
            let line = format!(
                "    {} {} {} {}",
                skipped.sha256,
                skipped.file_path.as_deref().unwrap_or_default(),
                skipped.reason,
                skipped.detail
            );
            put!(out, "{}", line.trim_end());
        }
    }
    if result.truncated_paths > 0 {
        put!(
            out,
            "  {} scans use a path that was cut when it was stored",
            result.truncated_paths
        );
    }
    side(&mut out, "base", &result.base);
    side(&mut out, "head", &result.head);

    put!(
        out,
        "rules: {} added, {} removed, {} changed",
        result.added_rules.len(),
        result.removed_rules.len(),
        result.changed_rules.len()
    );
    for (label, refs) in [
        ("added", &result.added_rules),
        ("removed", &result.removed_rules),
        ("changed", &result.changed_rules),
    ] {
        for rule in refs {
            put!(
                out,
                "  {label} {} ({}) in {}",
                rule.name,
                none_or(&rule.uuid),
                rule.file
            );
        }
    }
    if !result.diffed {
        put!(out, "nothing was compared: a ruleset would not load");
        return out;
    }

    let counts: Vec<String> = Category::ALL
        .iter()
        .filter_map(|c| {
            let count = result.counts.get(c.as_str()).copied().unwrap_or(0);
            (count > 0).then(|| format!("{} {count}", c.as_str()))
        })
        .collect();
    put!(out, "counts: {}", counts.join(", "));
    for (category, heading) in REPORT_BANDS {
        let rows: Vec<_> = result
            .rows
            .iter()
            .filter(|r| r.category == *category)
            .collect();
        if rows.is_empty() {
            continue;
        }
        put!(out, "{heading} ({}):", rows.len());
        for row in rows {
            let label = match (&row.label, row.category) {
                (Some(label), _) => format!("{label} ({})", none_or(&row.label_source)),
                (None, Category::NewFpOtherRule | Category::NewMatchRealHit) => {
                    "another rule's sample".to_owned()
                }
                (None, _) => "unlabeled".to_owned(),
            };
            let note = row
                .note
                .as_ref()
                .map(|n| format!(" -- {n}"))
                .unwrap_or_default();
            put!(
                out,
                "  {} {} ({}) {label}: base {}, head {}{note}",
                row.sha256,
                row.rule_name,
                row.rule_uuid,
                row.base.as_str(),
                row.head.as_str()
            );
        }
    }
    for item in &result.not_testable {
        put!(
            out,
            "not testable: {} ({}) in {}: {}",
            item.name,
            none_or(&item.uuid),
            item.file,
            item.reason
        );
    }
    for rule in &result.full_path_rules {
        put!(
            out,
            "filters on full_path, which a replay cannot reproduce: {} ({}) in {}",
            rule.name,
            none_or(&rule.uuid),
            rule.file
        );
    }
    for warning in &result.head.warnings {
        put!(out, "head compiler warning: {warning}");
    }
    put!(out, "scan time per namespace (base / head):");
    let namespaces: std::collections::BTreeSet<&String> = result
        .base
        .timings
        .keys()
        .chain(result.head.timings.keys())
        .collect();
    for namespace in namespaces {
        let time = |side: &SideReport| {
            side.timings
                .get(namespace)
                .map_or("-".to_owned(), |t| format!("{:.2}s", t.scan_seconds))
        };
        put!(
            out,
            "  {namespace}: {} / {}",
            time(&result.base),
            time(&result.head)
        );
    }
    out
}

/// `ace svs yara validate` over `replay`: the report or the result's JSON on stdout and 0, or the failure
/// on stderr and 1.
pub async fn validate(
    args: &ValidateArgs,
    replay: &dyn Replay,
    retired: std::collections::BTreeSet<(String, String)>,
    stdout: &mut String,
    stderr: &mut String,
) -> u8 {
    let request = ReplayRequest {
        repository: args.repository.clone(),
        base_sha: args.base.clone(),
        head_sha: args.head.clone(),
        branch: args.branch.clone(),
        // a retired sample is only counted, as the workers count it
        retired,
    };
    match replay.replay(&request, &CancellationToken::new()).await {
        Ok(result) => {
            if args.json {
                put!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            } else {
                stdout.push_str(&report(&result));
            }
            0
        }
        Err(ReplayError::Cancelled) => {
            put!(stderr, "validation failed: it was cancelled");
            1
        }
        Err(ReplayError::Failed(e) | ReplayError::Internal(e)) => {
            put!(stderr, "validation failed: {e}");
            1
        }
    }
}

/// `ace svs yara layout`: one line per namespace source of each repository.
pub fn layout(config: &ValidationConfig) -> String {
    let mut out = String::new();
    for name in config.repositories.keys() {
        match config.layout(name) {
            Ok(layout) if layout.signature_dir.is_empty() => {
                put!(
                    out,
                    "{name}: every directory of the repository root is a namespace"
                );
            }
            Ok(layout) => {
                put!(
                    out,
                    "{name}: every directory of {} is a namespace",
                    layout.signature_dir
                );
            }
            Err(e) => {
                put!(out, "{name}: {e}");
            }
        }
    }
    out
}

/// `ace svs yara prune`'s line.
pub async fn prune(service: &ace_service::Service, dry_run: bool) -> Result<String> {
    let actor = ace_service::Actor::Internal {
        id: ace_service::Component::new("scheduler:svs_validations_prune")
            .map_err(anyhow::Error::msg)?,
    };
    Ok(if dry_run {
        let count = service.prunable_svs_validations(&actor).await?;
        format!("would remove {count} validations\n")
    } else {
        let done = service.prune_svs_validations(&actor).await?;
        format!("removed {} validations\n", done.removed)
    })
}

pub fn run(_app: &crate::App, command: SvsCommand) -> Result<ExitCode> {
    let SvsCommand::Yara(command) = command;
    let overlay = crate::cli::overlay()?;
    let config = ValidationConfig::from_section(&overlay.svs.yara)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.yara section")?;
    if let SvsYaraCommand::Layout = command {
        print!("{}", layout(&config));
        return Ok(ExitCode::SUCCESS);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        let dispositions = ace_service::Dispositions::configured(&overlay)
            .map_err(anyhow::Error::msg)
            .context("the overlay's disposition sections")?;
        let (tp, fp) = dispositions.classes().lists();
        match command {
            SvsYaraCommand::Layout => unreachable!("printed above"),
            SvsYaraCommand::Prune(args) => {
                let orchestrator = ace_core::orchestrator::Orchestrator::new(
                    ace_core::eligibility::Catalog::new(vec![]),
                    ace_core::modes::Modes::ace3(),
                );
                let service = ace_service::Service::new(db, orchestrator)
                    .with_dispositions(dispositions)
                    .with_validation(config);
                print!("{}", prune(&service, args.dry_run).await?);
                Ok(ExitCode::SUCCESS)
            }
            SvsYaraCommand::Validate(args) => {
                let cache = tempfile::tempdir().context("a cache directory")?;
                let store = Store::new(
                    &BucketConfig::from_env()?,
                    NodeCache::new(cache.path(), 1 << 30).context("the cache")?,
                );
                let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
                let retired = ace_core::svs::validations::retired_pairs(&db).await?;
                let replayer = Replayer {
                    db,
                    bucket,
                    config,
                    tp,
                    fp,
                    child: Child::this_binary().map_err(anyhow::Error::msg)?,
                };
                let (mut stdout, mut stderr) = (String::new(), String::new());
                let code = validate(&args, &replayer, retired, &mut stdout, &mut stderr).await;
                print!("{stdout}");
                eprint!("{stderr}");
                Ok(ExitCode::from(code))
            }
        }
    })
}

#[cfg(test)]
mod tests;
