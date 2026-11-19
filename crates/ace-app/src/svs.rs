//! `ace svs`: ace3's `saq/cli/commands/svs.py`, as far as SVS is ported (PLAN.md 7.10).
//!
//! `yara validate` replays every stored sample under two commits of a rule repository and prints what
//! changed, synchronously and without storing anything (ace3's `docs/SVS_VALIDATION.md`); the validations a
//! CI requests are run by `ace serve`'s workers instead. Its scans run in this binary again, contained, as
//! the workers' do. `yara layout` prints which directory of each repository in `svs.yara.repositories` the
//! YARA pool loads. `yara prune` removes the validations older than `svs.yara.retention_days`, as the
//! scheduler's `svs_validations_prune` does daily, acting as that task's component.
//!
//! `catalog refresh` reads the tests of each Atomic Red Team repository in `svs.catalog.repositories` whose
//! commit changed, as the scheduler's `svs_catalog_refresh` does every five minutes, acting as that task's
//! component; `catalog status` prints each repository's commit, test count and last error (batch 4,
//! `ace_core::svs::catalog`). Their lines are ace3's.
//!
//! `attack extract` builds the ATT&CK extract of a release from MITRE's enterprise STIX bundle, for a
//! developer to vendor: ace3's `bin/update-attack-catalog` (`ace_core::svs::attack::extract`). It reads no
//! configuration and reaches nothing: the bundle is a file the developer downloaded.
//!
//! `coverage refresh` recomputes ATT&CK coverage and the worklist at once, as the scheduler's
//! `svs_coverage_refresh` does every two minutes, acting as that task's component; `coverage snapshot`
//! refreshes and files the day's (UTC) copy, as `svs_coverage_snapshot` does daily, and a rerun replaces
//! the day; `coverage status` prints the last refresh, the rows per state on each platform and the
//! worklist's rows per status (batch 8, `ace_core::svs::coverage`). Their lines are ace3's.
//!
//! What differs from ace3: ace3's prune, refresh and snapshot skip a node that isn't the primary one unless
//! given `--force`; ace4 has no primary node (every replica shares the queue and the refresh's lock), so
//! there's no `--force`.

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
    /// The Atomic Red Team test catalog.
    #[command(subcommand)]
    Catalog(SvsCatalogCommand),
    /// The ATT&CK release coverage is computed against.
    #[command(subcommand)]
    Attack(SvsAttackCommand),
    /// ATT&CK coverage per technique and platform.
    #[command(subcommand)]
    Coverage(SvsCoverageCommand),
}

#[derive(Subcommand)]
pub enum SvsCoverageCommand {
    /// Recompute ATT&CK coverage (the scheduler does this on its own).
    Refresh,
    /// Print the last coverage refresh and the rows per state.
    Status,
    /// Refresh ATT&CK coverage and file today's (UTC) snapshot; a rerun replaces the day.
    Snapshot,
}

#[derive(Subcommand)]
pub enum SvsCatalogCommand {
    /// Read the tests of each catalog repository whose commit changed (the scheduler does this on its
    /// own).
    Refresh(CatalogRefreshArgs),
    /// Print each catalog repository's commit and test count.
    Status,
}

#[derive(Args)]
pub struct CatalogRefreshArgs {
    /// Only this repository (one of svs.catalog.repositories).
    #[arg(long)]
    pub repository: Option<String>,
    /// Read the tests even if the commit did not change.
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand)]
pub enum SvsAttackCommand {
    /// Build the extract of an ATT&CK release from its enterprise STIX bundle, to vendor in
    /// crates/ace-core/data/attack.
    Extract(AttackExtractArgs),
}

#[derive(Args)]
pub struct AttackExtractArgs {
    /// The ATT&CK release, for example v20.0.
    pub release: String,
    /// The release's enterprise STIX bundle, downloaded from MITRE's attack-stix-data repository.
    #[arg(long)]
    pub input: std::path::PathBuf,
    /// An earlier extract, to list the techniques renamed since.
    #[arg(long)]
    pub previous: Option<std::path::PathBuf>,
    /// Where to write the extract.
    #[arg(long, default_value = "crates/ace-core/data/attack")]
    pub output_dir: std::path::PathBuf,
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

/// The settings with the SSH keys their repositories name, read from the overlay's `secrets:` as a pool
/// reads its modules' (PLAN.md 2.24): only the names `ssh_key` gives. One that isn't set is a warning
/// here, and its repository's validations fail saying so.
pub(crate) fn with_ssh_keys(
    config: ValidationConfig,
    overlay: &ace_sdk::Overlay,
) -> ValidationConfig {
    let names = config.secret_names();
    if names.is_empty() {
        return config;
    }
    let secrets =
        ace_pool::secrets::resolve_names("svs", &names, overlay, &ace_pool::secrets::process_env);
    config.with_secrets(&secrets)
}

/// `ace svs catalog refresh`'s lines and exit code: ace3's `cli_catalog_refresh`.
pub fn catalog_refresh_report(results: &[ace_service::CatalogRefresh]) -> (String, u8) {
    let mut out = String::new();
    if results.is_empty() {
        put!(out, "svs.catalog.repositories is empty");
        return (out, 0);
    }
    let mut status = 0;
    for result in results {
        let repository = &result.repository;
        if let Some(error) = &result.error {
            put!(out, "{repository}: {error}");
            status = 1;
        } else if result.retired {
            put!(
                out,
                "{repository}: no longer in svs.catalog.repositories, {} tests removed",
                result.removed
            );
        } else if result.refreshed {
            put!(
                out,
                "{repository} @ {}: {} tests ({} added, {} changed, {} removed, {} skipped)",
                short(result.commit.as_deref().unwrap_or("?")),
                result.tests,
                result.added,
                result.changed,
                result.removed,
                result.skipped.len()
            );
            for skipped in &result.skipped {
                let name = skipped
                    .name
                    .as_ref()
                    .map_or(String::new(), |name| format!(" ({name})"));
                put!(out, "  skipped {}{name}: {}", skipped.path, skipped.reason);
            }
        } else {
            put!(
                out,
                "{repository} @ {}: already read (--force to read it again)",
                short(result.commit.as_deref().unwrap_or("?"))
            );
        }
    }
    (out, status)
}

/// `ace svs catalog status`'s lines: ace3's `cli_catalog_status`.
pub fn catalog_status_report(statuses: &[ace_service::CatalogRepository]) -> String {
    let mut out = String::new();
    for status in statuses {
        let state = if status.retired {
            format!(" ({})", ace_core::svs::catalog::RETIRED_ERROR)
        } else if status.configured {
            String::new()
        } else {
            " (no longer in svs.catalog.repositories)".to_owned()
        };
        let error = status
            .error
            .as_ref()
            .map_or(String::new(), |error| format!("; last error: {error}"));
        match status.refreshed_at {
            None => put!(out, "{}{state}: never read{error}", status.name),
            Some(refreshed_at) => put!(
                out,
                "{}{state}: {} tests at {}, read {}, {} skipped, {} removed since{error}",
                status.name,
                status.test_count,
                short(status.commit.as_deref().unwrap_or("?")),
                refreshed_at.format("%Y-%m-%d %H:%M:%S UTC"),
                status.skipped_count,
                status.removed_count
            ),
        }
    }
    out
}

/// The component the catalog's refresh acts as, from the scheduler or this command.
fn catalog_actor() -> Result<ace_service::Actor> {
    Ok(ace_service::Actor::Internal {
        id: ace_service::Component::new("scheduler:svs_catalog_refresh")
            .map_err(anyhow::Error::msg)?,
    })
}

/// `ace svs catalog refresh` over `service`: its lines and its exit code.
pub async fn catalog_refresh(
    service: &ace_service::Service,
    repository: Option<&str>,
    force: bool,
) -> Result<(String, u8)> {
    let results = service
        .refresh_svs_catalog(&catalog_actor()?, repository, force)
        .await?;
    Ok(catalog_refresh_report(&results))
}

/// `ace svs catalog status`'s lines, read as an operator reads them: with the database's own credentials,
/// not through the service, as the command holds no user's permission.
pub async fn catalog_status(
    db: &Db,
    config: &ace_core::svs::catalog::CatalogConfig,
) -> Result<String> {
    let mut conn = db.pool().acquire().await.context("a connection")?;
    let statuses = ace_core::svs::catalog::repository_status(&mut conn, config).await?;
    Ok(catalog_status_report(&statuses))
}

/// The catalog's settings with the SSH keys their repositories name, as `with_ssh_keys` reads
/// validation's.
pub(crate) fn catalog_with_ssh_keys(
    config: ace_core::svs::catalog::CatalogConfig,
    overlay: &ace_sdk::Overlay,
) -> ace_core::svs::catalog::CatalogConfig {
    let names = config.secret_names();
    if names.is_empty() {
        return config;
    }
    let secrets = ace_pool::secrets::resolve_names(
        "svs catalog",
        &names,
        overlay,
        &ace_pool::secrets::process_env,
    );
    config.with_secrets(&secrets)
}

/// `ace svs attack extract`: writes `<output_dir>/<release>.json` and returns its summary line, with what
/// the build warned about before it.
pub fn attack_extract(args: &AttackExtractArgs) -> Result<String> {
    use ace_core::svs::attack::extract;
    let release = extract::parse_release(&args.release).map_err(anyhow::Error::msg)?;
    let bundle =
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?;
    let previous = match &args.previous {
        Some(path) => Some(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| format!("{} isn't an extract", path.display()))?,
        ),
        None => None,
    };
    let built = extract::build(
        &bundle,
        &release,
        &extract::source_url(&release),
        previous.as_ref(),
    )
    .map_err(anyhow::Error::msg)?;
    let path = args.output_dir.join(format!("{release}.json"));
    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("making {}", args.output_dir.display()))?;
    // written beside it and renamed, so a failed write leaves no half of an extract
    let mut temp = tempfile::NamedTempFile::new_in(&args.output_dir)
        .with_context(|| format!("writing in {}", args.output_dir.display()))?;
    std::io::Write::write_all(&mut temp, extract::render(&built.extract).as_bytes())
        .context("writing the extract")?;
    temp.persist(&path)
        .with_context(|| format!("writing {}", path.display()))?;
    let count = |key: &str| built.extract[key].as_object().map_or(0, |o| o.len());
    let mut out = String::new();
    for warning in &built.warnings {
        put!(out, "warning: {warning}");
    }
    put!(
        out,
        "wrote {}: {} techniques, {} tactics, {} revoked, {} renamed",
        path.display(),
        count("techniques"),
        built.extract["tactics"].as_array().map_or(0, Vec::len),
        count("revoked"),
        count("renamed")
    );
    Ok(out)
}

/// A component of the scheduler's, which a coverage command acts as.
fn scheduler_actor(task: &str) -> Result<ace_service::Actor> {
    Ok(ace_service::Actor::Internal {
        id: ace_service::Component::new(format!("scheduler:{task}")).map_err(anyhow::Error::msg)?,
    })
}

/// `ace svs coverage refresh` over `service`: its line and its exit code. ace3's `cli_coverage_refresh`.
pub async fn coverage_refresh(service: &ace_service::Service) -> Result<(String, u8)> {
    Ok(
        match service
            .refresh_svs_coverage(
                &scheduler_actor("svs_coverage_refresh")?,
                chrono::Utc::now(),
            )
            .await
        {
            Ok(result) => (
                format!(
                    "{} rows: {} changed ({} new, {} retired) in {}ms\n",
                    result.rows,
                    result.changed,
                    result.inserted,
                    result.retired,
                    result.duration_ms
                ),
                0,
            ),
            Err(error) => (format!("coverage refresh failed: {error}\n"), 1),
        },
    )
}

/// `ace svs coverage snapshot` over `service`: its line and its exit code. ace3's
/// `cli_coverage_snapshot`.
pub async fn coverage_snapshot(service: &ace_service::Service) -> Result<(String, u8)> {
    Ok(
        match service
            .write_svs_coverage_snapshot(
                &scheduler_actor("svs_coverage_snapshot")?,
                None,
                chrono::Utc::now(),
            )
            .await
        {
            Ok(result) => {
                let deleted = if result.deleted > 0 {
                    format!(", {} earlier rows of the day removed", result.deleted)
                } else {
                    String::new()
                };
                (
                    format!(
                        "snapshot of {} against ATT&CK {}: {} rows{deleted}\n",
                        result.snapshot_date, result.attack_release, result.rows
                    ),
                    0,
                )
            }
            Err(error) => (format!("coverage snapshot failed: {error}\n"), 1),
        },
    )
}

/// `ace svs coverage status`'s lines: ace3's `cli_coverage_status`.
pub fn coverage_status_report(status: &ace_service::SvsCoverageStatus) -> String {
    let mut out = String::new();
    match status
        .state
        .as_ref()
        .and_then(|state| state.refreshed_at.map(|refreshed_at| (state, refreshed_at)))
    {
        None => put!(out, "coverage has never been refreshed"),
        Some((state, refreshed_at)) => put!(
            out,
            "refreshed {} against ATT&CK {} in {}ms: {} rows, {} changed, {} retired; {} unknown and {} \
             ignored mitre: tags",
            refreshed_at.format("%Y-%m-%d %H:%M:%S UTC"),
            state.attack_release.as_deref().unwrap_or("?"),
            state.duration_ms.unwrap_or(0),
            state.rows,
            state.changed,
            state.retired,
            state.unknown_tags,
            state.ignored_tags
        ),
    }
    if let Some(error) = status.state.as_ref().and_then(|state| state.error.as_ref()) {
        put!(out, "the latest refresh failed: {error}");
    }
    let listed = |counts: &std::collections::BTreeMap<String, i64>, order: Vec<&'static str>| {
        order
            .into_iter()
            .filter_map(|value| counts.get(value).map(|count| format!("{count} {value}")))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (platform, counts) in &status.counts {
        let states = ace_service::SvsCoverageState::ALL
            .iter()
            .map(|state| state.as_str())
            .collect();
        put!(out, "  {platform}: {}", listed(counts, states));
    }
    let statuses = ace_service::WorklistStatus::ALL
        .iter()
        .map(|status| status.as_str())
        .collect();
    let worklist = listed(&status.worklist, statuses);
    put!(
        out,
        "worklist: {}",
        if worklist.is_empty() {
            "empty"
        } else {
            worklist.as_str()
        }
    );
    out
}

/// `ace svs coverage status`'s lines, read as an operator reads them: with the database's own
/// credentials, not through the service, as `catalog_status` is.
pub async fn coverage_status(db: &Db) -> Result<String> {
    let mut conn = db.pool().acquire().await.context("a connection")?;
    let status = ace_core::svs::coverage::status(&mut conn).await?;
    Ok(coverage_status_report(&status))
}

fn run_coverage(command: SvsCoverageCommand) -> Result<ExitCode> {
    let overlay = crate::cli::overlay()?;
    let catalog = ace_core::svs::attack::attack_catalog(&overlay.svs.attack_release)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.attack_release")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        if let SvsCoverageCommand::Status = command {
            print!("{}", coverage_status(&db).await?);
            return Ok(ExitCode::SUCCESS);
        }
        let orchestrator = ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        );
        let service = ace_service::Service::new(db, orchestrator).with_attack_catalog(catalog);
        let (out, code) = match command {
            SvsCoverageCommand::Snapshot => coverage_snapshot(&service).await?,
            _ => coverage_refresh(&service).await?,
        };
        print!("{out}");
        Ok(ExitCode::from(code))
    })
}

fn run_catalog(command: SvsCatalogCommand) -> Result<ExitCode> {
    let overlay = crate::cli::overlay()?;
    let config = ace_core::svs::catalog::CatalogConfig::from_section(&overlay.svs.catalog)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.catalog section")?;
    let config = catalog_with_ssh_keys(config, &overlay);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        match command {
            SvsCatalogCommand::Status => {
                print!("{}", catalog_status(&db, &config).await?);
                Ok(ExitCode::SUCCESS)
            }
            SvsCatalogCommand::Refresh(args) => {
                let orchestrator = ace_core::orchestrator::Orchestrator::new(
                    ace_core::eligibility::Catalog::new(vec![]),
                    ace_core::modes::Modes::ace3(),
                );
                let service = ace_service::Service::new(db, orchestrator).with_catalog(config);
                let (out, code) =
                    catalog_refresh(&service, args.repository.as_deref(), args.force).await?;
                print!("{out}");
                Ok(ExitCode::from(code))
            }
        }
    })
}

pub fn run(_app: &crate::App, command: SvsCommand) -> Result<ExitCode> {
    let command = match command {
        SvsCommand::Yara(command) => command,
        SvsCommand::Catalog(command) => return run_catalog(command),
        SvsCommand::Coverage(command) => return run_coverage(command),
        SvsCommand::Attack(SvsAttackCommand::Extract(args)) => {
            print!("{}", attack_extract(&args)?);
            return Ok(ExitCode::SUCCESS);
        }
    };
    let overlay = crate::cli::overlay()?;
    let config = ValidationConfig::from_section(&overlay.svs.yara)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.yara section")?;
    let config = with_ssh_keys(config, &overlay);
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
                )
                .await;
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
