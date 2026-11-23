//! `ace export <name>`: a detection export, a long-running process that publishes the observables
//! enabled for detection to a system outside ACE (PLAN.md decision 58), ace3's `observable_export_<name>`
//! targets (`saq/observables/export/`), which its `export-observables` cron job runs every minute.
//!
//! **What an export is.** A site adds one with `App::detection_export`: an [`ExportSpec`] (its name, the
//! secrets it reads and the connections it takes) and a builder that makes the [`DetectionExport`] from
//! its [`ExportSetup`]. ace4 ships none (its YARA export is built into the ruleset, PLAN.md 7.16);
//! `ace-site-example` has one that writes a file, as a test of this. As in ace3, an export runs in two
//! stages, so the common pass, nothing changed, is cheap: [`DetectionExport::export_list`] filters the live
//! detections to what it would publish, with no network, and [`DetectionExport::publish`] does the work,
//! only when the list's fingerprint (with the export's [`DetectionExport::fingerprint_salt`]) isn't the one
//! it last published, when the export says it is [`DetectionExport::due`] anyway, or when forced.
//!
//! **Where it runs.** Its own process of the `ace` binary, as `ace collect <name>` is, because it holds
//! the credential of the system it writes to, which `ace serve` doesn't hold (PLAN.md 2.24), so
//! `App::scheduled_task` can't host it. It resolves the secrets its spec names, and its connections'
//! secrets, from the overlay's `secrets:`, and no others, and reads only its own `exports.<name>` section.
//! It reads the database as the hunter does (`ACE4_DATABASE_URL`, the overlay at `ACE4_OVERLAY`), and
//! acts as the component `export:<name>`, which holds what the class `export` is granted:
//! `detection:read` and its own record's `export:record`, nothing else (migration 0086). It reaches no
//! bucket.
//!
//! **Off unless turned on.** An export writes to a system outside ACE, which ace3 may write to as well
//! (the owner, 2026-11-16), so `ace export <name>` refuses to start unless its section says
//! `enabled: true`, and `--once --force` doesn't get around that: ace3's `export-observables --names`
//! runs a disabled one, ace4 doesn't.
//!
//! **Its record.** ace3's state file is `export.targets`' row here (`ace_service`'s `exports`): the
//! fingerprint, and a JSON document of the export's own, such as which of its files landed and when, which
//! `publish` reads and changes. A pass claims the row with a lease, so two replicas never publish at once,
//! and writes it back after: the new fingerprint after a publish that returned Ok, the old one after one
//! that failed, so the next pass tries again, and the document either way, so what landed is kept, as
//! a site's export records each file in a `finally`. A publish that runs past `publish_timeout_seconds`
//! (600) is dropped and counted failed.
//!
//! **Passes.** One every `interval_seconds` (60, ace3's cron minute), or one with `--once`, `--force`
//! publishing whatever the fingerprint says. A pass reads at most `ace_core::rulesets`' bound of
//! detections (10,000; the detection list holds at most `ace_sdk::lists::MAX_ENTRIES`).
//!
//! **Stopping.** SIGTERM or SIGINT stops the process: a wait ends at once, and a publish under way has
//! `STOP_WAIT` to end before it's dropped and its pass written back as failed, so the lease goes with it.
//!
//! **Logs and metrics.** Each pass is a log line under the export's name and, under the target
//! `ace_metrics` at INFO (`ace_core::metrics`), an event `METRICS (export): ` with its JSON: `event_type`
//! `export`, `export`, `outcome` (`published`, `unchanged`, `failed` or `busy`), `entries`, `forced` and
//! `seconds`.
//!
//! **A site's Compose service.** As a collector's (`crate::collector`), with the export's connection's
//! secret and none of the others, and `command: ["site-ace", "export", "siem_export_lookup"]`.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_sdk::{ExportSection, Secrets};
use ace_service::{Actor, ExportOutcome, Service};
use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Digest;
use tokio_util::sync::CancellationToken;

/// What an export reads and lists, so a site's export needs no crate but this one for them.
pub use ace_core::rulesets::Detection;
pub use ace_yara::export::{ExportEntry, ExportList};

use crate::App;

/// How long a stop waits for a publish under way.
pub const STOP_WAIT: Duration = Duration::from_secs(30);
/// How long a pass's lease outlasts its publish's timeout, for writing it back.
pub const LEASE_MARGIN: Duration = Duration::from_secs(60);

/// What an export is, for `App::detection_export`: its name, which `ace export` and the overlay's
/// `exports:` call it and its component is named after, the secrets it reads and the connections it takes.
/// A site builds one with `ExportSpec::new` and the methods after it, so a field added here doesn't break
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportSpec {
    pub name: &'static str,
    /// The names in the overlay's `secrets:` this export is given, and no other.
    pub secrets: &'static [&'static str],
    /// The shared connections it takes (`ace_sdk::connections`), which its section binds with
    /// `connections:`; it is given their secrets too.
    pub connections: &'static [ace_sdk::ConnectionSlot],
}

impl ExportSpec {
    /// An export called `name`, which reads no secrets and takes no connections.
    pub const fn new(name: &'static str) -> ExportSpec {
        ExportSpec {
            name,
            secrets: &[],
            connections: &[],
        }
    }

    /// The secrets it reads.
    pub const fn secrets(mut self, secrets: &'static [&'static str]) -> ExportSpec {
        self.secrets = secrets;
        self
    }

    /// The shared connections it takes.
    pub const fn connections(
        mut self,
        connections: &'static [ace_sdk::ConnectionSlot],
    ) -> ExportSpec {
        self.connections = connections;
        self
    }
}

/// What an export's builder is given: its section's `settings`, and the secrets and connections its
/// spec names that the overlay could resolve. A test builds one with `ExportSetup::new` and the methods
/// after it.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ExportSetup {
    pub settings: Option<Value>,
    pub secrets: Secrets,
    /// The connections its section binds to its spec's slots, each with its own secrets.
    pub connections: ace_sdk::Connections,
}

impl ExportSetup {
    /// A setup with `settings`, and no secrets or connections.
    pub fn new(settings: Option<Value>) -> ExportSetup {
        ExportSetup {
            settings,
            ..ExportSetup::default()
        }
    }

    pub fn with_secrets(mut self, secrets: Secrets) -> ExportSetup {
        self.secrets = secrets;
        self
    }

    pub fn with_connections(mut self, connections: ace_sdk::Connections) -> ExportSetup {
        self.connections = connections;
        self
    }
}

/// What builds an export from its setup, or says why it can't, which stops `ace export`.
pub type ExportFactory =
    Arc<dyn Fn(&ExportSetup) -> Result<Arc<dyn DetectionExport>, String> + Send + Sync>;

/// What a publish returns.
pub type PublishFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// A system outside ACE that the detections are published to, ace3's `ObservableExport`.
pub trait DetectionExport: Send + Sync {
    /// What it would publish of `detections`, the live ones in id order: ace3's `build_export_list`.
    /// Filtering only, with no network, since every pass calls it. [`select`] is ace3's
    /// `select_detections` over the binary's types.
    fn export_list(&self, detections: &[Detection]) -> ExportList;

    /// Anything besides the list that changes what it publishes, such as its settings: ace3's
    /// `fingerprint_salt`. Empty by default.
    fn fingerprint_salt(&self) -> String {
        String::new()
    }

    /// True when it wants to publish though the list hasn't changed, such as a file it last published
    /// a day ago; `state` is its record's document. False by default, as ace3's export never is.
    fn due(&self, state: &Value, now: DateTime<Utc>) -> bool {
        let _ = (state, now);
        false
    }

    /// Publishes `list`, reading and changing `state`, its record's document, which is written back
    /// whatever this returns. An error is logged, the fingerprint isn't recorded, and the next pass
    /// tries again. `force` asks it to publish everything, ignoring what `state` says it published.
    fn publish<'a>(
        &'a self,
        list: &'a ExportList,
        state: &'a mut Value,
        force: bool,
    ) -> PublishFuture<'a>;
}

/// The detections `export_types` cover, each under the type it's exported as: ace3's
/// `select_detections`, over the binary's types (a type covers the types that extend it; the most
/// specific configured one wins). A blank type is ignored. In a stable order (`ExportList::new`).
pub fn select(export_types: &[impl AsRef<str>], detections: &[Detection]) -> ExportList {
    let configured: BTreeSet<&str> = export_types
        .iter()
        .map(|t| t.as_ref().trim())
        .filter(|t| !t.is_empty())
        .collect();
    ExportList::new(
        ace_yara::export::select_detections(&configured, detections, ace_core::rulesets::ancestors)
            .into_iter()
            .map(|(export_type, detection)| ExportEntry {
                id: detection.id,
                export_type,
                observable_type: detection.observable_type.clone(),
                value: detection.value.clone(),
            })
            .collect(),
    )
}

/// ace3's `ObservableExport.fingerprint`: the list's own (`ExportList::fingerprint`) with no salt, else
/// the sha256 of `<list's>:<salt>`.
pub fn fingerprint(list: &ExportList, salt: &str) -> String {
    let fingerprint = list.fingerprint();
    if salt.is_empty() {
        return fingerprint;
    }
    sha2::Sha256::digest(format!("{fingerprint}:{salt}").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// How the loop runs an export: its section's numbers, with ace3's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunSettings {
    pub interval: Duration,
    pub publish_timeout: Duration,
}

impl RunSettings {
    /// A section's numbers, each one left out its default: a pass a minute, and a publish stopped after
    /// 10 minutes.
    pub fn from_section(section: &ExportSection) -> Result<RunSettings, String> {
        if section.interval_seconds == Some(0) {
            return Err("interval_seconds must be at least 1".to_owned());
        }
        if section.publish_timeout_seconds == Some(0) {
            return Err("publish_timeout_seconds must be at least 1".to_owned());
        }
        Ok(RunSettings {
            interval: Duration::from_secs(section.interval_seconds.unwrap_or(60)),
            publish_timeout: Duration::from_secs(section.publish_timeout_seconds.unwrap_or(600)),
        })
    }
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassOutcome {
    /// It published a list of this many entries.
    Published { entries: usize },
    /// The list is the one it last published, and it isn't due.
    Unchanged { entries: usize },
    /// The publish failed, ran out of time or was stopped: why.
    Failed { entries: usize, error: String },
    /// Another process holds the export's pass.
    Busy,
}

impl PassOutcome {
    fn name(&self) -> &'static str {
        match self {
            PassOutcome::Published { .. } => "published",
            PassOutcome::Unchanged { .. } => "unchanged",
            PassOutcome::Failed { .. } => "failed",
            PassOutcome::Busy => "busy",
        }
    }

    fn entries(&self) -> usize {
        match self {
            PassOutcome::Published { entries }
            | PassOutcome::Unchanged { entries }
            | PassOutcome::Failed { entries, .. } => *entries,
            PassOutcome::Busy => 0,
        }
    }
}

/// What runs an export's passes: its name, the service it reads and records through, the component it
/// acts as, and who it is among the processes that may claim its pass.
pub struct Exporter {
    name: String,
    service: Service,
    actor: Actor,
    owner: String,
    settings: RunSettings,
}

impl Exporter {
    /// An exporter for the export `name`, acting as `export:<name>`, claiming its pass as `owner`.
    pub fn new(
        name: &str,
        service: Service,
        owner: impl Into<String>,
        settings: RunSettings,
    ) -> Result<Exporter> {
        Ok(Exporter {
            name: name.to_owned(),
            actor: Actor::Internal {
                id: ace_service::Component::new(format!("export:{name}"))?,
            },
            service,
            owner: owner.into(),
            settings,
        })
    }

    /// One pass (the module docs): a stop ends a publish under way after `STOP_WAIT`. An error is the
    /// database's or a permission's, and leaves the record as it was.
    pub async fn pass(
        &self,
        export: &dyn DetectionExport,
        force: bool,
        stop: &CancellationToken,
    ) -> Result<PassOutcome> {
        let started = Instant::now();
        let lease = self.settings.publish_timeout + LEASE_MARGIN;
        let Some(claimed) = self
            .service
            .claim_export(&self.actor, &self.name, &self.owner, lease)
            .await?
        else {
            let outcome = PassOutcome::Busy;
            self.log(&outcome, force, started);
            return Ok(outcome);
        };
        let detections = match self.service.active_detections(&self.actor).await {
            Ok(detections) => detections,
            Err(e) => {
                self.write_back(claimed.fingerprint.as_deref(), &claimed.state, false)
                    .await;
                return Err(e.into());
            }
        };
        let list = export.export_list(&detections);
        let entries = list.len();
        let fingerprint = fingerprint(&list, &export.fingerprint_salt());
        let changed = claimed.fingerprint.as_deref() != Some(fingerprint.as_str());
        let mut state = claimed.state.clone();
        if !state.is_object() {
            state = json!({});
        }
        if !force && !changed && !export.due(&state, Utc::now()) {
            self.write_back(claimed.fingerprint.as_deref(), &state, false)
                .await;
            let outcome = PassOutcome::Unchanged { entries };
            self.log(&outcome, force, started);
            return Ok(outcome);
        }
        let published = {
            let publish = export.publish(&list, &mut state, force);
            let stopped_long_ago = async {
                stop.cancelled().await;
                tokio::time::sleep(STOP_WAIT).await;
            };
            tokio::select! {
                published = tokio::time::timeout(self.settings.publish_timeout, publish) => match published {
                    Ok(published) => published,
                    Err(_) => Err(format!(
                        "the publish didn't end within {:?}",
                        self.settings.publish_timeout
                    )),
                },
                () = stopped_long_ago => Err(format!("stopping: the publish didn't end within {STOP_WAIT:?}")),
            }
        };
        let outcome = match published {
            Ok(()) => {
                self.write_back(Some(&fingerprint), &state, true).await;
                PassOutcome::Published { entries }
            }
            Err(error) => {
                self.write_back(claimed.fingerprint.as_deref(), &state, false)
                    .await;
                PassOutcome::Failed { entries, error }
            }
        };
        self.log(&outcome, force, started);
        Ok(outcome)
    }

    /// Writes the pass back, logging what keeps it from landing: the lease then runs out instead.
    async fn write_back(&self, fingerprint: Option<&str>, state: &Value, published: bool) {
        let outcome = ExportOutcome {
            fingerprint,
            state,
            published,
        };
        match self
            .service
            .record_export(&self.actor, &self.name, &self.owner, &outcome)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::error!(
                export = %self.name,
                "the export's lease ran out before its pass was written back: another process may have \
                 published since"
            ),
            Err(e) => {
                tracing::error!(export = %self.name, "the export's pass wasn't written back: {e}")
            }
        }
    }

    fn log(&self, outcome: &PassOutcome, forced: bool, started: Instant) {
        match outcome {
            PassOutcome::Failed { error, .. } => {
                tracing::error!(export = %self.name, "a publish failed: {error}");
            }
            PassOutcome::Busy => {
                tracing::info!(export = %self.name, "another process holds the export's pass");
            }
            _ => tracing::info!(
                export = %self.name,
                outcome = outcome.name(),
                entries = outcome.entries(),
                "an export pass ended"
            ),
        }
        ExportMetrics {
            event_type: "export",
            export: &self.name,
            outcome: outcome.name(),
            entries: outcome.entries(),
            forced,
            seconds: started.elapsed().as_secs_f64(),
        }
        .emit();
    }
}

/// A pass's metrics event (the module docs).
#[derive(Debug, Serialize)]
struct ExportMetrics<'a> {
    event_type: &'static str,
    export: &'a str,
    outcome: &'static str,
    entries: usize,
    forced: bool,
    seconds: f64,
}

/// The prefix of an export's metrics event's message.
pub const METRICS_PREFIX: &str = "METRICS (export): ";

impl ExportMetrics<'_> {
    fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_default();
        tracing::info!(
            target: ace_core::metrics::TARGET,
            event_type = self.event_type,
            export = self.export,
            "{METRICS_PREFIX}{json}"
        );
    }
}

/// Runs passes every `interval` until `stop`, or one with `once`. Returns how many passes ended, and
/// whether the last one failed.
pub async fn run_passes(
    exporter: &Exporter,
    export: &dyn DetectionExport,
    once: bool,
    force: bool,
    stop: &CancellationToken,
) -> (u64, bool) {
    let mut passes = 0;
    let mut failed = false;
    while !stop.is_cancelled() {
        let pass = exporter.pass(export, force, stop).await;
        passes += 1;
        failed = match pass {
            Ok(PassOutcome::Failed { .. }) => true,
            Ok(_) => false,
            Err(e) => {
                tracing::error!(export = %exporter.name, "a pass failed: {e:#}");
                true
            }
        };
        if once {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(exporter.settings.interval) => {}
            () = stop.cancelled() => {}
        }
    }
    (passes, failed)
}

/// `ace export <name>`.
pub fn run(
    app: &App,
    name: &str,
    once: bool,
    force: bool,
    telemetry: &mut ace_pool::telemetry::Telemetry,
) -> Result<ExitCode> {
    telemetry.start_export().context("starting span export")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let code = runtime.block_on(export(app, name, once, force));
    runtime.shutdown_timeout(Duration::from_secs(5));
    code
}

async fn export(app: &App, name: &str, once: bool, force: bool) -> Result<ExitCode> {
    use ace_core::db::{Db, DbConfig};

    let Some((spec, build)) = app.exports.iter().find(|(spec, _)| spec.name == name) else {
        let names: Vec<&str> = app.exports.iter().map(|(s, _)| s.name).collect();
        anyhow::bail!("this binary has no detection export {name:?}; it has {names:?}");
    };
    if force && !once {
        anyhow::bail!("--force publishes once: give --once with it");
    }
    let overlay = crate::cli::overlay(app)?;
    let section = overlay.exports.get(name).cloned().unwrap_or_default();
    if section.enabled != Some(true) {
        anyhow::bail!(
            "the detection export {name} is off: it writes to a system outside ACE, so it runs only when \
             the overlay's exports.{name} says enabled: true"
        );
    }
    let settings = RunSettings::from_section(&section)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("the overlay's exports.{name}"))?;
    let component = format!("export:{name}");
    let bindings = overlay.bind(
        &format!("exports.{name}.connections"),
        spec.connections,
        &section.connections,
    )?;
    let names: Vec<&str> = spec
        .secrets
        .iter()
        .copied()
        .chain(ace_sdk::connections::secret_names(&bindings))
        .collect();
    let resolved = ace_pool::secrets::resolve_names(
        &component,
        &names,
        &overlay,
        &ace_pool::secrets::process_env,
    );
    let export = build(&ExportSetup {
        settings: section.settings.clone(),
        secrets: resolved.only(spec.secrets),
        connections: ace_sdk::Connections::resolve(&bindings, &resolved),
    })
    .map_err(anyhow::Error::msg)
    .with_context(|| format!("building the detection export {name}"))?;

    let db = Db::connect(&DbConfig::from_env(format!("ace-export-{name}"))?)
        .await
        .context("connecting to Postgres")?;
    // the export reads the detections and its record, which need no module, mode or bucket
    let service = Service::new(
        db,
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new([]),
            app.modes(),
        ),
    );
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
        crate::serve::wait_for_stop().await;
        stopping.cancel();
    });
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "export".to_owned());
    let exporter = Exporter::new(
        name,
        service,
        format!("{host}/{}", std::process::id()),
        settings,
    )?;
    tracing::info!(
        export = name,
        interval_seconds = settings.interval.as_secs(),
        publish_timeout_seconds = settings.publish_timeout.as_secs(),
        once,
        force,
        "exporting the detections"
    );
    let (passes, failed) = run_passes(&exporter, export.as_ref(), once, force, &stop).await;
    tracing::info!(export = name, passes, "the export ended");
    Ok(if once && failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests;
