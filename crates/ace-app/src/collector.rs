//! `ace collect <name>`: a collector, a long-running process that reads a source outside ACE and
//! submits roots (PLAN.md 6.1), ace3's `CollectorService` hosting a `Collector`.
//!
//! **What a collector is.** A site adds one with `App::collector`: a [`CollectorSpec`] (its name and
//! the secrets it reads) and a builder that makes the [`Collector`] from its [`CollectorSetup`]. ace4
//! ships none; `ace-site-example` has one over a directory, as a test of this. A collector's
//! [`Collector::collect`] runs one pass: it reads what its source has ready, hands each item to the
//! [`Submitter`], and tells the source it has the item only once [`Submitter::submit`] says the item
//! is in (submitted, or a duplicate of one that is). That is the order ace3's collectors keep: the
//! journal collector deletes a queue message only after its submissions came back from the
//! generator.
//!
//! **Where it runs.** Its own process of the `ace` binary, as `ace hunter` is (PLAN.md 6.4) and as
//! each of ace3's collectors is its own service. A collector holds its source's credentials, which
//! 2.24 keeps out of `ace serve`; a pool reaches only the lease API and the bucket, and can't make a
//! root. So `ace collect <name>` resolves the secrets its spec names, from the overlay's `secrets:`,
//! and no others, and reads only its own `collectors.<name>` section. It reads the database and the
//! bucket as the hunter does (`ACE4_DATABASE_URL`, `ACE4_BUCKET_*`, the overlay at `ACE4_OVERLAY`) and
//! submits through the service layer as the component `collector:<name>`, which holds what the class
//! `collector` is granted, `alert:create` and nothing else (migration 0074,
//! `ace_service::Component::class`). Every root records it in `submitted_by` and in its audit row.
//! Each collector is a Compose service of its own (below).
//!
//! **Duplicates.** An item has a key, as ace3's `Submission.key`, such as an S3 object's key. Its root
//! and its key are written in one transaction (`Service::submit_collected`), and a key that made a root
//! within the collector's `key_lifetime_seconds` (4 hours, ace3's) makes none: the earlier root is the
//! answer. So a redelivered item is submitted once, and so is one whose commit landed but whose
//! answer was lost, which ace3's mark-then-stage order can't promise. An item with no key is always
//! submitted.
//!
//! **When the core can't take it.** A submission the core refuses as it is, such as one naming a mode
//! that doesn't exist, is [`NotSubmitted::Refused`] at once: trying it again can't help, and the
//! collector decides what its source does with it (ace3's journal collector deletes a message it can't
//! read). Anything else, the database or the bucket unreachable, a timeout, a missing grant, is tried
//! again, `submit_attempts` times in all (5 by default), waiting 1, 2, 4 and 8 seconds between them, and
//! is then [`NotSubmitted::GivenBack`]: the collector leaves the item in its source, which offers it
//! again (a queue message's visibility timeout), and the key makes sure it lands once. Nothing is lost
//! and nothing is submitted twice. A pass that fails is logged and the next starts after the poll wait,
//! as ace3's loop does.
//!
//! **Stopping.** SIGTERM or SIGINT stops the process. A wait between passes or between two attempts
//! ends at once, and the item in it is given back. A submission under way runs to its end, since its
//! transaction is what decides whether the item is in. The pass then has `stop_seconds` (30 by
//! default) to return; past that it is dropped, which rolls back a transaction still open, so what it
//! held goes back to its source uncommitted, and the process exits 0. ace3's `stop` waits for its
//! threads without a bound.
//!
//! **Logs and metrics.** Each submission is a log line under the collector's name and, under the
//! target `ace_metrics` at INFO (`ace_core::metrics`), an event `METRICS (collector): ` with its JSON:
//! `event_type` `collector`, `collector`, `outcome` (`submitted`, `duplicate`, `refused` or
//! `given_back`), `root_uuid` when there is one, `attempts`, `seconds` from the first attempt to the
//! last answer, and `has_key`; ace3's line has the outcome and the stage times. Spans export as the
//! other processes' do when `ACE4_OTLP_ENDPOINT` is set.
//!
//! **A site's Compose service.** ace4's Compose file runs no collector, as ace4 ships none. A site
//! runs each of its own as a service of its `ace` image, beside `ace`, with the same database and
//! bucket variables and only its own source's:
//!
//! ```text
//! journal-collector:
//!   image: site-port-ace:latest
//!   command: ["site-ace", "collect", "journal"]
//!   depends_on: {ace: {condition: service_healthy}}
//!   environment:
//!     ACE4_DATABASE_URL: ...      # as the ace service's
//!     ACE4_BUCKET_ENDPOINT: ...   # and the other ACE4_BUCKET_* variables
//!     ACE4_OVERLAY: /etc/ace4/overlay.yaml
//!     ACE4_LOG: info
//!     JOURNAL_QUEUE_TOKEN: ...    # what the overlay's secrets: names for this collector, and no other
//!   volumes: ["${ACE4_SITE}:/etc/ace4:ro"]
//!   restart: unless-stopped
//!   stop_grace_period: 40s        # more than its stop_seconds
//! ```

use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_core::bucket::Bucket;
/// What an [`Item`] is made of, so a site's collector needs no crate but this one for it.
pub use ace_core::submit::{Origin, Submission, SubmittedFile, SubmittedObservable};
use ace_sdk::{CollectorSection, Secrets};
use anyhow::{Context as _, Result};
use serde::Serialize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::App;

/// What a collector is, for `App::collector`: its name, which `ace collect` and the overlay's
/// `collectors:` call it and its component is named after, and the secrets it reads. A site builds
/// one with `CollectorSpec::new` and the methods after it, so a field added here doesn't break it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectorSpec {
    pub name: &'static str,
    /// The names in the overlay's `secrets:` this collector is given, and no other.
    pub secrets: &'static [&'static str],
    /// The shared connections it takes (`ace_sdk::connections`), which its section binds with
    /// `connections:`; it is given their secrets too.
    pub connections: &'static [ace_sdk::ConnectionSlot],
}

impl CollectorSpec {
    /// A collector called `name`, which reads no secrets and takes no connections.
    pub const fn new(name: &'static str) -> CollectorSpec {
        CollectorSpec {
            name,
            secrets: &[],
            connections: &[],
        }
    }

    /// The secrets it reads.
    pub const fn secrets(mut self, secrets: &'static [&'static str]) -> CollectorSpec {
        self.secrets = secrets;
        self
    }

    /// The shared connections it takes.
    pub const fn connections(
        mut self,
        connections: &'static [ace_sdk::ConnectionSlot],
    ) -> CollectorSpec {
        self.connections = connections;
        self
    }
}

/// What a collector's builder is given: its overlay section's `settings`, and the secrets its spec
/// names that the overlay could resolve. A test builds one with `CollectorSetup::new` and the
/// methods after it.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CollectorSetup {
    pub settings: Option<Value>,
    pub secrets: Secrets,
    /// The connections its section binds to its spec's slots, each with its own secrets.
    pub connections: ace_sdk::Connections,
}

impl CollectorSetup {
    /// A setup with `settings`, and no secrets or connections.
    pub fn new(settings: Option<Value>) -> CollectorSetup {
        CollectorSetup {
            settings,
            ..CollectorSetup::default()
        }
    }

    pub fn with_secrets(mut self, secrets: Secrets) -> CollectorSetup {
        self.secrets = secrets;
        self
    }

    pub fn with_connections(mut self, connections: ace_sdk::Connections) -> CollectorSetup {
        self.connections = connections;
        self
    }
}

/// What builds a collector from its setup, or says why it can't, which stops `ace collect`.
pub type CollectorFactory =
    Arc<dyn Fn(&CollectorSetup) -> Result<Arc<dyn Collector>, String> + Send + Sync>;

/// What one pass returns.
pub type PassFuture<'a> = Pin<Box<dyn Future<Output = Result<Pass, String>> + Send + 'a>>;

/// A source outside ACE that submits roots, ace3's `Collector`.
pub trait Collector: Send + Sync {
    /// One pass over the source: each item it has ready, handed to `submitter`. An item the source
    /// should offer again (one [`NotSubmitted::GivenBack`]) stays there. A pass should end soon
    /// after `submitter` says it is stopping. An error is logged, and the next pass starts after the
    /// poll wait.
    fn collect<'a>(&'a self, submitter: &'a Submitter) -> PassFuture<'a>;
}

/// What a pass found of its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// It took everything the source had ready: the next pass waits `poll_seconds`.
    Drained,
    /// It took a bounded batch and there may be more, ace3's `collect_until_empty`: the next pass
    /// starts at once.
    More,
}

/// One item a collector submits: a root's submission and files, and its key.
#[derive(Debug)]
pub struct Item {
    /// What makes it the same item when the source offers it again, ace3's `Submission.key`.
    pub key: Option<String>,
    pub submission: Submission,
    /// What the API's submission doesn't carry, such as ace3's alert type and tool, which a root keeps
    /// in `analysis.roots.origin` (`ace_core::submit::Origin`).
    pub origin: Origin,
    /// Its files, spooled on this node with [`Submitter::spool_bytes`] or [`Submitter::spool_file`].
    pub files: Vec<SubmittedFile>,
}

/// An item that is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// It made this root.
    New { root: Uuid },
    /// Its key made this root within the key's lifetime, so it made none.
    Duplicate { root: Uuid },
}

/// An item that isn't in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSubmitted {
    /// The core refused the submission as it is, and would again: the collector decides what its
    /// source does with the item.
    Refused(String),
    /// The core couldn't take it for a reason that isn't the item's, after every attempt, or the
    /// process is stopping: the item must stay in its source, which offers it again.
    GivenBack(String),
}

/// How a submission is tried (`collectors.<name>`'s numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    /// Attempts in all, at least 1.
    pub attempts: u32,
    /// The wait after the first failed attempt, doubled after each one, to at most 30 seconds.
    pub first_wait: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Retry {
            attempts: 5,
            first_wait: Duration::from_secs(1),
        }
    }
}

/// An attempt's failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptError {
    /// The submission itself is the problem.
    Refused(String),
    /// Something else is: trying again may work.
    Transient(String),
}

/// What hands a collector's items to the core.
pub struct Submitter {
    name: String,
    service: ace_service::Service,
    bucket: Bucket,
    actor: ace_service::Actor,
    key_lifetime: chrono::TimeDelta,
    retry: Retry,
    stop: CancellationToken,
}

impl Submitter {
    /// A submitter for the collector `name`, acting as `collector:<name>`.
    pub fn new(
        name: &str,
        service: ace_service::Service,
        bucket: Bucket,
        key_lifetime: chrono::TimeDelta,
        retry: Retry,
        stop: CancellationToken,
    ) -> Result<Submitter> {
        Ok(Submitter {
            name: name.to_owned(),
            actor: ace_service::Actor::Internal {
                id: ace_service::Component::new(format!("collector:{name}"))?,
            },
            service,
            bucket,
            key_lifetime,
            retry,
            stop,
        })
    }

    /// The collector's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// True once the process is stopping: a pass should end, giving back what it hasn't submitted.
    pub fn stopping(&self) -> bool {
        self.stop.is_cancelled()
    }

    /// Resolves once the process is stopping, for a pass waiting on its source (a long poll).
    pub async fn stopped(&self) {
        self.stop.cancelled().await;
    }

    /// Spools bytes on this node for an item's file.
    pub async fn spool_bytes(&self, bytes: &[u8]) -> Result<ace_store::Spooled> {
        Ok(self.bucket.store().spool_bytes(bytes).await?)
    }

    /// Spools a file on this node for an item's file.
    pub async fn spool_file(&self, path: &std::path::Path) -> Result<ace_store::Spooled> {
        Ok(self.bucket.store().spool_file(path).await?)
    }

    /// Submits `item`, trying again while the core can't take it (the module docs). Once stopping, an
    /// item not yet tried is given back.
    pub async fn submit(&self, item: &Item) -> Result<Submitted, NotSubmitted> {
        let started = Instant::now();
        let mut attempts = 0;
        let result = retrying(self.retry, &self.stop, || {
            attempts += 1;
            self.attempt(item)
        })
        .await;
        let (outcome, root) = match &result {
            Ok(Submitted::New { root }) => ("submitted", Some(*root)),
            Ok(Submitted::Duplicate { root }) => ("duplicate", Some(*root)),
            Err(NotSubmitted::Refused(_)) => ("refused", None),
            Err(NotSubmitted::GivenBack(_)) => ("given_back", None),
        };
        match &result {
            Ok(_) => tracing::info!(
                collector = %self.name,
                key = item.key.as_deref().unwrap_or(""),
                outcome,
                root = %root.unwrap_or_default(),
                "collected a submission"
            ),
            Err(NotSubmitted::Refused(why)) => tracing::warn!(
                collector = %self.name,
                key = item.key.as_deref().unwrap_or(""),
                "the core refused a submission: {why}"
            ),
            Err(NotSubmitted::GivenBack(why)) => tracing::error!(
                collector = %self.name,
                key = item.key.as_deref().unwrap_or(""),
                attempts,
                "gave a submission back to its source: {why}"
            ),
        }
        CollectorMetrics {
            event_type: "collector",
            collector: &self.name,
            outcome,
            root_uuid: root,
            attempts,
            seconds: started.elapsed().as_secs_f64(),
            has_key: item.key.is_some(),
        }
        .emit();
        result
    }

    async fn attempt(&self, item: &Item) -> Result<Submitted, AttemptError> {
        let collected = self
            .service
            .submit_collected(
                &self.actor,
                &self.bucket,
                &self.name,
                item.key.as_deref(),
                self.key_lifetime,
                &item.submission,
                &item.origin,
                &item.files,
            )
            .await;
        match collected {
            Ok(ace_service::Collected::Submitted(submitted)) => Ok(Submitted::New {
                root: submitted.uuid,
            }),
            Ok(ace_service::Collected::Duplicate { root }) => Ok(Submitted::Duplicate { root }),
            Err(ace_service::ServiceError::InvalidRequest(why)) => Err(AttemptError::Refused(why)),
            Err(e) => Err(AttemptError::Transient(e.to_string())),
        }
    }
}

/// Runs `attempt` until it succeeds, is refused, or has failed `retry.attempts` times, waiting
/// between failures; a stop ends a wait at once and gives the item back. An attempt under way is never
/// cut short. No attempt starts once stopping.
pub async fn retrying<F, Fut>(
    retry: Retry,
    stop: &CancellationToken,
    mut attempt: F,
) -> Result<Submitted, NotSubmitted>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Submitted, AttemptError>>,
{
    let mut wait = retry.first_wait;
    let mut last = String::new();
    for tried in 1..=retry.attempts.max(1) {
        if stop.is_cancelled() {
            return Err(NotSubmitted::GivenBack(format!(
                "stopping, after {} attempts{}",
                tried - 1,
                if last.is_empty() {
                    String::new()
                } else {
                    format!(": {last}")
                }
            )));
        }
        match attempt().await {
            Ok(submitted) => return Ok(submitted),
            Err(AttemptError::Refused(why)) => return Err(NotSubmitted::Refused(why)),
            Err(AttemptError::Transient(why)) => last = why,
        }
        if tried < retry.attempts {
            tracing::warn!(
                attempt = tried,
                of = retry.attempts,
                "the core couldn't take a submission, trying again in {wait:?}: {last}"
            );
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = stop.cancelled() => {}
            }
            wait = (wait * 2).min(Duration::from_secs(30));
        }
    }
    Err(NotSubmitted::GivenBack(format!(
        "{} attempts failed: {last}",
        retry.attempts.max(1)
    )))
}

/// A submission's metrics event (the module docs).
#[derive(Debug, Serialize)]
struct CollectorMetrics<'a> {
    event_type: &'static str,
    collector: &'a str,
    outcome: &'static str,
    root_uuid: Option<Uuid>,
    attempts: u32,
    seconds: f64,
    has_key: bool,
}

/// The prefix of a collector's metrics event's message.
pub const METRICS_PREFIX: &str = "METRICS (collector): ";

impl CollectorMetrics<'_> {
    fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_default();
        tracing::info!(
            target: ace_core::metrics::TARGET,
            event_type = self.event_type,
            collector = self.collector,
            "{METRICS_PREFIX}{json}"
        );
    }
}

/// How the loop runs a collector: its overlay section's numbers, with ace3's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunSettings {
    pub key_lifetime: chrono::TimeDelta,
    pub poll: Duration,
    pub retry: Retry,
    pub stop_wait: Duration,
}

impl RunSettings {
    /// A section's numbers, each one left out its default: a key holds 4 hours
    /// (`ace_service::DEFAULT_KEY_LIFETIME`), a pass that had nothing more waits 1 second (ace3's
    /// `collection_frequency`), a submission is tried 5 times, and a stop waits 30 seconds for the pass.
    pub fn from_section(section: &CollectorSection) -> Result<RunSettings, String> {
        let key_lifetime = match section.key_lifetime_seconds {
            None => ace_service::DEFAULT_KEY_LIFETIME,
            Some(0) => return Err("key_lifetime_seconds must be more than 0".to_owned()),
            Some(seconds) => i64::try_from(seconds)
                .ok()
                .and_then(chrono::TimeDelta::try_seconds)
                .ok_or("key_lifetime_seconds is too large")?,
        };
        if section.poll_seconds == Some(0) {
            return Err("poll_seconds must be at least 1".to_owned());
        }
        if section.submit_attempts == Some(0) {
            return Err("submit_attempts must be at least 1".to_owned());
        }
        Ok(RunSettings {
            key_lifetime,
            poll: Duration::from_secs(section.poll_seconds.unwrap_or(1)),
            retry: Retry {
                attempts: section.submit_attempts.unwrap_or(5),
                ..Retry::default()
            },
            stop_wait: Duration::from_secs(section.stop_seconds.unwrap_or(30)),
        })
    }
}

/// Runs `collector`'s passes until `stop`, then waits at most `settings.stop_wait` for the pass under
/// way (the module docs). Returns how many passes ended.
pub async fn run_passes(
    collector: &dyn Collector,
    submitter: &Submitter,
    settings: &RunSettings,
    stop: &CancellationToken,
) -> u64 {
    let mut passes = 0;
    while !stop.is_cancelled() {
        let pass = collector.collect(submitter);
        let stopped_long_ago = async {
            stop.cancelled().await;
            tokio::time::sleep(settings.stop_wait).await;
        };
        let ended = tokio::select! {
            ended = pass => ended,
            () = stopped_long_ago => {
                tracing::warn!(
                    collector = submitter.name(),
                    "the pass didn't end within {:?} of the stop: what it held goes back to its source",
                    settings.stop_wait
                );
                return passes;
            }
        };
        passes += 1;
        let wait = match ended {
            Ok(Pass::More) => Duration::ZERO,
            Ok(Pass::Drained) => settings.poll,
            Err(e) => {
                tracing::error!(collector = submitter.name(), "a pass failed: {e}");
                settings.poll.max(Duration::from_secs(1))
            }
        };
        if !wait.is_zero() {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = stop.cancelled() => {}
            }
        }
    }
    passes
}

/// `ace collect <name>`.
pub fn run(
    app: &App,
    name: &str,
    telemetry: &mut ace_pool::telemetry::Telemetry,
) -> Result<ExitCode> {
    telemetry.start_export().context("starting span export")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let code = runtime.block_on(collect(app, name));
    runtime.shutdown_timeout(Duration::from_secs(5));
    code
}

async fn collect(app: &App, name: &str) -> Result<ExitCode> {
    use ace_core::db::{Db, DbConfig};

    let Some((spec, build)) = app.collectors.iter().find(|(spec, _)| spec.name == name) else {
        let names: Vec<&str> = app.collectors.iter().map(|(s, _)| s.name).collect();
        anyhow::bail!("this binary has no collector {name:?}; it has {names:?}");
    };
    let overlay = crate::cli::overlay(app)?;
    let section = overlay.collectors.get(name).cloned().unwrap_or_default();
    let settings = RunSettings::from_section(&section)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("the overlay's collectors.{name}"))?;
    let component = format!("collector:{name}");
    let bindings = overlay.bind(
        &format!("collectors.{name}.connections"),
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
    let collector = build(&CollectorSetup {
        settings: section.settings.clone(),
        secrets: resolved.only(spec.secrets),
        connections: ace_sdk::Connections::resolve(&bindings, &resolved),
    })
    .map_err(anyhow::Error::msg)
    .with_context(|| format!("building the collector {name}"))?;

    let db = Db::connect(&DbConfig::from_env(format!("ace-collect-{name}"))?)
        .await
        .context("connecting to Postgres")?;
    let bucket = crate::cli::submitting_bucket(&db, &format!("ace4-collect-{name}-cache")).await?;
    let service = crate::cli::submitting_service(app, &overlay, db)?;
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
        crate::serve::wait_for_stop().await;
        stopping.cancel();
    });
    let submitter = Submitter::new(
        name,
        service,
        bucket,
        settings.key_lifetime,
        settings.retry,
        stop.clone(),
    )?;
    tracing::info!(
        collector = name,
        key_lifetime_seconds = settings.key_lifetime.num_seconds(),
        poll_seconds = settings.poll.as_secs(),
        submit_attempts = settings.retry.attempts,
        "collecting"
    );
    let passes = run_passes(collector.as_ref(), &submitter, &settings, &stop).await;
    tracing::info!(collector = name, passes, "collection ended");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests;
