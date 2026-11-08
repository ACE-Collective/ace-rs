//! The module traits: a sync one for parsers and an async one for lookups.
//!
//! A parser reads hostile files in a contained process of its own, so it is plain blocking code
//! that polls `TaskContext::is_cancelled`. A lookup waits on the network inside a shared async
//! pool, many tasks at a time, and selects on `TaskContext::cancelled`.

use std::future::Future;
use std::time::Duration;

use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::Instrument;

use crate::context::TaskContext;
use crate::lists::ListSpec;
use crate::manifest::Resources;
use crate::reads::Read;

/// A module's settings: the block a site's config overlay gives it. Missing settings fall back
/// to `Default`. Derive `Deserialize` with `#[serde(deny_unknown_fields)]`; the loader refuses
/// unknown keys either way.
pub trait Settings: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static {}

impl<T: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static> Settings for T {}

/// What every module has, whichever way it runs. `Manifest::parser` and `Manifest::lookup`
/// collect these constants into the module's manifest.
pub trait Module: Sized + Send + Sync + 'static {
    /// The module's name, as configured and as named in a result's `exclude_modules`.
    const NAME: &'static str;
    /// The observable types the module takes. Types that extend these are taken too.
    const INPUTS: &'static [ObservableKind];
    /// Modules whose results this one needs before it runs.
    const DEPENDS_ON: &'static [&'static str] = &[];
    /// Directives that keep the module off an observable, such as `no_scan` for YARA. The core
    /// doesn't queue the module for an observable that has one, and a run on an observable
    /// that gained one after its task was queued is skipped. `exclude_all` keeps every module
    /// off.
    const SKIP_DIRECTIVES: &'static [&'static str] = &[];
    /// The names of the secrets the module reads. The task context gives it these and no others.
    const SECRETS: &'static [&'static str] = &[];
    const RESOURCES: Resources = Resources::DEFAULT;
    /// True for a module that does nothing until a site configures it, such as the Splunk
    /// module, which needs its query: it runs only as the site overlay's named instances
    /// (PLAN.md 2.23), never as itself on its defaults.
    const INSTANCES_ONLY: bool = false;
    /// True for a module that reads the body of the email that carried its observable, as ace3's
    /// modules for encrypted attachments do. The core adds it to the module's tasks, which read it
    /// with `TaskContext::carrying_email`, or says an email in the root isn't parsed yet, and a
    /// module that needs to know then delays itself.
    const READS_CARRYING_EMAIL: bool = false;
    /// True for a module that runs once everything else in its root has finished, as ace3's
    /// `execute_final_analysis`, and reads the YARA rules that matched its observable or anything
    /// below it. The core holds its tasks back until then and adds those rules to them.
    const RUNS_LAST: bool = false;
    /// The analyst-edited lists the module reads (PLAN.md 5.14), such as the email module's
    /// whitelists. The core adds each to the module's tasks as it is when the task is leased, and
    /// the module reads it with `TaskContext::list`. The lists a binary knows are its modules'.
    const LISTS: &'static [ListSpec] = &[];
    /// The reads of ACE's own data the module makes (PLAN.md 7.2), with `TaskContext::read`. Only
    /// a lookup may declare one: `Manifest::parser` refuses a parser that does.
    const READS: &'static [Read] = &[];

    /// The analysis type the module writes.
    type Output: AnalysisType;
    type Settings: Settings;

    /// Builds the module once per process, before any task, such as loading a ruleset. A failure
    /// here is a setup failure, not a failed task.
    fn init(settings: &Self::Settings) -> Result<Self, ModuleError>;
}

/// A module that parses files: sync, one task per contained process.
pub trait Parser: Module {
    fn analyze(
        &self,
        ctx: &TaskContext<Self::Settings>,
    ) -> Result<Outcome<Self::Output>, ModuleError>;
}

/// A module that looks something up over the network: async, many tasks per pool process.
pub trait Lookup: Module {
    /// The TCP ports the module connects to.
    const TCP_PORTS: &'static [u16];

    fn analyze(
        &self,
        ctx: &TaskContext<Self::Settings>,
    ) -> impl Future<Output = Result<Outcome<Self::Output>, ModuleError>> + Send;
}

/// How a task ended, when it didn't fail.
// A task returns one Outcome and it's moved once or twice, so the size of the result variant
// costs nothing worth a Box at every module's return.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome<D> {
    /// The result, which the core checks against its schema and stores.
    Done(ResultEnvelope<D>),
    /// Run the task again later, as ace3's `delay_analysis`.
    Delay(Delay),
    /// The module had nothing to say about this observable, such as an archive module given a
    /// file that isn't an archive. No result is stored.
    Skipped(String),
}

/// A request to run the task again after `run_after`, the counterpart of ace3's
/// `delay_analysis` (`saq/modules/base_module.py:685`).
#[derive(Debug, Clone, PartialEq)]
pub struct Delay {
    pub run_after: Duration,
    /// How long after the first delay the task may keep asking for more. Past it, the task fails
    /// with `DelayTimedOut`. A module that wants a result on timeout, such as a query that "timed
    /// out", checks the elapsed time itself first, as ace3's API analyzers do.
    pub timeout: Duration,
    /// What the next run needs, such as a search id. `TaskContext::delay_state` reads it back.
    pub state: serde_json::Value,
}

impl Delay {
    pub fn new(run_after: Duration, timeout: Duration) -> Self {
        Delay {
            run_after,
            timeout,
            state: serde_json::Value::Null,
        }
    }

    pub fn with_state<T: Serialize>(mut self, state: &T) -> Result<Self, ModuleError> {
        self.state = serde_json::to_value(state)
            .map_err(|e| ModuleError::other(format!("delay state doesn't serialize: {e}")))?;
        Ok(self)
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Why a task failed.
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    /// The task was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// A peer the module depends on couldn't be reached. The task can be tried again later.
    #[error("peer unavailable: {0}")]
    Unavailable(#[source] BoxError),
    #[error("secret {0:?} isn't declared in the module's SECRETS")]
    UndeclaredSecret(String),
    #[error("secret {0:?} isn't set")]
    MissingSecret(String),
    #[error("the delay timed out {0:?} after the first delay")]
    DelayTimedOut(Duration),
    #[error("{0}")]
    Other(#[source] BoxError),
}

impl ModuleError {
    pub fn other(error: impl Into<BoxError>) -> Self {
        ModuleError::Other(error.into())
    }
}

impl From<std::io::Error> for ModuleError {
    fn from(error: std::io::Error) -> Self {
        ModuleError::Other(error.into())
    }
}

impl From<crate::files::FileOutputError> for ModuleError {
    fn from(error: crate::files::FileOutputError) -> Self {
        ModuleError::Other(error.into())
    }
}

/// The span a task runs in. Every log line inside it carries the root's uuid, the observable,
/// the module and, when the task came from the queue, its id.
pub fn task_span<S>(module: &'static str, ctx: &TaskContext<S>) -> tracing::Span {
    tracing::info_span!(
        "task",
        root = %ctx.root(),
        observable = %ctx.observable(),
        module = %module,
        task = ctx.task_id(),
    )
}

/// The directive that keeps every module off an observable, as ace3's `exclude_all`.
pub const EXCLUDE_ALL: &str = "exclude_all";

/// The tag and the directive ace3's `Observable.whitelist()` adds, and either one makes an observable
/// whitelisted: no module analyzes it, a result that whitelists the observable it analyzed stops its
/// root's analysis, and a root holding one never becomes an alert (`ace_core::orchestrator`).
pub const WHITELISTED: &str = "whitelisted";

/// The first of the observable's directives that keeps module `M` off it.
fn skipping_directive<M: Module, S>(ctx: &TaskContext<S>) -> Option<&str> {
    ctx.observable()
        .directives
        .iter()
        .map(String::as_str)
        .find(|d| *d == EXCLUDE_ALL || M::SKIP_DIRECTIVES.contains(d))
}

/// Runs a parser on one task, inside the task's span.
pub fn run_parser<M: Parser>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    let span = task_span(M::NAME, ctx);
    let _entered = span.enter();
    ctx.check_cancelled()?;
    if let Some(directive) = skipping_directive::<M, _>(ctx) {
        return Ok(Outcome::Skipped(format!("directive {directive}")));
    }
    let outcome = module.analyze(ctx)?;
    check_delay(ctx, outcome)
}

/// Runs a lookup on one task, inside the task's span. Cancelling the task's token ends it at the
/// module's next await, even if the module never checks the token itself.
pub async fn run_lookup<M: Lookup>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    async {
        ctx.check_cancelled()?;
        if let Some(directive) = skipping_directive::<M, _>(ctx) {
            return Ok(Outcome::Skipped(format!("directive {directive}")));
        }
        let outcome = tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(ModuleError::Cancelled),
            outcome = module.analyze(ctx) => outcome?,
        };
        check_delay(ctx, outcome)
    }
    .instrument(task_span(M::NAME, ctx))
    .await
}

/// Refuses a delay asked for after the timeout of the first one.
fn check_delay<S, D>(ctx: &TaskContext<S>, outcome: Outcome<D>) -> Result<Outcome<D>, ModuleError> {
    if let (Outcome::Delay(delay), Some(delayed)) = (&outcome, ctx.delayed()) {
        let waited = (ctx.now() - delayed.first_delayed_at)
            .to_std()
            .unwrap_or_default();
        if waited >= delay.timeout {
            return Err(ModuleError::DelayTimedOut(delay.timeout));
        }
    }
    Ok(outcome)
}
