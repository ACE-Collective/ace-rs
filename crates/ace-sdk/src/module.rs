//! The module traits: a sync one for parsers and an async one for lookups.
//!
//! A parser reads hostile files in a contained process of its own, so it is plain blocking code
//! that polls `TaskContext::is_cancelled`. A lookup waits on the network inside a shared async
//! pool, many tasks at a time, and selects on `TaskContext::cancelled`.

use std::future::Future;
use std::time::Duration;

use ace_results::{AnalysisType, ResultEnvelope};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::context::TaskContext;

/// A module's settings: the block a site's config overlay gives it. Missing settings fall back
/// to `Default`. Derive `Deserialize` with `#[serde(deny_unknown_fields)]`; the loader refuses
/// unknown keys either way.
pub trait Settings: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static {}

impl<T: DeserializeOwned + JsonSchema + Default + Send + Sync + 'static> Settings for T {}

/// What every module has, whichever way it runs.
pub trait Module: Sized + Send + Sync + 'static {
    /// The module's name, as configured and as named in a result's `exclude_modules`.
    const NAME: &'static str;
    /// The names of the secrets the module reads. The task context gives it these and no others.
    const SECRETS: &'static [&'static str] = &[];

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
    fn analyze(
        &self,
        ctx: &TaskContext<Self::Settings>,
    ) -> impl Future<Output = Result<Outcome<Self::Output>, ModuleError>> + Send;
}

/// How a task ended, when it didn't fail.
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

/// Runs a parser on one task.
pub fn run_parser<M: Parser>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    ctx.check_cancelled()?;
    let outcome = module.analyze(ctx)?;
    check_delay(ctx, outcome)
}

/// Runs a lookup on one task. Cancelling the task's token ends it at the module's next await,
/// even if the module never checks the token itself.
pub async fn run_lookup<M: Lookup>(
    module: &M,
    ctx: &TaskContext<M::Settings>,
) -> Result<Outcome<M::Output>, ModuleError> {
    ctx.check_cancelled()?;
    let outcome = tokio::select! {
        biased;
        () = ctx.cancelled() => return Err(ModuleError::Cancelled),
        outcome = module.analyze(ctx) => outcome?,
    };
    check_delay(ctx, outcome)
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
