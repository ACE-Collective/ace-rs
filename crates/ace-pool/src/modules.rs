//! The modules a pool runs, behind one interface each for parsers and lookups, so a pool's
//! runtime handles a leased task without knowing the module's types.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use ace_results::AnalysisType;
use ace_sdk::wire::{LeasedTask, TaskEnd};
use ace_sdk::{
    FileStore, Lookup, Manifest, ModuleError, Outcome, Parser, Secrets, SettingsError, TaskContext,
    load_settings, run_lookup, run_parser,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("module {module}: {source}")]
    Settings {
        module: &'static str,
        #[source]
        source: SettingsError,
    },
    #[error("module {module}: {source}")]
    Init {
        module: &'static str,
        #[source]
        source: ModuleError,
    },
}

/// Where a task runs and what it may use.
pub struct Run<'a> {
    pub task: &'a LeasedTask,
    /// The input file's bytes on this machine, for a file task.
    pub input: Option<&'a Path>,
    /// Where the module's output files go.
    pub outputs: Arc<dyn FileStore>,
    pub cancel: CancellationToken,
    /// True when the task runs contained (PLAN.md 2.18), so the module avoids what starts
    /// threads.
    pub contained: bool,
}

/// A parser a pool runs, built with its settings.
pub trait PoolParser: Send + Sync {
    fn manifest(&self) -> Manifest;
    fn run(&self, run: Run<'_>) -> TaskEnd;
}

/// A lookup a pool runs, built with its settings.
pub trait PoolLookup: Send + Sync {
    fn manifest(&self) -> Manifest;
    fn run<'a>(&'a self, run: Run<'a>) -> Pin<Box<dyn Future<Output = TaskEnd> + Send + 'a>>;
}

/// A module, its settings and the secrets it declared.
pub struct Entry<M: ace_sdk::Module> {
    module: M,
    settings: Arc<M::Settings>,
    secrets: Secrets,
    manifest: Manifest,
}

impl<M: ace_sdk::Module> Entry<M> {
    fn build(
        manifest: Manifest,
        settings: Option<&Value>,
        secrets: &Secrets,
    ) -> Result<Self, SetupError> {
        let settings: M::Settings =
            load_settings(settings).map_err(|source| SetupError::Settings {
                module: M::NAME,
                source,
            })?;
        let module = M::init(&settings).map_err(|source| SetupError::Init {
            module: M::NAME,
            source,
        })?;
        Ok(Entry {
            module,
            settings: Arc::new(settings),
            secrets: secrets.clone(),
            manifest,
        })
    }

    fn context(&self, run: &Run<'_>) -> TaskContext<M::Settings> {
        let ctx = TaskContext::new::<M>(
            run.task.root,
            run.task.observable.to_observable(run.input),
            self.settings.clone(),
        )
        .with_secrets(&self.secrets)
        .with_cancel(run.cancel.clone())
        .with_file_store(run.outputs.clone())
        .with_contained(run.contained)
        .with_task_id(run.task.id);
        match &run.task.delayed {
            Some(delayed) => ctx.with_delayed(delayed.clone()),
            None => ctx,
        }
    }
}

impl<M: Parser> Entry<M> {
    /// A parser with its settings block, which loads as a site overlay's would.
    pub fn parser(settings: Option<&Value>, secrets: &Secrets) -> Result<Self, SetupError> {
        Entry::build(Manifest::parser::<M>(), settings, secrets)
    }
}

impl<M: Lookup> Entry<M> {
    pub fn lookup(settings: Option<&Value>, secrets: &Secrets) -> Result<Self, SetupError> {
        Entry::build(Manifest::lookup::<M>(), settings, secrets)
    }
}

impl<M: Parser> PoolParser for Entry<M> {
    fn manifest(&self) -> Manifest {
        self.manifest
    }

    fn run(&self, run: Run<'_>) -> TaskEnd {
        task_end(run_parser(&self.module, &self.context(&run)))
    }
}

impl<M: Lookup> PoolLookup for Entry<M> {
    fn manifest(&self) -> Manifest {
        self.manifest
    }

    fn run<'a>(&'a self, run: Run<'a>) -> Pin<Box<dyn Future<Output = TaskEnd> + Send + 'a>> {
        Box::pin(async move {
            let ctx = self.context(&run);
            task_end(run_lookup(&self.module, &ctx).await)
        })
    }
}

/// How a module's run ends, as the lease API takes it.
pub fn task_end<D: AnalysisType>(outcome: Result<Outcome<D>, ModuleError>) -> TaskEnd {
    match outcome {
        Ok(Outcome::Done(result)) => match result.to_raw() {
            Ok(result) => TaskEnd::Done { result },
            Err(e) => TaskEnd::Failed {
                error: format!("the result doesn't serialize: {e}"),
            },
        },
        Ok(Outcome::Delay(delay)) => TaskEnd::Delay {
            after_seconds: delay.run_after.as_secs_f64(),
            state: delay.state,
        },
        Ok(Outcome::Skipped(reason)) => TaskEnd::Skipped { reason },
        Err(ModuleError::Cancelled) => TaskEnd::Cancelled,
        Err(e) => TaskEnd::Failed {
            error: e.to_string(),
        },
    }
}

/// The modules one pool runs, by name.
#[derive(Default)]
pub struct Modules {
    parsers: BTreeMap<String, Box<dyn PoolParser>>,
    lookups: BTreeMap<String, Box<dyn PoolLookup>>,
}

impl Modules {
    pub fn new() -> Self {
        Modules::default()
    }

    pub fn with_parser(mut self, parser: impl PoolParser + 'static) -> Self {
        self.parsers
            .insert(parser.manifest().name.to_owned(), Box::new(parser));
        self
    }

    pub fn with_lookup(mut self, lookup: impl PoolLookup + 'static) -> Self {
        self.lookups
            .insert(lookup.manifest().name.to_owned(), Box::new(lookup));
        self
    }

    pub fn parser(&self, name: &str) -> Option<&dyn PoolParser> {
        self.parsers.get(name).map(|p| p.as_ref())
    }

    pub fn lookup(&self, name: &str) -> Option<&dyn PoolLookup> {
        self.lookups.get(name).map(|l| l.as_ref())
    }

    /// The names of every module, parsers and lookups.
    pub fn names(&self) -> Vec<String> {
        self.parsers
            .keys()
            .chain(self.lookups.keys())
            .cloned()
            .collect()
    }

    pub fn manifests(&self) -> Vec<Manifest> {
        self.parsers
            .values()
            .map(|p| p.manifest())
            .chain(self.lookups.values().map(|l| l.manifest()))
            .collect()
    }
}
