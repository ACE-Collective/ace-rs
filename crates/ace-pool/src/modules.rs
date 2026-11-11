//! The modules a pool runs, behind one interface each for parsers and lookups, so a pool's
//! runtime handles a leased task without knowing the module's types. Each runs as a component
//! (PLAN.md 2.23): the module as itself, or a named instance of it from the site overlay, keyed
//! by the name its tasks carry.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use ace_results::AnalysisType;
use ace_sdk::reads::Reader;
use ace_sdk::tools::{LocalRunner, ToolRunner, ToolSpec};
use ace_sdk::wire::{LeasedTask, TaskEnd};
use ace_sdk::writes::WireWrite;
use ace_sdk::{
    CarryingEmail, Component, FileStore, Lookup, Manifest, ModuleError, Outcome, Parser, Secrets,
    SettingsError, TaskContext, load_settings, run_lookup, run_parser,
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
    #[error("this pool has no module {0}")]
    Unknown(String),
}

/// Why a pool's modules didn't start from the overlay.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Overlay(#[from] ace_sdk::OverlayError),
    #[error(transparent)]
    Setup(#[from] SetupError),
}

/// Where a task runs and what it may use.
pub struct Run<'a> {
    pub task: &'a LeasedTask,
    /// The input file's bytes on this machine, for a file task.
    pub input: Option<&'a Path>,
    /// The body of the email that carried the task's file, for a module that reads it.
    pub email_body: Option<&'a Path>,
    /// The directory of the tree's files the module reads, each named by its sha256.
    pub tree_files: Option<&'a Path>,
    /// Where the module's output files go.
    pub outputs: Arc<dyn FileStore>,
    pub cancel: CancellationToken,
    /// True when the task runs contained (PLAN.md 2.18), so the module avoids what starts
    /// threads.
    pub contained: bool,
    /// What makes the task's reads of ACE's data (PLAN.md 7.2): the lease API, for a lookup.
    pub reader: Option<Arc<dyn Reader>>,
    /// What runs the module's tools (PLAN.md 7.3): the supervisor, for a contained task.
    pub tools: Option<Arc<dyn ToolRunner>>,
    /// The task's latest scan's output archive on this machine (PLAN.md 7.7).
    pub scan_output: Option<&'a Path>,
}

impl Run<'_> {
    /// What the task's leased form and its fetched file say of the email that carried it.
    /// The task's latest scan, as its module reads it, with its output where the pool put it.
    fn scan(&self) -> Option<ace_sdk::scanners::Scan> {
        self.task.scan.as_ref().map(|scan| ace_sdk::scanners::Scan {
            id: scan.id,
            scanner: scan.scanner.clone(),
            state: scan.state,
            exit_code: scan.exit_code,
            error: scan.error.clone(),
            output: self.scan_output.map(Path::to_path_buf),
        })
    }

    fn carrying_email(&self) -> CarryingEmail {
        if self.task.emails_pending {
            return CarryingEmail::Pending;
        }
        match (&self.task.carrying_email, self.email_body) {
            (None, _) => CarryingEmail::Absent,
            (Some(_), Some(body)) => CarryingEmail::Body(body.to_owned()),
            (Some(_), None) => CarryingEmail::NoBody,
        }
    }
}

/// A parser a pool runs, built with its settings.
pub trait PoolParser: Send + Sync {
    fn manifest(&self) -> Manifest;
    /// The name its tasks carry: the module's, or its instance's.
    fn key(&self) -> &str;
    fn run(&self, run: Run<'_>) -> TaskEnd;
}

/// A lookup a pool runs, built with its settings.
pub trait PoolLookup: Send + Sync {
    fn manifest(&self) -> Manifest;
    fn key(&self) -> &str;
    fn run<'a>(&'a self, run: Run<'a>) -> Pin<Box<dyn Future<Output = TaskEnd> + Send + 'a>>;
}

/// A module, its settings and the secrets it declared, under its component's key.
pub struct Entry<M: ace_sdk::Module> {
    module: M,
    settings: Arc<M::Settings>,
    secrets: Secrets,
    manifest: Manifest,
    key: String,
}

impl<M: ace_sdk::Module> Entry<M> {
    fn build(
        manifest: Manifest,
        key: &str,
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
            key: key.to_owned(),
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
        .with_task_id(run.task.id)
        .with_yara_rules_below(run.task.yara_rules_below.clone())
        .with_carrying_email(run.carrying_email())
        .with_lists(run.task.lists.clone())
        .with_reader(run.reader.clone())
        .with_dependency_results(run.task.dependency_results.clone())
        .with_observables_below(run.task.observables_below.clone())
        .with_added_by(run.task.added_by.clone())
        .with_related_tags(run.task.related_tags.clone())
        .with_tree(run.task.tree.clone())
        .with_tree_files(run.tree_files.map(Path::to_path_buf))
        .with_tool_runner(run.tools.clone())
        .with_scan(run.scan());
        match &run.task.delayed {
            Some(delayed) => ctx.with_delayed(delayed.clone()),
            None => ctx,
        }
    }
}

impl<M: Parser> Entry<M> {
    /// A parser with its settings block, which loads as a site overlay's would.
    pub fn parser(settings: Option<&Value>, secrets: &Secrets) -> Result<Self, SetupError> {
        Entry::build(Manifest::parser::<M>(), M::NAME, settings, secrets)
    }
}

impl<M: Lookup> Entry<M> {
    pub fn lookup(settings: Option<&Value>, secrets: &Secrets) -> Result<Self, SetupError> {
        Entry::build(Manifest::lookup::<M>(), M::NAME, settings, secrets)
    }
}

impl<M: Parser> PoolParser for Entry<M> {
    fn manifest(&self) -> Manifest {
        self.manifest
    }

    fn key(&self) -> &str {
        &self.key
    }

    fn run(&self, run: Run<'_>) -> TaskEnd {
        task_end(run_parser(&self.module, &self.context(&run)), Vec::new())
    }
}

impl<M: Lookup> PoolLookup for Entry<M> {
    fn manifest(&self) -> Manifest {
        self.manifest
    }

    fn key(&self) -> &str {
        &self.key
    }

    fn run<'a>(&'a self, run: Run<'a>) -> Pin<Box<dyn Future<Output = TaskEnd> + Send + 'a>> {
        Box::pin(async move {
            let ctx = self.context(&run);
            let outcome = run_lookup(&self.module, &ctx).await;
            task_end(outcome, ctx.take_writes())
        })
    }
}

/// How a module's run ends, as the lease API takes it, with what it wrote (`Module::WRITES`) when
/// it ends with a result or a skip. Any other end drops them: a task that fails, delays or is
/// cancelled writes nothing.
pub fn task_end<D: AnalysisType>(
    outcome: Result<Outcome<D>, ModuleError>,
    writes: Vec<WireWrite>,
) -> TaskEnd {
    match outcome {
        Ok(Outcome::Done(result)) => match result.to_raw() {
            Ok(result) => TaskEnd::Done { result, writes },
            Err(e) => TaskEnd::Failed {
                error: format!("the result doesn't serialize: {e}"),
            },
        },
        Ok(Outcome::Delay(delay)) => TaskEnd::Delay {
            after_seconds: delay.run_after.as_secs_f64(),
            state: delay.state,
            scan: delay.scan,
        },
        Ok(Outcome::Skipped(reason)) => TaskEnd::Skipped { reason, writes },
        Err(ModuleError::Cancelled) => TaskEnd::Cancelled,
        Err(e) => TaskEnd::Failed {
            error: e.to_string(),
        },
    }
}

/// The modules one pool runs, by name, and the tools its image carries.
#[derive(Default)]
pub struct Modules {
    parsers: BTreeMap<String, Box<dyn PoolParser>>,
    lookups: BTreeMap<String, Box<dyn PoolLookup>>,
    tools: Vec<ToolSpec>,
}

impl Modules {
    pub fn new() -> Self {
        Modules::default()
    }

    pub fn with_parser(mut self, parser: impl PoolParser + 'static) -> Self {
        self.parsers
            .insert(parser.key().to_owned(), Box::new(parser));
        self
    }

    pub fn with_lookup(mut self, lookup: impl PoolLookup + 'static) -> Self {
        self.lookups
            .insert(lookup.key().to_owned(), Box::new(lookup));
        self
    }

    /// The tools the pool's image carries, which its modules may declare (PLAN.md 7.3).
    pub fn with_tools(mut self, tools: &[ToolSpec]) -> Self {
        self.tools = tools.to_vec();
        self
    }

    pub fn tools(&self) -> &[ToolSpec] {
        &self.tools
    }

    /// The tools a module declares that the pool doesn't carry, as `module: tool`.
    pub fn missing_tools(&self) -> Vec<String> {
        self.manifests()
            .iter()
            .flat_map(|m| m.tools.iter().map(move |tool| (m.name, *tool)))
            .filter(|(_, tool)| ace_sdk::tools::find(&self.tools, tool).is_none())
            .map(|(module, tool)| format!("{module}: {tool}"))
            .collect()
    }

    /// A runner of `module`'s tools as plain processes, for a task run in this process with no
    /// containment (`run_in_process`, a replay). None for a module that declares none.
    pub fn local_tools(&self, module: &str) -> std::io::Result<Option<Arc<dyn ToolRunner>>> {
        let Some(parser) = self.parser(module) else {
            return Ok(None);
        };
        let declared = parser.manifest().tools;
        if declared.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(LocalRunner::new(&self.tools, declared)?)))
    }

    pub fn parser(&self, name: &str) -> Option<&dyn PoolParser> {
        self.parsers.get(name).map(|p| p.as_ref())
    }

    pub fn lookup(&self, name: &str) -> Option<&dyn PoolLookup> {
        self.lookups.get(name).map(|l| l.as_ref())
    }

    /// The keys of every component, parsers and lookups.
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

/// Builds one component of a module type the registry knows.
type Build = fn(&Component, &Secrets, Modules) -> Result<Modules, SetupError>;

fn build_parser<M: Parser>(
    component: &Component,
    secrets: &Secrets,
    modules: Modules,
) -> Result<Modules, SetupError> {
    let entry = Entry::<M>::build(
        component.manifest,
        &component.key,
        component.settings.as_ref(),
        secrets,
    )?;
    Ok(modules.with_parser(entry))
}

fn build_lookup<M: Lookup>(
    component: &Component,
    secrets: &Secrets,
    modules: Modules,
) -> Result<Modules, SetupError> {
    let entry = Entry::<M>::build(
        component.manifest,
        &component.key,
        component.settings.as_ref(),
        secrets,
    )?;
    Ok(modules.with_lookup(entry))
}

/// The module types a binary links, so it can build the components a site overlay makes of
/// them without knowing their types.
#[derive(Default)]
pub struct Registry {
    modules: Vec<(Manifest, Build)>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    pub fn parser<M: Parser>(mut self) -> Self {
        self.modules
            .push((Manifest::parser::<M>(), build_parser::<M>));
        self
    }

    pub fn lookup<M: Lookup>(mut self) -> Self {
        self.modules
            .push((Manifest::lookup::<M>(), build_lookup::<M>));
        self
    }

    /// This registry's modules followed by `other`'s, as a binary that links several pools'.
    pub fn merge(mut self, other: &Registry) -> Self {
        self.modules.extend_from_slice(&other.modules);
        self
    }

    pub fn manifests(&self) -> Vec<Manifest> {
        self.modules.iter().map(|(manifest, _)| *manifest).collect()
    }

    /// The pool's modules from the site overlay: every component it makes of the registry's
    /// modules, skipping other pools' sections without a warning, with the secrets their manifests declare and no others (PLAN.md 2.24), read
    /// through `env` and the files the overlay names.
    pub fn start(
        &self,
        pool: &str,
        overlay: &ace_sdk::Overlay,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Modules, StartError> {
        let manifests = self.manifests();
        let components = overlay.for_pool(&manifests).components(&manifests)?;
        let secrets = crate::secrets::resolve(pool, &manifests, overlay, env);
        Ok(self.build(&components, &secrets)?)
    }

    /// Builds each of `components`, with its settings and `secrets`.
    pub fn build(
        &self,
        components: &[Component],
        secrets: &Secrets,
    ) -> Result<Modules, SetupError> {
        components
            .iter()
            .try_fold(Modules::new(), |modules, component| {
                let (_, build) = self
                    .modules
                    .iter()
                    .find(|(manifest, _)| manifest.name == component.manifest.name)
                    .ok_or_else(|| SetupError::Unknown(component.manifest.name.to_owned()))?;
                build(component, secrets, modules)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_results::ObservableKind;
    use ace_sdk::LocalFileStore;
    use ace_sdk::wire::{CarryingEmail as WireEmail, TaskObservable};
    use uuid::Uuid;

    fn task(carrying_email: Option<WireEmail>, emails_pending: bool) -> LeasedTask {
        LeasedTask {
            id: 1,
            root: Uuid::nil(),
            module: "m".to_owned(),
            attempts: 1,
            lease_expires_at: chrono::Utc::now(),
            lease_seconds: 1.0,
            observable: TaskObservable {
                kind: ObservableKind::File,
                value: String::new(),
                time: None,
                directives: Vec::new(),
                file: None,
                redirection: None,
                relationships: Vec::new(),
            },
            delayed: None,
            input_hashes: Vec::new(),
            carrying_email,
            emails_pending,
            yara_rules_below: Vec::new(),
            lists: Vec::new(),
            dependency_results: Default::default(),
            observables_below: Vec::new(),
            added_by: Vec::new(),
            related_tags: Vec::new(),
            tree: None,
            scan: None,
        }
    }

    /// PLAN.md 7.2: a task's writes go with a result or a skip, and with no other end.
    #[test]
    fn writes_go_only_with_a_result_or_a_skip() {
        use ace_results::types::brocess::EmailLoggingAnalysis;
        let writes = || {
            vec![WireWrite {
                write: "smtp-log".to_owned(),
                body: serde_json::json!({"rows": []}),
            }]
        };
        let result = ace_results::ResultEnvelope::new(EmailLoggingAnalysis {});
        let ends = [
            task_end(Ok(Outcome::Done(result)), writes()),
            task_end::<EmailLoggingAnalysis>(Ok(Outcome::Skipped("x".to_owned())), writes()),
            task_end::<EmailLoggingAnalysis>(
                Ok(Outcome::Delay(ace_sdk::Delay::new(
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(9),
                ))),
                writes(),
            ),
            task_end::<EmailLoggingAnalysis>(Err(ModuleError::other("broke")), writes()),
            task_end::<EmailLoggingAnalysis>(Err(ModuleError::Cancelled), writes()),
        ];
        let carried: Vec<usize> = ends
            .iter()
            .map(|end| match end {
                TaskEnd::Done { writes, .. } | TaskEnd::Skipped { writes, .. } => writes.len(),
                _ => 0,
            })
            .collect();
        assert_eq!(carried, [1, 1, 0, 0, 0]);
    }

    #[test]
    fn a_module_is_told_what_its_lease_and_its_fetched_file_say_of_the_email() {
        let dir = tempfile::tempdir().expect("a directory");
        let store: Arc<dyn FileStore> =
            Arc::new(LocalFileStore::new(dir.path().join("o")).expect("a store"));
        let body = dir.path().join("email_body");
        let state = |task: &LeasedTask, email_body: Option<&Path>| {
            Run {
                task,
                input: None,
                email_body,
                tree_files: None,
                outputs: store.clone(),
                cancel: CancellationToken::new(),
                contained: false,
                reader: None,
                tools: None,
                scan_output: None,
            }
            .carrying_email()
        };
        let no_body = task(Some(WireEmail { body: None }), false);
        assert_eq!(state(&task(None, true), None), CarryingEmail::Pending);
        assert_eq!(state(&task(None, false), None), CarryingEmail::Absent);
        assert_eq!(state(&no_body, None), CarryingEmail::NoBody);
        assert_eq!(
            state(&no_body, Some(&body)),
            CarryingEmail::Body(body.clone())
        );
    }
}
