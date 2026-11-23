//! The orchestrator: what happens when a result lands, and when a root's mode changes.
//!
//! A result lands in one transaction with its task's end: the result row, the observables it
//! adds, what it adds to the observable it analyzed and to the one that redirects to, its
//! detections, and the tasks that just became eligible. A detection in a detectable mode turns the root into an alert in
//! correlation mode, as ace3's engine does (`analysis_orchestrator.py`, `_handle_detection_points`),
//! and a mode change reruns eligibility over every observable the root has.
//!
//! Each of these locks the root's row first, so two results landing on one root take turns:
//! the second sees the first's observables and mode, and nothing the first made eligible is
//! missed. Landing a result checks the root's completion last, so the tasks it queues keep the
//! same pass open.
//!
//! The site's global exclusions (`ace_sdk::exclusions`, ace3's `observable_exclusions`) keep every
//! task off an observable they name: eligibility queues nothing for it, not its type step, and the
//! observable modifier's rules don't evaluate it, as ace3's executor drops such a work item before
//! any module, its modifier among them, sees it. The observable stays in the tree.
//!
//! ace3's whitelisting is gone, as ace3 removed it (8617ba8e): a `whitelisted` tag or directive is an
//! ordinary one, which keeps nothing off and doesn't stop a root from alerting.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use ace_results::{
    Detection, FieldError, NewObservable, ObservableAdditions, ObservableKind, ObservableRef,
    Registry, ResultEnvelope,
};
use ace_sdk::exclusions::Exclusions;
use serde_json::Value;
use uuid::Uuid;

use crate::cache::{self, CacheSettings};
use crate::db::{DbError, Retryable, Tx};
use crate::eligibility::{self, Catalog, Facts, TaskSeen, check};
use crate::hooks::{self, Hooks};
use crate::limits;
use crate::modes::{CORRELATION, DISPOSITIONED, Modes};
use crate::queue::{self, QueueError, Task, TaskId, TaskState, Worker};
use crate::takes::{self as declared, TakesMode};
use crate::tree::{self, ObservableId, ResultId};
use crate::type_step::{self, TYPE_STEP};

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("no root {0}")]
    NoRoot(Uuid),
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for OrchestratorError {
    fn from(error: sqlx::Error) -> Self {
        OrchestratorError::Db(DbError::Sqlx(error))
    }
}

impl Retryable for OrchestratorError {
    fn is_retryable(&self) -> bool {
        match self {
            OrchestratorError::Db(e) => e.is_retryable(),
            OrchestratorError::Queue(e) => e.is_retryable(),
            OrchestratorError::NoRoot(_) => false,
        }
    }
}

/// Which of a root's observables to look at.
#[derive(Debug, Clone, Copy)]
pub enum Scope<'a> {
    All,
    Observables(&'a [ObservableId]),
}

/// What landing a result did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landed {
    pub result: ResultId,
    /// Tasks queued because the result made them eligible, and its QA task if it has QA
    /// matches.
    pub queued: Vec<TaskId>,
    /// The mode the root changed to, when a detection made it an alert.
    pub mode_changed_to: Option<String>,
}

/// What a disposition did to an alert's analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispositioned {
    pub cancelled: queue::CancelledRoot,
    /// The dispositioned mode's tasks.
    pub queued: Vec<TaskId>,
}

/// The modules the core runs, and the modes that choose among them.
#[derive(Debug, Clone)]
pub struct Orchestrator {
    catalog: Catalog,
    modes: Modes,
    /// The catalog's analysis types and their schemas, built the first time a result is
    /// checked.
    registry: Arc<OnceLock<Result<Registry, String>>>,
    /// The hooks the core runs over the tree (`crate::hooks`).
    hooks: Hooks,
    /// Whether the modules' declarations keep tasks off the queue or are only audited
    /// (`crate::takes`).
    takes: TakesMode,
    /// The observables no module analyzes (`ace_sdk::exclusions`).
    exclusions: Arc<Exclusions>,
    /// The analysis cache's settings (`crate::cache`).
    cache: CacheSettings,
}

/// The targets of the relationships `result` adds to observables already in the root that are
/// neither in `root` nor added by `result` (PLAN.md decision 37), each once.
async fn unlandable_targets<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    root: Uuid,
    result: &ResultEnvelope<Value>,
) -> Result<Vec<ObservableRef>, DbError> {
    let added: BTreeSet<ObservableRef> = result
        .observables
        .iter()
        .map(|o| ObservableRef::new(o.kind, o.value.clone()))
        .chain(
            result
                .files
                .iter()
                .map(|f| ObservableRef::new(ObservableKind::File, f.sha256.to_hex())),
        )
        .collect();
    let mut targets: Vec<ObservableRef> = Vec::new();
    for additions in [&result.analyzed, &result.redirected]
        .into_iter()
        .chain(result.others.iter().map(|o| &o.additions))
    {
        for relationship in &additions.relationships {
            if !added.contains(&relationship.target) && !targets.contains(&relationship.target) {
                targets.push(relationship.target.clone());
            }
        }
    }
    tree::missing_observables(executor, root, &targets).await
}

/// `additions` without its relationships to `unlandable`.
fn landable<'a>(
    additions: &'a ObservableAdditions,
    unlandable: &[ObservableRef],
) -> Cow<'a, ObservableAdditions> {
    if unlandable.is_empty()
        || !additions
            .relationships
            .iter()
            .any(|r| unlandable.contains(&r.target))
    {
        return Cow::Borrowed(additions);
    }
    let mut kept = additions.clone();
    kept.relationships
        .retain(|r| !unlandable.contains(&r.target));
    Cow::Owned(kept)
}

/// How a task's result ends it (`Orchestrator::land_ending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Done, and kept by the analysis cache where its module's results are kept.
    Done,
    /// Done, and not kept (`Outcome::DoneNotKept`, PLAN.md decision 47).
    DoneNotKept,
    /// As far as it goes, run again on a change (`Outcome::Incomplete`, PLAN.md decision 34), and
    /// not kept.
    Incomplete,
}

/// Why a result was refused before anything from it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub error: String,
    /// Each field that failed the type's schema, by JSON pointer.
    pub fields: Vec<FieldError>,
}

impl Orchestrator {
    pub fn new(catalog: Catalog, modes: Modes) -> Self {
        Orchestrator {
            catalog,
            modes,
            registry: Arc::default(),
            hooks: Hooks::none(),
            takes: TakesMode::default(),
            exclusions: Arc::new(Exclusions::ace3()),
            cache: CacheSettings::default(),
        }
    }

    /// This orchestrator, with the analysis cache on or off as `cache` says (`crate::cache`). A new
    /// one has ace3's default: on, for the modules that opt in.
    pub fn with_cache(mut self, cache: CacheSettings) -> Self {
        self.cache = cache;
        self
    }

    pub fn cache(&self) -> &CacheSettings {
        &self.cache
    }

    /// This orchestrator, keeping every task off the observables `exclusions` name. A new one has
    /// ace3's defaults (`Exclusions::ace3`).
    pub fn with_exclusions(mut self, exclusions: Exclusions) -> Self {
        self.exclusions = Arc::new(exclusions);
        self
    }

    pub fn exclusions(&self) -> &Exclusions {
        &self.exclusions
    }

    /// This orchestrator, applying or auditing the modules' declarations (`crate::takes`).
    pub fn with_takes(mut self, takes: TakesMode) -> Self {
        self.takes = takes;
        self
    }

    pub fn takes(&self) -> TakesMode {
        self.takes
    }

    /// This orchestrator, running `hooks` (`crate::hooks`).
    pub fn with_hooks(mut self, hooks: Hooks) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn hooks(&self) -> &Hooks {
        &self.hooks
    }

    /// Checks a result before it lands (PLAN.md 2.15): its type is the one `module`'s manifest
    /// says it writes, and it passes that type's JSON Schema.
    pub fn check_result(&self, module: &str, result: &Value) -> Result<(), Rejected> {
        let rejected = |error: String| Rejected {
            error,
            fields: Vec::new(),
        };
        let manifest = self
            .catalog
            .get(module)
            .ok_or_else(|| rejected(format!("no module {module} in the catalog")))?;
        let name = result.get("analysis_type").and_then(Value::as_str);
        let version = result.get("schema_version").and_then(Value::as_u64);
        if name != Some(manifest.output.name) || version != Some(u64::from(manifest.output.version))
        {
            return Err(rejected(format!(
                "{module} writes {} version {}, not {} version {}",
                manifest.output.name,
                manifest.output.version,
                name.unwrap_or("nothing"),
                version.map_or("none".to_owned(), |v| v.to_string()),
            )));
        }
        if let Some(others) = result.get("others").and_then(Value::as_array)
            && !others.is_empty()
        {
            let Some(allowed) = manifest.adds_to_others else {
                return Err(rejected(format!(
                    "{module} doesn't declare what it adds to other observables (Module::ADDS_TO_OTHERS)"
                )));
            };
            for other in others {
                let additions: ace_results::ObservableAdditions =
                    serde_json::from_value(other.get("additions").cloned().unwrap_or_default())
                        .map_err(|e| rejected(format!("an entry of others doesn't read: {e}")))?;
                if let Some(why) = allowed.refusal(&additions) {
                    return Err(rejected(format!(
                        "{module} doesn't declare {why} among what it adds to other observables \
                         (Module::ADDS_TO_OTHERS)"
                    )));
                }
            }
        }
        // what a result limits the analysis of what it adds to is only what it declares (PLAN.md
        // decision 48)
        let limits = ["observables", "files"]
            .into_iter()
            .filter_map(|key| result.get(key).and_then(Value::as_array))
            .flatten()
            .filter_map(|added| added.get("limit_modules").and_then(Value::as_array))
            .flatten();
        for limit in limits {
            let name = limit.as_str().unwrap_or_default();
            if !manifest.limits_analysis_to.contains(&name) {
                return Err(rejected(format!(
                    "{module} doesn't declare that it limits what it adds to {limit} \
                     (Module::LIMITS_ANALYSIS_TO)"
                )));
            }
        }
        if let Some(root) = result.get("root").filter(|root| !root.is_null()) {
            let changes = |key: &str| root.get(key).is_some_and(|v| !v.is_null());
            if (changes("description") || changes("details")) && !manifest.sets_root {
                return Err(rejected(format!(
                    "{module} doesn't declare that it changes its root (Module::SETS_ROOT)"
                )));
            }
            let links = root
                .get("pivot_links")
                .and_then(Value::as_array)
                .is_some_and(|links| !links.is_empty());
            if links && !manifest.adds_root_pivot_links {
                return Err(rejected(format!(
                    "{module} doesn't declare that it adds links to its root \
                     (Module::ADDS_ROOT_PIVOT_LINKS)"
                )));
            }
        }
        let registry = self
            .registry
            .get_or_init(|| {
                // a module's instances share its analysis type, listed once
                let mut modules = BTreeSet::new();
                let outputs: Vec<_> = self
                    .catalog
                    .iter()
                    .filter(|c| modules.insert(c.manifest.name))
                    .map(|c| c.manifest.output)
                    .collect();
                Registry::new(&outputs).map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| rejected(format!("the catalog's analysis types: {e}")))?;
        registry.validate(result).map_err(|invalid| Rejected {
            error: invalid.to_string(),
            fields: invalid.fields().to_vec(),
        })
    }

    /// Checks the relationships a result adds to observables already in the root (`analyzed`,
    /// `redirected`, `others`; PLAN.md decision 37) before it lands: each target must be in the
    /// root or added by the result, as ace3's `add_relationship` takes an observable of the tree.
    pub async fn check_relationship_targets<'e>(
        &self,
        executor: impl sqlx::PgExecutor<'e>,
        root: Uuid,
        result: &ResultEnvelope<Value>,
    ) -> Result<Result<(), Rejected>, DbError> {
        let missing = unlandable_targets(executor, root, result).await?;
        Ok(match missing.first() {
            None => Ok(()),
            Some(target) => Err(Rejected {
                error: format!(
                    "a relationship's target {}:{} is neither in the root nor added by the result",
                    target.kind, target.value
                ),
                fields: Vec::new(),
            }),
        })
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn modes(&self) -> &Modes {
        &self.modes
    }

    /// Queues every eligible (observable, module) pair in `scope` that has no task yet. With
    /// `requeue_cancelled`, a cancelled task whose module is eligible runs again, as after a
    /// mode change.
    pub async fn queue_eligible(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        scope: Scope<'_>,
        requeue_cancelled: bool,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        let locked = lock_root(tx, root).await?;
        if locked.cancelled {
            return Ok(Vec::new());
        }
        self.queue_eligible_locked(tx, root, &locked.mode, scope, requeue_cancelled)
            .await
    }

    /// `queue_eligible` with the root locked. Its future is boxed: a hit it finds lands a result,
    /// whose eligibility runs this again (`try_hit`).
    fn queue_eligible_locked<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        mode: &'a str,
        scope: Scope<'a>,
        requeue_cancelled: bool,
    ) -> QueueFuture<'a> {
        Box::pin(self.queue_eligible_unboxed(tx, root, mode, scope, requeue_cancelled, false))
    }

    /// `queue_eligible_locked` for a new pass of the root, which runs again every task that ended
    /// incomplete, changed or not (PLAN.md decision 34), as well as what a disposition cancelled.
    fn queue_eligible_pass<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        mode: &'a str,
    ) -> QueueFuture<'a> {
        Box::pin(self.queue_eligible_unboxed(tx, root, mode, Scope::All, true, true))
    }

    async fn queue_eligible_unboxed(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        scope: Scope<'_>,
        requeue_cancelled: bool,
        rerun_all: bool,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        // what the mode runs and the binary has: a dependency outside it never has a result
        let catalog = self.catalog.keys();
        let mut mode_modules = self.modes.modules_in(mode);
        mode_modules.retain(|m| catalog.contains(m));
        let only: Option<Vec<i64>> = match scope {
            Scope::All => None,
            Scope::Observables(ids) => Some(ids.iter().map(|id| id.0).collect()),
        };
        let observables = sqlx::query!(
            r#"SELECT id AS "id: ObservableId", type AS kind, value, directives, exclude_modules,
                      limit_modules, type_result
               FROM analysis.observables
               WHERE root_id = $1 AND ($2::bigint[] IS NULL OR id = ANY($2))
               ORDER BY id"#,
            root,
            only.as_deref(),
        )
        .fetch_all(tx.conn())
        .await?;
        let mut results: BTreeMap<ObservableId, BTreeSet<String>> = BTreeMap::new();
        for row in sqlx::query!(
            r#"SELECT observable_id AS "observable_id: ObservableId", module
               FROM analysis.results
               WHERE root_id = $1 AND ($2::bigint[] IS NULL OR observable_id = ANY($2))"#,
            root,
            only.as_deref(),
        )
        .fetch_all(tx.conn())
        .await?
        {
            results
                .entry(row.observable_id)
                .or_default()
                .insert(row.module);
        }
        let mut tasks: BTreeMap<(ObservableId, String), (TaskId, TaskState, bool)> =
            BTreeMap::new();
        // the tasks that ended incomplete and run again (PLAN.md decision 34): every one on a new
        // pass, otherwise each whose observable changed since its claim
        let mut rerun: BTreeSet<(ObservableId, String)> = BTreeSet::new();
        for row in sqlx::query!(
            r#"SELECT t.id AS "id: TaskId", t.observable_id AS "observable_id: ObservableId",
                      t.module, t.state AS "state: TaskState",
                      t.declined IS NOT NULL AS "declined!",
                      (t.state = 'done' AND t.incomplete
                       AND ($3 OR o.changes > COALESCE(t.seen_changes, -1))) AS "rerun!"
               FROM queue.tasks t
               JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
               WHERE t.root_id = $1 AND ($2::bigint[] IS NULL OR t.observable_id = ANY($2))"#,
            root,
            only.as_deref(),
            rerun_all,
        )
        .fetch_all(tx.conn())
        .await?
        {
            if row.rerun {
                rerun.insert((row.observable_id, row.module.clone()));
            }
            tasks.insert(
                (row.observable_id, row.module),
                (row.id, row.state, row.declined),
            );
        }

        // each observable's tasks by component, as a dependency's settling reads them
        let mut seen: BTreeMap<ObservableId, BTreeMap<&str, TaskSeen>> = BTreeMap::new();
        for ((observable, key), (_, state, _)) in &tasks {
            let state = match state {
                TaskState::Done | TaskState::Failed => TaskSeen::Ended,
                TaskState::Cancelled => TaskSeen::None,
                _ => TaskSeen::Active,
            };
            seen.entry(*observable)
                .or_default()
                .insert(key.as_str(), state);
        }
        let no_tasks = BTreeMap::new();
        let none = BTreeSet::new();
        // a file's type step, queued first and alone where something reads the type
        // (`crate::type_step`)
        let type_step = self.catalog.component(TYPE_STEP);
        let reads_type: BTreeSet<&str> = self
            .catalog
            .iter()
            .filter(|component| component.takes.reads().file_type)
            .map(|component| component.key.as_str())
            .collect();
        // the files with no type step but a type kept for their bytes that their settled path
        // can use, which need no step of their own
        let untyped: Vec<ObservableId> = observables
            .iter()
            .filter(|o| o.kind == "file")
            .filter(|o| {
                matches!(
                    tasks.get(&(o.id, TYPE_STEP.to_owned())),
                    None | Some((_, TaskState::Cancelled, _))
                )
            })
            .map(|o| o.id)
            .collect();
        let kept = if type_step.is_some() && !untyped.is_empty() {
            type_step::kept(tx.conn(), root, &untyped).await?
        } else {
            BTreeMap::new()
        };
        let mut queued = Vec::new();
        // each observable's eligible components first, then the facts their declarations read,
        // read once for every observable that has a declaring component (`crate::takes`)
        let mut eligible: Vec<Eligible> = Vec::new();
        let mut declaring = Vec::new();
        for observable in &observables {
            let kind: ObservableKind = observable
                .kind
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.id.0)))?;
            // a globally excluded observable gets no task at all, not even its type step
            if self
                .exclusions
                .excludes(&observable.kind, &observable.value)
            {
                eligible.push(Eligible {
                    kind,
                    components: Vec::new(),
                    settled: BTreeSet::new(),
                    open: false,
                });
                continue;
            }
            let facts = Facts {
                kind,
                directives: &observable.directives,
                exclude_modules: &observable.exclude_modules,
                limit_modules: &observable.limit_modules,
            };
            // the components that won't store a result for it, which meets a dependency on them
            // (`eligibility::settle`, PLAN.md decision 30)
            let mut settled: BTreeSet<&str> = results
                .get(&observable.id)
                .unwrap_or(&none)
                .iter()
                .map(String::as_str)
                .collect();
            // ace3's file_type result, built from the file's type, is the dependency's result
            if observable.type_result {
                settled.insert(TYPE_STEP);
            }
            let tasks_on = seen.get(&observable.id).unwrap_or(&no_tasks);
            eligibility::settle(&self.catalog, facts, &mode_modules, &mut settled, |key| {
                tasks_on.get(key).copied().unwrap_or(TaskSeen::None)
            });
            let mut components: Vec<&ace_sdk::Component> = self
                .catalog
                .iter()
                .filter(|component| component.key != TYPE_STEP)
                .filter(|component| check(component, facts, &mode_modules, &settled).is_ok())
                .collect();
            let mut gated = false;
            if kind == ObservableKind::File
                && let Some(step) = type_step
            {
                // typed where ace3's file_type would run, so its result shows where ace3's does,
                // or where a module the mode runs on the file declares on the type
                let shows = check(step, facts, &mode_modules, &settled).is_ok();
                let wanted = shows
                    || components
                        .iter()
                        .any(|c| reads_type.contains(c.key.as_str()));
                // a type kept from other bytes' step serves once ace3's result shows, if it must
                let reused =
                    kept.contains_key(&observable.id) && (observable.type_result || !shows);
                let step_task = tasks.get(&(observable.id, TYPE_STEP.to_owned()));
                let ended = match step_task {
                    Some((_, TaskState::Done | TaskState::Failed, _)) => true,
                    // a step queued or running is waited for
                    Some((_, state, _)) if *state != TaskState::Cancelled => false,
                    // nothing reads the type, or the kept one serves: the rest is queued at once
                    _ if !wanted || reused => true,
                    None => {
                        queued.extend(queue::enqueue(tx, root, observable.id, TYPE_STEP).await?);
                        false
                    }
                    Some((id, _, _)) => {
                        if requeue_cancelled && queue::requeue_cancelled(tx, *id).await? {
                            queued.push(*id);
                        }
                        false
                    }
                };
                // nothing else on the file until its type step has ended
                if !ended {
                    components.clear();
                    gated = true;
                }
            }
            if components.iter().any(|c| !c.takes.is_everything()) {
                declaring.push(observable.id);
            }
            eligible.push(Eligible {
                kind,
                components,
                settled,
                open: !gated,
            });
        }
        let needs = declared::Needs::of(self.catalog.iter());
        let mut held = if declaring.is_empty() {
            BTreeMap::new()
        } else {
            declared::held(tx, root, &declaring, &needs).await?
        };
        let nothing_held = declared::Held::default();
        // the tasks a kept result may stand in for, looked up once everything else is queued
        // (`crate::cache`)
        let mut cacheable = Vec::new();
        // what each analysis type's automation limit counts (`crate::limits`)
        let mut counts = limits::Counts::default();
        for (observable, eligible) in observables.iter().zip(eligible) {
            let Eligible {
                kind,
                mut components,
                mut settled,
                open,
            } = eligible;
            let rules = Facts {
                kind,
                directives: &observable.directives,
                exclude_modules: &observable.exclude_modules,
                limit_modules: &observable.limit_modules,
            };
            let has_result = results.get(&observable.id).unwrap_or(&none);
            let tasks_on = seen.get(&observable.id).unwrap_or(&no_tasks);
            let mut looked: BTreeSet<&str> = components.iter().map(|c| c.key.as_str()).collect();
            // a component its declaration declines or its limit holds gets no task, which meets a
            // dependency on it, so what depends on it is looked at again (PLAN.md decision 30)
            while !components.is_empty() {
                if !held.contains_key(&observable.id)
                    && components.iter().any(|c| !c.takes.is_everything())
                {
                    held.extend(declared::held(tx, root, &[observable.id], &needs).await?);
                }
                let facts = held.get(&observable.id).unwrap_or(&nothing_held).facts(
                    kind,
                    &observable.directives,
                    mode,
                );
                let mut no_task = false;
                for component in std::mem::take(&mut components) {
                    let key = component.key.as_str();
                    let task = tasks.get(&(observable.id, key.to_owned()));
                    let again = rerun.contains(&(observable.id, key.to_owned()));
                    // a result with no task is one the cache wrote; one whose task ended incomplete
                    // runs again on a change (PLAN.md decision 34)
                    if has_result.contains(key) && !again {
                        continue;
                    }
                    // the module's declaration over what the core holds now (`crate::takes`)
                    let declined = component.takes.check(&facts).err();
                    if declined.is_some() && self.takes == TakesMode::Applied {
                        if task.is_none() {
                            no_task |= settled.insert(key);
                        }
                        continue;
                    }
                    // ace3's automation limit, after every other rule and before the cache
                    // (`crate::limits`); a task the audit queues only to mark isn't held to it
                    let limit = declined
                        .is_none()
                        .then(|| self.limit_for(component, &observable.directives))
                        .flatten();
                    if task.is_none() && declined.is_none() && cache::caches(&self.cache, component)
                    {
                        // its limit is checked where its lookup is made, below
                        cacheable.push((
                            observable.id,
                            kind,
                            observable.value.as_str(),
                            component,
                            limit,
                        ));
                        continue;
                    }
                    let requeued =
                        matches!(task, Some((_, TaskState::Cancelled, _))) && requeue_cancelled;
                    if let Some(limit) = limit
                        && (task.is_none() || requeued || again)
                    {
                        let (analysis_type, modules) = self.same_type(component);
                        // a rerun's own result counts, as ace3 counts the analysis it reruns, and
                        // one held back isn't waited for, since its result is there already
                        if counts.get(tx, root, analysis_type, &modules).await? >= limit {
                            if !again {
                                limits::hold(tx, root, observable.id, key, limit).await?;
                            }
                            if task.is_none() {
                                no_task |= settled.insert(key);
                            }
                            continue;
                        }
                    }
                    let added = match task {
                        None => queue::enqueue(tx, root, observable.id, key).await?,
                        Some((id, TaskState::Cancelled, _)) if requeue_cancelled => {
                            queue::requeue_cancelled(tx, *id).await?.then_some(*id)
                        }
                        Some((id, TaskState::Done, _)) if again => {
                            queue::requeue_incomplete(tx, *id).await?.then_some(*id)
                        }
                        Some(_) => None,
                    };
                    if added.is_some() {
                        // every task of a type counts toward its limit, a task of a component with
                        // none among them, but not one the audit queues only to mark, nor a rerun,
                        // whose result counts already
                        if declined.is_none() && !again {
                            counts.add(component.manifest.output.name);
                        }
                        if limit.is_some() {
                            limits::release(tx, root, observable.id, key).await?;
                        }
                    }
                    if self.takes == TakesMode::Audit {
                        // a task queued now is marked if the declaration declines it; one queued
                        // earlier and marked is cleared once it takes it, which is when the core
                        // would have queued it without the setting
                        let marked = matches!(task, Some((_, _, true)));
                        match (added, task) {
                            // a new task is unmarked; a requeued one may carry an old mark
                            (Some(id), _) if declined.is_some() || marked => {
                                declared::mark(tx, id, declined).await?;
                            }
                            (None, Some((id, _, true))) if declined.is_none() => {
                                declared::mark(tx, *id, None).await?;
                            }
                            _ => {}
                        }
                    }
                    queued.extend(added);
                }
                if !no_task || !open {
                    break;
                }
                eligibility::settle(&self.catalog, rules, &mode_modules, &mut settled, |key| {
                    tasks_on.get(key).copied().unwrap_or(TaskSeen::None)
                });
                components = self
                    .catalog
                    .iter()
                    .filter(|component| component.key != TYPE_STEP)
                    .filter(|component| !looked.contains(component.key.as_str()))
                    .filter(|component| check(component, rules, &mode_modules, &settled).is_ok())
                    .collect();
                looked.extend(components.iter().map(|c| c.key.as_str()));
            }
        }
        for (observable, kind, value, component, limit) in cacheable {
            // counted from the database: a hit before this one may have landed results and queued
            // tasks of its own
            if let Some(limit) = limit {
                let (analysis_type, modules) = self.same_type(component);
                if limits::count(tx, root, analysis_type, &modules).await? >= limit {
                    limits::hold(tx, root, observable, &component.key, limit).await?;
                    continue;
                }
                limits::release(tx, root, observable, &component.key).await?;
            }
            // a hit's eligibility can reach what's left here, and its detection can change the
            // mode, which reruns all of it
            match self
                .try_hit(tx, root, mode, observable, kind, value, component)
                .await?
            {
                Hit::Landed(landed) => {
                    queued.extend(landed.queued);
                    if landed.mode_changed_to.is_some() {
                        break;
                    }
                }
                Hit::Taken => {}
                Hit::Miss | Hit::Wait => {
                    queued.extend(queue::enqueue(tx, root, observable, &component.key).await?);
                }
            }
        }
        Ok(queued)
    }

    /// `component`'s automation limit on an observable with `directives`, unless the observable
    /// lifts it (`crate::limits`).
    fn limit_for(&self, component: &ace_sdk::Component, directives: &[String]) -> Option<u32> {
        component.automation_limit.filter(|_| {
            !directives
                .iter()
                .any(|d| d == limits::IGNORE_AUTOMATION_LIMITS)
        })
    }

    /// `component`'s analysis type, and the keys of every component that writes it, which its limit
    /// counts together, as ace3 counts a root's analyses of one type.
    fn same_type<'c>(&'c self, component: &'c ace_sdk::Component) -> (&'c str, Vec<String>) {
        let analysis_type = component.manifest.output.name;
        let modules = self
            .catalog
            .iter()
            .filter(|c| c.manifest.output.name == analysis_type)
            .map(|c| c.key.clone())
            .collect();
        (analysis_type, modules)
    }

    /// What a task of `module` that ended with no result frees: when its type has an automation
    /// limit, a place for the work the limit held back in the root, for which eligibility runs
    /// again, oldest observable first (`crate::limits`).
    pub async fn limit_freed(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        module: &str,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        let Some(component) = self.catalog.component(module) else {
            return Ok(Vec::new());
        };
        let (_, modules) = self.same_type(component);
        if !self
            .catalog
            .iter()
            .any(|c| modules.contains(&c.key) && c.automation_limit.is_some())
        {
            return Ok(Vec::new());
        }
        let held = limits::held(tx, root, &modules).await?;
        if held.is_empty() {
            return Ok(Vec::new());
        }
        self.queue_eligible(tx, root, Scope::Observables(&held), false)
            .await
    }

    /// What a task of `module` on `observable` that ended with no result frees: it is settled
    /// there, so a module that depends on it may run on the observable now (PLAN.md decision 30),
    /// for which eligibility runs again on the observable. A type step's end already ran it
    /// (`type_step_ended`).
    pub async fn dependency_ended(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
        module: &str,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        if module == TYPE_STEP
            || !self
                .catalog
                .iter()
                .any(|c| c.manifest.depends_on.contains(&module))
        {
            return Ok(Vec::new());
        }
        self.queue_eligible(tx, root, Scope::Observables(&[observable]), false)
            .await
    }

    /// Writes the result kept for `component` on an observable, if there is one, as its task's end
    /// would (`crate::cache`).
    #[allow(clippy::too_many_arguments)]
    async fn try_hit(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        observable: ObservableId,
        kind: ObservableKind,
        value: &str,
        component: &ace_sdk::Component,
    ) -> Result<Hit, OrchestratorError> {
        // what an earlier hit's eligibility did since this was gathered
        let taken = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT FROM analysis.results
                              WHERE root_id = $1 AND observable_id = $2 AND module = $3)
                   OR EXISTS (SELECT FROM queue.tasks
                              WHERE root_id = $1 AND observable_id = $2 AND module = $3)
               AS "taken!""#,
            root,
            observable as ObservableId,
            &component.key,
        )
        .fetch_one(tx.conn())
        .await?;
        if taken {
            return Ok(Hit::Taken);
        }
        // a hit or a miss is counted in the pass it lands or queues in (`crate::metrics`)
        queue::begin_pass(tx, root).await?;
        let started = std::time::Instant::now();
        let Some(kept) = self.kept_for(tx, component, kind, value).await? else {
            return missed(tx, root, &component.key, started).await;
        };
        // a result that adds files names them after its file's path, which is settled first, as a
        // lease would settle it, or else the task waits for its lease to settle it; one that puts
        // them under its observable's name doesn't need it
        let named = matches!(
            component.manifest.cache.map(|cache| cache.paths),
            Some(ace_sdk::cache::CachePaths::Named(_))
        );
        let analyzed = if kept.files.is_empty() || !named {
            None
        } else {
            match settleable_path(tx, &self.catalog, root, observable).await? {
                Some(path) => Some(path),
                None => return Ok(Hit::Wait),
            }
        };
        let Some(envelope) = cache::for_path(component, &kept, analyzed.as_deref()) else {
            return missed(tx, root, &component.key, started).await;
        };
        if !cache::hold_files(tx, root, &kept).await? {
            return missed(tx, root, &component.key, started).await;
        }
        let lookup = started.elapsed();
        cache::count(tx, root, &component.key, cache::Activity::Hit, lookup).await?;
        tracing::debug!(%root, module = %component.key, kept = kept.id, "a kept result stands in for a task");
        let locked = Locked {
            mode: mode.to_owned(),
            cancelled: false,
        };
        let landed = self
            .apply_result(
                tx,
                root,
                &locked,
                observable,
                &component.key,
                &envelope,
                Some(kept.created_at),
                false,
            )
            .await?;
        Ok(Hit::Landed(landed))
    }

    /// The result kept for `component` on an observable of `kind` and `value` that hasn't expired,
    /// under the key the core can make now.
    pub async fn kept_for(
        &self,
        tx: &mut Tx<'_>,
        component: &ace_sdk::Component,
        kind: ObservableKind,
        value: &str,
    ) -> Result<Option<cache::Kept>, OrchestratorError> {
        let Some(extended) = cache::extended(tx, component, value, None).await? else {
            return Ok(None);
        };
        let Some(key) = cache::key(component, kind.as_str(), value, &extended) else {
            return Ok(None);
        };
        Ok(cache::find(tx, &key).await?)
    }

    /// Ends a leased task with a kept result in place of its run (`crate::cache`): the task is done,
    /// and the result lands as a task's would. The caller found it with `kept_for` and holds its
    /// files for the root (`cache::hold_files`).
    pub async fn land_kept(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
        envelope: &ResultEnvelope<Value>,
        cached_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Landed, OrchestratorError> {
        let locked = lock_root(tx, task.root).await?;
        worker.finish_in(tx, task.id, TaskState::Done, None).await?;
        if self.takes == TakesMode::Audit {
            declared::report_if_marked(tx, task.id, &task.module, "stored a result").await?;
        }
        // a lookup at the lease counts its hit; a miss there was counted when the task was queued
        cache::count(
            tx,
            task.root,
            &task.module,
            cache::Activity::Hit,
            std::time::Duration::ZERO,
        )
        .await?;
        self.apply_result(
            tx,
            task.root,
            &locked,
            task.observable.id,
            &task.module,
            envelope,
            Some(cached_at),
            true,
        )
        .await
    }

    /// Starts analysis of a new root: queues what is eligible for every observable it has. A
    /// root with nothing eligible completes its first pass at once. A root that already holds a
    /// detection, such as a collector's submitted one, in a detectable mode is an alert in
    /// correlation mode, as a pre-hook's detection makes it: ace3's engine moves any root with
    /// detection points, its own included, to correlation (PLAN.md decision 54).
    pub async fn start(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        let locked = lock_root(tx, root).await?;
        queue::begin_pass(tx, root).await?;
        let all: Vec<ObservableId> = sqlx::query_scalar!(
            r#"SELECT id AS "id: ObservableId" FROM analysis.observables WHERE root_id = $1 ORDER BY id"#,
            root,
        )
        .fetch_all(tx.conn())
        .await?;
        // a file whose bytes were typed before needs no step (`take_kept_types`)
        self.take_kept_types(tx, root, &locked.mode, Scope::All)
            .await?;
        let pre = hooks::pre(
            tx,
            &self.hooks,
            &self.exclusions,
            &self.modes,
            root,
            &locked.mode,
            &all,
        )
        .await?;
        hooks::mark_due(tx, &self.hooks, &self.modes, root, &locked.mode).await?;
        let detectable = self.modes.is_detectable(&locked.mode);
        let detected = pre.detected
            || (detectable
                && sqlx::query_scalar!(
                    r#"SELECT EXISTS (SELECT FROM analysis.detections WHERE root_id = $1) AS "held!""#,
                    root,
                )
                .fetch_one(tx.conn())
                .await?);
        if detected && detectable {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %locked.mode, "a detection made the new root an alert");
            let queued = self.set_mode(tx, root, CORRELATION).await?;
            queue::check_completion(tx, root).await?;
            return Ok(queued);
        }
        let mut queued = self
            .queue_eligible_locked(tx, root, &locked.mode, Scope::All, false)
            .await?;
        queued.extend(pre.requeued);
        queue::check_completion(tx, root).await?;
        Ok(queued)
    }

    /// Changes a root's mode and reruns eligibility over every observable it has. Cancelled
    /// tasks whose modules the new mode runs are queued again, and a cancelled root's analysis
    /// restarts.
    pub async fn set_mode(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        self.switch_mode(tx, root, mode, false).await
    }

    /// `set_mode`, as a new pass of the root whether or not its mode changes, as ace3's
    /// `request_analyst_analysis` queues the alert again: every task that ended incomplete runs
    /// again (PLAN.md decision 34). `set_mode` is one only when the mode changes.
    pub async fn new_pass(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        self.switch_mode(tx, root, mode, true).await
    }

    async fn switch_mode(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        pass: bool,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        lock_root(tx, root).await?;
        let before = sqlx::query_scalar!(
            "UPDATE analysis.roots r SET analysis_mode = $2, cancelled_at = NULL
             FROM analysis.roots old WHERE r.id = $1 AND old.id = r.id
             RETURNING old.analysis_mode",
            root,
            mode,
        )
        .fetch_optional(tx.conn())
        .await?;
        hooks::mark_due(tx, &self.hooks, &self.modes, root, mode).await?;
        // a mode that runs file_type gives typed files ace3's result where an earlier mode didn't
        self.take_kept_types(tx, root, mode, Scope::All).await?;
        // ace3 analyzes the root again in its new mode: a new pass
        if pass || before.as_deref() != Some(mode) {
            self.queue_eligible_pass(tx, root, mode).await
        } else {
            self.queue_eligible_locked(tx, root, mode, Scope::All, true)
                .await
        }
    }

    /// What follows a file's type step, however it ended (`queue::TaskEnded`): the file shows
    /// ace3's file_type result where that module would have run, the observable modifier's `pre`
    /// rules see what that added, as they see what a landing adds, and the file's other tasks are
    /// queued. Called in the transaction that ended the step, with its root locked.
    pub async fn type_step_ended(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
    ) -> Result<Vec<TaskId>, OrchestratorError> {
        let locked = lock_root(tx, root).await?;
        if locked.cancelled {
            return Ok(Vec::new());
        }
        let mode = locked.mode;
        let mut touched = vec![observable];
        let shown = self
            .show_types(tx, root, &mode, Scope::Observables(&touched))
            .await?;
        let mut pre = hooks::Effects::default();
        if !shown.is_empty() {
            pre = hooks::pre(
                tx,
                &self.hooks,
                &self.exclusions,
                &self.modes,
                root,
                &mode,
                &touched,
            )
            .await?;
            touched.extend(pre.touched.iter().copied());
            hooks::mark_due(tx, &self.hooks, &self.modes, root, &mode).await?;
        }
        if pre.detected && self.modes.is_detectable(&mode) {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %mode, "a hook's detection made the root an alert");
            return self.set_mode(tx, root, CORRELATION).await;
        }
        let mut queued = self
            .queue_eligible_locked(tx, root, &mode, Scope::Observables(&touched), false)
            .await?;
        queued.extend(pre.requeued);
        Ok(queued)
    }

    /// Lets the type kept for a file's bytes serve each file in `scope` that has no type step
    /// (PLAN.md decision 25): its analysis path is settled now, by the rule a file's first lease
    /// applies (`Api::held_for_path`), where nothing nearer the root could still add a path, so
    /// that the path the kept type is read under is the one the file's tasks will read. Then each
    /// shows ace3's file_type result where that module would run (`show_types`). A file whose path
    /// can't be settled yet is typed by a step of its own, as a new file is; its lease, held until
    /// the path is settled, ends it without the pool where the kept type answers the path
    /// (`Api::leased`). Returns the files that now show ace3's result.
    async fn take_kept_types(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        scope: Scope<'_>,
    ) -> Result<Vec<ObservableId>, OrchestratorError> {
        if self.catalog.component(TYPE_STEP).is_none() {
            return Ok(Vec::new());
        }
        let only: Option<Vec<i64>> = match scope {
            Scope::All => None,
            Scope::Observables(ids) => Some(ids.iter().map(|id| id.0).collect()),
        };
        let unsettled = sqlx::query!(
            r#"SELECT o.id AS "id: ObservableId", o.depth
               FROM analysis.observables o
               WHERE o.root_id = $1 AND o.type = 'file' AND NOT o.type_result
                 AND ($2::bigint[] IS NULL OR o.id = ANY($2))
                 AND NOT EXISTS (SELECT FROM queue.tasks t
                                 WHERE t.root_id = o.root_id AND t.observable_id = o.id
                                   AND t.module = $3 AND t.state <> 'cancelled')
                 AND NOT EXISTS (SELECT FROM analysis.files f
                                 WHERE f.root_id = o.root_id AND f.observable_id = o.id
                                   AND f.analyzed)
                 AND EXISTS (SELECT FROM store.file_types k
                             WHERE k.sha256 = o.value AND k.is_image IS NOT NULL)
               ORDER BY o.id"#,
            root,
            only.as_deref(),
            TYPE_STEP,
        )
        .fetch_all(tx.conn())
        .await?;
        if !unsettled.is_empty() {
            let last: Vec<String> = self
                .catalog
                .iter()
                .filter(|c| c.manifest.runs_last)
                .map(|c| c.key.clone())
                .collect();
            for row in unsettled {
                if !tree::pending_above(tx.conn(), root, row.depth, &last).await? {
                    tree::choose_analysis_file(tx, root, row.id).await?;
                }
            }
        }
        self.show_types(tx, root, mode, scope).await
    }

    /// Gives each typed file in `scope` that doesn't show it yet ace3's file_type result, where
    /// that module would run on it in `mode` by the core's rules (`type_step::show`), and returns
    /// those files. A file is typed when its type step has ended in this root with a type kept, or
    /// when it has no step and a kept type serves its settled path (`type_step::kept`).
    async fn show_types(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        scope: Scope<'_>,
    ) -> Result<Vec<ObservableId>, OrchestratorError> {
        let Some(component) = self.catalog.component(TYPE_STEP) else {
            return Ok(Vec::new());
        };
        let catalog = self.catalog.keys();
        let mut mode_modules = self.modes.modules_in(mode);
        mode_modules.retain(|m| catalog.contains(m));
        let only: Option<Vec<i64>> = match scope {
            Scope::All => None,
            Scope::Observables(ids) => Some(ids.iter().map(|id| id.0).collect()),
        };
        let rows = sqlx::query!(
            r#"SELECT o.id AS "id: ObservableId", o.value, o.directives, o.exclude_modules,
                      o.limit_modules, t.state AS "step?: TaskState"
               FROM analysis.observables o
               LEFT JOIN queue.tasks t ON t.root_id = o.root_id AND t.observable_id = o.id
                    AND t.module = $3
               WHERE o.root_id = $1 AND o.type = 'file' AND NOT o.type_result
                 AND ($2::bigint[] IS NULL OR o.id = ANY($2))
               ORDER BY o.id"#,
            root,
            only.as_deref(),
            TYPE_STEP,
        )
        .fetch_all(tx.conn())
        .await?;
        let none = BTreeSet::new();
        let mut shown = Vec::new();
        let mut stepless = Vec::new();
        for row in rows {
            // an excluded file shows no type, as it gets no type step
            if self
                .exclusions
                .excludes(ObservableKind::File.as_str(), &row.value)
            {
                continue;
            }
            let facts = Facts {
                kind: ObservableKind::File,
                directives: &row.directives,
                exclude_modules: &row.exclude_modules,
                limit_modules: &row.limit_modules,
            };
            if check(component, facts, &mode_modules, &none).is_err() {
                continue;
            }
            match row.step {
                Some(TaskState::Done | TaskState::Failed) => {}
                None | Some(TaskState::Cancelled) => {
                    stepless.push(row.id);
                    continue;
                }
                // its own step is still to end
                Some(_) => continue,
            }
            let Some(type_facts) = type_step::facts_for(tx.conn(), &row.value).await? else {
                continue;
            };
            let Some(file) = tree::analysis_file(tx.conn(), root, row.id).await? else {
                continue;
            };
            type_step::show(tx, root, row.id, &file.path, &type_facts).await?;
            shown.push(row.id);
        }
        if !stepless.is_empty() {
            for (id, typed) in type_step::kept(tx.conn(), root, &stepless).await? {
                type_step::show(tx, root, id, &typed.path, &typed.facts).await?;
                shown.push(id);
            }
        }
        Ok(shown)
    }

    /// What follows a hooks run (`crate::hooks`): a detection in a detectable mode makes the root an
    /// alert in correlation mode, as a landing's does, and otherwise eligibility runs over what the
    /// hooks touched. Returns the tasks queued and the mode the root changed to.
    pub(crate) async fn after_hooks(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        touched: &[ObservableId],
        detected: bool,
    ) -> Result<(Vec<TaskId>, Option<String>), OrchestratorError> {
        if detected && self.modes.is_detectable(mode) {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %mode, "a hook's detection made the root an alert");
            let queued = self.set_mode(tx, root, CORRELATION).await?;
            return Ok((queued, Some(CORRELATION.to_owned())));
        }
        let queued = self
            .queue_eligible_locked(tx, root, mode, Scope::Observables(touched), false)
            .await?;
        Ok((queued, None))
    }

    /// What a disposition does to an alert's analysis: cancels it, then switches it to dispositioned
    /// mode, which queues that mode's few modules, as ace3 does when
    /// `stop_analysis_on_any_alert_disposition` is set. The disposition itself and who made it are
    /// `ace_service::Service::disposition`'s, in the same transaction.
    ///
    /// ace3 runs a dispositioned mode's modules on every dispositioned pass, so a disposition changed
    /// again runs them again: `svs_yara_sample_capture` captures once the alert's disposition is graded
    /// and retries a capture that's missing. A task here is once per (observable, module), so each
    /// ended task of a module the mode runs that stores no result, and so has none, is queued again.
    pub async fn stop_for_disposition(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
    ) -> Result<Dispositioned, OrchestratorError> {
        let cancelled = queue::cancel_root(tx, root).await?;
        let mut queued = self.set_mode(tx, root, DISPOSITIONED).await?;
        let rerun: Vec<String> = self
            .modes
            .modules_in(DISPOSITIONED)
            .into_iter()
            .filter(|key| {
                self.catalog
                    .get(key)
                    .is_some_and(|manifest| !manifest.stores_results)
            })
            .map(str::to_owned)
            .collect();
        if !rerun.is_empty() {
            let ended = sqlx::query_scalar!(
                r#"SELECT t.id AS "id: TaskId" FROM queue.tasks t
                   WHERE t.root_id = $1 AND t.module = ANY ($2) AND t.state IN ('done', 'failed')
                     AND NOT EXISTS (SELECT FROM analysis.results r
                                     WHERE r.root_id = t.root_id AND r.observable_id = t.observable_id
                                       AND r.module = t.module)
                   ORDER BY t.id"#,
                root,
                &rerun,
            )
            .fetch_all(tx.conn())
            .await?;
            for task in ended {
                if queue::requeue_ended(tx, task).await? {
                    queued.push(task);
                }
            }
        }
        queue::check_completion(tx, root).await?;
        Ok(Dispositioned { cancelled, queued })
    }

    /// Lands a module's result for a task the worker owns: ends the task and writes the result,
    /// the observables it adds, its additions to the analyzed observable and its detections,
    /// then queues what became eligible. A detection in a detectable mode makes the root an
    /// alert in correlation mode, which reruns eligibility over the whole root. A cacheable
    /// module's result is kept when it may be (`land_result_with`).
    pub async fn land_result(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
        result: &ResultEnvelope<Value>,
    ) -> Result<Landed, OrchestratorError> {
        self.land_result_with(tx, worker, task, result, &BTreeMap::new(), false)
            .await
    }

    /// `land_result`, keeping a cacheable module's result when it may be kept (`crate::cache`),
    /// under the versions its pool sent (`probes`); `writes` says whether the task made writes to
    /// ACE's data, which a result that is kept may not.
    pub async fn land_result_with(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
        result: &ResultEnvelope<Value>,
        probes: &BTreeMap<String, String>,
        writes: bool,
    ) -> Result<Landed, OrchestratorError> {
        self.land_ending(tx, worker, task, result, probes, writes, Ending::Done)
            .await
    }

    /// `land_result_with`, for a result that ends as `ending` says: an `Incomplete` one (PLAN.md
    /// decision 34) ends its task done and marked so, which runs it again when its observable
    /// changes; neither it nor a `DoneNotKept` one (decision 47) is kept by the analysis cache, as
    /// ace3's keeps only a `COMPLETED` one and its VirusTotal module only a hash VirusTotal knows.
    #[allow(clippy::too_many_arguments)]
    pub async fn land_ending(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
        result: &ResultEnvelope<Value>,
        probes: &BTreeMap<String, String>,
        writes: bool,
        ending: Ending,
    ) -> Result<Landed, OrchestratorError> {
        let root = task.root;
        let analyzed = task.observable.id;
        let locked = lock_root(tx, root).await?;
        worker.finish_in(tx, task.id, TaskState::Done, None).await?;
        if ending == Ending::Incomplete {
            queue::mark_incomplete(tx, task.id).await?;
        }
        if self.takes == TakesMode::Audit {
            declared::report_if_marked(tx, task.id, &task.module, "stored a result").await?;
        }
        if ending == Ending::Done {
            self.keep(tx, task, result, probes, writes).await?;
        }
        self.apply_result(
            tx,
            root,
            &locked,
            analyzed,
            &task.module,
            result,
            None,
            true,
        )
        .await
    }

    /// Keeps a task's result for later roots, when its module's are kept and it may be
    /// (`cache::refusal`), with the versions its pool sent.
    async fn keep(
        &self,
        tx: &mut Tx<'_>,
        task: &Task,
        result: &ResultEnvelope<Value>,
        probes: &BTreeMap<String, String>,
        writes: bool,
    ) -> Result<(), OrchestratorError> {
        let Some(component) = self.catalog.component(&task.module) else {
            return Ok(());
        };
        let Some(ttl) = component
            .cache_ttl
            .filter(|_| cache::caches(&self.cache, component))
        else {
            return Ok(());
        };
        // the images its task's scans ran are versions as its tools' are (`Cache::scanners`)
        let scanned;
        let probes = match component.manifest.cache.map(|cache| cache.scanners) {
            Some(scanners) if !scanners.is_empty() => {
                let mut with = probes.clone();
                with.extend(crate::scans::image_ids(tx, task.id, scanners).await?);
                scanned = with;
                &scanned
            }
            _ => probes,
        };
        if !probes.is_empty() {
            cache::record_probes(tx, &component.key, probes).await?;
        }
        let analyzed = if task.observable.kind == ObservableKind::File {
            tree::analysis_file(tx.conn(), task.root, task.observable.id)
                .await?
                .map(|file| file.path)
        } else {
            None
        };
        let observable = (task.observable.kind, task.observable.value.as_str());
        let (places, bytes) = match cache::refusal(
            component,
            result,
            writes,
            observable,
            analyzed.as_deref(),
        ) {
            Ok(kept) => kept,
            Err(why) => {
                tracing::debug!(task = %task.id, module = %task.module, "the result isn't kept: {why}");
                return Ok(());
            }
        };
        let value = task.observable.value.as_str();
        let Some(extended) = cache::extended(tx, component, value, Some(probes)).await? else {
            tracing::warn!(
                task = %task.id, module = %task.module,
                "the result isn't kept: its pool sent none of the versions its key holds, or its \
                 scan ran in no container"
            );
            return Ok(());
        };
        let kind = task.observable.kind.as_str();
        let Some(key) = cache::key(component, kind, value, &extended) else {
            return Ok(());
        };
        cache::keep(
            tx,
            &cache::Keep {
                key,
                module: &component.key,
                observable_type: kind,
                observable_value: value,
                result,
                file_paths: places,
                ttl,
            },
        )
        .await?;
        cache::count(
            tx,
            task.root,
            &component.key,
            cache::Activity::Kept { bytes },
            std::time::Duration::ZERO,
        )
        .await?;
        Ok(())
    }

    /// What a result's landing writes, whether a task's end made it or the cache kept it
    /// (`cached_at`, when the kept one's task ended): the result row, the observables it adds, its
    /// additions, its detections, the hooks' rules over what it touched, and what became eligible.
    /// `complete` checks the root's completion last, as a task's end does; a hit made while
    /// eligibility runs leaves that to whatever ran it.
    #[allow(clippy::too_many_arguments)]
    async fn apply_result(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        locked: &Locked,
        analyzed: ObservableId,
        module: &str,
        result: &ResultEnvelope<Value>,
        cached_at: Option<chrono::DateTime<chrono::Utc>>,
        complete: bool,
    ) -> Result<Landed, OrchestratorError> {
        let mode = locked.mode.clone();
        // a task's end was refused for these (`check_relationship_targets`); a cache hit in another
        // root, or a result landed without that check, drops them
        let unlandable = unlandable_targets(tx.conn(), root, result).await?;
        if !unlandable.is_empty() {
            tracing::warn!(
                %root,
                %module,
                "a result related observables to {} not in the root; those relationships are dropped",
                unlandable.len()
            );
        }
        // a rerun of an incomplete task replaces its result, and keeps what it added once each
        let (result_id, replaced) =
            tree::store_result(tx, root, analyzed, module, result, cached_at).await?;
        tree::add_to_observable(tx, root, analyzed, &landable(&result.analyzed, &unlandable))
            .await?;
        // the directives it adds are the module's (PLAN.md decision 44), a kept result's too
        let from = tree::DirectivesFrom::module(module);
        tree::record_directive_sources(tx, root, analyzed, &result.analyzed.directives, from)
            .await?;

        // what the result adds is one deeper than what it analyzed (`tree::upsert_observable_at`)
        let depth = tree::depth(tx.conn(), root, analyzed)
            .await?
            .saturating_add(1);
        let mut touched = vec![analyzed];
        let mut detections: Vec<(ObservableId, &Detection)> = result
            .detections
            .iter()
            .chain(&result.analyzed.detections)
            .map(|d| (analyzed, d))
            .collect();
        for observable in &result.observables {
            let id = tree::upsert_observable_at(tx, root, observable, depth)
                .await?
                .id;
            tree::record_directive_sources(tx, root, id, &observable.directives, from).await?;
            if !replaced || !tree::has_addition(tx, result_id, id, None).await? {
                tree::add_result_addition(tx, root, result_id, id, None).await?;
            }
            touched.push(id);
            detections.extend(observable.detections.iter().map(|d| (id, d)));
        }
        for file in &result.files {
            let mut observable = NewObservable::new(ObservableKind::File, file.sha256.to_hex());
            observable.tags = file.tags.clone();
            observable.directives = file.directives.clone();
            observable.exclude_modules = file.exclude_modules.clone();
            observable.limit_modules = file.limit_modules.clone();
            observable.relationships = file.relationships.clone();
            observable.redirection = file.redirection.clone();
            let id = tree::upsert_observable_at(tx, root, &observable, depth)
                .await?
                .id;
            tree::record_directive_sources(tx, root, id, &observable.directives, from).await?;
            let yara_meta: Vec<String> = file
                .yara_meta
                .iter()
                .map(|tag| tag.as_str().to_owned())
                .collect();
            tree::add_file_at(
                tx,
                root,
                id,
                file.path.as_str(),
                &yara_meta,
                file.role,
                depth,
            )
            .await?;
            if !replaced || !tree::has_addition(tx, result_id, id, Some(file.path.as_str())).await?
            {
                tree::add_result_addition(tx, root, result_id, id, Some(file.path.as_str()))
                    .await?;
            }
            touched.push(id);
            detections.extend(file.detections.iter().map(|d| (id, d)));
        }
        if !result.redirected.is_empty() {
            let target = match tree::redirection(tx.conn(), root, analyzed).await? {
                Some(target) => tree::find_observable(tx.conn(), root, &target).await?,
                None => None,
            };
            if let Some(id) = target {
                tree::add_to_observable(tx, root, id, &landable(&result.redirected, &unlandable))
                    .await?;
                tree::record_directive_sources(tx, root, id, &result.redirected.directives, from)
                    .await?;
                touched.push(id);
                detections.extend(result.redirected.detections.iter().map(|d| (id, d)));
            } else {
                // a module only writes these for an input that has a redirection, and its target
                // is an observable an earlier result named
                tracing::warn!(
                    %root,
                    %module,
                    "a result added to a redirection that isn't in the root; those additions are dropped"
                );
            }
        }
        for other in &result.others {
            match tree::find_observable(tx.conn(), root, &other.observable).await? {
                Some(id) => {
                    tree::add_to_observable(tx, root, id, &landable(&other.additions, &unlandable))
                        .await?;
                    tree::record_directive_sources(tx, root, id, &other.additions.directives, from)
                        .await?;
                    touched.push(id);
                    detections.extend(other.additions.detections.iter().map(|d| (id, d)));
                }
                None => tracing::warn!(
                    %root,
                    %module,
                    observable = %other.observable.value,
                    "a result added to an observable that isn't in the root; those additions are dropped"
                ),
            }
        }
        for (observable, detection) in &detections {
            if replaced
                && tree::has_detection(tx, result_id, *observable, &detection.description).await?
            {
                continue;
            }
            tree::add_detection(tx, root, *observable, Some(result_id), detection).await?;
        }
        if let Some(changes) = &result.root {
            tree::change_root(tx, root, changes).await?;
        }
        // the observable modifier's pre rules, before anything is queued for what the result touched
        let mut pre = hooks::Effects::default();
        if !locked.cancelled {
            // a file it added whose bytes were typed before needs no step, and its tags from that
            // type are there for the pre rules (`take_kept_types`)
            self.take_kept_types(tx, root, &mode, Scope::Observables(&touched))
                .await?;
            pre = hooks::pre(
                tx,
                &self.hooks,
                &self.exclusions,
                &self.modes,
                root,
                &mode,
                &touched,
            )
            .await?;
            touched.extend(pre.touched.iter().copied());
            hooks::mark_due(tx, &self.hooks, &self.modes, root, &mode).await?;
        }

        // a result that lands after its root was cancelled is kept, and queues nothing
        if locked.cancelled {
            if complete {
                queue::check_completion(tx, root).await?;
            }
            return Ok(Landed {
                result: result_id,
                queued: Vec::new(),
                mode_changed_to: None,
            });
        }
        // a QA rule's match never alerts; a task of the core's records it (PLAN.md 2.27)
        let mut qa_task = Vec::new();
        if !crate::yara_qa::qa_matches(result).is_empty()
            && let Some(id) = queue::enqueue(tx, root, analyzed, crate::yara_qa::QA_MODULE).await?
        {
            qa_task.push(id);
        }
        if (!detections.is_empty() || pre.detected) && self.modes.is_detectable(&mode) {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %mode, "a detection made the root an alert");
            let mut queued = self.set_mode(tx, root, CORRELATION).await?;
            queued.extend(qa_task);
            if complete {
                queue::check_completion(tx, root).await?;
            }
            return Ok(Landed {
                result: result_id,
                queued,
                mode_changed_to: Some(CORRELATION.to_owned()),
            });
        }
        let mut queued = self
            .queue_eligible_locked(tx, root, &mode, Scope::Observables(&touched), false)
            .await?;
        queued.extend(pre.requeued);
        queued.extend(qa_task);
        if complete {
            queue::check_completion(tx, root).await?;
        }
        Ok(Landed {
            result: result_id,
            queued,
            mode_changed_to: None,
        })
    }
}

impl queue::TaskEnded for Orchestrator {
    fn type_step<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
    ) -> queue::EndedFuture<'a> {
        Box::pin(async move {
            self.type_step_ended(tx, root, observable)
                .await
                .map(drop)
                .map_err(queue_error)
        })
    }

    fn without_result<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
        module: &'a str,
    ) -> queue::EndedFuture<'a> {
        Box::pin(async move {
            self.limit_freed(tx, root, module)
                .await
                .map_err(queue_error)?;
            self.dependency_ended(tx, root, observable, module)
                .await
                .map(drop)
                .map_err(queue_error)
        })
    }
}

fn queue_error(error: OrchestratorError) -> QueueError {
    match error {
        OrchestratorError::Queue(e) => e,
        OrchestratorError::Db(e) => QueueError::Db(e),
        OrchestratorError::NoRoot(root) => {
            QueueError::Db(DbError::Decode(format!("no root {root}")))
        }
    }
}

/// An observable's components as eligibility's first look over it found them.
struct Eligible<'a> {
    kind: ObservableKind,
    /// The components eligible for it now.
    components: Vec<&'a ace_sdk::Component>,
    /// The components that won't store a result for it (`eligibility::settle`).
    settled: BTreeSet<&'a str>,
    /// False when nothing more is queued on it now: a global exclusion names it, or its type step
    /// hasn't ended.
    open: bool,
}

/// What a lookup in place of a task found (`Orchestrator::try_hit`).
enum Hit {
    /// A kept result landed as the component's.
    Landed(Landed),
    /// Nothing kept: the task is queued.
    Miss,
    /// A kept result whose files need the file's path, which isn't settled yet: the task is
    /// queued, and its lease looks again once it is (`Api::leased`).
    Wait,
    /// The component already has a result or a task on the observable.
    Taken,
}

type QueueFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<TaskId>, OrchestratorError>> + Send + 'a>,
>;

/// Counts a lookup that found nothing to stand in for the task (`cache::count`).
async fn missed(
    tx: &mut Tx<'_>,
    root: Uuid,
    module: &str,
    started: std::time::Instant,
) -> Result<Hit, OrchestratorError> {
    cache::count(tx, root, module, cache::Activity::Miss, started.elapsed()).await?;
    Ok(Hit::Miss)
}

/// The path a file observable is analyzed under, settled now if a lease would settle it now
/// (`tree::path_settles`), or None when its lease would still be held for it.
async fn settleable_path(
    tx: &mut Tx<'_>,
    catalog: &Catalog,
    root: Uuid,
    observable: ObservableId,
) -> Result<Option<String>, OrchestratorError> {
    let last: Vec<String> = catalog
        .iter()
        .filter(|c| c.manifest.runs_last)
        .map(|c| c.key.clone())
        .collect();
    if !tree::path_settles(tx.conn(), root, observable, &last).await? {
        return Ok(None);
    }
    Ok(tree::choose_analysis_file(tx, root, observable)
        .await?
        .map(|file| file.path))
}

/// A root's state, read with its row locked.
struct Locked {
    mode: String,
    /// Its analysis was cancelled and no mode change has restarted it.
    cancelled: bool,
}

/// Locks the root's row until the transaction ends and returns its mode.
async fn lock_root(tx: &mut Tx<'_>, root: Uuid) -> Result<Locked, OrchestratorError> {
    let row = sqlx::query!(
        "SELECT analysis_mode, cancelled_at FROM analysis.roots WHERE id = $1 FOR UPDATE",
        root,
    )
    .fetch_optional(tx.conn())
    .await?
    .ok_or(OrchestratorError::NoRoot(root))?;
    Ok(Locked {
        mode: row.analysis_mode,
        cancelled: row.cancelled_at.is_some(),
    })
}
