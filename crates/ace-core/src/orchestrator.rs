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
//! Whitelisting is ace3's (PLAN.md 5.14): a whitelisted observable is eligible for nothing
//! (`eligibility`), a result that whitelists the observable it analyzed cancels the rest of its
//! root's analysis, as ace3's executor stops the tree, and a detection doesn't make a root holding a
//! whitelisted observable an alert. ace3 decides whether to alert when the analysis pass ends, and ace4
//! when a detection lands, so a root that alerted before something in it was whitelisted stays an
//! alert here, where ace3 wouldn't have alerted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use ace_results::{Detection, FieldError, NewObservable, ObservableKind, Registry, ResultEnvelope};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{DbError, Retryable, Tx};
use crate::eligibility::{Catalog, Facts, check, is_whitelisted};
use crate::hooks::{self, Hooks};
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
        }
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
        if result.get("root").is_some_and(|root| !root.is_null()) && !manifest.sets_root {
            return Err(rejected(format!(
                "{module} doesn't declare that it changes its root (Module::SETS_ROOT)"
            )));
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

    async fn queue_eligible_locked(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        mode: &str,
        scope: Scope<'_>,
        requeue_cancelled: bool,
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
            r#"SELECT id AS "id: ObservableId", type AS kind, tags, directives, exclude_modules,
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
        for row in sqlx::query!(
            r#"SELECT id AS "id: TaskId", observable_id AS "observable_id: ObservableId", module,
                      state AS "state: TaskState", declined IS NOT NULL AS "declined!"
               FROM queue.tasks
               WHERE root_id = $1 AND ($2::bigint[] IS NULL OR observable_id = ANY($2))"#,
            root,
            only.as_deref(),
        )
        .fetch_all(tx.conn())
        .await?
        {
            tasks.insert(
                (row.observable_id, row.module),
                (row.id, row.state, row.declined),
            );
        }

        let none = BTreeSet::new();
        // a file's type step, queued first and alone (`crate::type_step`)
        let type_step = self.catalog.component(TYPE_STEP);
        let mut queued = Vec::new();
        // each observable's eligible components first, then the facts their declarations read,
        // read once for every observable that has a declaring component (`crate::takes`)
        let mut eligible: Vec<(ObservableKind, Vec<&ace_sdk::Component>)> = Vec::new();
        let mut declaring = Vec::new();
        for observable in &observables {
            let kind: ObservableKind = observable
                .kind
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.id.0)))?;
            let facts = Facts {
                kind,
                tags: &observable.tags,
                directives: &observable.directives,
                exclude_modules: &observable.exclude_modules,
                limit_modules: &observable.limit_modules,
            };
            let mut done: BTreeSet<&str> = results
                .get(&observable.id)
                .unwrap_or(&none)
                .iter()
                .map(String::as_str)
                .collect();
            // ace3's file_type result, built from the file's type, is the dependency's result
            if observable.type_result {
                done.insert(TYPE_STEP);
            }
            let mut components: Vec<&ace_sdk::Component> = self
                .catalog
                .iter()
                .filter(|component| component.key != TYPE_STEP)
                .filter(|component| check(component, facts, &mode_modules, &done).is_ok())
                .collect();
            if kind == ObservableKind::File
                && let Some(step) = type_step
            {
                // typed when anything the mode runs, file_type among them, would look at it
                let wanted =
                    !components.is_empty() || check(step, facts, &mode_modules, &done).is_ok();
                let step_task = tasks.get(&(observable.id, TYPE_STEP.to_owned()));
                let ended = match step_task {
                    Some((_, TaskState::Done | TaskState::Failed, _)) => true,
                    None if wanted => {
                        queued.extend(queue::enqueue(tx, root, observable.id, TYPE_STEP).await?);
                        false
                    }
                    Some((id, TaskState::Cancelled, _)) if wanted && requeue_cancelled => {
                        if queue::requeue_cancelled(tx, *id).await? {
                            queued.push(*id);
                        }
                        false
                    }
                    _ => false,
                };
                // nothing else on the file until its type step has ended
                if !ended {
                    components.clear();
                }
            }
            if components.iter().any(|c| !c.takes.is_everything()) {
                declaring.push(observable.id);
            }
            eligible.push((kind, components));
        }
        let held = if declaring.is_empty() {
            BTreeMap::new()
        } else {
            let needs = declared::Needs::of(self.catalog.iter());
            declared::held(tx, root, &declaring, &needs).await?
        };
        let nothing_held = declared::Held::default();
        for (observable, (kind, components)) in observables.iter().zip(eligible) {
            let facts = held.get(&observable.id).unwrap_or(&nothing_held).facts(
                kind,
                &observable.directives,
                mode,
            );
            for component in components {
                let key = component.key.as_str();
                let task = tasks.get(&(observable.id, key.to_owned()));
                // the module's declaration over what the core holds now (`crate::takes`)
                let declined = component.takes.check(&facts).err();
                if declined.is_some() && self.takes == TakesMode::Applied {
                    continue;
                }
                let added = match task {
                    None => queue::enqueue(tx, root, observable.id, key).await?,
                    Some((id, TaskState::Cancelled, _)) if requeue_cancelled => {
                        queue::requeue_cancelled(tx, *id).await?.then_some(*id)
                    }
                    Some(_) => None,
                };
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
        }
        Ok(queued)
    }

    /// Starts analysis of a new root: queues what is eligible for every observable it has. A
    /// root with nothing eligible completes its first pass at once.
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
        let pre = hooks::pre(tx, &self.hooks, &self.modes, root, &locked.mode, &all).await?;
        hooks::mark_due(tx, &self.hooks, &self.modes, root, &locked.mode).await?;
        if pre.detected
            && self.modes.is_detectable(&locked.mode)
            && !tree::has_whitelisted(tx.conn(), root).await?
        {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
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
        lock_root(tx, root).await?;
        sqlx::query!(
            "UPDATE analysis.roots SET analysis_mode = $2, cancelled_at = NULL WHERE id = $1",
            root,
            mode,
        )
        .execute(tx.conn())
        .await?;
        hooks::mark_due(tx, &self.hooks, &self.modes, root, mode).await?;
        // a mode that runs file_type gives typed files ace3's result where an earlier mode didn't
        self.show_types(tx, root, mode, Scope::All).await?;
        self.queue_eligible_locked(tx, root, mode, Scope::All, true)
            .await
    }

    /// What follows a file's type step, however it ended (`queue::TypeStepEnded`): the file shows
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
            pre = hooks::pre(tx, &self.hooks, &self.modes, root, &mode, &touched).await?;
            touched.extend(pre.touched.iter().copied());
            hooks::mark_due(tx, &self.hooks, &self.modes, root, &mode).await?;
        }
        if pre.detected
            && self.modes.is_detectable(&mode)
            && !tree::has_whitelisted(tx.conn(), root).await?
        {
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

    /// Gives each typed file in `scope` that doesn't show it yet ace3's file_type result, where
    /// that module would run on it in `mode` by the core's rules (`type_step::show`), and returns
    /// those files.
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
            r#"SELECT o.id AS "id: ObservableId", o.value, o.tags, o.directives, o.exclude_modules,
                      o.limit_modules
               FROM analysis.observables o
               JOIN queue.tasks t ON t.root_id = o.root_id AND t.observable_id = o.id
                    AND t.module = $3 AND t.state IN ('done', 'failed')
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
        for row in rows {
            let facts = Facts {
                kind: ObservableKind::File,
                tags: &row.tags,
                directives: &row.directives,
                exclude_modules: &row.exclude_modules,
                limit_modules: &row.limit_modules,
            };
            if check(component, facts, &mode_modules, &none).is_err() {
                continue;
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
        if detected
            && self.modes.is_detectable(mode)
            && !tree::has_whitelisted(tx.conn(), root).await?
        {
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
    /// alert in correlation mode, which reruns eligibility over the whole root.
    pub async fn land_result(
        &self,
        tx: &mut Tx<'_>,
        worker: &Worker,
        task: &Task,
        result: &ResultEnvelope<Value>,
    ) -> Result<Landed, OrchestratorError> {
        let root = task.root;
        let analyzed = task.observable.id;
        let locked = lock_root(tx, root).await?;
        let mode = locked.mode;
        worker.finish_in(tx, task.id, TaskState::Done, None).await?;
        if self.takes == TakesMode::Audit {
            declared::report_if_marked(tx, task.id, &task.module, "stored a result").await?;
        }
        let result_id = tree::insert_result(tx, root, analyzed, &task.module, result).await?;
        tree::add_to_observable(tx, root, analyzed, &result.analyzed).await?;

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
            tree::add_result_addition(tx, root, result_id, id, None).await?;
            touched.push(id);
            detections.extend(observable.detections.iter().map(|d| (id, d)));
        }
        for file in &result.files {
            let mut observable = NewObservable::new(ObservableKind::File, file.sha256.to_hex());
            observable.tags = file.tags.clone();
            observable.directives = file.directives.clone();
            observable.exclude_modules = file.exclude_modules.clone();
            observable.relationships = file.relationships.clone();
            observable.redirection = file.redirection.clone();
            let id = tree::upsert_observable_at(tx, root, &observable, depth)
                .await?
                .id;
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
            tree::add_result_addition(tx, root, result_id, id, Some(file.path.as_str())).await?;
            touched.push(id);
            detections.extend(file.detections.iter().map(|d| (id, d)));
        }
        if !result.redirected.is_empty() {
            let target = match tree::redirection(tx.conn(), root, analyzed).await? {
                Some(target) => tree::find_observable(tx.conn(), root, &target).await?,
                None => None,
            };
            if let Some(id) = target {
                tree::add_to_observable(tx, root, id, &result.redirected).await?;
                touched.push(id);
                detections.extend(result.redirected.detections.iter().map(|d| (id, d)));
            } else {
                // a module only writes these for an input that has a redirection, and its target
                // is an observable an earlier result named
                tracing::warn!(
                    %root,
                    module = %task.module,
                    "a result added to a redirection that isn't in the root; those additions are dropped"
                );
            }
        }
        for other in &result.others {
            match tree::find_observable(tx.conn(), root, &other.observable).await? {
                Some(id) => {
                    tree::add_to_observable(tx, root, id, &other.additions).await?;
                    touched.push(id);
                    detections.extend(other.additions.detections.iter().map(|d| (id, d)));
                }
                None => tracing::warn!(
                    %root,
                    module = %task.module,
                    observable = %other.observable.value,
                    "a result added to an observable that isn't in the root; those additions are dropped"
                ),
            }
        }
        for (observable, detection) in &detections {
            tree::add_detection(tx, root, *observable, Some(result_id), detection).await?;
        }
        if let Some(changes) = &result.root {
            tree::change_root(tx, root, changes).await?;
        }
        // the observable modifier's pre rules, before anything is queued for what the result touched
        let mut pre = hooks::Effects::default();
        if !locked.cancelled {
            pre = hooks::pre(tx, &self.hooks, &self.modes, root, &mode, &touched).await?;
            touched.extend(pre.touched.iter().copied());
            hooks::mark_due(tx, &self.hooks, &self.modes, root, &mode).await?;
        }

        // a result that lands after its root was cancelled is kept, and queues nothing
        if locked.cancelled {
            queue::check_completion(tx, root).await?;
            return Ok(Landed {
                result: result_id,
                queued: Vec::new(),
                mode_changed_to: None,
            });
        }
        // ace3's executor: when the observable a module analyzed turns out whitelisted, the whole tree
        // is, so analysis stops there. What the result added stays, and the root never alerts.
        if is_whitelisted(&result.analyzed.tags, &result.analyzed.directives) {
            tracing::info!(%root, module = %task.module, "a result whitelisted its observable; stopping the root's analysis");
            queue::cancel_root(tx, root).await?;
            queue::check_completion(tx, root).await?;
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
        if (!detections.is_empty() || pre.detected)
            && self.modes.is_detectable(&mode)
            && !tree::has_whitelisted(tx.conn(), root).await?
        {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %mode, "a detection made the root an alert");
            let mut queued = self.set_mode(tx, root, CORRELATION).await?;
            queued.extend(qa_task);
            queue::check_completion(tx, root).await?;
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
        queue::check_completion(tx, root).await?;
        Ok(Landed {
            result: result_id,
            queued,
            mode_changed_to: None,
        })
    }
}

impl queue::TypeStepEnded for Orchestrator {
    fn ended<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
    ) -> queue::TypeStepFuture<'a> {
        Box::pin(async move {
            match self.type_step_ended(tx, root, observable).await {
                Ok(_) => Ok(()),
                Err(OrchestratorError::Queue(e)) => Err(e),
                Err(OrchestratorError::Db(e)) => Err(QueueError::Db(e)),
                Err(OrchestratorError::NoRoot(root)) => {
                    Err(QueueError::Db(DbError::Decode(format!("no root {root}"))))
                }
            }
        })
    }
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
