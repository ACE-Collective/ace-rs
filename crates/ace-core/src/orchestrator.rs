//! The orchestrator: what happens when a result lands, and when a root's mode changes.
//!
//! A result lands in one transaction with its task's end: the result row, the observables it
//! adds, what it adds to the observable it analyzed, its detections, and the tasks that just
//! became eligible. A detection in a detectable mode turns the root into an alert in
//! correlation mode, as ace3's engine does (`analysis_orchestrator.py`, `_handle_detection_points`),
//! and a mode change reruns eligibility over every observable the root has.
//!
//! Each of these locks the root's row first, so two results landing on one root take turns:
//! the second sees the first's observables and mode, and nothing the first made eligible is
//! missed. Landing a result checks the root's completion last, so the tasks it queues keep the
//! same pass open.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use ace_results::{Detection, FieldError, NewObservable, ObservableKind, Registry, ResultEnvelope};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{DbError, Retryable, Tx};
use crate::eligibility::{Catalog, Facts, check};
use crate::modes::{CORRELATION, DISPOSITIONED, Modes};
use crate::queue::{self, QueueError, Task, TaskId, TaskState, Worker};
use crate::tree::{self, ObservableId, ResultId};

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
    /// Tasks queued because the result made them eligible.
    pub queued: Vec<TaskId>,
    /// The mode the root changed to, when a detection made it an alert.
    pub mode_changed_to: Option<String>,
}

/// What dispositioning an alert did.
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
        }
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
        let registry = self
            .registry
            .get_or_init(|| {
                let outputs: Vec<_> = self.catalog.iter().map(|(_, m)| m.output).collect();
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
        let mode_modules = self.modes.modules_in(mode);
        let only: Option<Vec<i64>> = match scope {
            Scope::All => None,
            Scope::Observables(ids) => Some(ids.iter().map(|id| id.0).collect()),
        };
        let observables = sqlx::query!(
            r#"SELECT id AS "id: ObservableId", type AS kind, directives, exclude_modules
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
        let mut tasks: BTreeMap<(ObservableId, String), (TaskId, TaskState)> = BTreeMap::new();
        for row in sqlx::query!(
            r#"SELECT id AS "id: TaskId", observable_id AS "observable_id: ObservableId", module,
                      state AS "state: TaskState"
               FROM queue.tasks
               WHERE root_id = $1 AND ($2::bigint[] IS NULL OR observable_id = ANY($2))"#,
            root,
            only.as_deref(),
        )
        .fetch_all(tx.conn())
        .await?
        {
            tasks.insert((row.observable_id, row.module), (row.id, row.state));
        }

        let none = BTreeSet::new();
        let mut queued = Vec::new();
        for observable in &observables {
            let kind: ObservableKind = observable
                .kind
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", observable.id.0)))?;
            let facts = Facts {
                kind,
                directives: &observable.directives,
                exclude_modules: &observable.exclude_modules,
            };
            let done: BTreeSet<&str> = results
                .get(&observable.id)
                .unwrap_or(&none)
                .iter()
                .map(String::as_str)
                .collect();
            for (key, manifest) in self.catalog.iter() {
                if check(key, manifest, facts, &mode_modules, &done).is_err() {
                    continue;
                }
                match tasks.get(&(observable.id, key.to_owned())) {
                    None => {
                        if let Some(id) = queue::enqueue(tx, root, observable.id, key).await? {
                            queued.push(id);
                        }
                    }
                    Some((id, TaskState::Cancelled)) if requeue_cancelled => {
                        if queue::requeue_cancelled(tx, *id).await? {
                            queued.push(*id);
                        }
                    }
                    Some(_) => {}
                }
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
        let queued = self
            .queue_eligible_locked(tx, root, &locked.mode, Scope::All, false)
            .await?;
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
        self.queue_eligible_locked(tx, root, mode, Scope::All, true)
            .await
    }

    /// Records an analyst's disposition of an alert: cancels its analysis, then switches it
    /// to dispositioned mode, which queues that mode's few modules, as ace3 does when
    /// `stop_analysis_on_any_alert_disposition` is set.
    pub async fn disposition(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        disposition: &str,
    ) -> Result<Dispositioned, OrchestratorError> {
        let cancelled = queue::cancel_root(tx, root).await?;
        sqlx::query!(
            "UPDATE analysis.roots SET disposition = $2, dispositioned_at = now() WHERE id = $1",
            root,
            disposition,
        )
        .execute(tx.conn())
        .await?;
        let queued = self.set_mode(tx, root, DISPOSITIONED).await?;
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
        let result_id = tree::insert_result(tx, root, analyzed, &task.module, result).await?;
        tree::add_to_observable(
            tx,
            root,
            analyzed,
            &result.analyzed.tags,
            &result.analyzed.directives,
        )
        .await?;

        let mut touched = vec![analyzed];
        let mut detections: Vec<(ObservableId, &Detection)> = result
            .detections
            .iter()
            .chain(&result.analyzed.detections)
            .map(|d| (analyzed, d))
            .collect();
        for observable in &result.observables {
            let id = tree::upsert_observable(tx, root, observable).await?.id;
            touched.push(id);
            detections.extend(observable.detections.iter().map(|d| (id, d)));
        }
        for file in &result.files {
            let mut observable = NewObservable::new(ObservableKind::File, file.sha256.to_hex());
            observable.tags = file.tags.clone();
            observable.directives = file.directives.clone();
            observable.exclude_modules = file.exclude_modules.clone();
            let id = tree::upsert_observable(tx, root, &observable).await?.id;
            let yara_meta: Vec<String> = file
                .yara_meta
                .iter()
                .map(|tag| tag.as_str().to_owned())
                .collect();
            tree::add_file(tx, root, id, file.path.as_str(), &yara_meta).await?;
            touched.push(id);
            detections.extend(file.detections.iter().map(|d| (id, d)));
        }
        for (observable, detection) in &detections {
            tree::add_detection(tx, root, *observable, Some(result_id), detection).await?;
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
        if !detections.is_empty() && self.modes.is_detectable(&mode) {
            sqlx::query!(
                "UPDATE analysis.roots SET alerted_at = COALESCE(alerted_at, now()) WHERE id = $1",
                root,
            )
            .execute(tx.conn())
            .await?;
            tracing::info!(%root, from = %mode, "a detection made the root an alert");
            let queued = self.set_mode(tx, root, CORRELATION).await?;
            queue::check_completion(tx, root).await?;
            return Ok(Landed {
                result: result_id,
                queued,
                mode_changed_to: Some(CORRELATION.to_owned()),
            });
        }
        let queued = self
            .queue_eligible_locked(tx, root, &mode, Scope::Observables(&touched), false)
            .await?;
        queue::check_completion(tx, root).await?;
        Ok(Landed {
            result: result_id,
            queued,
            mode_changed_to: None,
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
