//! What the core holds about an observable when it decides whether to queue a task, for the
//! modules' declarations of what they take (`ace_sdk::takes`, PLAN.md decision 23), and the audit
//! setting that checks those declarations.
//!
//! Eligibility (`crate::orchestrator`) asks a component's declaration once the core's own rules
//! allow the task, and doesn't queue a task it declines. It asks again whenever it reruns for the
//! observable, which it does when a result adds to it or adds it again, when a hook changes it, and
//! over the whole root when the mode changes; so a fact that arrives later (a nearer path, a
//! directive, the module that adds a file, ace3's `file_type` result) queues the task then. The
//! facts here are the ones a leased task carries, read the same way: a file's path is the one it is
//! analyzed under (`tree::analysis_file`, settled or the one it would settle on now), its role the
//! one on that path, its size the store's for its bytes and its type what the type step found in
//! them (`crate::type_step`), which is known before any task but the type step is queued.
//!
//! **The audit setting**, `ACE_RS_TAKES_AUDIT=1` for `ace serve` and the hunter: the core queues
//! every task as it did before declarations, and marks the ones a declaration would have declined
//! with the reason (`queue.tasks.declined`). A mark is cleared when eligibility reruns and the
//! declaration takes the task, which is when the core would have queued it without the setting.
//! The pool checks the declaration again on every task either way, so a marked task ends skipped
//! unless the facts it was leased with differ from the ones it was marked on. A marked task that
//! nevertheless stored a result (which is how an observable, a tag, a detection or a file is
//! added) or failed is what the declaration would have lost: the core logs each at ERROR under the
//! target `ace_takes` as it ends, and `audit_report` lists them all. That list must be empty
//! before the setting is turned off for a module's declaration, a site's among them.

use std::collections::{BTreeMap, BTreeSet};

use ace_results::types::file_type::TypeFacts;
use ace_results::{FileRole, ObservableKind, Relationship, YaraMeta};
use ace_sdk::Component;
use ace_sdk::directives::SourcedDirective;
use ace_sdk::takes::{Facts, FileFacts};
use serde_json::Value;
use uuid::Uuid;

use crate::bucket::ALERT_FILES;
use crate::db::{DbError, Tx};
use crate::tree::ObservableId;
use crate::type_step::{self, TYPE_STEP};

/// Whether the core applies the modules' declarations or only audits them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TakesMode {
    /// A task a declaration declines isn't queued.
    #[default]
    Applied,
    /// Every task is queued as before, and the ones a declaration declines are marked.
    Audit,
}

impl TakesMode {
    /// `ACE_RS_TAKES_AUDIT`: `1` or `true` audits, unset, empty, `0` or `false` applies.
    pub fn from_env() -> Result<TakesMode, String> {
        match std::env::var("ACE_RS_TAKES_AUDIT").as_deref() {
            Err(_) | Ok("" | "0" | "false") => Ok(TakesMode::Applied),
            Ok("1" | "true") => Ok(TakesMode::Audit),
            Ok(other) => Err(format!("ACE_RS_TAKES_AUDIT is 1 or 0, not {other:?}")),
        }
    }
}

/// An observable's facts as the core read them, owned.
#[derive(Debug, Clone, Default)]
pub struct Held {
    /// Where its directives came from (`tree::directive_sources`), when a declaration reads it.
    pub directive_sources: Vec<SourcedDirective>,
    pub relationships: Vec<Relationship>,
    pub redirected: bool,
    pub added_by: Vec<String>,
    /// It came with its root's submission (`tree::at_root`).
    pub at_root: bool,
    pub file: Option<HeldFile>,
    pub results: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct HeldFile {
    pub path: String,
    pub size: Option<u64>,
    /// None when the file's type is unknown.
    pub facts: Option<TypeFacts>,
    pub role: Option<FileRole>,
    pub yara_meta: Vec<YaraMeta>,
}

impl Held {
    /// The facts for the declarations, with the observable's own row's.
    pub fn facts<'a>(
        &'a self,
        kind: ObservableKind,
        directives: &'a [String],
        mode: &'a str,
    ) -> Facts<'a> {
        Facts {
            kind,
            directives,
            directive_sources: &self.directive_sources,
            relationships: &self.relationships,
            redirected: self.redirected,
            added_by: &self.added_by,
            at_root: self.at_root,
            mode: Some(mode),
            file: self.file.as_ref().map(|file| FileFacts {
                path: &file.path,
                size: file.size,
                facts: file.facts.as_ref(),
                role: file.role,
                yara_meta: Some(&file.yara_meta),
            }),
            results: &self.results,
        }
    }
}

/// What the declarations of `components` read, so only that is fetched.
#[derive(Debug, Clone, Default)]
pub struct Needs {
    pub added_by: bool,
    pub directive_sources: bool,
    pub results: Vec<String>,
}

impl Needs {
    pub fn of<'a>(components: impl IntoIterator<Item = &'a Component>) -> Needs {
        let mut needs = Needs::default();
        let mut results = BTreeSet::new();
        for component in components {
            let reads = component.takes.reads();
            needs.added_by |= reads.added_by;
            needs.directive_sources |= reads.directive_sources;
            results.extend(reads.results);
        }
        needs.results = results.into_iter().collect();
        needs
    }
}

/// The facts of `observables` in `root` that declarations read, by observable. A file's path is the
/// one its tasks read (`tree::analysis_file`); a file without one in the root has no file facts,
/// and a lease would fail its task. Every observable listed has an entry.
pub async fn held(
    tx: &mut Tx<'_>,
    root: Uuid,
    observables: &[ObservableId],
    needs: &Needs,
) -> Result<BTreeMap<ObservableId, Held>, DbError> {
    let ids: Vec<i64> = observables.iter().map(|o| o.0).collect();
    let mut held: BTreeMap<ObservableId, Held> =
        observables.iter().map(|o| (*o, Held::default())).collect();
    let rows = sqlx::query!(
        r#"SELECT o.id AS "id: ObservableId", (o.redirection_type IS NOT NULL) AS "redirected!",
                  (o.depth = 0) AS "at_root!", o.value, f.path AS "path?", f.yara_meta AS "yara_meta?", f.role, s.size AS "size?"
           FROM analysis.observables o
           LEFT JOIN LATERAL (
               SELECT path, yara_meta, role FROM analysis.files
               WHERE root_id = o.root_id AND observable_id = o.id
               ORDER BY analyzed DESC, depth, path COLLATE "C" LIMIT 1
           ) f ON o.type = 'file'
           LEFT JOIN store.objects s ON o.type = 'file' AND s.pool = $3 AND s.sha256 = o.value
           WHERE o.root_id = $1 AND o.id = ANY($2)"#,
        root,
        &ids,
        ALERT_FILES,
    )
    .fetch_all(tx.conn())
    .await?;
    let files: Vec<String> = rows
        .iter()
        .filter(|row| row.path.is_some())
        .map(|row| row.value.clone())
        .collect();
    let mut types = type_step::facts_of(tx.conn(), &files).await?;
    for row in rows {
        let entry = held.entry(row.id).or_default();
        entry.redirected = row.redirected;
        // as `tree::at_root` reads it
        entry.at_root = row.at_root;
        if let Some(path) = row.path {
            entry.file = Some(HeldFile {
                path,
                size: row.size.and_then(|s| u64::try_from(s).ok()),
                facts: types.remove(&row.value),
                role: row.role.and_then(|role| role.parse().ok()),
                // as the lease reads them
                yara_meta: row
                    .yara_meta
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|tag| tag.parse().ok())
                    .collect(),
            });
        }
    }
    for row in sqlx::query!(
        r#"SELECT observable_id AS "id: ObservableId", kind, target_type, target_value
           FROM analysis.relationships
           WHERE root_id = $1 AND observable_id = ANY($2)
           ORDER BY observable_id, kind, target_type, target_value"#,
        root,
        &ids,
    )
    .fetch_all(tx.conn())
    .await?
    {
        let kind = serde_json::from_value(Value::String(row.kind.clone()))
            .map_err(|e| DbError::Decode(format!("observable {}: {}: {e}", row.id.0, row.kind)))?;
        let target = row
            .target_type
            .parse()
            .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.id.0)))?;
        held.entry(row.id)
            .or_default()
            .relationships
            .push(Relationship::new(
                kind,
                ace_results::ObservableRef::new(target, row.target_value),
            ));
    }
    if needs.added_by {
        for row in sqlx::query!(
            r#"SELECT a.observable_id AS "id: ObservableId", r.module AS "module!"
               FROM analysis.result_additions a
               JOIN analysis.results r ON r.id = a.result_id
               WHERE a.root_id = $1 AND a.observable_id = ANY($2)
               GROUP BY a.observable_id, r.module
               ORDER BY a.observable_id, min(a.id)"#,
            root,
            &ids,
        )
        .fetch_all(tx.conn())
        .await?
        {
            held.entry(row.id).or_default().added_by.push(row.module);
        }
    }
    // as `tree::directive_sources` reads them for a lease
    if needs.directive_sources {
        for row in sqlx::query!(
            r#"SELECT DISTINCT observable_id AS "id: ObservableId", directive, source
               FROM analysis.directive_sources
               WHERE root_id = $1 AND observable_id = ANY($2) AND source <> 'unrecorded'"#,
            root,
            &ids,
        )
        .fetch_all(tx.conn())
        .await?
        {
            let source = row
                .source
                .parse()
                .map_err(|e| DbError::Decode(format!("observable {}: {e}", row.id.0)))?;
            held.entry(row.id)
                .or_default()
                .directive_sources
                .push(SourcedDirective::new(row.directive, source));
        }
        for entry in held.values_mut() {
            entry.directive_sources.sort();
        }
    }
    // ace3's file_type result is built from the file's type where the file shows it
    if needs.results.iter().any(|module| module == TYPE_STEP) {
        for (id, typed) in type_step::results_of(tx.conn(), root, Some(observables)).await? {
            held.entry(id)
                .or_default()
                .results
                .insert(TYPE_STEP.to_owned(), typed.details());
        }
    }
    if !needs.results.is_empty() {
        for row in sqlx::query!(
            r#"SELECT observable_id AS "id: ObservableId", module, details
               FROM analysis.results
               WHERE root_id = $1 AND observable_id = ANY($2) AND module = ANY($3)"#,
            root,
            &ids,
            &needs.results,
        )
        .fetch_all(tx.conn())
        .await?
        {
            held.entry(row.id)
                .or_default()
                .results
                .insert(row.module, row.details);
        }
    }
    Ok(held)
}

/// Marks a task as one a declaration declines, with the reason, or clears the mark.
pub async fn mark(
    tx: &mut Tx<'_>,
    task: crate::queue::TaskId,
    declined: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE queue.tasks SET declined = $2 WHERE id = $1 AND declined IS DISTINCT FROM $2",
        task as crate::queue::TaskId,
        declined,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// A task a declaration declined that stored a result or failed: what the declaration would have
/// lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    pub task: i64,
    pub root: Uuid,
    pub module: String,
    pub observable: String,
    pub declined: String,
    /// `result` or `failed`.
    pub ended: String,
}

/// Every task the audit setting marked that stored a result or failed. Empty when every
/// declaration declined only what its module declined.
pub async fn audit_report(executor: impl sqlx::PgExecutor<'_>) -> Result<Vec<Lost>, DbError> {
    Ok(sqlx::query_as!(
        Lost,
        r#"SELECT t.id AS "task!", t.root_id AS "root!", t.module AS "module!",
                  (o.type || ':' || o.value) AS "observable!", t.declined AS "declined!",
                  (CASE WHEN r.id IS NOT NULL THEN 'result' ELSE 'failed' END) AS "ended!"
           FROM queue.tasks t
           JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
           LEFT JOIN analysis.results r ON r.root_id = t.root_id
                AND r.observable_id = t.observable_id AND r.module = t.module
           WHERE t.declined IS NOT NULL AND (r.id IS NOT NULL OR t.state = 'failed')
           ORDER BY t.id"#,
    )
    .fetch_all(executor)
    .await?)
}

/// Logs the task if the audit marked it, as one that `ended` as it did.
pub async fn report_if_marked(
    tx: &mut Tx<'_>,
    task: crate::queue::TaskId,
    module: &str,
    ended: &str,
) -> Result<(), DbError> {
    let declined = sqlx::query_scalar!(
        "SELECT declined FROM queue.tasks WHERE id = $1",
        task as crate::queue::TaskId,
    )
    .fetch_optional(tx.conn())
    .await?
    .flatten();
    if let Some(declined) = declined {
        report_lost(task, module, &declined, ended);
    }
    Ok(())
}

/// Logs a marked task that ended with a result or failed, at ERROR under `ace_takes`: the audit's
/// report as it happens. `declined` is the task's mark.
pub fn report_lost(task: crate::queue::TaskId, module: &str, declined: &str, ended: &str) {
    tracing::error!(
        target: "ace_takes",
        task = %task,
        module,
        declined,
        ended,
        "the module's declaration declined this task, and it {ended}: the declaration would lose that"
    );
}
