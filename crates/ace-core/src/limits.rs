//! ace3's automation limit (`automation_limit`, `saq/modules/base_module.py`'s `accepts`) and its
//! directive `ignore_automation_limits`: a module that may fan out, such as a lookup for each
//! recipient of a mass mail, stops at a number of analyses in a root.
//!
//! **What is counted**, as ace3 counts it: the root's results of the component's analysis type,
//! whichever component wrote them (ace3's `root.get_analysis_by_type`, so a module's instances count
//! together), a result from the analysis cache and one with an error among them, and, because ace4
//! runs a root's tasks at once where ace3 ran its modules one after another, the tasks of those
//! components still to run (queued, delayed or running): each is a result ace3 would have counted by
//! the time it looked at the next observable. A task the audit setting queued only because a
//! declaration declines it (`crate::takes`) isn't counted, since without the setting it wouldn't be
//! queued.
//!
//! **Where it is enforced**: where eligibility would queue the component's task on an observable
//! (`Orchestrator::queue_eligible`), after every other rule and the component's declaration, and
//! before the analysis cache is looked at, as ace3's `accepts` comes before its cache lookup. With
//! the count at the limit, nothing is queued and nothing is looked up. An observable with
//! `ignore_automation_limits` isn't held to it, though its result is counted, as ace3's is.
//!
//! **What happens to the work over the limit**: it isn't done, as in ace3, and it is recorded
//! (`analysis.automation_limited`, migration 0075), with a debug line, which is all ace3 writes.
//! ace3 asks `accepts` again whenever it looks at the observable, so an analysis that ended with
//! nothing frees a place for the next one; here a task of the same analysis type that ends with no
//! result (a skip, a failure, a cancellation: `queue::TaskEnded::without_result`) has eligibility run
//! again for the observables recorded, oldest first, which queues as many as the limit then allows.
//! So a root ends with as many results of the type as ace3's would, at most the limit.
//!
//! **Where the limit comes from**: a module's own default, `Module::AUTOMATION_LIMIT`, or its overlay
//! section's or instance's `automation_limit` (`ace_sdk::overlay`), beside `cache_ttl`, outside its
//! settings, so it isn't in a cached result's key, as ace3's config hash leaves it out. ace3's own
//! open-source modules set none at `fe6da632` (`saq.default.yaml`), so no module of ace4's has one.

use uuid::Uuid;

use crate::db::{DbError, Tx};
use crate::tree::ObservableId;

/// ace3's `DIRECTIVE_IGNORE_AUTOMATION_LIMITS`: an observable with it isn't held to any module's
/// limit, as when an analyst forces its analysis.
pub const IGNORE_AUTOMATION_LIMITS: &str = ace_sdk::module::IGNORE_AUTOMATION_LIMITS;

/// How many results of `analysis_type` the root holds and how many tasks of `modules` (the components
/// that write it) are still to run: what a component of that type is held to its limit by.
pub async fn count(
    tx: &mut Tx<'_>,
    root: Uuid,
    analysis_type: &str,
    modules: &[String],
) -> Result<u32, DbError> {
    let count = sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM analysis.results
                   WHERE root_id = $1 AND analysis_type = $2)
                + (SELECT count(*) FROM queue.tasks
                   WHERE root_id = $1 AND module = ANY($3)
                     AND state IN ('queued', 'delayed', 'running') AND declined IS NULL)
               AS "count!""#,
        root,
        analysis_type,
        modules,
    )
    .fetch_one(tx.conn())
    .await?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Records that `module`'s work on `observable` was held back at `limit`.
pub async fn hold(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    module: &str,
    limit: u32,
) -> Result<(), DbError> {
    tracing::debug!(
        %root,
        observable = observable.0,
        module,
        limit,
        "the module reached its automation limit in the root"
    );
    sqlx::query!(
        "INSERT INTO analysis.automation_limited (root_id, observable_id, module, automation_limit)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (root_id, observable_id, module) DO NOTHING",
        root,
        observable as ObservableId,
        module,
        i32::try_from(limit).unwrap_or(i32::MAX),
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Drops the record of `module`'s work on `observable` held back, once it is queued or done.
pub async fn release(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    module: &str,
) -> Result<(), DbError> {
    sqlx::query!(
        "DELETE FROM analysis.automation_limited
         WHERE root_id = $1 AND observable_id = $2 AND module = $3",
        root,
        observable as ObservableId,
        module,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The observables whose work for any of `modules` the limit held back in the root, oldest first.
pub async fn held(
    tx: &mut Tx<'_>,
    root: Uuid,
    modules: &[String],
) -> Result<Vec<ObservableId>, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT DISTINCT observable_id AS "id: ObservableId"
           FROM analysis.automation_limited
           WHERE root_id = $1 AND module = ANY($2)
           ORDER BY observable_id"#,
        root,
        modules,
    )
    .fetch_all(tx.conn())
    .await?)
}

/// What a module's limit counts in one root, for one run of eligibility: each analysis type's count,
/// read once and then kept up as tasks are queued.
#[derive(Debug, Default)]
pub struct Counts {
    counts: std::collections::BTreeMap<String, u32>,
}

impl Counts {
    /// The count for `analysis_type`, read on first use.
    pub async fn get(
        &mut self,
        tx: &mut Tx<'_>,
        root: Uuid,
        analysis_type: &str,
        modules: &[String],
    ) -> Result<u32, DbError> {
        if let Some(count) = self.counts.get(analysis_type) {
            return Ok(*count);
        }
        let count = count(tx, root, analysis_type, modules).await?;
        self.counts.insert(analysis_type.to_owned(), count);
        Ok(count)
    }

    /// One more for `analysis_type`, if its count was read: a task queued.
    pub fn add(&mut self, analysis_type: &str) {
        if let Some(count) = self.counts.get_mut(analysis_type) {
            *count = count.saturating_add(1);
        }
    }

    /// Forgets `analysis_type`'s count, so it is read again: after something this run can't follow,
    /// such as a cached result landing with eligibility of its own.
    pub fn forget(&mut self, analysis_type: &str) {
        self.counts.remove(analysis_type);
    }
}
