//! An analyst adds directives to an observable of an alert (PLAN.md decision 31).
//!
//! ace3 lets an analyst add a directive through its alert page's Add Observable form
//! (`app/analysis/views/edit/observable.py` at `fe6da632`, under `alert:write`), which offers
//! `GUI_DIRECTIVES` and, for an observable already in the alert, adds the directive to it. The API's
//! observable actions do the same for one directive each (`aceapi_v2/alerts/service.py`'s
//! `request_observable_analysis`, under `observable:write`): render, crawl, collect a file. Either way ace3
//! then calls `request_analyst_analysis`, which puts the alert back in correlation mode and past the stop
//! on a dispositioned alert, syncs it and queues it, so the engine runs every module the directive now
//! lets in. An alert whose disposition only ACE sets is refused (`ensure_not_frozen`).
//!
//! Here `add_directives` takes the directives the binary lists (`ace_sdk::directives`), refuses any other,
//! adds the new ones to the observable's row and moves the root to correlation mode
//! (`Orchestrator::set_mode`), which reruns eligibility over every observable and queues again what a
//! disposition cancelled, in one transaction with its audit row. A module whose required directive was
//! added is queued then. Each directive asked for is recorded as the analyst's (PLAN.md decision 44),
//! the ones the observable had already too, so a module that takes a directive only from an analyst
//! (`ace_sdk::takes::Condition::DirectiveFrom`) runs on an observable a hunt stamped it on once an
//! analyst asks for it. A module that already ran on the observable isn't run again, as in ace3, where
//! the engine skips a module whose analysis exists.
//!
//! Not here from ace3: `request_analyst_analysis` also clears the root's failed modules so they run
//! again, and ace4 never claims a failed task again (the owner's decision of 2026-11-16). ace3 has no way
//! for an analyst to remove a directive, and neither has this.

use ace_core::modes::CORRELATION;
use ace_core::queue;
use ace_sdk::directives::DirectiveList;
use serde::Serialize;
use uuid::Uuid;

use crate::actor::Actor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{ALERT_READ, OBSERVABLE_WRITE};
use crate::{Service, ServiceError};

/// What adding directives did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectivesAdded {
    /// The directives the observable didn't have, in the order asked for.
    pub added: Vec<String>,
    /// The observable's directives now.
    pub directives: Vec<String>,
    /// How many tasks the root queued again or anew.
    pub queued: usize,
}

/// The observable's state an audit row records before and after.
#[derive(Debug, Serialize)]
struct DirectiveState<'a> {
    directives: &'a [String],
    analysis_mode: &'a str,
}

impl Recorded for DirectiveState<'_> {}

/// What the row says about the request.
#[derive(Debug, Serialize)]
struct DirectiveRequest<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
    requested: &'a [String],
    added: &'a [String],
    queued: usize,
}

impl Recorded for DirectiveRequest<'_> {}

impl Service {
    /// The service with the directives an analyst may add, the built-in ones and the site's
    /// (`ace_app::App::directives`). `DirectiveList::builtin` unless the binary sets others.
    pub fn with_directives(mut self, directives: DirectiveList) -> Self {
        self.directives = std::sync::Arc::new(directives);
        self
    }

    /// The directives an analyst may add, for an adapter that has already checked the reader.
    pub fn directives(&self) -> &DirectiveList {
        &self.directives
    }

    /// The directives an analyst may add, in name order, under `alert:read`.
    pub async fn directive_list(&self, actor: &Actor) -> Result<&DirectiveList, ServiceError> {
        self.gate
            .read(actor, "directive_list", &ALERT_READ, &|_tx| {
                Box::pin(async { Ok(()) })
            })
            .await?;
        Ok(self.directives())
    }

    /// Adds directives to an observable of an alert, as ace3's Add Observable form does, and analyzes the
    /// alert again in correlation mode (the module's docs). It needs `observable:write`. Each directive
    /// must be one the binary lists (`InvalidRequest` otherwise, naming them), and there must be at least
    /// one. A root that isn't an alert, or an observable it doesn't have, is `NotFound`; an alert whose
    /// disposition only ACE sets is `Conflict`, ace3's `AlertFrozen`. A directive the observable has is
    /// left as it is, and the alert is analyzed again all the same, as ace3 does.
    pub async fn add_directives(
        &self,
        actor: &Actor,
        root: Uuid,
        observable: i64,
        directives: &[String],
    ) -> Result<DirectivesAdded, ServiceError> {
        self.gate
            .write(actor, "add_directives", &OBSERVABLE_WRITE, &|tx| {
                Box::pin(async move {
                    let requested = self.checked_directives(directives)?;
                    let found = sqlx::query!(
                        r#"SELECT disposition, analysis_mode, alerted_at IS NOT NULL AS "alert!"
                           FROM analysis.roots WHERE id = $1 FOR UPDATE"#,
                        root,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .filter(|found| found.alert)
                    .ok_or_else(|| ServiceError::NotFound(format!("no alert {root}")))?;
                    if self.dispositions.is_frozen(found.disposition.as_deref()) {
                        return Err(ServiceError::Conflict(format!(
                            "the alert's disposition {} is set only by ACE, so it isn't analyzed again",
                            found.disposition.as_deref().unwrap_or_default()
                        )));
                    }
                    let target = sqlx::query!(
                        "SELECT type, value, directives FROM analysis.observables
                         WHERE root_id = $1 AND id = $2",
                        root,
                        observable,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| {
                        ServiceError::NotFound(format!("no observable {observable} in alert {root}"))
                    })?;
                    let added: Vec<String> = requested
                        .iter()
                        .filter(|name| !target.directives.contains(name))
                        .cloned()
                        .collect();
                    let now: Vec<String> = sqlx::query_scalar!(
                        "UPDATE analysis.observables
                         SET directives = directives || $3::text[]
                         WHERE root_id = $1 AND id = $2
                         RETURNING directives",
                        root,
                        observable,
                        &added,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    // each asked for is the analyst's, one the observable had too, so a module that
                    // takes it only from an analyst runs now (PLAN.md decision 44)
                    let identity = actor.to_string();
                    ace_core::tree::record_directive_sources(
                        tx,
                        root,
                        ace_core::tree::ObservableId(observable),
                        &requested,
                        ace_core::tree::DirectivesFrom::analyst(&identity),
                    )
                    .await?;
                    // ace3's request_analyst_analysis: correlation mode, so a dispositioned alert runs
                    // what the directive lets in, and what its disposition cancelled
                    // a new pass, as ace3's `request_analyst_analysis` queues the alert again, which
                    // runs again what ended incomplete (PLAN.md decision 34)
                    let queued = self.orchestrator.new_pass(tx, root, CORRELATION).await?;
                    queue::check_completion(tx, root)
                        .await
                        .map_err(ace_core::orchestrator::OrchestratorError::from)?;
                    let change = Change::updated(
                        Target::observable(root, observable),
                        &DirectiveState {
                            directives: &target.directives,
                            analysis_mode: &found.analysis_mode,
                        },
                        &DirectiveState {
                            directives: &now,
                            analysis_mode: CORRELATION,
                        },
                    )?
                    .details(&DirectiveRequest {
                        kind: &target.r#type,
                        value: &target.value,
                        requested: &requested,
                        added: &added,
                        queued: queued.len(),
                    })?;
                    Ok(Audited::changed(
                        DirectivesAdded {
                            added,
                            directives: now,
                            queued: queued.len(),
                        },
                        change,
                    ))
                })
            })
            .await
    }

    /// The directives asked for, each once in the order asked, when every one is listed.
    fn checked_directives(&self, directives: &[String]) -> Result<Vec<String>, ServiceError> {
        if directives.is_empty() {
            return Err(ServiceError::InvalidRequest(
                "name at least one directive".to_owned(),
            ));
        }
        let unknown: Vec<&str> = directives
            .iter()
            .map(String::as_str)
            .filter(|name| !self.directives.contains(name))
            .collect();
        if !unknown.is_empty() {
            // a name is the caller's: it's quoted, and only the first few are, however many there are
            let named: Vec<String> = unknown
                .iter()
                .take(5)
                .map(|name| format!("{:?}", name.chars().take(64).collect::<String>()))
                .collect();
            return Err(ServiceError::InvalidRequest(format!(
                "not a directive an analyst may add: {} (the directives are {})",
                named.join(", "),
                self.directives.names().collect::<Vec<_>>().join(", ")
            )));
        }
        let mut once: Vec<String> = Vec::with_capacity(directives.len());
        for name in directives {
            if !once.contains(name) {
                once.push(name.clone());
            }
        }
        Ok(once)
    }
}
