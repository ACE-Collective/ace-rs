//! Detection verdicts (PLAN.md 7.14): ace3's `saq/detection_verdicts/`, the TP/FP grade of each detection,
//! which SVS (7.10) reads for its samples' labels.
//!
//! Only what someone said about one detection is stored, in `analysis.detection_verdicts`, with every change
//! in `analysis.detection_verdict_history` in the same transaction. Every other verdict is derived when it's
//! read, from the class of the alert's disposition (`DispositionClasses`):
//!
//! ```text
//! effective(detection) =
//!     NULL                      if the alert's disposition is unclassified
//!     NULL                      if the alert is attributed to a test run that isn't reviewed (7.10)
//!     fp  inherited_single      if the disposition is an FP one: a stored verdict is masked
//!     the stored verdict, explicit, if there is one
//!     tp  inherited_single      if the alert's detections are all from one signature
//!     tp  inherited_multi       otherwise: unconfirmed
//! ```
//!
//! The rule exists twice, as `effective_verdict` here and as `analysis.detection_verdict` and
//! `analysis.detection_verdict_source`, which every query uses, and the tests check that the two agree.
//! Migration 0047 (7.10) gave both the test run condition: every query passes `svs.unreviewed_run` of the
//! detection's root, true while an attribution of the alert that holds names a run that isn't reviewed, as
//! ace3's `unreviewed_run_condition` is. Removing the attribution gives the verdicts back.
//!
//! **What a verdict is keyed on.** ace3 keys it on a detection's content hash, a hash of the node it's on,
//! its signature, description and details, because its `detection_points` rows are copies that each sync of
//! the alert deletes and inserts again. ace4 keys it on the detection's row, `analysis.detections.id`. That
//! row is the detection itself, not a copy: a result is written once per (root, observable, module), and
//! nothing deletes a detection but its root's delete, which takes the verdicts with it, as deleting an alert
//! does in ace3. So the id is as stable as ace3's hash, it needs no frozen formula, and a detection on the
//! alert itself (7.6's, with no observable) needs no node key of its own. Where they differ: two identical
//! detections on one alert are two rows here, each with its own verdict, where ace3 collapses them into one.
//! For SVS, a sample's contributing detections are those of the rule's signature on the file observable
//! whose value is the sample's sha256, each joined to its verdict by its id; an attribution (7.10) names
//! the detection's id where ace3's names its hash. If a later step ever re-analyzes a root by deleting its
//! results, it has to carry the verdicts across, or they go with the rows.
//!
//! **Who may grade.** An analyst can only refine a TP alert: mark a detection that was noise as FP, or
//! confirm an inherited TP. On an FP alert every detection is FP, and a wrong one is fixed by correcting the
//! alert's disposition. A disposition only ACE sets (SIMULATED, `DispositionClasses::set_by_ace`) takes
//! verdicts only from ACE itself: ace3's `analyst=False`, which here is an `Actor::Internal`. Every write
//! needs `alert:write`, as ace3's routes do.
//!
//! From ace3, and what differs:
//! - `set_verdict`, `clear_verdict`, `set_verdicts` and `confirm_alert` are `set_detection_verdict`,
//!   `clear_detection_verdict`, `set_detection_verdicts` and `confirm_detections`, each through `Gate::write`
//!   with its audit row, in one transaction with its history rows.
//! - A target is (alert, detection id) where ace3's is (alert id, content hash). A detection of a root that
//!   isn't an alert is gone, as the detection list doesn't show it.
//! - ace3's `SkipCause.DETECTION`, a row synced before detection identity, has no counterpart: every row
//!   here is the detection itself.
//! - Who set a verdict is the actor, as every row here records one, where ace3 stores a user's id and refuses
//!   an API key without a user (422). A key without an owner holding `alert:write` can set one.
//! - `confirm_detections` reads and writes in one transaction, where ace3's reads first and then calls
//!   `set_verdicts` in a second; the result is the same, and nothing is set meanwhile.
//! - The classification is the site overlay's `disposition_classification:` and `dispositions:`, merged over
//!   ace3's `saq.default.yaml` and checked when `ace serve` starts (`Dispositions::configured`), then held
//!   by the service (`Service::with_dispositions`). `analyst_selectable: false` decides who grades the
//!   alert's detections here, and in `Service::disposition` who may set the disposition, as in ace3.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ace_core::db::Tx;
use serde::Serialize;
use sqlx::types::Json;
use uuid::Uuid;

use crate::dispositions::is_analyst;
use crate::permission::ALERT_WRITE;
use crate::{Actor, Audited, Change, Recorded, Service, ServiceError, Target};

/// The most targets one `set_detection_verdicts` takes.
pub const MAX_VERDICT_TARGETS: usize = 1000;

/// A detection's verdict: it found malicious activity (`Tp`) or it didn't (`Fp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Tp,
    Fp,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Tp => "tp",
            Verdict::Fp => "fp",
        }
    }

    /// `tp` or `fp`, as ace3 spells them.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tp" => Some(Verdict::Tp),
            "fp" => Some(Verdict::Fp),
            _ => None,
        }
    }
}

/// Why a detection's verdict is what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    /// Someone set it, or confirmed an inherited TP.
    Explicit,
    /// Inherited from the alert, which stated it for this detection: an FP alert, or a TP alert all of
    /// whose detections are from one signature.
    InheritedSingle,
    /// An inherited TP on an alert where several signatures fired, which nobody has confirmed: the
    /// weakest, which SVS reports apart.
    InheritedMulti,
}

impl VerdictSource {
    pub const ALL: [VerdictSource; 3] = [
        VerdictSource::Explicit,
        VerdictSource::InheritedSingle,
        VerdictSource::InheritedMulti,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VerdictSource::Explicit => "explicit",
            VerdictSource::InheritedSingle => "inherited_single",
            VerdictSource::InheritedMulti => "inherited_multi",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        VerdictSource::ALL
            .into_iter()
            .find(|source| source.as_str() == text)
    }
}

/// What a disposition says about an alert's detections: the overlay's `tp` and `fp`.
pub use ace_sdk::DispositionClass;

/// Which dispositions classify how, ace3's `disposition_classification`, and which only ACE sets, ace3's
/// `analyst_selectable: false`. A disposition in neither map is unclassified: its detections have no
/// verdict. An alert with no disposition is OPEN, which is unclassified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispositionClasses {
    classes: BTreeMap<String, DispositionClass>,
    set_by_ace: BTreeSet<String>,
}

impl Default for DispositionClasses {
    fn default() -> Self {
        DispositionClasses::ace3()
    }
}

impl DispositionClasses {
    /// ace3's, from its `saq.default.yaml` (`Dispositions::ace3`).
    pub fn ace3() -> Self {
        crate::Dispositions::ace3().classes().clone()
    }

    /// The dispositions only ACE sets, sorted.
    pub fn set_by_ace_list(&self) -> Vec<String> {
        self.set_by_ace.iter().cloned().collect()
    }

    pub fn new(
        classes: impl IntoIterator<Item = (String, DispositionClass)>,
        set_by_ace: impl IntoIterator<Item = String>,
    ) -> Self {
        DispositionClasses {
            classes: classes.into_iter().collect(),
            set_by_ace: set_by_ace.into_iter().collect(),
        }
    }

    /// The class of a disposition, None for an unclassified one.
    pub fn class(&self, disposition: Option<&str>) -> Option<DispositionClass> {
        disposition.and_then(|name| self.classes.get(name).copied())
    }

    /// The TP dispositions and the FP ones, each sorted, as the queries take them.
    pub fn lists(&self) -> (Vec<String>, Vec<String>) {
        let of = |class| {
            self.classes
                .iter()
                .filter(|(_, c)| **c == class)
                .map(|(name, _)| name.clone())
                .collect()
        };
        (of(DispositionClass::Tp), of(DispositionClass::Fp))
    }

    /// Whether only ACE sets the disposition, so only ACE grades its alerts' detections.
    pub fn set_by_ace(&self, disposition: Option<&str>) -> bool {
        disposition.is_some_and(|name| self.set_by_ace.contains(name))
    }

    /// Why no detection of an alert with this disposition takes a verdict from this kind of actor, or None
    /// when they do: ace3's `verdict_refusal`, for a caller that offers only what will work.
    pub fn refusal(&self, disposition: Option<&str>, analyst: bool) -> Option<String> {
        let shown = disposition.unwrap_or(crate::OPEN);
        match self.class(disposition) {
            Some(DispositionClass::Fp) => Some(
                "every detection on a false positive alert is FP; if the alert was wrong, correct its disposition"
                    .to_owned(),
            ),
            None => Some(format!(
                "the alert's disposition {shown} is unclassified, so its detections have no verdict"
            )),
            Some(DispositionClass::Tp) if analyst && self.set_by_ace(disposition) => Some(format!(
                "the verdicts of an alert with the disposition {shown} are set by ACE, not by analysts"
            )),
            Some(DispositionClass::Tp) => None,
        }
    }
}

/// A detection's verdict and its source: the rule in Rust, ace3's `compute_effective`. `class` is the
/// alert's disposition's, `stored` the stored verdict, `multi_signature` whether the alert has detections
/// from more than one signature, and `unreviewed_run` whether it's attributed to a test run that isn't
/// reviewed (7.10).
pub fn effective_verdict(
    class: Option<DispositionClass>,
    stored: Option<Verdict>,
    multi_signature: bool,
    unreviewed_run: bool,
) -> (Option<Verdict>, Option<VerdictSource>) {
    let Some(class) = class else {
        return (None, None);
    };
    if unreviewed_run {
        return (None, None);
    }
    if class == DispositionClass::Fp {
        return (Some(Verdict::Fp), Some(VerdictSource::InheritedSingle));
    }
    if let Some(stored) = stored {
        return (Some(stored), Some(VerdictSource::Explicit));
    }
    let source = if multi_signature {
        VerdictSource::InheritedMulti
    } else {
        VerdictSource::InheritedSingle
    };
    (Some(Verdict::Tp), Some(source))
}

/// Why a batch didn't write a detection's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SkipCause {
    /// The alert's disposition doesn't take this actor's verdicts.
    Alert,
    /// The alert has no such detection, or isn't an alert.
    Gone,
    /// Its verdict's source isn't the one asked for (`only_source`).
    Source,
}

/// A detection a batch didn't write, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDetection {
    pub alert: Uuid,
    pub detection: i64,
    pub cause: SkipCause,
    pub reason: String,
}

/// What a batch did: how many detections changed, how many had the verdict already, and the ones it
/// couldn't write, each with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerdictBatch {
    pub changed: usize,
    pub unchanged: usize,
    pub skipped: Vec<SkippedDetection>,
}

/// How a batch treats what it can't write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchRules {
    /// Skip a detection whose verdict's source, once it's locked, isn't this one, so a confirm never
    /// overwrites a verdict someone set meanwhile.
    pub only_source: Option<VerdictSource>,
    /// A skip of one of these causes fails the whole batch with `ServiceError::Conflict`, and nothing is
    /// written.
    pub refuse: BTreeSet<SkipCause>,
}

const GONE: &str = "the detection is gone from its alert";

/// One detection's stored verdict, before or after a write, as its audit row keeps it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VerdictState {
    detection: i64,
    alert: Uuid,
    signature_uuid: Option<String>,
    verdict: Option<Verdict>,
}

impl Recorded for VerdictState {}

/// Several detections' stored verdicts.
#[derive(Debug, Serialize)]
pub(crate) struct VerdictStates {
    pub(crate) verdicts: Vec<VerdictState>,
}

impl Recorded for VerdictStates {}

/// What a batch left as it was.
#[derive(Debug, Serialize)]
struct BatchDetails {
    unchanged: usize,
    skipped: usize,
}

impl Recorded for BatchDetails {}

/// What a write changed: each detection's stored verdict before and after.
#[derive(Debug, Default)]
pub(crate) struct Written {
    pub(crate) batch: VerdictBatch,
    pub(crate) before: Vec<VerdictState>,
    pub(crate) after: Vec<VerdictState>,
}

impl Service {
    /// The dispositions' classes the verdicts are derived from, the service's `Dispositions`'.
    pub fn disposition_classes(&self) -> &DispositionClasses {
        self.dispositions.classes()
    }

    /// Why no detection of an alert with this disposition takes a verdict from `actor`, or None when they
    /// do. It checks no permission: an adapter uses it to offer only what will work.
    pub fn verdict_refusal(&self, actor: &Actor, disposition: Option<&str>) -> Option<String> {
        self.dispositions
            .classes()
            .refusal(disposition, is_analyst(actor))
    }

    /// Stores `verdict` on one detection of a TP alert, ace3's `set_verdict`. It needs `alert:write`. Returns
    /// false, with no audit row, when it was stored already. A detection the alert doesn't have is
    /// `NotFound`; an alert whose disposition doesn't take the actor's verdicts is `Conflict`, saying why.
    pub async fn set_detection_verdict(
        &self,
        actor: &Actor,
        alert: Uuid,
        detection: i64,
        verdict: Verdict,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "set_detection_verdict", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    self.change_one(tx, actor, alert, detection, Some(verdict))
                        .await
                })
            })
            .await
    }

    /// Removes the stored verdict on one detection, so it inherits from the alert again: ace3's
    /// `clear_verdict`. Otherwise as `set_detection_verdict`.
    pub async fn clear_detection_verdict(
        &self,
        actor: &Actor,
        alert: Uuid,
        detection: i64,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "clear_detection_verdict", &ALERT_WRITE, &|tx| {
                Box::pin(async move { self.change_one(tx, actor, alert, detection, None).await })
            })
            .await
    }

    async fn change_one(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        alert: Uuid,
        detection: i64,
        verdict: Option<Verdict>,
    ) -> Result<Audited<bool>, ServiceError> {
        let rules = BatchRules {
            only_source: None,
            refuse: BTreeSet::from([SkipCause::Alert, SkipCause::Gone]),
        };
        let written = self
            .write_verdicts(tx, actor, &[(alert, detection)], verdict, &rules)
            .await?;
        match (
            written.before.into_iter().next(),
            written.after.into_iter().next(),
        ) {
            (Some(before), Some(after)) => Ok(Audited::changed(
                true,
                Change::updated(Target::detection(detection), &before, &after)?,
            )),
            _ => Ok(Audited::unchanged(false)),
        }
    }

    /// Stores `verdict` (None clears it) on every target, (alert, detection), in one transaction: ace3's
    /// `set_verdicts`. It needs `alert:write`, and takes at most `MAX_VERDICT_TARGETS`. A detection that can't
    /// take the verdict is skipped with the reason, not an error, unless `rules` refuses its cause, and an
    /// error writes nothing. The detections are locked in (alert, id) order, so two batches never wait on
    /// each other in a cycle. Its audit row names the detections it changed; one that changed none has none.
    pub async fn set_detection_verdicts(
        &self,
        actor: &Actor,
        targets: &[(Uuid, i64)],
        verdict: Option<Verdict>,
        rules: &BatchRules,
    ) -> Result<VerdictBatch, ServiceError> {
        if targets.len() > MAX_VERDICT_TARGETS {
            return Err(ServiceError::InvalidRequest(format!(
                "a batch of verdicts has at most {MAX_VERDICT_TARGETS} detections"
            )));
        }
        self.gate
            .write(actor, "set_detection_verdicts", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let written = self
                        .write_verdicts(tx, actor, targets, verdict, rules)
                        .await?;
                    if written.before.is_empty() {
                        return Ok(Audited::unchanged(written.batch));
                    }
                    let ids: Vec<i64> = written.after.iter().map(|s| s.detection).collect();
                    let change = Change::updated(
                        Target::detections(&ids),
                        &VerdictStates {
                            verdicts: written.before,
                        },
                        &VerdictStates {
                            verdicts: written.after,
                        },
                    )?
                    .details(&BatchDetails {
                        unchanged: written.batch.unchanged,
                        skipped: written.batch.skipped.len(),
                    })?;
                    Ok(Audited::changed(written.batch, change))
                })
            })
            .await
    }

    /// Confirms every unconfirmed (inherited_multi) TP of an alert by storing an explicit TP on each, which
    /// keeps the verdict and upgrades its source: ace3's `confirm_alert`. Returns how many it confirmed. It
    /// needs `alert:write`. An alert whose disposition doesn't take the actor's verdicts is `Conflict`, and a
    /// root that isn't an alert `NotFound`.
    pub async fn confirm_detections(
        &self,
        actor: &Actor,
        alert: Uuid,
    ) -> Result<usize, ServiceError> {
        let (tp, fp) = self.disposition_classes().lists();
        let (tp, fp) = (&tp, &fp);
        self.gate
            .write(actor, "confirm_detections", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let disposition = sqlx::query_scalar!(
                        "SELECT disposition FROM analysis.roots
                         WHERE id = $1 AND alerted_at IS NOT NULL",
                        alert,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| crate::alerts::no_alert(alert))?;
                    if let Some(why) = self.verdict_refusal(actor, disposition.as_deref()) {
                        return Err(ServiceError::Conflict(why));
                    }
                    let unconfirmed = sqlx::query_scalar!(
                        r#"SELECT d.id FROM analysis.detections d
                           JOIN analysis.roots r ON r.id = d.root_id
                           LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                           WHERE d.root_id = $1
                             AND analysis.detection_verdict_source(
                                   r.disposition, $2, $3, v.verdict,
                                   EXISTS (SELECT FROM analysis.detections o
                                           WHERE o.root_id = d.root_id
                                             AND o.signature_uuid IS DISTINCT FROM d.signature_uuid), svs.unreviewed_run(d.root_id))
                                 = 'inherited_multi'
                           ORDER BY d.id"#,
                        alert,
                        tp,
                        fp,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    if unconfirmed.is_empty() {
                        return Ok(Audited::unchanged(0));
                    }
                    let targets: Vec<(Uuid, i64)> =
                        unconfirmed.into_iter().map(|id| (alert, id)).collect();
                    // one that's gone, or no longer unconfirmed, has nothing to confirm; anything else
                    // refuses the whole confirm, as ace3's does
                    let rules = BatchRules {
                        only_source: Some(VerdictSource::InheritedMulti),
                        refuse: BTreeSet::from([SkipCause::Alert]),
                    };
                    let written = self
                        .write_verdicts(tx, actor, &targets, Some(Verdict::Tp), &rules)
                        .await?;
                    let confirmed = written.batch.changed;
                    if confirmed == 0 {
                        return Ok(Audited::unchanged(0));
                    }
                    let change = Change::updated(
                        Target::root(alert),
                        &VerdictStates {
                            verdicts: written.before,
                        },
                        &VerdictStates {
                            verdicts: written.after,
                        },
                    )?;
                    Ok(Audited::changed(confirmed, change))
                })
            })
            .await
    }

    /// The writes of every function above, and of SVS's sample actions, in the caller's transaction,
    /// which `Gate::write` checked `alert:write` in.
    pub(crate) async fn write_verdicts(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        targets: &[(Uuid, i64)],
        verdict: Option<Verdict>,
        rules: &BatchRules,
    ) -> Result<Written, ServiceError> {
        let mut written = Written::default();
        let wanted: BTreeSet<(Uuid, i64)> = targets.iter().copied().collect();
        if wanted.is_empty() {
            return Ok(written);
        }
        let ids: Vec<i64> = wanted.iter().map(|(_, id)| *id).collect();
        let (tp, fp) = self.disposition_classes().lists();
        let analyst = is_analyst(actor);
        // locking the detection's row serializes the writers of its verdict, the first insert too, which
        // has no verdict row to lock yet
        let rows = sqlx::query!(
            r#"SELECT d.id, d.root_id, d.signature_uuid, r.disposition
               FROM analysis.detections d
               JOIN analysis.roots r ON r.id = d.root_id
               WHERE d.id = ANY ($1) AND r.alerted_at IS NOT NULL
               ORDER BY d.root_id, d.id
               FOR NO KEY UPDATE OF d"#,
            &ids,
        )
        .fetch_all(tx.conn())
        .await?;
        let found: BTreeSet<(Uuid, i64)> = rows.iter().map(|row| (row.root_id, row.id)).collect();
        let skip = |written: &mut Written,
                    (alert, detection): (Uuid, i64),
                    cause: SkipCause,
                    reason: String|
         -> Result<(), ServiceError> {
            if rules.refuse.contains(&cause) {
                return Err(match cause {
                    SkipCause::Gone => ServiceError::NotFound(format!(
                        "alert {alert} has no detection {detection}"
                    )),
                    SkipCause::Alert | SkipCause::Source => ServiceError::Conflict(reason),
                });
            }
            written.batch.skipped.push(SkippedDetection {
                alert,
                detection,
                cause,
                reason,
            });
            Ok(())
        };
        for gone in wanted.difference(&found) {
            skip(&mut written, *gone, SkipCause::Gone, GONE.to_owned())?;
        }
        let mut refusals: HashMap<Uuid, Option<String>> = HashMap::new();
        for row in rows {
            let target = (row.root_id, row.id);
            if !wanted.contains(&target) {
                // the id is a detection of another alert
                continue;
            }
            let refusal = refusals
                .entry(row.root_id)
                .or_insert_with(|| {
                    self.disposition_classes()
                        .refusal(row.disposition.as_deref(), analyst)
                })
                .clone();
            if let Some(why) = refusal {
                skip(&mut written, target, SkipCause::Alert, why)?;
                continue;
            }
            if let Some(only) = rules.only_source {
                let source = sqlx::query_scalar!(
                    r#"SELECT analysis.detection_verdict_source(
                                r.disposition, $2, $3, v.verdict,
                                EXISTS (SELECT FROM analysis.detections o
                                        WHERE o.root_id = d.root_id
                                          AND o.signature_uuid IS DISTINCT FROM d.signature_uuid), svs.unreviewed_run(d.root_id))
                       FROM analysis.detections d
                       JOIN analysis.roots r ON r.id = d.root_id
                       LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                       WHERE d.id = $1"#,
                    row.id,
                    &tp,
                    &fp,
                )
                .fetch_one(tx.conn())
                .await?;
                if source.as_deref() != Some(only.as_str()) {
                    let source = source.unwrap_or_else(|| "None".to_owned());
                    skip(
                        &mut written,
                        target,
                        SkipCause::Source,
                        format!("its verdict source is {source}, not {}", only.as_str()),
                    )?;
                    continue;
                }
            }
            let stored = sqlx::query_scalar!(
                "SELECT verdict FROM analysis.detection_verdicts WHERE detection_id = $1",
                row.id,
            )
            .fetch_optional(tx.conn())
            .await?;
            let old = stored.as_deref().and_then(Verdict::parse);
            if old == verdict {
                written.batch.unchanged += 1;
                continue;
            }
            match verdict {
                Some(new) => {
                    sqlx::query!(
                        "INSERT INTO analysis.detection_verdicts
                             (detection_id, root_id, signature_uuid, verdict, set_by)
                         VALUES ($1, $2, $3, $4, $5::jsonb)
                         ON CONFLICT (detection_id) DO UPDATE
                         SET verdict = excluded.verdict, set_by = excluded.set_by, set_at = now()",
                        row.id,
                        row.root_id,
                        row.signature_uuid,
                        new.as_str(),
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                }
                None => {
                    sqlx::query!(
                        "DELETE FROM analysis.detection_verdicts WHERE detection_id = $1",
                        row.id,
                    )
                    .execute(tx.conn())
                    .await?;
                }
            }
            sqlx::query!(
                "INSERT INTO analysis.detection_verdict_history
                     (detection_id, root_id, signature_uuid, old_verdict, new_verdict, changed_by)
                 VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
                row.id,
                row.root_id,
                row.signature_uuid,
                old.map(Verdict::as_str),
                verdict.map(Verdict::as_str),
                Json(actor) as _,
            )
            .execute(tx.conn())
            .await?;
            let state = |verdict| VerdictState {
                detection: row.id,
                alert: row.root_id,
                signature_uuid: row.signature_uuid.clone(),
                verdict,
            };
            written.before.push(state(old));
            written.after.push(state(verdict));
            written.batch.changed += 1;
        }
        Ok(written)
    }
}
