//! Every alert's detections (PLAN.md 5.6's `detection_points`), for reports and exports: ace3's
//! `/api/v2/detection-points` list and its alerts router's `/alerts/{uuid}/detection-points`.
//!
//! ace3 copies each alert's detection points into `detection_points` when the alert syncs. ace4's
//! `analysis.detections` (2.10) is already that table: a row per detection, on the observable it's on, with
//! the result that raised it. A detection on a root no detection made an alert isn't listed, as ace3 has no
//! row for it, and reading one needs `alert:read`, as there. A read writes no row.
//!
//! The list is a keyset page in id order, oldest first, so a report builder paging to the end while
//! detections arrive sees each once and ends at the newest. As in ace3, a later page misses a detection
//! that commits after a page past its id was read, and one whose root becomes an alert after that.
//! `changed_since` is how a puller catches those, as in ace3: a detection made, or whose root became an
//! alert, at or after that time. Both times are their transaction's start, so as with ace3's a pull should
//! pass the time the previous pull started, and a transaction still open then can land a row stamped before
//! it; delivery is at least once for a transaction shorter than the gap between pulls.
//!
//! Each detection comes with its verdict (7.14, `crate::detection_verdicts`): the effective verdict, its
//! source, and the stored one behind them with who set it and when, as ace3's `detection_points_select`.
//! `changed_since` also catches a detection whose alert was dispositioned, which derives every verdict
//! again, and one whose stored verdict was set or cleared, from its history, as ace3's does. ace3 also
//! counts any other change to the alert's row, which says nothing new about a detection.
//!
//! The filters (5.10) are the detection points screen's (`crate::filters`): `Alert Date`, `Family`,
//! `Signature`, and 7.14's `Verdict` (with `none` for no verdict), `Source` and `Has Override`, each a fixed
//! condition in one static query with its values bound. ace3's others, and why they aren't here, are
//! `FilterScreen::DetectionPoints.left_out()`. The exports (`ace-api`) page through
//! `Service::detection_points` with the same filter to the end, and `detection_point_count` is how they
//! refuse one past their bound before sending anything.
//!
//! A detection's description and details are what a module, a rule's meta or a submission wrote, so they
//! are data: nothing here reads them, and the adapters return them as they are.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::{RecordedActor, SET_LIST_TIMEOUT, no_alert, page_limit, timed_out};
use crate::detection_verdicts::{Verdict, VerdictSource};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most detections one page holds, as ace3's listing.
pub const MAX_DETECTIONS_PAGE: u32 = 1000;

/// The Verdict filter's value for a detection with no verdict, ace3's `VERDICT_FILTER_NONE`.
const NO_VERDICT: &str = "none";

/// Which detections to list. Every filter that's set must match.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPointFilter {
    /// Only this alert's, as ace3's `/alerts/{uuid}/detection-points` lists them.
    pub alert: Option<Uuid>,
    /// The detection points screen's filters.
    pub filters: Vec<FilterEntry>,
    /// Only those made, whose root became an alert or was dispositioned, or whose stored verdict changed,
    /// at or after this.
    pub changed_since: Option<DateTime<Utc>>,
    /// Where a date filter's wall clock is.
    pub tz: Tz,
}

impl Default for DetectionPointFilter {
    fn default() -> Self {
        DetectionPointFilter {
            alert: None,
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

/// A date filter's windows as two arrays, starts and ends.
type Windows = (Option<Vec<DateTime<Utc>>>, Option<Vec<DateTime<Utc>>>);

/// The filter's parameters, as the queries take them.
struct Params {
    signed: (Option<Vec<String>>, Option<Vec<String>>),
    not_signed: (Option<Vec<String>>, Option<Vec<String>>),
    family: Option<Vec<String>>,
    not_family: Option<Vec<String>>,
    alerted: Windows,
    not_alerted: Windows,
    /// The TP dispositions and the FP ones.
    tp: Vec<String>,
    fp: Vec<String>,
    /// The verdicts asked for, and whether `none` was.
    verdict: (Option<Vec<String>>, bool),
    not_verdict: (Option<Vec<String>>, bool),
    source: Option<Vec<String>>,
    not_source: Option<Vec<String>>,
    /// `true`, `false` or both.
    has_override: Option<Vec<String>>,
    not_has_override: Option<Vec<String>>,
}

fn verdicts(names: Option<Vec<String>>) -> (Option<Vec<String>>, bool) {
    match names {
        None => (None, false),
        Some(names) => {
            let none = names.iter().any(|name| name == NO_VERDICT);
            (
                Some(
                    names
                        .into_iter()
                        .filter(|name| name != NO_VERDICT)
                        .collect(),
                ),
                none,
            )
        }
    }
}

fn params(service: &Service, filter: &DetectionPointFilter) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::DetectionPoints,
        &filter.filters,
        Utc::now(),
        filter.tz,
    )?;
    let (tp, fp) = service.disposition_classes().lists();
    Ok(Params {
        signed: split(f.signatures("signature", false)),
        not_signed: split(f.signatures("signature", true)),
        family: f.names("family", false),
        not_family: f.names("family", true),
        alerted: split(f.windows("alert_date", false)?),
        not_alerted: split(f.windows("alert_date", true)?),
        tp,
        fp,
        verdict: verdicts(f.names("verdict", false)),
        not_verdict: verdicts(f.names("verdict", true)),
        source: f.names("source", false),
        not_source: f.names("source", true),
        has_override: f.names("has_override", false),
        not_has_override: f.names("has_override", true),
    })
}

/// One detection of an alert, with its verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPoint {
    pub id: i64,
    pub alert: Uuid,
    /// The observable it's on, as (id, type, value). One on a module's analysis is on the observable it
    /// analyzed; None is a detection on the alert itself, as `configuration_defined_tagging` makes.
    pub observable: Option<(i64, String, String)>,
    /// The module whose result raised it, or None for one a submission or the core added.
    pub module: Option<String>,
    pub description: String,
    pub details: Option<Value>,
    /// The alert queue it asks for.
    pub queue: Option<String>,
    pub signature_uuid: Option<String>,
    pub signature_version: Option<String>,
    pub signature_family: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Its effective verdict, None when the alert's disposition is unclassified.
    pub verdict: Option<Verdict>,
    /// Why the verdict is what it is.
    pub verdict_source: Option<VerdictSource>,
    /// The stored verdict, if any: ace3's `override`, masked on an FP alert.
    pub override_verdict: Option<Verdict>,
    /// Who stored it, and when.
    pub override_by: Option<RecordedActor>,
    pub override_set_at: Option<DateTime<Utc>>,
}

/// One page of detections, oldest first, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPointPage {
    pub detections: Vec<DetectionPoint>,
    pub next: Option<i64>,
}

fn decode<T>(
    text: Option<String>,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, ServiceError> {
    text.map(|text| {
        parse(&text).ok_or_else(|| {
            ServiceError::from(ace_core::DbError::Decode(format!(
                "a stored verdict or source {text:?}"
            )))
        })
    })
    .transpose()
}

impl Service {
    /// A page of detections on alerts in id order, of up to `limit` (100 when None, at most
    /// `MAX_DETECTIONS_PAGE`) after the detection `after` names. An `alert` filter that names no alert is
    /// `NotFound`, as ace3's per-alert list is.
    pub async fn detection_points(
        &self,
        actor: &crate::Actor,
        filter: &DetectionPointFilter,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<DetectionPointPage, ServiceError> {
        let limit = page_limit(limit, MAX_DETECTIONS_PAGE)?;
        self.detection_page(actor, filter, limit, after, None).await
    }

    /// One detection of an alert, with its verdict, as the list gives it: ace3's `get_alert_detection_point`.
    /// It needs `alert:read`. A root that isn't an alert, or a detection it doesn't have, is `NotFound`.
    pub async fn detection_point(
        &self,
        actor: &crate::Actor,
        alert: Uuid,
        detection: i64,
    ) -> Result<DetectionPoint, ServiceError> {
        let filter = DetectionPointFilter {
            alert: Some(alert),
            ..DetectionPointFilter::default()
        };
        self.detection_page(actor, &filter, 1, None, Some(detection))
            .await?
            .detections
            .pop()
            .ok_or_else(|| {
                ServiceError::NotFound(format!("alert {alert} has no detection {detection}"))
            })
    }

    async fn detection_page(
        &self,
        actor: &crate::Actor,
        filter: &DetectionPointFilter,
        limit: i64,
        after: Option<i64>,
        only: Option<i64>,
    ) -> Result<DetectionPointPage, ServiceError> {
        let alert = filter.alert;
        let changed_since = filter.changed_since;
        let p = &params(self, filter)?;
        self.gate
            .read(actor, "detection_points", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    if let Some(alert) = alert {
                        known_alert(tx, alert).await?;
                    }
                    let rows = sqlx::query!(
                        r#"SELECT d.id, d.root_id, d.observable_id, o.type AS "type?", o.value AS "value?",
                                  res.module AS "module?", d.description, d.details, d.queue,
                                  d.signature_uuid, d.signature_version, d.signature_family,
                                  d.created_at, e.verdict AS "verdict?", e.source AS "source?",
                                  v.verdict AS "stored?", v.set_by AS "set_by?: Value",
                                  v.set_at AS "set_at?"
                           FROM analysis.detections d
                           JOIN analysis.roots r ON r.id = d.root_id
                           LEFT JOIN analysis.observables o
                             ON o.root_id = d.root_id AND o.id = d.observable_id
                           LEFT JOIN analysis.results res ON res.id = d.result_id
                           LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                           CROSS JOIN LATERAL (
                             SELECT analysis.detection_verdict(r.disposition, $16, $17, v.verdict, svs.unreviewed_run(d.root_id)) AS verdict,
                                    analysis.detection_verdict_source(
                                      r.disposition, $16, $17, v.verdict,
                                      EXISTS (SELECT FROM analysis.detections x
                                              WHERE x.root_id = d.root_id
                                                AND x.signature_uuid IS DISTINCT FROM d.signature_uuid), svs.unreviewed_run(d.root_id))
                                      AS source) e
                           WHERE r.alerted_at IS NOT NULL
                             AND ($2::uuid IS NULL OR d.root_id = $2)
                             AND ($3::bigint IS NULL OR d.id > $3)
                             AND ($4::timestamptz IS NULL OR d.created_at >= $4 OR r.alerted_at >= $4
                                  OR r.dispositioned_at >= $4
                                  OR EXISTS (SELECT FROM analysis.detection_verdict_history h
                                             WHERE h.detection_id = d.id AND h.changed_at >= $4))
                             AND ($5::bigint IS NULL OR d.id = $5)
                             -- Signature: its uuid, and its version when the value has one
                             AND ($6::text[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($6::text[], $7::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             AND ($8::text[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($8::text[], $9::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             -- Family
                             AND ($10::text[] IS NULL OR d.signature_family = ANY ($10::text[]))
                             AND ($11::text[] IS NULL
                                  OR NOT COALESCE(d.signature_family = ANY ($11::text[]), false))
                             -- Alert Date: when its root became an alert
                             AND ($12::timestamptz[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($12::timestamptz[], $13::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                             AND ($14::timestamptz[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($14::timestamptz[], $15::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                             -- Verdict, with none for no verdict
                             AND ($18::text[] IS NULL OR e.verdict = ANY ($18::text[])
                                  OR ($19::boolean AND e.verdict IS NULL))
                             AND ($20::text[] IS NULL OR NOT COALESCE(e.verdict = ANY ($20::text[])
                                  OR ($21::boolean AND e.verdict IS NULL), false))
                             -- Source
                             AND ($22::text[] IS NULL OR e.source = ANY ($22::text[]))
                             AND ($23::text[] IS NULL OR NOT COALESCE(e.source = ANY ($23::text[]), false))
                             -- Has Override: true, false or both
                             AND ($24::text[] IS NULL OR (v.verdict IS NOT NULL)::text = ANY ($24::text[]))
                             AND ($25::text[] IS NULL OR NOT (v.verdict IS NOT NULL)::text = ANY ($25::text[]))
                           ORDER BY d.id
                           LIMIT $1"#,
                        limit + 1,
                        alert,
                        after,
                        changed_since,
                        only,
                        p.signed.0.as_deref(),
                        p.signed.1.as_deref(),
                        p.not_signed.0.as_deref(),
                        p.not_signed.1.as_deref(),
                        p.family.as_deref(),
                        p.not_family.as_deref(),
                        p.alerted.0.as_deref(),
                        p.alerted.1.as_deref(),
                        p.not_alerted.0.as_deref(),
                        p.not_alerted.1.as_deref(),
                        &p.tp,
                        &p.fp,
                        p.verdict.0.as_deref(),
                        p.verdict.1,
                        p.not_verdict.0.as_deref(),
                        p.not_verdict.1,
                        p.source.as_deref(),
                        p.not_source.as_deref(),
                        p.has_override.as_deref(),
                        p.not_has_override.as_deref(),
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;
                    let mut detections = Vec::with_capacity(rows.len());
                    for row in rows {
                        detections.push(DetectionPoint {
                            id: row.id,
                            alert: row.root_id,
                            observable: match (row.observable_id, row.r#type, row.value) {
                                (Some(id), Some(kind), Some(value)) => Some((id, kind, value)),
                                _ => None,
                            },
                            module: row.module,
                            description: row.description,
                            details: row.details,
                            queue: row.queue,
                            signature_uuid: row.signature_uuid,
                            signature_version: row.signature_version,
                            signature_family: row.signature_family,
                            created_at: row.created_at,
                            verdict: decode(row.verdict, Verdict::parse)?,
                            verdict_source: decode(row.source, VerdictSource::parse)?,
                            override_verdict: decode(row.stored, Verdict::parse)?,
                            override_by: RecordedActor::from_row(row.set_by)?,
                            override_set_at: row.set_at,
                        });
                    }
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let more = detections.len() > limit;
                    detections.truncate(limit);
                    let next = if more {
                        detections.last().map(|detection| detection.id)
                    } else {
                        None
                    };
                    Ok(DetectionPointPage { detections, next })
                })
            })
            .await
    }

    /// How many detections `filter` matches, counting no further than `cap` + 1, so an export can refuse one
    /// past its bound before it sends anything. An `alert` filter that names no alert is `NotFound`.
    pub async fn detection_point_count(
        &self,
        actor: &crate::Actor,
        filter: &DetectionPointFilter,
        cap: i64,
    ) -> Result<i64, ServiceError> {
        let alert = filter.alert;
        let changed_since = filter.changed_since;
        let p = &params(self, filter)?;
        self.gate
            .read(actor, "detection_point_count", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    if let Some(alert) = alert {
                        known_alert(tx, alert).await?;
                    }
                    sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM (
                           SELECT FROM analysis.detections d
                           JOIN analysis.roots r ON r.id = d.root_id
                           LEFT JOIN analysis.detection_verdicts v ON v.detection_id = d.id
                           CROSS JOIN LATERAL (
                             SELECT analysis.detection_verdict(r.disposition, $14, $15, v.verdict, svs.unreviewed_run(d.root_id)) AS verdict,
                                    analysis.detection_verdict_source(
                                      r.disposition, $14, $15, v.verdict,
                                      EXISTS (SELECT FROM analysis.detections x
                                              WHERE x.root_id = d.root_id
                                                AND x.signature_uuid IS DISTINCT FROM d.signature_uuid), svs.unreviewed_run(d.root_id))
                                      AS source) e
                           WHERE r.alerted_at IS NOT NULL
                             AND ($2::uuid IS NULL OR d.root_id = $2)
                             AND ($3::timestamptz IS NULL OR d.created_at >= $3 OR r.alerted_at >= $3
                                  OR r.dispositioned_at >= $3
                                  OR EXISTS (SELECT FROM analysis.detection_verdict_history h
                                             WHERE h.detection_id = d.id AND h.changed_at >= $3))
                             AND ($4::text[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($4::text[], $5::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             AND ($6::text[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($6::text[], $7::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             AND ($8::text[] IS NULL OR d.signature_family = ANY ($8::text[]))
                             AND ($9::text[] IS NULL
                                  OR NOT COALESCE(d.signature_family = ANY ($9::text[]), false))
                             AND ($10::timestamptz[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($10::timestamptz[], $11::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                             AND ($12::timestamptz[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($12::timestamptz[], $13::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                             AND ($16::text[] IS NULL OR e.verdict = ANY ($16::text[])
                                  OR ($17::boolean AND e.verdict IS NULL))
                             AND ($18::text[] IS NULL OR NOT COALESCE(e.verdict = ANY ($18::text[])
                                  OR ($19::boolean AND e.verdict IS NULL), false))
                             AND ($20::text[] IS NULL OR e.source = ANY ($20::text[]))
                             AND ($21::text[] IS NULL OR NOT COALESCE(e.source = ANY ($21::text[]), false))
                             AND ($22::text[] IS NULL OR (v.verdict IS NOT NULL)::text = ANY ($22::text[]))
                             AND ($23::text[] IS NULL OR NOT (v.verdict IS NOT NULL)::text = ANY ($23::text[]))
                           LIMIT $1) counted"#,
                        cap.saturating_add(1),
                        alert,
                        changed_since,
                        p.signed.0.as_deref(),
                        p.signed.1.as_deref(),
                        p.not_signed.0.as_deref(),
                        p.not_signed.1.as_deref(),
                        p.family.as_deref(),
                        p.not_family.as_deref(),
                        p.alerted.0.as_deref(),
                        p.alerted.1.as_deref(),
                        p.not_alerted.0.as_deref(),
                        p.not_alerted.1.as_deref(),
                        &p.tp,
                        &p.fp,
                        p.verdict.0.as_deref(),
                        p.verdict.1,
                        p.not_verdict.0.as_deref(),
                        p.not_verdict.1,
                        p.source.as_deref(),
                        p.not_source.as_deref(),
                        p.has_override.as_deref(),
                        p.not_has_override.as_deref(),
                    )
                    .fetch_one(tx.conn())
                    .await
                    .map_err(timed_out)
                })
            })
            .await
    }
}

/// `NotFound` unless `alert` is an alert, as ace3's per-alert list answers.
async fn known_alert(tx: &mut ace_core::db::Tx<'_>, alert: Uuid) -> Result<(), ServiceError> {
    let known = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM analysis.roots
                          WHERE id = $1 AND alerted_at IS NOT NULL) AS "known!""#,
        alert,
    )
    .fetch_one(tx.conn())
    .await?;
    if known { Ok(()) } else { Err(no_alert(alert)) }
}
