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
//! The filters (5.10) are the detection points screen's (`crate::filters`): `Alert Date`, `Family` and
//! `Signature`, each a fixed condition in one static query with its values bound. ace3's others, and why
//! they aren't here, are `FilterScreen::DetectionPoints.left_out()`. The exports (`ace-api`) page through
//! `Service::detection_points` with the same filter to the end, and `detection_point_count` is how they
//! refuse one past their bound before sending anything.
//!
//! What later steps add here, and where:
//! - 7.14: each detection's effective verdict, its source and the stored override join `DetectionPoint`,
//!   and the verdict writes and the alert's confirm become writes here. ace3 keys a verdict on a content
//!   hash of the detection's node, signature, description and details; 7.14 decides whether ace4 keys it
//!   on that or on the row's id, which re-analysis doesn't keep.
//!
//! A detection's description and details are what a module, a rule's meta or a submission wrote, so they
//! are data: nothing here reads them, and the adapters return them as they are.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::{SET_LIST_TIMEOUT, no_alert, page_limit, timed_out};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most detections one page holds, as ace3's listing.
pub const MAX_DETECTIONS_PAGE: u32 = 1000;

/// Which detections to list. Every filter that's set must match.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPointFilter {
    /// Only this alert's, as ace3's `/alerts/{uuid}/detection-points` lists them.
    pub alert: Option<Uuid>,
    /// The detection points screen's filters.
    pub filters: Vec<FilterEntry>,
    /// Only those made, or whose root became an alert, at or after this.
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

/// The filter's parameters, in the order the queries take them.
type Params = (
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<String>>,
    Option<Vec<DateTime<Utc>>>,
    Option<Vec<DateTime<Utc>>>,
    Option<Vec<DateTime<Utc>>>,
    Option<Vec<DateTime<Utc>>>,
);

fn params(filter: &DetectionPointFilter) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::DetectionPoints,
        &filter.filters,
        Utc::now(),
        filter.tz,
    )?;
    let (signed, not_signed) = (
        f.signatures("signature", false),
        f.signatures("signature", true),
    );
    let (alerted, not_alerted) = (
        f.windows("alert_date", false)?,
        f.windows("alert_date", true)?,
    );
    let ((s1, s2), (s3, s4)) = (split(signed), split(not_signed));
    let ((a1, a2), (a3, a4)) = (split(alerted), split(not_alerted));
    Ok((
        s1,
        s2,
        s3,
        s4,
        f.names("family", false),
        f.names("family", true),
        a1,
        a2,
        a3,
        a4,
    ))
}

/// One detection of an alert.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPoint {
    pub id: i64,
    pub alert: Uuid,
    /// The observable it's on. One on a module's analysis is on the observable it analyzed.
    pub observable_id: i64,
    pub observable_type: String,
    pub observable_value: String,
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
}

/// One page of detections, oldest first, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionPointPage {
    pub detections: Vec<DetectionPoint>,
    pub next: Option<i64>,
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
        let alert = filter.alert;
        let changed_since = filter.changed_since;
        let params = &params(filter)?;
        self.gate
            .read(actor, "detection_points", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let (s1, s2, s3, s4, family, not_family, a1, a2, a3, a4) = params;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    if let Some(alert) = alert {
                        known_alert(tx, alert).await?;
                    }
                    let mut detections: Vec<DetectionPoint> = sqlx::query!(
                        r#"SELECT d.id, d.root_id, d.observable_id, o.type, o.value,
                                  res.module AS "module?", d.description, d.details, d.queue,
                                  d.signature_uuid, d.signature_version, d.signature_family,
                                  d.created_at
                           FROM analysis.detections d
                           JOIN analysis.roots r ON r.id = d.root_id
                           JOIN analysis.observables o
                             ON o.root_id = d.root_id AND o.id = d.observable_id
                           LEFT JOIN analysis.results res ON res.id = d.result_id
                           WHERE r.alerted_at IS NOT NULL
                             AND ($2::uuid IS NULL OR d.root_id = $2)
                             AND ($3::bigint IS NULL OR d.id > $3)
                             AND ($4::timestamptz IS NULL OR d.created_at >= $4 OR r.alerted_at >= $4)
                             -- Signature: its uuid, and its version when the value has one
                             AND ($5::text[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($5::text[], $6::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             AND ($7::text[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($7::text[], $8::text[]) g(u, v)
                                   WHERE lower(d.signature_uuid) = g.u
                                     AND (g.v = '' OR d.signature_version = g.v)))
                             -- Family
                             AND ($9::text[] IS NULL OR d.signature_family = ANY ($9::text[]))
                             AND ($10::text[] IS NULL
                                  OR NOT COALESCE(d.signature_family = ANY ($10::text[]), false))
                             -- Alert Date: when its root became an alert
                             AND ($11::timestamptz[] IS NULL OR EXISTS (
                                   SELECT FROM unnest($11::timestamptz[], $12::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                             AND ($13::timestamptz[] IS NULL OR NOT EXISTS (
                                   SELECT FROM unnest($13::timestamptz[], $14::timestamptz[]) w(s, e)
                                   WHERE r.alerted_at BETWEEN w.s AND w.e))
                           ORDER BY d.id
                           LIMIT $1"#,
                        limit + 1,
                        alert,
                        after,
                        changed_since,
                        s1.as_deref(),
                        s2.as_deref(),
                        s3.as_deref(),
                        s4.as_deref(),
                        family.as_deref(),
                        not_family.as_deref(),
                        a1.as_deref(),
                        a2.as_deref(),
                        a3.as_deref(),
                        a4.as_deref(),
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?
                    .into_iter()
                    .map(|row| DetectionPoint {
                        id: row.id,
                        alert: row.root_id,
                        observable_id: row.observable_id,
                        observable_type: row.r#type,
                        observable_value: row.value,
                        module: row.module,
                        description: row.description,
                        details: row.details,
                        queue: row.queue,
                        signature_uuid: row.signature_uuid,
                        signature_version: row.signature_version,
                        signature_family: row.signature_family,
                        created_at: row.created_at,
                    })
                    .collect();
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
        let params = &params(filter)?;
        self.gate
            .read(actor, "detection_point_count", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let (s1, s2, s3, s4, family, not_family, a1, a2, a3, a4) = params;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    if let Some(alert) = alert {
                        known_alert(tx, alert).await?;
                    }
                    sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM (
                           SELECT FROM analysis.detections d
                           JOIN analysis.roots r ON r.id = d.root_id
                           WHERE r.alerted_at IS NOT NULL
                             AND ($2::uuid IS NULL OR d.root_id = $2)
                             AND ($3::timestamptz IS NULL OR d.created_at >= $3 OR r.alerted_at >= $3)
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
                           LIMIT $1) counted"#,
                        cap.saturating_add(1),
                        alert,
                        changed_since,
                        s1.as_deref(),
                        s2.as_deref(),
                        s3.as_deref(),
                        s4.as_deref(),
                        family.as_deref(),
                        not_family.as_deref(),
                        a1.as_deref(),
                        a2.as_deref(),
                        a3.as_deref(),
                        a4.as_deref(),
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
