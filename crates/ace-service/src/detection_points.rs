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
//! that commits after a page past its id was read, and one whose root becomes an alert after that. ace3's
//! `changed_since` is how a puller catches those, and it comes with the filters.
//!
//! What later steps add here, and where:
//! - 5.10: ace3's filters (signature, family, alert date, queue, verdict, source, has_override) and
//!   `changed_since`, in the manage page's filter language, join `DetectionPointFilter`. Its NDJSON and CSV
//!   exports page through `Service::detection_points` with the same filter to the end.
//! - 7.14: each detection's effective verdict, its source and the stored override join `DetectionPoint`,
//!   and the verdict writes and the alert's confirm become writes here. ace3 keys a verdict on a content
//!   hash of the detection's node, signature, description and details; 7.14 decides whether ace4 keys it
//!   on that or on the row's id, which re-analysis doesn't keep.
//!
//! A detection's description and details are what a module, a rule's meta or a submission wrote, so they
//! are data: nothing here reads them, and the adapters return them as they are.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::{no_alert, page_limit};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most detections one page holds, as ace3's listing.
pub const MAX_DETECTIONS_PAGE: u32 = 1000;

/// Which detections to list. Every filter that's set must match. 5.10's filters join it.
#[derive(Debug, Clone, Default)]
pub struct DetectionPointFilter {
    /// Only this alert's, as ace3's `/alerts/{uuid}/detection-points` lists them.
    pub alert: Option<Uuid>,
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
        self.gate
            .read(actor, "detection_points", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    if let Some(alert) = alert {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM analysis.roots
                                              WHERE id = $1 AND alerted_at IS NOT NULL) AS "known!""#,
                            alert,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(no_alert(alert));
                        }
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
                           ORDER BY d.id
                           LIMIT $1"#,
                        limit + 1,
                        alert,
                        after,
                    )
                    .fetch_all(tx.conn())
                    .await?
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
}
