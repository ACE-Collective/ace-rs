//! SVS's declared-vs-measured worklist (PLAN.md 7.10 batch 8): the refresh, the resolutions and the reads
//! of ace3's `saq/svs/worklist.py`, `worklist_filters.py` and `aceapi_v2/svs/worklist/service.py`, over
//! `ace_core::svs::worklist`, which derives.
//!
//! One row of `svs.technique_worklist` per (signature, ATT&CK technique) for each measured signature: its
//! `mitre:` tags, confirmed or not by the tests it is expected of, and the techniques it is measured on
//! that no tag names. Everything but the resolution is derived by the coverage refresh ([`refresh_in`],
//! which `svs_coverage` runs under the refresh lock, before it computes coverage).
//!
//! **Reading** needs `svs:run_read`: the rows by signature, then technique, a page at a time with the
//! worklist screen's filters, and one signature's rows with what it is measured on now.
//!
//! **Resolving** needs `svs:run_manage`, as in ace3: [`Service::resolve_svs_worklist_row`] decides *keep*
//! or *remove* for a declared tag measurement doesn't confirm, [`Service::reopen_svs_worklist_row`] clears
//! the decision, and [`Service::resolve_svs_worklist_rows`] resolves up to [`MAX_BULK_ROWS`] alike. Each
//! takes the refresh lock first, so it never commits in the middle of a refresh, and each row changed has
//! its audit row. A remove stops the tag counting toward coverage from the next refresh; the row's own
//! `counts` says so at once.
//!
//! How it scales: the table holds a row per measured signature and technique and never loses one, so the
//! expectations ever made bound it. The refresh reads all of it once and writes only the rows that differ,
//! in one statement. The list pages by keyset along an index, a signature's rows are its own, and what a
//! signature is measured on now is judged over the tests that expect it alone.
//!
//! What differs from ace3's:
//! - A resolution records the actor that made it (`resolved_by`), as a decision does (`svs_decisions`),
//!   where ace3 keeps a user id and refuses a config key; the Resolved By filter matches the name the
//!   resolver had.
//! - A bulk resolution is a transaction per row, each under the lock, where ace3's is one transaction: a
//!   row that can't be resolved is reported and left alone either way.
//! - A reference is refused when it holds white space or a control character, since the pages link to it.
//! - `declared_as` and `measured_techniques` are arrays, where ace3 stores JSON text.

use std::collections::BTreeMap;

use ace_core::svs::attack::AttackCatalog;
use ace_core::svs::coverage::{self, CoverageTest, Measured};
use ace_core::svs::results::Precondition;
use ace_core::svs::signatures::{
    KnownSignature, SignatureTags, builtin_signatures, describe_signatures,
};
use ace_core::svs::windows::HuntInfo;
use ace_core::svs::worklist::{
    self, KnownSignatures, PlannedRow, RESOLVABLE, Resolved as StoredResolution, StoredRow,
    WorklistKind, WorklistResolution, WorklistStatus,
};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::alerts::{RecordedActor, page_limit};
use crate::filters::{FilterEntry, FilterScreen, Resolved};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_RUN_MANAGE, SVS_RUN_READ};
use crate::svs_coverage::{Excluded, lock_refresh, same_order};
use crate::svs_test_state::{StateTest, evaluate_tests};
use crate::{Actor, Service, ServiceError};

/// The most worklist rows one page holds.
pub const MAX_WORKLIST_PAGE: u32 = 1000;
/// The most rows one bulk resolution takes: ace3's `BulkResolutionRequest.rows`.
pub const MAX_BULK_ROWS: usize = 500;

/// One signature's tag on, or measurement of, one ATT&CK technique, as of the last coverage refresh (the
/// resolution as of now): a row of `svs.technique_worklist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistRow {
    pub signature_uuid: String,
    /// The technique in the pinned ATT&CK release (a revoked tag id counts as its successor).
    pub technique: String,
    /// Its name in the pinned release.
    pub technique_name: Option<String>,
    pub kind: WorklistKind,
    pub status: WorklistStatus,
    /// The tag ids, as the signature writes them, that count as the technique.
    pub declared_as: Vec<String>,
    /// The signature has the tag now.
    pub tag_present: bool,
    /// The signature is enabled, and isn't a YARA rule in QA mode.
    pub signature_counts: bool,
    /// The tag counts toward coverage as a manual mapping (from the next refresh, after a resolution).
    pub counts: bool,
    /// The signature is expected of a catalog test.
    pub measured: bool,
    pub measured_techniques: Vec<String>,
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    pub resolution: Option<WorklistResolution>,
    pub reason: Option<String>,
    /// A link, such as the pull request removing the tag.
    pub reference: Option<String>,
    pub resolved_by: Option<RecordedActor>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
    pub status_changed_at: DateTime<Utc>,
    /// When the row last changed: the `changed_since` key, and a write's `If-Match`.
    pub updated_at: DateTime<Utc>,
}

/// Which worklist rows to list.
#[derive(Debug, Clone)]
pub struct WorklistQuery {
    pub filters: Vec<FilterEntry>,
    pub changed_since: Option<DateTime<Utc>>,
    pub tz: Tz,
}

impl Default for WorklistQuery {
    fn default() -> Self {
        WorklistQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistPage {
    pub rows: Vec<WorklistRow>,
    pub next_cursor: Option<String>,
}

/// A catalog test, on a platform, that a signature is expected of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredTest {
    pub guid: Uuid,
    pub name: Option<String>,
    pub platform: String,
}

/// A technique a signature is measured on now, with the tests that measure it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredTechnique {
    pub technique: String,
    pub technique_name: Option<String>,
    pub tests: Vec<MeasuredTest>,
}

/// A signature's worklist rows, and what it is measured on now: ace3's `SignatureWorklist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureWorklist {
    pub signature_uuid: String,
    /// The family and name as the latest refresh knew them.
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    /// Every row of the signature, retired ones included.
    pub rows: Vec<WorklistRow>,
    /// Computed at the request.
    pub measured: Vec<MeasuredTechnique>,
}

/// What a bulk resolution did to each row it was given: ace3's `BulkResolution`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkResolution {
    /// The rows resolved, as (signature, technique).
    pub done: Vec<(String, String)>,
    /// Rows that are confirmed, informational, retired or removed, with their status; left alone.
    pub conflicts: Vec<(String, String, WorklistStatus)>,
    /// Rows that don't exist.
    pub unknown: Vec<(String, String)>,
}

/// What a coverage refresh did to the worklist: ace3's `WorklistRefresh`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorklistRefresh {
    /// Rows that aren't retired.
    pub rows: usize,
    pub changed: usize,
    pub inserted: usize,
    /// (signature_uuid, technique, from_status, to_status) of each stored row whose status changed.
    pub transitions: Vec<(String, String, String, String)>,
    /// (signature_uuid, technique, resolution) the refresh cleared: the tag came back after a remove.
    pub cleared: Vec<(String, String, String)>,
    /// (signature_uuid, from_technique, to_technique, resolution) moved after an ATT&CK upgrade.
    pub moved: Vec<(String, String, String, String)>,
    /// It wrote a row.
    pub wrote: bool,
}

struct Row {
    id: i64,
    signature_uuid: String,
    technique: String,
    kind: String,
    status: String,
    declared_as: Vec<String>,
    tag_present: bool,
    signature_counts: bool,
    counts: bool,
    measured: bool,
    measured_techniques: Vec<String>,
    signature_family: Option<String>,
    signature_name: Option<String>,
    resolution: Option<String>,
    reason: Option<String>,
    reference: Option<String>,
    resolved_by: Option<Value>,
    resolved_at: Option<DateTime<Utc>>,
    first_seen_at: DateTime<Utc>,
    status_changed_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn decoded<T>(what: &str, value: Option<T>) -> Result<T, ServiceError> {
    value.ok_or_else(|| ServiceError::from(ace_core::DbError::Decode(format!("a stored {what}"))))
}

impl Row {
    fn kind(&self) -> Result<WorklistKind, ServiceError> {
        decoded("worklist kind", WorklistKind::parse(&self.kind))
    }

    fn status(&self) -> Result<WorklistStatus, ServiceError> {
        decoded("worklist status", WorklistStatus::parse(&self.status))
    }

    fn resolution(&self) -> Result<Option<WorklistResolution>, ServiceError> {
        self.resolution
            .as_deref()
            .map(|text| decoded("worklist resolution", WorklistResolution::parse(text)))
            .transpose()
    }

    fn stored(&self) -> Result<StoredRow, ServiceError> {
        Ok(StoredRow {
            kind: self.kind()?,
            status: self.status()?,
            declared_as: self.declared_as.clone(),
            tag_present: self.tag_present,
            signature_counts: self.signature_counts,
            counts: self.counts,
            measured: self.measured,
            measured_techniques: self.measured_techniques.clone(),
            signature_family: self.signature_family.clone(),
            signature_name: self.signature_name.clone(),
            resolved: match (self.resolution()?, self.resolved_at) {
                (Some(resolution), Some(resolved_at)) => Some(StoredResolution {
                    resolution,
                    reason: self.reason.clone(),
                    reference: self.reference.clone(),
                    resolved_by: self.resolved_by.clone(),
                    resolved_at,
                }),
                _ => None,
            },
        })
    }

    fn row(self, catalog: &AttackCatalog) -> Result<WorklistRow, ServiceError> {
        Ok(WorklistRow {
            kind: self.kind()?,
            status: self.status()?,
            resolution: self.resolution()?,
            technique_name: catalog
                .technique(&self.technique)
                .map(|known| known.name.clone()),
            signature_uuid: self.signature_uuid,
            technique: self.technique,
            declared_as: self.declared_as,
            tag_present: self.tag_present,
            signature_counts: self.signature_counts,
            counts: self.counts,
            measured: self.measured,
            measured_techniques: self.measured_techniques,
            signature_family: self.signature_family,
            signature_name: self.signature_name,
            reason: self.reason,
            reference: self.reference,
            resolved_by: RecordedActor::from_row(self.resolved_by)?,
            resolved_at: self.resolved_at,
            first_seen_at: self.first_seen_at,
            status_changed_at: self.status_changed_at,
            updated_at: self.updated_at,
        })
    }
}

/// `{uuid: (family, name)}` of signatures without tags: as ACE knows them now, else as their expectations
/// recorded them. ace3's `_known_signatures`.
async fn known_signatures(
    conn: &mut PgConnection,
    uuids: Vec<&str>,
    hunts: &BTreeMap<String, HuntInfo>,
    yara: &[KnownSignature],
) -> Result<KnownSignatures, ServiceError> {
    let mut known: KnownSignatures =
        describe_signatures(uuids.iter().copied(), &builtin_signatures(), hunts, yara)
            .into_iter()
            .map(|(uuid, info)| (uuid, (info.family, info.name)))
            .collect();
    let remaining: Vec<String> = uuids
        .into_iter()
        .filter(|uuid| !known.contains_key(*uuid))
        .map(str::to_owned)
        .collect();
    if !remaining.is_empty() {
        for row in sqlx::query!(
            "SELECT DISTINCT ON (signature_uuid) signature_uuid, signature_family, signature_name
             FROM svs.expectations WHERE signature_uuid = ANY ($1)
             ORDER BY signature_uuid, decided_at DESC, id DESC",
            &remaining,
        )
        .fetch_all(conn)
        .await?
        {
            known.insert(
                row.signature_uuid,
                (row.signature_family, row.signature_name),
            );
        }
    }
    Ok(known)
}

fn planned_json(planned: &PlannedRow) -> Value {
    let row = &planned.row;
    let resolved = row.resolved.as_ref();
    json!({
        "signature_uuid": planned.signature_uuid,
        "technique": planned.technique,
        "kind": row.kind.as_str(),
        "status": row.status.as_str(),
        "declared_as": row.declared_as,
        "tag_present": row.tag_present,
        "signature_counts": row.signature_counts,
        "counts": row.counts,
        "measured": row.measured,
        "measured_techniques": row.measured_techniques,
        "signature_family": row.signature_family,
        "signature_name": row.signature_name,
        "resolution": resolved.map(|r| r.resolution.as_str()),
        "reason": resolved.and_then(|r| r.reason.as_deref()),
        "reference": resolved.and_then(|r| r.reference.as_deref()),
        "resolved_by": resolved.and_then(|r| r.resolved_by.as_ref()),
        "resolved_at": resolved.map(|r| r.resolved_at),
    })
}

/// Recomputes `svs.technique_worklist` in the caller's transaction, which holds the refresh lock, and
/// writes only the rows that changed: ace3's `refresh_worklist`. Returns what it did, for the caller to
/// log once committed ([`log_refresh`]), and the tags that don't count because they are resolved remove.
pub(crate) async fn refresh_in(
    conn: &mut PgConnection,
    catalog: &AttackCatalog,
    tags: &BTreeMap<String, SignatureTags>,
    measured: &Measured,
    hunts: &BTreeMap<String, HuntInfo>,
    yara: &[KnownSignature],
    now: DateTime<Utc>,
) -> Result<(WorklistRefresh, Excluded), ServiceError> {
    let untagged: Vec<&str> = measured
        .keys()
        .filter(|uuid| !tags.contains_key(*uuid))
        .map(String::as_str)
        .collect();
    let known = known_signatures(&mut *conn, untagged, hunts, yara).await?;
    let computed = worklist::compute_worklist(catalog, tags, measured, &known);
    let mut stored = BTreeMap::new();
    for row in sqlx::query_as!(
        Row,
        r#"SELECT id, signature_uuid, technique, kind, status, declared_as, tag_present,
                  signature_counts, counts, measured, measured_techniques, signature_family,
                  signature_name, resolution, reason, reference,
                  resolved_by AS "resolved_by: Value", resolved_at, first_seen_at, status_changed_at,
                  updated_at
           FROM svs.technique_worklist"#
    )
    .fetch_all(&mut *conn)
    .await?
    {
        stored.insert(
            (row.signature_uuid.clone(), row.technique.clone()),
            row.stored()?,
        );
    }
    let plan = worklist::plan_refresh(catalog, tags, measured, &computed, &stored);

    let rows: Vec<Value> = plan
        .written
        .iter()
        .filter(|planned| planned.write)
        .map(planned_json)
        .collect();
    let wrote = !rows.is_empty();
    if wrote {
        sqlx::query!(
            "INSERT INTO svs.technique_worklist
                 (signature_uuid, technique, kind, status, declared_as, tag_present, signature_counts,
                  counts, measured, measured_techniques, signature_family, signature_name, resolution,
                  reason, reference, resolved_by, resolved_at, first_seen_at, status_changed_at)
             SELECT u.signature_uuid, u.technique, u.kind, u.status, u.declared_as, u.tag_present,
                    u.signature_counts, u.counts, u.measured, u.measured_techniques,
                    u.signature_family, u.signature_name, u.resolution, u.reason, u.reference,
                    u.resolved_by, u.resolved_at, $2, $2
             FROM jsonb_to_recordset($1) AS u (
                 signature_uuid text, technique text, kind text, status text, declared_as text[],
                 tag_present boolean, signature_counts boolean, counts boolean, measured boolean,
                 measured_techniques text[], signature_family text, signature_name text,
                 resolution text, reason text, reference text, resolved_by jsonb,
                 resolved_at timestamptz)
             ON CONFLICT (signature_uuid, technique) DO UPDATE SET
                 kind = EXCLUDED.kind, declared_as = EXCLUDED.declared_as,
                 tag_present = EXCLUDED.tag_present, signature_counts = EXCLUDED.signature_counts,
                 counts = EXCLUDED.counts, measured = EXCLUDED.measured,
                 measured_techniques = EXCLUDED.measured_techniques,
                 signature_family = EXCLUDED.signature_family,
                 signature_name = EXCLUDED.signature_name, resolution = EXCLUDED.resolution,
                 reason = EXCLUDED.reason, reference = EXCLUDED.reference,
                 resolved_by = EXCLUDED.resolved_by, resolved_at = EXCLUDED.resolved_at,
                 status_changed_at = CASE WHEN svs.technique_worklist.status <> EXCLUDED.status
                                          THEN EXCLUDED.status_changed_at
                                          ELSE svs.technique_worklist.status_changed_at END,
                 status = EXCLUDED.status",
            Value::Array(rows),
            now,
        )
        .execute(conn)
        .await?;
    }

    Ok((
        WorklistRefresh {
            rows: plan.rows,
            changed: plan.changed,
            inserted: plan.inserted,
            transitions: plan
                .transitions
                .iter()
                .map(|(signature, technique, from, to)| {
                    (
                        signature.clone(),
                        technique.clone(),
                        from.as_str().to_owned(),
                        to.as_str().to_owned(),
                    )
                })
                .collect(),
            cleared: plan
                .cleared
                .iter()
                .map(|(signature, technique, resolution)| {
                    (
                        signature.clone(),
                        technique.clone(),
                        resolution.as_str().to_owned(),
                    )
                })
                .collect(),
            moved: plan
                .moved
                .iter()
                .map(|(signature, from, to, resolution)| {
                    (
                        signature.clone(),
                        from.clone(),
                        to.clone(),
                        resolution.as_str().to_owned(),
                    )
                })
                .collect(),
            wrote,
        },
        plan.excluded,
    ))
}

/// Logs what a committed refresh did to the worklist: ace3's `log_worklist_refresh`.
pub(crate) fn log_refresh(result: &WorklistRefresh, actor: &Actor) {
    for (signature_uuid, from_technique, technique, resolution) in &result.moved {
        tracing::info!(
            signature_uuid,
            technique,
            from_technique,
            resolution,
            %actor,
            "svs worklist resolution {resolution} of signature {signature_uuid} moved from \
             {from_technique} to {technique}"
        );
    }
    for (signature_uuid, technique, resolution) in &result.cleared {
        tracing::info!(
            signature_uuid,
            technique,
            cleared_resolution = resolution,
            %actor,
            "svs worklist resolution {resolution} of signature {signature_uuid} on {technique} cleared: \
             the tag is back"
        );
    }
    for (signature_uuid, technique, from_status, to_status) in &result.transitions {
        tracing::info!(
            signature_uuid,
            technique,
            from_status,
            to_status,
            "svs worklist row of signature {signature_uuid} on {technique}: {from_status} -> {to_status}"
        );
    }
}

/// (signature_uuid, technique) of the tags resolved remove that measurement doesn't confirm: they don't
/// count toward coverage. ace3's `excluded_mappings`.
pub(crate) async fn excluded_mappings(conn: &mut PgConnection) -> Result<Excluded, sqlx::Error> {
    Ok(sqlx::query!(
        "SELECT signature_uuid, technique FROM svs.technique_worklist
         WHERE kind = 'declared' AND resolution = 'remove' AND status <> 'confirmed'"
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| (row.signature_uuid, row.technique))
    .collect())
}

/// The worklist screen's filters as `svs.worklist_matches` reads them (migration 0058): ace3's
/// `worklist_filter_conditions`.
fn worklist_filter(query: &WorklistQuery, now: DateTime<Utc>) -> Result<Value, ServiceError> {
    let f = Resolved::new(FilterScreen::SvsWorklist, &query.filters, now, query.tz)?;
    let mut doc = Map::new();
    let key = |slug: &str, inverted: bool| {
        if inverted {
            format!("not_{slug}")
        } else {
            slug.to_owned()
        }
    };
    for inverted in [false, true] {
        for slug in ["family", "technique", "status", "kind", "resolved_by"] {
            if let Some(values) = f.names(slug, inverted) {
                doc.insert(key(slug, inverted), json!(values));
            }
        }
        // a signature's uuid, or text its name contains
        if let (Some(values), Some(patterns)) = (
            f.names("signature", inverted),
            f.patterns("signature", inverted, false),
        ) {
            doc.insert(key("signature", inverted), json!(values));
            doc.insert(key("signature_like", inverted), json!(patterns));
        }
        if let Some(values) = f.names("resolution", inverted) {
            let named: Vec<&String> = values.iter().filter(|value| *value != "none").collect();
            doc.insert(key("resolution", inverted), json!(named));
            if named.len() != values.len() {
                doc.insert(key("resolution_none", inverted), json!(true));
            }
        }
        if let Some((starts, ends)) = f.windows("resolved", inverted)? {
            let windows: Vec<Value> = starts
                .iter()
                .zip(&ends)
                .map(|(start, end)| json!([start, end]))
                .collect();
            doc.insert(key("resolved", inverted), Value::Array(windows));
        }
    }
    Ok(Value::Object(doc))
}

/// Where a page of worklist rows left off: by (signature_uuid, technique, id), or (updated_at, id) for a
/// changed-since pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorklistCursor {
    /// `signature` or `updated_at`.
    o: String,
    signature: String,
    technique: String,
    at: DateTime<Utc>,
    id: i64,
}

fn encode(cursor: &WorklistCursor) -> String {
    hex::encode(serde_json::to_vec(cursor).unwrap_or_default())
}

fn decode_cursor(text: &str) -> Result<WorklistCursor, ServiceError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))
}

async fn list(
    conn: &mut PgConnection,
    filter: &Value,
    changed_since: Option<DateTime<Utc>>,
    settle: f64,
    after: Option<&WorklistCursor>,
    limit: i64,
) -> Result<Vec<Row>, sqlx::Error> {
    if changed_since.is_some() {
        return sqlx::query_as!(
            Row,
            r#"SELECT id, signature_uuid, technique, kind, status, declared_as, tag_present,
                      signature_counts, counts, measured, measured_techniques, signature_family,
                      signature_name, resolution, reason, reference,
                      resolved_by AS "resolved_by: Value", resolved_at, first_seen_at,
                      status_changed_at, updated_at
               FROM svs.technique_worklist w
               WHERE svs.worklist_matches(w, $1)
                 AND w.updated_at >= $2 AND w.updated_at < now() - make_interval(secs => $3)
                 AND ($4::bigint IS NULL OR (w.updated_at, w.id) > ($5::timestamptz, $4))
               ORDER BY w.updated_at, w.id
               LIMIT $6"#,
            filter,
            changed_since,
            settle,
            after.map(|c| c.id),
            after.map(|c| c.at),
            limit,
        )
        .fetch_all(conn)
        .await;
    }
    sqlx::query_as!(
        Row,
        r#"SELECT id, signature_uuid, technique, kind, status, declared_as, tag_present,
                  signature_counts, counts, measured, measured_techniques, signature_family,
                  signature_name, resolution, reason, reference,
                  resolved_by AS "resolved_by: Value", resolved_at, first_seen_at, status_changed_at,
                  updated_at
           FROM svs.technique_worklist w
           WHERE svs.worklist_matches(w, $1)
             AND ($2::bigint IS NULL
                  OR (w.signature_uuid COLLATE "C", w.technique COLLATE "C", w.id)
                     > ($3::text, $4::text, $2))
           ORDER BY w.signature_uuid COLLATE "C", w.technique COLLATE "C", w.id
           LIMIT $5"#,
        filter,
        after.map(|c| c.id),
        after.map(|c| c.signature.as_str()),
        after.map(|c| c.technique.as_str()),
        limit,
    )
    .fetch_all(conn)
    .await
}

/// The row of a signature on a technique, locked for the caller's write: ace3's `_row`.
async fn locked_row(
    conn: &mut PgConnection,
    signature_uuid: &str,
    technique: &str,
) -> Result<Option<Row>, sqlx::Error> {
    sqlx::query_as!(
        Row,
        r#"SELECT id, signature_uuid, technique, kind, status, declared_as, tag_present,
                  signature_counts, counts, measured, measured_techniques, signature_family,
                  signature_name, resolution, reason, reference,
                  resolved_by AS "resolved_by: Value", resolved_at, first_seen_at, status_changed_at,
                  updated_at
           FROM svs.technique_worklist
           WHERE signature_uuid = $1 AND technique = $2 FOR UPDATE"#,
        signature_uuid,
        technique,
    )
    .fetch_optional(conn)
    .await
}

/// What a resolution's audit row keeps of a row: ace3's AUDIT line's fields.
#[derive(Serialize)]
struct ResolutionRecord<'a> {
    resolution: Option<&'a str>,
    reason: Option<&'a str>,
    reference: Option<&'a str>,
    status: &'a str,
    counts: bool,
}

impl Recorded for ResolutionRecord<'_> {}

impl<'a> ResolutionRecord<'a> {
    fn of(row: &'a Row) -> Self {
        ResolutionRecord {
            resolution: row.resolution.as_deref(),
            reason: row.reason.as_deref(),
            reference: row.reference.as_deref(),
            status: &row.status,
            counts: row.counts,
        }
    }
}

fn row_target(signature_uuid: &str, technique: &str) -> Target {
    Target::svs_worklist_row(&format!("{signature_uuid}/{technique}"))
}

fn no_row(signature_uuid: &str, technique: &str) -> ServiceError {
    ServiceError::NotFound(format!(
        "no worklist row for signature {signature_uuid} on {technique}"
    ))
}

/// The technique a write names, as the rows have it: ace3's `technique.strip().upper()`.
fn technique_of(technique: &str) -> String {
    technique.trim().to_uppercase()
}

/// Why one row of a write can't be resolved.
enum Refused {
    Unknown,
    Conflict(WorklistStatus),
    Other(ServiceError),
}

impl From<ServiceError> for Refused {
    fn from(error: ServiceError) -> Self {
        Refused::Other(error)
    }
}

impl From<sqlx::Error> for Refused {
    fn from(error: sqlx::Error) -> Self {
        Refused::Other(error.into())
    }
}

fn conflict(signature_uuid: &str, technique: &str, status: WorklistStatus) -> ServiceError {
    ServiceError::Conflict(format!(
        "the worklist row of signature {signature_uuid} on {technique} is {status}; only {} rows can \
         be resolved",
        RESOLVABLE
            .iter()
            .map(|status| status.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// One row's resolution, in the caller's transaction, which holds the refresh lock: ace3's `_row`,
/// `precondition.check` and `_resolve_row`. Returns the row as written and its audit change.
#[allow(clippy::too_many_arguments)]
async fn resolve_in(
    conn: &mut PgConnection,
    actor: &Actor,
    signature_uuid: &str,
    technique: &str,
    resolution: WorklistResolution,
    reason: &str,
    reference: Option<&str>,
    precondition: Precondition,
    now: DateTime<Utc>,
) -> Result<(Row, Change), Refused> {
    let Some(before) = locked_row(&mut *conn, signature_uuid, technique).await? else {
        return Err(Refused::Unknown);
    };
    if let Some(why) = precondition.refuses(
        Some(before.updated_at),
        &format!("the worklist row of {technique}"),
    ) {
        return Err(ServiceError::StaleWrite(why).into());
    }
    let status = before.status()?;
    if !RESOLVABLE.contains(&status) {
        return Err(Refused::Conflict(status));
    }
    let (new_status, counts) = worklist::rederive(
        before.kind()?,
        status,
        before.tag_present,
        before.signature_counts,
        before.counts,
        Some(resolution),
    );
    let after = sqlx::query_as!(
        Row,
        r#"UPDATE svs.technique_worklist
           SET resolution = $2, reason = $3, reference = $4, resolved_by = $5::jsonb,
               resolved_at = $6, status = $7, counts = $8,
               status_changed_at = CASE WHEN status <> $7 THEN $6 ELSE status_changed_at END
           WHERE id = $1
           RETURNING id, signature_uuid, technique, kind, status, declared_as, tag_present,
                     signature_counts, counts, measured, measured_techniques, signature_family,
                     signature_name, resolution, reason, reference,
                     resolved_by AS "resolved_by: Value", resolved_at, first_seen_at,
                     status_changed_at, updated_at"#,
        before.id,
        resolution.as_str(),
        reason,
        reference,
        Json(actor) as _,
        now,
        new_status.as_str(),
        counts,
    )
    .fetch_one(conn)
    .await?;
    let change = Change::updated(
        row_target(signature_uuid, technique),
        &ResolutionRecord::of(&before),
        &ResolutionRecord::of(&after),
    )?;
    Ok((after, change))
}

impl Service {
    /// A page of the worklist rows by signature, then technique, after where `cursor` left off: ace3's
    /// worklist listing. It needs `svs:run_read`.
    pub async fn svs_worklist(
        &self,
        actor: &Actor,
        query: &WorklistQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<WorklistPage, ServiceError> {
        let limit = page_limit(limit, MAX_WORKLIST_PAGE)?;
        let changed = query.changed_since.is_some();
        let after = cursor.map(decode_cursor).transpose()?;
        if let Some(after) = &after {
            same_order(&after.o, changed, "signature")?;
        }
        let after = &after;
        let filter = &worklist_filter(query, Utc::now())?;
        let catalog = &self.attack_catalog()?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_worklist", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = list(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        after.as_ref(),
                        limit + 1,
                    )
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&WorklistCursor {
                                o: if changed { "updated_at" } else { "signature" }.to_owned(),
                                signature: last.signature_uuid.clone(),
                                technique: last.technique.clone(),
                                at: last.updated_at,
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    Ok(WorklistPage {
                        rows: rows
                            .into_iter()
                            .map(|row| row.row(catalog))
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// How many worklist rows `query` matches, counting up to `max` + 1, for an export. It needs
    /// `svs:run_read`.
    pub async fn svs_worklist_count(
        &self,
        actor: &Actor,
        query: &WorklistQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let filter = &worklist_filter(query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_worklist_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let rows = list(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        None,
                        max.saturating_add(1),
                    )
                    .await?;
                    Ok(rows.len() as i64)
                })
            })
            .await
    }

    /// A signature's rows, retired ones included, and what it is measured on now: ace3's `get_signature`.
    /// One with no rows is `NotFound`. It needs `svs:run_read`.
    pub async fn svs_worklist_signature(
        &self,
        actor: &Actor,
        signature_uuid: &str,
    ) -> Result<SignatureWorklist, ServiceError> {
        let catalog = &self.attack_catalog()?;
        self.gate
            .read(actor, "svs_worklist_signature", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let rows = sqlx::query_as!(
                        Row,
                        r#"SELECT id, signature_uuid, technique, kind, status, declared_as, tag_present,
                                  signature_counts, counts, measured, measured_techniques,
                                  signature_family, signature_name, resolution, reason, reference,
                                  resolved_by AS "resolved_by: Value", resolved_at, first_seen_at,
                                  status_changed_at, updated_at
                           FROM svs.technique_worklist
                           WHERE signature_uuid = $1
                           ORDER BY technique COLLATE "C", id"#,
                        signature_uuid,
                    )
                    .fetch_all(&mut *conn)
                    .await?;
                    // the family and name as the latest refresh knew them
                    let Some(latest) = rows.iter().max_by_key(|row| row.updated_at) else {
                        return Err(ServiceError::NotFound(format!(
                            "signature {signature_uuid} has no worklist rows"
                        )));
                    };
                    let (signature_family, signature_name) =
                        (latest.signature_family.clone(), latest.signature_name.clone());

                    // what it is measured on now: the tests that expect it, ignores applied
                    let tests = sqlx::query!(
                        "SELECT guid, name, technique, technique_name, platforms, content_hash
                         FROM svs.catalog_tests t
                         WHERE t.removed_at IS NULL
                           AND EXISTS (SELECT FROM svs.expectations e
                                       WHERE e.test_guid = t.guid AND e.signature_uuid = $1
                                         AND e.state = 'expected')",
                        signature_uuid,
                    )
                    .fetch_all(&mut *conn)
                    .await?;
                    let names: BTreeMap<Uuid, String> = tests
                        .iter()
                        .map(|test| (test.guid, test.name.clone()))
                        .collect();
                    let state_tests: Vec<StateTest> = tests
                        .iter()
                        .map(|test| StateTest {
                            guid: test.guid,
                            content_hash: test.content_hash.clone(),
                            platforms: test.platforms.clone(),
                        })
                        .collect();
                    let coverage_tests: Vec<CoverageTest> = tests
                        .into_iter()
                        .map(|test| CoverageTest {
                            guid: test.guid,
                            technique: test.technique,
                            technique_name: test.technique_name,
                            platforms: test.platforms,
                        })
                        .collect();
                    let evaluations = evaluate_tests(conn, &state_tests).await?;
                    let measured =
                        coverage::measured_by_signature(catalog, &coverage_tests, &evaluations)
                            .remove(signature_uuid)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|(technique, pairs)| MeasuredTechnique {
                                technique_name: catalog
                                    .technique(&technique)
                                    .map(|known| known.name.clone()),
                                technique,
                                tests: pairs
                                    .into_iter()
                                    .map(|(guid, platform)| MeasuredTest {
                                        guid,
                                        name: names.get(&guid).cloned(),
                                        platform,
                                    })
                                    .collect(),
                            })
                            .collect();
                    Ok(SignatureWorklist {
                        signature_uuid: signature_uuid.to_owned(),
                        signature_family,
                        signature_name,
                        rows: rows
                            .into_iter()
                            .map(|row| row.row(catalog))
                            .collect::<Result<_, _>>()?,
                        measured,
                    })
                })
            })
            .await
    }

    /// Resolves a declared tag measurement doesn't confirm: keep it, or remove it. A remove stops the tag
    /// counting toward coverage from the next refresh. ace3's `resolve`. An unknown row is `NotFound`; one
    /// that is confirmed, informational, retired or removed `Conflict`; a resolution, reason or reference
    /// that can't be used `InvalidRequest`; a precondition that no longer holds `StaleWrite`. It needs
    /// `svs:run_manage`, and records the resolution.
    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_svs_worklist_row(
        &self,
        actor: &Actor,
        signature_uuid: &str,
        technique: &str,
        resolution: &str,
        reason: Option<&str>,
        reference: Option<&str>,
        precondition: Precondition,
        now: DateTime<Utc>,
    ) -> Result<WorklistRow, ServiceError> {
        let (resolution, reason, reference) =
            worklist::check_resolution(resolution, reason, reference)
                .map_err(ServiceError::InvalidRequest)?;
        let (reason, reference) = (reason.as_str(), reference.as_deref());
        let technique = &technique_of(technique);
        let catalog = &self.attack_catalog()?;
        self.gate
            .write(actor, "resolve_svs_worklist_row", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    lock_refresh(tx.conn()).await?;
                    let resolved = resolve_in(
                        tx.conn(),
                        actor,
                        signature_uuid,
                        technique,
                        resolution,
                        reason,
                        reference,
                        precondition,
                        now,
                    )
                    .await;
                    match resolved {
                        Ok((row, change)) => Ok(Audited::changed(row.row(catalog)?, change)),
                        Err(Refused::Unknown) => Err(no_row(signature_uuid, technique)),
                        Err(Refused::Conflict(status)) => {
                            Err(conflict(signature_uuid, technique, status))
                        }
                        Err(Refused::Other(error)) => Err(error),
                    }
                })
            })
            .await
    }

    /// Resolves each of `keys`, (signature, technique) pairs, alike, each under the refresh lock; a row
    /// that doesn't exist or can't be resolved is reported and left alone. ace3's `resolve_many`. A
    /// resolution, reason or reference that can't be used, or more than [`MAX_BULK_ROWS`] rows or none, is
    /// `InvalidRequest`. It needs `svs:run_manage`, and records each row it resolved.
    pub async fn resolve_svs_worklist_rows(
        &self,
        actor: &Actor,
        keys: &[(String, String)],
        resolution: &str,
        reason: Option<&str>,
        reference: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<BulkResolution, ServiceError> {
        let (resolution, reason, reference) =
            worklist::check_resolution(resolution, reason, reference)
                .map_err(ServiceError::InvalidRequest)?;
        if keys.is_empty() || keys.len() > MAX_BULK_ROWS {
            return Err(ServiceError::InvalidRequest(format!(
                "a bulk resolution takes from 1 to {MAX_BULK_ROWS} rows"
            )));
        }
        let (reason, reference) = (reason.as_str(), reference.as_deref());
        // once each, in the order given
        let mut seen = std::collections::BTreeSet::new();
        let mut result = BulkResolution::default();
        for (signature_uuid, technique) in keys {
            if !seen.insert((signature_uuid.as_str(), technique.as_str())) {
                continue;
            }
            let (signature_uuid, technique) = (signature_uuid.as_str(), technique.as_str());
            let normalized = &technique_of(technique);
            let outcome = self
                .gate
                .write(actor, "resolve_svs_worklist_rows", &SVS_RUN_MANAGE, &|tx| {
                    Box::pin(async move {
                        lock_refresh(tx.conn()).await?;
                        let resolved = resolve_in(
                            tx.conn(),
                            actor,
                            signature_uuid,
                            normalized,
                            resolution,
                            reason,
                            reference,
                            Precondition::None,
                            now,
                        )
                        .await;
                        match resolved {
                            Ok((row, change)) => Ok(Audited::changed(
                                Ok((row.signature_uuid, row.technique)),
                                change,
                            )),
                            Err(Refused::Other(error)) => Err(error),
                            Err(refused) => Ok(Audited::unchanged(Err(refused))),
                        }
                    })
                })
                .await?;
            match outcome {
                Ok(key) => result.done.push(key),
                Err(Refused::Conflict(status)) => {
                    result
                        .conflicts
                        .push((signature_uuid.to_owned(), technique.to_owned(), status))
                }
                Err(_) => result
                    .unknown
                    .push((signature_uuid.to_owned(), technique.to_owned())),
            }
        }
        Ok(result)
    }

    /// Clears a row's resolution: an unconfirmed tag is open again and counts from the next refresh.
    /// ace3's `reopen`. A row that doesn't exist, or has no resolution, is `NotFound`; a precondition that
    /// no longer holds `StaleWrite`. It needs `svs:run_manage`, and records what it cleared.
    pub async fn reopen_svs_worklist_row(
        &self,
        actor: &Actor,
        signature_uuid: &str,
        technique: &str,
        precondition: Precondition,
        now: DateTime<Utc>,
    ) -> Result<WorklistRow, ServiceError> {
        let technique = &technique_of(technique);
        let catalog = &self.attack_catalog()?;
        self.gate
            .write(actor, "reopen_svs_worklist_row", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    lock_refresh(tx.conn()).await?;
                    let Some(before) =
                        locked_row(tx.conn(), signature_uuid, technique).await?
                    else {
                        return Err(no_row(signature_uuid, technique));
                    };
                    let what = format!("the worklist row of {technique}");
                    if let Some(why) = precondition.refuses(Some(before.updated_at), &what) {
                        return Err(ServiceError::StaleWrite(why));
                    }
                    if before.resolution.is_none() {
                        return Err(ServiceError::NotFound(format!(
                            "the worklist row of signature {signature_uuid} on {technique} has no \
                             resolution"
                        )));
                    }
                    let (status, counts) = worklist::rederive(
                        before.kind()?,
                        before.status()?,
                        before.tag_present,
                        before.signature_counts,
                        before.counts,
                        None,
                    );
                    let after = sqlx::query_as!(
                        Row,
                        r#"UPDATE svs.technique_worklist
                           SET resolution = NULL, reason = NULL, reference = NULL, resolved_by = NULL,
                               resolved_at = NULL, status = $2, counts = $3,
                               status_changed_at = CASE WHEN status <> $2 THEN $4
                                                        ELSE status_changed_at END
                           WHERE id = $1
                           RETURNING id, signature_uuid, technique, kind, status, declared_as,
                                     tag_present, signature_counts, counts, measured,
                                     measured_techniques, signature_family, signature_name, resolution,
                                     reason, reference, resolved_by AS "resolved_by: Value",
                                     resolved_at, first_seen_at, status_changed_at, updated_at"#,
                        before.id,
                        status.as_str(),
                        counts,
                        now,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let change = Change::updated(
                        row_target(signature_uuid, technique),
                        &ResolutionRecord::of(&before),
                        &ResolutionRecord::of(&after),
                    )?;
                    Ok(Audited::changed(after.row(catalog)?, change))
                })
            })
            .await
    }
}
