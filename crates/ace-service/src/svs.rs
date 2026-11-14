//! SVS's service side (PLAN.md 7.10 batch 1): ace3's `saq/svs/hosts.py` writes and reads, and
//! `saq/svs/alert_status.py`. The model is `ace_core::svs`.
//!
//! **Test hosts.** `svs:admin` adds, changes and removes them, each with an audit row holding the host's
//! fields, where ace3 logs an AUDIT line with them; `svs:run_read` reads them, as ace3's `test-hosts`
//! router does. A short name is one host: a second host of that name in another domain is a `Conflict`, as
//! ace3's `DuplicateTestHost` is. Removing a host ends its open maintenance window (`svs_runs`); a run keeps
//! the targets it was registered with. A change may carry ace3's `If-Match` precondition (`ace_core::svs::results::Precondition`): a host changed since the form was loaded is `StaleWrite`. The list pages by name, with `changed_since` (`test_hosts_page`).
//!
//! **An alert's SVS status.** Derived whenever it's read from the attributions that hold, as ace3's is: an
//! alert all of whose detections are attributed is `test` (`test?` by context alone), one some are
//! `partial`, and one with a marker that disagrees with its run `mismatch`. What differs: ace3 reads a
//! mismatch from the alert's `svs:marker_mismatch` tag and lists the markers from its mismatch detections;
//! here the detections alone say it, since the core's SVS hook (batch 6) writes the two together and roots
//! carry no tags of their own. A detection is named by its id (`analysis.detections.id`), as 7.14's
//! verdicts are, where ace3 names its content hash.

use std::collections::{BTreeMap, BTreeSet};

use ace_core::svs::hosts::{HostFields, HostSpec, build_spec};
use ace_core::svs::results::Precondition;
use ace_core::svs::{
    AttributionConfidence, MARKER_MISMATCH_SIGNATURE, RunState, SvsStatus, derive_status,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::types::Json;
use uuid::Uuid;

use crate::alerts::{RecordedActor, no_alert};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{ALERT_READ, SVS_ADMIN, SVS_RUN_READ};
use crate::{Actor, Service, ServiceError};

/// A test host, as it's stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestHost {
    pub id: i64,
    pub hostname: String,
    pub fqdn: Option<String>,
    pub usernames: Vec<String>,
    pub ips: Vec<String>,
    pub platform: Option<String>,
    pub notes: Option<String>,
    pub created_by: Option<RecordedActor>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The most test hosts one page holds.
pub const MAX_TEST_HOSTS_PAGE: u32 = 1000;

/// A page of test hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestHostPage {
    pub hosts: Vec<TestHost>,
    pub next_cursor: Option<String>,
}

struct TestHostRow {
    id: i64,
    hostname: String,
    fqdn: Option<String>,
    usernames: Vec<String>,
    ips: Vec<String>,
    platform: Option<String>,
    notes: Option<String>,
    created_by: Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TestHostRow {
    fn into_host(self) -> Result<TestHost, ServiceError> {
        Ok(TestHost {
            id: self.id,
            hostname: self.hostname,
            fqdn: self.fqdn,
            usernames: self.usernames,
            ips: self.ips,
            platform: self.platform,
            notes: self.notes,
            created_by: RecordedActor::from_row(Some(self.created_by))?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// What a test host's audit row keeps: ace3's AUDIT line's fields.
#[derive(Debug, Serialize)]
struct HostRecord<'a> {
    hostname: &'a str,
    fqdn: Option<&'a str>,
    usernames: &'a [String],
    ips: &'a [String],
    platform: Option<&'a str>,
}

impl Recorded for HostRecord<'_> {}

impl<'a> HostRecord<'a> {
    fn of_host(host: &'a TestHost) -> Self {
        HostRecord {
            hostname: &host.hostname,
            fqdn: host.fqdn.as_deref(),
            usernames: &host.usernames,
            ips: &host.ips,
            platform: host.platform.as_deref(),
        }
    }
}

fn checked(fields: &HostFields) -> Result<HostSpec, ServiceError> {
    build_spec(fields).map_err(|error| ServiceError::InvalidRequest(error.0))
}

fn unknown_host(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("test host {id} not found"))
}

/// A unique violation on the short name is a host that's there already.
fn taken(hostname: &str) -> impl Fn(sqlx::Error) -> ServiceError + '_ {
    move |error| {
        if error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation())
        {
            ServiceError::Conflict(format!("{hostname} is already a test host"))
        } else {
            error.into()
        }
    }
}

async fn host_row(
    conn: &mut sqlx::PgConnection,
    id: i64,
    lock: bool,
) -> Result<TestHost, ServiceError> {
    let row = if lock {
        sqlx::query_as!(
            TestHostRow,
            r#"SELECT id, hostname, fqdn, usernames, ips, platform, notes,
                      created_by AS "created_by!: Value", created_at, updated_at
               FROM svs.test_hosts WHERE id = $1 FOR UPDATE"#,
            id,
        )
        .fetch_optional(&mut *conn)
        .await?
    } else {
        sqlx::query_as!(
            TestHostRow,
            r#"SELECT id, hostname, fqdn, usernames, ips, platform, notes,
                      created_by AS "created_by!: Value", created_at, updated_at
               FROM svs.test_hosts WHERE id = $1"#,
            id,
        )
        .fetch_optional(&mut *conn)
        .await?
    };
    row.ok_or_else(|| unknown_host(id))?.into_host()
}

/// A run, as an alert names it: ace3's `RunRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRef {
    pub uuid: Uuid,
    pub state: RunState,
    pub test_guid: Uuid,
    /// The catalog's name of the test; None when the catalog no longer has it.
    pub test_name: Option<String>,
}

/// A marker in the alert that doesn't agree with its run: ace3's `MarkerMismatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerMismatch {
    /// As the alert has it, in any case.
    pub marker: String,
    /// How it disagrees: `unknown`, `other host` or `outside window`.
    pub result: String,
    /// The run the marker belongs to; None when no run has it.
    pub run: Option<RunRef>,
}

/// An alert's SVS status and the runs it's attributed to, oldest run first; none for a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertSvsStatus {
    pub status: SvsStatus,
    pub runs: Vec<Uuid>,
}

/// What one alert's page shows of SVS: ace3's `AlertSVSView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertSvsView {
    pub status: SvsStatus,
    /// The runs whose attributions of the alert hold, oldest first.
    pub runs: Vec<RunRef>,
    /// Each attributed detection, by id, and the runs it's attributed to, oldest first.
    pub detections: BTreeMap<i64, Vec<Uuid>>,
    pub mismatches: Vec<MarkerMismatch>,
}

/// Each of `roots`' status, in one transaction and a fixed number of queries: ace3's `alert_svs_statuses`.
async fn statuses(
    conn: &mut sqlx::PgConnection,
    roots: &[Uuid],
) -> Result<BTreeMap<Uuid, AlertSvsStatus>, ServiceError> {
    let mut confidences: BTreeMap<Uuid, BTreeMap<i64, BTreeSet<AttributionConfidence>>> =
        BTreeMap::new();
    let mut runs: BTreeMap<Uuid, BTreeMap<i64, Uuid>> = BTreeMap::new();
    let held = sqlx::query!(
        r#"SELECT a.root_id, a.detection_id, a.confidence AS "confidence: AttributionConfidence",
                  r.id AS run_id, r.uuid AS run_uuid
           FROM svs.attributions a
           JOIN svs.runs r ON r.id = a.run_id
           WHERE a.root_id = ANY ($1) AND a.removed_at IS NULL"#,
        roots,
    )
    .fetch_all(&mut *conn)
    .await?;
    for row in held {
        confidences
            .entry(row.root_id)
            .or_default()
            .entry(row.detection_id)
            .or_default()
            .insert(row.confidence);
        runs.entry(row.root_id)
            .or_default()
            .insert(row.run_id, row.run_uuid);
    }
    let attributed: Vec<Uuid> = confidences.keys().copied().collect();
    let mut detections: BTreeMap<Uuid, Vec<i64>> = BTreeMap::new();
    if !attributed.is_empty() {
        for row in sqlx::query!(
            "SELECT root_id, id FROM analysis.detections WHERE root_id = ANY ($1)",
            &attributed,
        )
        .fetch_all(&mut *conn)
        .await?
        {
            detections.entry(row.root_id).or_default().push(row.id);
        }
    }
    let mismatched: BTreeSet<Uuid> = sqlx::query_scalar!(
        "SELECT DISTINCT root_id FROM analysis.detections
         WHERE root_id = ANY ($1) AND signature_uuid = $2",
        roots,
        MARKER_MISMATCH_SIGNATURE,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let mut found = BTreeMap::new();
    let none = BTreeMap::new();
    for root in roots {
        let status = derive_status(
            detections.get(root).into_iter().flatten().copied(),
            confidences.get(root).unwrap_or(&none),
        );
        if let Some(status) = status {
            // by run id, which is the order runs were registered in
            let runs = runs[root].values().copied().collect();
            found.insert(*root, AlertSvsStatus { status, runs });
        } else if mismatched.contains(root) {
            found.insert(
                *root,
                AlertSvsStatus {
                    status: SvsStatus::Mismatch,
                    runs: Vec::new(),
                },
            );
        }
    }
    Ok(found)
}

/// What a mismatch detection's details say: its marker, when it names one, and how it disagrees.
fn mismatch_of(details: Option<&Value>) -> Option<(String, String)> {
    let text = |value: Option<&Value>| match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => None,
    };
    let details = details?.as_object()?;
    let marker = text(details.get("marker")).filter(|marker| !marker.is_empty())?;
    Some((marker, text(details.get("result")).unwrap_or_default()))
}

struct RunRefRow {
    marker: String,
    uuid: Uuid,
    state: RunState,
    test_guid: Uuid,
    name: Option<String>,
}

impl RunRefRow {
    fn into_ref(self) -> RunRef {
        RunRef {
            uuid: self.uuid,
            state: self.state,
            test_guid: self.test_guid,
            test_name: self.name,
        }
    }
}

impl Service {
    /// Every test host, by name. It needs `svs:run_read`.
    pub async fn test_hosts(&self, actor: &Actor) -> Result<Vec<TestHost>, ServiceError> {
        self.gate
            .read(actor, "test_hosts", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    sqlx::query_as!(
                        TestHostRow,
                        r#"SELECT id, hostname, fqdn, usernames, ips, platform, notes,
                                  created_by AS "created_by!: Value", created_at, updated_at
                           FROM svs.test_hosts ORDER BY hostname"#,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(TestHostRow::into_host)
                    .collect()
                })
            })
            .await
    }

    /// A page of the test hosts, by name, after where `cursor` left off: ace3's `fetch_page`. With
    /// `changed_since`, only those added or changed at or after it, once the change has settled
    /// (`Service::with_feed_settle`). It needs `svs:run_read`. A limit out of range, or a cursor that
    /// isn't one, is `InvalidRequest`.
    pub async fn test_hosts_page(
        &self,
        actor: &Actor,
        changed_since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<TestHostPage, ServiceError> {
        let limit = crate::alerts::page_limit(limit, MAX_TEST_HOSTS_PAGE)?;
        let after = &match cursor {
            Some(text) => Some(
                hex::decode(text)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| {
                        ServiceError::InvalidRequest(format!("{text:?} isn't a cursor"))
                    })?,
            ),
            None => None,
        };
        let settle = self.feed_settle_seconds();
        self.gate
            .read(actor, "test_hosts_page", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query_as!(
                        TestHostRow,
                        r#"SELECT id, hostname, fqdn, usernames, ips, platform, notes,
                                  created_by AS "created_by!: Value", created_at, updated_at
                           FROM svs.test_hosts
                           WHERE ($1::timestamptz IS NULL
                                  OR (updated_at >= $1
                                      AND updated_at < now() - make_interval(secs => $4)))
                             AND ($2::text IS NULL OR hostname COLLATE "C" > $2)
                           ORDER BY hostname COLLATE "C"
                           LIMIT $3"#,
                        changed_since,
                        after.as_deref(),
                        limit + 1,
                        settle,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| hex::encode(last.hostname.as_bytes()))
                    } else {
                        None
                    };
                    Ok(TestHostPage {
                        hosts: rows
                            .into_iter()
                            .map(TestHostRow::into_host)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// One test host. It needs `svs:run_read`; one that isn't there is `NotFound`.
    pub async fn test_host(&self, actor: &Actor, id: i64) -> Result<TestHost, ServiceError> {
        self.gate
            .read(actor, "test_host", &SVS_RUN_READ, &|tx| {
                Box::pin(async move { host_row(tx.conn(), id, false).await })
            })
            .await
    }

    /// Adds a test host, normalized (`ace_core::svs::hosts::build_spec`): ace3's `create_host`. It needs
    /// `svs:admin`. A field that can't be used is `InvalidRequest`, saying why, and a short name another
    /// host has is `Conflict`.
    pub async fn create_test_host(
        &self,
        actor: &Actor,
        fields: &HostFields,
    ) -> Result<TestHost, ServiceError> {
        let spec = &checked(fields)?;
        self.gate
            .write(actor, "create_test_host", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    let id = sqlx::query_scalar!(
                        "INSERT INTO svs.test_hosts
                             (hostname, fqdn, usernames, ips, platform, notes, created_by)
                         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                         RETURNING id",
                        spec.hostname,
                        spec.fqdn,
                        &spec.usernames,
                        &spec.ips,
                        spec.platform,
                        spec.notes,
                        Json(actor) as _,
                    )
                    .fetch_one(tx.conn())
                    .await
                    .map_err(taken(&spec.hostname))?;
                    let host = host_row(tx.conn(), id, false).await?;
                    let change = Change::added(Target::test_host(id), &HostRecord::of_host(&host))?;
                    Ok(Audited::changed(host, change))
                })
            })
            .await
    }

    /// Replaces a test host's fields: ace3's `update_host`. It needs `svs:admin`. One that isn't there is
    /// `NotFound`; otherwise as `create_test_host`. A change to nothing has no audit row. A write from a
    /// form loaded before someone else changed the host is `StaleWrite`, not applied over it
    /// (`precondition`).
    pub async fn update_test_host(
        &self,
        actor: &Actor,
        id: i64,
        fields: &HostFields,
        precondition: Precondition,
    ) -> Result<TestHost, ServiceError> {
        let spec = &checked(fields)?;
        self.gate
            .write(actor, "update_test_host", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    let before = host_row(tx.conn(), id, true).await?;
                    if let Some(why) = precondition.refuses(
                        Some(before.updated_at),
                        &format!("test host {}", before.hostname),
                    ) {
                        return Err(ServiceError::StaleWrite(why));
                    }
                    let same = before.hostname == spec.hostname
                        && before.fqdn == spec.fqdn
                        && before.usernames == spec.usernames
                        && before.ips == spec.ips
                        && before.platform == spec.platform
                        && before.notes == spec.notes;
                    if same {
                        return Ok(Audited::unchanged(before));
                    }
                    sqlx::query!(
                        "UPDATE svs.test_hosts
                         SET hostname = $2, fqdn = $3, usernames = $4, ips = $5, platform = $6,
                             notes = $7
                         WHERE id = $1",
                        id,
                        spec.hostname,
                        spec.fqdn,
                        &spec.usernames,
                        &spec.ips,
                        spec.platform,
                        spec.notes,
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(taken(&spec.hostname))?;
                    let after = host_row(tx.conn(), id, false).await?;
                    let change = Change::updated(
                        Target::test_host(id),
                        &HostRecord::of_host(&before),
                        &HostRecord::of_host(&after),
                    )?;
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Removes a test host: ace3's `delete_host`. It needs `svs:admin`; one that isn't there is
    /// `NotFound`. A run keeps the targets it was registered with, whose host is then none. Its open
    /// maintenance window ends now, in the same transaction, and the audit row names it.
    pub async fn delete_test_host(&self, actor: &Actor, id: i64) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "delete_test_host", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    let host = host_row(tx.conn(), id, true).await?;
                    let ended =
                        crate::svs_runs::end_host_windows(tx.conn(), id, actor, Utc::now()).await?;
                    sqlx::query!("DELETE FROM svs.test_hosts WHERE id = $1", id)
                        .execute(tx.conn())
                        .await?;
                    let mut change =
                        Change::removed(Target::test_host(id), &HostRecord::of_host(&host))?;
                    if !ended.is_empty() {
                        change = change.details(&crate::svs_runs::EndedMaintenance {
                            ended_maintenance: ended,
                        })?;
                    }
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// The SVS status of each of the roots that has one, for a list of alerts: ace3's
    /// `alert_svs_statuses`. It needs `alert:read`.
    pub async fn alert_svs_statuses(
        &self,
        actor: &Actor,
        roots: &[Uuid],
    ) -> Result<BTreeMap<Uuid, AlertSvsStatus>, ServiceError> {
        self.gate
            .read(actor, "alert_svs_statuses", &ALERT_READ, &|tx| {
                Box::pin(async move { statuses(tx.conn(), roots).await })
            })
            .await
    }

    /// What an alert's page shows of SVS: its status, the runs it's attributed to, which detections each
    /// holds, and the markers that disagree with their run. None when SVS never touched the alert: ace3's
    /// `alert_svs_view`. It needs `alert:read`; a root that isn't an alert is `NotFound`.
    pub async fn alert_svs_view(
        &self,
        actor: &Actor,
        alert: Uuid,
    ) -> Result<Option<AlertSvsView>, ServiceError> {
        self.gate
            .read(actor, "alert_svs_view", &ALERT_READ, &|tx| {
                Box::pin(async move {
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
                    let status = statuses(tx.conn(), &[alert]).await?.remove(&alert);
                    let found: Vec<(String, String)> = sqlx::query_scalar!(
                        "SELECT details FROM analysis.detections
                         WHERE root_id = $1 AND signature_uuid = $2 ORDER BY id",
                        alert,
                        MARKER_MISMATCH_SIGNATURE,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .iter()
                    .filter_map(|details| mismatch_of(details.as_ref()))
                    .collect();
                    if status.is_none() && found.is_empty() {
                        return Ok(None);
                    }
                    let mut mismatches = Vec::new();
                    if !found.is_empty() {
                        // runs store a marker lower case; an alert may have it in any case
                        let markers: Vec<String> =
                            found.iter().map(|(marker, _)| marker.to_lowercase()).collect();
                        let by_marker: BTreeMap<String, RunRef> = sqlx::query_as!(
                            RunRefRow,
                            r#"SELECT r.marker AS "marker!", r.uuid AS "uuid!", r.state AS "state!: RunState",
                                      r.test_guid AS "test_guid!", t.name AS "name?"
                               FROM svs.runs r
                               LEFT JOIN svs.catalog_tests t ON t.guid = r.test_guid
                               WHERE r.marker = ANY ($1)"#,
                            &markers,
                        )
                        .fetch_all(tx.conn())
                        .await?
                        .into_iter()
                        .map(|row| (row.marker.clone(), row.into_ref()))
                        .collect();
                        for (marker, result) in found {
                            let run = by_marker.get(&marker.to_lowercase()).cloned();
                            mismatches.push(MarkerMismatch {
                                marker,
                                result,
                                run,
                            });
                        }
                    }
                    let held = sqlx::query!(
                        "SELECT a.detection_id, r.uuid AS run_uuid
                         FROM svs.attributions a
                         JOIN svs.runs r ON r.id = a.run_id
                         WHERE a.root_id = $1 AND a.removed_at IS NULL
                         ORDER BY r.id, a.detection_id",
                        alert,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut detections: BTreeMap<i64, Vec<Uuid>> = BTreeMap::new();
                    for row in held {
                        detections
                            .entry(row.detection_id)
                            .or_default()
                            .push(row.run_uuid);
                    }
                    let runs = sqlx::query_as!(
                        RunRefRow,
                        r#"SELECT r.marker AS "marker!", r.uuid AS "uuid!", r.state AS "state!: RunState",
                                  r.test_guid AS "test_guid!", t.name AS "name?"
                           FROM svs.runs r
                           LEFT JOIN svs.catalog_tests t ON t.guid = r.test_guid
                           WHERE EXISTS (SELECT FROM svs.attributions a
                                         WHERE a.run_id = r.id AND a.root_id = $1
                                           AND a.removed_at IS NULL)
                           ORDER BY r.id"#,
                        alert,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(RunRefRow::into_ref)
                    .collect();
                    Ok(Some(AlertSvsView {
                        status: status.map_or(SvsStatus::Mismatch, |status| status.status),
                        runs,
                        detections,
                        mismatches,
                    }))
                })
            })
            .await
    }
}
