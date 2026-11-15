//! Who owns an event, and attributing alerts to test runs (PLAN.md 7.10 batch 6, ace3 #842): ace3's
//! `saq/svs/attribution.py`, the judging half of `maintenance.py`, and `saq/modules/svs.py`'s
//! `SVSAlertTagger`.
//!
//! An alert is attributed by the markers found in it. A marker attributes only when it agrees with its
//! run: the run is registered, the alert involves one of the run's targets, and the alert's event time is
//! inside the run's attribution window. A marker that doesn't agree is a mismatch: nothing in the alert is
//! attributed, not even by context. An alert with no marker at all is attributed by context, to the one
//! run that can claim it by its hosts and event time, or it belongs to a test host's maintenance window.
//! Attribution is per detection: a marker attributes the detections on its own branch of the tree (the
//! observable it was found on, those above it and those beneath it); a marker on the root, and a context
//! attribution, attribute every detection.
//!
//! # One decision
//!
//! ace3 decides who owns an event in one function, `context_owners`, but each of its callers judges on its
//! own, in its own process and behind its own caches: the tagger module, the marker router at two stages,
//! and the hunter twice. Here:
//!
//! - [`Event::derive`] is the one place an event's hosts and time come from: a root's
//!   ([`root_event`]) and a hunt's submission (`ace_service`'s `record_hunt_run`).
//! - [`context_owners`] is the one function that decides the SVS context of events, over the database, in
//!   its caller's transaction, with no cache.
//! - It has two callers. The core's SVS hook ([`judge`], run by `crate::hooks` at the end of a pass)
//!   judges a root once and writes its attributions, tags, mismatch detections and maintenance record
//!   from that one judgment. `Service::record_hunt_run` asks it for a grouped hunt's suppression keys and
//!   for the runs its dropped matches belong to ([`record_suppressed_matches`]).
//!
//! Everything else reads `svs.attributions`, the tags and `svs.maintenance_alerts`, and never judges
//! again.
//!
//! # The gate
//!
//! Nothing is judged unless some run is registered or inside its attribution window, or a maintenance
//! window was open within `svs.runs.attribution_extra_hours` ([`attribution_open`]): ace3's gate, which
//! it caches for five seconds per process. Here it's one query in the caller's transaction, so a run
//! registered a moment ago is seen. While it's closed a root keeps the attributions and tags it has, as in
//! ace3.
//!
//! The hook reads the gate twice, each time through [`gate_open`]: `queue::check_completion` before it
//! queues the hooks task on SVS's account alone (a mode whose only hook is this one), so a pass with the
//! gate closed queues no task for it, and [`judge`] in the task. A pass that ends beside a registration
//! can't slip between them. [`gate_open`] takes [`GATE_LOCK`] shared, for its transaction, before it
//! reads; the two writes that can open the gate, registering a run and opening a maintenance window, take
//! it exclusive before they insert ([`lock_gate_to_open`]). So for a pass's end and a registration, one
//! of two things is true: the registration committed first, and the read, made after its lock was
//! granted, sees the run, so the hook judges the alert; or the pass's end committed first, with the gate
//! closed, before the run existed. Nothing else opens the gate: a run's start and end only move a run
//! that already holds it open, and time only closes it.
//!
//! # Bounds
//!
//! A root's tree is hostile, and the hook runs in the core. What one judgment reads:
//! - Text is searched for markers in the database: only observables, file names, detections and results
//!   that hold marker-shaped text (or the marker rule's matches) come back, at most [`MAX_MARKED_ROWS`] of
//!   each, and at most [`MAX_SIGHTINGS`] markers from module output are kept, ace3's
//!   `svs.attribution.max_sightings`. JSON is walked [`MAX_WALK_DEPTH`] deep, as ace3 walks it.
//! - At most [`MAX_MARKERS`] distinct markers are judged; the rest are logged and left out. A marker that
//!   agrees needs its run's host and window, so leaving out surplus ones gives an alert nothing.
//! - An event has at most [`MAX_EVENT_HOSTS`] host names and addresses; the rest are left out and logged.
//! - The runs and maintenance windows considered are those on the event's hosts whose windows overlap its
//!   time, found by an indexed query, at most [`MAX_RUNS_CONSIDERED`] runs (the latest started) and
//!   [`MAX_WINDOWS_CONSIDERED`] windows.
//! - A root with more than [`MAX_DETECTIONS`] detections isn't judged, and says so. The tree's edges, read
//!   only when a marker has to be placed on its branch, stop at [`MAX_BRANCH_EDGES`]; a missing edge can
//!   only leave a detection unattributed.
//! - A hunt run asks about at most [`MAX_EVENTS`] events at once.
//!
//! # What differs from ace3
//!
//! - A detection is its row, `analysis.detections.id` (migration 0047), where ace3 names it by a content
//!   hash, so two detections alike on one node are two here.
//! - Markers in module output are read from the results' details at the end of the pass, where ace3's
//!   executor saves them on the root as each module returns, before it drops the details. A match's bytes
//!   are `{"base64": ...}` here (`ace_results::Bytes`), which the walk reads as ace3 reads bytes; bytes in
//!   a result that holds no marker as text and no marker-rule match aren't searched.
//! - A judgment is written in the hook's transaction, with the run rows locked first in id order, so two
//!   alerts of one run wait their turn; the transaction is retried by `Db::transaction` when Postgres
//!   picks it as a deadlock victim, where ace3 retries its own.
//! - A maintenance record is always confirmed: the hook runs once a pass has nothing left to run, delayed
//!   work included, which is ace3's `final`.
//! - ace3's per-process marker cache, and the snapshot it can serve stale, don't exist. A write still
//!   judges lateness by the run's row as it locks it.
//! - Times are UTC instants, where ace3's are naive local times, and they keep their microseconds.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ace_results::ObservableKind;
use chrono::{DateTime, SubsecRound, TimeDelta, Utc};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use super::hosts::{normalize_ip, split_hostname};
use super::marker_rule::MARKER_RULE_NAME;
use super::markers::{find_markers, find_markers_in_match};
use super::signatures::FAMILY_BUILTIN;
use super::{
    AttributionConfidence, MARKER_MISMATCH_SIGNATURE, RUN_SIGNATURES, SvsStatus, TAG_MAINTENANCE,
    TAG_MARKER_MISMATCH, TAG_SVS_TEST, derive_status,
};
use crate::db::DbError;

/// ace3's module name, which the modes list: the hook runs in the modes that have it.
pub const SVS_ALERT_TAGGER: &str = "svs_alert_tagger";
/// How deep the walk over JSON goes: ace3's `MAX_WALK_DEPTH`.
pub const MAX_WALK_DEPTH: usize = 32;
/// The most markers from module output one judgment keeps: ace3's `svs.attribution.max_sightings`.
pub const MAX_SIGHTINGS: usize = 200;
/// The most distinct markers one judgment judges.
pub const MAX_MARKERS: usize = 256;
/// The most host names and addresses an event has.
pub const MAX_EVENT_HOSTS: usize = 256;
/// The most runs on an event's hosts one decision considers, the latest started.
pub const MAX_RUNS_CONSIDERED: i64 = 500;
/// The most maintenance windows on an event's hosts one decision considers, the latest opened.
pub const MAX_WINDOWS_CONSIDERED: i64 = 500;
/// The most rows of each kind (observables, file names, detections, results) read for their markers.
pub const MAX_MARKED_ROWS: i64 = 1000;
/// The most detections a root may have and still be judged.
pub const MAX_DETECTIONS: i64 = 10_000;
/// The most parent-to-child edges of the tree read to place a marker on its branch.
pub const MAX_BRANCH_EDGES: i64 = 100_000;
/// The most events one call of [`context_owners`] takes.
pub const MAX_EVENTS: usize = 10_000;

/// Why the hook removed one of its attributions: ace3's `REMOVAL_NO_LONGER_APPLIES`.
pub const REMOVAL_NO_LONGER_APPLIES: &str = "no longer attributed by the marker router";
/// The component the hook's rows name: ace3's `ROUTER_ACTOR`.
pub const ROUTER_ACTOR: &str = "svs";

/// Marker-shaped text, for the database to find the rows worth reading. `markers::find_markers` then
/// checks what touches it.
const MARKER_SQL: &str = "svs-[a-z2-7]{26}";

fn router_actor() -> Value {
    json!({"kind": "internal", "id": ROUTER_ACTOR})
}

macro_rules! names {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $text:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            pub const ALL: &[$name] = &[$($name::$variant,)+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)+
                }
            }

            pub fn parse(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.as_str() == text)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

names!(
    /// Where in an alert a marker was found: ace3's `ScanPoint`.
    ScanPoint {
        /// An observable's value, or a file's name.
        Observable => "observable",
        /// A detection's description or details.
        Detection => "detection",
        /// The alert's own details: a hunt's events, a submitter's details.
        RootDetails => "root_details",
        /// The details of a module's result.
        Analysis => "analysis",
        /// The marker rule matched a file.
        FileContents => "file_contents",
    }
);

names!(
    /// What a marker found in an alert says about it: ace3's `MarkerResult`.
    MarkerResult {
        /// It agrees with its run.
        Attributed => "attributed",
        /// No run has it.
        Unknown => "unknown",
        /// The alert involves none of its run's targets.
        OtherHost => "other host",
        /// The run never started, or the event is outside its attribution window.
        OutsideWindow => "outside window",
    }
);

names!(
    /// Where the event time an attribution was judged by came from: ace3's `AttributionTimeSource`.
    TimeSource {
        /// The event's own.
        Event => "event",
        /// A hunt's query time: the hunt couldn't extract the event's.
        QueryTime => "query_time",
        /// Nothing gave the alert a time, so its producer used the time it made it.
        Now => "now",
        /// The alert has none: when it became an alert.
        InsertTime => "insert_time",
    }
);

//
// what was found where
//

/// A marker found in an alert. `node` is the observable it was found on (for module output, the one the
/// module analyzed), None for the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sighting {
    pub marker: String,
    pub node: Option<i64>,
    pub scan_point: ScanPoint,
    pub module: Option<String>,
}

impl Sighting {
    pub fn new(marker: &str, node: Option<i64>, scan_point: ScanPoint) -> Sighting {
        Sighting {
            marker: marker.to_owned(),
            node,
            scan_point,
            module: None,
        }
    }
}

/// The bytes of `{"base64": ...}`, how a result carries bytes (`ace_results::Bytes`).
fn bytes_of(value: &Value) -> Option<Vec<u8>> {
    let map = value.as_object()?;
    if map.len() != 1 || !map.get(ace_results::bytes::BYTES_TAG)?.is_string() {
        return None;
    }
    serde_json::from_value::<ace_results::Bytes>(value.clone())
        .ok()
        .map(ace_results::Bytes::into_vec)
}

fn keep(found: &mut Vec<String>, markers: Vec<String>) {
    for marker in markers {
        if !found.contains(&marker) {
            found.push(marker);
        }
    }
}

fn walk(value: &Value, depth: usize, found: &mut Vec<String>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    match value {
        Value::String(text) => keep(found, find_markers(text)),
        Value::Object(map) => match bytes_of(value) {
            Some(bytes) => keep(found, find_markers_in_match(&bytes)),
            None => {
                for item in map.values() {
                    walk(item, depth + 1, found);
                }
            }
        },
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1, found);
            }
        }
        _ => {}
    }
}

/// The distinct markers in JSON: every string among an object's values and an array's items, and bytes
/// read as the marker rule's match data is. ace3's `find_markers_in_data`.
pub fn find_markers_in_data(value: &Value) -> Vec<String> {
    let mut found = Vec::new();
    walk(value, 0, &mut found);
    found
}

/// The markers the marker rule matched, from a YARA result's details: ace3's `_marker_rule_markers`.
fn marker_rule_markers(details: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let Some(results) = details.get("scan_results").and_then(Value::as_array) else {
        return found;
    };
    for entry in results {
        if entry.get("rule").and_then(Value::as_str) != Some(MARKER_RULE_NAME) {
            continue;
        }
        for string in entry
            .get("strings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // [offset, identifier, data]
            let Some(data) = string.as_array().and_then(|parts| parts.get(2)) else {
                continue;
            };
            match (bytes_of(data), data.as_str()) {
                (Some(bytes), _) => keep(&mut found, find_markers_in_match(&bytes)),
                // text that was UTF-16 keeps a NUL, or what a task's end made of it, between characters
                (None, Some(text)) => {
                    let text: String = text
                        .chars()
                        .filter(|c| !matches!(c, '\0' | '\u{fffd}'))
                        .collect();
                    keep(&mut found, find_markers(&text));
                }
                _ => {}
            }
        }
    }
    found
}

/// The markers in a module's result details: the marker rule's matches are file contents, anything else
/// is the module's output. ace3's `analysis_sightings`.
pub fn analysis_sightings(
    details: &Value,
    node: Option<i64>,
    module: Option<&str>,
) -> Vec<Sighting> {
    let mut sightings: Vec<Sighting> = Vec::new();
    let mut add = |marker: String, scan_point| {
        if !sightings.iter().any(|s| s.marker == marker) {
            sightings.push(Sighting {
                marker,
                node,
                scan_point,
                module: module.map(str::to_owned),
            });
        }
    };
    for marker in marker_rule_markers(details) {
        add(marker, ScanPoint::FileContents);
    }
    for marker in find_markers_in_data(details) {
        add(marker, ScanPoint::Analysis);
    }
    sightings
}

/// Adds `sightings` to `kept`, without duplicates (by marker, node and scan point) and up to `limit`:
/// ace3's `save_sightings`. Returns how many were added.
pub fn keep_sightings(kept: &mut Vec<Sighting>, sightings: Vec<Sighting>, limit: usize) -> usize {
    let mut added = 0;
    for sighting in sightings {
        if kept.iter().any(|k| {
            (&k.marker, k.node, k.scan_point)
                == (&sighting.marker, sighting.node, sighting.scan_point)
        }) {
            continue;
        }
        if kept.len() >= limit {
            tracing::warn!(
                svs_marker = %sighting.marker,
                "an alert already holds {limit} svs sightings; a marker is not kept"
            );
            break;
        }
        kept.push(sighting);
        added += 1;
    }
    added
}

//
// the runs
//

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSnapshot {
    /// The short host name.
    pub host: String,
    pub fqdn: Option<String>,
    /// Its test host's addresses.
    pub ips: BTreeSet<String>,
}

impl TargetSnapshot {
    pub fn new(host: &str, fqdn: Option<&str>, ips: &[&str]) -> TargetSnapshot {
        TargetSnapshot {
            host: host.to_owned(),
            fqdn: fqdn.map(str::to_owned),
            ips: ips.iter().map(|ip| (*ip).to_owned()).collect(),
        }
    }
}

/// What attribution needs of a run: ace3's `RunSnapshot`, read in the caller's transaction each time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSnapshot {
    pub id: i64,
    pub uuid: Uuid,
    pub test_guid: Uuid,
    pub marker: String,
    pub started_at: Option<DateTime<Utc>>,
    pub observation_ends_at: Option<DateTime<Utc>>,
    pub attribution_ends_at: Option<DateTime<Utc>>,
    pub targets: Vec<TargetSnapshot>,
    pub holds_host: bool,
}

impl RunSnapshot {
    /// When its claim on its hosts ends (`ace_service`'s `host_holders`).
    pub fn claim_ends_at(&self) -> Option<DateTime<Utc>> {
        if self.holds_host {
            self.attribution_ends_at
        } else {
            self.observation_ends_at
        }
    }

    pub fn in_window(&self, when: DateTime<Utc>) -> bool {
        matches!((self.started_at, self.attribution_ends_at),
                 (Some(started), Some(ends)) if started <= when && when <= ends)
    }

    /// Its claim on its hosts covers `when`.
    pub fn holds_host_at(&self, when: DateTime<Utc>) -> bool {
        self.claim_ends_at().is_none_or(|ends| when <= ends)
    }

    pub fn is_late(&self, when: DateTime<Utc>) -> bool {
        self.observation_ends_at.is_some_and(|ends| when > ends)
    }
}

/// What attribution needs of a maintenance window: ace3's `MaintenanceSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceSnapshot {
    pub id: i64,
    pub uuid: Uuid,
    pub target: TargetSnapshot,
    pub opened_at: DateTime<Utc>,
    /// When it ended, or ends.
    pub ends_at: DateTime<Utc>,
}

impl MaintenanceSnapshot {
    pub fn covers(&self, when: DateTime<Utc>) -> bool {
        self.opened_at <= when && when <= self.ends_at
    }
}

//
// an event's hosts and time
//

/// The hosts an event involves: host names, short and fully qualified, and IPv4 addresses. ace3's
/// `AlertHosts`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventHosts {
    pub names: BTreeSet<(String, Option<String>)>,
    pub ips: BTreeSet<String>,
}

impl EventHosts {
    pub fn of_names(names: &[&str]) -> EventHosts {
        EventHosts {
            names: names
                .iter()
                .map(|name| ((*name).to_owned(), None))
                .collect(),
            ips: BTreeSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.names.len() + self.ips.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn involves(&self, target: &TargetSnapshot) -> bool {
        // a fully qualified name must be the target's own when the target has one, as at registration
        // (`hosts::match_target`)
        self.names.iter().any(|(short, qualified)| {
            *short == target.host
                && (qualified.is_none() || target.fqdn.is_none() || *qualified == target.fqdn)
        }) || self.ips.iter().any(|ip| target.ips.contains(ip))
    }

    pub fn involves_run(&self, run: &RunSnapshot) -> bool {
        run.targets.iter().any(|target| self.involves(target))
    }
}

/// Whether observables of this type name a host: `hostname`, `fqdn`, `ipv4` and their subtypes.
fn names_a_host(kind: ObservableKind) -> bool {
    kind.is_subtype_of(ObservableKind::Hostname)
        || kind.is_subtype_of(ObservableKind::Fqdn)
        || kind.is_subtype_of(ObservableKind::Ipv4)
}

/// The names of the observable types that name a host, for a query.
pub fn host_kinds() -> Vec<String> {
    ObservableKind::all()
        .iter()
        .copied()
        .filter(|kind| names_a_host(*kind))
        .map(|kind| kind.as_str().to_owned())
        .collect()
}

/// An event: the hosts it involves and when it happened, with where that time came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub hosts: EventHosts,
    pub time: DateTime<Utc>,
    pub source: TimeSource,
}

impl Event {
    /// The one place an event's hosts and time are derived, for a root and for a hunt's match alike.
    /// The hosts are its `hostname` and `fqdn` observables (and their subtypes) and its `ipv4`
    /// observables, a value that isn't a host name or an address counting for nothing (ace3's
    /// `alert_hosts`), up to [`MAX_EVENT_HOSTS`]. The time is the event's own with its source, or
    /// `fallback`, when the alert was made, for an event with none (ace3's `alert_event_time`), to the
    /// microsecond, as the database stores it.
    pub fn derive<'a>(
        observables: impl IntoIterator<Item = (ObservableKind, &'a str)>,
        time: Option<(DateTime<Utc>, TimeSource)>,
        fallback: DateTime<Utc>,
    ) -> Event {
        let mut hosts = EventHosts::default();
        let mut left_out = 0usize;
        for (kind, value) in observables {
            if kind.is_subtype_of(ObservableKind::Hostname)
                || kind.is_subtype_of(ObservableKind::Fqdn)
            {
                if let Ok(name) = split_hostname(value) {
                    if hosts.names.contains(&name) {
                        continue;
                    }
                    if hosts.len() >= MAX_EVENT_HOSTS {
                        left_out += 1;
                        continue;
                    }
                    hosts.names.insert(name);
                }
            } else if kind.is_subtype_of(ObservableKind::Ipv4)
                && let Ok(ip) = normalize_ip(value)
            {
                if hosts.ips.contains(&ip) {
                    continue;
                }
                if hosts.len() >= MAX_EVENT_HOSTS {
                    left_out += 1;
                    continue;
                }
                hosts.ips.insert(ip);
            }
        }
        if left_out > 0 {
            tracing::warn!(
                left_out,
                "an event names more than {MAX_EVENT_HOSTS} hosts; svs judges it by the first"
            );
        }
        let (time, source) = time.unwrap_or((fallback, TimeSource::InsertTime));
        Event {
            hosts,
            time: time.trunc_subsecs(6),
            source,
        }
    }
}

/// A root's event, by [`Event::derive`]: its host observables, and its event time with its source, or
/// the time it became an alert. None for a root that isn't an alert, which SVS never judges, as ace3's
/// tagger and router judge only what has an alert row.
pub async fn root_event(conn: &mut PgConnection, root: Uuid) -> Result<Option<Event>, DbError> {
    let Some(head) = sqlx::query!(
        r#"SELECT event_time, event_time_source::text AS "source!", alerted_at
           FROM analysis.roots WHERE id = $1"#,
        root,
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let Some(alerted_at) = head.alerted_at else {
        return Ok(None);
    };
    // one more than an event keeps, so `derive` says when it left some out
    let rows = sqlx::query!(
        "SELECT type AS kind, value FROM analysis.observables
         WHERE root_id = $1 AND type = ANY ($2) ORDER BY id LIMIT $3",
        root,
        &host_kinds(),
        2 * MAX_EVENT_HOSTS as i64 + 1,
    )
    .fetch_all(&mut *conn)
    .await?;
    let observables: Vec<(ObservableKind, &str)> = rows
        .iter()
        .filter_map(|row| Some((row.kind.parse().ok()?, row.value.as_str())))
        .collect();
    // every source of a root's event time but unset, which has no time, is an attribution's by name
    let time = head
        .event_time
        .zip(TimeSource::parse(&head.source))
        .filter(|(_, source)| *source != TimeSource::InsertTime);
    Ok(Some(Event::derive(observables, time, alerted_at)))
}

//
// the database: the gate, the runs and the windows
//

/// Whether anything can be attributed at `now`: some run is registered and not started, or is inside its
/// attribution window, or a maintenance window was open within `extra`
/// (`svs.runs.attribution_extra_hours`), since an alert of a window may come as late as a run's. ace3's
/// `attribution_open`, without its cache.
pub async fn attribution_open(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
    extra: TimeDelta,
) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT (EXISTS (SELECT FROM svs.runs WHERE state = 'created')
                   OR EXISTS (SELECT FROM svs.runs
                              WHERE state <> 'created' AND attribution_ends_at >= $1)
                   OR EXISTS (SELECT FROM svs.maintenance_windows
                              WHERE ends_at >= $2 AND (ended_at IS NULL OR ended_at >= $2))) AS "open!""#,
        now,
        now - extra,
    )
    .fetch_one(conn)
    .await?)
}

/// The advisory lock that orders a read of the gate and a write that opens it (the module docs): `SVSGATE`
/// as a number.
pub const GATE_LOCK: i64 = 0x0053_5653_4741_5445;

/// [`attribution_open`], read under [`GATE_LOCK`] held shared until the caller's transaction ends, so a
/// registration or a maintenance window either committed before this read, and is seen, or begins after
/// the caller's transaction commits. Call it in a transaction.
pub async fn gate_open(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
    extra: TimeDelta,
) -> Result<bool, DbError> {
    sqlx::query!("SELECT pg_advisory_xact_lock_shared($1)", GATE_LOCK)
        .execute(&mut *conn)
        .await?;
    attribution_open(conn, now, extra).await
}

/// Takes [`GATE_LOCK`] exclusive until the caller's transaction ends: what a write that can open the gate
/// does before its insert, so no pass ends on a closed gate while that write is in flight. It waits for
/// the passes ending now, each a short transaction, and they wait for the caller's commit.
pub async fn lock_gate_to_open(conn: &mut PgConnection) -> Result<(), DbError> {
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", GATE_LOCK)
        .execute(conn)
        .await?;
    Ok(())
}

/// The runs with these ids, as attribution reads them, in id order.
async fn snapshots(conn: &mut PgConnection, ids: &[i64]) -> Result<Vec<RunSnapshot>, DbError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut runs: BTreeMap<i64, RunSnapshot> = sqlx::query!(
        "SELECT id, uuid, test_guid, marker, started_at, observation_ends_at, attribution_ends_at,
                holds_host
         FROM svs.runs WHERE id = ANY ($1)",
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        (
            row.id,
            RunSnapshot {
                id: row.id,
                uuid: row.uuid,
                test_guid: row.test_guid,
                marker: row.marker,
                started_at: row.started_at,
                observation_ends_at: row.observation_ends_at,
                attribution_ends_at: row.attribution_ends_at,
                targets: Vec::new(),
                holds_host: row.holds_host,
            },
        )
    })
    .collect();
    for row in sqlx::query!(
        r#"SELECT t.run_id, t.host, t.fqdn, COALESCE(h.ips, '{}') AS "ips!"
           FROM svs.run_targets t
           LEFT JOIN svs.test_hosts h ON h.id = t.test_host_id
           WHERE t.run_id = ANY ($1) ORDER BY t.id"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        if let Some(run) = runs.get_mut(&row.run_id) {
            run.targets.push(TargetSnapshot {
                host: row.host,
                fqdn: row.fqdn,
                ips: row.ips.into_iter().collect(),
            });
        }
    }
    Ok(runs.into_values().collect())
}

/// The run of each marker that has one: ace3's `resolve_markers`, always from the database.
pub async fn resolve_markers(
    conn: &mut PgConnection,
    markers: &[String],
) -> Result<BTreeMap<String, RunSnapshot>, DbError> {
    if markers.is_empty() {
        return Ok(BTreeMap::new());
    }
    let ids = sqlx::query_scalar!("SELECT id FROM svs.runs WHERE marker = ANY ($1)", markers)
        .fetch_all(&mut *conn)
        .await?;
    Ok(snapshots(conn, &ids)
        .await?
        .into_iter()
        .map(|run| (run.marker.clone(), run))
        .collect())
}

fn names_and_ips(hosts: &[&EventHosts]) -> (Vec<String>, Vec<String>) {
    let names: BTreeSet<String> = hosts
        .iter()
        .flat_map(|hosts| hosts.names.iter().map(|(short, _)| short.clone()))
        .collect();
    let ips: BTreeSet<String> = hosts
        .iter()
        .flat_map(|hosts| hosts.ips.iter().cloned())
        .collect();
    (names.into_iter().collect(), ips.into_iter().collect())
}

/// The runs on any of `hosts` whose attribution window overlaps `start` to `end`, in id order: ace3's
/// `runs_overlapping`, narrowed to the hosts asked about, and to the [`MAX_RUNS_CONSIDERED`] latest
/// started.
pub async fn runs_overlapping(
    conn: &mut PgConnection,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hosts: &[&EventHosts],
) -> Result<Vec<RunSnapshot>, DbError> {
    let (names, ips) = names_and_ips(hosts);
    if names.is_empty() && ips.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = sqlx::query_scalar!(
        "SELECT r.id FROM svs.runs r
         WHERE r.started_at <= $2 AND r.attribution_ends_at >= $1
           AND EXISTS (SELECT FROM svs.run_targets t
                       LEFT JOIN svs.test_hosts h ON h.id = t.test_host_id
                       WHERE t.run_id = r.id AND (t.host = ANY ($3) OR h.ips && $4))
         ORDER BY r.started_at DESC, r.id DESC LIMIT $5",
        start,
        end,
        &names,
        &ips,
        MAX_RUNS_CONSIDERED + 1,
    )
    .fetch_all(&mut *conn)
    .await?;
    if ids.len() as i64 > MAX_RUNS_CONSIDERED {
        ids.truncate(MAX_RUNS_CONSIDERED as usize);
        tracing::warn!(
            hosts = ?names,
            "more than {MAX_RUNS_CONSIDERED} svs runs on these hosts overlap an event; the latest started are considered"
        );
    }
    snapshots(conn, &ids).await
}

/// The maintenance windows on any of `hosts` open at some time from `start` to `end`, in id order:
/// ace3's `maintenance_windows_overlapping`, narrowed to the hosts asked about.
pub async fn maintenance_windows_overlapping(
    conn: &mut PgConnection,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hosts: &[&EventHosts],
) -> Result<Vec<MaintenanceSnapshot>, DbError> {
    let (names, ips) = names_and_ips(hosts);
    if names.is_empty() && ips.is_empty() {
        return Ok(Vec::new());
    }
    let mut rows = sqlx::query!(
        r#"SELECT w.id, w.uuid, w.host, w.fqdn, w.opened_at,
                  COALESCE(w.ended_at, w.ends_at) AS "ends_at!", COALESCE(h.ips, '{}') AS "ips!"
           FROM svs.maintenance_windows w
           LEFT JOIN svs.test_hosts h ON h.id = w.test_host_id
           WHERE w.ends_at >= $1 AND w.opened_at <= $2 AND (w.ended_at IS NULL OR w.ended_at >= $1)
             AND (w.host = ANY ($3) OR h.ips && $4)
           ORDER BY w.id DESC LIMIT $5"#,
        start,
        end,
        &names,
        &ips,
        MAX_WINDOWS_CONSIDERED + 1,
    )
    .fetch_all(conn)
    .await?;
    if rows.len() as i64 > MAX_WINDOWS_CONSIDERED {
        rows.truncate(MAX_WINDOWS_CONSIDERED as usize);
        tracing::warn!(
            hosts = ?names,
            "more than {MAX_WINDOWS_CONSIDERED} svs maintenance windows on these hosts overlap an event; the latest are considered"
        );
    }
    rows.reverse();
    Ok(rows
        .into_iter()
        .map(|row| MaintenanceSnapshot {
            id: row.id,
            uuid: row.uuid,
            target: TargetSnapshot {
                host: row.host,
                fqdn: row.fqdn,
                ips: row.ips.into_iter().collect(),
            },
            opened_at: row.opened_at,
            ends_at: row.ends_at,
        })
        .collect())
}

//
// who owns an event
//

/// The one run that can claim an event by context among the runs whose windows cover its time on one of
/// its hosts: the only one, or the latest started when every other one's claim on its hosts ended before
/// that start. Registration keeps a run from starting on a host another run still holds, and a test that
/// leaves nothing behind causes nothing after its claim ends, so the latest run is the one that was on
/// the host. None when the claims overlap. ace3's `context_claimant`.
pub fn context_claimant(candidates: &[RunSnapshot]) -> Option<&RunSnapshot> {
    if candidates.len() <= 1 {
        return candidates.first();
    }
    let latest = latest_started(candidates)?;
    let started = latest.started_at?;
    candidates
        .iter()
        .filter(|run| run.id != latest.id)
        .all(|run| run.claim_ends_at().is_some_and(|ends| ends < started))
        .then_some(latest)
}

fn latest_started(candidates: &[RunSnapshot]) -> Option<&RunSnapshot> {
    candidates.iter().max_by_key(|run| (run.started_at, run.id))
}

/// Who an event with no marker belongs to by its hosts and time: a run, a maintenance window, or nobody.
/// ace3's `ContextOwner`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextOwner {
    /// The run context attribution gives it to ([`context_claimant`]).
    pub run: Option<RunSnapshot>,
    /// The runs whose attribution window covers it on one of its hosts.
    pub candidates: Vec<RunSnapshot>,
    /// The maintenance window it happened in; no run owns it then.
    pub maintenance: Option<MaintenanceSnapshot>,
}

/// The run or maintenance window that keys a grouped hunt's suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionOwner<'a> {
    Run(&'a RunSnapshot),
    Maintenance(&'a MaintenanceSnapshot),
}

impl SuppressionOwner<'_> {
    pub fn uuid(&self) -> Uuid {
        match self {
            SuppressionOwner::Run(run) => run.uuid,
            SuppressionOwner::Maintenance(window) => window.uuid,
        }
    }

    /// The key a grouped hunt's suppression of `group_value` is recorded under during a run or a
    /// maintenance window, so the first match of each alerts, and neither a test nor a host's staging
    /// ever suppresses production or a run. ace3's `suppression_key`.
    pub fn key(&self, group_value: &str) -> String {
        let kind = match self {
            SuppressionOwner::Run(_) => "svs_run",
            SuppressionOwner::Maintenance(_) => "svs_maintenance",
        };
        format!("{kind}:{}:{group_value}", self.uuid())
    }
}

impl ContextOwner {
    /// The run or maintenance window that keys the suppression of a grouped hunt's match: the one
    /// context attribution would give it to, or the latest started of the runs that could claim it
    /// when their claims overlap. ace3's `suppression_owners`, for one event.
    pub fn suppression_owner(&self) -> Option<SuppressionOwner<'_>> {
        if let Some(window) = &self.maintenance {
            return Some(SuppressionOwner::Maintenance(window));
        }
        self.run
            .as_ref()
            .or_else(|| latest_started(&self.candidates))
            .map(SuppressionOwner::Run)
    }

    /// The runs a dropped match is recorded for: the one context attribution would give it to, or each
    /// of the candidates when their claims overlap, since none can be told apart.
    pub fn suppressed_for(&self) -> Vec<&RunSnapshot> {
        match &self.run {
            Some(run) => vec![run],
            None => self.candidates.iter().collect(),
        }
    }
}

/// The owner of each event: **the one decision** (the module docs). Attribution's context, a grouped
/// hunt's suppression keys and its dropped matches all ask here, in their own transaction, so they can't
/// disagree. Two queries for all the events, each narrowed to the events' hosts. ace3's `context_owners`.
pub async fn context_owners(
    conn: &mut PgConnection,
    events: &[Event],
) -> Result<Vec<ContextOwner>, DbError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    if events.len() > MAX_EVENTS {
        return Err(DbError::Decode(format!(
            "svs was asked who owns {} events at once, more than {MAX_EVENTS}",
            events.len()
        )));
    }
    let start = events.iter().map(|event| event.time).min().expect("some");
    let end = events.iter().map(|event| event.time).max().expect("some");
    let hosts: Vec<&EventHosts> = events.iter().map(|event| &event.hosts).collect();
    let runs = runs_overlapping(conn, start, end, &hosts).await?;
    let windows = maintenance_windows_overlapping(conn, start, end, &hosts).await?;
    Ok(events
        .iter()
        .map(|event| {
            let candidates: Vec<RunSnapshot> = runs
                .iter()
                .filter(|run| run.in_window(event.time) && event.hosts.involves_run(run))
                .cloned()
                .collect();
            let window = windows
                .iter()
                .find(|window| window.covers(event.time) && event.hosts.involves(&window.target));
            // no run holds a host while a window on it is open, so a run still holding one of the
            // event's hosts holds another one, and the event is the run's. A run whose late attribution
            // window still covers the event ended its claim before the window opened: what happened in
            // the window is the window's.
            match window {
                Some(window) if !candidates.iter().any(|run| run.holds_host_at(event.time)) => {
                    ContextOwner {
                        maintenance: Some(window.clone()),
                        ..ContextOwner::default()
                    }
                }
                _ => ContextOwner {
                    run: context_claimant(&candidates).cloned(),
                    candidates,
                    maintenance: None,
                },
            }
        })
        .collect())
}

//
// evaluation
//

/// A detection of the alert, other than the SVS built-ins'.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub id: i64,
    /// The observable it is on, None for the root.
    pub carrier: Option<i64>,
    pub signature_uuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerJudgement {
    pub marker: String,
    pub result: MarkerResult,
    /// Where the marker was first found.
    pub scan_point: ScanPoint,
    pub run: Option<RunSnapshot>,
}

/// One detection the hook attributes to a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub run: RunSnapshot,
    pub detection: i64,
    pub confidence: AttributionConfidence,
    pub late: bool,
    pub scan_point: Option<ScanPoint>,
}

/// A row of `svs.attributions` the hook doesn't own: a person's association, or a removal a person made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAttribution {
    pub run_id: i64,
    pub detection: i64,
    pub confidence: AttributionConfidence,
    pub removed: bool,
}

/// What attribution makes of an alert: ace3's `Evaluation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub status: Option<SvsStatus>,
    pub detections: Vec<Detection>,
    pub judgements: Vec<MarkerJudgement>,
    /// What the hook attributes; a person's rows are in `existing`.
    pub attributions: Vec<Attribution>,
    pub existing: Vec<ExistingAttribution>,
    /// Set when a context attribution was refused because more than one run could claim the alert.
    pub candidate_runs: Vec<RunSnapshot>,
    /// The event time it was judged by and where that came from, kept on each attribution.
    pub event_time: DateTime<Utc>,
    pub event_time_source: TimeSource,
    /// It has no marker and no attribution, and its event time is in a maintenance window on one of its
    /// hosts.
    pub maintenance: Option<MaintenanceSnapshot>,
}

impl Evaluation {
    fn of(event: &Event) -> Evaluation {
        Evaluation {
            status: None,
            detections: Vec::new(),
            judgements: Vec::new(),
            attributions: Vec::new(),
            existing: Vec::new(),
            candidate_runs: Vec::new(),
            event_time: event.time,
            event_time_source: event.source,
            maintenance: None,
        }
    }

    pub fn mismatches(&self) -> impl Iterator<Item = &MarkerJudgement> {
        self.judgements
            .iter()
            .filter(|judgement| judgement.result != MarkerResult::Attributed)
    }

    /// The runs it attributes to, in the order they first appear.
    pub fn runs(&self) -> Vec<&RunSnapshot> {
        let mut runs: Vec<&RunSnapshot> = Vec::new();
        for attribution in &self.attributions {
            if !runs.iter().any(|run| run.id == attribution.run.id) {
                runs.push(&attribution.run);
            }
        }
        runs
    }

    pub fn confidence(&self) -> Option<AttributionConfidence> {
        if self.attributions.is_empty() {
            return None;
        }
        Some(
            if self
                .attributions
                .iter()
                .all(|a| a.confidence == AttributionConfidence::Context)
            {
                AttributionConfidence::Context
            } else {
                AttributionConfidence::Marker
            },
        )
    }

    /// Every detection is attributed: the alert belongs in the test queue.
    pub fn routed(&self) -> bool {
        matches!(self.status, Some(SvsStatus::Test | SvsStatus::TestContext))
    }
}

/// Which observables are above which: a parent map over the tree. An observable can have more than one
/// parent, and a tree can have cycles. ace3's `_Branches`.
#[derive(Debug, Default)]
struct Branches {
    parents: HashMap<i64, BTreeSet<i64>>,
    ancestors: HashMap<i64, BTreeSet<i64>>,
}

impl Branches {
    async fn load(conn: &mut PgConnection, root: Uuid) -> Result<Branches, DbError> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT r.observable_id AS parent, a.observable_id AS child
               FROM analysis.result_additions a
               JOIN analysis.results r ON r.id = a.result_id
               WHERE a.root_id = $1 AND NOT a.ignored AND r.observable_id <> a.observable_id
               LIMIT $2"#,
            root,
            MAX_BRANCH_EDGES + 1,
        )
        .fetch_all(conn)
        .await?;
        if rows.len() as i64 > MAX_BRANCH_EDGES {
            tracing::warn!(
                alert_uuid = %root,
                "the alert's tree has more than {MAX_BRANCH_EDGES} edges; svs places markers by the first"
            );
        }
        let mut branches = Branches::default();
        for row in rows.into_iter().take(MAX_BRANCH_EDGES as usize) {
            branches
                .parents
                .entry(row.child)
                .or_default()
                .insert(row.parent);
        }
        Ok(branches)
    }

    fn ancestors(&mut self, node: i64) -> &BTreeSet<i64> {
        if !self.ancestors.contains_key(&node) {
            let mut seen = BTreeSet::new();
            let mut pending: Vec<i64> = self
                .parents
                .get(&node)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            while let Some(current) = pending.pop() {
                if !seen.insert(current) {
                    continue;
                }
                pending.extend(self.parents.get(&current).into_iter().flatten().copied());
            }
            seen.remove(&node);
            self.ancestors.insert(node, seen);
        }
        &self.ancestors[&node]
    }

    /// `a` and `b` are on one branch: one of them is the root, they are the same observable, or one is
    /// above the other.
    fn same_branch(&mut self, a: Option<i64>, b: Option<i64>) -> bool {
        let (Some(a), Some(b)) = (a, b) else {
            return true;
        };
        a == b || self.ancestors(b).contains(&a) || self.ancestors(a).contains(&b)
    }
}

/// Every marker in the alert: its observables' values and its files' names, its detections, its details,
/// and its results' details. ace3's `tree_sightings`, with its saved sightings read from the results.
pub async fn tree_sightings(conn: &mut PgConnection, root: Uuid) -> Result<Vec<Sighting>, DbError> {
    let mut sightings: Vec<Sighting> = Vec::new();
    for row in sqlx::query!(
        "SELECT id, value FROM analysis.observables
         WHERE root_id = $1 AND value ~* $2 ORDER BY id LIMIT $3",
        root,
        MARKER_SQL,
        MAX_MARKED_ROWS,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        for marker in find_markers(&row.value) {
            sightings.push(Sighting::new(&marker, Some(row.id), ScanPoint::Observable));
        }
    }
    for row in sqlx::query!(
        r#"SELECT observable_id, path FROM analysis.files
           WHERE root_id = $1 AND path ~* $2 ORDER BY observable_id, path COLLATE "C" LIMIT $3"#,
        root,
        MARKER_SQL,
        MAX_MARKED_ROWS,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        for marker in find_markers(&row.path) {
            sightings.push(Sighting::new(
                &marker,
                Some(row.observable_id),
                ScanPoint::Observable,
            ));
        }
    }
    for row in sqlx::query!(
        "SELECT observable_id, description, details FROM analysis.detections
         WHERE root_id = $1 AND (description ~* $2 OR details::text ~* $2) ORDER BY id LIMIT $3",
        root,
        MARKER_SQL,
        MAX_MARKED_ROWS,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let mut found = find_markers(&row.description);
        if let Some(details) = &row.details {
            keep(&mut found, find_markers_in_data(details));
        }
        for marker in found {
            sightings.push(Sighting::new(
                &marker,
                row.observable_id,
                ScanPoint::Detection,
            ));
        }
    }
    let details = sqlx::query_scalar!(
        r#"SELECT CASE WHEN (origin -> 'details')::text ~* $2 THEN origin -> 'details' END AS details
           FROM analysis.roots WHERE id = $1"#,
        root,
        MARKER_SQL,
    )
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    if let Some(details) = details {
        for marker in find_markers_in_data(&details) {
            sightings.push(Sighting::new(&marker, None, ScanPoint::RootDetails));
        }
    }
    let mut saved: Vec<Sighting> = Vec::new();
    for row in sqlx::query!(
        r#"SELECT observable_id, module, details AS "details!" FROM analysis.results
           WHERE root_id = $1 AND details IS NOT NULL
             AND (details::text ~* $2 OR details @> $3)
           ORDER BY id LIMIT $4"#,
        root,
        MARKER_SQL,
        json!({"scan_results": [{"rule": MARKER_RULE_NAME}]}),
        MAX_MARKED_ROWS,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let found = analysis_sightings(&row.details, Some(row.observable_id), Some(&row.module));
        keep_sightings(&mut saved, found, MAX_SIGHTINGS);
        if saved.len() >= MAX_SIGHTINGS {
            break;
        }
    }
    sightings.extend(saved);
    let mut distinct: Vec<Sighting> = Vec::with_capacity(sightings.len());
    for sighting in sightings {
        if !distinct.contains(&sighting) {
            distinct.push(sighting);
        }
    }
    Ok(distinct)
}

/// The alert's detections, except those of the SVS built-ins (`RUN_SIGNATURES`), in id order: ace3's
/// `alert_detections`. None when it has more than [`MAX_DETECTIONS`].
pub async fn alert_detections(
    conn: &mut PgConnection,
    root: Uuid,
) -> Result<Option<Vec<Detection>>, DbError> {
    let builtins: Vec<String> = RUN_SIGNATURES.iter().map(|s| (*s).to_owned()).collect();
    let rows = sqlx::query!(
        "SELECT id, observable_id, signature_uuid FROM analysis.detections
         WHERE root_id = $1 AND (signature_uuid IS NULL OR signature_uuid <> ALL ($2))
         ORDER BY id LIMIT $3",
        root,
        &builtins,
        MAX_DETECTIONS + 1,
    )
    .fetch_all(conn)
    .await?;
    if rows.len() as i64 > MAX_DETECTIONS {
        return Ok(None);
    }
    Ok(Some(
        rows.into_iter()
            .map(|row| Detection {
                id: row.id,
                carrier: row.observable_id,
                signature_uuid: row.signature_uuid,
            })
            .collect(),
    ))
}

/// A `service.actor` that is a person's: a user or an API key, not one of ACE's components.
fn is_person(actor: Option<&Value>) -> bool {
    actor
        .and_then(|actor| actor.get("kind"))
        .and_then(Value::as_str)
        .is_some_and(|kind| kind != "internal")
}

fn confidence_of(text: &str) -> Result<AttributionConfidence, DbError> {
    AttributionConfidence::parse(text)
        .ok_or_else(|| DbError::Decode(format!("attribution confidence {text:?}")))
}

/// Why a root can't be judged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotJudged {
    #[error("the alert has more than {MAX_DETECTIONS} detections")]
    TooManyDetections,
}

/// Judges every marker in the alert against its run and attributes its detections, by `event`'s hosts and
/// time. Reads the database, writes nothing; the caller checks the gate first. ace3's `evaluate`.
pub async fn evaluate(
    conn: &mut PgConnection,
    root: Uuid,
    event: &Event,
) -> Result<Result<Evaluation, NotJudged>, DbError> {
    let mut evaluation = Evaluation::of(event);
    let Some(detections) = alert_detections(conn, root).await? else {
        return Ok(Err(NotJudged::TooManyDetections));
    };
    evaluation.detections = detections;
    let sightings = tree_sightings(conn, root).await?;

    let mut first_scan_point: Vec<(String, ScanPoint)> = Vec::new();
    let mut left_out = 0usize;
    for sighting in &sightings {
        if first_scan_point.iter().any(|(m, _)| *m == sighting.marker) {
            continue;
        }
        if first_scan_point.len() >= MAX_MARKERS {
            left_out += 1;
            continue;
        }
        first_scan_point.push((sighting.marker.clone(), sighting.scan_point));
    }
    if left_out > 0 {
        tracing::warn!(
            alert_uuid = %root,
            "the alert holds more than {MAX_MARKERS} svs markers; the first are judged"
        );
    }
    let markers: Vec<String> = first_scan_point.iter().map(|(m, _)| m.clone()).collect();
    let resolved = resolve_markers(conn, &markers).await?;
    for (marker, scan_point) in first_scan_point {
        let run = resolved.get(&marker);
        let result = match run {
            None => MarkerResult::Unknown,
            Some(run) if !event.hosts.involves_run(run) => MarkerResult::OtherHost,
            Some(run) if !run.in_window(event.time) => MarkerResult::OutsideWindow,
            Some(_) => MarkerResult::Attributed,
        };
        evaluation.judgements.push(MarkerJudgement {
            marker,
            result,
            scan_point,
            run: run.cloned(),
        });
    }

    // a person's rows: the (run, detection) pairs the hook leaves alone, and the runs a person
    // disassociated the alert from, which it never attributes it to again, for any detection
    let mut blocked: BTreeSet<(i64, i64)> = BTreeSet::new();
    let mut disassociated: BTreeSet<i64> = BTreeSet::new();
    let mut associated: BTreeSet<i64> = BTreeSet::new();
    for row in sqlx::query!(
        r#"SELECT run_id, detection_id, confidence::text AS "confidence!", source, removed_at,
                  removed_by AS "removed_by: Value"
           FROM svs.attributions WHERE root_id = $1 ORDER BY id"#,
        root,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let manual = row.source == "manual";
        let removed_by_person = row.removed_at.is_some() && is_person(row.removed_by.as_ref());
        if manual && row.removed_at.is_none() {
            associated.insert(row.run_id);
        }
        if manual || removed_by_person {
            evaluation.existing.push(ExistingAttribution {
                run_id: row.run_id,
                detection: row.detection_id,
                confidence: confidence_of(&row.confidence)?,
                removed: row.removed_at.is_some(),
            });
            blocked.insert((row.run_id, row.detection_id));
            if removed_by_person {
                disassociated.insert(row.run_id);
            }
        }
    }
    let disassociated: BTreeSet<i64> = disassociated.difference(&associated).copied().collect();

    if evaluation.mismatches().next().is_some() {
        // a marker that doesn't agree ends attribution for the whole alert
        evaluation.status = Some(SvsStatus::Mismatch);
        return Ok(Ok(evaluation));
    }
    if evaluation.detections.is_empty() {
        return Ok(Ok(evaluation));
    }

    let mut attributions: BTreeMap<(i64, i64), Attribution> = BTreeMap::new();
    let mut order: Vec<(i64, i64)> = Vec::new();
    if !evaluation.judgements.is_empty() {
        let mut branches = Branches::load(conn, root).await?;
        for judgement in &evaluation.judgements {
            let Some(run) = &judgement.run else { continue };
            if disassociated.contains(&run.id) {
                continue;
            }
            for sighting in sightings.iter().filter(|s| s.marker == judgement.marker) {
                for detection in &evaluation.detections {
                    let key = (run.id, detection.id);
                    if attributions.contains_key(&key) || blocked.contains(&key) {
                        continue;
                    }
                    if branches.same_branch(sighting.node, detection.carrier) {
                        order.push(key);
                        attributions.insert(
                            key,
                            Attribution {
                                run: run.clone(),
                                detection: detection.id,
                                confidence: AttributionConfidence::Marker,
                                late: run.is_late(event.time),
                                scan_point: Some(sighting.scan_point),
                            },
                        );
                    }
                }
            }
        }
    } else {
        let owner = context_owners(conn, std::slice::from_ref(event))
            .await?
            .pop()
            .unwrap_or_default();
        // a person's association still holds
        if let Some(window) = owner.maintenance
            && evaluation.existing.iter().all(|row| row.removed)
        {
            evaluation.maintenance = Some(window);
            return Ok(Ok(evaluation));
        }
        match owner.run {
            Some(run) if !disassociated.contains(&run.id) => {
                for detection in &evaluation.detections {
                    let key = (run.id, detection.id);
                    if !blocked.contains(&key) {
                        order.push(key);
                        attributions.insert(
                            key,
                            Attribution {
                                run: run.clone(),
                                detection: detection.id,
                                confidence: AttributionConfidence::Context,
                                late: run.is_late(event.time),
                                scan_point: None,
                            },
                        );
                    }
                }
            }
            // attributing to the wrong run teaches the wrong expectation
            None if owner.candidates.len() > 1 => evaluation.candidate_runs = owner.candidates,
            _ => {}
        }
    }
    evaluation.attributions = order
        .iter()
        .filter_map(|key| attributions.remove(key))
        .collect();

    let mut confidences: BTreeMap<i64, BTreeSet<AttributionConfidence>> = BTreeMap::new();
    for attribution in &evaluation.attributions {
        confidences
            .entry(attribution.detection)
            .or_default()
            .insert(attribution.confidence);
    }
    for row in evaluation.existing.iter().filter(|row| !row.removed) {
        confidences
            .entry(row.detection)
            .or_default()
            .insert(row.confidence);
    }
    evaluation.status = derive_status(evaluation.detections.iter().map(|d| d.id), &confidences);
    Ok(Ok(evaluation))
}

//
// writing
//

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedAttribution {
    pub run_id: i64,
    pub detection: i64,
    pub confidence: AttributionConfidence,
    pub late: bool,
}

/// What a write changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteResult {
    pub written: Vec<Attribution>,
    pub removed: Vec<RemovedAttribution>,
    /// The alert had no rows of the hook's before this write: its first attribution.
    pub first: bool,
    /// The reviewed runs it marked changed since review.
    pub flagged: Vec<i64>,
}

/// Marks the runs' live results stale, in run id order, so two writers lock the rows in the same order:
/// ace3's `mark_runs_stale` for given runs. A run with no result yet (not started, canceled, closed) is
/// left alone.
pub async fn mark_runs_stale(conn: &mut PgConnection, runs: &[i64]) -> Result<(), sqlx::Error> {
    if runs.is_empty() {
        return Ok(());
    }
    sqlx::query!(
        "INSERT INTO svs.run_result_state (run_id, generation, stale)
         SELECT id, 1, true FROM svs.runs
         WHERE id = ANY ($1) AND state IN ('started', 'ended', 'reviewed')
         ORDER BY id
         ON CONFLICT (run_id) DO UPDATE
         SET generation = svs.run_result_state.generation + 1, stale = true",
        runs,
    )
    .execute(conn)
    .await?;
    Ok(())
}

async fn add_event(
    conn: &mut PgConnection,
    run: i64,
    kind: &str,
    details: Value,
    now: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO svs.run_events (run_id, kind, actor, details, created_at)
         VALUES ($1, $2, $3::jsonb, $4, $5)",
        run,
        kind,
        router_actor(),
        details,
        now,
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Brings the hook's rows for the alert in line with the evaluation, in the caller's transaction: adds
/// new ones, restores ones it removed earlier, and removes the ones that no longer hold. A person's rows
/// are never touched, and every change to an existing row is conditional on it still being the hook's.
/// Each change is in its run's event log, a change to a reviewed run marks the run changed since review,
/// and every change marks the run's result stale. The runs a write can touch are locked first, in id
/// order, so alerts of one run written at once wait their turn, and lateness is judged by each run's
/// observation window as it is then: a person may have ended the run early since the evaluation read it.
/// ace3's `write_attributions`.
pub async fn write_attributions(
    conn: &mut PgConnection,
    root: Uuid,
    evaluation: &Evaluation,
    now: DateTime<Utc>,
) -> Result<WriteResult, DbError> {
    let mut result = WriteResult::default();
    let wanted: Vec<i64> = evaluation
        .attributions
        .iter()
        .map(|a| a.run.id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let observation_ends: HashMap<i64, Option<DateTime<Utc>>> = sqlx::query!(
        "SELECT id, observation_ends_at FROM svs.runs
         WHERE id = ANY ($1) OR id IN (SELECT run_id FROM svs.attributions WHERE root_id = $2)
         ORDER BY id FOR UPDATE",
        &wanted,
        root,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| (row.id, row.observation_ends_at))
    .collect();

    let mut desired: BTreeMap<(i64, i64), Attribution> = BTreeMap::new();
    let mut order: Vec<(i64, i64)> = Vec::new();
    for attribution in &evaluation.attributions {
        // a run that's gone since the evaluation read it takes nothing
        let Some(ends) = observation_ends.get(&attribution.run.id) else {
            continue;
        };
        let mut attribution = attribution.clone();
        attribution.late = (*ends).is_some_and(|ends| evaluation.event_time > ends);
        let key = (attribution.run.id, attribution.detection);
        order.push(key);
        desired.insert(key, attribution);
    }
    let rows = sqlx::query!(
        r#"SELECT id, run_id, detection_id, confidence::text AS "confidence!", late, scan_point,
                  event_time, event_time_source, source, removed_at,
                  removed_by AS "removed_by: Value"
           FROM svs.attributions WHERE root_id = $1 ORDER BY id"#,
        root,
    )
    .fetch_all(&mut *conn)
    .await?;
    let source = evaluation.event_time_source.as_str();
    let mut known: BTreeSet<(i64, i64)> = BTreeSet::new();
    for row in &rows {
        let key = (row.run_id, row.detection_id);
        known.insert(key);
        if row.source != "router"
            || (row.removed_at.is_some() && is_person(row.removed_by.as_ref()))
        {
            continue;
        }
        let Some(attribution) = desired.get(&key) else {
            if row.removed_at.is_none() {
                // only while it still is the hook's and holds: a person may have taken it since
                let removed = sqlx::query!(
                    "UPDATE svs.attributions
                     SET removed_at = $2, removed_by = $3::jsonb, removal_reason = $4
                     WHERE id = $1 AND source = 'router' AND removed_at IS NULL",
                    row.id,
                    now,
                    router_actor(),
                    REMOVAL_NO_LONGER_APPLIES,
                )
                .execute(&mut *conn)
                .await?
                .rows_affected();
                if removed == 1 {
                    result.removed.push(RemovedAttribution {
                        run_id: row.run_id,
                        detection: row.detection_id,
                        confidence: confidence_of(&row.confidence)?,
                        late: row.late,
                    });
                }
            }
            continue;
        };
        let scan_point = attribution.scan_point.map(ScanPoint::as_str);
        let same = row.removed_at.is_none()
            && row.confidence == attribution.confidence.as_str()
            && row.late == attribution.late
            && row.scan_point.as_deref() == scan_point
            && row.event_time == Some(evaluation.event_time)
            && row.event_time_source.as_deref() == Some(source);
        if same {
            continue;
        }
        let changed = sqlx::query!(
            "UPDATE svs.attributions
             SET removed_at = NULL, removed_by = NULL, removal_reason = NULL,
                 confidence = $2::text::svs.attribution_confidence, late = $3, scan_point = $4,
                 event_time = $5, event_time_source = $6
             WHERE id = $1 AND source = 'router'
               AND (removed_by IS NULL OR removed_by ->> 'kind' = 'internal')",
            row.id,
            attribution.confidence.as_str(),
            attribution.late,
            scan_point,
            evaluation.event_time,
            source,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if changed == 1 {
            result.written.push(attribution.clone());
        }
    }
    for key in &order {
        if known.contains(key) {
            continue;
        }
        let attribution = &desired[key];
        // another writer may have the same alert (a person associating it); the unique key keeps the
        // row that came first
        let inserted = sqlx::query!(
            "INSERT INTO svs.attributions
                 (run_id, root_id, detection_id, confidence, late, event_time, event_time_source,
                  source, scan_point, actor, created_at)
             VALUES ($1, $2, $3, $4::text::svs.attribution_confidence, $5, $6, $7, 'router', $8,
                     $9::jsonb, $10)
             ON CONFLICT ON CONSTRAINT attributions_are_unique DO NOTHING",
            attribution.run.id,
            root,
            attribution.detection,
            attribution.confidence.as_str(),
            attribution.late,
            evaluation.event_time,
            source,
            attribution.scan_point.map(ScanPoint::as_str),
            router_actor(),
            now,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if inserted == 1 {
            result.written.push(attribution.clone());
        }
    }
    result.first = !result.written.is_empty() && rows.iter().all(|row| row.source != "router");

    // one event per run whose attributions of the alert changed, in the run's event log
    let mut written: BTreeMap<i64, Vec<Value>> = BTreeMap::new();
    for attribution in &result.written {
        written.entry(attribution.run.id).or_default().push(json!({
            "detection": attribution.detection,
            "confidence": attribution.confidence.as_str(),
            "late": attribution.late,
            "scan_point": attribution.scan_point.map(ScanPoint::as_str),
        }));
    }
    for (run, detections) in &written {
        add_event(
            conn,
            *run,
            "attributed",
            json!({"alert_uuid": root, "detections": detections}),
            now,
        )
        .await?;
    }
    let mut removed: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for row in &result.removed {
        removed.entry(row.run_id).or_default().push(row.detection);
    }
    for (run, detections) in &removed {
        add_event(
            conn,
            *run,
            "attribution_removed",
            json!({"alert_uuid": root, "detections": detections,
                   "reason": REMOVAL_NO_LONGER_APPLIES}),
            now,
        )
        .await?;
    }
    let touched: Vec<i64> = written
        .keys()
        .chain(removed.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !touched.is_empty() {
        // a late alert after sign-off returns the run to Needs attention
        result.flagged = sqlx::query_scalar!(
            "UPDATE svs.runs SET changed_since_review = true
             WHERE id = ANY ($1) AND state = 'reviewed' AND NOT changed_since_review
             RETURNING id",
            &touched,
        )
        .fetch_all(&mut *conn)
        .await?;
        result.flagged.sort_unstable();
        mark_runs_stale(conn, &touched).await?;
    }

    for attribution in &result.written {
        tracing::info!(
            svs_run = %attribution.run.uuid, svs_test = %attribution.run.test_guid,
            svs_marker = %attribution.run.marker, alert_uuid = %root,
            detection = attribution.detection, confidence = attribution.confidence.as_str(),
            late = attribution.late, source = "router",
            scan_point = attribution.scan_point.map(ScanPoint::as_str),
            "svs attribution written"
        );
    }
    for row in &result.removed {
        tracing::info!(
            svs_run_id = row.run_id, alert_uuid = %root, detection = row.detection,
            confidence = row.confidence.as_str(), late = row.late, source = "router",
            reason = REMOVAL_NO_LONGER_APPLIES,
            "svs attribution removed"
        );
    }
    for run in &result.flagged {
        tracing::info!(svs_run_id = run, alert_uuid = %root, "svs run changed since review");
    }
    Ok(result)
}

/// Brings the alert's maintenance record in line with the judgment: recorded for `window` while it is
/// judged maintenance, after which the timers may close it (batch 7), else removed so they leave it
/// alone. A record the timers closed is never changed. ace3's `maintenance.record_alert`, always
/// confirmed (the module docs). Returns whether a record was removed.
pub async fn record_maintenance_alert(
    conn: &mut PgConnection,
    root: Uuid,
    window: Option<i64>,
    now: DateTime<Utc>,
) -> Result<bool, DbError> {
    let removed = sqlx::query!(
        "UPDATE svs.maintenance_alerts SET removed_at = $3
         WHERE root_id = $1 AND removed_at IS NULL AND closed_at IS NULL
           AND ($2::bigint IS NULL OR window_id <> $2)",
        root,
        window,
        now,
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if removed > 0 {
        tracing::info!(alert_uuid = %root, "svs alert is no longer in a maintenance window");
    }
    if let Some(window) = window {
        sqlx::query!(
            "INSERT INTO svs.maintenance_alerts (window_id, root_id, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT ON CONSTRAINT maintenance_alerts_are_unique DO UPDATE
             SET removed_at = NULL
             WHERE svs.maintenance_alerts.closed_at IS NULL
               AND svs.maintenance_alerts.removed_at IS NOT NULL",
            window,
            root,
            now,
        )
        .execute(conn)
        .await?;
    }
    Ok(removed > 0)
}

//
// the hook
//

/// What the hook needs of the overlay's `svs.runs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookConfig {
    /// `svs.runs.attribution_extra_hours`: how long after a maintenance window an alert of it may come.
    pub attribution_extra: TimeDelta,
}

impl Default for HookConfig {
    /// ace3's default.
    fn default() -> Self {
        HookConfig {
            attribution_extra: TimeDelta::hours(24),
        }
    }
}

/// What the hook made of a root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {
    pub status: Option<SvsStatus>,
    /// The maintenance window the alert belongs to.
    pub maintenance: Option<Uuid>,
    /// The attributions it wrote and removed.
    pub written: usize,
    pub removed: usize,
    /// It added a mismatch detection to the root.
    pub detected: bool,
    /// The root's tags after it, when it changed them.
    pub tags: Option<Vec<String>>,
}

fn log_sightings(root: Uuid, evaluation: &Evaluation) {
    for judgement in &evaluation.judgements {
        let run = judgement.run.as_ref().map(|run| run.uuid.to_string());
        if judgement.result == MarkerResult::Attributed {
            tracing::info!(
                svs_marker = %judgement.marker, alert_uuid = %root, svs_run = run.as_deref(),
                scan_point = judgement.scan_point.as_str(), result = judgement.result.as_str(),
                "svs marker in an alert"
            );
        } else {
            tracing::warn!(
                svs_marker = %judgement.marker, alert_uuid = %root, svs_run = run.as_deref(),
                scan_point = judgement.scan_point.as_str(), result = judgement.result.as_str(),
                "svs marker in an alert does not match its run"
            );
        }
    }
    if !evaluation.candidate_runs.is_empty() {
        let candidates: Vec<String> = evaluation
            .candidate_runs
            .iter()
            .map(|run| run.uuid.to_string())
            .collect();
        tracing::warn!(
            alert_uuid = %root, candidate_runs = ?candidates,
            "svs context attribution of an alert refused: {} runs could claim it", candidates.len()
        );
    }
}

/// The core's SVS hook: judges a root once, at the end of a pass, and writes everything that follows
/// from that one judgment, in the caller's transaction: its attributions, the `svs_test`,
/// `svs:marker_mismatch` and `svs:maintenance` tags on the root, a detection for each marker that
/// doesn't agree with its run, and its maintenance record. Tags and detections are idempotent, and
/// `svs_test` and `svs:maintenance` go when they stop holding. A mismatch is never taken back: its tag
/// stays, and its detection names the marker, so every later judgment finds the marker there and the
/// alert stays a mismatch, attributed to nothing, as in ace3, whose tagger's detection its router reads
/// the same way. None when nothing is judged: the gate is closed, or the root isn't an alert. ace3's
/// `SVSAlertTagger` and its marker router's judging, which ace3 runs apart.
pub async fn judge(
    conn: &mut PgConnection,
    root: Uuid,
    config: &HookConfig,
    now: DateTime<Utc>,
) -> Result<Option<Judged>, DbError> {
    if !gate_open(conn, now, config.attribution_extra).await? {
        return Ok(None);
    }
    let Some(event) = root_event(conn, root).await? else {
        return Ok(None);
    };
    let evaluation = match evaluate(conn, root, &event).await? {
        Ok(evaluation) => evaluation,
        Err(why) => {
            tracing::error!(alert_uuid = %root, "svs doesn't judge the alert: {why}");
            return Ok(None);
        }
    };
    log_sightings(root, &evaluation);
    let written = write_attributions(conn, root, &evaluation, now).await?;
    // a hunt that alerted on a test host, inside a run's or a maintenance window, without the event's
    // own time: it was judged by the time the hunt ran its query, which can put it in the wrong window.
    // Said once: as the alert is first judged (it hasn't been routed yet, ace3's PRE_INSERT), or at the
    // later pass that first attributes it, not on every pass that changes its attributions.
    let concerned = !evaluation.attributions.is_empty()
        || evaluation.maintenance.is_some()
        || !evaluation.candidate_runs.is_empty();
    if evaluation.event_time_source == TimeSource::QueryTime && concerned {
        let head = sqlx::query!(
            "SELECT left(description, 512) AS description, routed_pass
             FROM analysis.roots WHERE id = $1",
            root,
        )
        .fetch_one(&mut *conn)
        .await?;
        if written.first || head.routed_pass.is_none() {
            let hunts: BTreeSet<&str> = evaluation
                .detections
                .iter()
                .filter_map(|d| d.signature_uuid.as_deref())
                .collect();
            let run = evaluation.runs().first().map(|run| run.uuid.to_string());
            let window = evaluation
                .maintenance
                .as_ref()
                .map(|window| window.uuid.to_string());
            tracing::warn!(
                alert_uuid = %root, hunt = head.description.as_deref(), hunt_uuids = ?hunts,
                svs_run = run.as_deref(), svs_maintenance = window.as_deref(),
                stage = if head.routed_pass.is_none() { "alerted" } else { "analyzed" },
                event_time_source = "query_time",
                "a hunt alerted on an svs test host without the event's own time: the alert was judged by the time the hunt ran its query"
            );
        }
    }
    record_maintenance_alert(
        conn,
        root,
        evaluation.maintenance.as_ref().map(|window| window.id),
        now,
    )
    .await?;

    let mut judged = Judged {
        status: evaluation.status,
        maintenance: evaluation.maintenance.as_ref().map(|window| window.uuid),
        written: written.written.len(),
        removed: written.removed.len(),
        ..Judged::default()
    };
    let before = sqlx::query_scalar!(
        "SELECT tags FROM analysis.roots WHERE id = $1 FOR UPDATE",
        root
    )
    .fetch_one(&mut *conn)
    .await?;
    let mut tags = before.clone();
    let mut set = |tag: &str, on: bool, keep: bool| {
        let has = tags.iter().any(|t| t == tag);
        if on && !has {
            tags.push(tag.to_owned());
        } else if !on && has && !keep {
            tags.retain(|t| t != tag);
        }
    };
    let mismatch = evaluation.status == Some(SvsStatus::Mismatch);
    set(TAG_MARKER_MISMATCH, mismatch, true);
    set(TAG_SVS_TEST, evaluation.routed(), false);
    set(TAG_MAINTENANCE, evaluation.maintenance.is_some(), false);
    if tags != before {
        sqlx::query!(
            "UPDATE analysis.roots SET tags = $2 WHERE id = $1",
            root,
            &tags
        )
        .execute(&mut *conn)
        .await?;
        judged.tags = Some(tags);
    }
    if mismatch {
        for judgement in evaluation.mismatches() {
            let description = format!(
                "SVS test run marker {} does not match its run: {}",
                judgement.marker, judgement.result
            );
            let added = sqlx::query!(
                "INSERT INTO analysis.detections
                     (root_id, observable_id, description, details, signature_uuid, signature_family)
                 SELECT $1, NULL, $2, $3, $4, $5
                 WHERE NOT EXISTS (SELECT FROM analysis.detections d
                                   WHERE d.root_id = $1 AND d.observable_id IS NULL
                                     AND d.description = $2)",
                root,
                description,
                json!({"marker": judgement.marker, "result": judgement.result.as_str()}),
                MARKER_MISMATCH_SIGNATURE,
                FAMILY_BUILTIN,
            )
            .execute(&mut *conn)
            .await?
            .rows_affected();
            judged.detected |= added > 0;
        }
    }
    Ok(Some(judged))
}

//
// suppressed matches (the hunter)
//

/// A match a hunt dropped, with who owns its event ([`context_owners`]).
#[derive(Debug, Clone)]
pub struct DroppedMatch<'a> {
    pub owner: &'a ContextOwner,
    pub event_time: DateTime<Utc>,
    pub group_value: Option<String>,
    /// The key the hunter found it a duplicate of; None when the hunt's suppression dropped it.
    pub dedup_key: Option<String>,
}

/// A row of `svs.suppressed_matches` written now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSuppression {
    pub run: Uuid,
    pub run_id: i64,
    pub group_value: Option<String>,
    pub dedup_key: Option<String>,
    pub event_time: DateTime<Utc>,
}

/// Records the runs whose attribution window covers the event time of a match a hunt dropped, on one of
/// the run's test hosts, and marks their results stale: the first match per run and hunt
/// (`svs.suppressed_matches`), in the caller's transaction. A match goes to the run context attribution
/// would give it to, or to each of the runs when their claims on the host overlap; a match of a
/// maintenance window goes to no run. Nothing is written for a run and hunt already recorded. The runs
/// are locked first, in id order, as a write of attributions locks them. The caller checks the gate and
/// asks [`context_owners`]. ace3's `record_suppressed_matches`.
pub async fn record_suppressed_matches(
    conn: &mut PgConnection,
    hunt_uuid: &str,
    matches: &[DroppedMatch<'_>],
) -> Result<Vec<RecordedSuppression>, DbError> {
    let mut by_time: Vec<&DroppedMatch<'_>> = matches.iter().collect();
    by_time.sort_by_key(|dropped| dropped.event_time);
    let mut first: BTreeMap<i64, (&RunSnapshot, &DroppedMatch<'_>)> = BTreeMap::new();
    for dropped in by_time {
        for run in dropped.owner.suppressed_for() {
            first.entry(run.id).or_insert((run, dropped));
        }
    }
    if first.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = first.keys().copied().collect();
    sqlx::query!(
        "SELECT id FROM svs.runs WHERE id = ANY ($1) ORDER BY id FOR UPDATE",
        &ids
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut recorded = Vec::new();
    for (run, dropped) in first.values() {
        // the hunt's previous run, or the same run recording its duplicates, may have recorded it
        let inserted = sqlx::query!(
            "INSERT INTO svs.suppressed_matches (run_id, hunt_uuid, group_value, dedup_key, event_time)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT ON CONSTRAINT suppressed_matches_are_unique DO NOTHING",
            run.id,
            hunt_uuid,
            dropped.group_value,
            dropped.dedup_key,
            dropped.event_time,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if inserted == 1 {
            recorded.push(RecordedSuppression {
                run: run.uuid,
                run_id: run.id,
                group_value: dropped.group_value.clone(),
                dedup_key: dropped.dedup_key.clone(),
                event_time: dropped.event_time,
            });
        }
    }
    let written: Vec<i64> = recorded.iter().map(|row| row.run_id).collect();
    mark_runs_stale(conn, &written).await?;
    for row in &recorded {
        match &row.dedup_key {
            Some(dedup_key) => tracing::info!(
                svs_run = %row.run, hunt_uuid, group_value = row.group_value.as_deref(),
                dedup_key = %dedup_key,
                "svs run: a hunt dropped a duplicate match"
            ),
            None => tracing::info!(
                svs_run = %row.run, hunt_uuid, group_value = row.group_value.as_deref(),
                "svs run: a hunt suppressed a match"
            ),
        }
    }
    Ok(recorded)
}

/// ace3's tests/saq/svs/test_attribution.py: the cases that need no database (`TestFindingMarkers` but
/// the tree's, `TestHosts`, `TestContextClaimant`). The rest are `ace-service`'s
/// `svs_attribution_tests`, which maps them.
#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "svs-aaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_MARKER: &str = "svs-bbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GUID: &str = "aaaaaaaa-1111-4111-8111-111111111111";

    fn t0() -> DateTime<Utc> {
        "2026-10-14T12:00:00Z".parse().expect("a time")
    }

    fn bytes(data: &[u8]) -> Value {
        serde_json::to_value(ace_results::Bytes::new(data)).expect("serializes")
    }

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// `test_json_shaped_data`.
    #[test]
    fn json_shaped_data() {
        let data = json!({
            "events": [{"cmd": format!("whoami & REM {MARKER}")}, {"n": 1}],
            "other": ["x", format!("<# {} #>", OTHER_MARKER.to_uppercase())],
        });
        assert_eq!(find_markers_in_data(&data), [MARKER, OTHER_MARKER]);
        // a key is never read, and the walk stops where ace3's does
        assert!(find_markers_in_data(&json!({MARKER: 1})).is_empty());
        let mut deep = json!(MARKER);
        for _ in 0..=MAX_WALK_DEPTH {
            deep = json!([deep]);
        }
        assert!(find_markers_in_data(&deep).is_empty());
        let mut shallow = json!(MARKER);
        for _ in 0..MAX_WALK_DEPTH {
            shallow = json!([shallow]);
        }
        assert_eq!(find_markers_in_data(&shallow), [MARKER]);
    }

    /// `test_bytes_are_read_as_match_data`.
    #[test]
    fn bytes_are_read_as_match_data() {
        let data = json!([bytes(&wide(&format!(" {MARKER} ")))]);
        assert_eq!(find_markers_in_data(&data), [MARKER]);
        // an object that only looks like bytes is walked as any other
        assert_eq!(
            find_markers_in_data(&json!({"base64": MARKER, "other": 1})),
            [MARKER]
        );
    }

    /// `test_the_marker_rule_is_file_contents`.
    #[test]
    fn the_marker_rule_is_file_contents() {
        let details = json!({"scan_results": [
            {"rule": MARKER_RULE_NAME,
             "strings": [[0, "$marker", bytes(format!(" {MARKER}\n").as_bytes())]]},
            {"rule": "other_rule", "strings": [[4, "$s", format!("cmd {OTHER_MARKER}")]]},
        ]});
        assert_eq!(
            analysis_sightings(&details, Some(7), Some("yara_scanner_v3_4")),
            [
                Sighting {
                    marker: MARKER.to_owned(),
                    node: Some(7),
                    scan_point: ScanPoint::FileContents,
                    module: Some("yara_scanner_v3_4".to_owned()),
                },
                Sighting {
                    marker: OTHER_MARKER.to_owned(),
                    node: Some(7),
                    scan_point: ScanPoint::Analysis,
                    module: Some("yara_scanner_v3_4".to_owned()),
                },
            ]
        );
    }

    /// `test_the_marker_rule_after_a_save`: a UTF-16 match, as its bytes and as the text a save left.
    #[test]
    fn the_marker_rule_after_a_save() {
        let data = wide(&format!(" {MARKER} "));
        let text: String = data
            .iter()
            .map(|byte| {
                if *byte == 0 {
                    '\u{fffd}'
                } else {
                    char::from(*byte)
                }
            })
            .collect();
        for saved in [bytes(&data), json!(text)] {
            let details = json!({"scan_results": [{"rule": MARKER_RULE_NAME, "strings": [[0, "$marker", saved]]}]});
            let points: Vec<ScanPoint> = analysis_sightings(&details, None, None)
                .iter()
                .map(|s| s.scan_point)
                .collect();
            assert_eq!(points, [ScanPoint::FileContents]);
        }
    }

    /// `test_saving_dedupes_and_caps`.
    #[test]
    fn keeping_dedupes_and_caps() {
        let sighting = Sighting {
            module: Some("m".to_owned()),
            ..Sighting::new(MARKER, None, ScanPoint::Analysis)
        };
        let mut kept = Vec::new();
        assert_eq!(
            keep_sightings(
                &mut kept,
                vec![sighting.clone(), sighting.clone()],
                MAX_SIGHTINGS
            ),
            1
        );
        assert_eq!(
            keep_sightings(&mut kept, vec![sighting.clone()], MAX_SIGHTINGS),
            0
        );
        let more: Vec<Sighting> = (0..3)
            .map(|_| {
                Sighting::new(
                    &crate::svs::markers::new_marker(),
                    None,
                    ScanPoint::Analysis,
                )
            })
            .collect();
        assert_eq!(keep_sightings(&mut kept, more, 2), 1);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0], sighting);
    }

    /// `test_the_hosts_of_an_alert`.
    #[test]
    fn the_hosts_of_an_event() {
        let event = Event::derive(
            [
                (ObservableKind::Hostname, "WIN10-01"),
                (ObservableKind::Fqdn, "web.example.com"),
                (ObservableKind::Ipv4, "10.0.0.5"),
                (ObservableKind::Hostname, "not a host"),
                (ObservableKind::Url, "http://win10-02/"),
            ],
            None,
            t0(),
        );
        assert_eq!(
            event.hosts.names,
            BTreeSet::from([
                ("win10-01".to_owned(), None),
                ("web".to_owned(), Some("web.example.com".to_owned())),
            ])
        );
        assert_eq!(event.hosts.ips, BTreeSet::from(["10.0.0.5".to_owned()]));
        // a subtype of fqdn names a host too
        let event = Event::derive(
            [(ObservableKind::EmailDkimSigningDomain, "mail.example.com")],
            None,
            t0(),
        );
        assert_eq!(event.hosts.names.len(), 1);
        assert!(host_kinds().contains(&"email_dkim_signing_domain".to_owned()));
    }

    /// The bound on an event's hosts.
    #[test]
    fn an_event_keeps_a_bounded_number_of_hosts() {
        let names: Vec<String> = (0..MAX_EVENT_HOSTS + 50)
            .map(|n| format!("host-{n}"))
            .collect();
        let event = Event::derive(
            names
                .iter()
                .map(|name| (ObservableKind::Hostname, name.as_str()))
                .chain([(ObservableKind::Ipv4, "10.0.0.5")]),
            None,
            t0(),
        );
        assert_eq!(event.hosts.len(), MAX_EVENT_HOSTS);
        assert!(event.hosts.ips.is_empty());
    }

    /// `test_involvement`.
    #[test]
    fn involvement() {
        let names = |short: &str, qualified: Option<&str>| EventHosts {
            names: BTreeSet::from([(short.to_owned(), qualified.map(str::to_owned))]),
            ips: BTreeSet::new(),
        };
        let ips = |ip: &str| EventHosts {
            names: BTreeSet::new(),
            ips: BTreeSet::from([ip.to_owned()]),
        };
        let lab = TargetSnapshot::new("win10-01", Some("win10-01.lab.example"), &[]);
        let bare = TargetSnapshot::new("win10-01", None, &[]);
        let addressed = TargetSnapshot::new("win10-01", None, &["10.0.0.5"]);
        for (hosts, target, expected) in [
            (names("win10-01", None), &lab, true),
            (names("win10-01", Some("win10-01.lab.example")), &lab, true),
            // a production host that shares the short name in another domain
            (
                names("win10-01", Some("win10-01.corp.example")),
                &lab,
                false,
            ),
            (
                names("win10-01", Some("win10-01.corp.example")),
                &bare,
                true,
            ),
            (names("win10-02", None), &bare, false),
            (ips("10.0.0.5"), &addressed, true),
            (ips("10.0.0.6"), &addressed, false),
        ] {
            assert_eq!(hosts.involves(target), expected, "{hosts:?} {target:?}");
        }
    }

    /// `test_event_time` and `test_every_source_of_a_root_event_time_is_one_an_attribution_records`.
    /// ace3's half about a local timezone has no counterpart: every time here is a UTC instant.
    #[test]
    fn event_time() {
        let none: [(ObservableKind, &str); 0] = [];
        let event = Event::derive(none, None, t0());
        assert_eq!((event.time, event.source), (t0(), TimeSource::InsertTime));
        let at = t0() + TimeDelta::hours(4);
        for source in [TimeSource::Event, TimeSource::QueryTime, TimeSource::Now] {
            let event = Event::derive(none, Some((at, source)), t0());
            assert_eq!((event.time, event.source), (at, source));
            // every source a root records is one an attribution records, by name
            assert!(["event", "query_time", "now"].contains(&source.as_str()));
        }
        // kept to the microsecond, as the database stores it
        let fine = t0() + TimeDelta::nanoseconds(1_234_567);
        assert_eq!(
            Event::derive(none, Some((fine, TimeSource::Event)), t0()).time,
            t0() + TimeDelta::microseconds(1_234)
        );
    }

    fn snapshot(
        id: i64,
        started: Option<DateTime<Utc>>,
        hours: i64,
        holds_host: bool,
    ) -> RunSnapshot {
        RunSnapshot {
            id,
            uuid: Uuid::from_u128(id as u128),
            test_guid: GUID.parse().expect("a uuid"),
            marker: MARKER.to_owned(),
            started_at: started,
            observation_ends_at: started.map(|s| s + TimeDelta::hours(hours)),
            attribution_ends_at: started.map(|s| s + TimeDelta::hours(hours + 24)),
            targets: Vec::new(),
            holds_host,
        }
    }

    /// `TestContextClaimant.test_none_or_one`.
    #[test]
    fn none_or_one_claimant() {
        assert_eq!(context_claimant(&[]), None);
        let run = snapshot(1, Some(t0()), 1, false);
        assert_eq!(context_claimant(std::slice::from_ref(&run)), Some(&run));
    }

    /// `test_the_latest_run_when_the_others_released_the_host_before_it_started`.
    #[test]
    fn the_latest_run_when_the_others_released_the_host_before_it_started() {
        let first = snapshot(1, Some(t0()), 1, false);
        let second = snapshot(2, Some(t0() + TimeDelta::hours(2)), 1, false);
        let third = snapshot(3, Some(t0() + TimeDelta::hours(4)), 1, false);
        let candidates = [third.clone(), first, second];
        assert_eq!(context_claimant(&candidates), Some(&third));
    }

    /// `test_none_when_claims_overlap`.
    #[test]
    fn no_claimant_when_claims_overlap() {
        for first in [
            // its observation window ends as the second starts
            snapshot(1, Some(t0()), 2, false),
            // it holds the host for its attribution window
            snapshot(1, Some(t0()), 1, true),
        ] {
            let second = snapshot(2, Some(t0() + TimeDelta::hours(2)), 1, false);
            assert_eq!(context_claimant(&[first, second]), None);
        }
    }

    /// `suppression_key`, and which owner keys it.
    #[test]
    fn the_suppression_owner_and_its_key() {
        let run = snapshot(1, Some(t0()), 1, false);
        let later = snapshot(2, Some(t0() + TimeDelta::minutes(5)), 1, false);
        let window = MaintenanceSnapshot {
            id: 9,
            uuid: Uuid::from_u128(9),
            target: TargetSnapshot::new("win10-01", None, &[]),
            opened_at: t0(),
            ends_at: t0() + TimeDelta::minutes(30),
        };
        let owned = ContextOwner {
            run: Some(run.clone()),
            candidates: vec![run.clone()],
            maintenance: None,
        };
        assert_eq!(
            owned.suppression_owner().map(|o| o.key("alice")),
            Some(format!("svs_run:{}:alice", run.uuid))
        );
        // overlapping claims: the latest started keys it, and every candidate gets a dropped match
        let overlapping = ContextOwner {
            run: None,
            candidates: vec![run.clone(), later.clone()],
            maintenance: None,
        };
        assert_eq!(
            overlapping.suppression_owner(),
            Some(SuppressionOwner::Run(&later))
        );
        assert_eq!(overlapping.suppressed_for(), [&run, &later]);
        let staged = ContextOwner {
            maintenance: Some(window.clone()),
            ..ContextOwner::default()
        };
        assert_eq!(
            staged.suppression_owner().map(|o| o.key("alice")),
            Some(format!("svs_maintenance:{}:alice", window.uuid))
        );
        assert!(staged.suppressed_for().is_empty());
        assert_eq!(ContextOwner::default().suppression_owner(), None);
    }

    #[test]
    fn the_names_are_ace3_s() {
        let names = |all: &[&str]| all.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            ScanPoint::ALL
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            names(&[
                "observable",
                "detection",
                "root_details",
                "analysis",
                "file_contents"
            ])
        );
        assert_eq!(
            MarkerResult::ALL
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
            names(&["attributed", "unknown", "other host", "outside window"])
        );
        assert_eq!(TimeSource::parse("query_time"), Some(TimeSource::QueryTime));
        assert_eq!(TimeSource::parse("unset"), None);
    }
}
