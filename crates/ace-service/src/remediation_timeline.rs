//! An alert's remediation timeline (PLAN.md decision 38): ace3's `saq/remediation/timeline.py` at
//! `85c8e9e5`, which its alert page's Remediation Timeline draws (`app/analysis/views/index.py`'s
//! `gather_remediation_events`).
//!
//! One read, under `remediation:read`, gives the alert's coverage (`Service::remediation_coverage`'s,
//! read in the same transaction so the badge and the rows agree) and its rows, from ace3's sources:
//! - ACE's own tries: each try (`queue.action_attempts`) of each remediation of one of the alert's
//!   `email_delivery` values, by any remediator. A try that acted on another target than its key
//!   (`resolved_target`, decision 36) reads `Remove (Success) via owner@x` with the target
//!   `alias@x → owner@x`. A finished removal whose result the journal explains for that address (the
//!   delivery tag the email module put on it, `journal_explains`) reads as what the journal says, such
//!   as `Remove (not delivered to this address; forwarded to owner@x)`, naming the mailboxes its
//!   `delivered_to` relationships reach. The try's message is kept for the row's tooltip.
//! - The events of each confirmed remediation check of the alert (ace3's external probes).
//! - One pending row per email still outstanding: neither remediated nor found gone while ACE is
//!   still removing it or a check still watching (ace3's `pending_events_from_coverage`).
//!
//! ace3's fourth source, analysis-tree providers (`register_remediation_event_provider`), has no
//! counterpart: nothing in ace3 or a site's integration registers one at `85c8e9e5`.
//!
//! Rows sort as ace3's: what happened before what is pending, then by the message's time, the try's
//! time (both to the whole second the table shows), the target, the source and the description; a
//! row with no message time goes after those with one. ACE's rows and pending rows take the alert's
//! event time as the message's, as ace3's take `root.event_time`.
//!
//! Bounds: at most `MAX_TIMELINE_TRIES` of ACE's tries are read, newest first, and at most
//! `MAX_TIMELINE_EVENTS` rows are returned; `truncated` says when either cut something.

use std::collections::BTreeMap;

use ace_core::actions as core_actions;
use ace_core::db::Tx;
use ace_results::types::email::DeliveryReason;
use chrono::{DateTime, SubsecRound, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::permission::REMEDIATION_READ;
use crate::remediation::{
    ACE_SOURCE, COVERAGE_TYPE, Coverage, confirmed_events, coverage_in, journal_explains,
};
use crate::{Actor, Service, ServiceError};

/// The most of ACE's tries one timeline reads.
pub const MAX_TIMELINE_TRIES: i64 = 1000;
/// The most rows one timeline holds.
pub const MAX_TIMELINE_EVENTS: usize = 1000;

/// One row of an alert's remediation timeline, ace3's `RemediationEvent` as its table shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineEvent {
    /// Who acted: `ACE`, a vendor's events' source, or for a pending row who is still working on it.
    pub source: String,
    /// What happened, such as `Remove (Success)`.
    pub description: String,
    /// When it happened, or for a pending row the latest activity on it.
    pub timestamp: DateTime<Utc>,
    /// When the message was received, from which `duration` counts.
    pub event_time: Option<DateTime<Utc>>,
    /// What was acted on, a recipient, or `alias → owner`.
    pub target: Option<String>,
    /// The remediator's or the vendor's own words, such as why it acted on another target.
    pub message: Option<String>,
    /// A vendor's link to the event.
    pub portal_url: Option<String>,
    /// ACE's remediation the try belongs to.
    pub remediation: Option<i64>,
    /// The `email_delivery` value of a pending row, since two emails to one recipient read the same.
    pub delivery: Option<String>,
    /// Still under way, not something that happened.
    pub pending: bool,
}

impl TimelineEvent {
    /// How long after the message the event came, ace3's `duration`; None for a pending row.
    pub fn duration(&self) -> Option<chrono::Duration> {
        if self.pending {
            return None;
        }
        self.event_time.map(|at| self.timestamp - at)
    }

    /// ace3's `duration_display`: `5m 22s`, `1d 4h`, `0s` for none or less.
    pub fn duration_display(&self) -> Option<String> {
        self.duration().map(format_duration)
    }
}

/// ace3's `_format_duration`.
pub fn format_duration(duration: chrono::Duration) -> String {
    let total = duration.num_seconds();
    if total <= 0 {
        return "0s".to_owned();
    }
    let unit = |big: i64, big_unit: &str, small: i64, small_unit: &str| {
        if small > 0 {
            format!("{big}{big_unit} {small}{small_unit}")
        } else {
            format!("{big}{big_unit}")
        }
    };
    match total {
        t if t < 60 => format!("{t}s"),
        t if t < 3600 => unit(t / 60, "m", t % 60, "s"),
        t if t < 86400 => unit(t / 3600, "h", (t % 3600) / 60, "m"),
        t => unit(t / 86400, "d", (t % 86400) / 3600, "h"),
    }
}

/// An alert's remediation: its coverage, which the badge sums up, and its timeline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RemediationTimeline {
    pub coverage: Coverage,
    pub events: Vec<TimelineEvent>,
    /// Some of ACE's tries or some rows were left out (`MAX_TIMELINE_TRIES`, `MAX_TIMELINE_EVENTS`).
    pub truncated: bool,
}

impl RemediationTimeline {
    /// The rows that happened, not those still pending.
    pub fn event_count(&self) -> usize {
        self.events.iter().filter(|e| !e.pending).count()
    }

    pub fn pending_count(&self) -> usize {
        self.events.iter().filter(|e| e.pending).count()
    }
}

/// One of the alert's `email_delivery` values, as the timeline reads it: the journal's reason when
/// its delivery tag says the address didn't get its own copy, and the values its `delivered_to`
/// relationships reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineDelivery {
    pub undelivered: Option<DeliveryReason>,
    pub delivered_to: Vec<String>,
}

/// One of ACE's remediations of one of the alert's deliveries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineRemediation {
    pub id: i64,
    pub value: String,
    pub action: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// One try of one of `TimelineRemediation`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineTry {
    pub remediation: i64,
    pub status: String,
    pub result: String,
    pub message: String,
    pub resolved_target: Option<String>,
    pub at: DateTime<Utc>,
}

/// One of the alert's remediation checks.
#[derive(Debug, Clone, PartialEq)]
pub struct TimelineCheck {
    pub value: String,
    pub handler: String,
    pub status: String,
    pub result: Option<String>,
    pub events: Option<serde_json::Value>,
    pub deadline: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// What one timeline is built from.
#[derive(Debug, Clone, Default)]
pub struct TimelineInput {
    pub deliveries: BTreeMap<String, TimelineDelivery>,
    pub remediations: Vec<TimelineRemediation>,
    pub tries: Vec<TimelineTry>,
    pub checks: Vec<TimelineCheck>,
    /// The alert's event time, which ACE's rows and pending rows take as the message's.
    pub event_time: Option<DateTime<Utc>>,
}

/// Python's `str.capitalize`, which ace3's descriptions use: `NOT_FOUND` reads `Not_found`.
fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
        None => String::new(),
    }
}

/// The first character upper-cased, the rest as they are, as ace3's template draws a source.
pub fn upper_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The recipient of an `email_delivery` value, ace3's `parse_email_delivery(...)[1]`: None when the
/// value has no `|` or nothing after it.
fn recipient(value: &str) -> Option<&str> {
    value
        .rsplit_once('|')
        .map(|(_, r)| r)
        .filter(|r| !r.is_empty())
}

/// ACE's rows: ace3's `_gather_ace_email_remediation_events`.
fn ace_events(input: &TimelineInput) -> Vec<TimelineEvent> {
    let by_id: BTreeMap<i64, &TimelineRemediation> =
        input.remediations.iter().map(|r| (r.id, r)).collect();
    let mut events = Vec::new();
    for attempt in &input.tries {
        let Some(remediation) = by_id.get(&attempt.remediation) else {
            continue;
        };
        let action = remediation.action.trim();
        let result = attempt.result.trim();
        let mut description = match (action.is_empty(), result.is_empty()) {
            (false, false) => format!("{} ({})", capitalize(action), capitalize(result)),
            (false, true) => capitalize(action),
            (true, false) => capitalize(result),
            (true, true) => "Remediation".to_owned(),
        };
        let mut target = recipient(&remediation.value).map(str::to_owned);
        let delivery = input.deliveries.get(&remediation.value);
        let undelivered = delivery.and_then(|d| d.undelivered);
        match &attempt.resolved_target {
            Some(resolved) if Some(resolved) != target.as_ref() => {
                // the remediator acted on another target than the key named, such as the mailbox
                // that owns an alias address; its message says why
                description = format!("{description} via {resolved}");
                target = Some(match target {
                    Some(key) => format!("{key} \u{2192} {resolved}"),
                    None => resolved.clone(),
                });
            }
            _ => {
                if action == "remove"
                    && attempt.status == core_actions::COMPLETED
                    && journal_explains(undelivered, Some(result))
                    && let Some(reason) = undelivered
                {
                    // the journal says this address didn't get its own copy, so this isn't a
                    // failed remediation
                    let mailboxes: Vec<String> = delivery
                        .map(|d| {
                            d.delivered_to
                                .iter()
                                .map(|v| recipient(v).unwrap_or(v).to_owned())
                                .collect()
                        })
                        .unwrap_or_default();
                    description = format!(
                        "{} ({})",
                        capitalize(action),
                        reason.describe_undelivered(&mailboxes)
                    );
                }
            }
        }
        events.push(TimelineEvent {
            source: ACE_SOURCE.to_owned(),
            description,
            timestamp: attempt.at,
            event_time: input.event_time,
            target,
            message: Some(attempt.message.clone()).filter(|m| !m.is_empty()),
            portal_url: None,
            remediation: Some(remediation.id),
            delivery: None,
            pending: false,
        });
    }
    events
}

/// The confirmed checks' events: ace3's `events_from_check`. Events that don't parse are left out.
fn check_events(input: &TimelineInput) -> Vec<TimelineEvent> {
    input
        .checks
        .iter()
        .filter(|c| c.result.as_deref() == Some("CONFIRMED"))
        .flat_map(|c| confirmed_events(c.events.as_ref()))
        .map(|event| TimelineEvent {
            source: event.source,
            description: event.description,
            timestamp: event.timestamp,
            event_time: event.event_time,
            target: event.target,
            message: None,
            portal_url: event.portal_url,
            remediation: None,
            delivery: None,
            pending: false,
        })
        .collect()
}

/// A pending row per email still outstanding: ace3's `pending_events_from_coverage`.
fn pending_events(input: &TimelineInput, coverage: &Coverage) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for target in &coverage.targets {
        if !target.pending || target.remediated() || target.not_found {
            continue;
        }
        let mut sources: Vec<String> = Vec::new();
        let mut activity: Vec<DateTime<Utc>> = Vec::new();
        let mut deadlines: Vec<DateTime<Utc>> = Vec::new();
        // ACE's latest remediation of it, when it hasn't finished
        if let Some(latest) = input
            .remediations
            .iter()
            .filter(|r| r.value == target.target)
            .max_by_key(|r| r.id)
            && latest.status != core_actions::COMPLETED
        {
            sources.push(ACE_SOURCE.to_owned());
            activity.push(latest.updated_at.unwrap_or(latest.created_at));
        }
        for check in input
            .checks
            .iter()
            .filter(|c| c.value == target.target && c.status != core_actions::COMPLETED)
        {
            let label = upper_first(&check.handler);
            if !sources.contains(&label) {
                sources.push(label);
            }
            activity.push(check.updated_at.unwrap_or(check.created_at));
            deadlines.extend(check.deadline);
        }
        let mut description = if target.remediating {
            "Remediating".to_owned()
        } else {
            "Watching".to_owned()
        };
        if let Some(deadline) = deadlines.iter().max() {
            description = format!(
                "{description} (until {} UTC)",
                deadline.format("%Y-%m-%d %H:%M:%S")
            );
        }
        events.push(TimelineEvent {
            source: sources.join(", "),
            description,
            timestamp: activity.into_iter().max().unwrap_or_else(Utc::now),
            event_time: input.event_time,
            target: Some(target.recipient().to_owned()),
            message: None,
            portal_url: None,
            remediation: None,
            delivery: Some(target.target.clone()),
            pending: true,
        });
    }
    events
}

/// The timeline's rows, sorted as ace3's `gather_remediation_events` sorts them.
pub fn assemble_timeline(input: &TimelineInput, coverage: &Coverage) -> Vec<TimelineEvent> {
    let mut events = ace_events(input);
    events.extend(check_events(input));
    events.extend(pending_events(input, coverage));
    events.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    events
}

type SortKey<'a> = (
    bool,
    bool,
    DateTime<Utc>,
    DateTime<Utc>,
    &'a str,
    &'a str,
    &'a str,
);

fn sort_key(event: &TimelineEvent) -> SortKey<'_> {
    let when = event.timestamp.trunc_subsecs(0);
    (
        event.pending,
        event.event_time.is_none(),
        event.event_time.map_or(when, |at| at.trunc_subsecs(0)),
        when,
        event.target.as_deref().unwrap_or(""),
        &event.source,
        &event.description,
    )
}

async fn timeline_in(tx: &mut Tx<'_>, alert: Uuid) -> Result<RemediationTimeline, ServiceError> {
    let coverage = coverage_in(tx, &[alert])
        .await?
        .remove(&alert)
        .unwrap_or_default();
    let event_time =
        sqlx::query_scalar!("SELECT event_time FROM analysis.roots WHERE id = $1", alert)
            .fetch_optional(tx.conn())
            .await?
            .flatten();
    let mut deliveries: BTreeMap<String, TimelineDelivery> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT o.value, o.tags,
                  coalesce(array_agg(r.target_value ORDER BY r.target_value)
                           FILTER (WHERE r.target_value IS NOT NULL), '{}') AS "delivered_to!"
           FROM analysis.observables o
           LEFT JOIN analysis.relationships r
             ON r.root_id = o.root_id AND r.observable_id = o.id
            AND r.kind = 'delivered_to' AND r.target_type = $2
           WHERE o.root_id = $1 AND o.type = $2
           GROUP BY o.id, o.value, o.tags"#,
        alert,
        COVERAGE_TYPE,
    )
    .fetch_all(tx.conn())
    .await?
    {
        let delivery = deliveries.entry(row.value).or_default();
        if delivery.undelivered.is_none() {
            delivery.undelivered = row.tags.iter().find_map(|tag| DeliveryReason::of_tag(tag));
        }
        for target in row.delivered_to {
            if !delivery.delivered_to.contains(&target) {
                delivery.delivered_to.push(target);
            }
        }
    }
    let values: Vec<String> = deliveries.keys().cloned().collect();
    let remediations: Vec<TimelineRemediation> = sqlx::query!(
        r#"SELECT id, observable_value, action AS "action!", status, created_at, updated_at
           FROM queue.actions
           WHERE kind = 'remediation' AND observable_type = $1 AND observable_value = ANY($2)
           ORDER BY id"#,
        COVERAGE_TYPE,
        &values,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|row| TimelineRemediation {
        id: row.id,
        value: row.observable_value,
        action: row.action,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
    .collect();
    let ids: Vec<i64> = remediations.iter().map(|r| r.id).collect();
    let mut tries: Vec<TimelineTry> = sqlx::query!(
        "SELECT action_id, status, result, message, resolved_target, created_at
         FROM queue.action_attempts WHERE action_id = ANY($1)
         ORDER BY created_at DESC, id DESC LIMIT $2",
        &ids,
        MAX_TIMELINE_TRIES + 1,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|row| TimelineTry {
        remediation: row.action_id,
        status: row.status,
        result: row.result,
        message: row.message,
        resolved_target: row.resolved_target,
        at: row.created_at,
    })
    .collect();
    let mut truncated = tries.len() > usize::try_from(MAX_TIMELINE_TRIES).unwrap_or(usize::MAX);
    tries.truncate(usize::try_from(MAX_TIMELINE_TRIES).unwrap_or(usize::MAX));
    let checks: Vec<TimelineCheck> = sqlx::query!(
        "SELECT a.observable_value, a.handler, a.status, a.result, a.events, a.deadline_at,
                a.created_at, a.updated_at
         FROM queue.actions a JOIN queue.action_roots r ON r.action_id = a.id
         WHERE a.kind = 'remediation_check' AND a.observable_type = $1 AND r.root_id = $2
         ORDER BY a.id",
        COVERAGE_TYPE,
        alert,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|row| TimelineCheck {
        value: row.observable_value,
        handler: row.handler,
        status: row.status,
        result: row.result,
        events: row.events,
        deadline: row.deadline_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
    .collect();
    let input = TimelineInput {
        deliveries,
        remediations,
        tries,
        checks,
        event_time,
    };
    let mut events = assemble_timeline(&input, &coverage);
    if events.len() > MAX_TIMELINE_EVENTS {
        truncated = true;
        events.truncate(MAX_TIMELINE_EVENTS);
    }
    Ok(RemediationTimeline {
        coverage,
        events,
        truncated,
    })
}

impl Service {
    /// An alert's remediation coverage and timeline, ace3's Remediation Timeline. An alert with no
    /// `email_delivery` targets, or none at all, has an empty one.
    pub async fn remediation_timeline(
        &self,
        actor: &Actor,
        alert: Uuid,
    ) -> Result<RemediationTimeline, ServiceError> {
        self.gate
            .read(actor, "remediation_timeline", &REMEDIATION_READ, &|tx| {
                Box::pin(async move { timeline_in(tx, alert).await })
            })
            .await
    }
}
