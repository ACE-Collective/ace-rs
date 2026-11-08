//! The event list's filters and sorts (PLAN.md 5.11's events area, 6c), ace3's `events/views/manage.py`.
//!
//! ace3's event list isn't one of its filter screens: it has no saved filters or share links, and keeps its
//! filters in the session as form fields (`SearchFilter`). So its filters are their own set here, beside the
//! screens' (`super`), with the same rules: `EventFilters::check` is the one gate, which refuses a value of
//! the wrong shape or past the bounds below and returns the filters in their canonical spelling, and the
//! list's query (`Service::event_list`) is one static query in which each filter is a fixed condition that a
//! NULL parameter turns off, every value a bound parameter.
//!
//! ace3's filters, and what each is here:
//! - Date Range, on the creation date, ace3's `MM-DD-YYYY HH:MM - MM-DD-YYYY HH:MM`, or any value the
//!   alert list's date filters take (`super::date_window`), resolved in UTC: ace3 compares the day with
//!   the times as typed, and a creation date is a UTC day. ace3 falls back to the last 7 days, with a
//!   flash, for a range it can't read; here that's refused, saying why.
//! - Disposition, the rolled-up one (`crate::rolled_up`), any of those given. ace3 filters it in Python
//!   after the query; here it's in the query.
//! - Status, any of those given. ace3 starts with `OPEN` (`EventFilters::ace3_default`).
//! - Owner, any of the users given, or nobody (`EventOwnerFilter::Nobody`), ace3's `None`.
//! - Type, Vector, Prevention Tool and Severity (the risk level), each one value or any, ace3's `ANY`.
//! - Observable Type and Observable Value: events with an alert holding an observable of the type, the
//!   value or both, the value matched exactly, as ace3's `observable_value_condition` matches on its hash.
//!   A value with a type is normalized as the alert list's observable filter normalizes it.
//! - Tag, any of the event's own tags given, matched exactly, as ace3's multiselect picks them.
//! - Threat (malware) and Threat Actor (campaign), any of those ticked, by id.
//!
//! ace3's Companies filter is left out: roots have no company.

use chrono::Utc;
use chrono_tz::Tz;
use uuid::Uuid;

use crate::ServiceError;

/// The most values one of the event list's text or user filters holds: the screens' bound.
pub const MAX_EVENT_FILTER_VALUES: usize = super::MAX_FILTER_VALUES;
/// The most malware or campaigns one filter ticks. ace3 lists a box for each; this bounds the query.
pub const MAX_EVENT_FILTER_IDS: usize = 1000;

/// Who owns the events the owner filter matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventOwnerFilter {
    /// Nobody, ace3's `None`.
    Nobody,
    User(Uuid),
}

/// The event list's filters. An empty list, or None, is no filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilters {
    /// A date range on the creation date.
    pub created: Option<String>,
    pub dispositions: Vec<String>,
    pub statuses: Vec<String>,
    pub owners: Vec<EventOwnerFilter>,
    pub kind: Option<String>,
    pub vector: Option<String>,
    pub prevention_tool: Option<String>,
    pub risk_level: Option<String>,
    pub observable_type: Option<String>,
    pub observable_value: Option<String>,
    pub tags: Vec<String>,
    pub malware: Vec<i32>,
    pub campaigns: Vec<i32>,
}

impl EventFilters {
    /// ace3's filters when the list opens or is reset: the open events.
    pub fn ace3_default() -> Self {
        EventFilters {
            statuses: vec!["OPEN".to_owned()],
            ..EventFilters::default()
        }
    }

    /// The filters checked and spelt canonically: each text trimmed, an empty one no filter, repeated
    /// values once, an observable's type as its type's name and its value normalized, and the bounds held.
    pub fn check(&self) -> Result<EventFilters, ServiceError> {
        let created = optional("Date Range", self.created.as_deref())?;
        if let Some(created) = &created {
            super::date_window(created, Utc::now(), Tz::UTC)
                .map_err(|why| invalid(format!("Date Range: {why}")))?;
        }
        let observable_type = optional("Observable Type", self.observable_type.as_deref())?;
        let observable_value = optional("Observable Value", self.observable_value.as_deref())?;
        let (observable_type, observable_value) = match (observable_type, observable_value) {
            (Some(kind), Some(value)) => {
                let (kind, value) = crate::observables::normalized(&kind, &value)
                    .map_err(|why| invalid(format!("Observable: {why}")))?;
                (Some(kind.as_str().to_owned()), Some(value))
            }
            (Some(kind), None) => {
                let kind: ace_results::ObservableKind = kind
                    .parse()
                    .map_err(|why| invalid(format!("Observable Type: {why}")))?;
                (Some(kind.as_str().to_owned()), None)
            }
            (None, value) => (None, value),
        };
        let mut owners = self.owners.clone();
        owners.sort_unstable();
        owners.dedup();
        if owners.len() > MAX_EVENT_FILTER_VALUES {
            return Err(too_many("Owner", MAX_EVENT_FILTER_VALUES));
        }
        Ok(EventFilters {
            created,
            dispositions: texts("Disposition", &self.dispositions)?,
            statuses: texts("Status", &self.statuses)?,
            owners,
            kind: optional("Type", self.kind.as_deref())?,
            vector: optional("Vector", self.vector.as_deref())?,
            prevention_tool: optional("Prevention Tool", self.prevention_tool.as_deref())?,
            risk_level: optional("Severity", self.risk_level.as_deref())?,
            observable_type,
            observable_value,
            tags: texts("Tag", &self.tags)?,
            malware: ids("Threat", &self.malware)?,
            campaigns: ids("Threat Actor", &self.campaigns)?,
        })
    }
}

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::InvalidRequest(message.into())
}

fn too_many(name: &str, max: usize) -> ServiceError {
    invalid(format!("the {name} filter takes at most {max} values"))
}

/// One value, trimmed, or None when it's empty.
fn optional(name: &str, value: Option<&str>) -> Result<Option<String>, ServiceError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > super::MAX_FILTER_VALUE_CHARS {
        return Err(invalid(format!(
            "a {name} value is at most {} characters",
            super::MAX_FILTER_VALUE_CHARS
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "a {name} value can't hold a control character"
        )));
    }
    Ok(Some(value.to_owned()))
}

/// Values, each trimmed and once, the empty ones dropped.
fn texts(name: &str, values: &[String]) -> Result<Vec<String>, ServiceError> {
    let mut out: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        if let Some(value) = optional(name, Some(value))?
            && !out.contains(&value)
        {
            out.push(value);
        }
    }
    if out.len() > MAX_EVENT_FILTER_VALUES {
        return Err(too_many(name, MAX_EVENT_FILTER_VALUES));
    }
    Ok(out)
}

fn ids(name: &str, values: &[i32]) -> Result<Vec<i32>, ServiceError> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_EVENT_FILTER_IDS {
        return Err(too_many(name, MAX_EVENT_FILTER_IDS));
    }
    Ok(out)
}

/// The event list's orders, ace3's: each sorts with the event's id to break a tie, in the same
/// direction, so the order is total and a cursor is stable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EventSort {
    /// The creation date, ace3's default.
    #[default]
    Date,
    /// The type, then the vector, then the name, as ace3's Event column sorts.
    Event,
    /// The campaign's name, ace3's Threat Actor; an event with none first going up.
    Campaign,
    /// The risk level's value, ace3's Severity.
    RiskLevel,
    /// The rolled-up disposition's rank, as ace3's `disposition_rank` sorts it.
    Disposition,
    Prevention,
    Remediation,
    Status,
    /// The owner's display name, or username when they have none; an event nobody owns first going up.
    Owner,
}

impl EventSort {
    pub const ALL: &'static [EventSort] = &[
        EventSort::Date,
        EventSort::Event,
        EventSort::Campaign,
        EventSort::RiskLevel,
        EventSort::Disposition,
        EventSort::Prevention,
        EventSort::Remediation,
        EventSort::Status,
        EventSort::Owner,
    ];

    /// Its name in a request: ace3's `sort_field`.
    pub fn as_str(self) -> &'static str {
        match self {
            EventSort::Date => "date",
            EventSort::Event => "event",
            EventSort::Campaign => "campaign",
            EventSort::RiskLevel => "risk_level",
            EventSort::Disposition => "disposition",
            EventSort::Prevention => "prevention",
            EventSort::Remediation => "remediation",
            EventSort::Status => "status",
            EventSort::Owner => "owner",
        }
    }

    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|sort| sort.as_str() == name)
    }
}

/// What the event list shows: its filters, in an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventQuery {
    pub filters: EventFilters,
    pub sort: EventSort,
    /// ace3's `event_sort_dir`, true at first.
    pub descending: bool,
}

impl Default for EventQuery {
    /// ace3's list as it opens: the open events, newest first.
    fn default() -> Self {
        EventQuery {
            filters: EventFilters::ace3_default(),
            sort: EventSort::Date,
            descending: true,
        }
    }
}
