//! What a correlation adds to a correlated hunt's submissions (`QueryHunt.process_query_results`
//! after its rows are grouped): each submission's share of the run's trace, the rows before
//! correlation, and which step of the hunt each observable came from.
//!
//! A submission's trace holds the event traces of the events it was made from and, for a grouped
//! hunt, of the events its group's value filtered or stopped, each with a one-line summary of its
//! event and where in the submission's `events` that event is; the stream's resets, timeouts and
//! discard are every submission's. A submission whose events errored or timed out is tagged
//! `warning:hunt_error`. Step 0 of the provenance is the hunt's own query, and steps 1 on are the
//! logic's property transforms in document order; an observable is from the step whose property
//! its mapping's field starts with.
//!
//! ace4 differs from ace3 in two places. ace3 looks an alert action's queue and analysis mode up by
//! the event's index after correlation, though the engine keeps them by its index before, so once
//! an event before it is filtered, an ungrouped hunt's override lands on the wrong submission; ace4
//! looks it up by the index the engine kept. And ace3 keys the provenance of an observable by its
//! uuid, which the root gives it; a submission's observables have none until the core makes the
//! root, so ace4 lists them with their type and value.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map as JsonMap, Value as Json, json};

use super::extract::{Extracted, py_str};
use super::observable::Observable;
use super::{Context, Submission};
use crate::correlate::action::ActionResult;
use crate::correlate::engine::Correlated;
use crate::correlate::property_steps;
use crate::correlate::trace::{CorrelationTrace, EventTrace};
use crate::model::HuntConfig;
use crate::render::methods::is_space;

/// `_EVENT_SUMMARY_MAX_LEN`.
const SUMMARY_MAX: usize = 160;

/// The action the engine kept for the event at `index` of the alerting events.
pub fn action_of(correlated: &Correlated, index: usize) -> Option<&ActionResult> {
    let origin = correlated.origins.get(index)?;
    correlated.event_actions.get(origin)
}

/// Which step each observable came from.
pub struct Provenance {
    /// `ordered_provenance_steps`.
    steps: Vec<Json>,
    /// A property's name to its step.
    by_property: BTreeMap<String, usize>,
    /// An observable's type and value to its steps.
    by_value: BTreeMap<(String, String), BTreeSet<usize>>,
}

impl Provenance {
    pub fn new(hunt: &HuntConfig) -> Provenance {
        let mut steps = Vec::new();
        let mut by_property = BTreeMap::new();
        if let Some(correlate) = &hunt.correlate {
            steps.push(json!({"index": 0, "label": "Initial Query", "property_name": null}));
            for (i, (description, property)) in
                property_steps(&correlate.logic).into_iter().enumerate()
            {
                let index = i + 1;
                let label = description
                    .filter(|d| !d.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("Correlated step {index}"));
                steps.push(json!({"index": index, "label": label, "property_name": property}));
                by_property.insert(property.to_owned(), index);
            }
        }
        Provenance {
            steps,
            by_property,
            by_value: BTreeMap::new(),
        }
    }

    /// Records the step of each observable a row's mappings made, before they're deduplicated.
    pub fn extracted(&mut self, observables: &[Extracted]) {
        for e in observables {
            let first = e.matched_field.split('.').next().unwrap_or("");
            let step = self.by_property.get(first).copied().unwrap_or(0);
            self.by_value
                .entry((e.observable.kind.clone(), e.observable.value.clone()))
                .or_default()
                .insert(step);
        }
    }

    fn of(&self, submission: &Submission) -> Json {
        let observables: Vec<Json> = submission
            .observables
            .iter()
            .filter_map(|o| {
                let steps = self.by_value.get(&(o.kind.clone(), o.value.clone()))?;
                Some(json!({"type": o.kind, "value": o.value, "steps": steps}))
            })
            .collect();
        json!({"steps": self.steps, "observables": observables})
    }
}

/// `_extract_event_summary`: the description field, the group value, up to four observables'
/// values and the event's time, each kept only when no part already says it, joined by ` · `.
pub fn event_summary(
    hunt: &HuntConfig,
    event: &JsonMap<String, Json>,
    observables: &[Observable],
    ctx: &Context<'_>,
) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut add = |value: Option<&Json>| {
        let value = match value {
            None | Some(Json::Null) => return,
            Some(Json::Array(items)) => match items.first() {
                None | Some(Json::Null) => return,
                Some(first) => first,
            },
            Some(v) => v,
        };
        let text = py_str(value).trim_matches(is_space).to_owned();
        add_text(&mut parts, text);
    };
    if let Some(field) = &hunt.description_field
        && event.contains_key(field)
    {
        add(event.get(field));
    }
    if let Some(group_by) = hunt.group_by.as_deref().filter(|g| *g != "ALL")
        && event.contains_key(group_by)
    {
        add(event.get(group_by));
    }
    for o in observables {
        if o.kind == "signature_id" {
            continue;
        }
        add_text(&mut parts, o.value.trim_matches(is_space).to_owned());
        if parts.len() >= 4 {
            break;
        }
    }
    if let Some(time) = (ctx.event_time)(event) {
        add_text(&mut parts, time.format("%H:%M:%S").to_string());
    }
    if parts.is_empty() {
        return None;
    }
    let summary = parts.join(" · ");
    if summary.chars().count() > SUMMARY_MAX {
        Some(summary.chars().take(SUMMARY_MAX - 1).collect::<String>() + "…")
    } else {
        Some(summary)
    }
}

/// `_add`: a part no other part already holds, replacing the parts it holds.
fn add_text(parts: &mut Vec<String>, text: String) {
    if text.is_empty() {
        return;
    }
    let folded = text.to_lowercase();
    let mut remove = Vec::new();
    for (i, existing) in parts.iter().enumerate() {
        let e = existing.to_lowercase();
        if folded == e || e.contains(&folded) {
            return;
        }
        if folded.contains(&e) {
            remove.push(i);
        }
    }
    for i in remove.into_iter().rev() {
        parts.remove(i);
    }
    parts.push(text);
}

/// Each submission's correlation details: its trace, the original rows and the provenance.
#[allow(clippy::too_many_arguments)]
pub fn details(
    hunt: &HuntConfig,
    correlated: &Correlated,
    original: &[JsonMap<String, Json>],
    rows: &[JsonMap<String, Json>],
    row_submissions: &[Vec<usize>],
    per_event: &[Vec<Observable>],
    provenance: &Provenance,
    ctx: &Context<'_>,
    submissions: &mut [Submission],
) {
    let origins = &correlated.origins;
    let trace = &correlated.trace;
    // per submission: the origins of its events, and where each is in its events
    let mut submission_origins: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); submissions.len()];
    let mut positions: Vec<BTreeMap<usize, usize>> = vec![BTreeMap::new(); submissions.len()];
    for (post, subs) in row_submissions.iter().enumerate() {
        let Some(&origin) = origins.get(post) else {
            continue;
        };
        for &at in subs {
            submission_origins[at].insert(origin);
            let next = positions[at].len();
            positions[at].entry(origin).or_insert(next);
        }
    }
    let origin_to_post: BTreeMap<usize, usize> = origins
        .iter()
        .enumerate()
        .map(|(post, &o)| (o, post))
        .collect();
    // a grouped hunt's filtered and stopped events of each submission's group
    let mut extra: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); submissions.len()];
    if let Some(group_by) = hunt.group_by.as_deref() {
        let rejected = trace
            .event_traces
            .iter()
            .filter(|et| matches!(et.outcome.as_str(), "filter" | "stop"))
            .filter(|et| et.event_index < original.len());
        for et in rejected {
            if group_by == "ALL" {
                for e in &mut extra {
                    e.insert(et.event_index);
                }
                continue;
            }
            let Some(value) = original[et.event_index].get(group_by) else {
                continue;
            };
            let values = match value {
                Json::Null => continue,
                Json::Array(items) => items.clone(),
                other => vec![other.clone()],
            };
            for gv in values {
                for (at, s) in submissions.iter().enumerate() {
                    if s.group_value.as_ref() == Some(&gv) {
                        extra[at].insert(et.event_index);
                    }
                }
            }
        }
    }
    for (at, submission) in submissions.iter_mut().enumerate() {
        let scoped: Vec<EventTrace> = trace
            .event_traces
            .iter()
            .filter(|et| {
                submission_origins[at].contains(&et.event_index)
                    || extra[at].contains(&et.event_index)
            })
            .map(|et| {
                let mut et = et.clone();
                let post = origin_to_post.get(&et.event_index).copied();
                et.summary = match post {
                    Some(post)
                        if submission_origins[at].contains(&et.event_index)
                            && post < rows.len() =>
                    {
                        event_summary(
                            hunt,
                            &rows[post],
                            per_event.get(post).map(Vec::as_slice).unwrap_or(&[]),
                            ctx,
                        )
                    }
                    _ if extra[at].contains(&et.event_index) && et.event_index < original.len() => {
                        event_summary(hunt, &original[et.event_index], &[], ctx)
                    }
                    _ => None,
                };
                et.events_position = positions[at].get(&et.event_index).copied();
                et
            })
            .collect();
        let failed = scoped
            .iter()
            .any(|et| matches!(et.outcome.as_str(), "error" | "timeout"));
        let scoped = CorrelationTrace {
            event_traces: scoped,
            stream_events: trace.stream_events.clone(),
        };
        submission.details.insert(
            "correlation_trace".to_owned(),
            serde_json::to_value(&scoped).unwrap_or(Json::Null),
        );
        if failed && !submission.tags.iter().any(|t| t == "warning:hunt_error") {
            submission.tags.push("warning:hunt_error".to_owned());
        }
    }
    for submission in submissions.iter_mut() {
        submission.details.insert(
            "original_events".to_owned(),
            Json::Array(original.iter().cloned().map(Json::Object).collect()),
        );
        submission
            .details
            .insert("hunt_provenance".to_owned(), provenance.of(submission));
    }
}
