//! Query hunts (PLAN.md 6.4): what ace3's `QueryHunt` makes of a search's rows
//! (`saq/collectors/hunter/query_hunter.py`, `process_query_results` and `create_root_analysis`),
//! and when it runs and what it searches ([`schedule`]).
//!
//! [`process`] takes the rows a hunt's search returned and gives the submissions ace3's hunter
//! would stage, field for field: one per row, or one per value of `group_by` (`ALL` for one in
//! all), named and described as ace3 does, with the observables the mappings take from the rows
//! ([`extract`], [`observable`]), the hunt's tags, pivot links, playbook URL, summary details,
//! dedup key and detection, each row's event time, and the details ace3 records. A grouped hunt with
//! a suppression drops the groups that alerted within it, and [`Processed::suppressed`] lists them,
//! which the hunter records as suppression rows (6.5).
//!
//! Correlation (`correlate`) is 6.6's: a hunt with one isn't processed here. The rest is pure: the
//! hunter (`ace_app::hunter`) runs the search, keeps the state and submits.

pub mod extract;
pub mod observable;
pub mod schedule;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as Json, json};

use crate::model::HuntConfig;
use crate::query::extract::{Extractor, FileContent, Row, lookup, py_str, whole_value_patterns};
use crate::query::observable::{EmailNormalizer, Observable};
use crate::query::schedule::{State, group_suppressed, timedelta_str};
use crate::render::{Rendered, Renderer};

/// Where a root's event time came from, as ace3's `EventTimeSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTimeSource {
    /// The row's own time.
    Event,
    /// The time the hunt processed the rows, for a row it couldn't take a time from.
    QueryTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PivotLink {
    pub url: String,
    pub icon: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SummaryDetail {
    pub header: Option<String>,
    pub content: String,
    pub format: String,
}

/// The root-level detection a hunt in correlation mode adds, which makes the root an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    pub description: String,
    pub signature_uuid: String,
    pub signature_version: String,
    pub signature_family: String,
}

/// One submission, the fields of ace3's `Submission` and its `RootAnalysis` that a hunt sets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Submission {
    /// The dedup key, `<hunt uuid>:<rendered dedup_key>`.
    pub key: Option<String>,
    /// The `group_by` value that made it, for a grouped hunt.
    pub group_value: Option<Json>,
    /// The key its group's suppression is kept under, set for a grouped hunt with a suppression.
    pub suppression_key: Option<String>,
    pub description: String,
    pub instructions: String,
    pub analysis_mode: String,
    pub alert_type: String,
    pub queue: String,
    pub tool: String,
    pub tool_instance: String,
    #[serde(serialize_with = "py_isoformat")]
    pub event_time: DateTime<Utc>,
    pub event_time_source: EventTimeSource,
    pub details: JsonMap<String, Json>,
    pub extensions: JsonMap<String, Json>,
    pub tags: Vec<String>,
    pub pivot_links: Vec<PivotLink>,
    pub summary_details: Vec<SummaryDetail>,
    pub detections: Vec<Detection>,
    pub observables: Vec<Observable>,
    pub files: Vec<FileContent>,
    /// The indexes of the rows it holds.
    #[serde(skip)]
    pub rows: Vec<usize>,
}

/// A hunt type's `extract_event_timestamp`.
pub type EventTimeFn<'a> = dyn Fn(&JsonMap<String, Json>) -> Option<DateTime<Utc>> + 'a;

/// What a run knows besides the hunt and its rows.
pub struct Context<'a> {
    pub renderer: &'a Renderer,
    pub now: DateTime<Utc>,
    /// The signatures commit the hunt was loaded from, ace3's `signature_version`.
    pub signature_version: &'a str,
    /// Where the hunt searched, ace3's `tool_instance`, such as the Splunk host.
    pub tool_instance: &'a str,
    /// The query as it ran, with its time ranges, or as the hunt type formats it.
    pub query: Option<String>,
    pub search_id: Option<String>,
    pub search_link: Option<String>,
    /// The hunt type's `extract_event_timestamp`: None for a row it can't take a time from.
    pub event_time: &'a EventTimeFn<'a>,
    /// Whether a type is one ace knows, for a templated observable type.
    pub valid_type: &'a dyn Fn(&str) -> bool,
    pub email: EmailNormalizer,
    /// The hunt's state, for its groups' suppression.
    pub state: &'a State,
    /// A validation run, which ignores suppression, as ace3's `manual_hunt`.
    pub manual: bool,
}

/// What [`process`] made of the rows.
#[derive(Debug, Default)]
pub struct Processed {
    pub submissions: Vec<Submission>,
    /// The submissions a group's suppression dropped, with their keys, which the hunter records.
    pub suppressed: Vec<(Submission, String)>,
}

/// Why rows weren't processed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessError {
    #[error("hunt {0} correlates its rows, which comes with PLAN.md 6.6")]
    Correlation(String),
}

/// A time as Python's `isoformat` writes a UTC one: `2026-11-01T11:55:01+00:00`.
pub fn isoformat(time: &DateTime<Utc>) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
}

fn py_isoformat<S: serde::Serializer>(time: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&isoformat(time))
}

/// The key a group value is kept under: its text, or its JSON for anything but a string.
pub fn group_key(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn text(rendered: Rendered) -> Option<String> {
    match rendered {
        Rendered::Text(t) => Some(t),
        _ => None,
    }
}

/// `QueryHunt.process_query_results`, without correlation.
pub fn process(
    hunt: &HuntConfig,
    rows: &[JsonMap<String, Json>],
    ctx: &Context<'_>,
) -> Result<Processed, ProcessError> {
    if hunt.correlate.is_some() {
        return Err(ProcessError::Correlation(hunt.name.clone()));
    }
    let renderer = ctx.renderer;
    let global_ignored = whole_value_patterns(&hunt.ignored_values);
    let extractor = Extractor {
        renderer,
        global_ignored: &global_ignored,
        valid_type: ctx.valid_type,
        email: ctx.email,
    };
    let loaded: Vec<Row<'_>> = rows.iter().map(Row::new).collect();
    let mut submissions: Vec<Submission> = Vec::new();
    // group value -> the index of its submission
    let mut groups: Vec<(Json, usize)> = Vec::new();
    let mut relationships: Vec<(Observable, Vec<crate::model::RelationshipMapping>)> = Vec::new();
    // row -> its submissions
    let mut row_submissions: Vec<Vec<usize>> = vec![Vec::new(); rows.len()];
    let group_by = hunt.group_by.as_deref();

    for (index, row) in loaded.iter().enumerate() {
        let (event_time, source) = match (ctx.event_time)(row.json) {
            Some(time) => (time, EventTimeSource::Event),
            None => (ctx.now, EventTimeSource::QueryTime),
        };
        let extraction = extractor.extract(row, &hunt.observable_mapping, Some(event_time));
        let mut observables: Vec<Observable> = Vec::new();
        for extracted in extraction.observables {
            match observables
                .iter_mut()
                .find(|o| o.same(&extracted.observable))
            {
                Some(kept) => {
                    for directive in &extracted.observable.directives {
                        kept.add_directive(directive);
                    }
                    for tag in &extracted.observable.tags {
                        kept.add_tag(tag);
                    }
                }
                None => observables.push(extracted.observable),
            }
        }
        for (observable, mappings) in extraction.relationships {
            match relationships.iter_mut().find(|(o, _)| o.same(&observable)) {
                Some(entry) => entry.1 = mappings,
                None => relationships.push((observable, mappings)),
            }
        }
        if let Some(mut signature) =
            Observable::create("signature_id", &hunt.uuid, false, ctx.email)
        {
            signature.display_value = Some(renderer.name(&hunt.name, &row.loaded));
            observables.push(signature);
        }

        let grouped_value = match group_by {
            Some("ALL") => Some(vec![Json::String("ALL".to_owned())]),
            Some(field) => match row.json.get(field) {
                Some(Json::Array(items)) => Some(items.clone()),
                Some(value) => Some(vec![value.clone()]),
                None => None,
            },
            None => None,
        };
        match grouped_value {
            None => {
                let mut submission = create(hunt, row, ctx);
                submission.key = dedup_key(hunt, row, renderer);
                if let Some(key) = &submission.key {
                    submission
                        .extensions
                        .insert("submission_key".to_owned(), json!(key));
                }
                submission.event_time = event_time;
                submission.event_time_source = source;
                if let Some(field) = &hunt.description_field
                    && let Some(value) = row.json.get(field)
                {
                    let value = match value {
                        Json::Array(items) => items.first().map(py_str).unwrap_or_default(),
                        other => py_str(other),
                    };
                    if truthy_text(&value, row.json.get(field)) {
                        submission.description.push_str(&format!(": {value}"));
                    }
                }
                for observable in &observables {
                    add_observable(&mut submission.observables, observable);
                }
                submission.files.extend(extraction.files.iter().cloned());
                events(&mut submission).push(Json::Object(row.json.clone()));
                submission.rows.push(index);
                row_submissions[index].push(submissions.len());
                submissions.push(submission);
            }
            Some(targets) => {
                for target in targets {
                    let at = match groups.iter().find(|(v, _)| *v == target) {
                        Some((_, at)) => *at,
                        None => {
                            let mut submission = create(hunt, row, ctx);
                            submission.key = dedup_key(hunt, row, renderer);
                            if let Some(key) = &submission.key {
                                submission
                                    .extensions
                                    .insert("submission_key".to_owned(), json!(key));
                            }
                            submission.group_value = Some(target.clone());
                            submission
                                .extensions
                                .insert("group_value".to_owned(), target.clone());
                            if target != json!("ALL") {
                                let suffix = match &hunt.description_field {
                                    Some(field) if row.json.contains_key(field) => {
                                        match &row.json[field] {
                                            Json::Array(items) => items
                                                .first()
                                                .map(py_str)
                                                .unwrap_or_else(|| py_str(&target)),
                                            other => py_str(other),
                                        }
                                    }
                                    _ => py_str(&target),
                                };
                                submission.description.push_str(&format!(": {suffix}"));
                            }
                            groups.push((target.clone(), submissions.len()));
                            submissions.push(submission);
                            submissions.len() - 1
                        }
                    };
                    let submission = &mut submissions[at];
                    for observable in &observables {
                        if !submission.observables.iter().any(|o| o.same(observable)) {
                            add_observable(&mut submission.observables, observable);
                        }
                    }
                    submission.files.extend(extraction.files.iter().cloned());
                    events(submission).push(Json::Object(row.json.clone()));
                    submission.rows.push(index);
                    row_submissions[index].push(at);
                    if submission.rows.len() == 1 || event_time < submission.event_time {
                        submission.event_time = event_time;
                        submission.event_time_source = source;
                    }
                }
            }
        }

        // the relationships, for every submission so far, rendered against this row
        for submission in submissions.iter_mut() {
            let targets: Vec<(usize, String, Observable)> = submission
                .observables
                .iter()
                .enumerate()
                .flat_map(|(i, observable)| {
                    let mappings = relationships
                        .iter()
                        .find(|(o, _)| o.same(observable))
                        .map(|(_, m)| m.clone())
                        .unwrap_or_default();
                    let found: Vec<(usize, String, Observable)> = mappings
                        .iter()
                        .flat_map(|mapping| {
                            renderer
                                .event_multi(&mapping.target.value, &row.loaded, true)
                                .unwrap_or_default()
                                .into_iter()
                                .filter(|v| !v.is_empty())
                                .filter_map(|value| {
                                    submission
                                        .observables
                                        .iter()
                                        .find(|t| t.kind == mapping.target.kind && t.value == value)
                                        .map(|t| (i, mapping.kind.clone(), t.clone()))
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    found
                })
                .collect();
            for (i, kind, target) in targets {
                let relationship = observable::Relationship {
                    kind,
                    target: observable::Target {
                        kind: target.kind.clone(),
                        value: target.value.clone(),
                    },
                };
                let rels = &mut submission.observables[i].relationships;
                if !rels.contains(&relationship) {
                    rels.push(relationship);
                }
            }
        }
    }

    if group_by.is_some() {
        for submission in &mut submissions {
            let n = submission.rows.len();
            submission
                .description
                .push_str(&format!(" ({n} event{})", if n == 1 { "" } else { "s" }));
        }
    }

    summary_details(hunt, &loaded, &row_submissions, &mut submissions, renderer);

    for submission in &mut submissions {
        let name = match submission.rows.first() {
            Some(&first) => renderer.name(&hunt.name, &loaded[first].loaded),
            None => hunt.name.clone(),
        };
        submission.details.insert(
            "hunt_metadata".to_owned(),
            json!({
                "name": name,
                "uuid": hunt.uuid,
                "type": hunt.kind,
                "group_by": hunt.group_by,
                "group_value": submission.group_value,
                "description_field": hunt.description_field,
                "frequency": schedule::frequency(hunt).map(timedelta_str),
            }),
        );
    }

    let mut processed = Processed::default();
    if group_by.is_some() && schedule::suppression(hunt).is_some() && !ctx.manual {
        for mut submission in submissions {
            submission.suppression_key = submission.group_value.as_ref().map(group_key);
            match submission.suppression_key.clone() {
                Some(key) if group_suppressed(hunt, ctx.state, &key, ctx.now) => {
                    processed.suppressed.push((submission, key));
                }
                _ => processed.submissions.push(submission),
            }
        }
    } else {
        processed.submissions = submissions;
    }
    Ok(processed)
}

/// Python's truth of a description value: a non-empty string, or any other true value.
fn truthy_text(text: &str, raw: Option<&Json>) -> bool {
    match raw {
        Some(Json::Array(items)) => {
            items
                .first()
                .is_some_and(|v| crate::query::extract::to_loaded(v).truthy())
                && !text.is_empty()
        }
        Some(Json::String(_)) | None => !text.is_empty(),
        Some(other) => crate::query::extract::to_loaded(other).truthy(),
    }
}

fn add_observable(observables: &mut Vec<Observable>, observable: &Observable) {
    if !observables.iter().any(|o| o.same(observable)) {
        observables.push(observable.clone());
    }
}

fn events(submission: &mut Submission) -> &mut Vec<Json> {
    match submission.details.get_mut("events") {
        Some(Json::Array(events)) => events,
        _ => unreachable!("create gives every submission its events"),
    }
}

/// `_compute_dedup_key`.
fn dedup_key(hunt: &HuntConfig, row: &Row<'_>, renderer: &Renderer) -> Option<String> {
    let template = hunt.dedup_key.as_deref().filter(|t| !t.is_empty())?;
    let value = text(renderer.event(template, &row.loaded, true))?;
    (!value.is_empty()).then(|| format!("{}:{value}", hunt.uuid))
}

/// `create_root_analysis`.
fn create(hunt: &HuntConfig, row: &Row<'_>, ctx: &Context<'_>) -> Submission {
    let renderer = ctx.renderer;
    let mut extensions = JsonMap::new();
    if let Some(url) = &hunt.playbook_url
        && let Some(url) = text(renderer.event(url, &row.loaded, true))
        && !url.is_empty()
    {
        extensions.insert("playbook_url".to_owned(), json!(url));
    }
    if let Some(icon) = &hunt.icon_configuration {
        extensions.insert(
            "icon_configuration".to_owned(),
            json!({
                "blueprint_file_location": icon.blueprint_file_location.as_ref().map(|b| json!({"name": b.name, "path": b.path})),
                "url": icon.url,
            }),
        );
    }
    if let Some(template) = &hunt.alert_template {
        extensions.insert("alert_template".to_owned(), json!(template));
    }
    let mut details = JsonMap::new();
    details.insert("search_id".to_owned(), json!(ctx.search_id));
    details.insert("search_link".to_owned(), json!(ctx.search_link));
    details.insert("query".to_owned(), json!(ctx.query));
    details.insert("events".to_owned(), json!([]));
    let mut submission = Submission {
        key: None,
        group_value: None,
        suppression_key: None,
        description: renderer.name(&hunt.name, &row.loaded),
        instructions: hunt.description.clone(),
        analysis_mode: hunt.analysis_mode.clone(),
        alert_type: hunt.alert_type.clone(),
        queue: hunt.queue.clone(),
        tool: format!("hunter-{}", hunt.kind),
        tool_instance: ctx.tool_instance.to_owned(),
        event_time: ctx.now,
        event_time_source: EventTimeSource::QueryTime,
        details,
        extensions,
        tags: Vec::new(),
        pivot_links: Vec::new(),
        summary_details: Vec::new(),
        detections: Vec::new(),
        observables: Vec::new(),
        files: Vec::new(),
        rows: Vec::new(),
    };
    if hunt.analysis_mode == "correlation" {
        submission.detections.push(Detection {
            description: format!("hunt {} ({}) matched", hunt.name, hunt.kind),
            signature_uuid: hunt.uuid.clone(),
            signature_version: ctx.signature_version.to_owned(),
            signature_family: "hunt".to_owned(),
        });
    }
    for tag in &hunt.tags {
        let Ok(values) = renderer.event_multi(tag, &row.loaded, true) else {
            continue;
        };
        for value in values.into_iter().filter(|v| !v.is_empty()) {
            if !submission.tags.contains(&value) {
                submission.tags.push(value);
            }
        }
    }
    for link in &hunt.pivot_links {
        let field = |name: &str| {
            link.get(name).map(|v| match v {
                Json::String(s) => s.clone(),
                other => py_str(other),
            })
        };
        let (Some(url), Some(link_text)) = (field("url"), field("text")) else {
            continue;
        };
        let Ok(rows) = renderer.events_multi(&[&url, &link_text], &row.loaded, true) else {
            continue;
        };
        let icon = link.get("icon").and_then(|v| v.as_str()).map(str::to_owned);
        for mut pair in rows {
            let link_text = pair.pop().unwrap_or_default();
            let url = pair.pop().unwrap_or_default();
            if url.is_empty() || link_text.is_empty() {
                continue;
            }
            submission.pivot_links.push(PivotLink {
                url,
                icon: icon.clone(),
                text: link_text,
            });
        }
    }
    submission
}

/// `event_has_required_fields`.
fn has_required(row: &Row<'_>, fields: &[String]) -> bool {
    fields
        .iter()
        .all(|field| match lookup(row.json, None, field) {
            None => false,
            Some(Json::Null) => false,
            Some(Json::String(s)) => !s.trim_matches(char::is_whitespace).is_empty(),
            Some(Json::Array(a)) => !a.is_empty(),
            Some(Json::Object(o)) => !o.is_empty(),
            Some(_) => true,
        })
}

/// `compute_dedup_key`: the fields' values, a missing one as None.
fn summary_dedup(row: &Row<'_>, fields: &[String]) -> Vec<Option<Json>> {
    fields.iter().map(|f| lookup(row.json, None, f)).collect()
}

/// `_process_summary_details`: each definition over the rows, for the submissions each row is in.
fn summary_details(
    hunt: &HuntConfig,
    rows: &[Row<'_>],
    row_submissions: &[Vec<usize>],
    submissions: &mut [Submission],
    renderer: &Renderer,
) {
    for detail in &hunt.summary_details {
        let limit = usize::try_from(detail.limit).unwrap_or(0);
        // per submission: what it collected, its dedup keys and its first row
        let mut count = vec![0usize; submissions.len()];
        let mut seen: Vec<Vec<Vec<Option<Json>>>> = vec![Vec::new(); submissions.len()];
        let mut collected: Vec<Option<Vec<usize>>> = vec![None; submissions.len()];
        let mut lines: Vec<Vec<String>> = vec![Vec::new(); submissions.len()];
        let mut order: Vec<usize> = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            if row_submissions[index].is_empty() {
                continue;
            }
            if let Some(required) = &detail.required_fields
                && !has_required(row, required)
            {
                continue;
            }
            if !detail.grouped {
                let Some(content) = renderer.summary_content(detail, &row.loaded) else {
                    continue;
                };
                let header = match renderer.summary_header(detail, &row.loaded) {
                    (true, header) => header,
                    (false, _) => None,
                };
                for &at in &row_submissions[index] {
                    if let Some(fields) = &detail.dedup_fields {
                        let key = summary_dedup(row, fields);
                        if seen[at].contains(&key) {
                            continue;
                        }
                        seen[at].push(key);
                    }
                    if count[at] >= limit {
                        count[at] = count[at].saturating_add(usize::from(count[at] == limit));
                        continue;
                    }
                    submissions[at].summary_details.push(SummaryDetail {
                        header: header.clone(),
                        content: content.clone(),
                        format: detail.format.clone(),
                    });
                    count[at] += 1;
                }
                continue;
            }
            // grouped: the jinja form collects rows, the other renders each row now
            let line = if detail.format == "jinja" {
                None
            } else {
                match renderer.summary_content(detail, &row.loaded) {
                    Some(line) => Some(line),
                    None => continue,
                }
            };
            for &at in &row_submissions[index] {
                if collected[at].is_none() {
                    collected[at] = Some(Vec::new());
                    order.push(at);
                }
                if let Some(fields) = &detail.dedup_fields {
                    let key = summary_dedup(row, fields);
                    if seen[at].contains(&key) {
                        continue;
                    }
                    seen[at].push(key);
                }
                let rows_of = collected[at].as_mut().expect("set above");
                if rows_of.len() >= limit {
                    continue;
                }
                rows_of.push(index);
                if let Some(line) = &line {
                    lines[at].push(line.clone());
                }
            }
        }
        if !detail.grouped {
            continue;
        }
        for at in order {
            let collected = collected[at].take().unwrap_or_default();
            let Some(&first) = collected.first() else {
                continue;
            };
            let header = match &detail.header {
                None => None,
                Some(_) => match renderer.summary_header(detail, &rows[first].loaded) {
                    (true, header) => header,
                    (false, _) => None,
                },
            };
            let content = if detail.format == "jinja" {
                let events: Vec<crate::value::Map> =
                    collected.iter().map(|&i| rows[i].loaded.clone()).collect();
                match renderer.grouped_summary_content(detail, &events) {
                    Some(content) => content,
                    None => continue,
                }
            } else {
                lines[at].join("\n")
            };
            submissions[at].summary_details.push(SummaryDetail {
                header,
                content,
                format: detail.format.clone(),
            });
        }
    }
}
