//! The Analyze page (PLAN.md 7.18): ace3's Manual Analysis, where an analyst makes an alert by hand
//! from observables and uploaded files (`app/analysis/views/edit/new.py`, `analysis/analyze_file.html`,
//! `new_alert_observable.html` and `static/js/new_alert.js`, at ace3 `ef85b7b8`).
//!
//! `GET /analyze` is ace3's `/file`, the form. `POST /analyze` is ace3's `/new_alert`: the GUI reads the
//! multipart form (the dates in the chosen timezone, a pair type's two values, a "one per line" value,
//! each file row's upload) and `Service::submit_manual` makes the alert, or one per observable, under
//! `alert:create`. `GET /analyze/row?index=N` is ace3's `/new_alert_observable`, one more observable row,
//! which the page's Add button appends through Datastar.
//!
//! ace3's script becomes Datastar attributes, and the expressions hold no outside value: a row's type
//! select is bound to a signal of the row's own number, and each of its value fields shows for the types
//! it is for. Every field of a row is in the form whatever its type, and the server reads the ones the
//! type uses. What differs from ace3:
//! - There is no Node choice, since ace-rs has one engine and no companies.
//! - The dates are `datetime-local` fields rather than ace3's `MM-DD-YYYY HH:MM:SS` text.
//! - Submit Multiple Alerts is always shown; ace3's script shows it only for more than one row or a
//!   "one per line" value. With one observable it makes the same alert as Submit.
//! - A new file row isn't given `sandbox`: ace3's script ticks it only when a row's type changes to
//!   file, which a new row's never does.
//! - A refusal draws the form again with the reason and what was typed, where ace3 goes to the alert
//!   list with a flash; the files are chosen again, since a browser can't be handed them back.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use ace_results::{AlertPath, ObservableKind};
use ace_service::{
    ALERT_CREATE, ManualAlert, ManualAlerts, ManualObservable, ManualValue, ServiceError,
    SubmittedFile,
};
use askama::Template;
use axum::extract::{Multipart, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use futures_util::TryStreamExt;
use serde::Deserialize;

use crate::Gui;
use crate::session::{Failure, SignedIn, render};
use crate::templates::Layout;

/// The most observable rows a form can hold, and the highest row number `GET /analyze/row` draws.
pub const MAX_ROWS: usize = 1000;

/// The largest text field of the form.
const MAX_FIELD_BYTES: usize = 1 << 20;

/// ace3's default description on the form.
const DEFAULT_DESCRIPTION: &str = "Manual Correlation";

/// The types whose directives are typed rather than picked, as ace3's script switches them.
const TYPED_DIRECTIVES: &[&str] = &["email_address", "user"];

/// The types entered as two values, and what joins them, as ace3's `new_alert` does.
fn pair_join(kind: &str, a: &str, b: &str) -> Option<String> {
    match kind {
        "email_conversation" | "email_delivery" => Some(format!("{a}|{b}")),
        "ipv4_conversation" => Some(format!("{a}_{b}")),
        "ipv4_full_conversation" => Some(format!("{a}:{b}")),
        // ace3's `create_file_location`
        "file_location" => Some(format!("{}@{b}", a.trim())),
        _ => None,
    }
}

/// What the form's limits are on this node: the API's limits on a submission (`ace_api::WebConfig`),
/// which `ace serve` gives the GUI too.
#[derive(Debug, Clone, Copy)]
pub struct SubmissionLimits {
    /// The largest form, files included.
    pub max_bytes: usize,
    /// The most files one form holds.
    pub max_files: usize,
}

impl Default for SubmissionLimits {
    fn default() -> Self {
        SubmissionLimits {
            max_bytes: 1 << 30,
            max_files: 1000,
        }
    }
}

/// One observable row, as it was typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzeRow {
    pub index: usize,
    pub time: String,
    /// The type's name; `file` for a new row, as ace3's.
    pub kind: String,
    pub value: String,
    /// The "one per line" value, and whether it's the one used.
    pub values: String,
    pub multi: bool,
    /// A pair type's two values.
    pub a: String,
    pub b: String,
    pub directives: Vec<String>,
    pub directive_text: String,
}

impl AnalyzeRow {
    fn new(index: usize) -> Self {
        AnalyzeRow {
            index,
            kind: ObservableKind::File.to_string(),
            ..AnalyzeRow::default()
        }
    }

    pub fn is_kind(&self, kind: &str) -> bool {
        self.kind == kind
    }

    pub fn has_directive(&self, directive: &str) -> bool {
        self.directives.iter().any(|d| d == directive)
    }
}

/// What the form shows, filled in or as typed.
#[derive(Debug, Clone)]
pub struct AnalyzeView {
    pub date: String,
    pub timezone: String,
    pub timezones: Vec<&'static str>,
    pub description: String,
    pub queue: String,
    /// The template chosen, empty for Automatic.
    pub template: String,
    /// The binary's named alert summaries, the templates an analyst can choose.
    pub templates: Vec<&'static str>,
    pub rows: Vec<AnalyzeRow>,
    /// The number the next row added gets.
    pub next_index: usize,
    pub problem: Option<String>,
}

impl AnalyzeView {
    pub fn is_timezone(&self, zone: &str) -> bool {
        self.timezone == zone
    }

    pub fn is_template(&self, template: &str) -> bool {
        self.template == template
    }
}

/// The observable types and directives a row offers.
#[derive(Debug, Clone)]
pub struct RowChoices {
    pub types: Vec<String>,
    /// Each directive's name and description.
    pub directives: Vec<(&'static str, &'static str)>,
}

impl RowChoices {
    fn of(gui: &Gui) -> Self {
        RowChoices {
            types: ObservableKind::all()
                .iter()
                .map(ToString::to_string)
                .collect(),
            directives: gui
                .service
                .directives()
                .iter()
                .map(|d| (d.name, d.description))
                .collect(),
        }
    }
}

/// `/analyze`.
#[derive(Debug, Template)]
#[template(path = "analyze.html")]
pub struct AnalyzePage {
    pub layout: Layout,
    pub view: AnalyzeView,
    pub choices: RowChoices,
}

/// One row, the fragment `GET /analyze/row` appends.
#[derive(Debug, Template)]
#[template(path = "analyze_row.html")]
pub struct AnalyzeRowFragment {
    pub row: AnalyzeRow,
    pub choices: RowChoices,
}

async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &ALERT_CREATE).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "Manual analysis needs alert:create. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// The form as it first shows: now in UTC, ace3's description, the viewer's own queue, Automatic, and
/// one file row.
async fn blank(gui: &Gui, viewer: &SignedIn) -> Result<AnalyzeView, ServiceError> {
    let queue = gui.service.own_account(&viewer.actor).await?.queue;
    Ok(AnalyzeView {
        date: Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        timezone: "UTC".to_owned(),
        timezones: crate::preferences::timezones(),
        description: DEFAULT_DESCRIPTION.to_owned(),
        queue,
        template: String::new(),
        templates: gui.summaries.templates().collect(),
        rows: vec![AnalyzeRow::new(0)],
        next_index: 1,
        problem: None,
    })
}

/// `GET /analyze`.
pub(crate) async fn page(State(gui): State<Gui>, viewer: SignedIn, parts: Parts) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    match blank(&gui, &viewer).await {
        Ok(view) => render(&AnalyzePage {
            layout: viewer.layout,
            choices: RowChoices::of(&gui),
            view,
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct RowQuery {
    index: usize,
}

/// `GET /analyze/row?index=N`: one more row, as a `datastar-patch-elements` event that appends it to the
/// form's rows.
pub(crate) async fn row(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    query: Result<Query<RowQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let index = match query {
        Ok(Query(RowQuery { index })) if index < MAX_ROWS => index,
        _ => {
            return Failure::new(
                StatusCode::BAD_REQUEST,
                format!("A row's number is below {MAX_ROWS}."),
                &parts,
            )
            .into_response();
        }
    };
    let fragment = AnalyzeRowFragment {
        row: AnalyzeRow::new(index),
        choices: RowChoices::of(&gui),
    };
    match fragment.render() {
        Ok(html) => (
            [
                (header::CONTENT_TYPE, "text/event-stream"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            append_event("#observables", &html),
        )
            .into_response(),
        Err(error) => {
            tracing::error!("an observable row couldn't be drawn: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// A `datastar-patch-elements` event that appends `html` inside `selector`. A carriage return can't be in
/// a `data:` line, so it's written as its entity, as `alert`'s events do.
fn append_event(selector: &str, html: &str) -> String {
    let mut event =
        format!("event: datastar-patch-elements\ndata: selector {selector}\ndata: mode append\n");
    for line in html.replace('\r', "&#13;").lines() {
        event.push_str("data: elements ");
        event.push_str(line);
        event.push('\n');
    }
    event.push('\n');
    event
}

/// What the form posted: its text fields, and each row's upload by row number.
#[derive(Debug, Default)]
pub(crate) struct Posted {
    fields: Vec<(String, String)>,
    files: BTreeMap<usize, SubmittedFile>,
}

impl Posted {
    fn one(&self, name: &str) -> &str {
        crate::list::one(&self.fields, name).unwrap_or("")
    }

    fn all(&self, name: &str) -> Vec<String> {
        crate::list::all(&self.fields, name)
    }
}

/// Why a form wasn't read: drawn as the form again, or a failure page when the form itself is broken.
enum Unread {
    Problem(String),
    Failed(Failure),
}

/// Reads the multipart form, spooling each row's upload into the node cache as it arrives. A file field
/// with no file chosen, which a browser sends with an empty name, is no upload.
async fn read_form(gui: &Gui, mut form: Multipart, parts: &Parts) -> Result<Posted, Unread> {
    let too_large = |e: axum::extract::multipart::MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Unread::Failed(Failure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The form is too large.",
                parts,
            ))
        } else {
            Unread::Failed(Failure::new(
                StatusCode::BAD_REQUEST,
                format!("The form doesn't read: {e}"),
                parts,
            ))
        }
    };
    let Some(bucket) = gui.service.bucket() else {
        return Err(Unread::Failed(Failure::from_service(
            ServiceError::Unconfigured("this node has no bucket to keep the files in".to_owned()),
            parts,
        )));
    };
    let mut posted = Posted::default();
    while let Some(field) = form.next_field().await.map_err(too_large)? {
        let name = field.name().unwrap_or_default().to_owned();
        if let Some(index) = name.strip_prefix("file_") {
            let file_name = field.file_name().unwrap_or_default().to_owned();
            if file_name.is_empty() {
                // drain it: nothing was chosen
                drop(field);
                continue;
            }
            let index: usize = index.parse().map_err(|_| {
                Unread::Failed(Failure::new(
                    StatusCode::BAD_REQUEST,
                    format!("An unexpected form field {name:?}."),
                    parts,
                ))
            })?;
            if posted.files.len() >= gui.limits.max_files {
                return Err(Unread::Problem(format!(
                    "A form holds at most {} files.",
                    gui.limits.max_files
                )));
            }
            let path = AlertPath::new(file_name.clone())
                .map_err(|e| Unread::Problem(format!("The file name {file_name:?}: {e}.")))?;
            let over = AtomicBool::new(false);
            let stream = field.map_err(|e| {
                if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    over.store(true, Ordering::Relaxed);
                }
                std::io::Error::other(e)
            });
            let mut reader = tokio_util::io::StreamReader::new(stream);
            let spooled = bucket.store().spool_reader(&mut reader).await;
            drop(reader);
            let spooled = spooled.map_err(|e| {
                if over.load(Ordering::Relaxed) {
                    Unread::Failed(Failure::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "The form is too large.",
                        parts,
                    ))
                } else {
                    Unread::Problem(format!("The file {file_name:?} didn't arrive: {e}."))
                }
            })?;
            posted.files.insert(index, SubmittedFile { path, spooled });
        } else {
            let mut text = Vec::new();
            let mut field = field;
            while let Some(chunk) = field.chunk().await.map_err(too_large)? {
                if text.len() + chunk.len() > MAX_FIELD_BYTES {
                    return Err(Unread::Problem(format!(
                        "The field {name:?} is over {MAX_FIELD_BYTES} bytes."
                    )));
                }
                text.extend_from_slice(&chunk);
            }
            let text = String::from_utf8(text)
                .map_err(|_| Unread::Problem(format!("The field {name:?} isn't UTF-8.")))?;
            posted.fields.push((name, text));
        }
    }
    Ok(posted)
}

/// The rows the form posted, by row number, as typed.
fn posted_rows(posted: &Posted) -> Vec<AnalyzeRow> {
    let mut indexes: Vec<usize> = posted
        .fields
        .iter()
        .filter_map(|(name, _)| name.strip_prefix("type_")?.parse().ok())
        .collect();
    indexes.sort_unstable();
    indexes.dedup();
    indexes
        .into_iter()
        .map(|i| AnalyzeRow {
            index: i,
            time: posted.one(&format!("time_{i}")).to_owned(),
            kind: posted.one(&format!("type_{i}")).to_owned(),
            value: posted.one(&format!("value_{i}")).to_owned(),
            values: posted.one(&format!("values_{i}")).to_owned(),
            multi: !posted.one(&format!("multi_{i}")).is_empty(),
            a: posted.one(&format!("a_{i}")).to_owned(),
            b: posted.one(&format!("b_{i}")).to_owned(),
            directives: posted.all(&format!("directives_{i}")),
            directive_text: posted.one(&format!("directive_text_{i}")).to_owned(),
        })
        .collect()
}

/// A `datetime-local` value, with or without its seconds, as a time in `zone`.
fn local_time(text: &str, zone: Tz, what: &str) -> Result<DateTime<Utc>, String> {
    let naive = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M"))
        .map_err(|_| format!("{what} {text:?} isn't a date and time."))?;
    zone.from_local_datetime(&naive)
        .earliest()
        .map(|time| time.with_timezone(&Utc))
        .ok_or_else(|| format!("{what} {text:?} doesn't exist in {zone}."))
}

/// ace3's "multi" value: split on newlines, or on commas when it has none, each part trimmed.
fn split_values(text: &str) -> Vec<String> {
    let parts: Vec<&str> = if text.contains(['\r', '\n']) {
        text.lines().collect()
    } else {
        text.split(',').collect()
    };
    parts
        .into_iter()
        .map(|part| part.trim().to_owned())
        .collect()
}

/// ace3's directives for a row: typed for `email_address` and `user`; else those picked, or those typed
/// when none were picked, as ace3's `new_alert` falls back to the text field.
fn row_directives(row: &AnalyzeRow) -> Vec<String> {
    let typed = || {
        row.directive_text
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_owned)
            .collect()
    };
    if TYPED_DIRECTIVES.contains(&row.kind.as_str()) || row.directives.is_empty() {
        typed()
    } else {
        row.directives.clone()
    }
}

/// The alert the form describes, taking each row's upload.
fn manual_alert(
    gui: &Gui,
    posted: &mut Posted,
    rows: &[AnalyzeRow],
) -> Result<ManualAlert, String> {
    let zone_name = posted.one("timezone");
    let zone: Tz = zone_name
        .parse()
        .map_err(|_| format!("There's no timezone {zone_name:?}."))?;
    let date = posted.one("date");
    let event_time = if date.is_empty() {
        Utc::now()
    } else {
        local_time(date, zone, "The insert date")?
    };
    let template = posted.one("template");
    let alert_template = if template.is_empty() {
        None
    } else if gui.summaries.templates().any(|t| t == template) {
        Some(template.to_owned())
    } else {
        tracing::warn!(
            template,
            "a manual alert named an alert template the binary hasn't"
        );
        return Err(format!("There's no alert template {template:?}."));
    };
    if rows.len() > MAX_ROWS {
        return Err(format!("A form holds at most {MAX_ROWS} observables."));
    }
    let mut observables = Vec::new();
    for row in rows {
        let kind: ObservableKind = row
            .kind
            .parse()
            .map_err(|_| format!("Observable {}: there's no type {:?}.", row.index, row.kind))?;
        let time = if row.time.is_empty() {
            None
        } else {
            Some(local_time(
                &row.time,
                zone,
                &format!("Observable {}'s time", row.index),
            )?)
        };
        let directives = row_directives(row);
        let one = |value: ManualValue| ManualObservable {
            kind,
            value,
            time,
            directives: directives.clone(),
        };
        if kind == ObservableKind::File {
            // a file row is nothing without its upload, and refuses the whole form
            let file = posted
                .files
                .remove(&row.index)
                .ok_or_else(|| format!("No file was uploaded for observable {}.", row.index))?;
            observables.push(one(ManualValue::File(file)));
        } else if let Some(value) = pair_join(&row.kind, &row.a, &row.b) {
            observables.push(one(ManualValue::Text(value)));
        } else if row.multi {
            for value in split_values(&row.values) {
                observables.push(one(ManualValue::Text(value)));
            }
        } else {
            observables.push(one(ManualValue::Text(row.value.clone())));
        }
    }
    Ok(ManualAlert {
        description: posted.one("description").to_owned(),
        queue: posted.one("queue").to_owned(),
        alert_template,
        event_time,
        observables,
        alerts: if posted.one("submit") == "each" {
            ManualAlerts::PerObservable
        } else {
            ManualAlerts::One
        },
    })
}

/// `POST /analyze`: the alert, or one per observable, and then the alert made, or the last of several.
pub(crate) async fn submit(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = match form {
        Ok(form) => form,
        Err(rejection) => {
            return Failure::new(StatusCode::BAD_REQUEST, rejection.body_text(), &parts)
                .into_response();
        }
    };
    let mut posted = match read_form(&gui, form, &parts).await {
        Ok(posted) => posted,
        Err(Unread::Failed(failure)) => return failure.into_response(),
        Err(Unread::Problem(problem)) => {
            return again(
                &gui,
                viewer,
                &parts,
                &Posted::default(),
                Vec::new(),
                problem,
            )
            .await;
        }
    };
    let rows = posted_rows(&posted);
    let alert = match manual_alert(&gui, &mut posted, &rows) {
        Ok(alert) => alert,
        Err(problem) => return again(&gui, viewer, &parts, &posted, rows, problem).await,
    };
    let Some(bucket) = gui.service.bucket() else {
        return Failure::from_service(
            ServiceError::Unconfigured("this node has no bucket to keep the files in".to_owned()),
            &parts,
        )
        .into_response();
    };
    match gui
        .service
        .submit_manual(&viewer.actor, bucket, alert)
        .await
    {
        Ok(made) => match made.last() {
            Some(last) => Redirect::to(&format!("/alerts/{last}")).into_response(),
            None => {
                tracing::error!(actor = %viewer.actor, "a manual submission made no alert");
                Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error", &parts)
                    .into_response()
            }
        },
        Err(ServiceError::InvalidRequest(problem)) => {
            again(&gui, viewer, &parts, &posted, rows, problem).await
        }
        Err(error) => {
            tracing::error!(actor = %viewer.actor, "a manual alert couldn't be made: {error}");
            Failure::from_service(error, &parts).into_response()
        }
    }
}

/// The form again, as it was typed, with why it was refused.
async fn again(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    posted: &Posted,
    rows: Vec<AnalyzeRow>,
    problem: String,
) -> Response {
    let mut view = match blank(gui, &viewer).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    if !posted.fields.is_empty() {
        view.date = posted.one("date").to_owned();
        view.timezone = posted.one("timezone").to_owned();
        view.description = posted.one("description").to_owned();
        view.queue = posted.one("queue").to_owned();
        view.template = posted.one("template").to_owned();
        view.next_index = rows.iter().map(|r| r.index + 1).max().unwrap_or(0);
        view.rows = rows;
    }
    view.problem = Some(problem);
    let mut response = render(&AnalyzePage {
        layout: viewer.layout,
        choices: RowChoices::of(gui),
        view,
    });
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}
