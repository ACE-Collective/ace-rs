//! The SVS area (PLAN.md 7.10 batch 5, part 5b): ace3's `app/svs` views and `svs/_tabs.html`,
//! `runs.html`, `run.html` and `test_hosts.html`, over `ace_service`'s `svs_run_reads`, `svs_results`,
//! `svs_decisions` and `svs`.
//!
//! The area's gate is `svs:run_read`, as ace3's blueprint gate is: a user without it gets 403, and a
//! visitor who isn't signed in goes to the login. ace3's pages are shells its scripts fill from
//! `/api/v2/svs`; here the server draws each one, and every control is a link or a form:
//! - `svs.svs_home`: `GET /svs`, which goes to the runs that need attention, the view ace3's Runs tab
//!   opens with.
//! - `svs.runs` and `svs.batches` (`runs.html`): `GET /svs/runs` and `GET /svs/runs/batches`, the runs
//!   newest first, or one row per batch, with ace3's runs screen's filters as a `GET` form folded into `f`,
//!   pages as First and Next links, the API's exports beside them, and how many of the missing signatures of
//!   reviewed runs were possibly suppressed.
//! - `svs.run_detail` (`run.html`): `GET /svs/runs/{run_id}`, the run with what its launcher sent and its
//!   test printed, its result a row per signature, how each did in the test's earlier runs, its comments
//!   and its event log. For `svs:run_manage`, each signature of the result has its decisions as forms
//!   (expect, reject, undecide, ignore for the test), and the page has the comment form; a global ignore's
//!   form is `svs:admin`'s. A decision made from the page says what the page showed, so one someone else
//!   made first is refused (412) rather than replaced.
//! - `svs.test_hosts` (`test_hosts.html`): `GET /svs/test-hosts`, the hosts runs may target, for
//!   `svs:admin`, with the form that adds one; `GET /svs/test-hosts/{id}` is a host's form, whose post
//!   carries the `updated_at` the form was drawn from, so a change from a stale form is refused.
//!
//! Each post is a `SignedIn` post that passed 5.7's same-origin check, through the service, which checks
//! its permission and writes its audit row, and answers with a redirect to the page it came from.
//!
//! Everything a run names comes from a launcher, a catalog repository, a rule or a person: test and
//! signature names, launcher and batch names, reasons, a test's output, comments. askama escapes it, and a
//! value in a link is percent-encoded; the log search is a link only when it's http or https, which the
//! overlay's check already requires.
//!
//! Left out, each with the batch that brings it: ace3's saved filters for this screen (the alert list's
//! saved filters cover no SVS screen yet); the run's alerts, its association form and its review, and the
//! runs' bulk actions (take, cancel, end, close), which are batches 6 and 7's; the Tests, Coverage and
//! Worklist tabs (batch 8); and the Guides link and the navigation entry's count (batch 9). The layout has
//! a plain SVS link for whoever holds `svs:run_read`, so the area can be reached until then.

use ace_service::filters::FilterScreen;
use ace_service::{
    HostFields, Ignore, IgnoreQuery, Precondition, Run, RunBatch, RunComment, RunEvent, RunHistory,
    RunQuery, RunResult, RunRow, SVS_ADMIN, SVS_RUN_MANAGE, SVS_RUN_READ, ServiceError,
    SuppressionShare, TestHost,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::Gui;
use crate::list::{one, pairs};
use crate::remediation::{FilterField, filter_fields, list_request};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// Runs, batches and test hosts on one page.
pub const SVS_PER_PAGE: u32 = 50;
/// A run page's result rows, earlier runs and events: what one page shows of each.
const RUN_PAGE_RESULTS: i64 = 500;
const RUN_PAGE_EVENTS: i64 = 200;

/// The runs that need attention: the view the Runs tab opens with.
pub const NEEDS_ATTENTION: &str = "/svs/runs?f=needs_attention%3Atrue";

fn when(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn maybe(time: Option<DateTime<Utc>>) -> String {
    time.map(when).unwrap_or_default()
}

fn with_query(path: &str, pairs: &[(&str, String)]) -> String {
    let encoded = serde_urlencoded::to_string(pairs).unwrap_or_default();
    if encoded.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{encoded}")
    }
}

/// A run's page.
pub fn run_href(uuid: Uuid) -> String {
    format!("/svs/runs/{uuid}")
}

/// A run state's badge class.
fn state_class(state: &str, needs_attention: bool) -> &'static str {
    match state {
        _ if needs_attention => "warning",
        "reviewed" => "success",
        "error" => "danger",
        "started" => "info",
        _ => "secondary",
    }
}

/// A result status's badge class.
fn status_class(status: &str) -> &'static str {
    match status {
        "hit" => "success",
        "missing" => "danger",
        "possibly_suppressed" | "candidate" => "warning",
        _ => "secondary",
    }
}

/// The area's tabs: only those the viewer may open are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tabs {
    /// `runs` or `test_hosts`: the open tab.
    pub open: &'static str,
    /// The viewer holds `svs:admin`, which the Test hosts tab needs.
    pub admin: bool,
}

/// A run as the list's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLine {
    pub href: String,
    pub created: String,
    pub test_name: String,
    pub technique: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub needs_attention: bool,
    pub platform: String,
    /// Each target as host or host/user.
    pub targets: String,
    pub launcher: String,
    pub batch: String,
    /// The runs of its batch.
    pub batch_href: Option<String>,
    /// `hit/expected`, empty without a result.
    pub hits: String,
    pub missing: i64,
    pub candidates: i64,
    pub alerts: i64,
    pub owner: String,
    pub stale: bool,
}

fn targets_of(run: &Run) -> String {
    run.targets
        .iter()
        .map(|target| match &target.username {
            Some(username) => format!("{}/{username}", target.hostname),
            None => target.hostname.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn run_line(row: &RunRow) -> RunLine {
    let run = &row.run;
    let s = &row.summary;
    let state = run.state.as_str();
    RunLine {
        href: run_href(run.uuid),
        created: when(run.created_at),
        test_name: row
            .test_name
            .clone()
            .unwrap_or_else(|| run.test_guid.to_string()),
        technique: row.technique.clone().unwrap_or_default(),
        state,
        state_class: state_class(state, row.needs_attention),
        needs_attention: row.needs_attention,
        platform: run.platform.clone(),
        targets: targets_of(run),
        launcher: run.launcher.clone(),
        batch: run.batch_id.clone().unwrap_or_default(),
        batch_href: run.batch_id.as_ref().map(|batch| batch_runs_href(batch)),
        hits: if s.expected() > 0 {
            format!("{}/{}", s.hit, s.expected())
        } else {
            String::new()
        },
        missing: s.all_missing(),
        candidates: s.candidate,
        alerts: s.alerts,
        owner: row.owner.clone().unwrap_or_default(),
        stale: s.result_stale,
    }
}

/// The runs of a batch: the runs list narrowed to it.
fn batch_runs_href(batch: &str) -> String {
    let entry = ace_service::FilterEntry::text("Batch", false, &[batch]);
    let filters = ace_service::filters::encode(FilterScreen::SvsRuns, &[entry]).unwrap_or_default();
    let pairs: Vec<(&str, String)> = filters.into_iter().map(|f| ("f", f)).collect();
    with_query("/svs/runs", &pairs)
}

/// The possibly-suppressed share, as the runs view states it.
pub fn share_line(share: &SuppressionShare) -> Option<String> {
    if share.reviewed_runs == 0 {
        return None;
    }
    let percent = share
        .share()
        .map(|share| format!(" ({:.0}%)", share * 100.0))
        .unwrap_or_default();
    Some(format!(
        "{} of {} expected signatures missing from {} reviewed runs were possibly suppressed{percent}.{}",
        share.possibly_suppressed,
        share.missing,
        share.reviewed_runs,
        if share.reconsider() {
            " Keeping the hunter from suppressing test targets is worth reconsidering."
        } else {
            ""
        }
    ))
}

/// `/svs/runs`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunsView {
    pub tabs: Tabs,
    pub fields: Vec<FilterField>,
    pub total: i64,
    pub share: Option<String>,
    pub rows: Vec<RunLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
    /// The batches of the same filters.
    pub batches: String,
}

fn filter_pairs(filters: &[String]) -> Vec<(&'static str, String)> {
    filters.iter().map(|f| ("f", f.clone())).collect()
}

fn pages(
    path: &str,
    filters: &[String],
    cursor: Option<&str>,
    next: Option<&str>,
) -> (Option<String>, Option<String>) {
    let base = filter_pairs(filters);
    let page = |cursor: Option<&str>| {
        let mut pairs = base.clone();
        if let Some(cursor) = cursor {
            pairs.push(("cursor", cursor.to_owned()));
        }
        with_query(path, &pairs)
    };
    (
        cursor.map(|_| page(None)),
        next.map(|next| page(Some(next))),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn runs_view(
    tabs: Tabs,
    query: &RunQuery,
    filters: &[String],
    total: i64,
    share: &SuppressionShare,
    runs: &[RunRow],
    cursor: Option<&str>,
    next: Option<&str>,
) -> RunsView {
    let base = filter_pairs(filters);
    let (first, next) = pages("/svs/runs", filters, cursor, next);
    RunsView {
        tabs,
        fields: filter_fields(FilterScreen::SvsRuns, &query.filters),
        total,
        share: share_line(share),
        rows: runs.iter().map(run_line).collect(),
        first,
        next,
        csv: with_query("/api/svs/v1/runs/export/csv", &base),
        ndjson: with_query("/api/svs/v1/runs/export/ndjson", &base),
        batches: with_query("/svs/runs/batches", &base),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/runs.html")]
pub struct RunsPage {
    pub layout: Layout,
    pub view: RunsView,
}

/// A batch as the batches view's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLine {
    pub batch: String,
    pub href: String,
    pub runs: i64,
    /// The states that have runs, as `2 ended, 1 started`.
    pub states: String,
    pub needs_attention: i64,
    pub first: String,
    pub last: String,
    pub hits: String,
    pub missing: i64,
    pub candidates: i64,
}

pub fn batch_line(batch: &RunBatch) -> BatchLine {
    BatchLine {
        href: batch_runs_href(&batch.batch_id),
        batch: batch.batch_id.clone(),
        runs: batch.runs,
        states: batch
            .states
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(state, count)| format!("{count} {state}"))
            .collect::<Vec<_>>()
            .join(", "),
        needs_attention: batch.needs_attention,
        first: when(batch.first_created_at),
        last: when(batch.last_created_at),
        hits: if batch.result_expected > 0 {
            format!("{}/{}", batch.result_hit, batch.result_expected)
        } else {
            String::new()
        },
        missing: batch.result_missing,
        candidates: batch.result_candidate,
    }
}

/// `/svs/runs/batches`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchesView {
    pub tabs: Tabs,
    pub fields: Vec<FilterField>,
    pub rows: Vec<BatchLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
    /// The runs of the same filters.
    pub runs: String,
}

pub fn batches_view(
    tabs: Tabs,
    query: &RunQuery,
    filters: &[String],
    batches: &[RunBatch],
    cursor: Option<&str>,
    next: Option<&str>,
) -> BatchesView {
    let base = filter_pairs(filters);
    let (first, next) = pages("/svs/runs/batches", filters, cursor, next);
    BatchesView {
        tabs,
        fields: filter_fields(FilterScreen::SvsRuns, &query.filters),
        rows: batches.iter().map(batch_line).collect(),
        first,
        next,
        csv: with_query("/api/svs/v1/runs/batches/export/csv", &base),
        ndjson: with_query("/api/svs/v1/runs/batches/export/ndjson", &base),
        runs: with_query("/svs/runs", &base),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/batches.html")]
pub struct BatchesPage {
    pub layout: Layout,
    pub view: BatchesView,
}

/// A fact of a run: its name and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub name: &'static str,
    pub value: String,
}

/// One signature of a run's result, with what its viewer may decide about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultLine {
    pub signature: String,
    pub name: String,
    pub family: String,
    /// Its live status; `left the result` once it has none.
    pub status: String,
    pub status_class: &'static str,
    pub alerts: i32,
    /// `late`, `context only`, `fallback time`: what's said of how it fired.
    pub notes: String,
    /// The alert that may have suppressed it.
    pub suppressing: Option<String>,
    pub reviewed: String,
    /// Its status in each earlier run, in the history's order; empty where it wasn't in that run's result.
    pub history: Vec<String>,
    /// The decisions its viewer may make: each a form's `decision` and its button's text.
    pub decisions: Vec<(&'static str, &'static str)>,
}

fn decisions_of(
    row: &RunResult,
    manage: bool,
    admin: bool,
    ignored_for_test: bool,
    ignored_globally: bool,
) -> Vec<(&'static str, &'static str)> {
    let mut decisions = Vec::new();
    if !manage {
        return decisions;
    }
    match row.status.as_deref() {
        Some("candidate") => {
            decisions.push(("expected", "Expect"));
            decisions.push(("rejected", "Reject"));
            decisions.push(("ignore", "Ignore for this test"));
            if admin {
                decisions.push(("ignore_globally", "Ignore for every test"));
            }
        }
        Some("hit" | "missing" | "possibly_suppressed" | "rejected") => {
            decisions.push(("undecide", "Undecide"));
        }
        Some("ignored") => {
            if ignored_for_test {
                decisions.push(("unignore", "Stop ignoring for this test"));
            }
            if ignored_globally && admin {
                decisions.push(("unignore_globally", "Stop ignoring for every test"));
            }
        }
        _ => {}
    }
    decisions
}

/// A comment, and whether its viewer wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentLine {
    pub id: i64,
    pub user: String,
    pub comment: String,
    pub created: String,
    /// When it was changed after it was written.
    pub edited: Option<String>,
    /// Its viewer wrote it, and manages runs: the edit and delete forms.
    pub own: bool,
    pub action: String,
}

/// One row of a run's event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLine {
    pub at: String,
    pub kind: String,
    /// `created → started`, for a transition.
    pub states: String,
    pub actor: String,
    /// Its details, as JSON.
    pub details: String,
}

pub fn event_line(event: &RunEvent) -> EventLine {
    EventLine {
        at: when(event.created_at),
        kind: event.kind.clone(),
        states: match (event.from_state, event.to_state) {
            (Some(from), Some(to)) => format!("{from} → {to}"),
            (None, Some(to)) => to.to_string(),
            _ => String::new(),
        },
        actor: event
            .actor
            .as_ref()
            .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone()))
            .unwrap_or_default(),
        details: event
            .details
            .as_ref()
            .map(|details| details.to_string())
            .unwrap_or_default(),
    }
}

/// What a run page is drawn from.
pub struct RunPageData<'a> {
    pub row: &'a RunRow,
    pub launcher_output: Option<&'a str>,
    pub log_search: Option<String>,
    pub results: &'a [RunResult],
    pub result_stale: bool,
    pub computed_at: Option<DateTime<Utc>>,
    pub history: &'a RunHistory,
    pub ignores: &'a [Ignore],
    pub comments: &'a [RunComment],
    pub events: &'a [RunEvent],
    /// The viewer's name, and what they hold.
    pub viewer: Option<&'a str>,
    pub manage: bool,
    pub admin: bool,
    pub notice: Option<String>,
}

/// `/svs/runs/{run_id}`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunView {
    pub tabs: Tabs,
    pub href: String,
    pub uuid: String,
    pub title: String,
    pub technique: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub needs_attention: bool,
    pub notice: Option<String>,
    pub facts: Vec<Fact>,
    pub launcher_error: String,
    pub launcher_output: String,
    /// The run's search in the site's log tooling, when it's an http or https link.
    pub log_search: Option<String>,
    pub result_note: String,
    pub results: Vec<ResultLine>,
    /// The earlier runs the history compares with, newest first: each its page and when it was registered.
    pub earlier: Vec<(String, String)>,
    pub comments: Vec<CommentLine>,
    pub manage: bool,
    pub events: Vec<EventLine>,
    /// More events than the page shows: the rest are the API's.
    pub more_events: bool,
    pub events_csv: String,
    pub results_csv: String,
}

fn seconds(seconds: i32) -> String {
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    match (hours, minutes) {
        (0, minutes) => format!("{minutes} min"),
        (hours, 0) => format!("{hours} h"),
        (hours, minutes) => format!("{hours} h {minutes} min"),
    }
}

pub fn run_view(tabs: Tabs, data: &RunPageData<'_>) -> RunView {
    let row = data.row;
    let run = &row.run;
    let state = run.state.as_str();
    let mut facts = vec![
        Fact {
            name: "Test",
            value: run.test_guid.to_string(),
        },
        Fact {
            name: "Platform",
            value: run.platform.clone(),
        },
        Fact {
            name: "Targets",
            value: targets_of(run),
        },
        Fact {
            name: "Launcher",
            value: run.launcher.clone(),
        },
        Fact {
            name: "Marker",
            value: run.marker.clone(),
        },
        Fact {
            name: "Registered",
            value: when(run.created_at),
        },
    ];
    let mut fact = |name: &'static str, value: String| {
        if !value.is_empty() {
            facts.push(Fact { name, value });
        }
    };
    fact("Batch", run.batch_id.clone().unwrap_or_default());
    fact(
        "Registered by",
        run.registered_by
            .as_ref()
            .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone()))
            .unwrap_or_default(),
    );
    fact("Started", maybe(run.started_at));
    fact("Executed", maybe(run.executed_at));
    fact(
        "Exit code",
        run.exit_code
            .map(|code| code.to_string())
            .unwrap_or_default(),
    );
    fact("Cleanup began", maybe(run.cleanup_at));
    fact(
        "Observation window",
        format!(
            "{}{}",
            seconds(run.observation_seconds),
            run.observation_ends_at
                .map(|at| format!(", until {}", when(at)))
                .unwrap_or_default()
        ),
    );
    fact(
        "Attribution window",
        format!(
            "{}{}{}",
            seconds(run.attribution_seconds),
            run.attribution_ends_at
                .map(|at| format!(", until {}", when(at)))
                .unwrap_or_default(),
            if run.holds_host {
                ", holding its hosts"
            } else {
                ""
            }
        ),
    );
    fact("Ended", maybe(run.ended_at));
    fact(
        "Ended early because",
        run.end_reason.clone().unwrap_or_default(),
    );
    fact("Canceled", maybe(run.canceled_at));
    fact(
        "Failed because",
        run.error_reason.clone().unwrap_or_default(),
    );
    fact("Closed", maybe(run.closed_at));
    fact(
        "Closed because",
        run.close_reason.clone().unwrap_or_default(),
    );
    fact("Owner", row.owner.clone().unwrap_or_default());
    fact("Reviewed by", row.reviewer.clone().unwrap_or_default());
    fact("Reviewed", maybe(row.reviewed_at));
    let s = &row.summary;
    fact(
        "Alerts",
        if s.alerts > 0 {
            format!(
                "{} ({} by a marker, {} by context alone, {} late)",
                s.alerts, s.marker_alerts, s.context_alerts, s.late_alerts
            )
        } else {
            String::new()
        },
    );
    if run.extra.as_object().is_some_and(|extra| !extra.is_empty()) {
        fact("Extra", run.extra.to_string());
    }

    let ignored = |signature: &str, global: bool| {
        data.ignores.iter().any(|ignore| {
            ignore.signature_uuid == signature && ignore.test_guid.is_none() == global
        })
    };
    let history: std::collections::BTreeMap<&str, &Vec<Option<String>>> = data
        .history
        .signatures
        .iter()
        .map(|signature| (signature.signature_uuid.as_str(), &signature.statuses))
        .collect();
    let results = data
        .results
        .iter()
        .map(|result| {
            let status = result.status.as_deref();
            let notes: Vec<&str> = [
                (result.late_only, "late"),
                (result.context_only, "context only"),
                (result.fallback_time, "fallback time"),
            ]
            .into_iter()
            .filter(|(set, _)| *set && status.is_some())
            .map(|(_, note)| note)
            .collect();
            ResultLine {
                signature: result.signature_uuid.clone(),
                name: result.signature_name.clone().unwrap_or_default(),
                family: result.signature_family.clone().unwrap_or_default(),
                status: status.unwrap_or("left the result").to_owned(),
                status_class: status_class(status.unwrap_or("")),
                alerts: result.alert_count,
                notes: notes.join(", "),
                suppressing: result
                    .suppressing_alert
                    .map(|alert| format!("/alerts/{alert}")),
                reviewed: result.reviewed_status.clone().unwrap_or_default(),
                history: history
                    .get(result.signature_uuid.as_str())
                    .map(|statuses| {
                        statuses
                            .iter()
                            .map(|status| status.clone().unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default(),
                decisions: decisions_of(
                    result,
                    data.manage,
                    data.admin,
                    ignored(&result.signature_uuid, false),
                    ignored(&result.signature_uuid, true),
                ),
            }
        })
        .collect();
    let href = run_href(run.uuid);
    let comments = data
        .comments
        .iter()
        .map(|comment| CommentLine {
            id: comment.id,
            user: comment
                .user
                .clone()
                .unwrap_or_else(|| "a removed user".to_owned()),
            comment: comment.comment.clone(),
            created: when(comment.created_at),
            edited: (comment.updated_at - comment.created_at > chrono::TimeDelta::seconds(1))
                .then(|| when(comment.updated_at)),
            own: data.manage
                && comment
                    .user
                    .as_deref()
                    .is_some_and(|user| Some(user) == data.viewer),
            action: format!("{href}/comments/{}", comment.id),
        })
        .collect();
    let result_note = if data.result_stale {
        "Something changed since this result was computed. It is recomputed within a minute."
            .to_owned()
    } else {
        match data.computed_at {
            Some(at) => format!("Computed {}.", when(at)),
            None => "No result yet: a run's result is computed when it ends.".to_owned(),
        }
    };
    RunView {
        tabs,
        uuid: run.uuid.to_string(),
        title: row
            .test_name
            .clone()
            .unwrap_or_else(|| run.test_guid.to_string()),
        technique: [row.technique.clone(), row.technique_name.clone()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
        state,
        state_class: state_class(state, row.needs_attention),
        needs_attention: row.needs_attention,
        notice: data.notice.clone(),
        facts,
        launcher_error: run.launcher_error.clone().unwrap_or_default(),
        launcher_output: data.launcher_output.unwrap_or_default().to_owned(),
        log_search: data.log_search.clone().filter(|url| {
            let lower = url.to_ascii_lowercase();
            lower.starts_with("https://") || lower.starts_with("http://")
        }),
        result_note,
        results,
        earlier: data
            .history
            .runs
            .iter()
            .map(|earlier| (run_href(earlier.run), when(earlier.created_at)))
            .collect(),
        comments,
        manage: data.manage,
        more_events: data.events.len() as i64 >= RUN_PAGE_EVENTS,
        events: data.events.iter().map(event_line).collect(),
        events_csv: format!("/api/svs/v1/runs/{}/events/export/csv", run.uuid),
        results_csv: format!("/api/svs/v1/runs/{}/results/export/csv", run.uuid),
        href,
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/run.html")]
pub struct RunPage {
    pub layout: Layout,
    pub view: RunView,
}

/// A test host as the tab's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLine {
    pub href: String,
    pub hostname: String,
    pub fqdn: String,
    pub platform: String,
    pub usernames: String,
    pub ips: String,
    pub notes: String,
    pub updated: String,
}

pub fn host_line(host: &TestHost) -> HostLine {
    HostLine {
        href: format!("/svs/test-hosts/{}", host.id),
        hostname: host.hostname.clone(),
        fqdn: host.fqdn.clone().unwrap_or_default(),
        platform: host.platform.clone().unwrap_or_default(),
        usernames: host.usernames.join(", "),
        ips: host.ips.join(", "),
        notes: host.notes.clone().unwrap_or_default(),
        updated: when(host.updated_at),
    }
}

/// The platforms a test host may have: ace3's `PLATFORMS`.
pub const HOST_PLATFORMS: &[&str] = &["windows", "linux", "macos"];

/// A test host's form: adding one, or changing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostForm {
    pub action: String,
    pub hostname: String,
    pub fqdn: String,
    pub platform: String,
    pub usernames: String,
    pub ips: String,
    pub notes: String,
    /// The host's `updated_at` as the form was drawn from it; empty for a new host.
    pub seen: String,
}

impl HostForm {
    pub fn new_host() -> Self {
        HostForm {
            action: "/svs/test-hosts".to_owned(),
            hostname: String::new(),
            fqdn: String::new(),
            platform: String::new(),
            usernames: String::new(),
            ips: String::new(),
            notes: String::new(),
            seen: String::new(),
        }
    }

    pub fn of(host: &TestHost) -> Self {
        HostForm {
            action: format!("/svs/test-hosts/{}", host.id),
            hostname: host.hostname.clone(),
            fqdn: host.fqdn.clone().unwrap_or_default(),
            platform: host.platform.clone().unwrap_or_default(),
            usernames: host.usernames.join(", "),
            ips: host.ips.join(", "),
            notes: host.notes.clone().unwrap_or_default(),
            seen: host
                .updated_at
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        }
    }

    pub fn is_platform(&self, platform: &str) -> bool {
        self.platform == platform
    }
}

/// `/svs/test-hosts`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsView {
    pub tabs: Tabs,
    pub notice: Option<String>,
    pub rows: Vec<HostLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub form: HostForm,
    pub platforms: &'static [&'static str],
}

pub fn hosts_view(
    tabs: Tabs,
    hosts: &[TestHost],
    cursor: Option<&str>,
    next: Option<&str>,
    notice: Option<String>,
) -> HostsView {
    let (first, next) = pages("/svs/test-hosts", &[], cursor, next);
    HostsView {
        tabs,
        notice,
        rows: hosts.iter().map(host_line).collect(),
        first,
        next,
        form: HostForm::new_host(),
        platforms: HOST_PLATFORMS,
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/test_hosts.html")]
pub struct HostsPage {
    pub layout: Layout,
    pub view: HostsView,
}

/// `/svs/test-hosts/{id}`'s content: one host's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostView {
    pub tabs: Tabs,
    pub hostname: String,
    pub form: HostForm,
    pub platforms: &'static [&'static str],
    pub delete: String,
}

pub fn host_view(tabs: Tabs, host: &TestHost) -> HostView {
    HostView {
        tabs,
        hostname: host.hostname.clone(),
        form: HostForm::of(host),
        platforms: HOST_PLATFORMS,
        delete: format!("/svs/test-hosts/{}/delete", host.id),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/test_host.html")]
pub struct HostPage {
    pub layout: Layout,
    pub view: HostView,
}

// ---- the gate ----

/// The area's gate, and whether the viewer holds `svs:admin`, which the Test hosts tab needs.
async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<bool, Failure> {
    match gui.service.allowed(&viewer.actor, &SVS_RUN_READ).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(Failure::new(
                StatusCode::FORBIDDEN,
                "The SVS area needs svs:run_read. Ask an administrator.",
                parts,
            ));
        }
        Err(error) => return Err(Failure::from_service(error, parts)),
    }
    gui.service
        .allowed(&viewer.actor, &SVS_ADMIN)
        .await
        .map_err(|error| Failure::from_service(error, parts))
}

/// The Test hosts tab's own gate, on top of the area's.
async fn enter_hosts(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    if enter(gui, viewer, parts).await? {
        Ok(())
    } else {
        Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The test hosts need svs:admin. Ask an administrator.",
            parts,
        ))
    }
}

fn failed(error: ServiceError, parts: &Parts) -> Response {
    Failure::from_service(error, parts).into_response()
}

fn bad_request(message: &str, parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, message, parts).into_response()
}

fn run_of(path: Result<Path<String>, PathRejection>) -> Option<Uuid> {
    path.ok().and_then(|Path(text)| text.parse().ok())
}

/// What a page says a post did.
fn notice_of(done: Option<&str>) -> Option<String> {
    Some(
        match done? {
            "expected" => "The signature is expected of this test on this platform.",
            "rejected" => "The signature is rejected for this test on this platform.",
            "undecide" => {
                "The decision is removed: the signature is a candidate again when it fires."
            }
            "ignore" => "The signature is ignored during this test's runs.",
            "ignore_globally" => "The signature is ignored during every test's runs.",
            "unignore" => "The signature is no longer ignored during this test's runs.",
            "unignore_globally" => "The signature is no longer ignored during every test's runs.",
            "commented" => "The comment is added.",
            "edited" => "The comment is changed.",
            "deleted" => "The comment is deleted.",
            "added" => "The test host is added.",
            "changed" => "The test host is changed.",
            "removed" => "The test host is removed.",
            _ => return None,
        }
        .to_owned(),
    )
}

// ---- the pages ----

/// `GET /svs`: the runs that need attention.
pub(crate) async fn home(State(gui): State<Gui>, viewer: SignedIn, parts: Parts) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    see_other(NEEDS_ATTENTION, None)
}

/// A runs list's request: its filters, their share link, and its cursor; or the redirect that folds the
/// filter form into `f`.
fn runs_request(
    path: &str,
    raw: Option<&str>,
) -> Result<Result<(RunQuery, Vec<String>), Response>, ServiceError> {
    let request = list_request(FilterScreen::SvsRuns, raw)?;
    let filters =
        ace_service::filters::encode(FilterScreen::SvsRuns, &request.filters).unwrap_or_default();
    if request.folded {
        return Ok(Err(see_other(
            &with_query(path, &filter_pairs(&filters)),
            None,
        )));
    }
    Ok(Ok((
        RunQuery {
            filters: request.filters,
            ..RunQuery::default()
        },
        filters,
    )))
}

/// `GET /svs/runs`.
pub(crate) async fn runs(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let (query, filters) = match runs_request("/svs/runs", raw.0.as_deref()) {
        Ok(Ok(request)) => request,
        Ok(Err(redirect)) => return redirect,
        Err(error) => return failed(error, &parts),
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let actor = &viewer.actor;
    let read = async {
        let page = gui
            .service
            .svs_runs(actor, &query, cursor, Some(SVS_PER_PAGE))
            .await?;
        let total = gui.service.svs_run_count(actor, &query).await?;
        let share = gui.service.svs_suppression_share(actor, Utc::now()).await?;
        Ok::<_, ServiceError>(runs_view(
            Tabs {
                open: "runs",
                admin,
            },
            &query,
            &filters,
            total,
            &share,
            &page.runs,
            cursor,
            page.next_cursor.as_deref(),
        ))
    };
    match read.await {
        Ok(view) => render(&RunsPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/runs/batches`: the same runs, one row per batch.
pub(crate) async fn batches(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let (query, filters) = match runs_request("/svs/runs/batches", raw.0.as_deref()) {
        Ok(Ok(request)) => request,
        Ok(Err(redirect)) => return redirect,
        Err(error) => return failed(error, &parts),
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    match gui
        .service
        .svs_run_batches(&viewer.actor, &query, cursor, Some(SVS_PER_PAGE))
        .await
    {
        Ok(page) => render(&BatchesPage {
            layout: viewer.layout,
            view: batches_view(
                Tabs {
                    open: "runs",
                    admin,
                },
                &query,
                &filters,
                &page.batches,
                cursor,
                page.next_cursor.as_deref(),
            ),
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/runs/{run_id}`: the run page.
pub(crate) async fn run(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let Some(uuid) = run_of(path) else {
        return bad_request("A run is named by its uuid.", &parts);
    };
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let notice = notice_of(one(&form, "done"));
    let actor = &viewer.actor;
    let service = &gui.service;
    let read = async {
        let detail = service.svs_run(actor, uuid).await?;
        let row = service.svs_run_row(actor, uuid).await?;
        let results = service
            .svs_run_results(actor, uuid, None, Some(RUN_PAGE_RESULTS))
            .await?;
        let history = service.svs_run_history(actor, uuid, None).await?;
        let ignores = service
            .svs_ignores(
                actor,
                &IgnoreQuery {
                    test: Some(row.run.test_guid.to_string()),
                    ..IgnoreQuery::default()
                },
                None,
                Some(ace_service::MAX_DECISIONS_PAGE),
            )
            .await?;
        let comments = service.svs_run_comments(actor, uuid).await?;
        let events = service
            .svs_run_events(actor, uuid, None, Some(RUN_PAGE_EVENTS))
            .await?;
        let manage = service.allowed(actor, &SVS_RUN_MANAGE).await?;
        let data = RunPageData {
            row: &row,
            launcher_output: detail.launcher_output.as_deref(),
            log_search: service.svs_run_log_search_url(&row.run, Utc::now()),
            results: &results.results,
            result_stale: results.stale,
            computed_at: results.computed_at,
            history: &history,
            ignores: &ignores.ignores,
            comments: &comments,
            events: &events,
            viewer: viewer.layout.username.as_deref(),
            manage,
            admin,
            notice,
        };
        Ok::<_, ServiceError>(run_view(
            Tabs {
                open: "runs",
                admin,
            },
            &data,
        ))
    };
    match read.await {
        Ok(view) => render(&RunPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

fn back_to_run(uuid: Uuid, done: &str) -> Response {
    see_other(&format!("{}?done={done}", run_href(uuid)), None)
}

/// `POST /svs/runs/{run_id}/decide`: a decision about one signature of the run's result, made from the
/// run. `decision` is `expected`, `rejected`, `undecide`, `ignore`, `ignore_globally`, `unignore` or
/// `unignore_globally`; `signature` is the signature; `reason` is why.
pub(crate) async fn decide(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = run_of(path) else {
        return bad_request("A run is named by its uuid.", &parts);
    };
    let form = pairs(&body);
    let (Some(decision), Some(signature)) = (one(&form, "decision"), one(&form, "signature"))
    else {
        return bad_request("A decision names a signature and what is decided.", &parts);
    };
    let reason = one(&form, "reason")
        .map(str::trim)
        .filter(|r| !r.is_empty());
    let actor = &viewer.actor;
    let service = &gui.service;
    let decided = async {
        let run = service.svs_run(actor, uuid).await?.run;
        let test = run.test_guid.to_string();
        let now = Utc::now();
        // a decision made from the page says the page showed none: one someone else made first is
        // refused, not replaced
        match decision {
            "expected" | "rejected" => service
                .set_svs_expectation(
                    actor,
                    &test,
                    None,
                    signature,
                    decision,
                    reason,
                    Some(uuid),
                    Precondition::Absent,
                    now,
                )
                .await
                .map(|_| ()),
            "undecide" => {
                service
                    .remove_svs_expectation(actor, &test, &run.platform, signature)
                    .await
            }
            "ignore" => service
                .set_svs_ignore(
                    actor,
                    signature,
                    Some(&test),
                    reason,
                    Precondition::Absent,
                    now,
                )
                .await
                .map(|_| ()),
            "ignore_globally" => service
                .set_svs_ignore(actor, signature, None, reason, Precondition::Absent, now)
                .await
                .map(|_| ()),
            "unignore" => {
                service
                    .remove_svs_ignore(actor, signature, Some(&test))
                    .await
            }
            "unignore_globally" => service.remove_svs_ignore(actor, signature, None).await,
            other => Err(ServiceError::InvalidRequest(format!(
                "{other:?} isn't a decision"
            ))),
        }
    };
    let done = match decision {
        "expected" => "expected",
        "rejected" => "rejected",
        "undecide" => "undecide",
        "ignore" => "ignore",
        "ignore_globally" => "ignore_globally",
        "unignore" => "unignore",
        _ => "unignore_globally",
    };
    match decided.await {
        Ok(()) => back_to_run(uuid, done),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/runs/{run_id}/comments`: a new comment.
pub(crate) async fn comment(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = run_of(path) else {
        return bad_request("A run is named by its uuid.", &parts);
    };
    let form = pairs(&body);
    match gui
        .service
        .add_svs_run_comment(
            &viewer.actor,
            uuid,
            one(&form, "comment").unwrap_or(""),
            Utc::now(),
        )
        .await
    {
        Ok(_) => back_to_run(uuid, "commented"),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/runs/{run_id}/comments/{id}`: its author changes a comment, or with `delete` deletes it.
pub(crate) async fn change_comment(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((uuid, id)) = path
        .ok()
        .and_then(|Path((run, id))| Some((run.parse::<Uuid>().ok()?, id.parse::<i64>().ok()?)))
    else {
        return bad_request("A comment is named by its run's uuid and its id.", &parts);
    };
    let form = pairs(&body);
    let changed = if one(&form, "delete").is_some() {
        gui.service
            .delete_svs_run_comment(&viewer.actor, uuid, id)
            .await
            .map(|()| "deleted")
    } else {
        gui.service
            .update_svs_run_comment(&viewer.actor, uuid, id, one(&form, "comment").unwrap_or(""))
            .await
            .map(|_| "edited")
    };
    match changed {
        Ok(done) => back_to_run(uuid, done),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/test-hosts`: the hosts runs may target, for `svs:admin`.
pub(crate) async fn test_hosts(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    if let Err(failure) = enter_hosts(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    match gui
        .service
        .test_hosts_page(&viewer.actor, None, cursor, Some(SVS_PER_PAGE))
        .await
    {
        Ok(page) => render(&HostsPage {
            layout: viewer.layout,
            view: hosts_view(
                Tabs {
                    open: "test_hosts",
                    admin: true,
                },
                &page.hosts,
                cursor,
                page.next_cursor.as_deref(),
                notice_of(one(&form, "done")),
            ),
        }),
        Err(error) => failed(error, &parts),
    }
}

fn host_of(path: Result<Path<String>, PathRejection>) -> Option<i64> {
    path.ok().and_then(|Path(text)| text.parse().ok())
}

/// `GET /svs/test-hosts/{id}`: a host's form.
pub(crate) async fn test_host(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter_hosts(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = host_of(path) else {
        return bad_request("A test host is named by its id.", &parts);
    };
    match gui.service.test_host(&viewer.actor, id).await {
        Ok(host) => render(&HostPage {
            layout: viewer.layout,
            view: host_view(
                Tabs {
                    open: "test_hosts",
                    admin: true,
                },
                &host,
            ),
        }),
        Err(error) => failed(error, &parts),
    }
}

/// A list a person types: its items, apart at commas and white space.
fn items(text: Option<&str>) -> Vec<String> {
    text.unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn host_fields(form: &[(String, String)]) -> HostFields {
    let text = |name: &str| {
        one(form, name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    HostFields {
        hostname: one(form, "hostname").unwrap_or("").trim().to_owned(),
        fqdn: text("fqdn"),
        usernames: items(one(form, "usernames")),
        ips: items(one(form, "ips")),
        platform: text("platform"),
        notes: text("notes"),
    }
}

/// `POST /svs/test-hosts`: adds a test host.
pub(crate) async fn add_test_host(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter_hosts(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    match gui
        .service
        .create_test_host(&viewer.actor, &host_fields(&form))
        .await
    {
        Ok(_) => see_other("/svs/test-hosts?done=added", None),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/test-hosts/{id}`: changes a test host, from the form as it was drawn (`seen`): a host
/// someone else changed since is refused, not written over.
pub(crate) async fn change_test_host(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter_hosts(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = host_of(path) else {
        return bad_request("A test host is named by its id.", &parts);
    };
    let form = pairs(&body);
    let precondition = match Precondition::parse(one(&form, "seen").filter(|s| !s.is_empty()), None)
    {
        Ok(precondition) => precondition,
        Err(why) => return bad_request(&why, &parts),
    };
    match gui
        .service
        .update_test_host(&viewer.actor, id, &host_fields(&form), precondition)
        .await
    {
        Ok(_) => see_other("/svs/test-hosts?done=changed", None),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/test-hosts/{id}/delete`: removes a test host.
pub(crate) async fn remove_test_host(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter_hosts(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = host_of(path) else {
        return bad_request("A test host is named by its id.", &parts);
    };
    match gui.service.delete_test_host(&viewer.actor, id).await {
        Ok(()) => see_other("/svs/test-hosts?done=removed", None),
        Err(error) => failed(error, &parts),
    }
}
