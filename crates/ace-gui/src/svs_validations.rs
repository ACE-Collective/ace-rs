//! The signatures area's validations pages (PLAN.md 7.10 batch 3): ace3's `validations.html`,
//! `_validations_page.html` and `validation_detail.html`, over `ace_service`'s `svs_validations`.
//!
//! The area's gate is `signature:read`, as every page of it (`signatures`' docs): a user without it gets
//! 403, and a visitor who isn't signed in goes to the login. ace3's pages are shells its scripts fill from
//! `/api/v2/svs/yara/validations`; here the server draws each one, and every control is a link or a form:
//! - `signatures.validations` (`validations.html`, with `_validations_page.html` as its table): `GET
//!   /signatures/validations`, the validations newest first, with ace3's validations screen's filters as a
//!   `GET` form folded into `f`, as the samples' are, and its pages as First and Next links, since the cursor
//!   goes one way, with the API's exports beside them.
//! - `signatures.validation_detail` (`validation_detail.html`): `GET /signatures/validations/{uuid}`, the
//!   report a rule repository's CI links to (`validation_report_path`): the validation's state, its
//!   commits, its counts, how each commit compiled, the rules added, removed and changed, the rules that
//!   can't be tested and the samples not replayed, then its rows a page at a time, filtered by category with
//!   a `GET` form, each linking to its sample. For `signature:download`, the selected rows' files are the
//!   API's audited download.
//!
//! Everything a validation names comes from a rule repository or an alert: rule and file names, branch
//! names, errors, a pull request's URL. askama escapes it, and a sha256 or rule uuid in a link is
//! percent-encoded; the pull request is a link only when it's http or https, as the service already
//! requires.
//!
//! Left out: ace3's saved filters for this screen, which the alert list's saved filters (5.10) don't cover
//! yet for any SVS screen, and its copy buttons, which need a script.

use ace_service::filters::FilterScreen;
use ace_service::{
    ResultSelection, SIGNATURE_DOWNLOAD, SIGNATURE_READ, ServiceError, Validation,
    ValidationDetail, ValidationQuery, ValidationResult, listed_categories,
};
use askama::Template;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::Gui;
use crate::list::{one, pairs};
use crate::remediation::{FilterField, filter_fields, list_request};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::svs_samples::sample_href;
use crate::templates::Layout;

/// Validations, and a report's rows, on one page.
pub const VALIDATIONS_PER_PAGE: u32 = 50;

fn when(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn short(sha: &str) -> String {
    sha.get(..12).unwrap_or(sha).to_owned()
}

/// A validation's page.
pub fn validation_href(uuid: Uuid) -> String {
    format!("/signatures/validations/{uuid}")
}

fn with_query(path: &str, pairs: &[(&str, String)]) -> String {
    let encoded = serde_urlencoded::to_string(pairs).unwrap_or_default();
    if encoded.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{encoded}")
    }
}

fn http_link(url: &Option<String>) -> Option<String> {
    url.as_ref()
        .filter(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("https://") || lower.starts_with("http://")
        })
        .cloned()
}

/// A validation as the list's row and the head of its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRow {
    pub href: String,
    pub uuid: String,
    pub repository: String,
    pub branch: String,
    pub base_sha: String,
    pub head_sha: String,
    pub short_base: String,
    pub short_head: String,
    pub pr_url: Option<String>,
    pub state: &'static str,
    /// The state's badge class.
    pub state_class: &'static str,
    pub requested_by: String,
    pub created: String,
    pub started: String,
    pub finished: String,
    pub error: String,
    /// Empty until it completes.
    pub regressions: String,
    pub new_fps: String,
    pub compile_errors: String,
    /// False when either commit's rules wouldn't load.
    pub diffed: Option<bool>,
}

pub fn validation_row(v: &Validation) -> ValidationRow {
    let count = |n: Option<i32>| n.map(|n| n.to_string()).unwrap_or_default();
    let state = v.state.as_str();
    let state_class = match state {
        "completed" if v.regressions.unwrap_or(0) > 0 || v.new_fps.unwrap_or(0) > 0 => "warning",
        "completed" => "success",
        "failed" => "danger",
        "running" => "info",
        _ => "secondary",
    };
    ValidationRow {
        href: validation_href(v.uuid),
        uuid: v.uuid.to_string(),
        repository: v.repository.clone(),
        branch: v.branch.clone(),
        short_base: short(&v.base_sha),
        short_head: short(&v.head_sha),
        base_sha: v.base_sha.clone(),
        head_sha: v.head_sha.clone(),
        pr_url: http_link(&v.pr_url),
        state,
        state_class,
        requested_by: v
            .requested_by
            .name
            .clone()
            .unwrap_or_else(|| v.requested_by.id.clone()),
        created: when(v.created_at),
        started: v.started_at.map(when).unwrap_or_default(),
        finished: v.finished_at.map(when).unwrap_or_default(),
        error: v.error.clone().unwrap_or_default(),
        regressions: count(v.regressions),
        new_fps: count(v.new_fps),
        compile_errors: count(v.compile_errors),
        diffed: v.diffed,
    }
}

/// `/signatures/validations`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationsView {
    pub fields: Vec<FilterField>,
    /// The filters as a share link's query, which the pages carry.
    pub filters: Vec<String>,
    pub rows: Vec<ValidationRow>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
}

pub fn validations_view(
    query: &ValidationQuery,
    filters: Vec<String>,
    validations: &[Validation],
    cursor: Option<&str>,
    next: Option<&str>,
) -> ValidationsView {
    let base: Vec<(&str, String)> = filters.iter().map(|f| ("f", f.clone())).collect();
    let page = |cursor: Option<&str>| {
        let mut pairs = base.clone();
        if let Some(cursor) = cursor {
            pairs.push(("cursor", cursor.to_owned()));
        }
        with_query("/signatures/validations", &pairs)
    };
    ValidationsView {
        fields: filter_fields(FilterScreen::SvsValidations, &query.filters),
        rows: validations.iter().map(validation_row).collect(),
        first: cursor.map(|_| page(None)),
        next: next.map(|next| page(Some(next))),
        csv: with_query("/api/svs/v1/yara/validations/export/csv", &base),
        ndjson: with_query("/api/svs/v1/yara/validations/export/ndjson", &base),
        filters,
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/validations.html")]
pub struct ValidationsPage {
    pub layout: Layout,
    pub view: ValidationsView,
}

/// One row of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRow {
    pub sample_href: String,
    pub sha256: String,
    pub short_sha256: String,
    pub rule_uuid: String,
    pub rule_name: String,
    pub namespace: String,
    pub label: String,
    pub base: String,
    pub head: String,
    pub category: String,
    pub note: String,
}

fn result_row(r: &ValidationResult) -> ResultRow {
    let label = match (&r.label, &r.label_source) {
        (Some(label), Some(source)) => format!("{label} ({source})"),
        (Some(label), None) => label.clone(),
        (None, _) => String::new(),
    };
    let raw = |outcome: &str, raw: bool| {
        if outcome == "miss" && raw {
            "miss (matches, no detection)".to_owned()
        } else {
            outcome.to_owned()
        }
    };
    ResultRow {
        sample_href: sample_href(&r.sha256, &r.rule_uuid),
        short_sha256: format!("{}…", r.sha256.get(..16).unwrap_or(&r.sha256)),
        sha256: r.sha256.clone(),
        rule_uuid: r.rule_uuid.clone(),
        rule_name: r.rule_name.clone(),
        namespace: r.namespace.clone().unwrap_or_default(),
        label,
        base: raw(&r.base, r.raw_base),
        head: raw(&r.head, r.raw_head),
        category: r.category.clone(),
        note: r.note.clone().unwrap_or_default(),
    }
}

/// A line of the report: a file or rule and what's said of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLine {
    pub subject: String,
    pub text: String,
}

/// How one commit compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideView {
    pub name: &'static str,
    pub sha: String,
    pub namespaces: String,
    pub rule_count: String,
    pub ruleset_error: String,
    pub lines: Vec<ReportLine>,
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn side_view(name: &'static str, side: &Value) -> SideView {
    let mut lines = Vec::new();
    for error in side["file_errors"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: text(&error["file"]),
            text: format!(
                "doesn't compile, its {} rule(s) are dropped: {}",
                error["dropped"].as_array().map_or(0, Vec::len),
                text(&error["error"])
            ),
        });
    }
    for item in side["not_loaded"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: text(&item["path"]),
            text: format!("not loaded: {}", text(&item["reason"])),
        });
    }
    for item in side["skipped_members"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: text(&item[0]),
            text: format!("not exported: {}", text(&item[1])),
        });
    }
    for warning in side["warnings"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: "compiler".to_owned(),
            text: text(warning),
        });
    }
    let namespaces: Vec<String> = side["namespaces"]
        .as_array()
        .into_iter()
        .flatten()
        .map(text)
        .collect();
    SideView {
        name,
        sha: text(&side["sha"]),
        namespaces: if namespaces.is_empty() {
            "none".to_owned()
        } else {
            namespaces.join(", ")
        },
        rule_count: text(&side["rule_count"]),
        ruleset_error: text(&side["ruleset_error"]),
        lines,
    }
}

fn rule_lines(report: &Value) -> Vec<ReportLine> {
    let mut lines = Vec::new();
    for (key, what) in [
        ("added_rules", "added"),
        ("removed_rules", "removed"),
        ("changed_rules", "changed"),
    ] {
        for rule in report[key].as_array().into_iter().flatten() {
            lines.push(ReportLine {
                subject: text(&rule["name"]),
                text: format!(
                    "{what} ({}) in {}",
                    text(&rule["uuid"]),
                    text(&rule["file"])
                ),
            });
        }
    }
    for rule in report["not_testable"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: text(&rule["name"]),
            text: format!(
                "not testable in {}: {}",
                text(&rule["file"]),
                text(&rule["reason"])
            ),
        });
    }
    for rule in report["full_path_rules"].as_array().into_iter().flatten() {
        lines.push(ReportLine {
            subject: text(&rule["name"]),
            text: "filters on full_path, which a replay can't reproduce".to_owned(),
        });
    }
    lines
}

/// A category's count, and the link that shows its rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountView {
    pub category: String,
    pub count: i64,
    /// The rows of it, when the report lists them.
    pub href: Option<String>,
}

/// A validation's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationView {
    pub validation: ValidationRow,
    pub attempts: i32,
    pub claimed_by: String,
    pub counts: Vec<CountView>,
    pub sides: Vec<SideView>,
    pub rules: Vec<ReportLine>,
    /// The corpus: files, scans, samples, bytes and how long it took.
    pub corpus: String,
    pub skipped: Vec<ReportLine>,
    /// The categories the rows' form offers, and the ones chosen.
    pub categories: Vec<&'static str>,
    pub chosen: Vec<String>,
    pub results: Vec<ResultRow>,
    pub first: Option<String>,
    pub next: Option<String>,
    /// The API's download of the shown rows' files, for `signature:download`.
    pub download: Option<String>,
}

impl ValidationView {
    pub fn is_chosen(&self, category: &str) -> bool {
        self.chosen.iter().any(|c| c == category)
    }
}

pub fn validation_view(
    detail: &ValidationDetail,
    chosen: &[String],
    results: &[ValidationResult],
    cursor: Option<&str>,
    next: Option<&str>,
    can_download: bool,
) -> ValidationView {
    let validation = validation_row(&detail.validation);
    let href = validation.href.clone();
    let base: Vec<(&str, String)> = chosen.iter().map(|c| ("category", c.clone())).collect();
    let page = |cursor: Option<&str>| {
        let mut pairs = base.clone();
        if let Some(cursor) = cursor {
            pairs.push(("cursor", cursor.to_owned()));
        }
        with_query(&href, &pairs)
    };
    let listed = listed_categories();
    let counts = detail
        .validation
        .counts
        .iter()
        .flatten()
        .filter(|(_, count)| **count > 0)
        .map(|(category, count)| CountView {
            category: category.clone(),
            count: *count,
            href: listed
                .contains(&category.as_str())
                .then(|| with_query(&href, &[("category", category.clone())])),
        })
        .collect();
    let report = detail.report.clone().unwrap_or(Value::Null);
    let sides = if report.is_null() {
        Vec::new()
    } else {
        vec![
            side_view("base", &report["base"]),
            side_view("head", &report["head"]),
        ]
    };
    let skipped = report["skipped"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| ReportLine {
            subject: text(&s["sha256"]),
            text: format!(
                "{} {} {}",
                text(&s["file_path"]),
                text(&s["reason"]),
                text(&s["detail"])
            )
            .trim()
            .to_owned(),
        })
        .collect();
    let corpus = if report.is_null() {
        String::new()
    } else {
        format!(
            "{} files, {} scans, {} samples, {} bytes, in {:.1}s",
            text(&report["files"]),
            text(&report["units"]),
            text(&report["samples"]),
            text(&report["bytes"]),
            report["duration_seconds"].as_f64().unwrap_or_default()
        )
    };
    let uuid = detail.validation.uuid;
    ValidationView {
        attempts: detail.attempts,
        claimed_by: detail.claimed_by.clone().unwrap_or_default(),
        counts,
        sides,
        rules: rule_lines(&report),
        corpus,
        skipped,
        categories: listed,
        chosen: chosen.to_vec(),
        results: results.iter().map(result_row).collect(),
        first: cursor.map(|_| page(None)),
        next: next.map(|next| page(Some(next))),
        download: (can_download && !results.is_empty()).then(|| {
            with_query(
                &format!("/api/svs/v1/yara/validations/{uuid}/download"),
                &base,
            )
        }),
        validation,
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/validation_detail.html")]
pub struct ValidationPage {
    pub layout: Layout,
    pub view: ValidationView,
}

// ---- the gate ----

async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &SIGNATURE_READ).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The signatures area needs signature:read. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

fn failed(error: ServiceError, parts: &Parts) -> Response {
    Failure::from_service(error, parts).into_response()
}

// ---- the pages ----

/// `GET /signatures/validations`.
pub(crate) async fn validations(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let request = match list_request(FilterScreen::SvsValidations, raw.0.as_deref()) {
        Ok(request) => request,
        Err(error) => return failed(error, &parts),
    };
    let filters = ace_service::filters::encode(FilterScreen::SvsValidations, &request.filters)
        .unwrap_or_default();
    if request.folded {
        let pairs: Vec<(&str, String)> = filters.iter().map(|f| ("f", f.clone())).collect();
        return see_other(&with_query("/signatures/validations", &pairs), None);
    }
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let query = ValidationQuery {
        filters: request.filters.clone(),
        ..ValidationQuery::default()
    };
    match gui
        .service
        .svs_validations(&viewer.actor, &query, cursor, Some(VALIDATIONS_PER_PAGE))
        .await
    {
        Ok(page) => render(&ValidationsPage {
            layout: viewer.layout,
            view: validations_view(
                &query,
                filters,
                &page.validations,
                cursor,
                page.next_cursor.as_deref(),
            ),
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /signatures/validations/{uuid}`: the report CI links to.
pub(crate) async fn validation(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(uuid) = path.ok().and_then(|Path(text)| text.parse::<Uuid>().ok()) else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "A validation is named by its uuid.",
            &parts,
        )
        .into_response();
    };
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let chosen: Vec<String> = form
        .iter()
        .filter(|(k, v)| k == "category" && !v.is_empty())
        .map(|(_, v)| v.clone())
        .collect();
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let selection = ResultSelection {
        categories: chosen.clone(),
        rule_uuids: Vec::new(),
    };
    let actor = &viewer.actor;
    let read = async {
        let detail = gui.service.svs_validation(actor, uuid).await?;
        let page = gui
            .service
            .svs_validation_results(actor, uuid, &selection, cursor, Some(VALIDATIONS_PER_PAGE))
            .await?;
        let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
        Ok::<_, ServiceError>(validation_view(
            &detail,
            &chosen,
            &page.results,
            cursor,
            page.next_cursor.as_deref(),
            can_download,
        ))
    };
    match read.await {
        Ok(view) => render(&ValidationPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}
