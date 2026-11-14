//! The signatures area's samples pages (PLAN.md 7.10 batch 2): ace3's `samples.html`, `_samples_page.html`
//! and `sample_detail.html`, over `ace_service`'s `svs_samples`.
//!
//! The area's gate is `signature:read`, as every page of it (`signatures`' docs): a user without it gets
//! 403, and a visitor who isn't signed in goes to the login. ace3's pages are shells its scripts fill from
//! `/api/v2/svs/samples`; here the server draws each one, and every control is a link or a form:
//! - `signatures.samples` (`samples.html`, with `_samples_page.html` as its table): `GET
//!   /signatures/samples`, the samples with ace3's samples screen's filters as a `GET` form folded into
//!   `f`, as the remediations' are, its sorts as a `GET` form, and its pages as First and Next links, since
//!   the cursor goes one way. Beside them the exports and, for `signature:download`, the bulk download,
//!   which are the API's, and the captures that lack something, by rule.
//! - `signatures.sample_detail` (`sample_detail.html`): `GET /signatures/samples/{sha256}/{rule_uuid}`, the
//!   sample, its label and votes, its retirement, and every capture with its contributing detections and
//!   their verdicts, a link to the alert and to the match record. The actions are forms whose posts are
//!   `SignedIn` posts that passed 5.7's same-origin check, each through the service, which checks its
//!   permission and writes its audit row: Mark TP, Mark FP and Reset label, and Confirm when there's an
//!   unconfirmed detection, for `alert:write`; Retire with a reason and Unretire for `svs:admin`. The label
//!   forms are offered only when a relabel would write something (`SampleDetail::relabel_refusal`), and
//!   the refusal shows otherwise, as ace3's page does.
//! - Delete is destructive, so it's two steps where ace3's page asks in a modal: `GET
//!   /signatures/samples/{sha256}/delete` says what goes and asks for a reason, and its form posts to the
//!   same path, `svs:admin`, through `Service::delete_svs_sample`.
//!
//! Everything a rule, a file or an alert brings is text: a rule's name and namespace, a file's path, and
//! the yara_meta tags. askama escapes it, and a sha256 or a rule uuid in a link is percent-encoded.
//!
//! Left out: ace3's copy buttons and select boxes, which need a script, and its `wrong_node` notes, since
//! ace4's bucket is one. ace3's validations pages come with batch 3.

use ace_service::filters::FilterScreen;
use ace_service::{
    ALERT_WRITE, LabelChange, MissingCount, SIGNATURE_DOWNLOAD, SIGNATURE_READ, SVS_ADMIN, Sample,
    SampleDetail, SampleLabel, SampleQuery, SampleSort, ServiceError, Verdict,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

use crate::Gui;
use crate::actions::encode;
use crate::list::{one, pairs};
use crate::remediation::{FilterField, filter_fields, list_request};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::signatures::size;
use crate::templates::Layout;

/// Samples on one page.
pub const SAMPLES_PER_PAGE: u32 = 50;
/// The largest action form: a reason of 4000 characters, percent-encoded.
pub const MAX_SAMPLE_FORM_BYTES: usize = 64 << 10;

fn when(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// A sample's page.
pub fn sample_href(sha256: &str, rule_uuid: &str) -> String {
    format!(
        "/signatures/samples/{}/{}",
        encode(sha256),
        encode(rule_uuid)
    )
}

/// A sample as the list's row and the head of its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRow {
    pub href: String,
    pub sha256: String,
    pub short_sha256: String,
    pub rule_uuid: String,
    pub rule_name: String,
    pub namespace: String,
    pub file_path: String,
    pub size: String,
    /// `TP`, `FP`, `conflicted`, or empty with no label.
    pub label: &'static str,
    /// The label's badge class.
    pub label_class: &'static str,
    pub label_source: &'static str,
    pub capture_count: i64,
    pub stored: i64,
    pub missing: i64,
    pub missing_data: i64,
    pub unknown_version: i64,
    pub first_captured: String,
    pub last_captured: String,
    pub retired: bool,
    pub retired_by: String,
    pub retired_at: String,
    pub retired_reason: String,
    /// The votes, as `tp/fp` at each strength.
    pub votes: String,
}

pub fn sample_row(sample: &Sample) -> SampleRow {
    let (label, label_class) = match sample.label {
        Some(SampleLabel::Tp) => ("TP", "danger"),
        Some(SampleLabel::Fp) => ("FP", "success"),
        Some(SampleLabel::Conflicted) => ("conflicted", "warning"),
        None => ("", "light"),
    };
    let v = &sample.votes;
    SampleRow {
        href: sample_href(&sample.sha256, &sample.rule_uuid),
        sha256: sample.sha256.clone(),
        short_sha256: format!("{}…", sample.sha256.get(..16).unwrap_or(&sample.sha256)),
        rule_uuid: sample.rule_uuid.clone(),
        rule_name: sample.rule_name.clone(),
        namespace: sample.namespace.clone().unwrap_or_default(),
        file_path: sample.file_path.clone(),
        size: sample.file_size.map(size).unwrap_or_default(),
        label,
        label_class,
        label_source: sample.label_source.map(|s| s.as_str()).unwrap_or(""),
        capture_count: sample.capture_count,
        stored: sample.stored,
        missing: sample.missing,
        missing_data: sample.missing_data,
        unknown_version: sample.unknown_version,
        first_captured: when(sample.first_captured),
        last_captured: when(sample.last_captured),
        retired: sample.retired,
        retired_by: sample
            .retired_by
            .as_ref()
            .map(|by| by.name.clone().unwrap_or_else(|| by.id.clone()))
            .unwrap_or_default(),
        retired_at: sample.retired_at.map(when).unwrap_or_default(),
        retired_reason: sample.retired_reason.clone().unwrap_or_default(),
        votes: format!(
            "explicit {}/{}, single {}/{}, multi {}/{}",
            v.tp_explicit,
            v.fp_explicit,
            v.tp_inherited_single,
            v.fp_inherited_single,
            v.tp_inherited_multi,
            v.fp_inherited_multi
        ),
    }
}

/// How many captures of a rule lack something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingRow {
    pub rule_uuid: String,
    pub rule_name: String,
    pub reason: &'static str,
    pub count: i64,
}

fn missing_row(m: &MissingCount) -> MissingRow {
    MissingRow {
        rule_uuid: m.rule_uuid.clone(),
        rule_name: m.rule_name.clone(),
        reason: m.reason.as_str(),
        count: m.count,
    }
}

/// `/signatures/samples`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplesView {
    pub fields: Vec<FilterField>,
    /// The sort and its direction, and the sorts the form offers.
    pub sort: &'static str,
    pub descending: bool,
    pub sorts: [&'static str; 6],
    /// The filters as a share link's query, which the sort form and the pages carry.
    pub filters: Vec<String>,
    pub rows: Vec<SampleRow>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
    /// The API's bulk download with the same filters, for `signature:download`.
    pub download: Option<String>,
    pub missing: Vec<MissingRow>,
}

fn sample_query_string(
    filters: &[String],
    sort: SampleSort,
    descending: bool,
) -> Vec<(&'static str, String)> {
    let mut pairs: Vec<(&str, String)> = filters.iter().map(|f| ("f", f.clone())).collect();
    pairs.push(("sort", sort.as_str().to_owned()));
    pairs.push(("desc", descending.to_string()));
    pairs
}

fn with_query(path: &str, pairs: &[(&str, String)]) -> String {
    let encoded = serde_urlencoded::to_string(pairs).unwrap_or_default();
    if encoded.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{encoded}")
    }
}

/// The list as it draws for a page of samples.
#[allow(clippy::too_many_arguments)]
pub fn samples_view(
    query: &SampleQuery,
    filters: Vec<String>,
    samples: &[Sample],
    cursor: Option<&str>,
    next: Option<&str>,
    can_download: bool,
    missing: &[MissingCount],
) -> SamplesView {
    let base = sample_query_string(&filters, query.sort, query.descending);
    let page = |cursor: Option<&str>| {
        let mut pairs = base.clone();
        if let Some(cursor) = cursor {
            pairs.push(("cursor", cursor.to_owned()));
        }
        with_query("/signatures/samples", &pairs)
    };
    let api_filters: Vec<(&str, String)> = filters.iter().map(|f| ("f", f.clone())).collect();
    SamplesView {
        fields: filter_fields(FilterScreen::SvsSamples, &query.filters),
        sort: query.sort.as_str(),
        descending: query.descending,
        sorts: SampleSort::ALL.map(SampleSort::as_str),
        rows: samples.iter().map(sample_row).collect(),
        first: cursor.map(|_| page(None)),
        next: next.map(|next| page(Some(next))),
        csv: with_query("/api/svs/v1/samples/export/csv", &base),
        ndjson: with_query("/api/svs/v1/samples/export/ndjson", &base),
        download: can_download.then(|| with_query("/api/svs/v1/samples/download", &api_filters)),
        missing: missing.iter().map(missing_row).collect(),
        filters,
    }
}

#[derive(Debug, Template)]
#[template(path = "signatures/samples.html")]
pub struct SamplesPage {
    pub layout: Layout,
    pub view: SamplesView,
}

/// A contributing detection as a capture's row lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionRow {
    pub id: i64,
    pub verdict: &'static str,
    pub source: &'static str,
    pub overridden: String,
}

/// A capture of the sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRow {
    pub id: i64,
    pub alert: String,
    pub alert_href: String,
    pub file_path: String,
    pub size: String,
    pub state: &'static str,
    pub missing_reason: &'static str,
    pub signature_version: String,
    pub yara_meta_tags: String,
    pub captured: String,
    /// The API's match record, when it's kept.
    pub record: Option<String>,
    pub string_matches: String,
    pub detections: Vec<DetectionRow>,
}

/// A sample's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleView {
    pub sample: SampleRow,
    pub captures: Vec<CaptureRow>,
    /// Why a relabel would be refused, shown in place of its forms.
    pub relabel_refusal: Option<String>,
    pub can_label: bool,
    /// An unconfirmed (inherited_multi) detection is there to confirm.
    pub can_confirm: bool,
    pub can_admin: bool,
    pub download: Option<String>,
    pub notice: Option<&'static str>,
    pub max_reason: usize,
}

impl SampleView {
    pub fn action(&self, what: &str) -> String {
        format!("{}/{what}", self.sample.href)
    }

    pub fn delete_href(&self) -> String {
        format!("/signatures/samples/{}/delete", encode(&self.sample.sha256))
    }
}

pub fn sample_view(
    detail: &SampleDetail,
    can_label: bool,
    can_admin: bool,
    can_download: bool,
    done: Option<&str>,
) -> SampleView {
    let sample = sample_row(&detail.sample);
    let can_confirm = detail.captures.iter().any(|c| {
        c.detections
            .iter()
            .any(|d| d.verdict_source == Some(ace_service::VerdictSource::InheritedMulti))
    });
    SampleView {
        captures: detail
            .captures
            .iter()
            .map(|c| CaptureRow {
                id: c.id,
                alert: c.alert.to_string(),
                alert_href: format!("/alerts/{}", c.alert),
                file_path: c.file_path.clone(),
                size: c.file_size.map(size).unwrap_or_default(),
                state: c.state.as_str(),
                missing_reason: c.missing_reason.map(|r| r.as_str()).unwrap_or(""),
                signature_version: c.signature_version.clone(),
                yara_meta_tags: c.yara_meta_tags.join(", "),
                captured: when(c.created_at),
                record: c
                    .has_record
                    .then(|| format!("/api/svs/v1/samples/captures/{}/record", c.id)),
                string_matches: c
                    .match_summary
                    .as_ref()
                    .and_then(|s| s["string_match_count"].as_i64())
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                detections: c
                    .detections
                    .iter()
                    .map(|d| DetectionRow {
                        id: d.detection,
                        verdict: d.verdict.map(Verdict::as_str).unwrap_or("none"),
                        source: d.verdict_source.map(|s| s.as_str()).unwrap_or(""),
                        overridden: d
                            .override_verdict
                            .map(Verdict::as_str)
                            .unwrap_or("")
                            .to_owned(),
                    })
                    .collect(),
            })
            .collect(),
        relabel_refusal: detail.relabel_refusal.clone(),
        can_label,
        can_confirm: can_label && can_confirm,
        can_admin,
        download: (can_download && detail.sample.stored > 0).then(|| {
            format!(
                "/api/svs/v1/samples/{}/{}/download",
                encode(&detail.sample.sha256),
                encode(&detail.sample.rule_uuid)
            )
        }),
        notice: notice(done),
        max_reason: ace_service::MAX_SAMPLE_REASON,
        sample,
    }
}

fn notice(done: Option<&str>) -> Option<&'static str> {
    Some(match done? {
        "relabeled" => "The sample's contributing detections have the verdict.",
        "reset" => "The explicit verdicts are cleared: the label is inherited again.",
        "confirmed" => "The unconfirmed TP detections are confirmed.",
        "unchanged" => "Nothing changed: the detections were as asked already.",
        "retired" => "The sample is retired for its rule.",
        "unretired" => "The sample is expected to match its rule again.",
        _ => return None,
    })
}

#[derive(Debug, Template)]
#[template(path = "signatures/sample_detail.html")]
pub struct SamplePage {
    pub layout: Layout,
    pub view: SampleView,
}

/// What a deletion removes, and its form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteView {
    pub sha256: String,
    pub action: String,
    /// The samples of the file, by rule.
    pub rows: Vec<SampleRow>,
    pub reason: String,
    pub max_reason: usize,
    pub problem: Option<String>,
}

#[derive(Debug, Template)]
#[template(path = "signatures/confirm_sample_delete.html")]
pub struct ConfirmDeletePage {
    pub layout: Layout,
    pub view: DeleteView,
}

/// The kept row of a deletion.
#[derive(Debug, Template)]
#[template(path = "signatures/sample_deleted.html")]
pub struct DeletedPage {
    pub layout: Layout,
    pub sha256: String,
    pub capture_count: i32,
    pub rules: String,
    pub purged: bool,
}

// ---- the gate and the answers every handler shares ----

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

fn bad_request(message: impl Into<String>, parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, message, parts).into_response()
}

fn key_of(path: Result<Path<(String, String)>, PathRejection>) -> Option<(String, String)> {
    path.ok().map(|Path(key)| key)
}

// ---- the pages ----

/// `GET /signatures/samples`.
pub(crate) async fn samples(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let request = match list_request(FilterScreen::SvsSamples, raw.0.as_deref()) {
        Ok(request) => request,
        Err(error) => return failed(error, &parts),
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let sort = match one(&form, "sort").filter(|s| !s.is_empty()) {
        None => SampleSort::LastCaptured,
        Some(text) => match SampleSort::parse(text) {
            Some(sort) => sort,
            None => return bad_request(format!("{text:?} isn't a sort."), &parts),
        },
    };
    let descending = !matches!(one(&form, "desc"), Some("false"));
    let filters = ace_service::filters::encode(FilterScreen::SvsSamples, &request.filters)
        .unwrap_or_default();
    if request.folded {
        return see_other(
            &with_query(
                "/signatures/samples",
                &sample_query_string(&filters, sort, descending),
            ),
            None,
        );
    }
    let query = SampleQuery {
        filters: request.filters.clone(),
        sort,
        descending,
        ..SampleQuery::default()
    };
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let actor = &viewer.actor;
    let read = async {
        let page = gui
            .service
            .svs_samples(actor, &query, cursor, Some(SAMPLES_PER_PAGE))
            .await?;
        let missing = gui.service.svs_missing(actor).await?;
        let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
        Ok::<_, ServiceError>(samples_view(
            &query,
            filters.clone(),
            &page.samples,
            cursor,
            page.next.as_deref(),
            can_download,
            &missing,
        ))
    };
    match read.await {
        Ok(view) => render(&SamplesPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /signatures/samples/{sha256}/{rule_uuid}`.
pub(crate) async fn sample(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((sha256, rule_uuid)) = key_of(path) else {
        return bad_request("A sample is a sha256 and a rule's uuid.", &parts);
    };
    let form = pairs(parts.uri.query().unwrap_or("").as_bytes());
    let done = one(&form, "done");
    let actor = &viewer.actor;
    let read = async {
        let detail = gui.service.svs_sample(actor, &sha256, &rule_uuid).await?;
        let can_label = gui.service.allowed(actor, &ALERT_WRITE).await?;
        let can_admin = gui.service.allowed(actor, &SVS_ADMIN).await?;
        let can_download = gui.service.allowed(actor, &SIGNATURE_DOWNLOAD).await?;
        Ok::<_, ServiceError>(sample_view(
            &detail,
            can_label,
            can_admin,
            can_download,
            done,
        ))
    };
    match read.await {
        Ok(view) => render(&SamplePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

fn back_to(sha256: &str, rule_uuid: &str, done: &str) -> Response {
    see_other(
        &format!("{}?done={done}", sample_href(sha256, rule_uuid)),
        None,
    )
}

fn label_done(change: &LabelChange, done: &'static str) -> &'static str {
    if change.changed == 0 {
        "unchanged"
    } else {
        done
    }
}

/// `POST /signatures/samples/{sha256}/{rule_uuid}/label`: `verdict` is `tp`, `fp`, or `reset`.
pub(crate) async fn label(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((sha256, rule_uuid)) = key_of(path) else {
        return bad_request("A sample is a sha256 and a rule's uuid.", &parts);
    };
    let form = pairs(&body);
    let actor = &viewer.actor;
    let result = match one(&form, "verdict") {
        Some("reset") => gui
            .service
            .reset_svs_sample_label(actor, &sha256, &rule_uuid)
            .await
            .map(|c| label_done(&c, "reset")),
        Some(text) => match Verdict::parse(text) {
            Some(verdict) => gui
                .service
                .relabel_svs_sample(actor, &sha256, &rule_uuid, verdict)
                .await
                .map(|c| label_done(&c, "relabeled")),
            None => return bad_request("The verdict is tp, fp or reset.", &parts),
        },
        None => return bad_request("The verdict is tp, fp or reset.", &parts),
    };
    match result {
        Ok(done) => back_to(&sha256, &rule_uuid, done),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /signatures/samples/{sha256}/{rule_uuid}/confirm`.
pub(crate) async fn confirm(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((sha256, rule_uuid)) = key_of(path) else {
        return bad_request("A sample is a sha256 and a rule's uuid.", &parts);
    };
    match gui
        .service
        .confirm_svs_sample(&viewer.actor, &sha256, &rule_uuid)
        .await
    {
        Ok(change) => back_to(&sha256, &rule_uuid, label_done(&change, "confirmed")),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /signatures/samples/{sha256}/{rule_uuid}/retire`, with a reason.
pub(crate) async fn retire(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((sha256, rule_uuid)) = key_of(path) else {
        return bad_request("A sample is a sha256 and a rule's uuid.", &parts);
    };
    let form = pairs(&body);
    let reason = one(&form, "reason").unwrap_or("");
    match gui
        .service
        .retire_svs_sample(&viewer.actor, &sha256, &rule_uuid, reason)
        .await
    {
        Ok(_) => back_to(&sha256, &rule_uuid, "retired"),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /signatures/samples/{sha256}/{rule_uuid}/unretire`.
pub(crate) async fn unretire(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some((sha256, rule_uuid)) = key_of(path) else {
        return bad_request("A sample is a sha256 and a rule's uuid.", &parts);
    };
    match gui
        .service
        .unretire_svs_sample(&viewer.actor, &sha256, &rule_uuid)
        .await
    {
        Ok(_) => back_to(&sha256, &rule_uuid, "unretired"),
        Err(error) => failed(error, &parts),
    }
}

async fn delete_view(
    gui: &Gui,
    viewer: &SignedIn,
    sha256: &str,
    reason: String,
) -> Result<DeleteView, ServiceError> {
    let query = SampleQuery {
        filters: vec![ace_service::FilterEntry::text("SHA256", false, &[sha256])],
        sort: SampleSort::Rule,
        descending: false,
        ..SampleQuery::default()
    };
    let page = gui
        .service
        .svs_samples(
            &viewer.actor,
            &query,
            None,
            Some(ace_service::MAX_SAMPLES_PAGE),
        )
        .await?;
    if page.samples.is_empty() {
        return Err(ServiceError::NotFound(format!("no sample {sha256}")));
    }
    Ok(DeleteView {
        sha256: sha256.to_ascii_lowercase(),
        action: format!("/signatures/samples/{}/delete", encode(sha256)),
        rows: page.samples.iter().map(sample_row).collect(),
        reason,
        max_reason: ace_service::MAX_SAMPLE_REASON,
        problem: None,
    })
}

/// The refusal of a viewer who doesn't hold `svs:admin`, or None for one who does.
async fn refused_admin(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Option<Response> {
    match gui.service.allowed(&viewer.actor, &SVS_ADMIN).await {
        Ok(true) => None,
        Ok(false) => Some(
            Failure::new(
                StatusCode::FORBIDDEN,
                "Deleting a sample needs svs:admin.",
                parts,
            )
            .into_response(),
        ),
        Err(error) => Some(failed(error, parts)),
    }
}

/// `GET /signatures/samples/{sha256}/delete`: what a deletion removes, and its form.
pub(crate) async fn confirm_delete(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    sha256: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Path(sha256)) = sha256 else {
        return bad_request("A file is its sha256.", &parts);
    };
    // only someone who could delete is asked to confirm one
    if let Some(refused) = refused_admin(&gui, &viewer, &parts).await {
        return refused;
    }
    match delete_view(&gui, &viewer, &sha256, String::new()).await {
        Ok(view) => render(&ConfirmDeletePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /signatures/samples/{sha256}/delete`: the deletion, through `Service::delete_svs_sample`.
pub(crate) async fn delete(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    sha256: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Path(sha256)) = sha256 else {
        return bad_request("A file is its sha256.", &parts);
    };
    let form = pairs(&body);
    let reason = one(&form, "reason").unwrap_or("").to_owned();
    let Some(bucket) = gui.service.bucket() else {
        return failed(
            ServiceError::Unconfigured("this node has no bucket to purge the file from".to_owned()),
            &parts,
        );
    };
    match gui
        .service
        .delete_svs_sample(&viewer.actor, bucket, &sha256, &reason)
        .await
    {
        Ok(deletion) => render(&DeletedPage {
            layout: viewer.layout,
            sha256: deletion.sha256,
            capture_count: deletion.capture_count,
            rules: deletion.rule_uuids.join(", "),
            purged: deletion.purged_at.is_some(),
        }),
        // a reason missing or too long draws the form again with what was typed
        Err(ServiceError::InvalidRequest(problem)) => {
            match delete_view(&gui, &viewer, &sha256, reason).await {
                Ok(mut view) => {
                    view.problem = Some(problem);
                    let mut response = render(&ConfirmDeletePage {
                        layout: viewer.layout,
                        view,
                    });
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    response
                }
                Err(error) => failed(error, &parts),
            }
        }
        Err(error) => failed(error, &parts),
    }
}
