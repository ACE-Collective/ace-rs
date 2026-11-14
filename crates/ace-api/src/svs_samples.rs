//! `/api/svs/v1/samples`: SVS's samples (PLAN.md 7.10 batch 2), ace3's `aceapi_v2/svs/samples` router, over
//! `ace_service`'s `svs_samples`. A sample is a file a YARA rule matched on an alert an analyst graded TP or
//! FP, over every alert it was captured from, with a label derived from the verdicts on those alerts'
//! detections.
//!
//! Reading needs `signature:read`; anything that hands over the files needs `signature:download`, and they
//! come only inside a zip encrypted with AES-256 and the password `infected`, as YARA QA's downloads do.
//! Relabel, reset and confirm write verdicts, so they need `alert:write` as well; retire and delete need
//! `svs:admin`. Every write, and every download, is audited by the service.

use std::io::{Seek, SeekFrom, Write};

use ace_core::bucket::BucketError;
use ace_core::svs::samples::{Label, SVS_SAMPLES, Strength, Votes};
use ace_results::Sha256;
use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    Actor, LabelChange, MissingCount, Retirement, Sample, SampleCapture, SampleDeletion,
    SampleDetail, SampleDetection, SampleDownload, SampleQuery, SampleSort,
};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::{ActorBody, ZIP_PASSWORD, ZipBody};
use crate::auth::Authenticated;
use crate::detection_points::{VerdictBody, VerdictSourceBody};
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

/// A sample's label: `tp`, `fp`, or `conflicted` when votes of the strongest strength present disagree.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LabelBody {
    Tp,
    Fp,
    Conflicted,
}

impl From<Label> for LabelBody {
    fn from(label: Label) -> Self {
        match label {
            Label::Tp => LabelBody::Tp,
            Label::Fp => LabelBody::Fp,
            Label::Conflicted => LabelBody::Conflicted,
        }
    }
}

fn strength(strength: Strength) -> VerdictSourceBody {
    match strength {
        Strength::Explicit => VerdictSourceBody::Explicit,
        Strength::InheritedSingle => VerdictSourceBody::InheritedSingle,
        Strength::InheritedMulti => VerdictSourceBody::InheritedMulti,
    }
}

/// How many contributing detections vote TP or FP, at each strength (verdict source).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct VotesBody {
    tp_explicit: i64,
    fp_explicit: i64,
    tp_inherited_single: i64,
    fp_inherited_single: i64,
    tp_inherited_multi: i64,
    fp_inherited_multi: i64,
}

impl From<Votes> for VotesBody {
    fn from(votes: Votes) -> Self {
        VotesBody {
            tp_explicit: votes.tp_explicit,
            fp_explicit: votes.fp_explicit,
            tp_inherited_single: votes.tp_inherited_single,
            fp_inherited_single: votes.fp_inherited_single,
            tp_inherited_multi: votes.tp_inherited_multi,
            fp_inherited_multi: votes.fp_inherited_multi,
        }
    }
}

/// One sample: a file and a YARA rule it matched, over every alert it was captured from. Its rule name,
/// namespace and file path are what the rule's author and the alert's sender wrote: show them as text.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SampleBody {
    sha256: String,
    /// The rule's uuid meta: the signature of its detections.
    rule_uuid: String,
    /// The rule's name, namespace, and the file's path and size, in the latest capture.
    rule_name: String,
    namespace: Option<String>,
    file_path: String,
    file_size: Option<i64>,
    /// How many captures (one per alert) it has, how many hold the file, and how many couldn't.
    capture_count: i64,
    stored: i64,
    missing: i64,
    /// How many captures lack something: the file, or the match record.
    missing_data: i64,
    /// How many captures recorded the signature version `unknown`.
    unknown_version: i64,
    first_captured: DateTime<Utc>,
    last_captured: DateTime<Utc>,
    /// The latest change of any of its captures.
    updated_at: DateTime<Utc>,
    latest_capture_id: i64,
    /// Null when no contributing detection has a verdict.
    label: Option<LabelBody>,
    /// The strength that decided the label: explicit > inherited_single > inherited_multi.
    label_source: Option<VerdictSourceBody>,
    votes: VotesBody,
    /// Whether it's retired for its rule: YARA validation only counts it.
    retired: bool,
    retired_by: Option<ActorBody>,
    retired_at: Option<DateTime<Utc>>,
    retired_reason: Option<String>,
}

impl From<Sample> for SampleBody {
    fn from(sample: Sample) -> Self {
        SampleBody {
            sha256: sample.sha256,
            rule_uuid: sample.rule_uuid,
            rule_name: sample.rule_name,
            namespace: sample.namespace,
            file_path: sample.file_path,
            file_size: sample.file_size,
            capture_count: sample.capture_count,
            stored: sample.stored,
            missing: sample.missing,
            missing_data: sample.missing_data,
            unknown_version: sample.unknown_version,
            first_captured: sample.first_captured,
            last_captured: sample.last_captured,
            updated_at: sample.updated_at,
            latest_capture_id: sample.latest_capture_id,
            label: sample.label.map(LabelBody::from),
            label_source: sample.label_source.map(strength),
            votes: sample.votes.into(),
            retired: sample.retired,
            retired_by: sample.retired_by.map(ActorBody::from),
            retired_at: sample.retired_at,
            retired_reason: sample.retired_reason,
        }
    }
}

impl ExportRow for SampleBody {
    const HEADER: &'static [&'static str] = &[
        "sha256",
        "rule_uuid",
        "rule_name",
        "namespace",
        "file_path",
        "file_size",
        "capture_count",
        "stored",
        "missing",
        "missing_data",
        "unknown_version",
        "first_captured",
        "last_captured",
        "updated_at",
        "latest_capture_id",
        "label",
        "label_source",
        "retired",
        "retired_by",
        "retired_at",
        "retired_reason",
        "tp_explicit",
        "fp_explicit",
        "tp_inherited_single",
        "fp_inherited_single",
        "tp_inherited_multi",
        "fp_inherited_multi",
    ];

    fn cells(&self) -> Vec<String> {
        fn text<T: Serialize>(value: &T) -> String {
            match serde_json::to_value(value) {
                Ok(Value::String(text)) => text,
                Ok(Value::Null) | Err(_) => String::new(),
                Ok(other) => other.to_string(),
            }
        }
        vec![
            self.sha256.clone(),
            self.rule_uuid.clone(),
            self.rule_name.clone(),
            self.namespace.clone().unwrap_or_default(),
            self.file_path.clone(),
            text(&self.file_size),
            self.capture_count.to_string(),
            self.stored.to_string(),
            self.missing.to_string(),
            self.missing_data.to_string(),
            self.unknown_version.to_string(),
            time_cell(Some(self.first_captured)),
            time_cell(Some(self.last_captured)),
            time_cell(Some(self.updated_at)),
            self.latest_capture_id.to_string(),
            text(&self.label),
            text(&self.label_source),
            self.retired.to_string(),
            self.retired_by
                .as_ref()
                .and_then(|by| serde_json::to_value(by).ok())
                .map(|by| text(&by["name"]))
                .unwrap_or_default(),
            time_cell(self.retired_at),
            self.retired_reason.clone().unwrap_or_default(),
            self.votes.tp_explicit.to_string(),
            self.votes.fp_explicit.to_string(),
            self.votes.tp_inherited_single.to_string(),
            self.votes.fp_inherited_single.to_string(),
            self.votes.tp_inherited_multi.to_string(),
            self.votes.fp_inherited_multi.to_string(),
        ]
    }
}

/// A page of samples.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SamplePageBody {
    samples: Vec<SampleBody>,
    /// Pass as `cursor`, with the same filters and sort, for the next page; null on the last.
    next: Option<String>,
}

/// A contributing detection: a detection of the rule on the file, on the capture's alert.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SampleDetectionBody {
    /// The detection's id on its alert.
    detection: i64,
    verdict: Option<VerdictBody>,
    verdict_source: Option<VerdictSourceBody>,
    /// The stored verdict, who stored it and when.
    override_verdict: Option<VerdictBody>,
    override_by: Option<ActorBody>,
    override_set_at: Option<DateTime<Utc>>,
}

impl From<SampleDetection> for SampleDetectionBody {
    fn from(d: SampleDetection) -> Self {
        SampleDetectionBody {
            detection: d.detection,
            verdict: d.verdict.map(VerdictBody::from),
            verdict_source: d.verdict_source.map(VerdictSourceBody::from),
            override_verdict: d.override_verdict.map(VerdictBody::from),
            override_by: d.override_by.map(ActorBody::from),
            override_set_at: d.override_set_at,
        }
    }
}

/// One capture of a sample: the file as one alert had it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SampleCaptureBody {
    id: i64,
    /// The alert it was captured from, which may since have been deleted.
    alert: Uuid,
    observable: Option<i64>,
    rule_name: String,
    namespace: Option<String>,
    /// The commit of the rule's repository when it matched, or `unknown`.
    signature_version: String,
    rule_content_hash: Option<String>,
    file_path: String,
    file_size: Option<i64>,
    yara_meta_tags: Vec<String>,
    /// `stored` or `missing`.
    state: String,
    /// `file`, `storage` or `match_record`, when it lacks something.
    missing_reason: Option<String>,
    /// Whether its match record is kept (`GET /api/svs/v1/samples/captures/{id}/record`).
    has_record: bool,
    /// The record's rule, meta, tags and per string how many times it matched and where first.
    #[schema(value_type = Option<Object>)]
    match_summary: Option<Value>,
    /// The yara-x version of the core that kept it.
    yara_version: Option<String>,
    created_at: DateTime<Utc>,
    stored_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    /// Its contributing detections; none once the alert is gone.
    detections: Vec<SampleDetectionBody>,
}

impl From<SampleCapture> for SampleCaptureBody {
    fn from(c: SampleCapture) -> Self {
        SampleCaptureBody {
            id: c.id,
            alert: c.alert,
            observable: c.observable,
            rule_name: c.rule_name,
            namespace: c.namespace,
            signature_version: c.signature_version,
            rule_content_hash: c.rule_content_hash,
            file_path: c.file_path,
            file_size: c.file_size,
            yara_meta_tags: c.yara_meta_tags,
            state: c.state.as_str().to_owned(),
            missing_reason: c.missing_reason.map(|r| r.as_str().to_owned()),
            has_record: c.has_record,
            match_summary: c.match_summary,
            yara_version: c.yara_version,
            created_at: c.created_at,
            stored_at: c.stored_at,
            updated_at: c.updated_at,
            detections: c
                .detections
                .into_iter()
                .map(SampleDetectionBody::from)
                .collect(),
        }
    }
}

/// One sample with every capture, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SampleDetailBody {
    sample: SampleBody,
    captures: Vec<SampleCaptureBody>,
    /// Why a relabel would be refused (every contributing detection is on an FP or SIMULATED alert, say),
    /// or null when it can be relabeled.
    relabel_refusal: Option<String>,
}

impl From<SampleDetail> for SampleDetailBody {
    fn from(detail: SampleDetail) -> Self {
        SampleDetailBody {
            sample: detail.sample.into(),
            captures: detail
                .captures
                .into_iter()
                .map(SampleCaptureBody::from)
                .collect(),
            relabel_refusal: detail.relabel_refusal,
        }
    }
}

/// How many captures of a rule lack something, for one reason.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MissingCountBody {
    rule_uuid: String,
    rule_name: String,
    /// `file`: the file was gone before it could be kept; `storage`: the bucket refused it; `match_record`:
    /// the file is kept, its match record was gone.
    reason: String,
    count: i64,
}

impl From<MissingCount> for MissingCountBody {
    fn from(m: MissingCount) -> Self {
        MissingCountBody {
            rule_uuid: m.rule_uuid,
            rule_name: m.rule_name,
            reason: m.reason.as_str().to_owned(),
            count: m.count,
        }
    }
}

/// The explicit verdict to store on every contributing detection that can take one.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LabelRequest {
    verdict: VerdictBody,
}

/// Why, recorded with the action.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReasonRequest {
    /// 1 to 4000 characters.
    reason: String,
}

/// A contributing detection that couldn't take the verdict, and why.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SkippedDetectionBody {
    alert: Uuid,
    detection: i64,
    reason: String,
}

/// What a relabel, reset or confirm wrote, and the sample's label afterwards.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LabelChangeBody {
    /// How many contributing detections changed, and how many were as asked already.
    changed: usize,
    unchanged: usize,
    /// The ones that can't take an analyst's verdict (on a false positive, unclassified or test alert),
    /// each with why.
    skipped: Vec<SkippedDetectionBody>,
    label: Option<LabelBody>,
    label_source: Option<VerdictSourceBody>,
}

impl From<LabelChange> for LabelChangeBody {
    fn from(change: LabelChange) -> Self {
        LabelChangeBody {
            changed: change.changed,
            unchanged: change.unchanged,
            skipped: change
                .skipped
                .into_iter()
                .map(|s| SkippedDetectionBody {
                    alert: s.alert,
                    detection: s.detection,
                    reason: s.reason,
                })
                .collect(),
            label: change.label.map(LabelBody::from),
            label_source: change.label_source.map(strength),
        }
    }
}

/// A sample's retirement.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RetirementBody {
    sha256: String,
    rule_uuid: String,
    /// Whether it's retired now; false once unretired.
    retired: bool,
    reason: String,
    retired_by: Option<ActorBody>,
    retired_at: DateTime<Utc>,
    unretired_by: Option<ActorBody>,
    unretired_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl From<Retirement> for RetirementBody {
    fn from(r: Retirement) -> Self {
        RetirementBody {
            sha256: r.sha256,
            rule_uuid: r.rule_uuid,
            retired: r.retired,
            reason: r.reason,
            retired_by: r.retired_by.map(ActorBody::from),
            retired_at: r.retired_at,
            unretired_by: r.unretired_by.map(ActorBody::from),
            unretired_at: r.unretired_at,
            updated_at: r.updated_at,
        }
    }
}

/// The kept row of a file deleted from SVS.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SampleDeletionBody {
    sha256: String,
    /// The rules it had captures for, and how many captures went.
    rule_uuids: Vec<String>,
    capture_count: i32,
    deleted_by: Option<ActorBody>,
    reason: String,
    deleted_at: DateTime<Utc>,
    /// When its bytes were purged; null while they aren't, and deleting the sample again retries.
    purged_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl From<SampleDeletion> for SampleDeletionBody {
    fn from(d: SampleDeletion) -> Self {
        SampleDeletionBody {
            sha256: d.sha256,
            rule_uuids: d.rule_uuids,
            capture_count: d.capture_count,
            deleted_by: d.deleted_by.map(ActorBody::from),
            reason: d.reason,
            deleted_at: d.deleted_at,
            purged_at: d.purged_at,
            updated_at: d.updated_at,
        }
    }
}

/// A page of deletions, oldest change first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DeletionPageBody {
    deletions: Vec<SampleDeletionBody>,
    /// Pass as `cursor`, with the same `changed_since`, for the next page; null on the last.
    next: Option<String>,
}

/// A list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct SamplesQuery {
    /// A filter in the share-link encoding, `[!]<slug>:<value>,<value>`, with the samples screen's slugs
    /// (`GET /api/filters/v1/screens/svs_samples`); repeat it for more. Filters are ANDed, the values of
    /// one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `last_captured` (the default), `first_captured`, `capture_count`, `rule`, `label` or `sha256`.
    sort: Option<String>,
    /// Descending, the default; `false` for ascending.
    desc: Option<bool>,
    /// Only samples that may have changed at or after this time, UTC when it has no offset: a capture
    /// added or changed, a retirement, a contributing alert's disposition, or a contributing detection's
    /// stored verdict. Pass the time the previous pull started.
    changed_since: Option<String>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct SampleExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// As the list takes it.
    sort: Option<String>,
    desc: Option<bool>,
    changed_since: Option<String>,
    tz: Option<String>,
}

/// A bulk download's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct SampleDownloadQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    tz: Option<String>,
}

/// The deletions' parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct DeletionsQuery {
    /// Only deletions recorded or changed (their purge finished) at or after this time.
    changed_since: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

fn sample_query(params: &Params) -> Result<SampleQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsSamples, &params.all("f"), true)?;
    let sort = match params.one("sort")? {
        None => SampleSort::LastCaptured,
        Some(text) => SampleSort::parse(text).ok_or_else(|| {
            ApiError::bad_request(format!(
                "sort is last_captured, first_captured, capture_count, rule, label or sha256, not {text:?}"
            ))
        })?,
    };
    Ok(SampleQuery {
        filters,
        tz: params.tz()?,
        sort,
        descending: params.parsed("desc", "true or false")?.unwrap_or(true),
        changed_since: params.time("changed_since")?,
    })
}

fn sample_key(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(String, String), ApiError> {
    let Path((sha256, rule_uuid)) = path?;
    Ok((sha256, rule_uuid))
}

/// Samples, one per (sha256, rule uuid), with their capture counts and label, a page at a time in the
/// order asked for, over the captures there were when the first page was read. Follow `next` with the same
/// filters and sort until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples",
    tag = "svs",
    params(SamplesQuery),
    responses(
        (status = 200, description = "A page of samples", body = SamplePageBody),
        (status = 400, description = "A filter, sort, time, timezone, limit or cursor that isn't one, a cursor of another order, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<SamplePageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = sample_query(&params)?;
    let page = web
        .service
        .svs_samples(
            &actor,
            &query,
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(SamplePageBody {
        samples: page.samples.into_iter().map(SampleBody::from).collect(),
        next: page.next,
    }))
}

async fn export_samples(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = sample_query(&params)?;
    let total = service.svs_sample_count(&actor, &query, max).await?;
    let first = service
        .svs_samples(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.samples.into_iter().map(SampleBody::from).collect(),
        first.next,
    );
    export::respond(
        format,
        "svs-samples",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_samples(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.samples.into_iter().map(SampleBody::from).collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every sample the list's filters match, in its order, as CSV: a header line, then a row per sample with
/// its votes in their own columns, and a cell a spreadsheet would read as a formula behind a `'`. A failure
/// part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/export/csv",
    tag = "svs",
    params(SampleExportQuery),
    responses(
        (status = 200, description = "The samples", content_type = "text/csv", body = String),
        (status = 400, description = "A filter, sort, time or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 413, description = "More samples than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_samples(Format::Csv, actor, web, raw).await
}

/// Every sample the list's filters match, in its order, as NDJSON: a sample as the list gives it on each
/// line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/export/ndjson",
    tag = "svs",
    params(SampleExportQuery),
    responses(
        (status = 200, description = "The samples", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter, sort, time or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 413, description = "More samples than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_samples(Format::Ndjson, actor, web, raw).await
}

/// How many captures of each rule lack something, by reason: `file`, `storage` or `match_record`. The
/// rules with the most first.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/missing",
    tag = "svs",
    responses(
        (status = 200, description = "The counts", body = Vec<MissingCountBody>),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn missing(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<Vec<MissingCountBody>>, ApiError> {
    let missing = web.service.svs_missing(&actor).await?;
    Ok(Json(
        missing.into_iter().map(MissingCountBody::from).collect(),
    ))
}

/// A capture's whole match record: the alert's YARA scan result for the rule, as its result has it. It's
/// shown inline as JSON, never sniffed as anything else, since it holds bytes of the file.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/captures/{id}/record",
    tag = "svs",
    params(("id" = i64, Path, description = "The capture's id")),
    responses(
        (status = 200, description = "The record", content_type = "application/json", body = Object),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No capture with that id, or one with no record kept", body = ErrorBody),
    )
)]
pub(crate) async fn record(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = id?;
    let record = web.service.svs_capture_record(&actor, id).await?;
    let body = serde_json::to_vec(&record).map_err(ApiError::internal)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"svs-capture-{id}.json\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

fn deletion_cursor(deletion: &SampleDeletion) -> String {
    format!("{}_{}", deletion.updated_at.to_rfc3339(), deletion.id)
}

fn parse_deletion_cursor(text: &str) -> Result<(DateTime<Utc>, i64), ApiError> {
    let bad = || ApiError::bad_request(format!("{text:?} isn't a cursor"));
    let (at, id) = text.rsplit_once('_').ok_or_else(bad)?;
    let at = DateTime::parse_from_rfc3339(at).map_err(|_| bad())?;
    let id = id.parse().map_err(|_| bad())?;
    Ok((at.with_timezone(&Utc), id))
}

/// The audit of the sample files deleted from SVS, oldest change first: who deleted each, why, which rules
/// it had captures for, and whether its bytes are purged yet.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/deletions",
    tag = "svs",
    params(DeletionsQuery),
    responses(
        (status = 200, description = "A page of deletions", body = DeletionPageBody),
        (status = 400, description = "A time, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn deletions(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<DeletionPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let after = params
        .one("cursor")?
        .map(parse_deletion_cursor)
        .transpose()?;
    let limit: u32 = params
        .parsed("limit", "a number from 1 to 1000")?
        .unwrap_or(100);
    if !(1..=ace_service::MAX_DELETIONS_PAGE).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "a page holds 1 to {}, not {limit}",
            ace_service::MAX_DELETIONS_PAGE
        )));
    }
    // one more than the page, to know there's a next
    let mut rows = web
        .service
        .svs_sample_deletions(
            &actor,
            params.time("changed_since")?,
            after,
            Some(limit + 1),
        )
        .await?;
    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next = if more {
        rows.last().map(deletion_cursor)
    } else {
        None
    };
    Ok(Json(DeletionPageBody {
        deletions: rows.into_iter().map(SampleDeletionBody::from).collect(),
        next,
    }))
}

/// One sample with every capture, newest first, and the verdicts of each capture's contributing
/// detections.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    responses(
        (status = 200, description = "The sample", body = SampleDetailBody),
        (status = 400, description = "A sha256 or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule", body = ErrorBody),
    )
)]
pub(crate) async fn sample(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<SampleDetailBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let detail = web.service.svs_sample(&actor, &sha256, &rule_uuid).await?;
    Ok(Json(detail.into()))
}

/// One sample's file and the match records of its captures, as a zip encrypted with AES-256 and the
/// password `infected`. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/download",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "A sha256 or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:download", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule, or none of its captures holds the file", body = ErrorBody),
    )
)]
pub(crate) async fn download_sample(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let download = web
        .service
        .download_svs_sample(&actor, &sha256, &rule_uuid)
        .await?;
    zip_response(
        &web,
        format!("svs-sample-{}", sha256.to_ascii_lowercase()),
        download,
    )
    .await
}

/// The files of every sample the filters match that holds its file, with their match records and a
/// manifest, as one zip encrypted with AES-256 and the password `infected`. Each file is in it once,
/// whatever the number of rules it matched. At most 500 files and 1 GiB. The download is in the audit
/// record.
#[utoipa::path(
    get,
    path = "/api/svs/v1/samples/download",
    tag = "svs",
    params(SampleDownloadQuery),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "A filter or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:download", body = ErrorBody),
        (status = 404, description = "No sample the filters match holds its file", body = ErrorBody),
        (status = 413, description = "More files or bytes than a download holds", body = ErrorBody),
    )
)]
pub(crate) async fn download_samples(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let params = Params::of(raw)?;
    let query = sample_query(&params)?;
    let download = web.service.download_svs_samples(&actor, &query).await?;
    zip_response(&web, "svs-samples".to_owned(), download).await
}

/// Relabels the sample: stores the explicit verdict on every contributing detection that can take an
/// analyst's verdict, in one transaction. Detections on false positive, unclassified or test alerts are
/// skipped and listed with why; 409 when none can take it (correct the alert's disposition instead).
#[utoipa::path(
    put,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/label",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    request_body = LabelRequest,
    responses(
        (status = 200, description = "What was written, and the label after", body = LabelChangeBody),
        (status = 400, description = "A sha256, rule uuid or body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write and signature:read", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule", body = ErrorBody),
        (status = 409, description = "No contributing detection can take the verdict, or none is left", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn relabel(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<LabelRequest>, JsonRejection>,
) -> Result<Json<LabelChangeBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let Json(body) = body?;
    let change = web
        .service
        .relabel_svs_sample(&actor, &sha256, &rule_uuid, body.verdict.into())
        .await?;
    Ok(Json(change.into()))
}

/// Resets the sample's label to inherited: clears the explicit verdicts on its contributing detections,
/// so they inherit from their alerts' dispositions again. Nothing to reset isn't an error.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/label",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    responses(
        (status = 200, description = "What was cleared, and the label after", body = LabelChangeBody),
        (status = 400, description = "A sha256 or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write and signature:read", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule", body = ErrorBody),
    )
)]
pub(crate) async fn reset_label(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<LabelChangeBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let change = web
        .service
        .reset_svs_sample_label(&actor, &sha256, &rule_uuid)
        .await?;
    Ok(Json(change.into()))
}

/// Confirms the sample's unconfirmed TP detections (source inherited_multi): an explicit TP on each, which
/// makes them weigh as a person's verdict. Nothing to confirm isn't an error.
#[utoipa::path(
    post,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/confirm",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    responses(
        (status = 200, description = "What was confirmed, and the label after", body = LabelChangeBody),
        (status = 400, description = "A sha256 or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write and signature:read", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule", body = ErrorBody),
        (status = 409, description = "No unconfirmed detection can take the verdict", body = ErrorBody),
    )
)]
pub(crate) async fn confirm(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<LabelChangeBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let change = web
        .service
        .confirm_svs_sample(&actor, &sha256, &rule_uuid)
        .await?;
    Ok(Json(change.into()))
}

/// Retires the sample for its rule: it's no longer expected to match, and YARA validation only counts it.
/// Retiring a retired sample changes nothing.
#[utoipa::path(
    put,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/retirement",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    request_body = ReasonRequest,
    responses(
        (status = 200, description = "The retirement", body = RetirementBody),
        (status = 400, description = "A sha256, rule uuid, reason or body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "No sample of that file and rule", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn retire(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<RetirementBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let Json(body) = body?;
    let retirement = web
        .service
        .retire_svs_sample(&actor, &sha256, &rule_uuid, &body.reason)
        .await?;
    Ok(Json(retirement.into()))
}

/// Unretires the sample: it's expected to match its rule again. 404 when it isn't retired.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/samples/{sha256}/{rule_uuid}/retirement",
    tag = "svs",
    params(
        ("sha256" = String, Path, description = "The file's sha256"),
        ("rule_uuid" = String, Path, description = "The rule's uuid meta"),
    ),
    responses(
        (status = 200, description = "The retirement, ended", body = RetirementBody),
        (status = 400, description = "A sha256 or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "The sample isn't retired", body = ErrorBody),
    )
)]
pub(crate) async fn unretire(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<RetirementBody>, ApiError> {
    let (sha256, rule_uuid) = sample_key(path)?;
    let retirement = web
        .service
        .unretire_svs_sample(&actor, &sha256, &rule_uuid)
        .await?;
    Ok(Json(retirement.into()))
}

/// Deletes the file from SVS, for every rule: its captures and retirements go, its bytes are purged from
/// the samples' pool, and a row is kept (`GET /api/svs/v1/samples/deletions`) that also keeps the file
/// from being captured again. Not reached: the alerts' own files and YARA QA's. Deleting a deleted sample
/// retries a purge that didn't finish, and returns the first deletion's row.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/samples/{sha256}",
    tag = "svs",
    params(("sha256" = String, Path, description = "The file's sha256")),
    request_body = ReasonRequest,
    responses(
        (status = 200, description = "The deletion's row", body = SampleDeletionBody),
        (status = 400, description = "A sha256, reason or body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "No sample of that file", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    sha256: Result<Path<String>, PathRejection>,
    body: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<SampleDeletionBody>, ApiError> {
    let Path(sha256) = sha256?;
    let Json(body) = body?;
    let deletion = web
        .service
        .delete_svs_sample(&actor, &web.bucket, &sha256, &body.reason)
        .await?;
    Ok(Json(deletion.into()))
}

/// A file in a download's manifest, and where its bytes and its records are in the zip.
#[derive(Serialize)]
struct Included {
    sha256: String,
    file_size: Option<i64>,
    rule_uuids: Vec<String>,
    /// Null when the bucket no longer has the file.
    file: Option<String>,
    captures: Vec<IncludedCapture>,
}

#[derive(Serialize)]
struct IncludedCapture {
    id: i64,
    alert: Uuid,
    rule_uuid: String,
    rule_name: String,
    /// Null when its record isn't kept.
    record: Option<String>,
}

#[derive(Serialize)]
struct Manifest {
    files: Vec<Included>,
}

enum Entry {
    Bytes(Vec<u8>),
    File(std::fs::File, u64),
}

/// The zip of `download`: `<label>/manifest.json`, and for each file `<label>/<sha256>/<sha256>`, its
/// bytes, when the bucket has them, and `<label>/<sha256>/match-<capture id>.json`, each capture's record.
/// Nothing a rule or a file named becomes an entry's name.
pub(crate) async fn zip_response(
    web: &Web,
    label: String,
    download: SampleDownload,
) -> Result<Response, ApiError> {
    let mut entries: Vec<(String, Entry)> = Vec::new();
    let mut manifest = Manifest { files: Vec::new() };
    for file in download.files {
        let sha256: Sha256 = file.sha256.parse().map_err(ApiError::internal)?;
        let directory = format!("{label}/{sha256}");
        let name = match web.bucket.get(SVS_SAMPLES, &sha256).await {
            Ok(cached) => {
                let name = format!("{directory}/{sha256}");
                entries.push((name.clone(), Entry::File(cached.file, cached.size)));
                Some(name)
            }
            Err(BucketError::NotFound { .. }) => None,
            Err(e) => return Err(ApiError::internal(e)),
        };
        let mut captures = Vec::new();
        for capture in file.captures {
            let record = match &capture.record {
                Some(record) => {
                    let name = format!("{directory}/match-{}.json", capture.id);
                    let bytes = serde_json::to_vec_pretty(record).map_err(ApiError::internal)?;
                    entries.push((name.clone(), Entry::Bytes(bytes)));
                    Some(name)
                }
                None => None,
            };
            captures.push(IncludedCapture {
                id: capture.id,
                alert: capture.alert,
                rule_uuid: capture.rule_uuid,
                rule_name: capture.rule_name,
                record,
            });
        }
        manifest.files.push(Included {
            sha256: file.sha256,
            file_size: file.file_size,
            rule_uuids: file.rule_uuids,
            file: name,
            captures,
        });
    }
    let manifest = serde_json::to_vec_pretty(&manifest).map_err(ApiError::internal)?;
    let manifest_name = format!("{label}/manifest.json");
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let out = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(out);
        let options = |size: u64| {
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .large_file(size >= u64::from(u32::MAX))
                .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD)
        };
        zip.start_file(manifest_name, options(0))
            .map_err(std::io::Error::other)?;
        zip.write_all(&manifest)?;
        for (name, entry) in entries {
            match entry {
                Entry::Bytes(bytes) => {
                    zip.start_file(name, options(0))
                        .map_err(std::io::Error::other)?;
                    zip.write_all(&bytes)?;
                }
                Entry::File(mut file, size) => {
                    zip.start_file(name, options(size))
                        .map_err(std::io::Error::other)?;
                    std::io::copy(&mut file, &mut zip)?;
                }
            }
        }
        let mut out = zip.finish().map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Start(0))?;
        Ok(out)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let length = zipped.metadata().map_err(ApiError::internal)?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(zipped),
    ));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{label}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}
