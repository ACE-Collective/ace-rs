//! SVS's samples (PLAN.md 7.10 batch 2), for the `svs/samples` routes and the signatures area's samples
//! pages: ace3's `saq/svs/samples.py`, `filters.py` and `actions.py`. The model and the capture are
//! `ace_core::svs::samples`; migration 0048 holds the tables.
//!
//! **Reading.** A sample is one (sha256, rule uuid) pair over its captures, with its label, which
//! `svs.samples` derives from the verdicts of its contributing detections under the site's dispositions'
//! classes whenever it's read (`ace_core::svs::samples`' docs). Reading samples, their captures and match
//! records needs `signature:read`; anything that hands over the files needs `signature:download`, and goes
//! through `Gate::write` with a row of what was read, as ace3 logs one. A list is keyset-paged in its order,
//! over the captures there were when its first page was read, so a sample captured again between pages is
//! neither skipped nor repeated. Its filters are ace3's samples screen's (`FilterScreen::SvsSamples`): Alert,
//! File Name and Rule test a sample's captures, so a sample matches when any of its captures does.
//!
//! **Acting** (ace3's `actions.py`). Relabel, reset and confirm never store a label: they write, clear or
//! confirm the explicit verdicts on the sample's contributing detections, all in one transaction, through
//! 7.14's verdict writes, and so need `alert:write` as well as `signature:read`, as ace3's routes do. A
//! detection that can't take an analyst's verdict (on an FP alert, an unclassified alert, one only ACE sets)
//! is skipped and reported with why; when none can, it's a `Conflict` and nothing is written. Retire marks a
//! pair as no longer expected to match its rule, so YARA validation only counts it; unretiring is soft and
//! the row is reused. Delete removes a file from SVS for a legal or privacy request: every capture of the
//! sha256 for every rule and its retirements go, the file's bytes are purged from the `svs_samples` pool
//! whatever holds them, and the deletion's row is kept, which also keeps capture from taking the file
//! again. Retire and delete need `svs:admin`. Each write has its audit row, where ace3 logs an AUDIT line.
//!
//! From ace3, and what differs:
//! - A detection is named by its id (`analysis.detections.id`), as 7.14's verdicts are, where ace3 names its
//!   content hash; a capture names its alert by the root's id and its observable by its id in the root.
//! - Who acted is the actor, so an API key without an owner may act, where ace3 refuses one with 422.
//! - A no-op (a relabel that changed nothing, retiring a retired sample) has no audit row, as every write
//!   here; ace3 logs a line for a relabel either way.
//! - The bucket is one, shared by every node, so there's no `wrong_node`, no `local` and no `node`; and it
//!   has no legal holds, so a deletion is never refused for one. ace3's `cas_purges` audit row of the purge
//!   is the deletion's own audit row here.
//! - A deletion is one transaction, the sample's lock taken as capture takes it, so a capture racing it
//!   either lands first and is removed with the rest, or sees the deletion and writes nothing. Its bytes go
//!   once that commits; a purge that doesn't finish leaves `purged_at` NULL and is retried when the sample
//!   is deleted again, as in ace3. Marking it purged is part of the same audited request and writes no
//!   second row.
//! - ace3's `changed_since` also counts a change to a contributing alert's row; here that's its
//!   disposition (`dispositioned_at`), which is what relabels it, with the verdicts' history.
//! - A download names each file by its sha256 inside the zip, as YARA QA's do, so nothing an alert's sender
//!   named becomes an entry's name; ace3 sanitizes the latest capture's file name.

use std::collections::BTreeMap;

use ace_core::bucket::{Bucket, claim_purge_in};
use ace_core::svs::samples::{
    CaptureState, Label, MissingReason, SVS_SAMPLES, Strength, Votes, capture_hold, lock_sample,
};
use ace_results::Sha256;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::types::Json;
use uuid::Uuid;

use crate::alerts::{RecordedActor, SET_LIST_TIMEOUT, page_limit, timed_out};
use crate::detection_verdicts::{BatchRules, SkipCause, Verdict, VerdictSource};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::gate::{Audited, Change, Recorded, Target, holds};
use crate::permission::{ALERT_WRITE, SIGNATURE_DOWNLOAD, SIGNATURE_READ, SVS_ADMIN};
use crate::{Actor, Service, ServiceError};

/// The most samples one page holds, ace3's `LISTING_MAX_PAGE_SIZE`.
pub const MAX_SAMPLES_PAGE: u32 = 1000;
/// The most deletions one page holds.
pub const MAX_DELETIONS_PAGE: u32 = 1000;
/// The most files one download holds, ace3's `svs.samples.max_bulk_download_files`.
pub const MAX_SAMPLE_DOWNLOAD_FILES: usize = 500;
/// The most bytes of files one download holds, ace3's `svs.samples.max_bulk_download_bytes`.
pub const MAX_SAMPLE_DOWNLOAD_BYTES: i64 = 1 << 30;
/// The longest reason for a retirement or a deletion, as ace3's.
pub const MAX_SAMPLE_REASON: usize = 4000;
/// Why relabel is refused for a sample whose alerts are gone, ace3's `NO_DETECTION_LEFT`.
pub const NO_DETECTION_LEFT: &str =
    "the sample has no contributing detection left: the alerts it was captured from were deleted";

/// What a list of samples is ordered by: ace3's `SampleSort`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleSort {
    #[default]
    LastCaptured,
    FirstCaptured,
    CaptureCount,
    Rule,
    Label,
    Sha256,
}

impl SampleSort {
    pub const ALL: [SampleSort; 6] = [
        SampleSort::LastCaptured,
        SampleSort::FirstCaptured,
        SampleSort::CaptureCount,
        SampleSort::Rule,
        SampleSort::Label,
        SampleSort::Sha256,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SampleSort::LastCaptured => "last_captured",
            SampleSort::FirstCaptured => "first_captured",
            SampleSort::CaptureCount => "capture_count",
            SampleSort::Rule => "rule",
            SampleSort::Label => "label",
            SampleSort::Sha256 => "sha256",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|sort| sort.as_str() == text)
    }
}

/// Which samples to list, and how.
#[derive(Debug, Clone)]
pub struct SampleQuery {
    /// The samples screen's filters.
    pub filters: Vec<FilterEntry>,
    /// Where a date filter's wall clock is.
    pub tz: Tz,
    pub sort: SampleSort,
    pub descending: bool,
    /// Only samples that may have changed at or after this: a capture added or changed, a retirement, a
    /// contributing alert's disposition, or a contributing detection's stored verdict set or cleared.
    pub changed_since: Option<DateTime<Utc>>,
}

impl Default for SampleQuery {
    fn default() -> Self {
        SampleQuery {
            filters: Vec::new(),
            tz: Tz::UTC,
            sort: SampleSort::LastCaptured,
            descending: true,
            changed_since: None,
        }
    }
}

/// One sample: a file and a YARA rule it matched, over every alert it was captured from.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub sha256: String,
    pub rule_uuid: String,
    /// The rule's name, namespace, the file's path and size in its latest capture.
    pub rule_name: String,
    pub namespace: Option<String>,
    pub file_path: String,
    pub file_size: Option<i64>,
    /// How many captures it has (one per alert), how many hold the file and how many couldn't.
    pub capture_count: i64,
    pub stored: i64,
    pub missing: i64,
    /// How many captures lack something: the file, or the match record.
    pub missing_data: i64,
    /// How many captures recorded the signature version `unknown`.
    pub unknown_version: i64,
    pub first_captured: DateTime<Utc>,
    pub last_captured: DateTime<Utc>,
    /// The latest change of any of its captures.
    pub updated_at: DateTime<Utc>,
    pub latest_capture_id: i64,
    pub label: Option<Label>,
    pub label_source: Option<Strength>,
    pub votes: Votes,
    /// Whether it's retired for its rule now, by whom, when and why.
    pub retired: bool,
    pub retired_by: Option<RecordedActor>,
    pub retired_at: Option<DateTime<Utc>>,
    pub retired_reason: Option<String>,
}

/// A page of samples, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq)]
pub struct SamplePage {
    pub samples: Vec<Sample>,
    pub next: Option<String>,
}

/// A contributing detection of a capture: a detection of the rule on the file, on the capture's alert.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleDetection {
    pub detection: i64,
    pub verdict: Option<Verdict>,
    pub verdict_source: Option<VerdictSource>,
    /// The stored verdict, ace3's `override`, who stored it and when.
    pub override_verdict: Option<Verdict>,
    pub override_by: Option<RecordedActor>,
    pub override_set_at: Option<DateTime<Utc>>,
}

/// One capture of a sample: the file as one alert had it.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleCapture {
    pub id: i64,
    pub alert: Uuid,
    pub observable: Option<i64>,
    pub rule_name: String,
    pub namespace: Option<String>,
    /// The commit of the rule's repository when it matched, or `unknown`.
    pub signature_version: String,
    pub rule_content_hash: Option<String>,
    pub file_path: String,
    pub file_size: Option<i64>,
    pub yara_meta_tags: Vec<String>,
    pub state: CaptureState,
    pub missing_reason: Option<MissingReason>,
    /// Whether its match record is kept (`svs_capture_record`).
    pub has_record: bool,
    /// The record's rule, meta, tags and per string how many times it matched and where first.
    pub match_summary: Option<Value>,
    pub yara_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub stored_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    /// Its contributing detections; none once the alert is gone.
    pub detections: Vec<SampleDetection>,
}

/// One sample with every capture, newest first.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleDetail {
    pub sample: Sample,
    pub captures: Vec<SampleCapture>,
    /// Why a relabel would be refused, or None when it would write at least one verdict: so a page offers
    /// it only when it works.
    pub relabel_refusal: Option<String>,
}

/// How many captures of a rule lack something, for one reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingCount {
    pub rule_uuid: String,
    /// The rule's name in its latest capture that lacks something.
    pub rule_name: String,
    pub reason: MissingReason,
    pub count: i64,
}

/// A detection a label action didn't write, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSampleDetection {
    pub alert: Uuid,
    pub detection: i64,
    pub reason: String,
}

/// What a relabel, reset or confirm did, and the sample's label afterwards: ace3's `LabelChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelChange {
    pub changed: usize,
    pub unchanged: usize,
    pub skipped: Vec<SkippedSampleDetection>,
    pub label: Option<Label>,
    pub label_source: Option<Strength>,
}

/// A sample's retirement row, retired now or not.
#[derive(Debug, Clone, PartialEq)]
pub struct Retirement {
    pub sha256: String,
    pub rule_uuid: String,
    pub retired: bool,
    pub reason: String,
    pub retired_by: Option<RecordedActor>,
    pub retired_at: DateTime<Utc>,
    pub unretired_by: Option<RecordedActor>,
    pub unretired_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// The kept row of a file deleted from SVS.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleDeletion {
    pub id: i64,
    pub sha256: String,
    /// The rules it had captures for, and how many captures went.
    pub rule_uuids: Vec<String>,
    pub capture_count: i32,
    pub deleted_by: Option<RecordedActor>,
    pub reason: String,
    pub deleted_at: DateTime<Utc>,
    /// When its bytes were purged; None while they aren't, and deleting the sample again retries.
    pub purged_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// A capture in a download: its match record, when it's kept.
#[derive(Debug, Clone, PartialEq)]
pub struct DownloadCapture {
    pub id: i64,
    pub alert: Uuid,
    pub rule_uuid: String,
    pub rule_name: String,
    pub record: Option<Value>,
}

/// One file in a download, with the samples of it the download selected and their captures.
#[derive(Debug, Clone, PartialEq)]
pub struct DownloadFile {
    pub sha256: String,
    pub file_size: Option<i64>,
    pub rule_uuids: Vec<String>,
    pub captures: Vec<DownloadCapture>,
}

/// What a download hands over: each file once, whatever the number of rules it matched.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleDownload {
    pub files: Vec<DownloadFile>,
}

// ---- audit records ----

#[derive(Serialize)]
struct LabelRecord<'a> {
    action: &'a str,
    verdict: Option<&'a str>,
    changed: usize,
    unchanged: usize,
    skipped: usize,
    detections: Vec<i64>,
}

impl Recorded for LabelRecord<'_> {}

#[derive(Serialize)]
struct RetirementRecord<'a> {
    retired: bool,
    reason: &'a str,
}

impl Recorded for RetirementRecord<'_> {}

#[derive(Serialize)]
struct DeletionRecord<'a> {
    reason: &'a str,
    rule_uuids: &'a [String],
    capture_count: i64,
    captures: &'a [i64],
}

impl Recorded for DeletionRecord<'_> {}

#[derive(Serialize)]
struct DownloadRecord<'a> {
    filters: Option<&'a [FilterEntry]>,
    rule_uuid: Option<&'a str>,
    sha256s: Vec<&'a str>,
}

impl Recorded for DownloadRecord<'_> {}

// ---- the cursor ----

/// Where a page of samples ended, in its order and over the captures its first page read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    sort: SampleSort,
    descending: bool,
    through: i64,
    key: String,
    sha256: String,
    rule_uuid: String,
}

impl Cursor {
    fn encode(&self) -> String {
        hex::encode(serde_json::to_vec(self).unwrap_or_default())
    }

    fn decode(text: &str) -> Result<Cursor, ServiceError> {
        hex::decode(text)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))
    }
}

fn check_sha256(sha256: &str) -> Result<String, ServiceError> {
    let lower = sha256.to_ascii_lowercase();
    if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(lower)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "{sha256:?} isn't a sha256, which is 64 hex characters"
        )))
    }
}

fn check_rule_uuid(rule_uuid: &str) -> Result<(), ServiceError> {
    if rule_uuid.is_empty() || rule_uuid.chars().count() > 36 {
        return Err(ServiceError::InvalidRequest(format!(
            "{rule_uuid:?} isn't a rule's uuid, which is 1 to 36 characters"
        )));
    }
    Ok(())
}

fn check_reason(reason: &str) -> Result<String, ServiceError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "a reason is required".to_owned(),
        ));
    }
    if reason.chars().count() > MAX_SAMPLE_REASON {
        return Err(ServiceError::InvalidRequest(format!(
            "a reason is at most {MAX_SAMPLE_REASON} characters"
        )));
    }
    Ok(reason.to_owned())
}

fn decoded<T>(
    text: Option<String>,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, ServiceError> {
    text.map(|text| {
        parse(&text).ok_or_else(|| {
            ServiceError::from(ace_core::DbError::Decode(format!(
                "a stored value {text:?}"
            )))
        })
    })
    .transpose()
}

/// The samples screen's parameters, in the order its query takes them after its first six.
struct Params {
    texts: [Option<Vec<String>>; 12],
    alerts: [Option<Vec<Uuid>>; 2],
    none: [bool; 2],
    windows: [Option<Vec<DateTime<Utc>>>; 4],
    flags: [Option<Vec<String>>; 8],
}

fn params(query: &SampleQuery) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::SvsSamples,
        &query.filters,
        Utc::now(),
        query.tz,
    )?;
    let ((w1, w2), (w3, w4)) = (
        split(f.windows("last_captured", false)?),
        split(f.windows("last_captured", true)?),
    );
    let uuids = |values: Option<Vec<String>>| {
        values.map(|values| values.iter().filter_map(|v| v.parse().ok()).collect())
    };
    let (label, none) = labels(f.names("label", false));
    let (not_label, not_none) = labels(f.names("label", true));
    Ok(Params {
        texts: [
            f.names("signature", false),
            f.names("signature", true),
            f.names("sha256", false),
            f.names("sha256", true),
            f.patterns("file_name", false, false),
            f.patterns("file_name", true, false),
            f.patterns("rule", false, false),
            f.patterns("rule", true, false),
            label,
            not_label,
            f.names("label_source", false),
            f.names("label_source", true),
        ],
        alerts: [
            uuids(f.names("alert", false)),
            uuids(f.names("alert", true)),
        ],
        none: [none, not_none],
        windows: [w1, w2, w3, w4],
        flags: [
            f.names("stored", false),
            f.names("stored", true),
            f.names("missing_data", false),
            f.names("missing_data", true),
            f.names("unknown_version", false),
            f.names("unknown_version", true),
            f.names("retired", false),
            f.names("retired", true),
        ],
    })
}

/// The Label filter's labels, and whether it names `none`.
fn labels(values: Option<Vec<String>>) -> (Option<Vec<String>>, bool) {
    match values {
        None => (None, false),
        Some(values) => {
            let none = values
                .iter()
                .any(|v| v == ace_core::svs::samples::LABEL_FILTER_NONE);
            (
                Some(
                    values
                        .into_iter()
                        .filter(|v| v != ace_core::svs::samples::LABEL_FILTER_NONE)
                        .collect(),
                ),
                none,
            )
        }
    }
}

/// A row of `svs.samples`, as every query here reads it.
struct SampleRow {
    sha256: Option<String>,
    rule_uuid: Option<String>,
    capture_count: Option<i64>,
    stored: Option<i64>,
    missing: Option<i64>,
    missing_data: Option<i64>,
    unknown_version: Option<i64>,
    first_captured: Option<DateTime<Utc>>,
    last_captured: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    latest_capture_id: Option<i64>,
    rule_name: Option<String>,
    namespace: Option<String>,
    file_path: Option<String>,
    file_size: Option<i64>,
    tp_explicit: Option<i64>,
    fp_explicit: Option<i64>,
    tp_inherited_single: Option<i64>,
    fp_inherited_single: Option<i64>,
    tp_inherited_multi: Option<i64>,
    fp_inherited_multi: Option<i64>,
    label: Option<String>,
    label_source: Option<String>,
    retired: Option<bool>,
    retired_by: Option<Value>,
    retired_at: Option<DateTime<Utc>>,
    retired_reason: Option<String>,
}

fn missing_column(name: &str) -> ServiceError {
    ServiceError::from(ace_core::DbError::Decode(format!(
        "svs.samples gave no {name}"
    )))
}

impl SampleRow {
    fn into_sample(self) -> Result<Sample, ServiceError> {
        macro_rules! req {
            ($field:ident) => {
                self.$field
                    .ok_or_else(|| missing_column(stringify!($field)))?
            };
        }
        Ok(Sample {
            sha256: req!(sha256),
            rule_uuid: req!(rule_uuid),
            rule_name: req!(rule_name),
            namespace: self.namespace,
            file_path: req!(file_path),
            file_size: self.file_size,
            capture_count: req!(capture_count),
            stored: req!(stored),
            missing: req!(missing),
            missing_data: req!(missing_data),
            unknown_version: req!(unknown_version),
            first_captured: req!(first_captured),
            last_captured: req!(last_captured),
            updated_at: req!(updated_at),
            latest_capture_id: req!(latest_capture_id),
            label: decoded(self.label, Label::parse)?,
            label_source: decoded(self.label_source, Strength::parse)?,
            votes: Votes {
                tp_explicit: self.tp_explicit.unwrap_or_default(),
                fp_explicit: self.fp_explicit.unwrap_or_default(),
                tp_inherited_single: self.tp_inherited_single.unwrap_or_default(),
                fp_inherited_single: self.fp_inherited_single.unwrap_or_default(),
                tp_inherited_multi: self.tp_inherited_multi.unwrap_or_default(),
                fp_inherited_multi: self.fp_inherited_multi.unwrap_or_default(),
            },
            retired: self.retired.unwrap_or(false),
            retired_by: RecordedActor::from_row(self.retired_by)?,
            retired_at: self.retired_at,
            retired_reason: self.retired_reason,
        })
    }
}

/// One sample, read in the caller's transaction.
async fn one_sample(
    tx: &mut ace_core::db::Tx<'_>,
    tp: &[String],
    fp: &[String],
    sha256: &str,
    rule_uuid: &str,
) -> Result<Option<Sample>, ServiceError> {
    let row = sqlx::query_as!(
        SampleRow,
        "SELECT * FROM svs.samples($1, $2, NULL) s WHERE s.sha256 = $3 AND s.rule_uuid = $4",
        tp,
        fp,
        sha256,
        rule_uuid,
    )
    .fetch_optional(tx.conn())
    .await?;
    row.map(SampleRow::into_sample).transpose()
}

/// The contributing detections of a sample's captures, by capture, each with its verdict and stored
/// override, in detection order.
async fn contributing(
    tx: &mut ace_core::db::Tx<'_>,
    tp: &[String],
    fp: &[String],
    sha256: &str,
    rule_uuid: &str,
) -> Result<BTreeMap<i64, Vec<(Uuid, SampleDetection)>>, ServiceError> {
    let rows = sqlx::query!(
        r#"SELECT c.capture_id AS "capture_id!", c.root_id AS "root_id!",
                  c.detection_id AS "detection_id!", c.verdict, c.verdict_source,
                  v.verdict AS "stored?", v.set_by AS "set_by?: Value", v.set_at AS "set_at?"
           FROM svs.contributing_detections($1, $2) c
           LEFT JOIN analysis.detection_verdicts v ON v.detection_id = c.detection_id
           WHERE c.sha256 = $3 AND c.rule_uuid = $4
           ORDER BY c.detection_id, c.capture_id"#,
        tp,
        fp,
        sha256,
        rule_uuid,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut by: BTreeMap<i64, Vec<(Uuid, SampleDetection)>> = BTreeMap::new();
    for row in rows {
        by.entry(row.capture_id).or_default().push((
            row.root_id,
            SampleDetection {
                detection: row.detection_id,
                verdict: decoded(row.verdict, Verdict::parse)?,
                verdict_source: decoded(row.verdict_source, VerdictSource::parse)?,
                override_verdict: decoded(row.stored, Verdict::parse)?,
                override_by: RecordedActor::from_row(row.set_by)?,
                override_set_at: row.set_at,
            },
        ));
    }
    Ok(by)
}

async fn sample_exists(
    tx: &mut ace_core::db::Tx<'_>,
    sha256: &str,
    rule_uuid: &str,
) -> Result<bool, ServiceError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM svs.yara_captures WHERE sha256 = $1 AND rule_uuid = $2)
           AS "exists!""#,
        sha256,
        rule_uuid,
    )
    .fetch_one(tx.conn())
    .await?)
}

fn no_sample(sha256: &str, rule_uuid: &str) -> ServiceError {
    ServiceError::NotFound(format!("no sample {sha256} for rule {rule_uuid}"))
}

struct RetirementRow {
    sha256: String,
    rule_uuid: String,
    reason: String,
    retired_by: Value,
    retired_at: DateTime<Utc>,
    unretired_by: Option<Value>,
    unretired_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl RetirementRow {
    fn into_retirement(self) -> Result<Retirement, ServiceError> {
        Ok(Retirement {
            retired: self.unretired_at.is_none(),
            sha256: self.sha256,
            rule_uuid: self.rule_uuid,
            reason: self.reason,
            retired_by: RecordedActor::from_row(Some(self.retired_by))?,
            retired_at: self.retired_at,
            unretired_by: RecordedActor::from_row(self.unretired_by)?,
            unretired_at: self.unretired_at,
            updated_at: self.updated_at,
        })
    }
}

async fn retirement(
    tx: &mut ace_core::db::Tx<'_>,
    sha256: &str,
    rule_uuid: &str,
) -> Result<Option<RetirementRow>, ServiceError> {
    Ok(sqlx::query_as!(
        RetirementRow,
        r#"SELECT sha256, rule_uuid, reason, retired_by AS "retired_by!: Value", retired_at,
                  unretired_by AS "unretired_by?: Value", unretired_at, updated_at
           FROM svs.sample_retirements WHERE sha256 = $1 AND rule_uuid = $2 FOR UPDATE"#,
        sha256,
        rule_uuid,
    )
    .fetch_optional(tx.conn())
    .await?)
}

struct DeletionRow {
    id: i64,
    sha256: String,
    rule_uuids: Vec<String>,
    capture_count: i32,
    deleted_by: Value,
    reason: String,
    deleted_at: DateTime<Utc>,
    purged_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl DeletionRow {
    fn into_deletion(self) -> Result<SampleDeletion, ServiceError> {
        Ok(SampleDeletion {
            id: self.id,
            sha256: self.sha256,
            rule_uuids: self.rule_uuids,
            capture_count: self.capture_count,
            deleted_by: RecordedActor::from_row(Some(self.deleted_by))?,
            reason: self.reason,
            deleted_at: self.deleted_at,
            purged_at: self.purged_at,
            updated_at: self.updated_at,
        })
    }
}

impl Service {
    fn classes_lists(&self) -> (Vec<String>, Vec<String>) {
        self.disposition_classes().lists()
    }

    /// A page of samples, one per (sha256, rule uuid), in `query`'s order, of up to `limit` (100 when None,
    /// at most `MAX_SAMPLES_PAGE`), after where `cursor` left off: ace3's `list_samples`. A cursor belongs to
    /// its order: one from another sort or direction is `InvalidRequest`. It needs `signature:read`.
    pub async fn svs_samples(
        &self,
        actor: &Actor,
        query: &SampleQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SamplePage, ServiceError> {
        let limit = page_limit(limit, MAX_SAMPLES_PAGE)?;
        let cursor = cursor.map(Cursor::decode).transpose()?;
        if let Some(cursor) = &cursor
            && (cursor.sort != query.sort || cursor.descending != query.descending)
        {
            return Err(ServiceError::InvalidRequest(
                "the cursor belongs to another order: pass the sort and direction of the first page"
                    .to_owned(),
            ));
        }
        let p = &params(query)?;
        let (tp, fp) = &self.classes_lists();
        let cursor = &cursor;
        let (samples, through) = self
            .gate
            .read(actor, "svs_samples", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let through = match cursor {
                        Some(cursor) => cursor.through,
                        None => sqlx::query_scalar!("SELECT max(id) FROM svs.yara_captures")
                            .fetch_one(tx.conn())
                            .await?
                            .unwrap_or(0),
                    };
                    let rows = page(tx, tp, fp, through, query, cursor.as_ref(), p, limit + 1)
                        .await
                        .map_err(timed_out)?;
                    let samples = rows
                        .into_iter()
                        .map(SampleRow::into_sample)
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((samples, through))
                })
            })
            .await?;
        let mut samples = samples;
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let more = samples.len() > limit;
        samples.truncate(limit);
        let next = if more {
            samples.last().map(|last| {
                Cursor {
                    sort: query.sort,
                    descending: query.descending,
                    through,
                    key: sort_key(last, query.sort),
                    sha256: last.sha256.clone(),
                    rule_uuid: last.rule_uuid.clone(),
                }
                .encode()
            })
        } else {
            None
        };
        Ok(SamplePage { samples, next })
    }

    /// How many samples `query`'s filters match, counted up to one past `max`, for an export that refuses
    /// a list past its bound. It needs `signature:read`.
    pub async fn svs_sample_count(
        &self,
        actor: &Actor,
        query: &SampleQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let p = &params(query)?;
        let (tp, fp) = &self.classes_lists();
        self.gate
            .read(actor, "svs_sample_count", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = page(tx, tp, fp, i64::MAX, query, None, p, max.saturating_add(1))
                        .await
                        .map_err(timed_out)?;
                    Ok(i64::try_from(rows.len()).unwrap_or(i64::MAX))
                })
            })
            .await
    }

    /// One sample with every capture, newest first, and each capture's contributing detections with their
    /// verdicts: ace3's `get_sample_detail`. A pair with no capture is `NotFound`. It needs
    /// `signature:read`.
    pub async fn svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
    ) -> Result<SampleDetail, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        let (tp, fp) = &self.classes_lists();
        let (sample, captures, dispositions) = self
            .gate
            .read(actor, "svs_sample", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let sample = one_sample(tx, tp, fp, sha256, rule_uuid)
                        .await?
                        .ok_or_else(|| no_sample(sha256, rule_uuid))?;
                    let mut detections = contributing(tx, tp, fp, sha256, rule_uuid).await?;
                    let rows = sqlx::query!(
                        r#"SELECT id, root_id, observable_id, rule_name, namespace, signature_version,
                                  rule_content_hash, file_path, file_size, yara_meta_tags, state,
                                  missing_reason, record IS NOT NULL AS "has_record!", match_summary,
                                  yara_version, created_at, stored_at, updated_at
                           FROM svs.yara_captures WHERE sha256 = $1 AND rule_uuid = $2
                           ORDER BY id DESC"#,
                        sha256,
                        rule_uuid,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut captures = Vec::with_capacity(rows.len());
                    let mut alerts = Vec::new();
                    for row in rows {
                        let found = detections.remove(&row.id).unwrap_or_default();
                        alerts.extend(found.iter().map(|(alert, _)| *alert));
                        captures.push(SampleCapture {
                            id: row.id,
                            alert: row.root_id,
                            observable: row.observable_id,
                            rule_name: row.rule_name,
                            namespace: row.namespace,
                            signature_version: row.signature_version,
                            rule_content_hash: row.rule_content_hash,
                            file_path: row.file_path,
                            file_size: row.file_size,
                            yara_meta_tags: row.yara_meta_tags,
                            state: CaptureState::parse(&row.state).ok_or_else(|| {
                                missing_column("a capture's state")
                            })?,
                            missing_reason: decoded(row.missing_reason, MissingReason::parse)?,
                            has_record: row.has_record,
                            match_summary: row.match_summary,
                            yara_version: row.yara_version,
                            created_at: row.created_at,
                            stored_at: row.stored_at,
                            updated_at: row.updated_at,
                            detections: found.into_iter().map(|(_, d)| d).collect(),
                        });
                    }
                    alerts.sort_unstable();
                    alerts.dedup();
                    let dispositions = sqlx::query!(
                        "SELECT id, disposition FROM analysis.roots WHERE id = ANY ($1)",
                        &alerts,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| (row.id, row.disposition))
                    .collect::<BTreeMap<Uuid, Option<String>>>();
                    Ok((sample, captures, dispositions))
                })
            })
            .await?;
        let relabel_refusal = self.relabel_refusal(actor, &captures, &dispositions);
        Ok(SampleDetail {
            sample,
            captures,
            relabel_refusal,
        })
    }

    /// ace3's `relabel_refusal`: why no contributing detection would take an analyst's verdict, or None.
    fn relabel_refusal(
        &self,
        actor: &Actor,
        captures: &[SampleCapture],
        dispositions: &BTreeMap<Uuid, Option<String>>,
    ) -> Option<String> {
        let alerts: Vec<Uuid> = captures
            .iter()
            .filter(|capture| !capture.detections.is_empty())
            .map(|capture| capture.alert)
            .collect();
        if alerts.is_empty() {
            return Some(NO_DETECTION_LEFT.to_owned());
        }
        let mut reasons = std::collections::BTreeSet::new();
        for alert in alerts {
            let disposition = dispositions.get(&alert).cloned().flatten();
            // one that takes the verdict is enough for a relabel to write
            reasons.insert(self.verdict_refusal(actor, disposition.as_deref())?);
        }
        Some(format!(
            "no contributing detection of the sample can take the verdict: {}",
            reasons.into_iter().collect::<Vec<_>>().join("; ")
        ))
    }

    /// How many captures of each rule lack something, per reason, with the rule's latest name; the rules
    /// with the most first: ace3's `missing_by_rule`. It needs `signature:read`.
    pub async fn svs_missing(&self, actor: &Actor) -> Result<Vec<MissingCount>, ServiceError> {
        self.gate
            .read(actor, "svs_missing", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        r#"SELECT g.rule_uuid AS "rule_uuid!", l.rule_name AS "rule_name!",
                                  g.missing_reason AS "reason!", g.count AS "count!"
                           FROM (SELECT rule_uuid, missing_reason, count(*) AS count,
                                        max(id) AS latest
                                 FROM svs.yara_captures WHERE missing_reason IS NOT NULL
                                 GROUP BY rule_uuid, missing_reason) g
                           JOIN svs.yara_captures l ON l.id = g.latest
                           ORDER BY g.count DESC, g.rule_uuid, g.missing_reason"#,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    rows.into_iter()
                        .map(|row| {
                            Ok(MissingCount {
                                rule_uuid: row.rule_uuid,
                                rule_name: row.rule_name,
                                reason: MissingReason::parse(&row.reason)
                                    .ok_or_else(|| missing_column("a missing reason"))?,
                                count: row.count,
                            })
                        })
                        .collect()
                })
            })
            .await
    }

    /// A capture's match record: the alert's YARA scan result for the rule, as its result has it. A capture
    /// with no record, or no such capture, is `NotFound`. It needs `signature:read`.
    pub async fn svs_capture_record(&self, actor: &Actor, id: i64) -> Result<Value, ServiceError> {
        self.gate
            .read(actor, "svs_capture_record", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    sqlx::query_scalar!("SELECT record FROM svs.yara_captures WHERE id = $1", id)
                        .fetch_optional(tx.conn())
                        .await?
                        .flatten()
                        .ok_or_else(|| {
                            ServiceError::NotFound(format!("no match record kept for capture {id}"))
                        })
                })
            })
            .await
    }

    /// The deletions, oldest change first, after the keyset `after` (a row's `updated_at` and id), changed
    /// at or after `changed_since` when it's given, of up to `limit` (100 when None): ace3's
    /// `deletions_page`. It needs `signature:read`.
    pub async fn svs_sample_deletions(
        &self,
        actor: &Actor,
        changed_since: Option<DateTime<Utc>>,
        after: Option<(DateTime<Utc>, i64)>,
        limit: Option<u32>,
    ) -> Result<Vec<SampleDeletion>, ServiceError> {
        // one past a page, so a caller can tell there's a next
        let limit = page_limit(limit, MAX_DELETIONS_PAGE + 1)?;
        let (after_at, after_id) = (after.map(|a| a.0), after.map(|a| a.1));
        self.gate
            .read(actor, "svs_sample_deletions", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query_as!(
                        DeletionRow,
                        r#"SELECT id, sha256, rule_uuids, capture_count,
                                  deleted_by AS "deleted_by!: Value", reason, deleted_at, purged_at,
                                  updated_at
                           FROM svs.sample_deletions
                           WHERE ($1::timestamptz IS NULL OR updated_at >= $1)
                             AND ($2::timestamptz IS NULL OR (updated_at, id) > ($2, $3))
                           ORDER BY updated_at, id LIMIT $4"#,
                        changed_since,
                        after_at,
                        after_id,
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    rows.into_iter().map(DeletionRow::into_deletion).collect()
                })
            })
            .await
    }

    // ---- relabel, reset, confirm ----

    /// Stores the explicit verdict on every contributing detection of the sample that can take one, in one
    /// transaction: ace3's `relabel`. It needs `alert:write` and `signature:read`. No sample is `NotFound`;
    /// none that can take it, or a sample whose alerts are gone, is `Conflict` saying why.
    pub async fn relabel_svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
        verdict: Verdict,
    ) -> Result<LabelChange, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        let (tp, fp) = &self.classes_lists();
        self.gate
            .write(actor, "relabel_svs_sample", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    self.label_body(
                        tx,
                        actor,
                        sha256,
                        rule_uuid,
                        LabelAction::Relabel(verdict),
                        tp,
                        fp,
                    )
                    .await
                })
            })
            .await
    }

    /// Clears the explicit verdicts on the sample's contributing detections, so its label comes from its
    /// alerts' dispositions again: ace3's `reset_label`. Only explicit detections are its targets, so one on
    /// an FP alert, whose override is masked, isn't listed as skipped. Nothing to reset isn't an error.
    pub async fn reset_svs_sample_label(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
    ) -> Result<LabelChange, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        let (tp, fp) = &self.classes_lists();
        self.gate
            .write(actor, "reset_svs_sample_label", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    self.label_body(tx, actor, sha256, rule_uuid, LabelAction::Reset, tp, fp)
                        .await
                })
            })
            .await
    }

    /// Confirms the sample's unconfirmed (inherited_multi) TP detections with an explicit TP on each, which
    /// upgrades their source and keeps the verdict: ace3's `confirm`. Nothing to confirm isn't an error.
    pub async fn confirm_svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
    ) -> Result<LabelChange, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        let (tp, fp) = &self.classes_lists();
        self.gate
            .write(actor, "confirm_svs_sample", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    self.label_body(tx, actor, sha256, rule_uuid, LabelAction::Confirm, tp, fp)
                        .await
                })
            })
            .await
    }

    /// The body of relabel, reset and confirm, in `Gate::write`'s transaction, which checked `alert:write`.
    #[allow(clippy::too_many_arguments)]
    async fn label_body(
        &self,
        tx: &mut ace_core::db::Tx<'_>,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
        what: LabelAction,
        tp: &[String],
        fp: &[String],
    ) -> Result<Audited<LabelChange>, ServiceError> {
        let action = what.name();
        if !holds(tx.conn(), actor, &SIGNATURE_READ).await? {
            tracing::warn!(%actor, permission = %SIGNATURE_READ, action, "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: SIGNATURE_READ,
            });
        }
        if !sample_exists(tx, sha256, rule_uuid).await? {
            return Err(no_sample(sha256, rule_uuid));
        }
        let detections = contributing(tx, tp, fp, sha256, rule_uuid).await?;
        let only = what.source();
        let mut targets: Vec<(Uuid, i64)> = detections
            .values()
            .flatten()
            .filter(|(_, d)| only.is_none_or(|only| d.verdict_source == Some(only)))
            .map(|(alert, d)| (*alert, d.detection))
            .collect();
        targets.sort_unstable();
        targets.dedup();
        if let LabelAction::Relabel(_) = what
            && targets.is_empty()
        {
            return Err(ServiceError::Conflict(NO_DETECTION_LEFT.to_owned()));
        }
        let rules = BatchRules {
            only_source: match what {
                LabelAction::Confirm => Some(VerdictSource::InheritedMulti),
                _ => None,
            },
            refuse: Default::default(),
        };
        let written = self
            .write_verdicts(tx, actor, &targets, what.verdict(), &rules)
            .await?;
        let batch = &written.batch;
        if batch.changed == 0 && batch.unchanged == 0 {
            // nothing could be written, and something other than a race says why
            let refusals: std::collections::BTreeSet<&str> = batch
                .skipped
                .iter()
                .filter(|s| s.cause == SkipCause::Alert)
                .map(|s| s.reason.as_str())
                .collect();
            if !refusals.is_empty() {
                return Err(ServiceError::Conflict(format!(
                    "no contributing detection of the sample can take the verdict: {}",
                    refusals.into_iter().collect::<Vec<_>>().join("; ")
                )));
            }
        }
        let sample = one_sample(tx, tp, fp, sha256, rule_uuid).await?;
        let change = LabelChange {
            changed: batch.changed,
            unchanged: batch.unchanged,
            skipped: batch
                .skipped
                .iter()
                .map(|s| SkippedSampleDetection {
                    alert: s.alert,
                    detection: s.detection,
                    reason: s.reason.clone(),
                })
                .collect(),
            label: sample.as_ref().and_then(|s| s.label),
            label_source: sample.as_ref().and_then(|s| s.label_source),
        };
        if batch.changed == 0 {
            return Ok(Audited::unchanged(change));
        }
        let record = Change::updated(
            Target::svs_sample(sha256, rule_uuid),
            &crate::detection_verdicts::VerdictStates {
                verdicts: written.before,
            },
            &crate::detection_verdicts::VerdictStates {
                verdicts: written.after,
            },
        )?
        .details(&LabelRecord {
            action: what.name(),
            verdict: what.verdict().map(Verdict::as_str),
            changed: change.changed,
            unchanged: change.unchanged,
            skipped: change.skipped.len(),
            detections: targets.iter().map(|(_, id)| *id).collect(),
        })?;
        Ok(Audited::changed(change, record))
    }

    // ---- retire ----

    /// Retires the sample for its rule: it's no longer expected to match, and YARA validation only counts
    /// it. Retiring a retired sample changes nothing and keeps its first reason. No sample is `NotFound`,
    /// and an empty reason `InvalidRequest`. It needs `svs:admin`.
    pub async fn retire_svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
        reason: &str,
    ) -> Result<Retirement, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        let reason = &check_reason(reason)?;
        self.gate
            .write(actor, "retire_svs_sample", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    if !sample_exists(tx, sha256, rule_uuid).await? {
                        return Err(no_sample(sha256, rule_uuid));
                    }
                    let before = retirement(tx, sha256, rule_uuid).await?;
                    if let Some(row) = before
                        && row.unretired_at.is_none()
                    {
                        return Ok(Audited::unchanged(row.into_retirement()?));
                    }
                    let row = sqlx::query_as!(
                        RetirementRow,
                        r#"INSERT INTO svs.sample_retirements (sha256, rule_uuid, reason, retired_by)
                           VALUES ($1, $2, $3, $4::jsonb)
                           ON CONFLICT (sha256, rule_uuid) DO UPDATE
                           SET reason = excluded.reason, retired_by = excluded.retired_by,
                               retired_at = now(), unretired_by = NULL, unretired_at = NULL
                           RETURNING sha256, rule_uuid, reason, retired_by AS "retired_by!: Value",
                                     retired_at, unretired_by AS "unretired_by?: Value",
                                     unretired_at, updated_at"#,
                        sha256,
                        rule_uuid,
                        reason,
                        Json(actor) as _,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let change = Change::added(
                        Target::svs_sample(sha256, rule_uuid),
                        &RetirementRecord {
                            retired: true,
                            reason,
                        },
                    )?;
                    Ok(Audited::changed(row.into_retirement()?, change))
                })
            })
            .await
    }

    /// Unretires the sample: it's expected to match its rule again. One that isn't retired is `NotFound`,
    /// as ace3's route answers its `NotRetired`. It needs `svs:admin`.
    pub async fn unretire_svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
    ) -> Result<Retirement, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        self.gate
            .write(actor, "unretire_svs_sample", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    let before = retirement(tx, sha256, rule_uuid).await?;
                    let Some(before) = before.filter(|row| row.unretired_at.is_none()) else {
                        return Err(ServiceError::NotFound(format!(
                            "sample {sha256} isn't retired for rule {rule_uuid}"
                        )));
                    };
                    let row = sqlx::query_as!(
                        RetirementRow,
                        r#"UPDATE svs.sample_retirements
                           SET unretired_by = $3::jsonb, unretired_at = now()
                           WHERE sha256 = $1 AND rule_uuid = $2
                           RETURNING sha256, rule_uuid, reason, retired_by AS "retired_by!: Value",
                                     retired_at, unretired_by AS "unretired_by?: Value",
                                     unretired_at, updated_at"#,
                        sha256,
                        rule_uuid,
                        Json(actor) as _,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let change = Change::updated(
                        Target::svs_sample(sha256, rule_uuid),
                        &RetirementRecord {
                            retired: true,
                            reason: &before.reason,
                        },
                        &RetirementRecord {
                            retired: false,
                            reason: &before.reason,
                        },
                    )?;
                    Ok(Audited::changed(row.into_retirement()?, change))
                })
            })
            .await
    }

    /// The (sha256, rule uuid) pairs retired now: ace3's `retired_pairs`, which YARA validation reads. It
    /// needs `signature:read`.
    pub async fn svs_retired_pairs(
        &self,
        actor: &Actor,
    ) -> Result<Vec<(String, String)>, ServiceError> {
        self.gate
            .read(actor, "svs_retired_pairs", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        "SELECT sha256, rule_uuid FROM svs.sample_retirements
                         WHERE unretired_at IS NULL ORDER BY sha256, rule_uuid"
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok(rows.into_iter().map(|r| (r.sha256, r.rule_uuid)).collect())
                })
            })
            .await
    }

    // ---- delete ----

    /// Deletes the file from SVS: every capture of the sha256, for every rule, and its retirements, with the
    /// deletion's row and its audit row in one transaction under the sample's lock, then the file's bytes,
    /// purged from the `svs_samples` pool in `bucket` whatever holds them: ace3's `delete_sample`. Deleting a
    /// deleted file retries a purge that didn't finish and returns the row, its first reason kept. A sha256
    /// with no capture and no deletion is `NotFound`, an empty reason `InvalidRequest`. It needs `svs:admin`.
    pub async fn delete_svs_sample(
        &self,
        actor: &Actor,
        bucket: &Bucket,
        sha256: &str,
        reason: &str,
    ) -> Result<SampleDeletion, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        let reason = &check_reason(reason)?;
        let parsed: Sha256 = sha256
            .parse()
            .map_err(|_| ServiceError::InvalidRequest(format!("{sha256:?} isn't a sha256")))?;
        let parsed = &parsed;
        let (deletion, claimed) = self
            .gate
            .write(actor, "delete_svs_sample", &SVS_ADMIN, &|tx| {
                Box::pin(async move {
                    lock_sample(tx, sha256).await?;
                    let existing = sqlx::query_as!(
                        DeletionRow,
                        r#"SELECT id, sha256, rule_uuids, capture_count,
                                  deleted_by AS "deleted_by!: Value", reason, deleted_at, purged_at,
                                  updated_at
                           FROM svs.sample_deletions WHERE sha256 = $1"#,
                        sha256,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let captures = sqlx::query!(
                        "DELETE FROM svs.yara_captures WHERE sha256 = $1 RETURNING id, rule_uuid",
                        sha256,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    if existing.is_none() && captures.is_empty() {
                        return Err(ServiceError::NotFound(format!("no sample {sha256}")));
                    }
                    sqlx::query!(
                        "DELETE FROM svs.sample_retirements WHERE sha256 = $1",
                        sha256
                    )
                    .execute(tx.conn())
                    .await?;
                    for capture in &captures {
                        ace_core::bucket::release_in(
                            tx,
                            SVS_SAMPLES,
                            parsed,
                            &capture_hold(capture.id),
                        )
                        .await?;
                    }
                    // the bytes go whatever else holds them, and nothing can hold them again
                    let claimed = claim_purge_in(tx, SVS_SAMPLES, parsed).await?;
                    if let Some(existing) = existing {
                        // a retry: the row and its reason are the first deletion's
                        return Ok(Audited::unchanged((existing.into_deletion()?, claimed)));
                    }
                    let mut rule_uuids: Vec<String> =
                        captures.iter().map(|c| c.rule_uuid.clone()).collect();
                    rule_uuids.sort_unstable();
                    rule_uuids.dedup();
                    let count = i32::try_from(captures.len()).unwrap_or(i32::MAX);
                    let row = sqlx::query_as!(
                        DeletionRow,
                        r#"INSERT INTO svs.sample_deletions
                               (sha256, deleted_by, reason, rule_uuids, capture_count, purged_at)
                           VALUES ($1, $2::jsonb, $3, $4, $5, CASE WHEN $6::boolean THEN NULL ELSE now() END)
                           RETURNING id, sha256, rule_uuids, capture_count,
                                     deleted_by AS "deleted_by!: Value", reason, deleted_at,
                                     purged_at, updated_at"#,
                        sha256,
                        Json(actor) as _,
                        reason,
                        &rule_uuids,
                        count,
                        claimed,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let mut ids: Vec<i64> = captures.iter().map(|c| c.id).collect();
                    ids.sort_unstable();
                    let change = Change::removed(
                        Target::svs_sample_file(sha256),
                        &DeletionRecord {
                            reason,
                            rule_uuids: &rule_uuids,
                            capture_count: i64::from(count),
                            captures: &ids,
                        },
                    )?;
                    Ok(Audited::changed((row.into_deletion()?, claimed), change))
                })
            })
            .await?;
        if !claimed || deletion.purged_at.is_some() {
            return Ok(deletion);
        }
        // the bytes, once the deletion committed: a failure leaves the object `deleting` and `purged_at`
        // NULL, and deleting the sample again retries
        match bucket.finish_purge(SVS_SAMPLES, parsed).await {
            Ok(()) => {
                let row = sqlx::query_as!(
                    DeletionRow,
                    r#"UPDATE svs.sample_deletions SET purged_at = COALESCE(purged_at, now())
                       WHERE sha256 = $1
                       RETURNING id, sha256, rule_uuids, capture_count,
                                 deleted_by AS "deleted_by!: Value", reason, deleted_at, purged_at,
                                 updated_at"#,
                    sha256,
                )
                .fetch_one(self.gate.db().pool())
                .await?;
                tracing::info!(%actor, sha256, "AUDIT: purged a deleted svs sample's file");
                row.into_deletion()
            }
            Err(e) => {
                tracing::error!(
                    sha256,
                    "unable to purge the file of deleted svs sample {sha256}: {e}"
                );
                Ok(deletion)
            }
        }
    }

    // ---- downloads ----

    /// Lets an actor download one sample's file and the match records of its captures, and records that
    /// they did, as ace3 logs it. A sample no capture of which holds the file is `NotFound`. It needs
    /// `signature:download`.
    pub async fn download_svs_sample(
        &self,
        actor: &Actor,
        sha256: &str,
        rule_uuid: &str,
    ) -> Result<SampleDownload, ServiceError> {
        let sha256 = &check_sha256(sha256)?;
        check_rule_uuid(rule_uuid)?;
        self.gate
            .write(actor, "download_svs_sample", &SIGNATURE_DOWNLOAD, &|tx| {
                Box::pin(async move {
                    if !sample_exists(tx, sha256, rule_uuid).await? {
                        return Err(no_sample(sha256, rule_uuid));
                    }
                    let pairs = vec![(sha256.clone(), rule_uuid.to_owned())];
                    let download = download_of(tx, &pairs).await?;
                    if download.files.is_empty() {
                        return Err(ServiceError::NotFound(
                            "no capture of this sample holds its file".to_owned(),
                        ));
                    }
                    let change = Change::read(
                        Target::svs_sample(sha256, rule_uuid),
                        &DownloadRecord {
                            filters: None,
                            rule_uuid: Some(rule_uuid),
                            sha256s: vec![sha256.as_str()],
                        },
                    )?;
                    Ok(Audited::changed(download, change))
                })
            })
            .await
    }

    /// Lets an actor download the files of every sample `query`'s filters match that holds its file, with
    /// their match records, and records that they did: ace3's bulk download. At most
    /// `MAX_SAMPLE_DOWNLOAD_FILES` files and `MAX_SAMPLE_DOWNLOAD_BYTES` bytes; past either it's `TooLarge`,
    /// and none at all is `NotFound`. It needs `signature:download`.
    pub async fn download_svs_samples(
        &self,
        actor: &Actor,
        query: &SampleQuery,
    ) -> Result<SampleDownload, ServiceError> {
        let mut by_sha = SampleQuery {
            sort: SampleSort::Sha256,
            descending: false,
            ..query.clone()
        };
        by_sha.changed_since = None;
        let p = &params(&by_sha)?;
        let (tp, fp) = &self.classes_lists();
        let by_sha = &by_sha;
        let filters = &query.filters;
        self.gate
            .write(actor, "download_svs_samples", &SIGNATURE_DOWNLOAD, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = page(tx, tp, fp, i64::MAX, by_sha, None, p, i64::MAX)
                        .await
                        .map_err(timed_out)?;
                    let pairs: Vec<(String, String)> = rows
                        .into_iter()
                        .filter(|row| row.stored.unwrap_or(0) > 0)
                        .filter_map(|row| Some((row.sha256?, row.rule_uuid?)))
                        .collect();
                    let mut files: Vec<&str> = pairs.iter().map(|(s, _)| s.as_str()).collect();
                    files.dedup();
                    if files.is_empty() {
                        return Err(ServiceError::NotFound(
                            "no stored samples to download".to_owned(),
                        ));
                    }
                    if files.len() > MAX_SAMPLE_DOWNLOAD_FILES {
                        return Err(ServiceError::TooLarge(format!(
                            "more than {MAX_SAMPLE_DOWNLOAD_FILES} files; narrow the download with filters"
                        )));
                    }
                    let download = download_of(tx, &pairs).await?;
                    let bytes: i64 = download.files.iter().filter_map(|f| f.file_size).sum();
                    if bytes > MAX_SAMPLE_DOWNLOAD_BYTES {
                        return Err(ServiceError::TooLarge(format!(
                            "{bytes} bytes is more than {MAX_SAMPLE_DOWNLOAD_BYTES}; narrow the download with filters"
                        )));
                    }
                    let change = Change::read(
                        Target::svs_samples(),
                        &DownloadRecord {
                            filters: Some(filters),
                            rule_uuid: None,
                            sha256s: download.files.iter().map(|f| f.sha256.as_str()).collect(),
                        },
                    )?;
                    Ok(Audited::changed(download, change))
                })
            })
            .await
    }
}

#[derive(Debug, Clone, Copy)]
enum LabelAction {
    Relabel(Verdict),
    Reset,
    Confirm,
}

impl LabelAction {
    fn name(self) -> &'static str {
        match self {
            LabelAction::Relabel(_) => "relabel",
            LabelAction::Reset => "reset",
            LabelAction::Confirm => "confirm",
        }
    }

    /// The verdict it stores; None clears.
    fn verdict(self) -> Option<Verdict> {
        match self {
            LabelAction::Relabel(verdict) => Some(verdict),
            LabelAction::Reset => None,
            LabelAction::Confirm => Some(Verdict::Tp),
        }
    }

    /// The source of the detections it targets: every one for a relabel.
    fn source(self) -> Option<VerdictSource> {
        match self {
            LabelAction::Relabel(_) => None,
            LabelAction::Reset => Some(VerdictSource::Explicit),
            LabelAction::Confirm => Some(VerdictSource::InheritedMulti),
        }
    }
}

/// A sample's sort key as text that sorts as the value does, as `page`'s SQL makes it: times as UTC with
/// microseconds, counts padded, and no label as the empty string (ace3's `sort_value`).
fn sort_key(sample: &Sample, sort: SampleSort) -> String {
    let time = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
    match sort {
        SampleSort::LastCaptured => time(sample.last_captured),
        SampleSort::FirstCaptured => time(sample.first_captured),
        SampleSort::CaptureCount => format!("{:020}", sample.capture_count),
        SampleSort::Rule => sample.rule_name.clone(),
        SampleSort::Label => sample.label.map(Label::as_str).unwrap_or("").to_owned(),
        SampleSort::Sha256 => sample.sha256.clone(),
    }
}

/// One page of `svs.samples` over the captures up to `through`, with the screen's filters, in `query`'s
/// order after `cursor`.
#[allow(clippy::too_many_arguments)]
async fn page(
    tx: &mut ace_core::db::Tx<'_>,
    tp: &[String],
    fp: &[String],
    through: i64,
    query: &SampleQuery,
    cursor: Option<&Cursor>,
    p: &Params,
    limit: i64,
) -> Result<Vec<SampleRow>, sqlx::Error> {
    let [t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11] = &p.texts;
    let [a0, a1] = &p.alerts;
    let [w0, w1, w2, w3] = &p.windows;
    let [f0, f1, f2, f3, f4, f5, f6, f7] = &p.flags;
    let (after_key, after_sha, after_rule) = match cursor {
        Some(c) => (Some(&c.key), Some(&c.sha256), Some(&c.rule_uuid)),
        None => (None, None, None),
    };
    // the static SQL, each filter a fixed condition with its values bound
    sqlx::query_as!(
        SampleRow,
        r#"WITH keyed AS (
             SELECT s.*,
                    CASE $4::text
                      WHEN 'last_captured' THEN to_char(s.last_captured AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
                      WHEN 'first_captured' THEN to_char(s.first_captured AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
                      WHEN 'capture_count' THEN lpad(s.capture_count::text, 20, '0')
                      WHEN 'rule' THEN s.rule_name
                      WHEN 'label' THEN coalesce(s.label, '')
                      ELSE s.sha256 END COLLATE "C" AS sort_key
             FROM svs.samples($1, $2, $3) s
             WHERE ($9::text[] IS NULL OR s.rule_uuid = ANY ($9))
               AND ($10::text[] IS NULL OR NOT s.rule_uuid = ANY ($10))
               AND ($11::text[] IS NULL OR s.sha256 = ANY ($11))
               AND ($12::text[] IS NULL OR NOT s.sha256 = ANY ($12))
               -- File Name, Rule and Alert: any of its captures
               AND ($13::text[] IS NULL OR EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.file_path ILIKE ANY ($13)))
               AND ($14::text[] IS NULL OR NOT EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.file_path ILIKE ANY ($14)))
               AND ($15::text[] IS NULL OR EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.rule_name ILIKE ANY ($15)))
               AND ($16::text[] IS NULL OR NOT EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.rule_name ILIKE ANY ($16)))
               AND ($21::uuid[] IS NULL OR EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.root_id = ANY ($21)))
               AND ($22::uuid[] IS NULL OR NOT EXISTS (
                     SELECT FROM svs.yara_captures c
                     WHERE c.sha256 = s.sha256 AND c.rule_uuid = s.rule_uuid AND c.id <= $3
                       AND c.root_id = ANY ($22)))
               -- Label, with none for no label
               AND ($17::text[] IS NULL OR s.label = ANY ($17) OR ($23::boolean AND s.label IS NULL))
               AND ($18::text[] IS NULL
                    OR NOT COALESCE(s.label = ANY ($18) OR ($24::boolean AND s.label IS NULL), false))
               AND ($19::text[] IS NULL OR s.label_source = ANY ($19))
               AND ($20::text[] IS NULL OR NOT COALESCE(s.label_source = ANY ($20), false))
               -- Last Captured
               AND ($25::timestamptz[] IS NULL OR EXISTS (
                     SELECT FROM unnest($25::timestamptz[], $26::timestamptz[]) w(b, e)
                     WHERE s.last_captured BETWEEN w.b AND w.e))
               AND ($27::timestamptz[] IS NULL OR NOT EXISTS (
                     SELECT FROM unnest($27::timestamptz[], $28::timestamptz[]) w(b, e)
                     WHERE s.last_captured BETWEEN w.b AND w.e))
               -- Stored, Missing Data, Unknown Version and Retired: true, false or both
               AND ($29::text[] IS NULL OR (s.stored > 0)::text = ANY ($29))
               AND ($30::text[] IS NULL OR NOT (s.stored > 0)::text = ANY ($30))
               AND ($31::text[] IS NULL OR (s.missing_data > 0)::text = ANY ($31))
               AND ($32::text[] IS NULL OR NOT (s.missing_data > 0)::text = ANY ($32))
               AND ($33::text[] IS NULL OR (s.unknown_version > 0)::text = ANY ($33))
               AND ($34::text[] IS NULL OR NOT (s.unknown_version > 0)::text = ANY ($34))
               AND ($35::text[] IS NULL OR s.retired::text = ANY ($35))
               AND ($36::text[] IS NULL OR NOT s.retired::text = ANY ($36))
               -- changed since: a capture, a retirement, a contributing alert's disposition or a verdict
               AND ($37::timestamptz IS NULL OR s.updated_at >= $37
                    OR EXISTS (SELECT FROM svs.sample_retirements r
                               WHERE r.sha256 = s.sha256 AND r.rule_uuid = s.rule_uuid
                                 AND r.updated_at >= $37)
                    OR EXISTS (SELECT FROM svs.contributing_detections($1, $2) d
                               JOIN analysis.roots ro ON ro.id = d.root_id
                               WHERE d.sha256 = s.sha256 AND d.rule_uuid = s.rule_uuid
                                 AND (ro.dispositioned_at >= $37
                                      OR EXISTS (SELECT FROM analysis.detection_verdict_history h
                                                 WHERE h.detection_id = d.detection_id
                                                   AND h.changed_at >= $37))))
           )
           SELECT k.sha256, k.rule_uuid, k.capture_count, k.stored, k.missing, k.missing_data,
                  k.unknown_version, k.first_captured, k.last_captured, k.updated_at,
                  k.latest_capture_id, k.rule_name, k.namespace, k.file_path, k.file_size,
                  k.tp_explicit, k.fp_explicit, k.tp_inherited_single, k.fp_inherited_single,
                  k.tp_inherited_multi, k.fp_inherited_multi, k.label, k.label_source, k.retired,
                  k.retired_by, k.retired_at, k.retired_reason
           FROM keyed k
           WHERE $6::text IS NULL
              OR ($5 AND (k.sort_key, k.sha256 COLLATE "C", k.rule_uuid COLLATE "C")
                         < ($6 COLLATE "C", $7 COLLATE "C", $8 COLLATE "C"))
              OR (NOT $5 AND (k.sort_key, k.sha256 COLLATE "C", k.rule_uuid COLLATE "C")
                             > ($6 COLLATE "C", $7 COLLATE "C", $8 COLLATE "C"))
           ORDER BY CASE WHEN $5 THEN k.sort_key END DESC,
                    CASE WHEN NOT $5 THEN k.sort_key END ASC,
                    CASE WHEN $5 THEN k.sha256 COLLATE "C" END DESC,
                    CASE WHEN NOT $5 THEN k.sha256 COLLATE "C" END ASC,
                    CASE WHEN $5 THEN k.rule_uuid COLLATE "C" END DESC,
                    CASE WHEN NOT $5 THEN k.rule_uuid COLLATE "C" END ASC
           LIMIT $38"#,
        tp,
        fp,
        through,
        query.sort.as_str(),
        query.descending,
        after_key,
        after_sha,
        after_rule,
        t0.as_deref(),
        t1.as_deref(),
        t2.as_deref(),
        t3.as_deref(),
        t4.as_deref(),
        t5.as_deref(),
        t6.as_deref(),
        t7.as_deref(),
        t8.as_deref(),
        t9.as_deref(),
        t10.as_deref(),
        t11.as_deref(),
        a0.as_deref(),
        a1.as_deref(),
        p.none[0],
        p.none[1],
        w0.as_deref(),
        w1.as_deref(),
        w2.as_deref(),
        w3.as_deref(),
        f0.as_deref(),
        f1.as_deref(),
        f2.as_deref(),
        f3.as_deref(),
        f4.as_deref(),
        f5.as_deref(),
        f6.as_deref(),
        f7.as_deref(),
        query.changed_since,
        limit,
    )
    .fetch_all(tx.conn())
    .await
}

/// The files of these (sha256, rule uuid) samples that a stored capture holds, each once, with each
/// selected sample's captures and their records.
async fn download_of(
    tx: &mut ace_core::db::Tx<'_>,
    pairs: &[(String, String)],
) -> Result<SampleDownload, ServiceError> {
    let sha256s: Vec<String> = pairs.iter().map(|(s, _)| s.clone()).collect();
    let rules: Vec<String> = pairs.iter().map(|(_, r)| r.clone()).collect();
    let rows = sqlx::query!(
        r#"SELECT c.id, c.root_id, c.sha256, c.rule_uuid, c.rule_name, c.record, c.state,
                  c.file_size
           FROM svs.yara_captures c
           JOIN unnest($1::text[], $2::text[]) p(sha256, rule_uuid)
             ON p.sha256 = c.sha256 AND p.rule_uuid = c.rule_uuid
           ORDER BY c.sha256, c.rule_uuid, c.id"#,
        &sha256s,
        &rules,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut files: Vec<DownloadFile> = Vec::new();
    for row in rows {
        let file = match files.last_mut() {
            Some(file) if file.sha256 == row.sha256 => file,
            _ => {
                files.push(DownloadFile {
                    sha256: row.sha256.clone(),
                    file_size: None,
                    rule_uuids: Vec::new(),
                    captures: Vec::new(),
                });
                files.last_mut().expect("just pushed")
            }
        };
        if row.state == CaptureState::Stored.as_str() && file.file_size.is_none() {
            file.file_size = row.file_size;
        }
        if !file.rule_uuids.contains(&row.rule_uuid) {
            file.rule_uuids.push(row.rule_uuid.clone());
        }
        file.captures.push(DownloadCapture {
            id: row.id,
            alert: row.root_id,
            rule_uuid: row.rule_uuid,
            rule_name: row.rule_name,
            record: row.record,
        });
    }
    // a file no capture stored isn't in the pool
    let stored: Vec<String> = sqlx::query_scalar!(
        "SELECT DISTINCT sha256 FROM svs.yara_captures WHERE sha256 = ANY ($1) AND state = 'stored'",
        &sha256s,
    )
    .fetch_all(tx.conn())
    .await?;
    files.retain(|file| stored.contains(&file.sha256));
    Ok(SampleDownload { files })
}
