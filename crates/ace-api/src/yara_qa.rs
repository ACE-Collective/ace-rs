//! `/api/yara-qa/v1`: the YARA rules in QA mode, what they matched, the files, and purges.

use std::io::{Seek, SeekFrom, Write};

use ace_core::bucket::{ALERT_FILES, BucketError};
use ace_results::Sha256;
use ace_service::{
    QaDownload, QaMatch, QaMatchDetail, QaPurge, QaRuleFilter, QaRuleSummary, QaRuleset, QaSort,
    QaStatus, QaVersion,
};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::{ZIP_PASSWORD, ZipBody};
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// Whether a rule is in QA mode in the current ruleset: `qa`, or `not_qa` for a rule with matches that
/// isn't, because it left QA mode or the repository.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QaStatusBody {
    Qa,
    NotQa,
}

impl From<QaStatus> for QaStatusBody {
    fn from(status: QaStatus) -> Self {
        match status {
            QaStatus::Qa => QaStatusBody::Qa,
            QaStatus::NotQa => QaStatusBody::NotQa,
        }
    }
}

impl From<QaStatusBody> for QaStatus {
    fn from(status: QaStatusBody) -> Self {
        match status {
            QaStatusBody::Qa => QaStatus::Qa,
            QaStatusBody::NotQa => QaStatus::NotQa,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QaSortBody {
    #[default]
    Name,
    LastMatch,
    MatchCount,
}

/// A rule in QA mode now, or one with matches recorded. Its name, uuid, namespace and tags are what the
/// rule's author wrote: show them as text.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaRuleBody {
    /// The rule's `uuid` meta, which its matches are kept under.
    signature_uuid: String,
    name: String,
    status: QaStatusBody,
    /// Its `enabled` meta in the current ruleset; null when it isn't a QA rule there.
    enabled: Option<bool>,
    namespace: Option<String>,
    /// Its file in the current ruleset, relative to the signature directory.
    path: Option<String>,
    tags: Vec<String>,
    /// Every match recorded, across versions.
    match_count: i64,
    /// The files kept now, across versions.
    stored_count: i64,
    /// How many versions of the rule have matched.
    version_count: usize,
    first_match_at: Option<DateTime<Utc>>,
    last_match_at: Option<DateTime<Utc>>,
}

impl From<QaRuleSummary> for QaRuleBody {
    fn from(rule: QaRuleSummary) -> Self {
        QaRuleBody {
            signature_uuid: rule.signature_uuid,
            name: rule.name,
            status: rule.status.into(),
            enabled: rule.enabled,
            namespace: rule.namespace,
            path: rule.path,
            tags: rule.tags,
            match_count: rule.match_count,
            stored_count: rule.stored_count,
            version_count: rule.version_count,
            first_match_at: rule.first_match_at,
            last_match_at: rule.last_match_at,
        }
    }
}

/// The ruleset the QA rules come from: the latest the core built.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaRulesetBody {
    /// The sha256 of its bytes.
    key: String,
    commit: String,
    built_at: DateTime<Utc>,
    /// False for a ruleset built before its QA rules were recorded, until the builder fills them in: a rule
    /// that never matched is missing from the list until then.
    qa_rules_recorded: bool,
}

impl From<QaRuleset> for QaRulesetBody {
    fn from(ruleset: QaRuleset) -> Self {
        QaRulesetBody {
            key: ruleset.key,
            commit: ruleset.commit,
            built_at: ruleset.built_at,
            qa_rules_recorded: ruleset.qa_rules_recorded,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaRulePageBody {
    rules: Vec<QaRuleBody>,
    /// How many rules match the filters, across pages.
    total: usize,
    limit: u32,
    offset: u32,
    /// Null when no ruleset has been built: then only rules with matches are listed.
    ruleset: Option<QaRulesetBody>,
}

/// What was recorded for one version of a rule.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaVersionBody {
    /// The commit of the rule's repository, or `unknown`.
    signature_version: String,
    /// The rule's name and namespace when it last matched under this version.
    rule: String,
    namespace: String,
    match_count: i64,
    stored_count: i64,
    first_match_at: DateTime<Utc>,
    last_match_at: DateTime<Utc>,
}

impl From<QaVersion> for QaVersionBody {
    fn from(version: QaVersion) -> Self {
        QaVersionBody {
            signature_version: version.signature_version,
            rule: version.rule,
            namespace: version.namespace,
            match_count: version.match_count,
            stored_count: version.stored_count,
            first_match_at: version.first_match_at,
            last_match_at: version.last_match_at,
        }
    }
}

/// One rule, with its versions, most recently matched first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaRuleDetailBody {
    rule: QaRuleBody,
    versions: Vec<QaVersionBody>,
    ruleset: Option<QaRulesetBody>,
}

/// One kept file of a rule. Its path is what the alert's sender named it: show it as text.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaMatchBody {
    id: i64,
    signature_uuid: String,
    signature_version: String,
    rule: String,
    namespace: String,
    /// The key of the ruleset the rule came from, when the scan used one the core built.
    ruleset: Option<String>,
    sha256: String,
    /// The file's path in the alert when it last matched.
    file_path: String,
    /// Null when the bucket no longer has the file.
    file_size: Option<i64>,
    /// The root the file was found in when it last matched, which may be gone.
    root: Uuid,
    /// Whether that root is an alert.
    alerted: bool,
    observable_id: i64,
    /// How many times this file matched this version of the rule.
    hit_count: i32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    /// When the file is let go unless it matches again.
    expires_at: DateTime<Utc>,
}

impl From<QaMatch> for QaMatchBody {
    fn from(m: QaMatch) -> Self {
        QaMatchBody {
            id: m.id,
            signature_uuid: m.signature_uuid,
            signature_version: m.signature_version,
            rule: m.rule,
            namespace: m.namespace,
            ruleset: m.ruleset,
            sha256: m.sha256,
            file_path: m.file_path,
            file_size: m.file_size,
            root: m.root,
            alerted: m.alerted,
            observable_id: m.observable_id,
            hit_count: m.hit_count,
            first_seen: m.first_seen,
            last_seen: m.last_seen,
            expires_at: m.expires_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaMatchPageBody {
    matches: Vec<QaMatchBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// How often one of the rule's strings matched the file, and where first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaStringBody {
    identifier: String,
    count: usize,
    first_offset: u64,
}

/// A match's record in short. The meta is the rule's, as its author wrote it: show it as text.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaSummaryBody {
    meta: Value,
    tags: Vec<String>,
    /// The commit of the rule's repository, when it came from one.
    commit: Option<String>,
    strings: Vec<QaStringBody>,
}

/// One kept match, with its record in short; the whole record is at `/record`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaMatchDetailBody {
    #[serde(rename = "match")]
    qa_match: QaMatchBody,
    /// Null when the record isn't one the YARA module writes.
    summary: Option<QaSummaryBody>,
}

impl From<QaMatchDetail> for QaMatchDetailBody {
    fn from(detail: QaMatchDetail) -> Self {
        QaMatchDetailBody {
            qa_match: detail.qa_match.into(),
            summary: detail.summary.map(|summary| QaSummaryBody {
                meta: Value::Object(summary.meta),
                tags: summary.tags,
                commit: summary.commit,
                strings: summary
                    .strings
                    .into_iter()
                    .map(|s| QaStringBody {
                        identifier: s.identifier,
                        count: s.count,
                        first_offset: s.first_offset,
                    })
                    .collect(),
            }),
        }
    }
}

/// What to purge from one rule: every kept file of some versions, or some matches. Exactly one of the two.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct QaPurgeRequest {
    /// Purge every match of these versions, 1 to 1000 of them.
    versions: Option<Vec<String>>,
    /// Purge these matches, 1 to 500 of them; an id of another rule's match is left alone.
    match_ids: Option<Vec<i64>>,
    /// Why, for the audit record: at most 1024 characters.
    reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QaPurgedBody {
    /// The matches removed. A file goes at the bucket's next GC after its grace, once no root or other
    /// match holds it.
    purged: Vec<i64>,
    /// Matches left past the 500 one purge removes: purge again to remove them.
    remaining: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct QaRulesQuery {
    /// A substring of the rule's name, uuid, namespace or file, in any case.
    q: Option<String>,
    /// `qa` or `not_qa`; all when left out.
    #[param(value_type = Option<QaStatusBody>)]
    status: Option<QaStatusBody>,
    /// Only rules that have (true) or haven't (false) matched.
    has_matches: Option<bool>,
    /// `name`, `last_match` or `match_count`; `name` when left out.
    #[param(value_type = Option<QaSortBody>)]
    sort: Option<QaSortBody>,
    #[serde(default)]
    descending: bool,
    /// How many, 1 to 500; 50 when left out.
    limit: Option<u32>,
    /// How many to skip.
    #[serde(default)]
    offset: u32,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct QaMatchesQuery {
    /// Only matches under this version of the rule.
    version: Option<String>,
    /// How many, 1 to 500; 50 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct QaDownloadQuery {
    /// Only matches under this version of the rule.
    version: Option<String>,
    /// Only these matches, as ids separated by commas; each has to be one of this rule's.
    match_ids: Option<String>,
}

fn ruleset(ruleset: Option<QaRuleset>) -> Option<QaRulesetBody> {
    ruleset.map(QaRulesetBody::from)
}

/// The rules in QA mode in the current ruleset, whether or not they matched, and the rules with matches
/// recorded, with their counts.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/rules",
    tag = "yara_qa",
    params(QaRulesQuery),
    responses(
        (status = 200, description = "A page of rules", body = QaRulePageBody),
        (status = 400, description = "A limit out of range, or a filter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn rules(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<QaRulesQuery>, QueryRejection>,
) -> Result<Json<QaRulePageBody>, ApiError> {
    let Query(query) = query?;
    let filter = QaRuleFilter {
        q: query.q,
        status: query.status.map(QaStatus::from),
        has_matches: query.has_matches,
        sort: match query.sort.unwrap_or_default() {
            QaSortBody::Name => QaSort::Name,
            QaSortBody::LastMatch => QaSort::LastMatch,
            QaSortBody::MatchCount => QaSort::MatchCount,
        },
        descending: query.descending,
    };
    let page = web
        .service
        .qa_rules(&actor, &filter, query.limit, query.offset)
        .await?;
    Ok(Json(QaRulePageBody {
        rules: page.rules.into_iter().map(QaRuleBody::from).collect(),
        total: page.total,
        limit: query.limit.unwrap_or(50),
        offset: query.offset,
        ruleset: ruleset(page.ruleset),
    }))
}

/// One rule, with its counts per version.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/rules/{uuid}",
    tag = "yara_qa",
    params(("uuid" = String, Path, description = "The rule's uuid meta")),
    responses(
        (status = 200, description = "The rule", body = QaRuleDetailBody),
        (status = 400, description = "A uuid that isn't UTF-8", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No rule in QA mode and no matches with that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn rule(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    uuid: Result<Path<String>, PathRejection>,
) -> Result<Json<QaRuleDetailBody>, ApiError> {
    let Path(uuid) = uuid?;
    let detail = web.service.qa_rule(&actor, &uuid).await?;
    Ok(Json(QaRuleDetailBody {
        rule: detail.rule.into(),
        versions: detail
            .versions
            .into_iter()
            .map(QaVersionBody::from)
            .collect(),
        ruleset: ruleset(detail.ruleset),
    }))
}

/// A rule's kept files, newest first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/rules/{uuid}/matches",
    tag = "yara_qa",
    params(("uuid" = String, Path, description = "The rule's uuid meta"), QaMatchesQuery),
    responses(
        (status = 200, description = "A page of matches", body = QaMatchPageBody),
        (status = 400, description = "A limit out of range, a cursor that isn't one, or a uuid that isn't UTF-8", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn matches(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    uuid: Result<Path<String>, PathRejection>,
    query: Result<Query<QaMatchesQuery>, QueryRejection>,
) -> Result<Json<QaMatchPageBody>, ApiError> {
    let Path(uuid) = uuid?;
    let Query(query) = query?;
    let page = web
        .service
        .qa_matches(
            &actor,
            &uuid,
            query.version.as_deref(),
            query.limit,
            query.after,
        )
        .await?;
    Ok(Json(QaMatchPageBody {
        matches: page.matches.into_iter().map(QaMatchBody::from).collect(),
        next: page.next,
    }))
}

/// One kept match, with its record in short: the rule's meta and tags, and per string how many times it
/// matched and where first.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/matches/{id}",
    tag = "yara_qa",
    params(("id" = i64, Path, description = "The match's id")),
    responses(
        (status = 200, description = "The match", body = QaMatchDetailBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No kept match with that id", body = ErrorBody),
    )
)]
pub(crate) async fn one_match(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<QaMatchDetailBody>, ApiError> {
    let Path(id) = id?;
    let detail = web.service.qa_match(&actor, id).await?;
    Ok(Json(detail.into()))
}

/// A kept match's whole record as the YARA module wrote it, never cut short, with bytes of the file. It's
/// served to show in a browser tab, and never to be sniffed as anything but JSON.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/matches/{id}/record",
    tag = "yara_qa",
    params(("id" = i64, Path, description = "The match's id")),
    responses(
        (status = 200, description = "The record", body = Value),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No kept match with that id", body = ErrorBody),
    )
)]
pub(crate) async fn record(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = id?;
    let record = web.service.qa_match_record(&actor, id).await?;
    let body = serde_json::to_vec(&record).map_err(ApiError::internal)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"yara-qa-match-{id}.json\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// One kept file and its record as a zip encrypted with AES-256 and the password `infected`, laid out as
/// a rule's download is. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/matches/{id}/download",
    tag = "yara_qa",
    params(("id" = i64, Path, description = "The match's id")),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:download", body = ErrorBody),
        (status = 404, description = "No kept match with that id", body = ErrorBody),
    )
)]
pub(crate) async fn download_match(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = id?;
    let download = web.service.download_qa_match(&actor, id).await?;
    zip_response(&web, format!("yara-qa-match-{id}"), vec![download]).await
}

/// A rule's kept files with their records and a manifest, as one zip encrypted with AES-256 and the
/// password `infected`: every kept file of the rule, of one version, or the matches named. At most 500
/// files and 1 GiB. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/yara-qa/v1/rules/{uuid}/download",
    tag = "yara_qa",
    params(("uuid" = String, Path, description = "The rule's uuid meta"), QaDownloadQuery),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "Match ids that aren't ids", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:download", body = ErrorBody),
        (status = 404, description = "No kept matches, or a match id that isn't one of the rule's", body = ErrorBody),
        (status = 413, description = "More than 500 files or 1 GiB: narrow it by version or match id", body = ErrorBody),
    )
)]
pub(crate) async fn download_rule(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    uuid: Result<Path<String>, PathRejection>,
    query: Result<Query<QaDownloadQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Path(uuid) = uuid?;
    let Query(query) = query?;
    let ids = match query.match_ids.as_deref() {
        None | Some("") => Vec::new(),
        Some(ids) => ids
            .split(',')
            .map(|id| id.trim().parse::<i64>())
            .collect::<Result<_, _>>()
            .map_err(|_| ApiError::bad_request("match_ids is ids separated by commas"))?,
    };
    let downloads = web
        .service
        .download_qa_matches(&actor, &uuid, query.version.as_deref(), &ids)
        .await?;
    // a uuid is meta a rule's author wrote, so it names the archive only when it's plain
    let plain = !uuid.is_empty()
        && uuid.len() <= 64
        && uuid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let label = if plain {
        format!("yara-qa-{uuid}")
    } else {
        "yara-qa-rule".to_owned()
    };
    zip_response(&web, label, downloads).await
}

/// Purges a rule's matches: every match of some versions, or some matches, up to 500 at once. Only each
/// match's own hold on its file goes, so a file that a root or another match still holds stays. A file
/// that matches again later is kept again. The purge is in the audit record, with its reason.
#[utoipa::path(
    post,
    path = "/api/yara-qa/v1/rules/{uuid}/purge",
    tag = "yara_qa",
    params(("uuid" = String, Path, description = "The rule's uuid meta")),
    request_body = QaPurgeRequest,
    responses(
        (status = 200, description = "What the purge removed", body = QaPurgedBody),
        (status = 400, description = "Both versions and match ids or neither, too many, a reason too long, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:qa_purge, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn purge(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    uuid: Result<Path<String>, PathRejection>,
    body: Result<Json<QaPurgeRequest>, JsonRejection>,
) -> Result<Json<QaPurgedBody>, ApiError> {
    let Path(uuid) = uuid?;
    let Json(body) = body?;
    let purged = web
        .service
        .purge_qa_matches(
            &actor,
            &uuid,
            &QaPurge {
                versions: body.versions,
                match_ids: body.match_ids,
                reason: body.reason,
            },
        )
        .await?;
    Ok(Json(QaPurgedBody {
        purged: purged.purged,
        remaining: purged.remaining,
    }))
}

/// A match in a download's manifest, and where its file and record are in the zip.
#[derive(Debug, Serialize)]
struct Included {
    #[serde(flatten)]
    qa_match: QaMatchBody,
    /// Null when the bucket no longer has the file.
    file: Option<String>,
    record: String,
}

/// `manifest.json` in a download.
#[derive(Debug, Serialize)]
struct Manifest {
    matches: Vec<Included>,
}

/// The zip of `downloads`: `<label>/manifest.json`, and for each match `<label>/<id>/match.json`, its
/// record, and `<label>/<id>/<sha256>`, its file, when the bucket has it. Nothing a rule or a file named
/// becomes an entry's name.
async fn zip_response(
    web: &Web,
    label: String,
    downloads: Vec<QaDownload>,
) -> Result<Response, ApiError> {
    let mut entries: Vec<(String, Entry)> = Vec::new();
    let mut manifest = Manifest {
        matches: Vec::new(),
    };
    for download in downloads {
        let id = download.qa_match.id;
        let record_name = format!("{label}/{id}/match.json");
        let record = serde_json::to_vec_pretty(&download.record).map_err(ApiError::internal)?;
        entries.push((record_name.clone(), Entry::Bytes(record)));
        let sha256: Sha256 = download
            .qa_match
            .sha256
            .parse()
            .map_err(ApiError::internal)?;
        let file = match web.bucket.get(ALERT_FILES, &sha256).await {
            Ok(cached) => {
                let name = format!("{label}/{id}/{sha256}");
                entries.push((name.clone(), Entry::File(cached.file, cached.size)));
                Some(name)
            }
            Err(BucketError::NotFound { .. }) => None,
            Err(e) => return Err(ApiError::internal(e)),
        };
        manifest.matches.push(Included {
            qa_match: download.qa_match.into(),
            file,
            record: record_name,
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

enum Entry {
    Bytes(Vec<u8>),
    /// A file from the bucket, open, and its size.
    File(std::fs::File, u64),
}
