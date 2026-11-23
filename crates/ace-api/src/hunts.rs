//! `/api/hunts/v1`: ace3's `hunt` router (PLAN.md 5.6, 6.4), and the hunts the hunter loaded.
//!
//! | ace3 | here |
//! |---|---|
//! | `POST /hunt/validate`, under `hunt:write` | `POST /api/hunts/v1/validate`, under `hunt:write`, audited |
//! | (none: hunts are files, their state pickles on the node) | `GET /api/hunts/v1/hunts` and `GET /api/hunts/v1/hunts/{uuid}`, under `hunt:read` |
//! | (none: a suppression is a log line, #840) | `GET /api/hunts/v1/hunts/{uuid}/suppressions?limit=&after=`, under `hunt:read`, newest first (PLAN.md 6.5) |
//!
//! A validation takes ace3's body, the `validate-hunt` CLI's compiled package (`compiled_hunt`: its
//! target and its assets, with `__pkg__/` pointing at where they're written) and optional
//! `execution_arguments`, and answers in ace3's shape: 200 with `{"valid": true}` and, when it ran, the
//! roots it made, or 400 with `{"valid": false, "error": ...}`. The package is loaded as the hunter
//! loads a hunt (`ace_hunt::load_hunt`), with no file outside the package. Every request that holds
//! `hunt:write` leaves one audit row, as ace3's leaves one `HUNT_AUDIT` line.
//!
//! What's left out, and why:
//! - Running a hunt against its data source (`start_time`, `end_time`, `timezone`,
//!   `time_range_overrides`): that needs the source's credentials, which this process doesn't hold
//!   (PLAN.md 2.24); only `ace hunter` resolves them. A run over the events sent in `query_results`
//!   works, as ace3's does, and a run asking for the source is 400, saying so.
//! - `analyze_results` and `create_alerts`, which would submit the roots as the caller: 400 for now.
//! - The answer's `logs`, every log line ace3's run wrote: ace-rs's tracing isn't captured per request.
//!
//! Correlation (PLAN.md 6.6): a hunt with a `correlate` block is checked as ace3's validation checks
//! one (`ace_hunt::correlate::check`), a template that reads `_secrets` or `_config` and a custom
//! command type that isn't this binary's, failed to build, has a `cache:` it can't take or options
//! its model refuses each a 400 with ace3's message. A run correlates the rows sent before
//! processing them, as ace3's does, and answers with ace3's `correlation_trace`, `original_events`
//! (the rows sent) and `correlate_results` (the correlation's queries and their rows, to save and
//! send back as `execution_arguments.correlate_results`, whose saved answers it replays). This
//! process holds no data source's credentials, so a correlation query it can't replay fails its step,
//! and its event alerts with the reason on its trace.
//! - ace3 has no enable or disable: a hunt's `enabled` is in its file, in the signatures repository.

use std::path::{Component, Path as FsPath};
use std::sync::Arc;

use ace_hunt::correlate::command::CommandTypes;
use ace_hunt::query::observable::EmailNormalizer;
use ace_hunt::query::{self, Context, schedule::State};
use ace_hunt::render::Renderer;
use ace_hunt::{HuntType, LoadOptions};
use ace_service::{HuntRow, HuntState, HuntValidation, Suppression, SuppressionReason};
use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use utoipa::{IntoParams, ToSchema};

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// What validation needs from the binary: its hunt types, and how it normalizes an email address.
#[derive(Clone)]
pub struct HuntSupport {
    pub types: Vec<Arc<dyn HuntType>>,
    /// ace3's `normalize_email_address`; `ace serve` passes the email module's.
    pub email: EmailNormalizer,
    /// Whether an observable type is one the binary has.
    pub valid_type: fn(&str) -> bool,
    /// The binary's correlation command types (`App::command_types`).
    pub command_types: Arc<CommandTypes>,
    /// The overlay's query sources, built without their secrets and refusing to run a query
    /// (`ace_app::hunter::validation_sources`, PLAN.md decision 40): what a correlation's time
    /// fields and its trace's windows are read from. None by default.
    pub sources: Arc<ace_hunt::correlate::source::Sources>,
}

impl Default for HuntSupport {
    fn default() -> Self {
        HuntSupport {
            types: vec![Arc::new(ace_hunt::types::Splunk::default())],
            email: |_| None,
            valid_type: |t| t.parse::<ace_results::ObservableKind>().is_ok(),
            command_types: Arc::new(CommandTypes::new()),
            sources: Arc::new(ace_hunt::correlate::source::Sources::new()),
        }
    }
}

/// A hunt's state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HuntStateBody {
    last_executed_time: Option<DateTime<Utc>>,
    /// The end of the last window it searched.
    last_end_time: Option<DateTime<Utc>>,
    last_alert_time: Option<DateTime<Utc>>,
    /// When each group last alerted, for a grouped hunt with a suppression.
    last_alert_times: std::collections::BTreeMap<String, DateTime<Utc>>,
}

impl From<HuntState> for HuntStateBody {
    fn from(state: HuntState) -> Self {
        HuntStateBody {
            last_executed_time: state.last_executed_time,
            last_end_time: state.last_end_time,
            last_alert_time: state.last_alert_time,
            last_alert_times: state.last_alert_times,
        }
    }
}

/// A hunt file as the hunter last loaded it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HuntBody {
    #[serde(rename = "type")]
    kind: String,
    /// The file, relative to the signatures checkout.
    path: String,
    name: Option<String>,
    uuid: Option<String>,
    enabled: Option<bool>,
    frequency: Option<String>,
    /// Why it didn't load, in ace3's words; null for a hunt that loaded.
    error: Option<String>,
    loaded_at: DateTime<Utc>,
    /// Null for a hunt that hasn't run.
    state: Option<HuntStateBody>,
}

impl From<HuntRow> for HuntBody {
    fn from(row: HuntRow) -> Self {
        HuntBody {
            kind: row.hunt.kind,
            path: row.hunt.path,
            name: row.hunt.name,
            uuid: row.hunt.uuid,
            enabled: row.hunt.enabled,
            frequency: row.hunt.frequency,
            error: row.hunt.error,
            loaded_at: row.loaded_at,
            state: row.state.map(HuntStateBody::from),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HuntsBody {
    hunts: Vec<HuntBody>,
}

/// The hunts the hunter loaded, by type and path, each with its state.
#[utoipa::path(
    get,
    path = "/api/hunts/v1/hunts",
    tag = "hunts",
    responses(
        (status = 200, description = "The hunts", body = HuntsBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold hunt:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    AxumState(web): AxumState<Web>,
) -> Result<Json<HuntsBody>, ApiError> {
    let hunts = web.service.hunts(&actor).await?;
    Ok(Json(HuntsBody {
        hunts: hunts.into_iter().map(HuntBody::from).collect(),
    }))
}

/// One hunt by its uuid, with its state.
#[utoipa::path(
    get,
    path = "/api/hunts/v1/hunts/{uuid}",
    tag = "hunts",
    params(("uuid" = String, Path, description = "The hunt's uuid")),
    responses(
        (status = 200, description = "The hunt", body = HuntBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold hunt:read", body = ErrorBody),
        (status = 404, description = "No loaded hunt has that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    AxumState(web): AxumState<Web>,
    Path(uuid): Path<String>,
) -> Result<Json<HuntBody>, ApiError> {
    Ok(Json(web.service.hunt(&actor, &uuid).await?.into()))
}

/// Why a hunt dropped a hit.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SuppressionReasonBody {
    /// Its group alerted within the hunt's `suppression`.
    Group,
    /// Its dedup key made a root less than 4 hours before, as ace3's collector drops duplicates.
    Duplicate,
}

/// A hit a hunt dropped (PLAN.md 6.5).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SuppressionBody {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    uuid: String,
    reason: SuppressionReasonBody,
    /// The group's suppression key, or the dedup key.
    key: String,
    /// The `group_by` value, for a grouped hunt.
    group_value: Option<JsonValue>,
    /// The root it would have been, as the hunt names it. Show it as text.
    description: String,
    event_time: DateTime<Utc>,
    /// How many of the search's rows it held.
    events: i32,
    /// The window it fell into, from the earlier hit.
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    /// The earlier hit's root; null when ace-rs didn't make it.
    cause_root: Option<uuid::Uuid>,
    /// The window the run searched.
    search_start: Option<DateTime<Utc>>,
    search_end: Option<DateTime<Utc>>,
    decided_at: DateTime<Utc>,
}

impl From<Suppression> for SuppressionBody {
    fn from(s: Suppression) -> Self {
        SuppressionBody {
            id: s.id,
            kind: s.kind,
            name: s.name,
            uuid: s.uuid,
            reason: match s.reason {
                SuppressionReason::Group => SuppressionReasonBody::Group,
                SuppressionReason::Duplicate => SuppressionReasonBody::Duplicate,
            },
            key: s.key,
            group_value: s.group_value,
            description: s.description,
            event_time: s.event_time,
            events: s.events,
            window_start: s.window_start,
            window_end: s.window_end,
            cause_root: s.cause_root,
            search_start: s.search_start,
            search_end: s.search_end,
            decided_at: s.decided_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SuppressionPageBody {
    suppressions: Vec<SuppressionBody>,
    /// The `after` of the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SuppressionsQuery {
    /// How many, 1 to 500; 50 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// The hits a hunt dropped, newest decision first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/hunts/v1/hunts/{uuid}/suppressions",
    tag = "hunts",
    params(("uuid" = String, Path, description = "The hunt's uuid"), SuppressionsQuery),
    responses(
        (status = 200, description = "A page of suppression decisions", body = SuppressionPageBody),
        (status = 400, description = "A limit out of range, or a cursor that names no suppression of this hunt", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold hunt:read", body = ErrorBody),
        (status = 404, description = "No loaded hunt has that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn suppressions(
    Authenticated(actor): Authenticated,
    AxumState(web): AxumState<Web>,
    Path(uuid): Path<String>,
    query: Result<Query<SuppressionsQuery>, QueryRejection>,
) -> Result<Json<SuppressionPageBody>, ApiError> {
    let Query(query) = query?;
    let page = web
        .service
        .hunt_suppressions(&actor, &uuid, query.limit, query.after)
        .await?;
    Ok(Json(SuppressionPageBody {
        suppressions: page
            .suppressions
            .into_iter()
            .map(SuppressionBody::from)
            .collect(),
        next: page.next,
    }))
}

/// A file of a compiled hunt package.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AssetBody {
    /// yaml, query, query_include, executable or support.
    kind: String,
    /// Relative to the package root.
    path: String,
    content: String,
    /// `text` or `base64`.
    #[serde(default = "text_encoding")]
    encoding: String,
    #[serde(default)]
    permissions: Option<u32>,
    /// Where it was on the compiling machine; never read.
    #[serde(default)]
    original_abs: Option<String>,
}

fn text_encoding() -> String {
    "text".to_owned()
}

/// ace3's `CompiledHunt`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CompiledHuntBody {
    #[serde(default = "version_two")]
    version: i64,
    /// The hunt's file, relative to the package root.
    target: String,
    /// The package root on the compiling machine; never read.
    #[serde(default)]
    package_root: Option<String>,
    #[serde(default)]
    assets: Vec<AssetBody>,
}

fn version_two() -> i64 {
    2
}

/// How to run the hunt; only `query_results` runs here (the module docs say why).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ExecutionBody {
    /// The events to run the hunt over, in place of its search.
    #[serde(default)]
    #[schema(value_type = Option<Vec<Object>>)]
    query_results: Option<Vec<JsonMap<String, JsonValue>>>,
    #[serde(default)]
    start_time: Option<String>,
    #[serde(default)]
    end_time: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    analyze_results: bool,
    #[serde(default)]
    create_alerts: bool,
    #[serde(default)]
    queue: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    time_range_overrides: Option<JsonMap<String, JsonValue>>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    correlate_results: Option<JsonValue>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ValidateRequest {
    compiled_hunt: CompiledHuntBody,
    #[serde(default)]
    execution_arguments: Option<ExecutionBody>,
}

/// ace3's answer to a validation.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationBody {
    valid: bool,
    /// Why it isn't valid, or why its run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// What the run made, as ace3's hunter makes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    roots: Option<Vec<JsonValue>>,
    /// A run's correlation trace, null for a hunt that doesn't correlate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    correlation_trace: Option<JsonValue>,
    /// A run's rows as they were sent, before correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<Object>>)]
    original_events: Option<JsonValue>,
    /// A run's correlation queries and their rows, `{"version": 1, "queries": [...]}`, null for a
    /// hunt that doesn't correlate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    correlate_results: Option<JsonValue>,
}

impl ValidationBody {
    fn refused(error: String) -> ValidationBody {
        ValidationBody {
            valid: false,
            error: Some(error),
            roots: None,
            correlation_trace: None,
            original_events: None,
            correlate_results: None,
        }
    }

    fn valid() -> ValidationBody {
        ValidationBody {
            valid: true,
            error: None,
            roots: None,
            correlation_trace: None,
            original_events: None,
            correlate_results: None,
        }
    }
}

/// Writes the package's assets under `dir`, refusing a path outside it, and gives its target's path.
fn materialize(package: &CompiledHuntBody, dir: &FsPath) -> Result<std::path::PathBuf, String> {
    if package.version != 2 {
        return Err(format!(
            "unsupported CompiledHunt version: {} (expected 2)",
            package.version
        ));
    }
    let inside = |rel: &str, what: &str| -> Result<std::path::PathBuf, String> {
        let path = FsPath::new(rel);
        if path.is_absolute() {
            return Err(format!(
                "{what} path {rel:?} is absolute; it must be relative to the package root"
            ));
        }
        if rel.is_empty()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(format!("{what} path {rel:?} is outside the package root"));
        }
        Ok(dir.join(path))
    };
    let target = inside(&package.target, "target")?;
    let expansion = format!("{}/", dir.to_string_lossy().trim_end_matches('/'));
    for asset in &package.assets {
        let path = inside(&asset.path, "asset")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let bytes = if asset.encoding == "base64" {
            base64_decode(&asset.content)
                .ok_or_else(|| format!("asset {:?} isn't base64", asset.path))?
        } else {
            asset.content.replace("__pkg__/", &expansion).into_bytes()
        };
        std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        let _ = (&asset.kind, asset.permissions, &asset.original_abs);
    }
    let _ = &package.package_root;
    Ok(target)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        };
        bits = bits << 6 | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

/// Loads and, with `query_results`, runs the hunt: the audit record and the answer.
fn validate(
    request: &ValidateRequest,
    support: &HuntSupport,
) -> (HuntValidation, StatusCode, ValidationBody) {
    let mut record = HuntValidation {
        target: request.compiled_hunt.target.clone(),
        kind: None,
        name: None,
        uuid: None,
        valid: false,
        error: None,
        events: None,
        roots: 0,
    };
    let refuse = |mut record: HuntValidation, error: String| {
        record.error = Some(error.clone());
        (
            record,
            StatusCode::BAD_REQUEST,
            ValidationBody::refused(error),
        )
    };
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => return refuse(record, format!("error loading compiled hunt: {e}")),
    };
    let target = match materialize(&request.compiled_hunt, dir.path()) {
        Ok(target) => target,
        Err(e) => return refuse(record, format!("error loading compiled hunt: {e}")),
    };
    let options = LoadOptions {
        home: dir.path().to_owned(),
        ..LoadOptions::default()
    };
    // the hunt's own type, as ace3's peek_hunt_type finds it
    let mut loaded = None;
    for kind in &support.types {
        match ace_hunt::load_hunt(&target, kind.as_ref(), &options) {
            Ok(hunt) if hunt.config.kind == kind.name() => {
                loaded = Some((hunt, kind));
                break;
            }
            Ok(hunt) => record.kind = Some(hunt.config.kind),
            Err(e) => {
                if record.error.is_none() {
                    record.error = Some(e.to_string());
                }
            }
        }
    }
    let Some((hunt, kind)) = loaded else {
        let error = match (&record.kind, record.error.take()) {
            (Some(kind), _) => format!("invalid hunt type {kind}"),
            (None, Some(e)) => format!("invalid hunt config: {e}"),
            (None, None) => "invalid hunt config".to_owned(),
        };
        return refuse(record, error);
    };
    // a file the hunt reads must be the package's
    if let Some(outside) = hunt
        .files
        .iter()
        .find(|f| !FsPath::new(f).starts_with(dir.path()))
    {
        return refuse(record, format!("{outside} is outside the hunt's package"));
    }
    record.kind = Some(hunt.config.kind.clone());
    record.name = Some(hunt.config.name.clone());
    record.uuid = Some(hunt.config.uuid.clone());
    // a correlation's templates and custom command types, which loading doesn't check
    let correlate = hunt.config.correlate.as_ref();
    let template_errors =
        ace_hunt::correlate::check::removed_names(correlate, Some(&hunt.commands));
    if !template_errors.is_empty() {
        return refuse(record, template_errors.join("; "));
    }
    let type_errors = ace_hunt::correlate::check::custom_command_types(
        correlate,
        Some(&hunt.commands),
        &support.command_types,
    );
    if !type_errors.is_empty() {
        return refuse(record, type_errors.join("; "));
    }
    let Some(execution) = &request.execution_arguments else {
        record.valid = true;
        return (record, StatusCode::OK, ValidationBody::valid());
    };
    if execution.analyze_results || execution.create_alerts {
        return refuse(
            record,
            "analyze_results and create_alerts aren't taken here: the roots come back for review"
                .to_owned(),
        );
    }
    let Some(rows) = &execution.query_results else {
        return refuse(
            record,
            "running a hunt against its data source needs the source's credentials, which only ace hunter holds: send the events as query_results".to_owned(),
        );
    };
    let _ = (
        &execution.start_time,
        &execution.end_time,
        &execution.timezone,
        &execution.queue,
    );
    let _ = &execution.time_range_overrides;
    record.events = Some(rows.len());
    let now = Utc::now();
    let renderer = Renderer::default();
    let correlated = match correlate {
        None => None,
        Some(correlate) => match run_correlation(&hunt, correlate, rows, execution, support, now) {
            Ok(c) => Some(c),
            Err(e) => return refuse(record, format!("error executing hunt: {e}")),
        },
    };
    // the hunt type's own row time, as `ace hunter` gives it (PLAN.md decision 43)
    let event_time = |row: &JsonMap<String, JsonValue>| kind.event_time(&hunt.config, row, now);
    let valid_type = support.valid_type;
    let state = State::default();
    let ctx = Context {
        renderer: &renderer,
        now,
        signature_version: "unknown",
        tool_instance: "localhost",
        query: None,
        search_id: None,
        search_link: None,
        event_time: &event_time,
        valid_type: &valid_type,
        email: support.email,
        state: &state,
        manual: true,
        correlated: correlated.as_ref(),
    };
    match query::process(&hunt.config, rows, &ctx) {
        Ok(processed) => {
            let roots: Vec<JsonValue> = processed
                .submissions
                .iter()
                .map(|s| {
                    let mut v = serde_json::to_value(s).unwrap_or(JsonValue::Null);
                    if let Some(o) = v.as_object_mut() {
                        o.remove("files");
                    }
                    v
                })
                .collect();
            record.valid = true;
            record.roots = roots.len();
            let mut body = ValidationBody::valid();
            body.roots = Some(roots);
            body.original_events = Some(json!(rows));
            body.correlation_trace = Some(
                correlated
                    .as_ref()
                    .and_then(|c| serde_json::to_value(&c.trace).ok())
                    .unwrap_or(JsonValue::Null),
            );
            body.correlate_results = Some(
                correlated
                    .as_ref()
                    .map(|c| json!({"version": 1, "queries": c.captured}))
                    .unwrap_or(JsonValue::Null),
            );
            (record, StatusCode::OK, body)
        }
        Err(e) => refuse(record, format!("error executing hunt: {e}")),
    }
}

/// The hunt's correlation over the rows sent, as ace3's validation runs it: a zero-width window at
/// now, the saved `correlate_results` replayed, the sources' time fields and no data source, and
/// no cache.
fn run_correlation(
    hunt: &ace_hunt::Hunt,
    correlate: &ace_hunt::correlate::Correlate,
    rows: &[JsonMap<String, JsonValue>],
    execution: &ExecutionBody,
    support: &HuntSupport,
    now: DateTime<Utc>,
) -> Result<ace_hunt::correlate::engine::Correlated, String> {
    use ace_hunt::correlate::engine::{Engine, HuntRun, Runtime};
    let renderer = Renderer::correlation(ace_hunt::render::Limits::default());
    let sources = &support.sources;
    let clock = Utc::now;
    let stopped = || false;
    let rt = Runtime {
        renderer: &renderer,
        sources,
        command_types: &support.command_types,
        cache: &ace_hunt::correlate::cache::NoCache,
        secrets: &[],
        clock: &clock,
        stopped: &stopped,
        limits: Default::default(),
    };
    let mut run = HuntRun::at(now);
    run.source_type = Some(hunt.config.kind.clone());
    run.name = Some(hunt.config.name.clone());
    run.uuid = Some(hunt.config.uuid.clone());
    run.replay = execution
        .correlate_results
        .as_ref()
        .and_then(|r| r.get("queries"))
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    let events = rows
        .iter()
        .map(
            |r| match ace_hunt::query::extract::to_loaded(&JsonValue::Object(r.clone())) {
                ace_hunt::value::Value::Map(m) => m,
                _ => ace_hunt::value::Map::new(),
            },
        )
        .collect();
    Engine::new(&rt, correlate, &hunt.commands, run)
        .execute(events)
        .map_err(|e| e.to_string())
}

/// Checks a hunt package the way the hunter loads it and, with `execution_arguments.query_results`,
/// runs it over those events. The answer is ace3's: 200 when it's valid, 400 when it isn't.
#[utoipa::path(
    post,
    path = "/api/hunts/v1/validate",
    tag = "hunts",
    request_body = ValidateRequest,
    responses(
        (status = 200, description = "The hunt is valid, and what its run made", body = ValidationBody),
        (status = 400, description = "The hunt isn't valid, or its run failed", body = ValidationBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold hunt:write", body = ErrorBody),
        (status = 422, description = "The body isn't a validation request", body = ErrorBody),
    )
)]
pub(crate) async fn validate_hunt(
    Authenticated(actor): Authenticated,
    AxumState(web): AxumState<Web>,
    body: Result<Json<ValidateRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) =
        body.map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e.body_text()))?;
    let support = web.hunts.clone();
    let (status, answer) = web
        .service
        .validate_hunt(&actor, &|| {
            let (record, status, answer) = validate(&request, &support);
            (record, (status, answer))
        })
        .await?;
    Ok((status, Json(json!(answer))).into_response())
}
