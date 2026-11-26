//! `/api/observables/v1`: an observable's prevalence across alerts, and the observable types.

use std::collections::BTreeMap;

use ace_results::ObservableKind;
use ace_service::{Lookup, Prevalence};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairBody {
    #[serde(rename = "type")]
    kind: String,
    /// The value as an observable holds it; a file's is its sha256.
    value: String,
}

fn five() -> u32 {
    5
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LookupRequest {
    /// 1 to 1000 pairs.
    observables: Vec<PairBody>,
    /// How many of the newest alerts to list for each, 0 to 20.
    #[serde(default = "five")]
    #[schema(default = 5)]
    recent_alerts: u32,
    /// Up to 100 alerts to leave out, such as the caller's own.
    #[serde(default)]
    exclude_alerts: Vec<Uuid>,
    /// Count only alerts made at or after this.
    #[serde(default)]
    since: Option<DateTime<Utc>>,
    /// The alert queues whose alerts are counted and listed, 1 to 100 names of 1 to 64 characters; the
    /// default queue when omitted, so prevalence leaves out test runs and special-purpose queues.
    /// `faqueue` alerts never count.
    #[serde(default)]
    #[schema(min_items = 1, max_items = 100)]
    queues: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RecentAlertBody {
    id: Uuid,
    disposition: Option<String>,
    alerted_at: DateTime<Utc>,
    /// The queue it's in.
    queue: String,
}

/// One pair's prevalence, at its index in the request.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PrevalenceBody {
    index: usize,
    #[serde(rename = "type")]
    kind: String,
    /// The value as it was matched, such as a lowercased sha256; null when the pair was refused.
    value: Option<String>,
    /// Why the pair couldn't be looked up, such as a type that doesn't exist.
    error: Option<String>,
    /// How many alerts in the lookup's queues hold it, `faqueue` alerts left out.
    alerts: i64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    /// Those alerts by disposition, `OPEN` for none yet.
    dispositions: BTreeMap<String, i64>,
    /// The newest of them.
    recent: Vec<RecentAlertBody>,
}

impl From<Prevalence> for PrevalenceBody {
    fn from(found: Prevalence) -> Self {
        PrevalenceBody {
            index: found.index,
            kind: found.kind,
            value: found.value,
            error: found.error,
            alerts: found.alerts,
            first_seen: found.first_seen,
            last_seen: found.last_seen,
            dispositions: found.dispositions,
            recent: found
                .recent
                .into_iter()
                .map(|alert| RecentAlertBody {
                    id: alert.id,
                    disposition: alert.disposition,
                    alerted_at: alert.alerted_at,
                    queue: alert.queue,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LookupBody {
    results: Vec<PrevalenceBody>,
}

/// How often each observable has been in an alert, when, with what dispositions, and the newest few. A
/// pair that can't be looked up gets its error at its index, and the rest are still answered.
#[utoipa::path(
    post,
    path = "/api/observables/v1/lookup",
    tag = "observables",
    request_body = LookupRequest,
    responses(
        (status = 200, description = "Each pair's prevalence", body = LookupBody),
        (status = 400, description = "A lookup outside its limits, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:read, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn lookup(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<LookupRequest>, JsonRejection>,
) -> Result<Json<LookupBody>, ApiError> {
    let Json(body) = body?;
    let lookup = Lookup {
        pairs: body
            .observables
            .into_iter()
            .map(|pair| (pair.kind, pair.value))
            .collect(),
        recent: body.recent_alerts,
        exclude: body.exclude_alerts,
        since: body.since,
        queues: body.queues,
    };
    let results = web.service.lookup_observables(&actor, &lookup).await?;
    Ok(Json(LookupBody {
        results: results.into_iter().map(PrevalenceBody::from).collect(),
    }))
}

/// One observable type.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservableTypeBody {
    /// The type's name, as an observable's `type` holds it.
    name: &'static str,
    /// The type this one extends: a module that accepts the parent also accepts this type.
    parent: Option<&'static str>,
    /// Recognized, but not offered to analysts.
    deprecated: bool,
    /// The label shown when nothing sets one on the observable.
    default_display_type: Option<&'static str>,
    description: Option<&'static str>,
}

impl From<ObservableKind> for ObservableTypeBody {
    fn from(kind: ObservableKind) -> Self {
        ObservableTypeBody {
            name: kind.as_str(),
            parent: kind.parent().map(ObservableKind::as_str),
            deprecated: kind.is_deprecated(),
            default_display_type: kind.default_display_type(),
            description: kind.description(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservableTypesBody {
    types: Vec<ObservableTypeBody>,
}

/// The observable types this node knows, in name order: the open-source ones and the site's own,
/// deprecated ones included.
#[utoipa::path(
    get,
    path = "/api/observables/v1/types",
    tag = "observables",
    responses(
        (status = 200, description = "Every observable type", body = ObservableTypesBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:read", body = ErrorBody),
    )
)]
pub(crate) async fn observable_types(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<ObservableTypesBody>, ApiError> {
    let kinds = web.service.observable_types(&actor).await?;
    Ok(Json(ObservableTypesBody {
        types: kinds
            .iter()
            .copied()
            .map(ObservableTypeBody::from)
            .collect(),
    }))
}
