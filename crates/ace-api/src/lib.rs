//! The JSON API (PLAN.md 5.5): an axum adapter over `ace-service`, for people and their scripts. Workers
//! use the lease API in `ace_core::api`, on a listener of its own (`ace serve`'s docs say why).
//!
//! This crate holds the request and response types, the extractor that authenticates a request
//! (`auth`), and the mapping from `ServiceError` to a status (`error`). It runs no SQL and decides
//! nothing: every read and write is a service function, which checks the permission and writes the
//! audit row. The one thing it checks itself is a submission's permission before it reads the body,
//! so a key that can't submit can't make the node spool a gigabyte first; the service checks again.
//!
//! The routes keep nothing of ace3's `/api/v2` (PLAN.md decision 7). They follow the core's
//! `/api/<area>/v1/` paths, and `GET /api/openapi.json` serves the document utoipa derives from them,
//! which `openapi.json` in this crate holds and `tests/api.rs` keeps current. Every route takes an API key
//! as `Authorization: Bearer <token>`, or a GUI session's cookie with the same-origin check
//! (`Service::authenticate_request`).
//!
//! What ace3's alerts, analysis and observables routers do, and where each went:
//!
//! | ace3 `/api/v2` | here |
//! |---|---|
//! | `GET /alerts` | `GET /api/alerts/v1/alerts`, newest first, a page at a time |
//! | `GET /alerts/{uuid}`, `/meta` | `GET /api/alerts/v1/alerts/{id}`, and its observables, results and detections in pages at `/observables` |
//! | `GET /alerts/{uuid}/observables/{o}/zip`, `/download` | `GET /api/alerts/v1/alerts/{id}/observables/{o}/file`, one file, audited |
//! | the GUI's disposition | `PUT /api/alerts/v1/alerts/{id}/disposition` |
//! | `POST /analysis` | `POST /api/analysis/v1/submit` |
//! | `POST /observables/lookup` | `POST /api/observables/v1/lookup` |
//!
//! Left out, each for a reason:
//! - The listing's filters, `count`, `export/*` and `date-range` use the manage page's filter language,
//!   which comes with that page in 5.10, as does a list's `changed_since`.
//! - The ETag and 304 on an alert: ace4 has no version counter, and 5.8 pushes changes to an open page.
//! - `/download` of a whole alert's directory: ace4 has none, and each file downloads on its own.
//! - `/text`, `/hex` and `/image` views of a file, and the alert's `saq.log`, belong to the alert view
//!   (5.8, 5.9). ace4 keeps a task's error on its row, not in a log file.
//! - `PUT /owner`, comment editing and `bulk-add-observable`: roots have no owner or comments yet, and an
//!   observable added by hand needs a decision about what it does to a dispositioned alert's analysis.
//! - `collect-file`, `render`, `crawl`, `check-for-clickers` and `clicker-searches` ask modules for more
//!   analysis on one observable. File collection is 7.9 and phishkit 7.7, and the clicker check needs the
//!   core to rerun a module on an observable that has its result, which nothing does yet.
//! - Detection points are their own router in 5.6.
//! - `PATCH /observables/interesting` sets a flag in ace3's index of every observable, which ace4 doesn't
//!   have: a flag an analyst sets across alerts is one of 5.14's analyst-edited lists.

use std::net::SocketAddr;

use ace_core::bucket::Bucket;
use ace_service::{Service, Transport};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use utoipa::OpenApi;

mod alerts;
mod analysis;
mod auth;
mod error;
mod observables;

use auth::Schemes;

pub use error::ErrorBody;

/// Limits on what a request can make this node hold.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Whether the browser reaches this server over TLS, which turns on the session cookie's `Secure`
    /// attribute and `__Host-` name (`ace_service::SessionCookie`). TLS isn't in the stack yet, so
    /// `ace serve` says `Plain`; whatever terminates TLS later sets this.
    pub transport: Transport,
    /// The largest submission, files included. ace3 has no limit of its own.
    pub max_submission_bytes: usize,
    /// The largest JSON body, and the largest `analysis` field of a submission.
    pub max_json_bytes: usize,
    /// The most files one submission holds.
    pub max_submitted_files: usize,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            transport: Transport::Plain,
            max_submission_bytes: 1 << 30,
            max_json_bytes: 4 << 20,
            max_submitted_files: 1000,
        }
    }
}

impl WebConfig {
    /// The defaults, with the largest submission from `ACE4_MAX_SUBMISSION_BYTES` when it's set.
    pub fn from_env() -> Self {
        let mut config = WebConfig::default();
        if let Some(bytes) = std::env::var("ACE4_MAX_SUBMISSION_BYTES")
            .ok()
            .and_then(|bytes| bytes.parse().ok())
        {
            config.max_submission_bytes = bytes;
        }
        config
    }
}

/// What every handler gets: the service, the bucket that files go to and come from, and the limits.
#[derive(Clone)]
pub struct Web {
    service: Service,
    bucket: Bucket,
    config: WebConfig,
}

impl Web {
    pub fn new(service: Service, bucket: Bucket, config: WebConfig) -> Self {
        Web {
            service,
            bucket,
            config,
        }
    }

    /// The API's routes. A JSON body is held to `max_json_bytes`, and a submission to
    /// `max_submission_bytes`.
    pub fn router(&self) -> Router {
        let json_limit = DefaultBodyLimit::max(self.config.max_json_bytes);
        Router::new()
            .route("/api/openapi.json", get(openapi))
            .route("/api/alerts/v1/alerts", get(alerts::list))
            .route("/api/alerts/v1/alerts/{id}", get(alerts::one))
            .route(
                "/api/alerts/v1/alerts/{id}/observables",
                get(alerts::observables),
            )
            .route(
                "/api/alerts/v1/alerts/{id}/observables/{observable}/file",
                get(alerts::file),
            )
            .route(
                "/api/alerts/v1/alerts/{id}/disposition",
                put(alerts::disposition).layer(json_limit),
            )
            .route(
                "/api/analysis/v1/submit",
                post(analysis::submit)
                    .layer(DefaultBodyLimit::max(self.config.max_submission_bytes)),
            )
            .route(
                "/api/observables/v1/lookup",
                post(observables::lookup).layer(json_limit),
            )
            .layer(axum::middleware::from_fn(auth::with_source))
            .with_state(self.clone())
    }
}

/// The OpenAPI document of every route above but its own, which needs no credential.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "ACE",
        description = "ACE's JSON API. A request authenticates with an API key as `Authorization: Bearer <token>`, or with a GUI session's cookie from ACE's own pages.",
        version = "1"
    ),
    paths(
        alerts::list,
        alerts::one,
        alerts::observables,
        alerts::file,
        alerts::disposition,
        analysis::submit,
        observables::lookup,
    ),
    modifiers(&Schemes),
    security(("api_key" = []), ("session" = [])),
    tags(
        (name = "alerts", description = "Alerts, what modules found in them, and their dispositions"),
        (name = "analysis", description = "Submitting analysis"),
        (name = "observables", description = "Observables across alerts"),
    )
)]
pub struct ApiDoc;

/// The document as `GET /api/openapi.json` serves it and `openapi.json` holds it.
pub fn openapi_json() -> String {
    let mut text = ApiDoc::openapi()
        .to_pretty_json()
        .expect("the document is JSON");
    text.push('\n');
    text
}

async fn openapi() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        openapi_json(),
    )
        .into_response()
}

/// Serves the router on `listener` until `shutdown` completes, with each request's peer address, which
/// its audit rows record.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
