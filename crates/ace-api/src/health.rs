//! `/api/health/v1/ping` (PLAN.md 5.6's `health` router): a sign that this listener answers, for a
//! load balancer or a person checking the API is up.
//!
//! As in ace3, it takes no credential and checks nothing else: no database, no bucket. So it says
//! nothing about the node to someone without a key, and it answers while the database is down, which
//! is what a check of this process should do. A credential sent with it is ignored, so a revoked key
//! in a monitor doesn't fail it. The stack's own healthcheck is the lease API's `GET /healthz` on the
//! workers' listener (`ace_core::api`), which asks the database.

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// The answer to a ping.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PingBody {
    /// Always `pong`.
    result: &'static str,
}

#[utoipa::path(
    get,
    path = "/api/health/v1/ping",
    tag = "health",
    security(()),
    responses(
        (status = 200, description = "The API answers", body = PingBody),
    )
)]
pub(crate) async fn ping() -> Json<PingBody> {
    Json(PingBody { result: "pong" })
}
