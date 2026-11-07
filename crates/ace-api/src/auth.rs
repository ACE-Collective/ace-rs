//! Who a request is, and where it came from.
//!
//! `Authenticated` is the extractor every route takes first, so a request without a credential is a 401
//! before anything else about it is read. It passes the headers to `Service::authenticate_request`
//! (PLAN.md 5.4), which judges a bearer key, or a session cookie with its same-origin check, and returns
//! the actor or refuses. An actor is good for the one request.
//!
//! `with_source` runs each request inside `ace_service::with_source_ip`, so its audit rows record the
//! address. That's the TCP peer. No proxy header is trusted: ace3 takes the first `X-Forwarded-For`
//! entry, which any client can write. Behind Docker's published port the peer is Docker's gateway, not
//! the client. A production proxy (PLAN.md's Deferred) brings the list of proxies to trust, and this is
//! where the header would be read.

use std::net::SocketAddr;

use ace_service::{Actor, RequestParts};
use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::header;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use utoipa::Modify;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::Web;
use crate::error::ApiError;

/// The actor a request authenticated as.
pub(crate) struct Authenticated(pub(crate) Actor);

impl FromRequestParts<Web> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, web: &Web) -> Result<Self, ApiError> {
        // A header that isn't text is still there: an Authorization header that can't be read refuses
        // the request rather than letting a cookie decide it.
        let header = |name: header::HeaderName| {
            parts
                .headers
                .get(name)
                .map(|value| value.to_str().unwrap_or(""))
        };
        let request = RequestParts {
            transport: web.config.transport,
            method: parts.method.as_str(),
            authorization: header(header::AUTHORIZATION),
            cookie: header(header::COOKIE),
            sec_fetch_site: header(header::HeaderName::from_static("sec-fetch-site")),
            origin: header(header::ORIGIN),
            host: header(header::HOST),
        };
        Ok(Authenticated(
            web.service.authenticate_request(&request).await?,
        ))
    }
}

/// Runs the request with its peer's address as its audit rows' `src_ip`.
pub(crate) async fn with_source(request: Request, next: Next) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    ace_service::with_source_ip(ip, next.run(request)).await
}

/// The two ways to authenticate, in the document.
pub(crate) struct Schemes;

impl Modify for Schemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "An API key, `ace4k_...`, shown once when it was made.",
                    ))
                    .build(),
            ),
        );
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "ace4_session",
                "A GUI session's cookie, `__Host-ace4_session` under TLS. A request that could \
                 change something must also come from ACE's own pages.",
            ))),
        );
    }
}
