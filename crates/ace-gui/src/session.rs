//! Who is looking at a page, and the answers every page shares.
//!
//! A page authenticates its request with `Service::authenticate_request`, as the API does (5.4), so a
//! session's request that could change something has passed `RequestParts::same_origin` before a handler
//! sees it. The GUI looks only at the session cookie: a request's `Authorization` header is left out, so
//! an API key opens no page. Keys are for the API.
//!
//! `Viewer` is anyone, signed in or not; `SignedIn` sends a visitor who isn't to `/login`, coming back
//! afterwards. A Datastar request (`Datastar-Request: true`) gets 401 instead, as ace3's
//! `reject_unauthenticated_datastar` does, so the page doesn't morph the login form into itself.

use std::net::SocketAddr;

use ace_service::{Actor, RequestParts, ServiceError, Theme};
use askama::Template;
use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::Gui;
use crate::headers::Nonce;
use crate::templates::{ErrorPage, Layout};

/// Runs the request with its peer's address as its audit rows' `src_ip`. As in `ace-api`, the TCP peer,
/// and no proxy header is trusted.
pub(crate) async fn with_source(request: Request, next: Next) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    ace_service::with_source_ip(ip, next.run(request)).await
}

/// The request as the service judges it, with the session cookie and no `Authorization`.
pub(crate) fn request_parts<'a>(parts: &'a Parts, gui: &Gui) -> RequestParts<'a> {
    let header = |name: header::HeaderName| {
        parts
            .headers
            .get(name)
            .map(|value| value.to_str().unwrap_or(""))
    };
    RequestParts {
        transport: gui.transport,
        method: parts.method.as_str(),
        authorization: None,
        cookie: header(header::COOKIE),
        sec_fetch_site: header(header::HeaderName::from_static("sec-fetch-site")),
        origin: header(header::ORIGIN),
        host: header(header::HOST),
    }
}

pub(crate) fn nonce(parts: &Parts) -> String {
    parts
        .extensions
        .get::<Nonce>()
        .map(|nonce| nonce.0.clone())
        .expect("headers::secure gives every request a nonce")
}

/// A page's layout for this viewer: their theme, or the default if it can't be read, so a page still
/// draws when the database is failing, as ace3's does.
pub(crate) async fn layout_for(gui: &Gui, actor: Option<&Actor>, parts: &Parts) -> Layout {
    let nonce = nonce(parts);
    let path = parts.uri.path();
    let Some(actor) = actor else {
        return Layout::new(&nonce, Theme::default(), None, path);
    };
    let theme = gui.service.theme(actor).await.unwrap_or_else(|error| {
        tracing::warn!(%actor, "reading the theme failed, so the page has the default: {error}");
        Theme::default()
    });
    let username = match actor {
        Actor::User { name, .. } => Some(name.clone()),
        Actor::ApiKey { .. } | Actor::Internal { .. } => None,
    };
    let mut layout = Layout::new(&nonce, theme, username, path);
    layout.admin = gui
        .service
        .allowed(actor, &ace_service::ADMIN_READ)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%actor, "checking admin:read failed, so the page has no admin link: {error}");
            false
        });
    layout
}

/// Anyone: the actor if the request has a live session, and the page's layout.
pub(crate) struct Viewer {
    pub(crate) actor: Option<Actor>,
    pub(crate) layout: Layout,
}

impl FromRequestParts<Gui> for Viewer {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, gui: &Gui) -> Result<Self, Failure> {
        let actor = match gui
            .service
            .authenticate_request(&request_parts(parts, gui))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ServiceError::NotAuthenticated) => None,
            Err(error) => return Err(Failure::from_service(error, parts)),
        };
        let layout = layout_for(gui, actor.as_ref(), parts).await;
        Ok(Viewer { actor, layout })
    }
}

/// A signed-in user.
pub(crate) struct SignedIn {
    pub(crate) actor: Actor,
    pub(crate) layout: Layout,
}

impl FromRequestParts<Gui> for SignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, gui: &Gui) -> Result<Self, Response> {
        let viewer = Viewer::from_request_parts(parts, gui)
            .await
            .map_err(IntoResponse::into_response)?;
        match viewer.actor {
            Some(actor) => Ok(SignedIn {
                actor,
                layout: viewer.layout,
            }),
            None => Err(sign_in(parts)),
        }
    }
}

/// Where a visitor who isn't signed in goes: `/login`, coming back to this page if it's one to come
/// back to, or 401 for Datastar.
fn sign_in(parts: &Parts) -> Response {
    if parts.headers.contains_key("datastar-request") {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let back = parts
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .filter(|_| parts.method == axum::http::Method::GET)
        .and_then(local_path);
    login_url(back).into_response()
}

/// A redirect to `/login`, with where to go after.
pub(crate) fn login_url(next: Option<&str>) -> Redirect {
    match next.filter(|next| *next != "/") {
        Some(next) => Redirect::to(&format!(
            "/login?{}",
            serde_urlencoded::to_string([("next", next)]).expect("a string encodes")
        )),
        None => Redirect::to("/login"),
    }
}

/// A path on this site to send a browser to, or None for anything else: a URL with a scheme or a host,
/// `//host` and `/\host`, which browsers read as another host, and anything with a control character or
/// that isn't ASCII, which can't be a `Location` as it is. ace3 checks the host; this takes only a path.
pub(crate) fn local_path(next: &str) -> Option<&str> {
    let mut bytes = next.bytes();
    let safe = next.len() <= 2048
        && bytes.next() == Some(b'/')
        && !matches!(bytes.next(), Some(b'/' | b'\\'))
        && next.bytes().all(|byte| byte.is_ascii_graphic())
        && !next.contains('\\');
    safe.then_some(next)
}

/// A page, as HTML, or a 500 if it can't be drawn.
pub(crate) fn render(page: &impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!("a page couldn't be drawn: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// A refusal or a failure, as a page in the default theme.
#[derive(Debug)]
pub(crate) struct Failure {
    status: StatusCode,
    message: String,
    nonce: String,
}

impl Failure {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>, parts: &Parts) -> Self {
        Failure {
            status,
            message: message.into(),
            nonce: nonce(parts),
        }
    }

    /// A service error as a page, with the API's statuses for a refusal (`ace-api`'s `error`). A failure that isn't the
    /// viewer's says only "internal error", with the detail in the log.
    pub(crate) fn from_service(error: ServiceError, parts: &Parts) -> Self {
        let status = match &error {
            ServiceError::NotAuthenticated => StatusCode::UNAUTHORIZED,
            ServiceError::CrossSiteRequest
            | ServiceError::Forbidden(_)
            | ServiceError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            ServiceError::InvalidRequest(_)
            | ServiceError::WeakPassword
            | ServiceError::InvalidKeyName
            | ServiceError::CantDisableYourself
            | ServiceError::CantDropYourOwnUserWrite => StatusCode::BAD_REQUEST,
            ServiceError::NotFound(_) | ServiceError::NoUser(_) => StatusCode::NOT_FOUND,
            ServiceError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServiceError::UsernameTaken
            | ServiceError::GroupNameTaken
            | ServiceError::FilterNameTaken(_)
            | ServiceError::UsersExist => StatusCode::CONFLICT,
            _ => {
                tracing::error!("a page failed: {error}");
                return Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error", parts);
            }
        };
        Failure::new(status, error.to_string(), parts)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let page = ErrorPage {
            layout: Layout::signed_out(&self.nonce),
            status: self.status.as_u16(),
            message: self.message,
        };
        let mut response = render(&page);
        *response.status_mut() = self.status;
        response
    }
}

/// A 303 to a path, with headers to add, such as a cookie.
pub(crate) fn see_other(location: &str, set_cookie: Option<String>) -> Response {
    let mut response = Redirect::to(location).into_response();
    if let Some(cookie) = set_cookie {
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).expect("a cookie is a header value"),
        );
    }
    response
}
