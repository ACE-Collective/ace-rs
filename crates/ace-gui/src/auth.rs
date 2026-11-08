//! ace3's `/login` and `/logout` (`app/auth/views.py`), over 5.4's `Service::login` and `Service::logout`.
//!
//! CSRF: a login has no session yet, so `Service::authenticate_request` can't check it, and this calls
//! `RequestParts::same_origin` itself before reading the form. Without the check another site could post
//! its own name and password here and sign the analyst in as the attacker. A logout is checked the same
//! way. That check is all there is, with no token in the form, and it's enough for every browser the GUI
//! supports, because it fails closed: a browser sends `Sec-Fetch-Site` (Chrome 76, Firefox 90 and Safari
//! 16.4 on) or `Origin` (every current browser, on a POST) with a form post, and a post carrying neither
//! is refused, so a browser too old to send them can't log in rather than being open to a forged form.
//! ace3's Flask-WTF token guards against the same thing; its `_reject_cross_site_cookie_write`, which 5.4
//! ported, is the check its API makes.
//!
//! A login ends in a new session id whatever cookie came with it (`Service::login`'s `previous`), and the
//! cookie is `SessionCookie::set`, `Secure` with the `__Host-` name when the site is behind TLS. A failed
//! login answers the form again with ace3's "Invalid username or password." for every cause. Nothing here
//! logs the name or the password; the service logs a failed login's user id if the name was a user's,
//! and this adds the address, which ace3 logs too.
//!
//! What differs from ace3: no "keep me logged in", since a session ends 12 hours after its login
//! (`ace_service::SESSION_LIFETIME_SECONDS`); no `username` cookie that refills the form, which ace3 sets
//! for its jQuery; `next` must be a path on this site, where ace3 accepts any URL on its host.

use std::net::SocketAddr;

use ace_service::{Password, ServiceError, SessionCookie};
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::Gui;
use crate::session::{Failure, Viewer, layout_for, local_path, render, request_parts, see_other};
use crate::templates::LoginPage;

#[derive(Debug, Deserialize)]
pub(crate) struct NextQuery {
    next: Option<String>,
}

/// The login form's fields. Its `Debug` shows no password.
#[derive(Deserialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
    next: Option<String>,
}

/// The peer's address, for the log.
fn source(parts: &Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(
            || "an unknown address".to_owned(),
            |ConnectInfo(peer)| peer.ip().to_string(),
        )
}

/// `GET /login`: the form. A visitor already signed in sees it too, as in ace3, and a login replaces
/// their session.
pub(crate) async fn login_page(viewer: Viewer, Query(query): Query<NextQuery>) -> Response {
    let next = query
        .next
        .as_deref()
        .and_then(local_path)
        .map(str::to_owned);
    render(&LoginPage {
        layout: viewer.layout,
        next,
        failed: false,
    })
}

/// `POST /login`.
pub(crate) async fn login(
    State(gui): State<Gui>,
    parts: Parts,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Response {
    let request = request_parts(&parts, &gui);
    if !request.same_origin() {
        tracing::warn!(source = %source(&parts), "a cross-site login was refused");
        return Failure::new(
            StatusCode::FORBIDDEN,
            "This form came from another site.",
            &parts,
        )
        .into_response();
    }
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let cookie = SessionCookie::new(gui.transport);
    let previous = request.cookie.and_then(|header| cookie.read(header));
    let next = form.next.as_deref().and_then(local_path).map(str::to_owned);
    match gui
        .service
        .login(&form.username, Password::new(form.password), previous)
        .await
    {
        Ok(session) => {
            tracing::info!(actor = %session.actor, source = %source(&parts), "a GUI login");
            see_other(next.as_deref().unwrap_or("/"), Some(cookie.set(&session)))
        }
        Err(ServiceError::NotAuthenticated) => {
            tracing::warn!(source = %source(&parts), "a GUI login failed");
            render(&LoginPage {
                layout: layout_for(&gui, None, &parts).await,
                next,
                failed: true,
            })
        }
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /logout`: ends the session the cookie names, clears the cookie and goes to `/login`. A cookie
/// that names no live session is cleared all the same.
pub(crate) async fn logout(State(gui): State<Gui>, parts: Parts) -> Response {
    let request = request_parts(&parts, &gui);
    if !request.same_origin() {
        tracing::warn!(source = %source(&parts), "a cross-site logout was refused");
        return Failure::new(
            StatusCode::FORBIDDEN,
            "This form came from another site.",
            &parts,
        )
        .into_response();
    }
    let cookie = SessionCookie::new(gui.transport);
    if let Some(token) = parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| cookie.read(header))
        && let Err(error) = gui.service.logout(token).await
    {
        return Failure::from_service(error, &parts).into_response();
    }
    see_other("/login", Some(cookie.clear()))
}
