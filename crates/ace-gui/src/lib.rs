//! The GUI (PLAN.md 5.7): server-rendered HTML over `ace-service`, as DESIGN.md's *The API and the GUI*
//! says, beside the JSON API of `ace-api`. Like that crate it runs no SQL and decides nothing: a page
//! reads through a service function, which checks the permission, and a form writes through one, which
//! checks it and writes the audit row.
//!
//! `ace serve` merges `Gui::router` into the JSON API's listener (`ACE4_WEB_LISTEN`), so the pages and
//! the API share one origin and one session cookie, and the lease API stays on its own.
//!
//! What's here:
//! - `templates`: askama's templates, compiled into the binary and checked against their structs, so a
//!   template that names a field its struct doesn't have fails the build. Every one escapes HTML.
//! - `assets`: the stylesheet and Datastar, the one vendored file (`vendor/README.md`), embedded in the
//!   binary and served under a hash of their bytes, cached for a year. Nothing is read from disk while
//!   it runs, so nothing depends on where the checkout or the binary is (PLAN.md 0.7, ace3 #920).
//! - `headers`: the security headers on every response, with a Content-Security-Policy whose nonce is
//!   new for each page, which is how Datastar runs its expressions without `unsafe-eval`.
//! - `session`: who the viewer is, through `Service::authenticate_request`.
//! - `auth`: ace3's `/login` and `/logout`, with the CSRF check that a login has to make itself.
//! - `preferences`: the theme form. The base layout draws every page in the viewer's theme.
//!
//! From ace3's `app/templates/base.html` and `core.html`, and what differs: the layout keeps ace3's
//! theme attribute on `<html>`, its five themes and its log out by POST. It has none of ace3's jQuery,
//! Bootstrap, Google Fonts or CDN links: the stylesheet is this crate's own, and Datastar is the only
//! script. ace3's inline script that resolves the `system` theme is a `prefers-color-scheme` rule in the
//! stylesheet, so the page has no inline script. Its navigation links come with the pages they lead to
//! (5.8 to 5.11).

use ace_service::{Service, Transport};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

mod assets;
mod auth;
mod headers;
mod preferences;
mod session;
pub mod templates;

pub use assets::{Asset, asset_named};
pub use headers::content_security_policy;

/// The largest form a page posts. A login's is a name and a password of at most
/// `ace_service::MAX_PASSWORD_BYTES`.
const MAX_FORM_BYTES: usize = 16 << 10;

/// What every handler gets: the service, and whether the browser reaches this server over TLS, which
/// the site's configuration says (`ace_api::WebConfig::transport`, from `ACE4_WEB_TLS`) and the session
/// cookie follows.
#[derive(Clone)]
pub struct Gui {
    service: Service,
    transport: Transport,
}

impl Gui {
    pub fn new(service: Service, transport: Transport) -> Self {
        Gui { service, transport }
    }

    /// The GUI's routes, to merge with the JSON API's. Each response has `headers`' security headers,
    /// and each request records its peer as its audit rows' `src_ip`, as the API's do.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(session::home))
            .route("/login", get(auth::login_page).post(auth::login))
            .route("/logout", post(auth::logout))
            .route("/preferences/theme", post(preferences::set_theme))
            .route("/static/{name}", get(assets::serve))
            .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
            .layer(axum::middleware::from_fn(headers::secure))
            .layer(axum::middleware::from_fn(session::with_source))
            .with_state(self.clone())
    }
}
