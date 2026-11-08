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
//! - `auth`: ace3's `/login` and `/logout`, with the CSRF check that a login has to make itself, and its
//!   password change, `/login/change` (5.11's auth area).
//! - `preferences`: the preferences page (5.11's preferences area), with the profile, the theme, the
//!   alert list's columns and the user's own API keys; the theme menu, and the alert page's section pins.
//!   The base layout draws every page in the viewer's theme.
//! - `alert`: an alert's page and its analysis tree, and the event stream that draws a result on an open
//!   page when it lands (5.8), and a result's page (5.9).
//! - `analysis`: each analysis type's view, ace3's analysis templates, by type from the binary's list
//!   (5.9).
//! - `actions`: the observable actions the tree offers, from the binary's list, and the comment form
//!   ace3's "Add Comment" opens (5.9, #1032).
//! - `list`: the alert list at `/` (5.10), ace3's manage page, with its filters, saved filters, columns,
//!   sorts, bulk disposition and refresh.
//! - `saved_filters`: the saved filters' forms and their manage page (5.10, and 5.11's saved_filters
//!   area), ace3's `saved_filters/_modals.html`, where a saved filter is renamed and the quick filters
//!   reordered.
//! - `admin`: the administration area under `admin:read` (5.11's admin area), ace3's `admin/hub.html` and
//!   `admin/manage.html`: users, groups, grants and keys over the `users` service. The base layout links
//!   to it for whoever holds `admin:read`.
//! - `signatures`: the signatures area under `signature:read` (5.11's signatures area), ace3's
//!   `signatures/hub.html` and `yara_qa.html`: the YARA QA rules, their versions and kept files, the
//!   links to the API's downloads, and purges with a confirm page, over the `yara_qa` service. The base
//!   layout links to it for whoever holds `signature:read`.
//! - `events`: the events area under `event:read` (5.11's events area): ace3's event list with its
//!   filters, sorts and CSV export, an event's page with Close Event behind a confirm, and its
//!   add-to-event modal as a page, opened from the alert list's bulk form, and Create Event, the same
//!   page with no alerts, over `Service::add_to_event`. The base layout links to the list for whoever
//!   holds `event:read`.
//!
//! From ace3's `app/templates/base.html` and `core.html`, and what differs: the layout keeps ace3's
//! theme attribute on `<html>`, its five themes and its log out by POST. It has none of ace3's jQuery,
//! Bootstrap, Google Fonts or CDN links: the stylesheet is this crate's own, and Datastar is the only
//! script. ace3's inline script that resolves the `system` theme is a `prefers-color-scheme` rule in the
//! stylesheet, so the page has no inline script. Its navigation links come with the pages they lead to
//! (5.8 to 5.11). `/` is the alert list, as ace3's home page is its manage page.

use ace_service::{Service, Transport};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

pub mod actions;
pub mod admin;
pub mod alert;
pub mod analysis;
mod assets;
mod auth;
pub mod events;
mod headers;
pub mod list;
mod places;
pub mod preferences;
pub mod saved_filters;
mod session;
pub mod signatures;
pub mod templates;

pub use actions::{ObservableAction, ObservableActions};
pub use alert::LiveLimits;
pub use analysis::{AnalysisView, ViewEntry, Views};
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
    live: std::sync::Arc<alert::Live>,
    views: std::sync::Arc<Views>,
    actions: std::sync::Arc<ObservableActions>,
    refreshes: std::sync::Arc<places::Places>,
}

impl Gui {
    pub fn new(service: Service, transport: Transport) -> Self {
        Gui::with_limits(service, transport, LiveLimits::default())
    }

    /// A GUI whose alert streams have these limits, rather than the defaults.
    pub fn with_limits(service: Service, transport: Transport, limits: LiveLimits) -> Self {
        Gui {
            service,
            transport,
            live: std::sync::Arc::new(alert::Live::new(limits)),
            views: std::sync::Arc::new(Views::builtin()),
            actions: std::sync::Arc::new(ObservableActions::builtin()),
            refreshes: std::sync::Arc::new(places::Places::new(
                list::REFRESH_LIMITS.0,
                list::REFRESH_LIMITS.1,
            )),
        }
    }

    /// The GUI drawing results with these analysis views (5.9), the binary's list, rather than the
    /// open-source ones alone.
    pub fn with_views(mut self, views: Views) -> Self {
        self.views = std::sync::Arc::new(views);
        self
    }

    /// The GUI offering these observable actions (5.9), the binary's list, rather than the open-source
    /// ones alone.
    pub fn with_actions(mut self, actions: ObservableActions) -> Self {
        self.actions = std::sync::Arc::new(actions);
        self
    }

    /// The GUI with these bounds on list refreshes (`list::REFRESH_LIMITS`): in all, and for one user.
    pub fn with_refresh_limits(mut self, total: usize, per_user: usize) -> Self {
        self.refreshes = std::sync::Arc::new(places::Places::new(total, per_user));
        self
    }

    /// How many alert streams are open.
    pub fn open_streams(&self) -> usize {
        self.live.open()
    }

    /// The GUI's routes, to merge with the JSON API's. Each response has `headers`' security headers,
    /// and each request records its peer as its audit rows' `src_ip`, as the API's do.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(list::page))
            .route("/alerts/list", get(list::refresh))
            .route(
                "/alerts/disposition",
                post(list::bulk_disposition)
                    .layer(DefaultBodyLimit::max(list::MAX_BULK_FORM_BYTES)),
            )
            .route("/events", get(events::list_page))
            .route("/events/export", get(events::export))
            .route(
                "/events/add",
                get(events::add_page)
                    .post(events::add)
                    .layer(DefaultBodyLimit::max(events::MAX_ADD_FORM_BYTES)),
            )
            .route("/events/{event}", get(events::event_page))
            .route(
                "/events/{event}/close",
                get(events::confirm_close).post(events::close),
            )
            .route(
                "/filters/saved",
                get(saved_filters::manage_page).post(saved_filters::save_filter),
            )
            .route(
                "/filters/saved/{id}",
                get(saved_filters::edit_filter_page).post(saved_filters::save_edit),
            )
            .route(
                "/filters/saved/{id}/delete",
                post(saved_filters::delete_filter),
            )
            .route("/filters/saved/{id}/quick", post(saved_filters::pin_filter))
            .route("/filters/saved/{id}/move", post(saved_filters::move_filter))
            .route("/preferences/manage-columns", post(list::set_columns))
            .route("/login", get(auth::login_page).post(auth::login))
            .route("/logout", post(auth::logout))
            .route(
                "/login/change",
                get(auth::change_password_page).post(auth::change_password),
            )
            .route("/preferences", get(preferences::page))
            .route("/preferences/profile", post(preferences::save_profile))
            .route("/preferences/keys", post(preferences::create_key))
            .route(
                "/preferences/keys/{id}",
                get(preferences::key_page).post(preferences::save_key),
            )
            .route(
                "/preferences/keys/{id}/revoke",
                post(preferences::revoke_key),
            )
            .route("/preferences/theme", post(preferences::set_theme))
            .route(
                "/preferences/alert-section",
                post(preferences::set_alert_section),
            )
            .route("/admin", get(admin::hub))
            .route(
                "/admin/users",
                get(admin::users_page).post(admin::create_user),
            )
            .route("/admin/users/{id}", get(admin::user_page))
            .route("/admin/users/{id}/profile", post(admin::save_profile))
            .route("/admin/users/{id}/enabled", post(admin::set_enabled))
            .route("/admin/users/{id}/password", post(admin::reset_password))
            .route("/admin/users/{id}/groups", post(admin::join_group))
            .route("/admin/users/{id}/keys", post(admin::create_key))
            .route("/admin/groups", post(admin::create_group))
            .route("/admin/groups/{id}", get(admin::group_page))
            .route("/admin/groups/{id}/delete", post(admin::delete_group))
            .route("/admin/groups/{id}/members", post(admin::add_member))
            .route(
                "/admin/groups/{id}/members/{user}/remove",
                post(admin::remove_member),
            )
            .route("/admin/grants", post(admin::grant))
            .route("/admin/grants/revoke", post(admin::revoke))
            .route(
                "/admin/keys/{id}",
                get(admin::key_page).post(admin::save_key),
            )
            .route("/admin/keys/{id}/revoke", post(admin::revoke_key))
            .route("/signatures", get(signatures::hub))
            .route("/signatures/yara-qa", get(signatures::yara_qa))
            .route(
                "/signatures/yara-qa/rules/{uuid}",
                get(signatures::rule_page),
            )
            .route(
                "/signatures/yara-qa/rules/{uuid}/download",
                get(signatures::download_selected),
            )
            .route(
                "/signatures/yara-qa/rules/{uuid}/purge",
                get(signatures::confirm_purge)
                    .post(signatures::purge)
                    .layer(DefaultBodyLimit::max(signatures::MAX_PURGE_FORM_BYTES)),
            )
            .route(
                "/signatures/yara-qa/matches/{id}",
                get(signatures::match_page),
            )
            .route("/alerts/{id}", get(alert::page))
            .route("/alerts/{id}/live", get(alert::live))
            .route("/alerts/{id}/results/{result}", get(alert::result_page))
            .route(
                "/alerts/{id}/observables/{observable}/comment",
                get(actions::comment_page)
                    .post(actions::add_comment)
                    .layer(DefaultBodyLimit::max(actions::MAX_COMMENT_FORM_BYTES)),
            )
            .route("/static/{name}", get(assets::serve))
            .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
            .layer(axum::middleware::from_fn(headers::secure))
            .layer(axum::middleware::from_fn(session::with_source))
            .with_state(self.clone())
    }
}
