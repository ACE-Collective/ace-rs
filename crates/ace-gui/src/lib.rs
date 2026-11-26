//! The GUI (PLAN.md 5.7): server-rendered HTML over `ace-service`, as DESIGN.md's *The API and the GUI*
//! says, beside the JSON API of `ace-api`. Like that crate it runs no SQL and decides nothing: a page
//! reads through a service function, which checks the permission, and a form writes through one, which
//! checks it and writes the audit row.
//!
//! `ace serve` merges `Gui::router` into the JSON API's listener (`ACE_RS_WEB_LISTEN`), so the pages and
//! the API share one origin and one session cookie, and the lease API stays on its own.
//!
//! What's here:
//! - `templates`: askama's templates, compiled into the binary and checked against their structs, so a
//!   template that names a field its struct doesn't have fails the build. Every one escapes HTML.
//! - `assets`: the stylesheet (`static/ace.css`: design tokens, then a small set of components every
//!   page is drawn with, and nothing fetched from anywhere else), Datastar, and vis.js with the
//!   graph's own script (5.13), the vendored files being Datastar and vis (`vendor/README.md`),
//!   embedded in the binary and served under a hash of their bytes, cached for a year. Nothing is
//!   read from disk while it runs, so nothing depends on where the checkout or the binary is
//!   (PLAN.md 0.7, ace3 #920).
//! - `headers`: the security headers on every response, with a Content-Security-Policy whose nonce is
//!   new for each page, which is how Datastar runs its expressions without `unsafe-eval`.
//! - `session`: who the viewer is, through `Service::authenticate_request`.
//! - `auth`: ace3's `/login` and `/logout`, with the CSRF check that a login has to make itself, and its
//!   password change, `/login/change` (5.11's auth area).
//! - `preferences`: the preferences page (5.11's preferences area), with the profile, the theme, the
//!   alert list's columns and the user's own API keys; the theme menu, and the alert page's section pins.
//!   The base layout draws every page in the viewer's theme.
//! - `alert`: an alert's page and its analysis tree, and the event stream that draws a result on an open
//!   page when it lands (5.8), a result's page (5.9), and the alert's relationship graph (5.13).
//! - `analysis`: each analysis type's view, ace3's analysis templates, by type from the binary's list
//!   (5.9), and `analysis::summary`, the alert page's summary by alert type, ace3's per-alert-type
//!   templates, from the binary's list too.
//! - `actions`: the observable actions the tree offers, from the binary's list, the comment form
//!   ace3's "Add Comment" opens (5.9, #1032), and the form of the directives an analyst may add to an
//!   observable (PLAN.md decision 31).
//! - `list`: the alert list at `/` (5.10), ace3's manage page, with its filters, saved filters, columns,
//!   sorts, bulk disposition and refresh, and taking and assigning ownership (7.17).
//! - `alert_comments`: comments on an alert (5.15): the alert page's Add Comment and its author's edit
//!   and delete, and the bulk Add Comment of the alert list and an event's page.
//! - `analyze`: the Analyze page (7.18), ace3's Manual Analysis: a form of observables and uploaded
//!   files that makes an alert, or one per observable, through `Service::submit_manual`.
//! - `saved_filters`: the saved filters' forms and their manage page (5.10, and 5.11's saved_filters
//!   area), ace3's `saved_filters/_modals.html`, where a saved filter is renamed and the quick filters
//!   reordered, for the alert list and for each other screen that has quick filters.
//! - `admin`: the administration area under `admin:read` (5.11's admin area), ace3's `admin/hub.html` and
//!   `admin/manage.html`: users, groups, grants and keys over the `users` service. The base layout links
//!   to it for whoever holds `admin:read`.
//! - `cli`: Administration's CLI (5.12), ace3's `admin/cli.html`: the form that starts an `ace` command a
//!   parser pool runs contained, the history of runs, a run's page that polls for its output while it
//!   runs, and its cancel, over the `commands` service.
//! - `detection`: Administration's Observables page (7.6), ace3's `admin/detection.html`: the observables
//!   ACE detects, filtered and paged, added, given an expiry and removed, over the `detection` service.
//! - `monitoring`: Administration's Monitoring page (7.12), which ace3 doesn't have: the scheduled tasks
//!   and their runs, and what the monitoring checks last found, over the `monitoring` service.
//! - `signatures`: the signatures area under `signature:read` (5.11's signatures area), ace3's
//!   `signatures/hub.html` and `yara_qa.html`: the YARA QA rules, their versions and kept files, the
//!   links to the API's downloads, and purges with a confirm page, over the `yara_qa` service. The base
//!   layout links to it for whoever holds `signature:read`.
//! - `svs_samples`: the signatures area's samples pages (PLAN.md 7.10 batch 2), ace3's `samples.html`,
//!   `_samples_page.html` and `sample_detail.html`: the samples with their filters and sorts, a sample with
//!   its captures and verdicts, relabel, reset, confirm, retire, and a deletion behind a confirm, over the
//!   `svs_samples` service.
//! - `svs_validations`: the signatures area's validations pages (PLAN.md 7.10 batch 3), ace3's
//!   `validations.html`, `_validations_page.html` and `validation_detail.html`: the validations with their
//!   filters, and a validation's report with its rows by category and the download of their files, over
//!   the `svs_validations` service.
//! - `svs`: the SVS area under `svs:run_read` (PLAN.md 7.10 batch 5), ace3's `app/svs`: the Runs tab (the
//!   runs and their batches, with the runs screen's filters), the run page (its result with the decisions
//!   as forms, its history, comments and event log) and, for `svs:admin`, the Test hosts tab, over the
//!   `svs_run_reads`, `svs_decisions` and `svs` services. The base layout links to it for whoever holds
//!   `svs:run_read`. Batch 7b brought the run page's alerts, association forms and review, and a person's
//!   take, cancel, end and close of runs, over `svs_review` and `svs_association`.
//! - `svs_coverage`: the SVS area's Tests, Coverage and Worklist tabs (PLAN.md 7.10 batch 8), ace3's
//!   `tests.html`, `test.html`, `coverage.html`, `coverage_detail.html`, `worklist.html` and
//!   `worklist_signature.html`: the catalog's tests with their state and run history, a test's page with
//!   its settings and decisions, coverage per technique and platform with a technique's drill-down, and
//!   the declared-vs-measured worklist with its resolutions as forms, over the `svs_catalog`,
//!   `svs_coverage`, `svs_worklist` and `svs_decisions` services.
//! - `svs_alert`: what SVS makes of an alert, on its page (PLAN.md 7.10 batch 7b): ace3's SVS banner, with
//!   the root's tags, and the forms that give the alert back to analysts. The alert list shows the same
//!   status and tags beside each alert's description (`list`).
//! - `help`: the help area (5.11's help area, with PLAN.md 7.10 batch 9), ace3's `app/help`: the
//!   training guides, Markdown embedded in the binary and drawn as pages for any signed-in user, with
//!   the SVS guide set. The base layout links to it as Documentation, and beside its SVS link says how
//!   many test runs need attention.
//! - `events`: the events area under `event:read` (5.11's events area): ace3's event list with its
//!   filters, sorts and CSV export, an event's page with Close Event behind a confirm, and its
//!   add-to-event modal as a page, opened from the alert list's bulk form, and Create Event, the same
//!   page with no alerts, over `Service::add_to_event`; an event's edit, its alerts removed or
//!   dispositioned, and its own tags (6d). The base layout links to the list for whoever holds
//!   `event:read`.
//!
//! - `remediation`: the remediations and file collections areas (5.11, brought by 7.9), ace3's
//!   `remediation/manage.html` and `file_collection/manage.html`: each list with its screen's filters, a
//!   row's page with its tries, its forms, Add Remediation and Request File Collection, over the `remediation` and
//!   `file_collections` services, and the event page's remediation coverage badges. The base layout links
//!   to each for whoever holds its `:read`.
//!
//! - `search`: ace3's search box and its "similar alerts" (PLAN.md 7.11), as a page whose URL says the
//!   search, `/search`, which the alert list's box and an alert's page lead to, over
//!   `Service::search_alerts` and `Service::similar_alerts`.
//!
//! From ace3's `app/templates/base.html` and `core.html`, and what differs: the layout keeps ace3's
//! theme attribute on `<html>`, its five themes and its log out by POST. It has none of ace3's jQuery,
//! Bootstrap, Google Fonts or CDN links: the stylesheet is this crate's own, and Datastar is the only
//! script but on the graph's page, which adds vis.js and its own. ace3's inline script that resolves the
//! `system` theme is a `prefers-color-scheme` rule in the stylesheet, so the page has no inline script.
//! Its navigation links come with the pages they lead to (5.8 to 5.11). `/` is the alert list, as ace3's home page is its manage page.

use ace_service::{Service, Transport};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

pub mod actions;
pub mod admin;
pub mod alert;
pub mod alert_actions;
pub mod alert_comments;
pub mod analysis;
pub mod analyze;
mod assets;
mod auth;
pub mod cli;
pub mod commonalities;
pub mod detection;
pub mod events;
mod headers;
pub mod help;
pub mod icons;
pub mod list;
pub mod monitoring;
mod places;
pub mod preferences;
pub mod remediation;
pub mod saved_filters;
pub mod search;
mod session;
pub mod signatures;
pub mod svs;
pub mod svs_alert;
pub mod svs_coverage;
pub mod svs_samples;
pub mod svs_validations;
pub mod templates;
pub mod verdicts;

pub use actions::{ObservableAction, ObservableActions};
pub use alert::LiveLimits;
pub use alert_actions::{AlertAction, AlertActionTarget, AlertActions};
pub use analysis::summary::{
    AlertSummary, EmailBody, MAX_BODY_BYTES, MAX_BODY_EMAILS, Summaries as AlertSummaries,
    SummaryEntry, SummaryInput,
};
pub use analysis::{AnalysisView, ViewEntry, Views};
pub use assets::{Asset, asset_named};
pub use headers::content_security_policy;
pub use icons::{PivotIcon, PivotIcons};

/// The largest form a page posts. A login's is a name and a password of at most
/// `ace_service::MAX_PASSWORD_BYTES`.
const MAX_FORM_BYTES: usize = 16 << 10;

/// What every handler gets: the service, and whether the browser reaches this server over TLS, which
/// the site's configuration says (`ace_api::WebConfig::transport`, from `ACE_RS_WEB_TLS`) and the session
/// cookie follows.
#[derive(Clone)]
pub struct Gui {
    service: Service,
    transport: Transport,
    live: std::sync::Arc<alert::Live>,
    views: std::sync::Arc<Views>,
    actions: std::sync::Arc<ObservableActions>,
    alert_actions: std::sync::Arc<AlertActions>,
    summaries: std::sync::Arc<AlertSummaries>,
    icons: std::sync::Arc<icons::PivotIcons>,
    refreshes: std::sync::Arc<places::Places>,
    cli_refreshes: std::sync::Arc<places::Places>,
    svs_attention: std::sync::Arc<session::NavCount>,
    limits: analyze::SubmissionLimits,
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
            alert_actions: std::sync::Arc::new(AlertActions::empty()),
            summaries: std::sync::Arc::new(AlertSummaries::builtin()),
            icons: std::sync::Arc::new(icons::PivotIcons::builtin()),
            refreshes: std::sync::Arc::new(places::Places::new(
                list::REFRESH_LIMITS.0,
                list::REFRESH_LIMITS.1,
            )),
            cli_refreshes: std::sync::Arc::new(places::Places::new(
                cli::REFRESH_LIMITS.0,
                cli::REFRESH_LIMITS.1,
            )),
            svs_attention: std::sync::Arc::new(session::NavCount::new(
                session::SVS_ATTENTION_FRESH,
            )),
            limits: analyze::SubmissionLimits::default(),
        }
    }

    /// The GUI reading the navigation's count of runs that need attention again once it is this old,
    /// rather than `session`'s default.
    pub fn with_svs_attention_fresh(mut self, fresh: std::time::Duration) -> Self {
        self.svs_attention = std::sync::Arc::new(session::NavCount::new(fresh));
        self
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

    /// The GUI offering these alert actions on the alert page (PLAN.md decision 55), the site's, rather
    /// than ace-rs's own, which are none.
    pub fn with_alert_actions(mut self, actions: AlertActions) -> Self {
        self.alert_actions = std::sync::Arc::new(actions);
        self
    }

    /// The GUI drawing an alert's summary by its type with these (`analysis::summary`), the binary's
    /// list, rather than the open-source ones alone.
    pub fn with_summaries(mut self, summaries: AlertSummaries) -> Self {
        self.summaries = std::sync::Arc::new(summaries);
        self
    }

    /// The GUI serving these pivot link icons (PLAN.md decision 32 part (b)), the binary's list,
    /// rather than ace-rs's own, which are none.
    pub fn with_icons(mut self, icons: icons::PivotIcons) -> Self {
        self.icons = std::sync::Arc::new(icons);
        self
    }

    /// The GUI holding the Analyze page's form to these limits (PLAN.md 7.18), the API's on a
    /// submission, rather than the defaults.
    pub fn with_submission_limits(mut self, limits: analyze::SubmissionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The icons a pivot link may name.
    pub(crate) fn icons(&self) -> &icons::PivotIcons {
        &self.icons
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
            .route("/search", get(search::page))
            .route(
                "/analyze",
                get(analyze::page)
                    .post(analyze::submit)
                    .layer(DefaultBodyLimit::max(self.limits.max_bytes)),
            )
            .route("/analyze/row", get(analyze::row))
            .route(
                "/alerts/disposition",
                post(list::bulk_disposition).layer(DefaultBodyLimit::max(
                    alert_comments::MAX_COMMENT_FORM_BYTES,
                )),
            )
            .route(
                "/alerts/comment",
                post(alert_comments::bulk).layer(DefaultBodyLimit::max(
                    alert_comments::MAX_COMMENT_FORM_BYTES,
                )),
            )
            .route(
                "/alerts/{id}/comments",
                post(alert_comments::add).layer(DefaultBodyLimit::max(
                    alert_comments::MAX_COMMENT_FORM_BYTES,
                )),
            )
            .route(
                "/alerts/{id}/comments/{comment}",
                post(alert_comments::change).layer(DefaultBodyLimit::max(
                    alert_comments::MAX_COMMENT_FORM_BYTES,
                )),
            )
            .route(
                "/alerts/owner",
                post(list::bulk_owner).layer(DefaultBodyLimit::max(list::MAX_BULK_FORM_BYTES)),
            )
            .route("/events", get(events::list_page))
            .route("/events/export", get(events::export))
            .route(
                "/events/add",
                get(events::add_page)
                    .post(events::add)
                    .layer(DefaultBodyLimit::max(events::MAX_ADD_FORM_BYTES)),
            )
            .route(
                "/events/tags",
                post(events::tag_events).layer(DefaultBodyLimit::max(list::MAX_BULK_FORM_BYTES)),
            )
            .route("/events/{event}", get(events::event_page))
            .route(
                "/events/{event}/close",
                get(events::confirm_close).post(events::close),
            )
            .route(
                "/events/{event}/edit",
                get(events::edit_page)
                    .post(events::save_edit)
                    .layer(DefaultBodyLimit::max(events::MAX_EDIT_FORM_BYTES)),
            )
            .route(
                "/events/{event}/alerts/remove",
                post(events::remove_alerts).layer(DefaultBodyLimit::max(list::MAX_BULK_FORM_BYTES)),
            )
            .route(
                "/events/{event}/tags",
                post(events::add_tags).layer(DefaultBodyLimit::max(list::MAX_BULK_FORM_BYTES)),
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
                "/admin/detection",
                get(detection::page).post(detection::add),
            )
            .route(
                "/admin/detection/{id}/expiration",
                post(detection::set_expiration),
            )
            .route("/admin/detection/{id}/delete", post(detection::delete))
            .route("/admin/monitoring", get(monitoring::page))
            .route("/admin/cli", get(cli::console).post(cli::start))
            .route("/admin/cli/{id}", get(cli::run_page))
            .route("/admin/cli/{id}/output", get(cli::output))
            .route("/admin/cli/{id}/cancel", post(cli::cancel))
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
            .route("/svs", get(svs::home))
            .route("/svs/runs", get(svs::runs))
            .route("/svs/runs/batches", get(svs::batches))
            .route("/svs/runs/{run_id}", get(svs::run))
            .route("/svs/runs/bulk", post(svs::bulk))
            .route("/svs/runs/{run_id}/alerts", post(svs::associate))
            .route("/svs/runs/{run_id}/review", post(svs::review))
            .route("/svs/runs/{run_id}/decide", post(svs::decide))
            .route("/svs/runs/{run_id}/comments", post(svs::comment))
            .route(
                "/svs/runs/{run_id}/comments/{id}",
                post(svs::change_comment),
            )
            .route(
                "/svs/test-hosts",
                get(svs::test_hosts).post(svs::add_test_host),
            )
            .route(
                "/svs/test-hosts/{id}",
                get(svs::test_host).post(svs::change_test_host),
            )
            .route("/svs/test-hosts/{id}/delete", post(svs::remove_test_host))
            .route("/svs/tests", get(svs_coverage::tests))
            .route("/svs/tests/{guid}", get(svs_coverage::test))
            .route(
                "/svs/tests/{guid}/settings",
                post(svs_coverage::test_settings),
            )
            .route("/svs/tests/{guid}/decide", post(svs_coverage::test_decide))
            .route(
                "/svs/tests/{guid}/exclusion",
                post(svs_coverage::test_exclusion),
            )
            .route("/svs/coverage", get(svs_coverage::coverage))
            .route("/svs/coverage/{technique}", get(svs_coverage::technique))
            .route("/svs/worklist", get(svs_coverage::worklist))
            .route(
                "/svs/worklist/resolve",
                post(svs_coverage::resolve_many)
                    .layer(DefaultBodyLimit::max(svs_coverage::MAX_WORKLIST_FORM_BYTES)),
            )
            .route(
                "/svs/worklist/{signature_uuid}",
                get(svs_coverage::worklist_signature),
            )
            .route(
                "/svs/worklist/{signature_uuid}/resolve",
                post(svs_coverage::resolve)
                    .layer(DefaultBodyLimit::max(svs_coverage::MAX_WORKLIST_FORM_BYTES)),
            )
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
            .route("/signatures/samples", get(svs_samples::samples))
            .route("/signatures/validations", get(svs_validations::validations))
            .route(
                "/signatures/validations/{uuid}",
                get(svs_validations::validation),
            )
            .route(
                "/signatures/samples/{sha256}/delete",
                get(svs_samples::confirm_delete)
                    .post(svs_samples::delete)
                    .layer(DefaultBodyLimit::max(svs_samples::MAX_SAMPLE_FORM_BYTES)),
            )
            .route(
                "/signatures/samples/{sha256}/{rule_uuid}",
                get(svs_samples::sample),
            )
            .route(
                "/signatures/samples/{sha256}/{rule_uuid}/label",
                post(svs_samples::label)
                    .layer(DefaultBodyLimit::max(svs_samples::MAX_SAMPLE_FORM_BYTES)),
            )
            .route(
                "/signatures/samples/{sha256}/{rule_uuid}/confirm",
                post(svs_samples::confirm),
            )
            .route(
                "/signatures/samples/{sha256}/{rule_uuid}/retire",
                post(svs_samples::retire)
                    .layer(DefaultBodyLimit::max(svs_samples::MAX_SAMPLE_FORM_BYTES)),
            )
            .route(
                "/signatures/samples/{sha256}/{rule_uuid}/unretire",
                post(svs_samples::unretire),
            )
            .route("/alerts/{id}", get(alert::page))
            .route("/alerts/{id}/live", get(alert::live))
            .route("/alerts/{id}/graph", get(alert::graph_page))
            .route("/alerts/{id}/results/{result}", get(alert::result_page))
            .route(
                "/alerts/{id}/detections/{detection}/verdict",
                post(verdicts::set),
            )
            .route("/alerts/{id}/detections/confirm", post(verdicts::confirm))
            .route("/alerts/{id}/svs", post(svs_alert::release))
            .route(
                "/alerts/{id}/observables/{observable}/comment",
                get(actions::comment_page)
                    .post(actions::add_comment)
                    .layer(DefaultBodyLimit::max(actions::MAX_COMMENT_FORM_BYTES)),
            )
            .route(
                "/alerts/{id}/observables/{observable}/directives",
                get(actions::directive_page)
                    .post(actions::add_directives)
                    .layer(DefaultBodyLimit::max(actions::MAX_DIRECTIVE_FORM_BYTES)),
            )
            .route(
                "/remediations",
                get(remediation::remediations).post(remediation::queue),
            )
            .route("/remediations/targets", get(remediation::targets))
            .route("/remediations/{id}", get(remediation::remediation))
            .route(
                "/remediations/{id}/{what}",
                post(remediation::remediation_write),
            )
            .route(
                "/file-collections",
                get(remediation::collections).post(remediation::request),
            )
            .route("/file-collections/new", get(remediation::request_form))
            .route("/file-collections/{id}", get(remediation::collection))
            .route(
                "/file-collections/{id}/{what}",
                post(remediation::collection_write),
            )
            .route("/help", get(help::index))
            .route("/help/{set}", get(help::set_home))
            .route("/help/{set}/", get(help::set_home))
            .route("/help/{set}/{guide}", get(help::guide))
            .route("/help/{set}/images/{file}", get(help::image))
            .route("/static/{name}", get(assets::serve))
            .route("/icons/{file}", get(icons::serve))
            .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
            .layer(axum::middleware::from_fn(headers::secure))
            .layer(axum::middleware::from_fn(session::with_source))
            .with_state(self.clone())
    }
}
