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
//! (`Service::authenticate_request`), but the document itself and `GET /api/health/v1/ping`, which the
//! document marks as taking none.
//!
//! What ace3's alerts, analysis and observables routers do (PLAN.md 5.5), and where each went:
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
//!
//! ace3's `users` router (PLAN.md 5.6), and its Flask password change, under `/api/users/v1`:
//!
//! | ace3 | here |
//! |---|---|
//! | `GET /users/management-view` | its parts: `GET /users`, `GET /groups` and `GET /catalog` |
//! | `GET /users/details?user_ids=` | `GET /users/{id}`, one user, with their grants and groups |
//! | `GET /users/catalog` | `GET /catalog` |
//! | `POST /users/` | `POST /users`, with no grants or groups |
//! | `PATCH /users/` | per user: `PATCH /users/{id}` for the profile, `PUT /users/{id}/enabled`, `PUT /users/{id}/password` |
//! | the `groups` of `POST` and `PATCH /users/` | `PUT` and `DELETE /groups/{id}/members/{user}` |
//! | the `permissions` of `POST` and `PATCH /users/`, and `POST /users/permissions` | `POST /grants`, to a user, group or key |
//! | `POST /users/permissions/delete`, by row ids | `POST /grants/revoke`, by holder, pattern and effect |
//! | `POST /users/groups`, `POST /users/groups/delete` | `POST /groups`, `DELETE /groups/{id}` |
//! | `GET /users/{id}/apikeys` | `GET /keys?owner={id}`, or every key, ownerless ones included |
//! | `POST /users/{id}/apikeys` | `POST /keys`, with an `owner` or none |
//! | `PUT`, `DELETE /users/apikeys/{id}` | `PUT`, `DELETE /keys/{id}` |
//! | `GET`, `PATCH /users/me` | `GET`, `PATCH /me` |
//! | the Flask `/auth/login/change` | `PUT /me/password`, which also clears the session's cookie |
//! | `GET`, `POST /users/me/apikeys`, `PUT`, `DELETE /users/me/apikeys/{id}` | the same under `/me/keys` |
//!
//! What differs, or is left out, and why:
//! - ace3 changes many users in one `PATCH`, with their grants and groups. Here each change is its own
//!   request and its own audit row, through the service functions 5.4 and this step made.
//! - ace3's `inherit` flag on a key is a scope of `*:*` (`ace_service`'s gate docs), and a key's scope
//!   update keeps any deny on it. A revoke of a key that isn't there, or isn't the caller's, is a 404
//!   rather than ace3's `{"revoked": false}`.
//! - ace3 lets an API key that inherits its owner's scope read and change its owner's `/me`. Here only a
//!   user has an account, so every key gets 403.
//! - A user's `queue`: alerts have no queues yet (PLAN.md 7.13).
//! - Login and logout are ace3's Flask views, and come with the GUI's login page (5.7), which sets the
//!   cookie this API reads. ace3's held catalog, the scope picker of a user's own keys, has no route in
//!   its router: it comes with the preferences page (5.11).
//!
//! ace3's `health` router (PLAN.md 5.6):
//!
//! | ace3 | here |
//! |---|---|
//! | `GET /health/ping`, `{"result": "pong"}` with no credential | `GET /api/health/v1/ping`, the same |
//!
//! Nothing is left out. Like ace3's, it checks no database or bucket (`health`'s docs say why).
//!
//! ace3's `observable_types` router (PLAN.md 5.6), under `observable:read` as there:
//!
//! | ace3 | here |
//! |---|---|
//! | `GET /observable-types/`, `{"data": [{"name": ...}]}` | `GET /api/observables/v1/types`, `{"types": [...]}` |
//!
//! ace3 gives each type's name. Here each also has its parent, deprecated flag, default display type
//! and description, which ace3 keeps in the same registry but doesn't serve. The list is the running
//! binary's, a site's own types among them (PLAN.md 2.31), sorted by name with deprecated types
//! included, as ace3's is. Left out: ace3's 60-second cache and its `Cache-Control: private, max-age=60`,
//! which exist because ace3 reloads its YAML while it runs; ace4's list is fixed when the binary is
//! built. The GUI's observable actions are 5.9's (ace3 #1032), not this router's.
//!
//! ace3's `crashes` router (PLAN.md 5.6), under `crash:read` as there. An ace3 crash report is a failed
//! task here (`ace_service`'s `crashes` docs), and its crash id is the task's id:
//!
//! | ace3 | here |
//! |---|---|
//! | `GET /crashes/?root_uuid=&module=&limit=&offset=` | `GET /api/crashes/v1/crashes?root=&module=&limit=&after=`, newest failure first, a page at a time |
//! | `GET /crashes/{crash_id}` | `GET /api/crashes/v1/crashes/{id}`, with the file's paths and whether the bucket has each input |
//! | `GET /crashes/{crash_id}/download` | `GET /api/crashes/v1/crashes/{id}/download`, the same zip and password with AES-256, audited |
//!
//! What differs, or is left out, and why:
//! - ace3's `crash_type` filter and field (`exception`, `timeout`, `killed`): a failed task has no type
//!   column, and its error says which, as "the module panicked", "ran past its deadline" or "killed by".
//! - The `node` filter, `local`, `remote`, `downloadable` and the 409 `wrong_node`: every node reads one
//!   bucket and one queue, so any node serves any failed task.
//! - `offset`: a cursor, as the alert list has, so a page doesn't shift while tasks fail.
//! - `module` matches a module's key. ace3 also matches a Python module path, which ace4 doesn't have.
//! - ace3's report holds the traceback, the hung thread's stacks and the analysis tree. A task's error is
//!   its whole record, and the tree is the alert's, at `/api/alerts/v1`. `complete` and `omitted` are
//!   about a report written while its worker died: a row is written in one transaction, and the zip's
//!   `task.json` lists as `omitted` an input the bucket no longer has.
//! - No write. ace3's router has none, and neither does its GUI. A failed task is final in the queue, so
//!   a retry would need the queue to allow one; `ace task replay` runs one again on a laptop and changes
//!   nothing. ace3's `ace crash prune` and `sync` are the bucket's GC and its single store.
//!
//! ace3's `yara_qa` router (PLAN.md 5.6), under ace3's `signature:read`, `signature:download` and
//! `signature:qa_purge` (`ace_service`'s `yara_qa` docs). A rule is named by its `uuid` meta, as there:
//!
//! | ace3 `/api/v2/signatures/yara-qa` | here |
//! |---|---|
//! | `GET /?q=&status=&has_matches=&sort=&descending=&limit=&offset=` | `GET /api/yara-qa/v1/rules`, the same filters, order and paging |
//! | `GET /{signature_uuid}` | `GET /api/yara-qa/v1/rules/{uuid}`, with its versions |
//! | `GET /{signature_uuid}/matches?version=&limit=&offset=` | `GET /api/yara-qa/v1/rules/{uuid}/matches?version=&limit=&after=`, newest first |
//! | `GET /{signature_uuid}/download?version=&match_id=` | `GET /api/yara-qa/v1/rules/{uuid}/download?version=&match_ids=`, ids separated by commas, audited |
//! | `POST /{signature_uuid}/purge` | `POST /api/yara-qa/v1/rules/{uuid}/purge`, the same body, audited |
//! | `GET /matches/{match_id}` | `GET /api/yara-qa/v1/matches/{id}`, with its record in short |
//! | `GET /matches/{match_id}/record` | `GET /api/yara-qa/v1/matches/{id}/record`, inline JSON with `nosniff` |
//! | `GET /matches/{match_id}/download` | `GET /api/yara-qa/v1/matches/{id}/download`, audited |
//!
//! What differs, or is left out, and why:
//! - The rules in QA mode come from the current ruleset's row (2.25), whose manifest now lists them, where
//!   ace3 reads its rule files every 60 seconds. ace3's `inventory_error` becomes the page's `ruleset`:
//!   null when none was built, and `qa_rules_recorded` false for a row built before the list existed,
//!   which the builder fills in on its next run.
//! - `status` is `qa` or `not_qa`. ace3's `missing`, a uuid no loaded rule has, needs every rule's uuid,
//!   and the manifest records only the QA rules', so a rule that left the repository is `not_qa` here.
//!   `current_version` and `current_content_hash` become the ruleset's `commit` and `key`, the same for
//!   every rule.
//! - A version is the commit of the rule's repository, as 2.27 records it, so there's no `version_kind`,
//!   `first_commit` or `last_commit`: ace3's content hash of a rule isn't computed here.
//! - ace3 keeps at most 25 files per version and 250 per rule, counting the rest, and rolls old versions
//!   over. 2.27 keeps every file, so `match_count` is the sum of each file's hits and `stored_count` the
//!   files not yet expired.
//! - `node`, `local` and the 409 `wrong_node`: every node reads one bucket.
//! - A download's entries are `<label>/<id>/<sha256>`, `<label>/<id>/match.json` and
//!   `<label>/manifest.json`, so nothing a file or a rule was named becomes an entry's name. A file the
//!   bucket no longer has is listed with a null `file`, where ace3 lists one on another node as `skipped`.
//!   `match_id` repeated is `match_ids` with commas, which axum's query reader takes.
//! - A purge removes up to 500 matches in one transaction with its audit row, and says how many are
//!   left, where ace3 deletes in batches that commit one by one and audits first. The audit row lists
//!   each match removed. A purge that finds nothing has no row, as a write that changes nothing.
//! - ace3's daily prune of expired rows: 2.27's holds expire on their own, and an expired row isn't
//!   listed or served here. Deleting the rows is the scheduler's (6.7).
//! - `ace yara-qa list` and the GUI page come with 5.11's signatures area.
//!
//! ace3's `observable_comments` router (PLAN.md 5.6), under ace3's `observable:read` and `observable:write`
//! (`ace_service`'s `observable_comments` docs). A comment is on a type and value, across alerts:
//!
//! | ace3 `/api/v2/observable-comments` | here |
//! |---|---|
//! | `GET /{observable_id}` | `GET /api/observables/v1/comments?type=&value=`, oldest first |
//! | `POST /`, `{observable_type, observable_value, comment}` | `POST /api/observables/v1/comments`, `{type, value, comment}` |
//! | `PATCH /{comment_id}` | `PATCH /api/observables/v1/comments/{id}`, audited |
//! | `DELETE /{comment_id}` | `DELETE /api/observables/v1/comments/{id}`, audited |
//!
//! What differs, or is left out, and why:
//! - ace3 names an observable by the id of its row in its index of every observable, which a comment
//!   creates when it's missing. ace4 has no index, so a list names the type and value, and a comment's
//!   own row holds them. There's no `observable_id`.
//! - The author is `author`, with the user's id, username and display name now, and `created_by` is the
//!   actor that wrote it, a key when the user's key did. ace3 gives `user_id` and `user_display_name`.
//! - An API key with no owner is refused with 403, where ace3 answers 401: it authenticated, but has no
//!   user to be the author. Another user's comment is a 403, as in ace3.
//! - A comment is 1 to 16384 characters and not all whitespace, where ace3's API takes any text and its
//!   GUI refuses an empty one.
//! - ace3's upload of a file into an alert saves the form's comment as a comment on that file. ace4 has no
//!   such upload yet; it can call `Service::add_observable_comment`. The alert view's comments come with
//!   it in 5.8, through `Service::alert_observable_comments`.

use std::net::SocketAddr;

use ace_core::bucket::Bucket;
use ace_service::{Service, Transport};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post, put};
use utoipa::OpenApi;

mod alerts;
mod analysis;
mod auth;
mod crashes;
mod error;
mod health;
mod observable_comments;
mod observables;
mod users;
mod yara_qa;

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
            .route("/api/health/v1/ping", get(health::ping))
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
            .route(
                "/api/observables/v1/types",
                get(observables::observable_types),
            )
            .route(
                "/api/observables/v1/comments",
                get(observable_comments::list)
                    .post(observable_comments::add)
                    .layer(json_limit),
            )
            .route(
                "/api/observables/v1/comments/{id}",
                patch(observable_comments::edit)
                    .delete(observable_comments::delete)
                    .layer(json_limit),
            )
            .route("/api/crashes/v1/crashes", get(crashes::list))
            .route("/api/crashes/v1/crashes/{id}", get(crashes::one))
            .route(
                "/api/crashes/v1/crashes/{id}/download",
                get(crashes::download),
            )
            .route("/api/yara-qa/v1/rules", get(yara_qa::rules))
            .route("/api/yara-qa/v1/rules/{uuid}", get(yara_qa::rule))
            .route(
                "/api/yara-qa/v1/rules/{uuid}/matches",
                get(yara_qa::matches),
            )
            .route(
                "/api/yara-qa/v1/rules/{uuid}/download",
                get(yara_qa::download_rule),
            )
            .route(
                "/api/yara-qa/v1/rules/{uuid}/purge",
                post(yara_qa::purge).layer(json_limit),
            )
            .route("/api/yara-qa/v1/matches/{id}", get(yara_qa::one_match))
            .route("/api/yara-qa/v1/matches/{id}/record", get(yara_qa::record))
            .route(
                "/api/yara-qa/v1/matches/{id}/download",
                get(yara_qa::download_match),
            )
            .merge(self.users_router())
            .layer(axum::middleware::from_fn(auth::with_source))
            .with_state(self.clone())
    }
}

impl Web {
    /// `/api/users/v1`, every body held to `max_json_bytes`.
    fn users_router(&self) -> Router<Web> {
        Router::new()
            .route(
                "/api/users/v1/users",
                get(users::list_users).post(users::create_user),
            )
            .route(
                "/api/users/v1/users/{id}",
                get(users::user).patch(users::update_user),
            )
            .route("/api/users/v1/users/{id}/enabled", put(users::set_enabled))
            .route(
                "/api/users/v1/users/{id}/password",
                put(users::reset_password),
            )
            .route(
                "/api/users/v1/groups",
                get(users::list_groups).post(users::create_group),
            )
            .route("/api/users/v1/groups/{id}", delete(users::delete_group))
            .route(
                "/api/users/v1/groups/{id}/members/{user}",
                put(users::add_member).delete(users::remove_member),
            )
            .route("/api/users/v1/grants", post(users::grant))
            .route("/api/users/v1/grants/revoke", post(users::revoke))
            .route("/api/users/v1/catalog", get(users::catalog))
            .route(
                "/api/users/v1/keys",
                get(users::list_keys).post(users::create_key),
            )
            .route(
                "/api/users/v1/keys/{id}",
                put(users::update_key).delete(users::revoke_key),
            )
            .route("/api/users/v1/me", get(users::me).patch(users::update_me))
            .route("/api/users/v1/me/password", put(users::change_password))
            .route(
                "/api/users/v1/me/keys",
                get(users::my_keys).post(users::create_my_key),
            )
            .route(
                "/api/users/v1/me/keys/{id}",
                put(users::update_my_key).delete(users::revoke_my_key),
            )
            .layer(DefaultBodyLimit::max(self.config.max_json_bytes))
    }
}

/// The OpenAPI document of every route above but its own, which needs no credential. A route that needs
/// none either says `security(())`.
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
        observables::observable_types,
        observable_comments::list,
        observable_comments::add,
        observable_comments::edit,
        observable_comments::delete,
        users::list_users,
        users::create_user,
        users::user,
        users::update_user,
        users::set_enabled,
        users::reset_password,
        users::list_groups,
        users::create_group,
        users::delete_group,
        users::add_member,
        users::remove_member,
        users::grant,
        users::revoke,
        users::catalog,
        users::list_keys,
        users::create_key,
        users::update_key,
        users::revoke_key,
        users::me,
        users::update_me,
        users::change_password,
        users::my_keys,
        users::create_my_key,
        users::update_my_key,
        users::revoke_my_key,
        health::ping,
        crashes::list,
        crashes::one,
        crashes::download,
        yara_qa::rules,
        yara_qa::rule,
        yara_qa::matches,
        yara_qa::download_rule,
        yara_qa::purge,
        yara_qa::one_match,
        yara_qa::record,
        yara_qa::download_match,
    ),
    modifiers(&Schemes),
    security(("api_key" = []), ("session" = [])),
    tags(
        (name = "alerts", description = "Alerts, what modules found in them, and their dispositions"),
        (name = "analysis", description = "Submitting analysis"),
        (name = "observables", description = "Observables across alerts"),
        (name = "users", description = "Users, groups, grants and API keys, and the caller's own account"),
        (name = "health", description = "Whether the API answers"),
        (name = "crashes", description = "Failed tasks, their errors and their inputs"),
        (name = "yara_qa", description = "YARA rules in QA mode, the files they matched, and purges"),
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
