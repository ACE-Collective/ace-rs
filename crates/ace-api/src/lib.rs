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
//! | `GET /alerts?f=&cursor=&limit=&tz=` | `GET /api/alerts/v1/alerts?f=&sort=&dir=&tz=&after=&limit=`, newest first or in the order asked, a page at a time, with `total` (5.10's filters and orders) |
//! | `GET /alerts/{uuid}`, `/meta` | `GET /api/alerts/v1/alerts/{id}`, and its observables, results and detections in pages at `/observables` |
//! | `GET /alerts/{uuid}/observables/{o}/zip`, `/download` | `GET /api/alerts/v1/alerts/{id}/observables/{o}/file`, one file, audited |
//! | the GUI's disposition | `PUT /api/alerts/v1/alerts/{id}/disposition` |
//! | `POST /analysis` | `POST /api/analysis/v1/submit` |
//! | `POST /observables/lookup` | `POST /api/observables/v1/lookup` |
//! | `GET /alerts/export/csv`, `/export/ndjson` (5.10) | `GET /api/alerts/v1/alerts/export/csv`, `/export/ndjson`, up to 100,000 alerts, or 413 |
//!
//! Left out, each for a reason:
//! - The list's `f` takes ace3's share-link encoding and slugs, and the filters ace4's alerts have fields
//!   for (`ace_service::filters`). Its order is ace3's manage page's: by when each became an alert, the
//!   title or the disposition, either way, where ace3's API pages in id order. ace3's `changed_since` on
//!   the alert list, its `(updated_at, id)` order, needs a time a root last changed, which roots don't
//!   record. `count` is the list's `total`. `date-range`, the window a relative token means now, waits for
//!   an editor that shows it; `ace_service::filters::date_window` computes it.
//! - The ETag and 304 on an alert: ace4 has no version counter, and 5.8 pushes changes to an open page.
//! - `/download` of a whole alert's directory: ace4 has none, and each file downloads on its own.
//! - `/text`, `/hex` and `/image` views of a file, and the alert's `saq.log`, belong to the alert view
//!   (5.8, 5.9). ace4 keeps a task's error on its row, not in a log file.
//! - `PUT /owner`, comment editing and `bulk-add-observable`: roots have no owner or comments yet, and an
//!   observable added by hand needs a decision about what it does to a dispositioned alert's analysis.
//! - `collect-file`, `render`, `crawl`, `check-for-clickers` and `clicker-searches` ask modules for more
//!   analysis on one observable. File collection is 7.9 and phishkit 7.7, and the clicker check needs the
//!   core to rerun a module on an observable that has its result, which nothing does yet.
//! - Detection points are their own router in 5.6, below.
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
//! - Login and logout are ace3's Flask views, and are the GUI's (`ace-gui`, 5.7), which sets the cookie
//!   this API reads. ace3's held catalog, the scope picker of a user's own keys, has no route in
//!   its router: it comes with the preferences page (5.11).
//!
//! ace3's `user_preferences` router (PLAN.md 5.6, 5.7), the caller's own, with no grant, as there
//! (`ace_service`'s `preferences` docs):
//!
//! | ace3 `/api/v2/users/me/preferences` | here, under `/api/users/v1/me/preferences` |
//! |---|---|
//! | `GET /`, `{"data": {key: ...}}` | `GET`, `{"preferences": [...]}` in key order |
//! | `GET /{key}` | `GET /{key}` |
//! | `PUT /{key}`, the value as the body | `PUT /{key}`, the same |
//! | `DELETE /{key}`, answering the default | `DELETE /{key}`, the same |
//!
//! What differs: the keys are `theme`, 5.8's `alert_sections` and 5.10's `manage_columns`. A
//! value that isn't its key's is 400 where ace3 answers 422 with pydantic's errors. ace3 lets an API key
//! that inherits its owner's scope use these; here a key is refused with 403, as with the rest of `/me`.
//! Each set and reset that changes something has an audit row, which ace3 doesn't write.
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
//!
//! ace3's `detection_points` router (PLAN.md 5.6), and its alerts router's list of one alert's, under
//! `alert:read` as there (`ace_service`'s `detection_points` docs):
//!
//! | ace3 `/api/v2` | here |
//! |---|---|
//! | `GET /detection-points/?cursor=&limit=` | `GET /api/alerts/v1/detections?after=&limit=`, oldest first, a page at a time |
//! | `GET /alerts/{uuid}/detection-points` | `GET /api/alerts/v1/detections?alert={id}`, paged the same way |
//!
//! What differs, or is left out, and why:
//! - The path is under `alerts`, since a detection is an alert's. ace3's `detection` router, its list of
//!   observables to detect, is another thing and comes with 7.6.
//! - The `f` filters (5.10) are the detection points screen's that ace4 has fields for: `alert_date`,
//!   `family` and `signature`. `queue`, `verdict`, `source` and `has_override` come with alert routing
//!   (7.13) and verdicts (7.14). `changed_since` is a detection made, or whose root became an alert, at or
//!   after the time, where ace3 also counts a verdict's change. The exports, `export/csv` and
//!   `export/ndjson`, page through this list to the end, and refuse more than 100,000 rows with 413.
//! - `verdict`, `verdict_source`, `override`, `override_user` and `override_set_at`, the verdict writes
//!   under `/alerts/{uuid}/detection-points/{content_hash}/verdict` and the alert's `confirm` come with
//!   detection verdicts in 7.14.
//! - ace3's `content_hash` keys verdicts, so it comes with 7.14 too. A detection is named by its `id` here.
//! - ace3's `node_kind`, `node_type`, `node_value_sha256` and `node_module_path` become `observable`, the
//!   one it's on with its type and value, and `module`, the module whose result raised it. ace4 stores a
//!   detection on an analysis on the observable that was analyzed (`ace_core::normal`'s docs), so ace3's
//!   `analysis` and `observable` kinds aren't told apart, and its `root` kind has no row: every detection
//!   here is on an observable.
//! - `details` is the JSON that was written, where ace3 stores text and parses it back, falling back to
//!   the text when it isn't JSON.
//! - ace3 scopes the list to the alerts its node shows. Every node here shows every alert.
//!
//! ace3's `events`, `threat_types` and `threats` routers (PLAN.md 5.6, 5.11) are under `/api/events/v1`, and
//! `events`' docs map them.
//!
//! ace3's `filter_screens` and `saved_filters` routers (PLAN.md 5.6, 5.10), under the screen's permission,
//! `alert:read` for both screens here, as in ace3 (`ace_service`'s `filters` and `saved_filters` docs):
//!
//! | ace3 `/api/v2` | here, under `/api/filters/v1` |
//! |---|---|
//! | `GET /filter-screens/{screen}` | `GET /screens/{screen}`, with each filter's kind for every screen, and `left_out` |
//! | `POST /filter-screens/{screen}/encode` | `POST /screens/{screen}/encode` |
//! | `GET /filter-screens/{screen}/decode?f=` | `GET /screens/{screen}/decode?f=` |
//! | `GET /saved-filters/?screen=` | `GET /saved?screen=` |
//! | `POST /saved-filters/?screen=` | `POST /saved?screen=`, audited |
//! | `GET`, `PATCH`, `DELETE /saved-filters/{uuid}` | `GET`, `PATCH`, `DELETE /saved/{id}`, the writes audited |
//! | `PUT /saved-filters/quick-filters?screen=` | `PUT /saved/quick?screen=`, `{"ids": [...]}`, audited |
//!
//! What differs, or is left out, and why:
//! - Two of ace3's eleven screens: `alerts` and `detection_points`. The SVS, remediation and file
//!   collection screens come with their steps.
//! - A filter that isn't the screen's, or a value of the wrong shape, is 400 where ace3 answers 422 with
//!   pydantic's errors.
//! - `PUT /saved-filters/scratch/{kind}` and ace3's `working` and `temp` rows: the GUI's list keeps its
//!   filters in its URL, so there's nothing to hold between requests.
//! - An API key with no owner is refused with 403 where ace3 answers 401, as with comments. Each write has
//!   an audit row, and a user has at most 200 saved filters on a screen.
//!
//! ace3's `cli` router and the `engine` router's `cli` endpoint (PLAN.md 5.6, 5.12), under `cli:execute`
//! as in ace3 (`ace_service`'s `commands` docs). A command is queued for a parser pool, which runs it
//! contained until its deadline, so the session and the API that took it don't bound it (#973):
//!
//! | ace3 `/api/v2` | here, under `/api/cli/v1` |
//! |---|---|
//! | `POST /cli/executions`, one row per node | `POST /commands`, one run, 202, audited |
//! | `GET /cli/executions?cursor=&limit=` | `GET /commands?after=&limit=`, newest first, without output |
//! | `GET /cli/executions/{id}` | `GET /commands/{id}`, with its output so far |
//! | none | `POST /commands/{id}/cancel`, audited |
//! | `POST /engine/cli/{id}`, node to node with the automation key | the lease API's `POST /api/worker/v1/commands/lease`: a pool takes the run, rather than a node being told to start it |
//!
//! What differs, or is left out, and why:
//! - `node_ids` and a run per node, and the node's name on a run: one node runs here, and any pool that
//!   runs commands may take one. Multi-node is *Deferred*'s.
//! - ace3's `pending` is `queued`; ace3's statuses are otherwise kept, and `cancelled` is new, since ace3
//!   has no cancel. ace3 refuses more than 3 running at once on a node with 429; here a pool runs 3 at
//!   once and the rest wait queued, up to their timeout, after which they're `abandoned`.
//! - The timeout starts when a pool takes the run, which is its deadline; ace3's starts when its node
//!   does.
//! - ace3 refuses `--password` and other secret options. No ace4 command takes a secret on its command
//!   line, so nothing is refused for one; a leading option other than help or version is, as there.
//! - A key with no owner is refused with 403, as ace3 refuses a config key: a run names its person.
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
mod cli;
mod crashes;
mod detection_points;
mod error;
mod events;
mod export;
mod filters;
mod health;
mod observable_comments;
mod observables;
mod params;
mod user_preferences;
mod users;
mod yara_qa;

use auth::Schemes;

pub use error::ErrorBody;

/// Limits on what a request can make this node hold.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Whether the browser reaches this server over TLS, which turns on the session cookie's `Secure`
    /// attribute and `__Host-` name (`ace_service::SessionCookie`). The site says so with
    /// `ACE4_WEB_TLS=true`, set wherever TLS is terminated in front of `ace serve`. TLS isn't in the
    /// stack yet, so Compose leaves it unset, which is `Plain`. The GUI (`ace-gui`) is given the same.
    pub transport: Transport,
    /// The largest submission, files included. ace3 has no limit of its own.
    pub max_submission_bytes: usize,
    /// The largest JSON body, and the largest `analysis` field of a submission.
    pub max_json_bytes: usize,
    /// The most files one submission holds.
    pub max_submitted_files: usize,
    /// The most rows one export of a list holds.
    pub max_export_rows: i64,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            transport: Transport::Plain,
            max_submission_bytes: 1 << 30,
            max_json_bytes: 4 << 20,
            max_submitted_files: 1000,
            max_export_rows: export::MAX_EXPORT_ROWS,
        }
    }
}

impl WebConfig {
    /// The defaults, with the largest submission from `ACE4_MAX_SUBMISSION_BYTES` when it's set, and the
    /// transport from `ACE4_WEB_TLS`: `true` or `false`, and unset or empty is `false`. Any other value
    /// is an error, since a cookie setting that was misspelled shouldn't quietly become the weaker one.
    pub fn from_env() -> Result<Self, String> {
        let mut config = WebConfig::default();
        match std::env::var("ACE4_WEB_TLS").as_deref() {
            Ok("true") => config.transport = Transport::Tls,
            Ok("false" | "") | Err(std::env::VarError::NotPresent) => {}
            Ok(other) => return Err(format!("ACE4_WEB_TLS is {other:?}, not true or false")),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("ACE4_WEB_TLS isn't text".to_owned());
            }
        }
        if let Some(bytes) = std::env::var("ACE4_MAX_SUBMISSION_BYTES")
            .ok()
            .and_then(|bytes| bytes.parse().ok())
        {
            config.max_submission_bytes = bytes;
        }
        Ok(config)
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
            .route("/api/alerts/v1/alerts/export/csv", get(alerts::export_csv))
            .route(
                "/api/alerts/v1/alerts/export/ndjson",
                get(alerts::export_ndjson),
            )
            .route("/api/alerts/v1/detections", get(detection_points::list))
            .route(
                "/api/alerts/v1/detections/export/csv",
                get(detection_points::export_csv),
            )
            .route(
                "/api/alerts/v1/detections/export/ndjson",
                get(detection_points::export_ndjson),
            )
            .route("/api/filters/v1/screens/{screen}", get(filters::screen))
            .route(
                "/api/filters/v1/screens/{screen}/encode",
                post(filters::encode).layer(json_limit),
            )
            .route(
                "/api/filters/v1/screens/{screen}/decode",
                get(filters::decode),
            )
            .route(
                "/api/filters/v1/saved",
                get(filters::list).post(filters::create).layer(json_limit),
            )
            .route(
                "/api/filters/v1/saved/quick",
                put(filters::quick).layer(json_limit),
            )
            .route(
                "/api/filters/v1/saved/{id}",
                get(filters::one)
                    .patch(filters::update)
                    .delete(filters::delete)
                    .layer(json_limit),
            )
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
            .route("/api/events/v1/events/open", get(events::open))
            .route("/api/events/v1/events/export/csv", get(events::export_csv))
            .route("/api/events/v1/events/{event}", get(events::one))
            .route(
                "/api/events/v1/events/{event}/status",
                put(events::set_status).layer(json_limit),
            )
            .route(
                "/api/events/v1/threat-types",
                get(events::threat_types)
                    .post(events::create_threat_type)
                    .layer(json_limit),
            )
            .route(
                "/api/events/v1/threat-types/{id}",
                get(events::threat_type)
                    .patch(events::rename_threat_type)
                    .delete(events::delete_threat_type)
                    .layer(json_limit),
            )
            .route(
                "/api/events/v1/threats",
                get(events::threats)
                    .post(events::add_threat)
                    .layer(json_limit),
            )
            .route(
                "/api/events/v1/threats/{malware}/{threat_type}",
                delete(events::remove_threat),
            )
            .route(
                "/api/cli/v1/commands",
                get(cli::list).post(cli::start).layer(json_limit),
            )
            .route("/api/cli/v1/commands/{id}", get(cli::one))
            .route("/api/cli/v1/commands/{id}/cancel", post(cli::cancel))
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
            .route("/api/users/v1/me/preferences", get(user_preferences::list))
            .route(
                "/api/users/v1/me/preferences/{key}",
                get(user_preferences::one)
                    .put(user_preferences::set)
                    .delete(user_preferences::reset),
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
        alerts::export_csv,
        alerts::export_ndjson,
        detection_points::list,
        detection_points::export_csv,
        detection_points::export_ndjson,
        filters::screen,
        filters::encode,
        filters::decode,
        filters::list,
        filters::create,
        filters::one,
        filters::update,
        filters::delete,
        filters::quick,
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
        user_preferences::list,
        user_preferences::one,
        user_preferences::set,
        user_preferences::reset,
        health::ping,
        events::open,
        events::one,
        events::set_status,
        events::export_csv,
        events::threat_types,
        events::create_threat_type,
        events::threat_type,
        events::rename_threat_type,
        events::delete_threat_type,
        events::threats,
        events::add_threat,
        events::remove_threat,
        crashes::list,
        crashes::one,
        crashes::download,
        cli::start,
        cli::list,
        cli::one,
        cli::cancel,
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
        (name = "cli", description = "ace commands run from the GUI, contained on a pool until their deadline"),
        (name = "yara_qa", description = "YARA rules in QA mode, the files they matched, and purges"),
        (name = "events", description = "Events, the alerts in them, threat types and malware's threats"),
        (name = "filters", description = "A list screen's filters, their share links, and the caller's saved filters"),
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
