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
//! | the GUI's `GET /json?alert_uuid=`, which fed its vis.js graph until ace3 removed both in `9f63a496` (5.13) | `GET /api/alerts/v1/alerts/{id}/graph`, at most 1000 nodes and 2000 edges, with a note when cut |
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
//! ace3's `email` router (PLAN.md 5.6, 7.5 batch 9), under ace3's `email:read`, which serves the email
//! archive (`ace_core::email_archive`, `ace_service`'s `email_archive` docs):
//!
//! | ace3 | here |
//! |---|---|
//! | `GET /email/archive?message_id=`, the email as `message/rfc822` | `GET /api/email/v1/archive?message_id=`, the same, audited |
//!
//! What differs, or is left out, and why:
//! - The read is audited: the archive holds any alert's emails, and a read of an alert's file is audited
//!   here too. ace3 writes no row.
//! - The email is decrypted before the answer starts, so a failure to open it is a 500, where ace3 has
//!   started streaming and truncates. The core opens up to 64 MiB, as it archives.
//! - A missing `message_id` is 400, as the API's other bad queries; ace3's is FastAPI's 422.
//! - ace3 opens the file under its own node's hostname, so it can't serve an email another node archived;
//!   one bucket is every node's here.
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
//! ace3's `svs` routers' samples (PLAN.md 7.10 batch 2), under ace3's `signature:read`, `signature:download`,
//! `alert:write` with `signature:read` for the label actions, and `svs:admin` (`ace_service`'s
//! `svs_samples` docs). A sample is named by its file's sha256 and its rule's uuid meta:
//!
//! | ace3 `/api/v2/svs/samples` | here |
//! |---|---|
//! | `GET /?f=&sort=&desc=&changed_since=&cursor=&limit=&tz=` | `GET /api/svs/v1/samples`, the same filters, sorts and keyset paging |
//! | `GET /export/ndjson`, `GET /export/csv` | `GET /api/svs/v1/samples/export/ndjson`, `.../export/csv` |
//! | `GET /missing` | `GET /api/svs/v1/samples/missing` |
//! | `GET /captures/{capture_id}/record` | `GET /api/svs/v1/samples/captures/{id}/record`, inline JSON with `nosniff` |
//! | `GET /deletions?changed_since=&cursor=&limit=` | `GET /api/svs/v1/samples/deletions`, the same |
//! | `GET /download?f=&tz=` | `GET /api/svs/v1/samples/download`, audited |
//! | `GET /{sha256}/{rule_uuid}` | `GET /api/svs/v1/samples/{sha256}/{rule_uuid}` |
//! | `GET /{sha256}/{rule_uuid}/download` | `GET /api/svs/v1/samples/{sha256}/{rule_uuid}/download`, audited |
//! | `PUT`, `DELETE /{sha256}/{rule_uuid}/label` | `PUT`, `DELETE /api/svs/v1/samples/{sha256}/{rule_uuid}/label`, audited |
//! | `POST /{sha256}/{rule_uuid}/confirm` | `POST /api/svs/v1/samples/{sha256}/{rule_uuid}/confirm`, audited |
//! | `PUT`, `DELETE /{sha256}/{rule_uuid}/retirement` | `PUT`, `DELETE /api/svs/v1/samples/{sha256}/{rule_uuid}/retirement`, audited |
//! | `DELETE /{sha256}` | `DELETE /api/svs/v1/samples/{sha256}`, audited |
//!
//! What differs, or is left out, and why:
//! - A list's page is `{samples, next}` and the deletions' `{deletions, next}`, as the API's other pages,
//!   where ace3's are `{data, next_cursor}`; a bad request is 400 where ace3's is FastAPI's 422.
//! - A detection is named by its id, and a capture's alert by the root's id, where ace3 names a content hash
//!   and an alert uuid; a capture's observable is its id in the root.
//! - `node`, `local`, the 409 `wrong_node` and `legal_hold`: every node reads one bucket, which has no
//!   legal holds. A file the bucket no longer has is in a download's manifest with a null `file`.
//! - A key without an owner may act, as the actor is what's recorded, where ace3 answers 422.
//! - A download names each file by its sha256 in the zip, so nothing a sender named becomes an entry's
//!   name, as YARA QA's downloads do.
//! - A capture's `yara_version` is yara-x's, where ace3 has `yara_python_version` and
//!   `yara_scanner_version`.
//!
//! ace3's `svs` routers' YARA validations (PLAN.md 7.10 batch 3), under ace3's `svs:validate` (a rule
//! repository's CI: request and status), `signature:read` and `signature:download` (`ace_service`'s
//! `svs_validations` docs):
//!
//! | ace3 `/api/v2/svs/yara/validations` | here |
//! |---|---|
//! | `POST /`, 202 or 200 | `POST /api/svs/v1/yara/validations`, 202 or 200, audited |
//! | `GET /{uuid}/status` | `GET /api/svs/v1/yara/validations/{uuid}/status` |
//! | `GET /?f=&changed_since=&cursor=&limit=&tz=` | `GET /api/svs/v1/yara/validations`, the same filters and keyset paging |
//! | `GET /export/ndjson`, `GET /export/csv` | `GET /api/svs/v1/yara/validations/export/ndjson`, `.../export/csv` |
//! | `GET /{uuid}` | `GET /api/svs/v1/yara/validations/{uuid}` |
//! | `GET /{uuid}/results?category=&rule_uuid=&cursor=&limit=` | `GET /api/svs/v1/yara/validations/{uuid}/results` |
//! | `GET /{uuid}/results/export/ndjson`, `.../csv` | `GET /api/svs/v1/yara/validations/{uuid}/results/export/ndjson`, `.../csv` |
//! | `GET /{uuid}/download?category=&rule_uuid=` | `GET /api/svs/v1/yara/validations/{uuid}/download`, audited |
//!
//! What differs: a page is `{validations, next}` and `{results, next}`; a bad request is 400 where ace3's is
//! 422; a key without an owner may request one; the status's `report_path` is the GUI's
//! `/signatures/validations/{uuid}`; a download names each file by its sha256, and has no node to skip.
//!
//! ace3's `svs` routers' catalog (PLAN.md 7.10 batch 4), the Atomic Red Team tests runs may be registered
//! for, under ace3's `svs:run_read` (`ace_service`'s `svs_catalog` docs):
//!
//! | ace3 `/api/v2/svs` | here |
//! |---|---|
//! | `GET /tests/?f=&changed_since=&cursor=&limit=` | `GET /api/svs/v1/tests`, the same filters and keyset paging |
//! | `GET /tests/export/ndjson`, `GET /tests/export/csv` | `GET /api/svs/v1/tests/export/ndjson`, `.../export/csv` |
//! | `GET /tests/{guid}` | `GET /api/svs/v1/tests/{guid}` |
//! | `GET /catalog/repositories` | `GET /api/svs/v1/catalog/repositories` |
//! | `PUT`/`DELETE /tests/{guid}/expectations/{platform}/{signature_uuid}`, `PUT`/`DELETE /tests/{guid}/ignores/{signature_uuid}`, `GET`/`PUT`/`DELETE /tests/{guid}/settings` | the same paths under `/api/svs/v1`, with part 5b's decisions, below |
//!
//! What differs: a page is `{tests, next}`; a bad request is 400 where ace3's is 422; a test's state and run
//! history (`test_state`, `run_count`, `last_run_*`, `last_reviewed_*`, `expected_signatures`,
//! `recent_runs*`, and the detail's `platform_states`) come with the runs and decisions of batches 5 and
//! 8; the detail's atomic entry is `entry`, and it adds `platform_slugs`. Nothing here writes: the catalog
//! is refreshed by the scheduler's `svs_catalog_refresh` and `ace svs catalog refresh`.
//!
//! ace3's `svs` routers' runs and test hosts (PLAN.md 7.10 batch 5, part 5a): a launcher's calls under
//! ace3's `svs:run_register`, reads under `svs:run_read`, and the test hosts' writes under `svs:admin`
//! (`ace_service`'s `svs_runs` and `svs` docs):
//!
//! | ace3 `/api/v2/svs` | here |
//! |---|---|
//! | `POST /runs/`, 201 | `POST /api/svs/v1/runs`, 201, audited; a refusal is 403 and alerts |
//! | `POST /runs/validate` | `POST /api/svs/v1/runs/validate` |
//! | `POST /runs/{run_id}/start`, `executed`, `cleanup`, `cancel` | `POST /api/svs/v1/runs/{run_id}/start`, `executed`, `cleanup`, `cancel`, audited |
//! | `GET /runs/{run_id}` | `GET /api/svs/v1/runs/{run_id}`, with what the runs' list shows of it and its log search; its review blockers come with batch 7 |
//! | `GET /runs/{run_id}/events?cursor=&limit=` | `GET /api/svs/v1/runs/{run_id}/events?after=&limit=` |
//! | `GET /test-hosts/?changed_since=&cursor=&limit=` | `GET /api/svs/v1/test-hosts`, the same, a page `{hosts, next}` |
//! | `GET /test-hosts/export/ndjson`, `.../csv` | `GET /api/svs/v1/test-hosts/export/{format}` |
//! | `POST /test-hosts/`, `GET`, `PUT`, `DELETE /test-hosts/{host_id}` | `POST /api/svs/v1/test-hosts`, `GET`, `PUT`, `DELETE /api/svs/v1/test-hosts/{host}`, audited |
//! | `POST`, `DELETE`, `GET /test-hosts/{host}/maintenance` | `POST`, `DELETE`, `GET /api/svs/v1/test-hosts/{host}/maintenance`, audited |
//!
//! `PUT /test-hosts/{host}` takes `If-Match`, and a host changed since it was read is 412.
//!
//! Part 5b (`svs_run_reads` and `svs_decisions`): the runs' reads under ace3's `svs:run_read`, a run's
//! comments under `svs:run_manage`, and what's decided about a test's signatures under `svs:run_manage`,
//! a global ignore under `svs:admin` (`ace_service`'s `svs_run_reads`, `svs_results` and `svs_decisions`
//! docs):
//!
//! | ace3 `/api/v2/svs` | here |
//! |---|---|
//! | `GET /runs/?f=&changed_since=&cursor=&limit=&tz=` | `GET /api/svs/v1/runs`, the same filters, orders and keyset paging |
//! | `GET /runs/export/ndjson`, `.../csv` | `GET /api/svs/v1/runs/export/{format}` |
//! | `GET /runs/count?f=` | `GET /api/svs/v1/runs/count` |
//! | `GET /runs/suppression-share` | `GET /api/svs/v1/runs/suppression-share` |
//! | `GET /runs/batches?f=&cursor=&limit=`, its exports | `GET /api/svs/v1/runs/batches`, `.../batches/export/{format}` |
//! | `GET /runs/events?f=&changed_since=&cursor=&limit=`, its exports | `GET /api/svs/v1/runs/events`, `.../events/export/{format}` |
//! | `GET /runs/results?f=&changed_since=&cursor=&limit=`, its exports | `GET /api/svs/v1/runs/results`, `.../results/export/{format}` |
//! | `GET /runs/{run_id}/events/export/ndjson`, `.../csv` | `GET /api/svs/v1/runs/{run_id}/events/export/{format}` |
//! | `GET /runs/{run_id}/results?cursor=&limit=`, its exports | `GET /api/svs/v1/runs/{run_id}/results?after=&limit=`, `.../results/export/{format}` |
//! | `GET /runs/{run_id}/history?runs=` | `GET /api/svs/v1/runs/{run_id}/history` |
//! | `GET`, `POST /runs/{run_id}/comments`, `PATCH`, `DELETE /runs/{run_id}/comments/{comment_id}` | the same under `/api/svs/v1`, the writes audited |
//! | `GET /expectations/?test=&platform=&signature=&state=&changed_since=&cursor=&limit=`, its exports | `GET /api/svs/v1/expectations`, `.../expectations/export/{format}` |
//! | `GET /ignores/?scope=&test=&signature=&changed_since=&cursor=&limit=`, its exports | `GET /api/svs/v1/ignores`, `.../ignores/export/{format}` |
//! | `PUT`, `DELETE /ignores/global/{signature_uuid}` | the same under `/api/svs/v1`, audited |
//! | `PUT`, `DELETE /tests/{guid}/expectations/{platform}/{signature_uuid}` | the same under `/api/svs/v1`, audited |
//! | `PUT`, `DELETE /tests/{guid}/ignores/{signature_uuid}` | the same under `/api/svs/v1`, audited |
//! | `GET`, `PUT`, `DELETE /tests/{guid}/settings` | the same under `/api/svs/v1`, the writes audited |
//!
//! What differs: a page is its rows under their own name and `next`; a refused parameter or decision is 400
//! where ace3's is 422; an export is one operation with `csv` or `ndjson` as its last segment, at ace3's
//! two URLs; a write's `If-Match` and `If-None-Match: *` (`aceapi_v2/svs/preconditions.py`) are taken as
//! in ace3, and a 412's body is `{"error": ...}`, where ace3's carries the row as it is now; who did
//! something is an actor, so a key that belongs to nobody decides, where ace3 refuses it, but can't
//! comment, as in ace3. Still to come: the attribution feed, a run's attributions and its alerts, with
//! batch 6's attribution; a person's bulk actions (`/runs/bulk/*`), association
//! (`/runs/{run_id}/alerts/*`), review and a run's review blockers, with batch 7.
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
//! ace3's `detection` router (PLAN.md 5.6, brought by 7.6), under ace3's `detection:read` and
//! `detection:write` (`ace_service`'s `detection` docs). A detection is an entry of the
//! `observable_detection` list, which that module reads on each task, so it applies with no export:
//!
//! | ace3 `/api/v2/detection` | here |
//! |---|---|
//! | `GET /?search=&observable_type=&status=&page=&page_size=` | `GET /api/observables/v1/detections?search=&type=&status=&page=&page_size=` |
//! | `GET /types` | `GET /api/observables/v1/detections/types` |
//! | `POST /`, `{type, value, expires_on?, detection_context?, batch_id?}` | `POST /api/observables/v1/detections`, `{type, value, expires_on?, detection_context?}`, audited |
//! | `DELETE /{detection_id}` | `DELETE /api/observables/v1/detections/{id}`, audited |
//! | `PATCH /{detection_id}/expiration`, `{expires_on}` | `PATCH /api/observables/v1/detections/{id}/expiration`, audited |
//!
//! What differs, or is left out, and why:
//! - `batch_id` isn't taken: a list entry has no column for it and nothing in ace4 sends one. `fa_hits`
//!   and `observable_id` come from ace3's index of every observable, which ace4 doesn't have; a
//!   detection's comments are the observable's, by type and value.
//! - A value is stored as given, a file's sha256 lowercased, where ace3 normalizes some types through
//!   its observable classes. A status that isn't one is 400 where FastAPI answers 422, and a server whose
//!   modules don't read the list answers 404.
//! - A new expiry has to be in the future (400), as on every list; ace3 takes a past one. Remove a
//!   detection to turn it off.
//! - ace3's audit is a log line; here each write has an audit row, as a list entry's.
//!
//! ace3's `detection_points` router (PLAN.md 5.6), and its alerts router's list of one alert's, under
//! `alert:read` as there (`ace_service`'s `detection_points` docs):
//!
//! | ace3 `/api/v2` | here |
//! |---|---|
//! | `GET /detection-points/?cursor=&limit=` | `GET /api/alerts/v1/detections?after=&limit=`, oldest first, a page at a time |
//! | `GET /alerts/{uuid}/detection-points` | `GET /api/alerts/v1/detections?alert={id}`, paged the same way |
//! | `PUT /alerts/{uuid}/detection-points/{content_hash}/verdict`, `{verdict}` | `PUT /api/alerts/v1/alerts/{id}/detections/{detection}/verdict`, `{verdict}`, audited (7.14) |
//! | `DELETE /alerts/{uuid}/detection-points/{content_hash}/verdict` | `DELETE /api/alerts/v1/alerts/{id}/detections/{detection}/verdict`, audited |
//! | `POST /alerts/{uuid}/detection-points/confirm` | `POST /api/alerts/v1/alerts/{id}/detections/confirm`, audited |
//!
//! The writes need `alert:write`, as ace3's do (`ace_service`'s `detection_verdicts` docs).
//!
//! What differs, or is left out, and why:
//! - The path is under `alerts`, since a detection is an alert's. ace3's `detection` router, its list of
//!   observables to detect, is another thing and comes with 7.6.
//! - The `f` filters (5.10) are the detection points screen's that ace4 has fields for: `alert_date`,
//!   `family`, `signature`, 7.14's `verdict`, `source` and `has_override`, and 7.13's `queue`, which takes
//!   `$USER_QUEUE` for the caller's own (a key's owner's). `changed_since` is a detection made, whose root became an alert or was dispositioned,
//!   or whose stored verdict was set or cleared, at or after the time; ace3 also counts any other change to
//!   the alert's row. The exports, `export/csv` and `export/ndjson`, page through this list to the end, and
//!   refuse more than 100,000 rows with 413.
//! - A detection is named by its `id`, which keys its verdict, where ace3 names it by its `content_hash`
//!   (7.14's choice, in `ace_service`'s `detection_verdicts` docs). `override_user` is `override_by`, the
//!   actor who stored it. Setting a verdict doesn't need a user: ace3 answers 422 to a key without one.
//! - A verdict write answers 409 as ace3's does, and a verdict that isn't `tp` or `fp` 400 where FastAPI
//!   answers 422.
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
//! - Four of ace3's eleven screens: `alerts`, `detection_points`, and 7.9's `remediations` and
//!   `file_collections`. The SVS screens come with SVS (7.10).
//! - A filter that isn't the screen's, or a value of the wrong shape, is 400 where ace3 answers 422 with
//!   pydantic's errors.
//! - `PUT /saved-filters/scratch/{kind}` and ace3's `working` and `temp` rows: the GUI's list keeps its
//!   filters in its URL, so there's nothing to hold between requests.
//! - An API key with no owner is refused with 403 where ace3 answers 401, as with comments. Each write has
//!   an audit row, and a user has at most 200 saved filters on a screen.
//!
//! The analyst-edited lists (PLAN.md 5.14), under `/api/lists/v1` with the new `list:read` and `list:write`
//! (`ace_service`'s `lists` docs). ace3 has no router for them: its brotex whitelist was a file on each node,
//! `etc/brotex.whitelist`, which `saq/whitelist.py` reloaded when its mtime changed, and its GUI's
//! Whitelist action, which tagged an observable's value, was removed with `whitelist:write` before this
//! plan's commit. So nothing maps; the routes are:
//!
//! | ace3 | here |
//! |---|---|
//! | none | `GET /lists`, the lists this server's modules read |
//! | reading `etc/brotex.whitelist` | `GET /lists/{list}`, a list's entries in order |
//! | adding a `smtp_from:` or `smtp_to:` line | `POST /lists/{list}/entries`, audited |
//! | changing a line | `PUT /lists/{list}/entries/{id}`, audited |
//! | deleting a line | `DELETE /lists/{list}/entries/{id}`, audited |
//!
//! ace3's `http_host`, `http_src_ip` and `http_dest_ip` keys have no list: nothing in ace3 read them any
//! more. A bad entry is refused with 400, where ace3 logged a line it couldn't parse and skipped it.
//!
//! ace3's `remediation` and `file_collection` routers (PLAN.md 5.6, brought by 7.9), under ace3's
//! `remediation:read`/`write` and `file_collection:read`/`write`, and `file_collection:create`, which ace3's
//! integrations check (`ace_service`'s `remediation` and
//! `file_collections` docs). A remediation, a remediation check and a file collection are actions on the
//! one queue (`ace_core::actions`), which network pools run:
//!
//! | ace3 `/api/v2` | here |
//! |---|---|
//! | `POST /remediation/targets/lookup`, `{alert_uuids}` or `{observables}` | `POST /api/remediation/v1/targets`, `{alerts}` or `{observables}` |
//! | `GET /remediation/remediations?f=&cursor=&limit=&tz=` | `GET /api/remediation/v1/remediations?f=&after=&limit=&tz=`, newest first, with `total` |
//! | `GET /remediation/remediations/export/csv`, `/export/ndjson` | the same under `/api/remediation/v1/remediations/export/`, up to 100,000 rows, or 413 |
//! | `GET /remediation/remediations/{id}/history?limit=` | `GET /api/remediation/v1/remediations/{id}/history?limit=` |
//! | `POST /remediation/remediations`, `{action, targets}` | `POST /api/remediation/v1/remediations`, the same, 201, audited |
//! | `POST /remediation/remediations/{id}/cancel`, `/retry`, `/restore` | the same under `/api/remediation/v1/remediations/{id}/`, audited |
//! | `DELETE /remediation/remediations/{id}` | `DELETE /api/remediation/v1/remediations/{id}`, audited |
//! | none | `GET /api/remediation/v1/remediations/{id}` |
//! | `GET /file-collections/?f=&cursor=&limit=&tz=`, its exports | `GET /api/file-collections/v1/collections`, and `/export/csv`, `/export/ndjson` |
//! | none in ace3's router; a site's `POST /integrations/endpoint_vendor/endpoint/browser-history`, `{hostname}`, under `file_collection:create` | `POST /api/file-collections/v1/collections`, `{collector, observable_type, observable_value, alerts}`, under `file_collection:create`: 201 for a new collection, 200 for a pending one it joins, audited |
//! | `GET /file-collections/{id}/history?limit=` | `GET /api/file-collections/v1/collections/{id}/history?limit=` |
//! | `POST /file-collections/{id}/cancel`, `/retry` | the same under `/api/file-collections/v1/collections/{id}/`, audited |
//! | `DELETE /file-collections/{id}` | `DELETE /api/file-collections/v1/collections/{id}`, audited |
//! | none | `GET /api/file-collections/v1/collections/{id}` |
//!
//! What differs, or is left out, and why:
//! - A target's key is `{remediator, observable_type, observable_value}`, as ace3's. Each write is an
//!   audit row where ace3 logs a line; queueing several targets is one row naming each.
//! - A remediation is a person's: a key with no owner is refused with 403, where ace3 answers 400.
//! - A list has the filters' `total`, and pages by `after`, the last row's id, newest first.
//! - A file collection's row names every alert it belongs to (`alerts`), where ace3's has one
//!   `alert_uuid` (#1101), and its `file` once collected.
//! - A value its type refuses is 400 where ace3 answers 422.
//! - ace3's `file_collection:create`, which only an integration's API (EndpointVendor's endpoint) checks, isn't
//!   here: nothing in this repository asks for a collection through the API.
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
mod detection;
mod detection_points;
mod email;
mod error;
mod events;
mod export;
mod file_collections;
mod filters;
mod health;
mod hunts;
mod lists;
mod observable_comments;
mod observables;
mod params;
mod remediation;
mod svs_catalog;
mod svs_decisions;
mod svs_run_reads;
mod svs_runs;
mod svs_samples;
mod svs_validations;
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
    hunts: hunts::HuntSupport,
    /// The email archive the `email` router serves, with the core's key.
    archive: Option<ace_core::email_archive::EmailArchive>,
}

pub use hunts::HuntSupport;

impl Web {
    pub fn new(service: Service, bucket: Bucket, config: WebConfig) -> Self {
        Web {
            service,
            bucket,
            config,
            hunts: HuntSupport::default(),
            archive: None,
        }
    }

    /// The email archive the `email` router serves (PLAN.md 7.5 batch 9).
    pub fn with_email_archive(mut self, archive: ace_core::email_archive::EmailArchive) -> Self {
        self.archive = Some(archive);
        self
    }

    /// The binary's hunt types and email normalizer, which the `hunt` router validates hunts with.
    pub fn with_hunts(mut self, hunts: HuntSupport) -> Self {
        self.hunts = hunts;
        self
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
            .route("/api/alerts/v1/dispositions", get(alerts::dispositions))
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
            .route("/api/alerts/v1/alerts/{id}/graph", get(alerts::graph))
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
                "/api/alerts/v1/alerts/{id}/detections/{detection}/verdict",
                put(detection_points::set_verdict)
                    .delete(detection_points::clear_verdict)
                    .layer(json_limit),
            )
            .route(
                "/api/alerts/v1/alerts/{id}/detections/confirm",
                post(detection_points::confirm),
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
            .route(
                "/api/observables/v1/detections",
                get(detection::list)
                    .post(detection::create)
                    .layer(json_limit),
            )
            .route(
                "/api/observables/v1/detections/types",
                get(detection::types),
            )
            .route(
                "/api/observables/v1/detections/{id}",
                delete(detection::delete),
            )
            .route(
                "/api/observables/v1/detections/{id}/expiration",
                patch(detection::set_expiration).layer(json_limit),
            )
            .route("/api/hunts/v1/hunts", get(hunts::list))
            .route("/api/hunts/v1/hunts/{uuid}", get(hunts::one))
            .route(
                "/api/hunts/v1/hunts/{uuid}/suppressions",
                get(hunts::suppressions),
            )
            .route(
                "/api/hunts/v1/validate",
                post(hunts::validate_hunt).layer(json_limit),
            )
            .route("/api/lists/v1/lists", get(lists::lists))
            .route("/api/lists/v1/lists/{list}", get(lists::list))
            .route(
                "/api/lists/v1/lists/{list}/entries",
                post(lists::add).layer(json_limit),
            )
            .route(
                "/api/lists/v1/lists/{list}/entries/{id}",
                put(lists::replace).delete(lists::delete).layer(json_limit),
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
            .route("/api/email/v1/archive", get(email::archive))
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
            .route("/api/svs/v1/samples", get(svs_samples::list))
            .route(
                "/api/svs/v1/samples/export/csv",
                get(svs_samples::export_csv),
            )
            .route(
                "/api/svs/v1/samples/export/ndjson",
                get(svs_samples::export_ndjson),
            )
            .route("/api/svs/v1/samples/missing", get(svs_samples::missing))
            .route(
                "/api/svs/v1/samples/captures/{id}/record",
                get(svs_samples::record),
            )
            .route("/api/svs/v1/samples/deletions", get(svs_samples::deletions))
            .route(
                "/api/svs/v1/samples/download",
                get(svs_samples::download_samples),
            )
            .route(
                "/api/svs/v1/samples/{sha256}",
                delete(svs_samples::delete).layer(json_limit),
            )
            .route(
                "/api/svs/v1/samples/{sha256}/{rule_uuid}",
                get(svs_samples::sample),
            )
            .route(
                "/api/svs/v1/samples/{sha256}/{rule_uuid}/download",
                get(svs_samples::download_sample),
            )
            .route(
                "/api/svs/v1/samples/{sha256}/{rule_uuid}/label",
                put(svs_samples::relabel)
                    .delete(svs_samples::reset_label)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/samples/{sha256}/{rule_uuid}/confirm",
                post(svs_samples::confirm),
            )
            .route(
                "/api/svs/v1/samples/{sha256}/{rule_uuid}/retirement",
                put(svs_samples::retire)
                    .delete(svs_samples::unretire)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/yara/validations",
                get(svs_validations::list)
                    .post(svs_validations::request)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/yara/validations/export/csv",
                get(svs_validations::export_csv),
            )
            .route(
                "/api/svs/v1/yara/validations/export/ndjson",
                get(svs_validations::export_ndjson),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}",
                get(svs_validations::detail),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}/status",
                get(svs_validations::status),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}/results",
                get(svs_validations::results),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}/results/export/csv",
                get(svs_validations::export_results_csv),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}/results/export/ndjson",
                get(svs_validations::export_results_ndjson),
            )
            .route(
                "/api/svs/v1/yara/validations/{uuid}/download",
                get(svs_validations::download),
            )
            .route("/api/svs/v1/tests", get(svs_catalog::list))
            .route("/api/svs/v1/tests/export/csv", get(svs_catalog::export_csv))
            .route(
                "/api/svs/v1/tests/export/ndjson",
                get(svs_catalog::export_ndjson),
            )
            .route("/api/svs/v1/tests/{guid}", get(svs_catalog::detail))
            .route(
                "/api/svs/v1/catalog/repositories",
                get(svs_catalog::repositories),
            )
            .route(
                "/api/svs/v1/runs",
                get(svs_run_reads::list)
                    .post(svs_runs::register)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/runs/export/{format}",
                get(svs_run_reads::export),
            )
            .route("/api/svs/v1/runs/count", get(svs_run_reads::count))
            .route(
                "/api/svs/v1/runs/suppression-share",
                get(svs_run_reads::suppression_share),
            )
            .route("/api/svs/v1/runs/batches", get(svs_run_reads::batches))
            .route(
                "/api/svs/v1/runs/batches/export/{format}",
                get(svs_run_reads::export_batches),
            )
            .route("/api/svs/v1/runs/events", get(svs_run_reads::event_feed))
            .route(
                "/api/svs/v1/runs/events/export/{format}",
                get(svs_run_reads::export_event_feed),
            )
            .route("/api/svs/v1/runs/results", get(svs_run_reads::result_feed))
            .route(
                "/api/svs/v1/runs/results/export/{format}",
                get(svs_run_reads::export_result_feed),
            )
            .route(
                "/api/svs/v1/runs/attributions",
                get(svs_run_reads::attribution_feed),
            )
            .route(
                "/api/svs/v1/runs/attributions/export/{format}",
                get(svs_run_reads::export_attribution_feed),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/attributions",
                get(svs_run_reads::run_attributions),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/attributions/export/{format}",
                get(svs_run_reads::export_run_attributions),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/events/export/{format}",
                get(svs_run_reads::export_run_events),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/results",
                get(svs_run_reads::run_results),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/results/export/{format}",
                get(svs_run_reads::export_run_results),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/history",
                get(svs_run_reads::history),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/comments",
                get(svs_run_reads::comments)
                    .post(svs_run_reads::add_comment)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/runs/{run_id}/comments/{id}",
                patch(svs_run_reads::update_comment)
                    .delete(svs_run_reads::delete_comment)
                    .layer(json_limit),
            )
            .route("/api/svs/v1/expectations", get(svs_decisions::expectations))
            .route(
                "/api/svs/v1/expectations/export/{format}",
                get(svs_decisions::export_expectations),
            )
            .route("/api/svs/v1/ignores", get(svs_decisions::ignores))
            .route(
                "/api/svs/v1/ignores/export/{format}",
                get(svs_decisions::export_ignores),
            )
            .route(
                "/api/svs/v1/ignores/global/{signature_uuid}",
                put(svs_decisions::set_global_ignore)
                    .delete(svs_decisions::remove_global_ignore)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/tests/{guid}/expectations/{platform}/{signature_uuid}",
                put(svs_decisions::set_expectation)
                    .delete(svs_decisions::remove_expectation)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/tests/{guid}/ignores/{signature_uuid}",
                put(svs_decisions::set_test_ignore)
                    .delete(svs_decisions::remove_test_ignore)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/tests/{guid}/settings",
                get(svs_decisions::settings)
                    .put(svs_decisions::set_settings)
                    .delete(svs_decisions::remove_settings)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/test-hosts/export/{format}",
                get(svs_runs::export_test_hosts),
            )
            .route(
                "/api/svs/v1/runs/validate",
                post(svs_runs::validate).layer(json_limit),
            )
            .route("/api/svs/v1/runs/{run_id}", get(svs_runs::detail))
            .route("/api/svs/v1/runs/{run_id}/events", get(svs_runs::events))
            .route("/api/svs/v1/runs/{run_id}/start", post(svs_runs::start))
            .route(
                "/api/svs/v1/runs/{run_id}/executed",
                post(svs_runs::executed).layer(json_limit),
            )
            .route("/api/svs/v1/runs/{run_id}/cleanup", post(svs_runs::cleanup))
            .route("/api/svs/v1/runs/{run_id}/cancel", post(svs_runs::cancel))
            .route(
                "/api/svs/v1/test-hosts",
                get(svs_runs::test_hosts)
                    .post(svs_runs::create_test_host)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/test-hosts/{host}",
                get(svs_runs::test_host)
                    .put(svs_runs::update_test_host)
                    .delete(svs_runs::delete_test_host)
                    .layer(json_limit),
            )
            .route(
                "/api/svs/v1/test-hosts/{host}/maintenance",
                get(svs_runs::list_maintenance)
                    .post(svs_runs::open_maintenance)
                    .delete(svs_runs::end_maintenance)
                    .layer(json_limit),
            )
            .route(
                "/api/remediation/v1/targets",
                post(remediation::targets).layer(json_limit),
            )
            .route(
                "/api/remediation/v1/remediations",
                get(remediation::list)
                    .post(remediation::queue)
                    .layer(json_limit),
            )
            .route(
                "/api/remediation/v1/remediations/export/csv",
                get(remediation::export_csv),
            )
            .route(
                "/api/remediation/v1/remediations/export/ndjson",
                get(remediation::export_ndjson),
            )
            .route(
                "/api/remediation/v1/remediations/{id}",
                get(remediation::one).delete(remediation::delete),
            )
            .route(
                "/api/remediation/v1/remediations/{id}/history",
                get(remediation::history),
            )
            .route(
                "/api/remediation/v1/remediations/{id}/cancel",
                post(remediation::cancel),
            )
            .route(
                "/api/remediation/v1/remediations/{id}/retry",
                post(remediation::retry),
            )
            .route(
                "/api/remediation/v1/remediations/{id}/restore",
                post(remediation::restore),
            )
            .route(
                "/api/file-collections/v1/collections",
                get(file_collections::list)
                    .post(file_collections::request)
                    .layer(json_limit),
            )
            .route(
                "/api/file-collections/v1/collections/export/csv",
                get(file_collections::export_csv),
            )
            .route(
                "/api/file-collections/v1/collections/export/ndjson",
                get(file_collections::export_ndjson),
            )
            .route(
                "/api/file-collections/v1/collections/{id}",
                get(file_collections::one).delete(file_collections::delete),
            )
            .route(
                "/api/file-collections/v1/collections/{id}/history",
                get(file_collections::history),
            )
            .route(
                "/api/file-collections/v1/collections/{id}/cancel",
                post(file_collections::cancel),
            )
            .route(
                "/api/file-collections/v1/collections/{id}/retry",
                post(file_collections::retry),
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
        alerts::graph,
        alerts::file,
        alerts::disposition,
        alerts::dispositions,
        alerts::export_csv,
        alerts::export_ndjson,
        detection_points::list,
        detection_points::export_csv,
        detection_points::export_ndjson,
        detection_points::set_verdict,
        detection_points::clear_verdict,
        detection_points::confirm,
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
        detection::list,
        detection::types,
        detection::create,
        detection::delete,
        detection::set_expiration,
        hunts::list,
        hunts::one,
        hunts::suppressions,
        hunts::validate_hunt,
        lists::lists,
        lists::list,
        lists::add,
        lists::replace,
        lists::delete,
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
        email::archive,
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
        svs_samples::list,
        svs_samples::export_csv,
        svs_samples::export_ndjson,
        svs_samples::missing,
        svs_samples::record,
        svs_samples::deletions,
        svs_samples::download_samples,
        svs_samples::delete,
        svs_samples::sample,
        svs_samples::download_sample,
        svs_samples::relabel,
        svs_samples::reset_label,
        svs_samples::confirm,
        svs_samples::retire,
        svs_samples::unretire,
        svs_validations::request,
        svs_validations::status,
        svs_validations::list,
        svs_validations::export_csv,
        svs_validations::export_ndjson,
        svs_validations::detail,
        svs_validations::results,
        svs_validations::export_results_csv,
        svs_validations::export_results_ndjson,
        svs_validations::download,
        svs_catalog::list,
        svs_catalog::export_csv,
        svs_catalog::export_ndjson,
        svs_catalog::detail,
        svs_catalog::repositories,
        svs_runs::register,
        svs_runs::validate,
        svs_runs::detail,
        svs_runs::events,
        svs_runs::start,
        svs_runs::executed,
        svs_runs::cleanup,
        svs_runs::cancel,
        svs_run_reads::list,
        svs_run_reads::export,
        svs_run_reads::count,
        svs_run_reads::suppression_share,
        svs_run_reads::batches,
        svs_run_reads::export_batches,
        svs_run_reads::event_feed,
        svs_run_reads::export_event_feed,
        svs_run_reads::result_feed,
        svs_run_reads::export_result_feed,
        svs_run_reads::attribution_feed,
        svs_run_reads::export_attribution_feed,
        svs_run_reads::run_attributions,
        svs_run_reads::export_run_attributions,
        svs_run_reads::export_run_events,
        svs_run_reads::run_results,
        svs_run_reads::export_run_results,
        svs_run_reads::history,
        svs_run_reads::comments,
        svs_run_reads::add_comment,
        svs_run_reads::update_comment,
        svs_run_reads::delete_comment,
        svs_decisions::expectations,
        svs_decisions::export_expectations,
        svs_decisions::ignores,
        svs_decisions::export_ignores,
        svs_decisions::set_global_ignore,
        svs_decisions::remove_global_ignore,
        svs_decisions::set_expectation,
        svs_decisions::remove_expectation,
        svs_decisions::set_test_ignore,
        svs_decisions::remove_test_ignore,
        svs_decisions::settings,
        svs_decisions::set_settings,
        svs_decisions::remove_settings,
        svs_runs::test_hosts,
        svs_runs::export_test_hosts,
        svs_runs::create_test_host,
        svs_runs::test_host,
        svs_runs::update_test_host,
        svs_runs::delete_test_host,
        svs_runs::open_maintenance,
        svs_runs::end_maintenance,
        svs_runs::list_maintenance,
        remediation::targets,
        remediation::list,
        remediation::export_csv,
        remediation::export_ndjson,
        remediation::queue,
        remediation::one,
        remediation::history,
        remediation::cancel,
        remediation::retry,
        remediation::restore,
        remediation::delete,
        file_collections::list,
        file_collections::request,
        file_collections::export_csv,
        file_collections::export_ndjson,
        file_collections::one,
        file_collections::history,
        file_collections::cancel,
        file_collections::retry,
        file_collections::delete,
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
        (name = "email", description = "The email archive's emails, decrypted, by Message-ID"),
        (name = "cli", description = "ace commands run from the GUI, contained on a pool until their deadline"),
        (name = "yara_qa", description = "YARA rules in QA mode, the files they matched, and purges"),
        (name = "svs", description = "SVS's samples: the files YARA rules matched on alerts graded TP or FP, their labels, retirements and deletions; and YARA validations, a rule change replayed over them"),
        (name = "events", description = "Events, the alerts in them, threat types and malware's threats"),
        (name = "filters", description = "A list screen's filters, their share links, and the caller's saved filters"),
        (name = "hunts", description = "The hunts the hunter loaded, their state, and validating a hunt"),
        (name = "remediation", description = "Remediations: removing what an alert found, such as an email from a mailbox, and restoring it"),
        (name = "file_collections", description = "Files fetched from hosts for alerts, and their tries"),
        (name = "lists", description = "The analyst-edited lists, such as the email whitelists, which apply to the next task that reads them"),
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
