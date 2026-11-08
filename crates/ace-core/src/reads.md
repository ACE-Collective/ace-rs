# Reads for modules

PLAN.md 7.2. Workers hold no database credentials and no encryption key. A module that reads ACE's own data in ace3 reads it from the core, as its pool, through the lease API (`api.rs`). This file is the contract for those reads. None is built yet: the one ported module that reads ACE's data in ace3, `yara_scanner_v3_4`, gets it on the ruleset, and that waits for 7.6, which brings the data it reads. Each module's port step builds the reads it calls, with the tests below, and marks them built here.

`docs/modules.md`'s *What 7.2 serves* names what serves each module. `tools/ace3/modules/check` fails when a module that reads ACE's data in ace3 has nothing named there, or names a read this file doesn't have.

## How a module gets ACE's data

In order of preference:

1. **On the lease.** The core adds what it knows when it hands out the task and the module always needs: the carrying email (4.6, `Module::READS_CARRYING_EMAIL`) and the lists the module declares (5.14, `Module::LISTS`).
2. **On the ruleset** (`GET /api/worker/v1/yara/ruleset`), for data that changes with the rules.
3. **A read**, `POST /api/worker/v1/tasks/{id}/reads/{read}`, for something the analysis decides, such as a Message-ID or a URL. Only a lookup pool's module calls one. A parser's task process has no network and no channel back to its supervisor while it runs, so a parser gets its data on the lease or the ruleset.
4. **A write lands with the task's end** (`POST /api/worker/v1/tasks/{id}/end`). It goes in the end's own transaction, so a task that's retried never writes twice and a failed one writes nothing. The module declares its writes in `Module::WRITES`, and `TaskEnd::Result` carries them beside the result.

## The read contract

A module declares its reads in `Module::READS: &'static [Read]`, where `ace_sdk::reads::Read` names each read, as `LISTS` names lists. The manifest carries the list, and the catalog refuses a parser that declares one. The module calls a read with `TaskContext::read`, which goes through the pool's client with the pool's token.

The request is `POST /api/worker/v1/tasks/{id}/reads/{read}`, with `Authorization: Bearer <pool token>`, the worker's name in `x-ace4-worker`, and a JSON body. The answer is JSON. The core checks, in this order:

| Status | When |
|---|---|
| 401 | the token isn't a pool's |
| 400 | no worker header, or the body doesn't read |
| 409 | the task isn't leased to `<pool>/<worker>` now: another pool's token, another worker of the same pool, a task that ended, or a lease past its `lease_expires_at`. `Worker::owned` alone doesn't check the expiry, so a read also checks `lease_expires_at > now()` |
| 403 | the task's module doesn't declare the read, or the request names an observable or file that isn't in the task's root |
| 503 | the store behind the read is down. ace3's thread analyzer goes into cooldown when brocess times out, and the port does the same on a 503 |
| 200 | the answer. Nothing found is a 200 with an empty answer, not a 404, so a module can tell a miss from a refusal |

**Scope.** Each read names its subject: the task's own observable, or an observable or file in the task's root. The core looks the subject up by root and type and value, or by root and sha256, before it reads anything. Most reads answer only about that subject. Some answer from other alerts' data, as ace3's do. Those are marked in the table below with their bound: a count, or capped rows of header metadata. None returns another alert's tree, its files or its id.

**Sensitive data.** The core decrypts with ACE's key, and the key never leaves the core. A read that yields an email body puts the plaintext in the bucket's `alert_files` pool, held by the task's root, as a module's own output file is. It answers with the file's sha256, its size and a presigned download, as the lease does for a task's input. ace3 doesn't audit these reads: its `log_audit` records its API's callers, and its modules' archive reads write only their own log lines. So ace4 writes no audit row for them either. The core logs each with the task, the root, the read and the sha256.

**Replay.** `ace task replay` replays a task without a lease. A replayed module calls `/api/admin/v1/tasks/{id}/reads/{read}` with the admin token, with the same checks except the lease. The first read that's built brings this route.

**Tests.** When a read is built, it gets tests for a success, an unknown token (401), another pool's token (409), another worker (409), an expired lease (409), a subject from another root (403), a module that doesn't declare the read (403), and its bound: an answer past its cap says it was truncated.

## The reads

| Read | Module | Subject | Answers | Across alerts | Built by |
|---|---|---|---|---|---|
| `archived-email` | `message_id_analyzer_v2` | the task's message_id observable | the newest archived email with that Message-ID, decrypted and gunzipped in the core, as a file in the root's hold; or none | yes, as in ace3: the archive holds every email archived from any alert. One email per call, the newest (ace3's `ORDER BY insert_date DESC`), no larger than the bucket's largest object | 7.5 batch 9 |
| `decrypted-archive` | `encrypted_archive_analyzer` | a file in the root, by sha256, whose name ends `.gz.e` | the file decrypted and gunzipped, as a file in the root's hold. A gunzip past the bucket's largest object fails; ace3 sets no cap (`archive.py:75`) | no | 7.5 batch 9 |
| `archived-url-count` | `url_email_pivot_analyzer` | the task's url observable | how many archived emails are indexed with the URL (`COUNT(DISTINCT archive_id)`), over every archive ace3 sums | yes: a count only | 7.5 batch 9 |
| `smtp-counts` | `email_conversation_frequency_analyzer` | the task's email_conversation observable, its sender and recipient | brocess's `SUM(numconnections)` for the sender, and for the sender and recipient | yes: two counts | 7.4 |
| `email-thread` | `email_thread_analyzer` | the task's message_id observable | the recorded conversation, as ace3's `get_conversation` returns it: each message's header metadata (Message-ID, In-Reply-To, subject, from address and domain, direction, dates), its participants, the roles and addresses per domain, the thread counts, and whether it was truncated | yes: other emails' header metadata, without bodies or alert ids. At most `max_messages` messages and `max_threads` threads (ace3's defaults are 50 each), which the core caps at 500 whatever the module asks. ace3 leaves the roles and addresses per domain uncapped, because they decide its verdict; the core caps them at 10,000 rows and says so when it truncates | 7.4 |
| `email-thread-domains` | `email_logger` | a thread id that is the Message-ID, In-Reply-To or a References id of an email in the root, with its normalized subject | the domains established by earlier messages (domain, address, role, first seen) and the thread's message count, as ace3's `get_established_domains` and `get_thread_message_count` | yes: the domains and addresses of earlier messages in the thread, or in same-subject threads that share a domain with it. At most 10,000 rows, truncation said | 7.4 |
| `snort-signature` | `snort_signature_analysis_v1` | the task's snort_signature observable (sid and rev) | the rule line with that sid and rev, from the rules file `ace signatures build-db` indexes, which the core indexes instead of Redis | no: rule text, not alert data | 7.4 |
| `observable-tags` | `user_defined_tagging` | the task's own observable | the tags mapped to its type and sha256 | no: mappings keyed by value, not alerts | 7.6 |
| `svs-attribution` | `svs_alert_tagger` | the task's root | its alert's insert time, whether attribution is open, the runs (with their test hosts) for the markers the module found or overlapping the time range it gives, the maintenance windows overlapping that range, and the root's existing attributions | no: SVS's runs and windows, and the root's own rows | 7.10 |
| `svs-capture-state` | `svs_yara_sample_capture` | the task's root, and file sha256s in it | the root's disposition, whether it belongs to an unreviewed run, and which of the files SVS deleted or already captured | no | 7.10 |

## Served another way

- `yara_scanner_v3_4`, **on the ruleset**. ace3 reads the `observable_detections` row a matched `$obsd_<id>` string names, and adds its observable. In ace4 those rows are entries of 7.6's `observable_detection` list (5.14). 7.6's export writes their rules, and the ruleset the core builds carries each `$obsd_` id's observable type and value beside the rules. The core builds both from one read of the list, so a rule and its observable always agree. ace3 reads the row at scan time and skips one deleted since the export. ace3's legacy `$obs_<id>` strings name its own `observables` rows, which ace4 doesn't have, so they aren't served (`crates/ace-mod-yara/tests/differences.md`). Built by 7.6.
- `observable_detection`, **on the lease**: the `observable_detection` list in `Module::LISTS`, as 7.6 says. ace3 reads a Redis copy that `ace observables export` keeps.
- `alert_added_to_event`, **in the core**. Its pool is the core's, since it changes the root's analysis mode, so it reads the root's events there. The owner hasn't decided whether it's ported.
- **Writes, at the task's end.** `email_archiver` archives the email: a hold on its file in an archive pool, its archive, index and history rows, and once the root's other analysis is done, the index of the URLs below it. `email_logger` adds to brocess's `smtplog` and records the thread. `svs_yara_sample_capture` records its captures and SVS's holds.
