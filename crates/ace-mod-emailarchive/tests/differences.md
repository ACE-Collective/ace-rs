# Differences from ace3's reference dumps

`tests/reference.rs` runs the four email archive modules on ace3's dumps, made by `tools/ace3/dumps/make-dumps email_archive`, where ace3's archive was `run_module.py`'s in-memory `email-archive` database and its work directory, under the test-only key in `tools/ace3/dumps/fixtures/email_archive/key`. The test answers each read as the core answers it over the same archive; ace-pool's `lease_api` test runs the core's reads and the archiver's write over the same fixtures and checks them against these dumps. The test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

## email_archiver

The dumps are every email of the sample set with the `archive` directive, against an empty archive, with ace3's email, file type and URL extraction modules. The module gets ace4's email module's result for the same email as its dependency. Besides the analysis, the test checks that the write names the Message-ID ace3 indexed and the recipients ace3 recorded, in its order, and the hash ace3 archived; `lease_api` checks the rows the core writes for them, URLs included, against ace3's.

| Dumps | Path | Why |
|---|---|---|
| `ace3/email/*` | `/details/archive_id` | ace3's is the id its `INSERT` gave the row, 1 in a run's empty archive. The module can't know it when it builds its result, so it sends none, and the core sets it when the archive lands in the task's end (`lease_api` checks the landed result has the row's id). |
| `ace3/email/*` | `/details/archive_path` | ace3's is the encrypted file's path on its node, `<data>/archive/email/<hostname>/<xx>/<sha256>.gz.e`. ace4's archive is an object in the bucket, so the path names the email by its hash as ace3's does, without the data directory or a node: `archive/email/<xx>/<sha256>.gz.e`. |
| `ace3/email/*` | `/summary` | The same path, in ace3's `Archive Path: <path>`. |

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 archives in its normal analysis and indexes the URLs below the email in its post-analysis. The core indexes them when the root's analysis completes, in the transaction that records it, and again when a later pass completes, adding what that pass found; ace3's post-analysis runs only in the modes that run the module, so it doesn't index a correlation pass's URLs. An index row keeps the archive's own `insert_date`, so it goes with its archive, where ace3's has the time it was indexed.
- ace3 copies an email it can't archive, for a missing Message-ID or envelope recipient, to `review/rfc822/` on its node; ace4 keeps no file outside an alert, so it logs that.
- ace3 keeps one file for each email's hash, and a later archive of the same email takes a new row and leaves the file; here a new row holds the same object too, while it's in the bucket.
- ace3's `whitelisted` check is the core's: a whitelisted file is eligible for nothing.
- ace4's email module gives envelope recipients only from an Office 365 journal's meta block, since the SMTP collector's `smtp_rcpt_to` observables went with the collector (`crates/ace-mod-email/tests/differences.md`), so only journaled emails are archived until an ingest step adds them.
- The core archives an email up to 64 MiB (`ace_core::email_archive::MAX_EMAIL_BYTES`), sealing it in memory; a larger one fails the task, saying why. ace3 streams and has no limit.
- ace3's `expiration_days` is read nowhere; here too. The archive's retention is its partitions' (`ACE4_EMAIL_ARCHIVE_RETENTION_DAYS`, 30 days, ace3's `email_archive.partition_retention_days`).
- ace3 writes its archive file in the v0 layout and MySQL rows; the core writes ace3's v1 layout, whose header is authenticated and names the key, into the bucket's `email_archive` pool, and Postgres rows. It reads v0 too.

## encrypted_archive_analyzer

The dumps are each sealed fixture of `fixtures/email_archive`: v0 and v1, another key, a body that isn't gzip, a truncated file, a changed byte, and the v0 file under a name that doesn't end `.gz.e`.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 leaves the decrypted gzip, `<name>.rfc822.gz`, in the alert's directory, not an observable. ace4 keeps no file outside the tree.
- ace3 returns at once when its encryption isn't initialized. Here the core, which holds the key, answers that it has none, and the module adds nothing, as ace3 does when its key can't open the file.
- ace3 has no limit on the gunzip (`archive.py:75`); the core stops past 64 MiB, and the module adds nothing.

## url_email_pivot_analyzer

The dumps are a URL in one archived email, one in three (two of them the same Message-ID archived twice), one in none, and the second again with a `result_limit` the count passes.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 sums the count over its primary archive database and every `database_email_archive_*` section; ace4 has one archive.
- ace3 fails the module on a database error; here the core's 503 fails the task as unavailable, so it runs again later.

## message_id_analyzer_v2

The dumps are a Message-ID archived once, the same without its brackets, one archived twice (the newer is taken), one not archived, one whose file is gone, and one whose email is empty.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 first looks up the tree for an email analysis with this Message-ID (`search_down`); here it's whether the email module's result added the observable (`Module::READS_ADDED_BY`), which is the email such an analysis would be, and which also excludes this module on it, as in ace3. The two differ only for an email whose raw Message-ID isn't in `<` and `>`, which ace3's search doesn't match and whose module is excluded anyway.
- ace3 opens the archive's file under its own node's hostname, whatever node archived it, so an email archived on another node fails to open there; one bucket is every node's here.
- ace3 writes the email in the root's directory before it knows it's empty, and removes it. The core puts the opened email in the root's files, held by the root, before the module sees its size, so an empty one stays in the bucket with the root, as no observable.
- ace3 has no limit on the email it opens; the core opens up to 64 MiB, and answers the rest with an error, which the module logs.
