# Differences from ace3's reference dumps

`tests/reference.rs` runs the two email archive modules on ace3's dumps, made by `tools/ace3/dumps/make-dumps email_archive`, where ace3's archive was `run_module.py`'s in-memory `archived_messages` and its CAS pool in the work directory, under the test-only key in `tools/ace3/dumps/fixtures/email_archive/key`. The test answers each read as the core answers it over the same archive; ace-pool's `lease_api` test runs the core's read and the archiver's write over the same fixtures and checks them against these dumps. The test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5.

ace3's 4f1fa192 cut its archive to the Message-ID to the email and removed `encrypted_archive_analyzer` and `url_email_pivot_analyzer`, and ace-rs followed it (the owner, 2026-11-21).

## email_archiver

The dumps are every email of the sample set with the `archive` directive, against an empty archive, with ace3's email, file type and URL extraction modules. The module gets ace-rs's email module's result for the same email as its dependency. Besides the analysis, the test checks that the write names the Message-ID ace3 archived the email under and that the email is the one ace3's row names; `lease_api` checks the row the core writes for it against ace3's.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 copies an email it can't archive, for a missing Message-ID, to `review/rfc822/` on its node; ace-rs keeps no file outside an alert, so it logs that.
- ace3 keeps one object for each email's sha256 in its pool, and archiving it again renews the object's time to live; here a new row holds the same object too, while it's in the bucket, until the row's week is dropped.
- The core archives an email up to 64 MiB (`ace_core::email_archive::MAX_EMAIL_BYTES`), sealing it in memory; a larger one fails the task, saying why. ace3 streams and has no limit.
- ace3's `expiration_days` is read nowhere; here too. The archive's retention is its partitions' (`ACE_RS_EMAIL_ARCHIVE_RETENTION_DAYS`, 30 days, ace3's `email_archive.partition_retention_days`), and ace3's object time to live (`ttl_days`) is the row's hold.
- ace3's pool gzips and encrypts with its CAS's layout; the core writes ace3's v1 layout, whose header is authenticated and names the key, into the bucket's `email_archive` pool, and Postgres rows.

## message_id_analyzer_v2

The dumps are a Message-ID archived once, the same without its brackets, one archived twice (the newer is taken), one not archived, one whose object is gone, and one whose email is empty.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 first looks up the tree for an email analysis with this Message-ID (`search_down`); here it's whether the email module's result added the observable (`Module::READS_ADDED_BY`), which is the email such an analysis would be, and which also excludes this module on it, as in ace3. The two differ only for an email whose raw Message-ID isn't in `<` and `>`, which ace3's search doesn't match and whose module is excluded anyway.
- ace3 writes the email in the root's directory before it knows it's empty, and removes it. The core puts the opened email in the root's files, held by the root, before the module sees its size, so an empty one stays in the bucket with the root, as no observable.
- ace3 has no limit on the email it opens; the core opens up to 64 MiB, and answers the rest with an error, which the module logs.
