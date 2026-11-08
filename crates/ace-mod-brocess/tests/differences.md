# Differences from ace3's reference dumps

`tests/reference.rs` runs the brocess modules on ace3's dumps. Rows name a dump under `tools/ace3/dumps/reference/email_conversation_frequency_analyzer/` or `email_logger/`.

## email_conversation_frequency_analyzer

The test runs the conversation frequency module on each `email_conversation` value `tools/ace3/dumps/reference/email_conversation_frequency_analyzer/` has a dump for. ace3 counted from the smtplog rows in `tools/ace3/dumps/fixtures/brocess/smtplog.json` in place of brocess (`tools/ace3/dumps/run_module.py --brocess`, which sums them as ace3's SQL does). The test answers the module's `smtp-counts` read with the counts the core's query gives for those rows; ace-pool's `lease_api` test runs that query on the same rows in Postgres and checks it against the same dumps. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- When brocess can't be queried, ace3 logs it, puts the module in a cooldown of `cooldown_period` (60 s) during which it analyzes nothing, and stores no result, or for a known sender a result without `dest_count`. A core that can't answer (503) fails the task as unavailable here, so it runs again later. There is no cooldown.
- ace3 asks for the conversation's count only when the sender's isn't 0. The `smtp-counts` read answers both at once; the module ignores the second for a new sender, as ace3 never has it.

## email_logger

The test runs the email logger on each of its dumps: every email in the sample set against an empty brocess, and the conversation in `tools/ace3/dumps/fixtures/email_logger/` in order, each against the brocess the one before left, starting from `seed.json`. ace3 ran in `run_module.py` with `--brocess-store`, a brocess in memory that answers its SQL as MySQL would, and `--fluent-bit`, which kept what it sent fluent-bit. Here the email module parses the same email and its result goes to the logger with the task, the `email-thread-domains` read is answered with what ace3's reads answered, and a fake fluent-bit decodes what the module sends. Compared: the rows the run added to brocess, without the ids, hashes and times the store makes (ace-pool's `lease_api` test writes them in Postgres and checks those against the dumps), and the records sent to the logger's four tags, without the scan's time (`date` and the `timestamp` made from it), with the URLs sorted, since ace3 makes a set of them. Each test reads only the rows under its module's heading.

| Dumps | Path | Why |
|---|---|---|
| `ace3/email/extra_message_id*` | `/fluent_bit/*/record/attachment_hashes/2` | The email module's: a nested message is stored as its bytes appear in the email, where ace3 stores Python's re-serialization (`crates/ace-mod-email/tests/differences.md`), so its sha256 in the log entry differs. |
| `ace3/email/extra_message_id*` | `/fluent_bit/*/record/attachment_sizes/2` | The same nested message's size: 39,010 bytes in the email, 39,025 as Python writes it. |
| `ace3/email/nested_rfc822_bom*` | `/fluent_bit/*/record/attachment_hashes/1` | The email module's, as above: a nested message stored as it appears. |
| `ace3/email/nested_rfc822_bom*` | `/fluent_bit/*/record/attachment_sizes/1` | The same nested message: 429 bytes, 430 as Python writes it. |

### Behaviour the dumps don't exercise

These depart from ace3:

- The email's URLs are the `url` observables below it. ace3 also adds every URL its `url_extraction` module found in a file, including those past the module's observable cap, from that module's details. `url_extraction` isn't ported (7.5 batch 1), so no URLs come from it, and none of the dumps has one.
- `archive_path` is null: `email_archiver` isn't ported (7.5 batch 9). It will come with the task when it is.
- ace3 keeps a socket to fluent-bit per tag for the life of the module and drops a record it can't send without a word. Here a task's records go over one connection, and a failure is logged, with how many were dropped.
- ace3 sends each record as it makes it; here they go together at the end of the task, in the same order.
- A domain's punycode form is the `idna` crate's UTS 46, strict, where ace3 uses the `idna` package's IDNA 2008. They differ only for names one of them refuses, which each then keeps as written.
- ace3's subject fallback and timeline read same-subject threads' participants with `IN (subquery)`, in whatever order MySQL's plan gives. The core reads them in the order they were written, grouped by thread in that order, which is what `run_module.py`'s fake does.

## email_thread_analyzer

The test runs the thread module on each `message_id` value `tools/ace3/dumps/reference/email_thread_analyzer/` has a dump for. ace3 read the brocess the email logger's thread runs left (`run_module.py --brocess-store`), and its dumps keep what `get_conversation` answered. Here the `email-thread` read is answered with that; ace-pool's `lease_api` test runs the core's read over the same rows in Postgres and checks it against the same answers. The analysis goes into the normal form `ace_testkit::reference` describes, beside the findings: the markdown ace3 adds as a summary detail, which ace4's view draws from the details, since its results have no summary details. Two runs have settings of their own: `.capped`, with 2 messages and 1 thread, and `.ignored`, with a pair never reported.

| Dumps | Path | Why |
|---|---|---|

### Behaviour the dumps don't exercise

These depart from ace3:

- ace3 reads the pairs never to report from `etc/email_thread_analysis.yaml`, which analysts edit and it reloads when it changes. Here they're the module's `ignored_domain_pairs` setting, in the site's overlay.
- When brocess can't be queried, ace3 goes into a cooldown of `cooldown_period` (60 s), analyzing nothing. A core that can't answer (503) fails the task as unavailable here.
- ace3 reads a same-subject conversation's participants with `IN (subquery)` and leaves the roles and addresses per domain uncapped. The core reads at most 10,000 such rows, in the order they were written, and says when it cut them (`roles_truncated`), and caps the messages and threads at 500 whatever the settings ask. A cap of 0 is refused.
