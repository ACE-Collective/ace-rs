# Differences from ace3's reference dumps

`tests/reference.rs` runs the email module on each email fixture that `tools/ace3/dumps/reference/email_analyzer/` has a dump for, puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit fe6da632.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text. A `/` inside a file's path is written `~1`, as JSON pointers escape it.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/email/log_entry/date` | The time the message was scanned. The harness fixes the clock at 2026-01-01, and ace3's dumps carry the time they were made. |
| `*` | `/analyzed/tags/email` | ace3's file_type module tags an email file `email`. The dumps ran it as the email module's dependency. In ace4 that's `file_type`'s own result (`crates/ace-mod-files`), which this test gives the module but doesn't run; the trees compare its tags. |
| `*` | `/analyzed/yara_meta/type=email` | Also file_type's: it gives an email file the `yara_meta` tag `type=email`. |
| `*` | `/observables/file:*/tags/*` | Every tag on a file in these dumps is file_type's, which ran on each file the email module wrote: `email` on the headers file, the combined file and nested messages, `pdf`, `zip`, `ole` and `microsoft_office` on attachments. The email module itself tags no file. |
| `*` | `/observables/file:*/yara_meta/type=email` | file_type's `type=email`, on the headers file, the combined file and nested messages. |
| `*` | `/observables/file:*/yara_meta/type=document.*` | file_type's `type=document.html` and `type=document.pdf`, on HTML parts and PDF attachments. |
| `ace3/email/extra_message_id*` | `/observables/file:email.rfc822.email.rfc822/sha256` | A nested message is written as its bytes appear in the email. ace3 writes `Message.as_bytes()`, Python's re-serialization of the parsed message, which refolds headers longer than 78 characters and adds a space after an empty header's colon. Here that makes the file 39,025 bytes, against 39,010 in the email. The second nested message, `email.rfc822.email_000.rfc822`, has no long headers and matches. |
| `ace3/email/extra_message_id*` | `/observables/file:email.rfc822.email.rfc822/size` | The same nested message. |
| `ace3/email/extra_message_id*` | `/details/email/log_entry/attachment_hashes/2` | The same nested message, in the log entry. |
| `ace3/email/extra_message_id*` | `/details/email/log_entry/attachment_sizes/2` | The same nested message, in the log entry. |
| `ace3/email/nested_rfc822_bom*` | `/observables/file:email.rfc822.email.rfc822/sha256` | A nested message written as its bytes appear (429 bytes) rather than as Python re-serializes it (430): Python's generator ends the inner multipart with an extra line break. |
| `ace3/email/nested_rfc822_bom*` | `/observables/file:email.rfc822.email.rfc822/size` | The same nested message. |
| `ace3/email/nested_rfc822_bom*` | `/details/email/log_entry/attachment_hashes/1` | The same nested message, in the log entry. |
| `ace3/email/nested_rfc822_bom*` | `/details/email/log_entry/attachment_sizes/1` | The same nested message, in the log entry. |

## Behaviour the dumps don't exercise

These follow ace3 on purpose, so they aren't differences, but they're easy to get wrong:

- ace3 parses the file through Python's `BytesParser.parse`, which reads it with universal newlines: every `\r\n` and `\r` becomes `\n` before the parser sees it. The module does the same, so header values, body parts and the headers file have `\n` line endings, as in ace3. `nested_rfc822_bom` is the fixture with CRLF line endings.
- Names that are taken get ace3's `_NNN` suffix, but only against the input file and the files the same result writes. ace3 also checks every file already in the alert's directory, which a module here can't see; the core has to settle clashes between results.
- A name that starts with a drive letter, such as `C:evil.exe`, is written `C_evil.exe`, because a path inside an alert can't start with one (PLAN.md 1.21). ace3 keeps the colon.

These depart from ace3:

- Sender and recipient whitelisting reads two analyst-edited lists (PLAN.md 5.14), `email_sender_whitelist` and `email_recipient_whitelist`, in place of ace3's brotex whitelist file and its `smtp_from` and `smtp_to` keys. ace3's entries were case-blind substrings; an entry here is an exact value, a substring or a regex, with or without case. The dumps were made with ace3's empty whitelist, and the harness gives the module empty lists, so they don't exercise it; `tests/headers.rs` does.
- A whitelisted message gets a result with no details and ace3's summary for it, "Email Analysis: (whitelisted email)", carrying the `whitelisted` tag and directive to the file. ace3 adds the tag and directive to the file and no analysis, but here a result is the only way a module adds to the file it analyzed.
- The SMTP collector's `smtp_rcpt_to` and `smtp_mail_from` observables, the `remediate` directive copied from a `message_id` observable, and renaming the alert from the subject all need the rest of the alert, which a module doesn't see until the core exists.
