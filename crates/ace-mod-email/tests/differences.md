# Differences from ace3's reference dumps

`tests/reference.rs` runs the email module on each email fixture that `tools/ace3/dumps/reference/email_analyzer/` has a dump for, puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 844e3584.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/email/log_entry/date` | The time the message was scanned. The harness fixes the clock at 2026-01-01, and ace3's dumps carry the time they were made. |
| `*` | `/analyzed/tags/email` | ace3's file_type module tags an email file `email`. The dumps ran it as the email module's dependency; ace4 has no file_type module yet, and the email module reads libmagic's mime type instead. |
| `*` | `/analyzed/yara_meta/type=email` | Also file_type's: it gives an email file the `yara_meta` tag `type=email`. |
| `*` | `/details/email/log_entry/attachment_*/**` | Body parts and attachments come in step 1.26. |
| `*` | `/observables/file:*/**` | The files the module writes: body parts, attachments, the headers file and the combined file. They come in step 1.26. |
