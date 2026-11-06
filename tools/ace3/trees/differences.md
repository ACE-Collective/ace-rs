# Differences between ace3's and ace4's trees

`ace compare` (`crates/ace-app/src/compare.rs`) diffs ace4's normal form of each sample with ace3's in `reference/`, and classes each difference by the first row here that matches it. `tests/e2e/run` fails on a row that matches nothing, and on a difference no row matches in its own sample. In the Samples column, `*` matches any text in a sample's path. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text. The When column narrows a row: `ace4 only` is what ace3 doesn't have, and `ace3 holds <text>` a value of ace3's with that text in it.

A row covering only samples under `local/` has to name them, because those samples are git-ignored and CI doesn't have them.

ace3's trees ran at the commit in `reference/index.json`, which is newer than the commit the five modules were ported from (`tools/ace3/dumps/reference/index.json`). A row marked *drift* is something ace3 added after the port. The trees follow the newest ace3 (`PLAN.md` decision 14), so rerun `make-trees` after ace3 moves, then port or list whatever changed.

A module ace4 doesn't have, such as `file_type` (7.5), isn't listed: the command takes its results out of both forms and counts them. When a module is ported its results start being compared, and what it added outside its results moves out of *Effects of modules not ported*.

## Explained

| Samples | Path | Why | When |
|---|---|---|---|
| `*` | `/observables/*/results/archive/details/extraction_error` | *Drift.* ace3 added it with its sandboxed extractors (`c817977f`). It is null here, and the port has no such key. |  |
| `*` | `/observables/*/results/clicker_detection_splunk/details/gui_link` | ace3 sets a Splunk web link only for a query with `<O_TIMESPEC>`, so it's null. The port doesn't fill `<O_TIMESPEC>` and has no such key. |  |
| `*` | `/observables/*/results/rdap_analyzer/details/rdap_data` | whoisit's parse of the response, stored beside the response itself. Nothing in ace3 reads it but its tests. |  |
| `*` | `/observables/*/results/rdap_analyzer/details/whois_data` | The WHOIS fallback isn't ported. ace3 sets this only when RDAP fails and WHOIS answers, so it's null. |  |
| `*` | `/observables/*/results/rdap_analyzer/details/whois_raw_text` | The same. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/strings/*/2` | The bytes a pattern matched stay bytes, written `{"base64": ...}` (ace3 #999). ace3 turns them into text. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/context/*/2` | The same matched bytes, in the context entry. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/match_context/*/data` | The context bytes are bytes too: `{"base64": ...}` where ace3 writes the base64 text itself. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/namespace` | The rule directory's name. ace3's scan result carries the directory's path on the node. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/target` | The file scanned, by its path inside the alert. ace3 records its path on the node, which has no meaning once files live in the bucket. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/rule_source` | ace3 attaches each rule's source text for the analysis template. That belongs with the ruleset the match came from (5.9). |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/string_patterns` | The same: each pattern's definition from the rule source. |  |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/rule_content_hash` | A hash of the rule's text, which ace3's SVS capture and YARA QA store read. ace4 names a rule by its ruleset's key and its name. SVS is 7.10. |  |
| `*` | `/observables/file:*/paths/*` | ace3 keeps one observable with one path per sha256 (`tree_form` in `run_module.py`). Each file a module writes here keeps its own path, even when two have the same bytes (`crates/ace-mod-archive/tests/differences.md`). Where ace3's one path is missing from ace4, that's a difference of its own, which this row doesn't match. | `ace4 only` |
| `ace3/archive/dhl_report.ace` | `/observables/*/results/archive` | ACE archives aren't read: ace3 runs `unace`, and no Rust crate reads the format. The module skips the file, so there is no result, and none of what ace3 extracted. |  |
| `ace3/archive/dhl_report.ace` | `/observables/file:*` | What ace3 extracted from it. |  |
| `ace3/archive/malicious.jar` | `/observables/file:*` | More files than the limit. Both pick the riskiest kinds first, but within a kind ace3 takes them in its filesystem's order (`os.walk`) and ace4 in archive order, so they extract different files (`crates/ace-mod-archive/tests/differences.md`). |  |
| `ace3/archive/malicious.jar` | `/observables/*/results/archive/details/extracted_files/*` | The same choice of files. |  |
| `ace3/archive/malicious.jar` | `/observables/*/results/archive/summary` | The same choice of files, in the summary. |  |
| `ace3/archive/over.7z` | `/observables/*/results/archive/details/extracted_files/*` | The same choice of files. |  |
| `ace3/archive/over.7z` | `/observables/*/results/archive/summary` | The same choice of files, in the summary. |  |
| `ace3/archive/test.jar` | `/observables/file:*` | More files than the limit. Both pick the riskiest kinds first, but within a kind ace3 takes them in its filesystem's order (`os.walk`) and ace4 in archive order, so they extract different files (`crates/ace-mod-archive/tests/differences.md`). |  |
| `ace3/archive/test.jar` | `/observables/*/results/archive/details/extracted_files/*` | The same choice of files. |  |
| `ace3/archive/test.jar` | `/observables/*/results/archive/summary` | The same choice of files, in the summary. |  |
| `ace3/archive/too_many_files.jar` | `/observables/file:*` | More files than the limit. Both pick the riskiest kinds first, but within a kind ace3 takes them in its filesystem's order (`os.walk`) and ace4 in archive order, so they extract different files (`crates/ace-mod-archive/tests/differences.md`). |  |
| `ace3/archive/too_many_files.jar` | `/observables/*/results/archive/details/extracted_files/*` | The same choice of files. |  |
| `ace3/archive/too_many_files.jar` | `/observables/*/results/archive/summary` | The same choice of files, in the summary. |  |
| `ace3/archive/over.7z` | `/observables/file:*/paths/*` | More files than the limit, and all eleven have the same bytes. Both sides record that one observable under the names they extracted, which aren't the same (`crates/ace-mod-archive/tests/differences.md`). |  |
| `ace3/office/doc.docx` | `/observables/*/results/archive/details/extracted_files/*` | The same files in another order: ace4 in archive order, ace3 in the filesystem's (`os.walk`). |  |
| `ace3/office/doc.docx` | `/observables/*/results/archive/summary` | The summary lists them in the same order. |  |
| `ace3/office/js_ole_obj.docx` | `/observables/*/results/archive/details/extracted_files/*` | The same files in another order: ace4 in archive order, ace3 in the filesystem's (`os.walk`). |  |
| `ace3/office/js_ole_obj.docx` | `/observables/*/results/archive/summary` | The summary lists them in the same order. |  |
| `ace3/office/mortgage_payment-0873821-0565.docm` | `/observables/*/results/archive/details/extracted_files/*` | The same files in another order: ace4 in archive order, ace3 in the filesystem's (`os.walk`). |  |
| `ace3/office/mortgage_payment-0873821-0565.docm` | `/observables/*/results/archive/summary` | The summary lists them in the same order. |  |
| `local/archive/zip-slip.zip` | `/observables/*/results/archive/details/extracted_files/*` | The same files in another order: ace4 in archive order, ace3 in the filesystem's (`os.walk`). |  |
| `local/archive/zip-slip.zip` | `/observables/*/results/archive/summary` | The summary lists them in the same order. |  |
| `local/office/invoice.xlsm` | `/observables/*/results/archive/details/extracted_files/*` | The same files in another order: ace4 in archive order, ace3 in the filesystem's (`os.walk`). |  |
| `local/office/invoice.xlsm` | `/observables/*/results/archive/summary` | The summary lists them in the same order. |  |
| `ace3/email/extra_message_id*` | `/observables/file:65551fd054a53e746d7d76c5c164bc69dbaed932c36a973b953dba2f13c36d99` | A nested message is written as its bytes appear in the email. ace3 writes `Message.as_bytes()`, Python's re-serialization of the parsed message (`crates/ace-mod-email/tests/differences.md`). This is ace3's bytes. |  |
| `ace3/email/extra_message_id*` | `/observables/file:40c99b06194a67e0a9c07603ed8819695ba48d8ea505c2f32130812d9f016c10` | The same message: ace4's bytes. |  |
| `ace3/email/extra_message_id*` | `/observables/*/results/email_analyzer/details/email/log_entry/attachment_hashes/2` | The same message, in the log entry. |  |
| `ace3/email/extra_message_id*` | `/observables/*/results/email_analyzer/details/email/log_entry/attachment_sizes/2` | The same message, in the log entry. |  |
| `ace3/email/nested_rfc822_bom*` | `/observables/file:ad051cc117906f0d8dc87062a6f26980483e0bd908e7dbe0a85ed05e182f5ee2` | A nested message is written as its bytes appear in the email. ace3 writes `Message.as_bytes()`, Python's re-serialization of the parsed message (`crates/ace-mod-email/tests/differences.md`). This is ace3's bytes. |  |
| `ace3/email/nested_rfc822_bom*` | `/observables/file:f007e1d587b9403795d169002b2b9dded64f0b110c651e7a4a6fb8256a17b4d5` | The same message: ace4's bytes. |  |
| `ace3/email/nested_rfc822_bom*` | `/observables/*/results/email_analyzer/details/email/log_entry/attachment_hashes/1` | The same message, in the log entry. |  |
| `ace3/email/nested_rfc822_bom*` | `/observables/*/results/email_analyzer/details/email/log_entry/attachment_sizes/1` | The same message, in the log entry. |  |

## Effects of modules not ported

What a module ace4 doesn't have added outside its own result. The form doesn't say who added a tag, so these stay differences, reported apart. Each is checked against `saq/modules/file_analysis/file_type.py` at ace3's commit, whose only tags are `microsoft_office`, `ole`, `rtf`, `pdf`, `executable`, `zip`, `lnk`, `x509`, `jar` and `email`, and whose only `yara_meta` types are `image`, `document.pdf`, `document.rtf`, `executable`, `archive.jar`, `certificate.x509`, `email`, `document.html` and `script.javascript`. A row here matches only what ace3 has and ace4 doesn't. What such a tag leads to, such as a rule that can't match, isn't listed, and shows as the difference it is.

| Samples | Path | Why | When |
|---|---|---|---|
| `*` | `/observables/file:*/tags/email` | file_type's tag. |  |
| `*` | `/observables/file:*/tags/zip` | file_type's tag. |  |
| `*` | `/observables/file:*/tags/jar` | file_type's tag. |  |
| `*` | `/observables/file:*/tags/microsoft_office` | file_type's tag. |  |
| `*` | `/observables/file:*/tags/ole` | file_type's tag. |  |
| `*` | `/observables/file:*/tags/pdf` | file_type's tag. |  |
| `local/rtf/*` | `/observables/file:*/tags/rtf` | file_type's tag. |  |
| `*` | `/observables/file:*/paths/*/type=email` | file_type's `yara_meta` tag. Until it's ported, a rule that needs this tag can't match in ace4. |  |
| `*` | `/observables/file:*/paths/*/type=archive.jar` | file_type's `yara_meta` tag. |  |
| `*` | `/observables/file:*/paths/*/type=document.html` | file_type's `yara_meta` tag. |  |
| `*` | `/observables/file:*/paths/*/type=document.pdf` | file_type's `yara_meta` tag. |  |
| `*` | `/observables/file:*/paths/*/type=image` | file_type's `yara_meta` tag. |  |
| `local/rtf/*` | `/observables/file:*/paths/*/type=document.rtf` | file_type's `yara_meta` tag. |  |
| `ace3/archive/test.zip` | `/observables/file:*/paths/*/type=script.javascript` | file_type's `yara_meta` tag. |  |

## Harness limits

The two runs didn't see the same world, so the difference says nothing about a port.

| Samples | Path | Why | When |
|---|---|---|---|
| `*` | `/observables/*/results/rdap_analyzer/details/error` | Only `example.com` has a recorded RDAP answer. For anything else ace3's replay raises a connection error, ace3 then tries WHOIS, which also fails, while ace4's responder answers 404. Neither system got an answer, so this says nothing about the port. A recording of each name would remove it. | `ace3 holds nothing recorded` |
| `*` | `/observables/*/results/rdap_analyzer/details/rdap_attempt_error` | The same: ace3 records the failed connection, and a 404 isn't one in ace4. | `ace3 holds nothing recorded` |
