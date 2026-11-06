# Differences between ace3's and ace4's trees

`tests/e2e/run` compares ace4's normal form of a sample with ace3's in `reference/`, and fails on a difference this table doesn't list or a row that matches nothing. In the Samples column, `*` matches any text in a sample's path. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text.

ace3's trees ran at the commit in `reference/index.json`, which is newer than the commit the five modules were ported from (`tools/ace3/dumps/reference/index.json`). A row marked *drift* is something ace3 added after the port. The trees follow the newest ace3 (`PLAN.md` decision 14), so rerun `make-trees` after ace3 moves, then port or list whatever changed.

| Samples | Path | Why |
|---|---|---|
| `*` | `/observables/file:*/results/file_type` | ace3's email and archive modules depend on file_type, so its trees run it. ace4 has no file_type module yet (7.5). |
| `*` | `/observables/file:*/tags/email` | file_type's tag on an email file. |
| `*` | `/observables/file:*/tags/zip` | file_type's tag on a zip file. |
| `*` | `/observables/file:*/paths/*/type=email` | file_type's `yara_meta` tag on an email file. Until it's ported, a rule that needs this tag can't match in ace4. |
| `*` | `/observables/*/results/archive/details/extraction_error` | *Drift.* ace3 added it with its sandboxed extractors (`c817977f`). It is null here, and the port has no such key. |
| `*` | `/observables/*/results/clicker_detection_splunk/details/gui_link` | ace3 sets a Splunk web link only for a query with `<O_TIMESPEC>`, so it's null. The port doesn't fill `<O_TIMESPEC>` and has no such key. |
| `*` | `/observables/*/results/rdap_analyzer/details/rdap_data` | whoisit's parse of the response, stored beside the response itself. Nothing in ace3 reads it but its tests. |
| `*` | `/observables/*/results/rdap_analyzer/details/whois_data` | The WHOIS fallback isn't ported. ace3 sets this only when RDAP fails and WHOIS answers, so it's null. |
| `*` | `/observables/*/results/rdap_analyzer/details/whois_raw_text` | The same. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/strings/*/2` | The bytes a pattern matched stay bytes, written `{"base64": ...}` (ace3 #999). ace3 turns them into text. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/context/*/2` | The same matched bytes, in the context entry. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/match_context/*/data` | The context bytes are bytes too: `{"base64": ...}` where ace3 writes the base64 text itself. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/namespace` | The rule directory's name. ace3's scan result carries the directory's path on the node. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/target` | The file scanned, by its path inside the alert. ace3 records its path on the node, which has no meaning once files live in the bucket. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/rule_source` | ace3 attaches each rule's source text for the analysis template. That belongs with the ruleset the match came from (5.9). |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/string_patterns` | The same: each pattern's definition from the rule source. |
| `*` | `/observables/*/results/yara_scanner_v3_4/details/scan_results/*/rule_content_hash` | A hash of the rule's text, which ace3's SVS capture and YARA QA store read. ace4 names a rule by its ruleset's key and its name. SVS is 7.10. |
