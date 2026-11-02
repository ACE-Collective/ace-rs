# Differences from ace3's reference dumps

`tests/reference.rs` runs the RDAP module on the domain and the IP address that `tools/ace3/dumps/reference/rdap_analyzer/` has dumps for, with ace3's recorded HTTP exchanges replayed on 127.0.0.1, at the time ace3 ran each lookup. It puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 844e3584.

`rdap_raw_json` is compared as JSON rather than as text: ace3 writes it with Python's `json.dumps` (`", "` and `": "` between items, non-ASCII escaped) and ace4 with serde_json, and the two hold the same response.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/rdap_data` | whoisit's parse of the response, which ace3 stores beside the response itself. Nothing in ace3 reads it but its tests: the summary, the template and the other fields come from the fields the module extracts, which match. ace4 keeps the response in `rdap_raw_json` and doesn't store a second copy in whoisit's shape. |
| `*` | `/details/whois_data` | The WHOIS fallback isn't ported, so there are no WHOIS fields. ace3 sets them only when RDAP fails and WHOIS answers; both dumps have them null. |
| `*` | `/details/whois_raw_text` | The same. |

## Behaviour the dumps don't exercise

These depart from ace3:

- When RDAP can't answer (no RDAP server for the TLD, an error status, a response that doesn't parse), ace3 asks WHOIS through python-whois. ace4 records `rdap: <error>` in `error` and the RDAP error in `rdap_attempt_error`, with `lookup_protocol` null.
- A server that can't be reached, or answers 429, 502, 503 or 504, fails the task as unavailable, so it runs again later (PLAN.md 1.20). ace3 records `rdap client error: ...` and tries WHOIS.
- whoisit picks one of a TLD's RDAP servers at random; ace4 takes the first HTTPS one, as icann-rdap-common's `get_preferred_url` does.
- When a response has no `self` link, ace3 names the registry instead (`rir`, from the bootstrap data); ace4 leaves `rdap_service_url` empty.
- The public suffix list is the snapshot tldextract 5.4.0 ships (2025-04-07). ace3's tldextract fetched the live list when the dumps were made.
- Dates are read as RFC 3339, with or without an offset. whoisit uses dateutil's fuzzy parser, which reads more forms.
