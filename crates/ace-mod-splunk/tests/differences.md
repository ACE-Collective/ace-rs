# Differences from ace3's reference dumps

`tests/reference.rs` runs the Splunk module with the settings of proxy_domain_lookup, the example query ace3 ships in `etc/saq.splunk_modules.yaml`, on the two dumps in `tools/ace3/dumps/reference/proxy_domain_lookup/`: a search that finishes on ace3's second poll, and one that never finishes and times out after 3 seconds. ace3 ran against `tools/ace3/dumps/fake_splunk.py`, a fake Splunk REST API with made-up rows, and the test replays the exchanges it recorded. The harness runs the module again after each delay it asks for, as if the delay had passed. It puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/query_start` | When the analysis started, in seconds since the epoch. ace3's is the time of its run; the harness runs at a fixed time (2026-01-01T00:00:00Z) and counts each delay as passed. |
| `*` | `/details/start_time` | When the job was submitted, in ace3's `format_iso8601` form on both sides. A clock time, as `query_start`. |
| `*` | `/details/running_start_time` | When the module first saw the job running. A clock time, as `query_start`. |
| `fqdn_www.example.com` | `/details/end_time` | When the module read the rows. A clock time, as `query_start`. The search that never finishes has none on either side. |
| `*` | `/details/gui_link` | A Splunk web link, which ace3 sets only for a query with `<O_TIMESPEC>`, so it's null in both dumps. The port doesn't fill `<O_TIMESPEC>` and has no `gui_link` key. |

## Behaviour the dumps don't exercise

These depart from ace3:

- **One query per module.** ace3 configures each Splunk query as an analysis module of its own (proxy_domain_lookup here), every one of class `SplunkAPIAnalyzer`. The port is one module, `splunk_api`, whose settings hold one query. Running several queries needs module instances, which the core doesn't have yet. For the same reason the module's `INPUTS` is every type and `valid_observable_types` narrows it inside the module, which skips the rest, so the core would queue it for every observable.
- **Fewer requests.** ace3 reads a job's status three times a poll (splunk-sdk's lookup of the job, `is_ready` and `refresh`) and the server info twice; the port reads each once. ace3 logs in when the module loads; the port logs in at its first task and keeps the session until splunkd answers 401.
- **splunkd down.** A splunkd that can't be reached, or answers 429, 502, 503 or 504, fails the task as unavailable, so it runs again later (PLAN.md 1.20). ace3 ends the analysis with `HTTP 500: Splunk search failed: <error>` as its error (`Analysis.error`, its `query_error` until `41d44392`), once splunk-sdk has spent its retries on a failed connection (five, 10 seconds apart, over the module's life).
- **Login.** A failed login fails the task. In ace3 it stops the module from loading.
- **401 while polling.** ace3 keeps polling through 401s for `auth_failure_grace_period` (60 seconds), for search head clusters that fail to proxy a request. The port logs in again once and then ends the analysis with the 401 as a failed search.
- **Certificates.** The port verifies splunkd's certificate, with `ca_certificates` for a private CA. ace3 doesn't verify it (`verify=False`).
- **Proxy.** ace3 can reach splunkd through the proxy its Splunk config names. The port uses no proxy.
- **Job budgets.** ace3's client also abandons a job that stays queued past `dispatch_timeout` (900 seconds) or runs past 30 minutes, with an `HTTP 504` error. With the default `query_timeout` of 300 seconds the analyzer gives up first, so the port has only `query_timeout`.
- **Query tokens.** `<O_TIMESPEC>`, `<O_VALUE1>` and the like, `<observable.*>` and named time ranges aren't filled, and a query that uses one fails at init. Nor are `query_path`, `pivot_links`, `summary_details` or the performance log CSVs ported; settings that name one fail to load.
- **Observable mappings.** A mapping takes `field`, `type`, `tags`, `directives`, `time`, `ignored_values` and `display_type`. ace3's other options (`fields` and `fields_mode`, value and type templates, Jinja in tags and directives, dotted field paths, files, relationships, `limit`, `volatile`, `display_value`) aren't ported, and a mapping that uses one fails to load.
- **Values.** ace3 refuses a value its observable type doesn't accept, type by type. The port checks only IP addresses. `ignored_values` are Rust regular expressions, which lack Python's lookaround and backreferences.
