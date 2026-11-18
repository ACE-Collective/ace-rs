# Differences from ace3's reference dumps: the clicker detection module

`tests/reference.rs` runs the clicker detection module (`clicker.rs`) with the searches of `tools/ace3/dumps/fixtures/clicker/clicker_detection.yaml` on the dumps in `tools/ace3/dumps/reference/clicker_detection_splunk/`, which ace3's `SplunkClickerDetectionAnalyzer` made against `tools/ace3/dumps/fake_splunk.py` answering from `fixtures/splunk/clicker_rows.json`. The test replays the exchanges ace3 made, runs the module again after each delay it asks for, and runs it at the time ace3's searches were around (the first search's `earliest`, seven days on), so its searches, word for word with their time ranges, are ace3's; it checks that they are, but for the dump with a child URL. A dump without the `clicker_detection` directive has no analysis in ace3, and the core doesn't queue the module for it (`REQUIRED_DIRECTIVES`). Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit fe6da632.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/query_start` | When the analysis started, in seconds since the epoch: ace3's clock when its first run began, some seconds after the root's event time its searches were around. The harness runs at that event time. |
| `url_https:__click.example.com_r?u=https:__click.example.com_login` | `/details/matched_url_count` | ace3 matches the URL and every child URL urlfinderlib finds in it, here the URL in its `u` parameter, so 2; urlfinderlib's URL isn't ported (7.5's `url_extraction` brings it), so the module matches the URL alone. |
| `url_https:__click.example.com_r?u=https:__click.example.com_login` | `/details/gui_link` | The same: ace3's link to the last search has the child URL in its OR-group too. |
| `url_https:__click.example.com_r?u=https:__click.example.com_login` | `/details/clicker_events/*/portal_url` | The same, in each click's link to its search. The clicks are the same: the fake answers by the domain both searches name. |
| `url_https:__multi.example.com_x` | `/detections/*` | The proxy search's hit has two users in one multivalue field. ace3 builds the set of the hits' users (`{e["user"] for e in hits}`), and a list can't be in a set, so it raises `TypeError` before the detection point, leaving the analysis as that search left it. ace4 takes each user of the field, `URL clicker identified via proxy (frank@example.com, grace@example.com)`. |
| `url_https:__multi.example.com_x` | `/analyzed/directives/crawl` | The same `TypeError` stops ace3 before it crawls the URL; ace4 goes on and adds `crawl`. |
| `url_https:__multi.example.com_x` | `/details/clicker_index` | The same: ace3 stops before it counts the search done, at 1 of 2; ace4 finishes, at 2. |
| `url_https:__multi.example.com_x` | `/details/search_id` | The same: ace3 stops before it clears the search's job, which ace4 clears. |
| `url_https:__multi.example.com_x` | `/details/dispatch_state` | The same. |
| `url_https:__multi.example.com_x` | `/details/start_time` | The same. |
| `url_https:__multi.example.com_x` | `/details/running_start_time` | The same. |
| `url_https:__multi.example.com_x` | `/details/end_time` | The same. |
| `url_https:__multi.example.com_x` | `/error` | The same `TypeError`. It raises out of ace3's module after the analysis exists, so ace3's engine marks the analysis failed with the exception, `TypeError: cannot use 'list' as a set element (unhashable type: 'list')`, and its crash report's id, which the form leaves out. ace4 doesn't raise, so its result has no error. |
| `url_https:__multi.example.com_x` | `/summary` | The same: ace3's summary has that error after its one click, `URL Clicks (Splunk): 1 click found, ERROR: TypeError: ...`, and ace4's is `URL Clicks (Splunk): 1 click found`. |

## Behaviour the dumps don't exercise

These depart from ace3:

- **Child URLs.** ace3 matches a URL and every child URL urlfinderlib finds in it: a URL in a query or fragment value, one encoded in base64, and the URL a Mandrill or Proofpoint link wraps. Only the dump above has one. The module matches the URL alone until 7.5's `url_extraction` brings urlfinderlib's URL to ace4.
- **The config.** ace3 reads `etc/clicker_detection.yaml` relative to its home and watches it with `watch_file`. The module reads the file `config_path` names, as PyYAML's `safe_load` reads it (`ace_hunt::yaml`), again whenever its modification time or size changes. With no `config_path` there are no searches, as with ace3's shipped file.
- **Time ranges.** A search's time ranges are around the observable's time, or else the first run's time, where ace3 falls back to the root's event time. ace4's task has no root event time. `<O_TIMESPEC>`, `<O_VALUEn>` and `<observable.*>` tokens but `<observable.value>` and `<observable.type>` fail the task, where ace3 fills them (or, for `<O_TIMESPEC>` without the observable's time, raises).
- **Phishkit.** On a clicked URL with `crawl_clicked_url`, ace3 also clears a Phishkit analysis that was skipped, so Phishkit runs. ace4 has no Phishkit yet (7.7); the URL gets `crawl` alone.
- **A failed search.** A search that splunkd refuses ends with `<name>: HTTP 500: Splunk search failed: <error>` in the result's error (ace3's `Analysis.error`), as the Splunk module words it, and the next search runs, as in ace3. A splunkd that can't be reached fails the task as unavailable, so it runs again later, as the Splunk module's does.
- **The Splunk client.** It is the Splunk module's, with the same departures (`differences.md`): fewer status reads, certificates verified, no proxy, `query_timeout` only.
- **The URL Clicks view and the observable actions.** ace3 gathers every source's clicks into the alert's URL Clicks panel and offers "Check for clickers" and "Open clicker search in Splunk" on an observable. Those are GUI areas of their own; the module's result has its own view.
