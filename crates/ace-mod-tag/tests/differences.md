# Differences from ace3's reference dumps

`tests/reference.rs` runs `observable_detection`, `user_defined_tagging` and `site_tagger` on each observable and file `tools/ace3/dumps/reference/` has a dump of theirs for. ace3 read `tools/ace3/dumps/fixtures/tag/`: `detections.json` as its Redis cache of detections and `observable_tags.json` as its database's tag mappings, which `tools/ace3/dumps/run_module.py` fakes (`--detections`, `--observable-tags`), and `site_tags.csv` as the site tagger's `csv_file`. The test gives the detections as the `observable_detection` list's entries, answers the `observable-tags` read with the tags mapped to the dump's type and value, and gives the CSV's text as the site tagger's `csv` setting. The core's read is tested through the lease API in ace-pool's `lease_api` test. Both results go into the normal form `ace_testkit::reference` describes, and each test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

| Dumps | Path | Why |
|---|---|---|

## Behaviour the dumps don't exercise

These depart from ace3:

- `observable_detection` reads the `observable_detection` list (PLAN.md 5.14) on the lease, where ace3 reads a Redis copy of its `observable_detections` table that `ace observables export` rewrites every minute. An edit applies to the next task, with no export between, and a task carries the list as it was when it was leased. The list holds at most 1,000 entries (`ace_sdk::lists::MAX_ENTRIES`); ace3's table has no limit.
- `user_defined_tagging` reads migration 0042's `analysis.observable_tags` through the `observable-tags` read, by type and value, where ace3 keys its mappings by type and the sha256 of the value, which names the same observable. A core that can't answer fails the task as unavailable, so it runs again later; ace3 logs the error and raises it. An answer holds at most 1,000 tags and says when it was cut.
- `site_tagger` takes the CSV's text as its `csv` setting, from the site's overlay, read when the pool starts, where ace3 reads `csv_file` and reloads it when it changes. It's off until the overlay gives it a section, where ace3 enables it and fails to load without the file, which it doesn't ship. A row's regex compiles with the `regex` crate, not Python's `re`, so one using what only `re` has, such as a look-around or a backreference, is skipped as ace3 skips a pattern that doesn't compile. `ignore_case` lowercases with Rust's `to_lowercase`, which differs from Python's `str.lower` only for a few characters outside ASCII. A CIDR row takes a prefix length, or for IPv4 a netmask or host mask, as `ip_network` does.
