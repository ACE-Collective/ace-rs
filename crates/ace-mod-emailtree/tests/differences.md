# Differences from ace3's reference dumps

`tests/reference.rs` runs the lure and mailbox modules on ace3's dumps, made by `tools/ace3/dumps/make-dumps emailtree` with each run's whole root kept (`run_module.py --tree-view`). Each module gets that root as the core's tree (`ace_testkit::reference::Dump::tree_view`), the HTML bodies the dump kept as the tree's files, and ace4's email module's result for the same email as its dependency. The test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

| Dumps | Path | Why |
|---|---|---|

The lure dumps are every email of the sample set, the lure module run with the parsers `tools/ace3/trees/make-trees` enables, and `lure_button` again with a settings file of its own. Compared: the analysis's summary and details, without each candidate's `observable_uuid`, which ace3 gives an observable anew each run and ace4's observables don't have, and whether the primary URL got `crawl`. The mailbox dumps are every email as a `mailbox` alert with `original_email`, and `lure_button` as a `cli_analysis` one. Compared: the analysis, the root's description, the keys of its details, and the Message-IDs with `tracked`; the test also checks that the details the module merges are the email module's result, as ace3's are its `EmailAnalysis.details`.

### Behaviour the dumps don't exercise

These depart from ace3:

- `lure_url_analyzer`
  - ace3 scores in `execute_final_analysis` and reruns on each final pass, since a module that works in final analysis can add a URL after the first. ace4's runs once, after every other module of the root has finished, those that run last included only if they finished first; its result isn't revised after.
  - ace3 reads its settings from `etc/lure_url.yaml`, which analysts edit and it reloads, keeping the settings in effect when an edit doesn't load. Here they're the module's settings in the site's overlay, with the same keys and defaults, checked when the pool starts.
  - A candidate has no `observable_uuid`, and the GUI draws the result as the analysis's view, not as a section of the alert page. A candidate's `url` is its observable's value, which is how ace4 finds the observable.
  - ace3's tldextract can fetch the public suffix list on first use and falls back to its bundled snapshot; ace4's `registrable_domain` uses its own bundled list (`ace_sdk::domains`) and never fetches it.
  - ace3 has an observable for each path of a file and walks each; ace4 has one per file, and the walk keys a file's visit by the path it reached it under, so a URL in two attached copies of one file names both, as in ace3.
  - A body larger than 5 MiB isn't parsed, as in ace3, which logs it; the core doesn't send its bytes. A body the core sent and the pool couldn't fetch ends the run as any of the pool's downloads does, where ace3 logs a body it can't read and scores without its links.
  - QR codes (`qrcode`) and crawls (`phishkit_analyzer`) aren't ported (7.5 batch 10, 7.7). The walk reads their results by module name, as ace3 reads their classes, so they count once they are.
- `mailbox_email_analyzer`
  - ace3 sets the root's description and merges the email's details into the root's in place. Here the result carries them and the core lands them with it: the description in the root's row and the details merged into its origin's `details`, where a submitter inside ACE keeps what it said about the root. A root's alert type is its origin's `alert_type`. Nothing in ace4 submits a `mailbox` root until 6.1, which decision 17 skips, so the module skips every root today.
  - ace3's `RootAnalysis.whitelisted` is also true for a whitelisted analysis or a root tagged `whitelisted`; ace4 has neither, so the tree's `whitelisted` is any observable's tag or directive.
  - `tracked` reaches each Message-ID through the result's additions to other observables, which ace4's core makes eligible again as ace3's directive does.
