# Differences from ace3's reference dumps

`tests/reference.rs` runs the lure and mailbox modules on ace3's dumps, made by `tools/ace3/dumps/make-dumps emailtree` with each run's whole root kept (`run_module.py --tree-view`). Each module gets that root as the core's tree (`ace_testkit::reference::Dump::tree_view_with_details`, with the details of `pdf_link_text`'s results, which the lure module declares it reads), the bodies the dump kept, HTML and plain text, as the tree's files, and ace-rs's email module's result for the same email as its dependency. The test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5, which has the lure module's context scoring (`b4badb2c`, `40ee8208`).

| Dumps | Path | Why |
|---|---|---|

The lure dumps are every email of the sample set, the lure module run with the parsers `tools/ace3/trees/make-trees` enables, `pdf_link_text` among them, and again: `lure_button` with a settings file of its own (`.settings`); five of the context emails with other sign-off phrases, attachment phrases, sentence lengths and weights (`.context`); two with no sign-off and no attachment phrases (`.no_reference`); and `lure_pdf_link` without `pdf_link_text` (`.no_link_text`), as in an alert analyzed with it disabled. 70 dumps, with no difference. Compared: the analysis's summary and details, without each candidate's `observable_uuid`, which ace3 gives an observable anew each run and ace-rs's observables don't have, and whether the primary URL got `crawl`. The mailbox dumps are every email as a `mailbox` alert with `original_email`, and `lure_button` as a `cli_analysis` one. Compared: the analysis, the root's description, the keys of its details, and the Message-IDs with `tracked`; the test also checks that the details the module merges are the email module's result, as ace3's are its `EmailAnalysis.details`.

### Behaviour the dumps don't exercise

These depart from ace3:

- `lure_url_analyzer`
  - ace3 scores in `execute_final_analysis` and reruns on each final pass, since a module that works in final analysis can add a URL after the first. ace-rs's runs once, after every other module of the root has finished, those that run last included only if they finished first; its result isn't revised after.
  - ace3 reads its settings from `etc/lure_url.yaml`, which analysts edit and it reloads, keeping the settings in effect when an edit doesn't load. Here they're the module's settings in the site's overlay, with the same keys and defaults, checked when the pool starts.
  - A candidate has no `observable_uuid`, and the GUI draws the result as the analysis's view, not as a section of the alert page. A candidate's `url` is its observable's value, which is how ace-rs finds the observable.
  - ace3's tldextract can fetch the public suffix list on first use and falls back to its bundled snapshot; ace-rs's `registrable_domain` uses its own bundled list (`ace_sdk::domains`) and never fetches it.
  - ace3 has an observable for each path of a file and walks each; ace-rs has one per file, and the walk keys a file's visit by the path it reached it under, so a URL in two attached copies of one file names both, as in ace3.
  - ace3's `find_phrase` matches a phrase with Python's `re.IGNORECASE`, which also takes a dotless `ı` for an `i` and a long `ſ` for an `s`; ace-rs's uses the regex crate's case folding, which takes the `ſ` and not the `ı`. A body that writes "please fınd attached" refers to its attachment by "attached" in ace-rs and by the longer phrase in ace3: the score is the same, and the words the reason quotes can differ.
  - A body larger than 5 MiB isn't parsed, as in ace3, which logs it; the core doesn't send its bytes. A body the core sent and the pool couldn't fetch ends the run as any of the pool's downloads does, where ace3 logs a body it can't read and scores without its links.
  - The walk reads the results of `qrcode`, `phishkit_analyzer` and `pdf_link_text` by module name, as ace3 reads their classes.
  - ace3 has a `pdf_link_text` result for each path of a PDF, and the walk takes each as it reaches that path. ace-rs analyzes a file once, so one result serves every path the file was added under, and the PDF's name in "the only link in ..." is the path the walk reached it by, as in ace3 (`lure_pdf_quoted_reference`'s two copies of one PDF).
- `mailbox_email_analyzer`
  - ace3 sets the root's description and merges the email's details into the root's in place. Here the result carries them and the core lands them with it: the description in the root's row and the details merged into its origin's `details`, where a submitter inside ACE keeps what it said about the root. A root's alert type is its origin's `alert_type`. Nothing in ace-rs submits a `mailbox` root until 6.1, which decision 17 skips, so the module skips every root today.
  - `tracked` reaches each Message-ID through the result's additions to other observables, which ace-rs's core makes eligible again as ace3's directive does.
