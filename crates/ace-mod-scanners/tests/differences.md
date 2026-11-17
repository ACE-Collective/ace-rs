# Differences from ace3's reference dumps

`tests/reference.rs` runs `javascript_deobfuscation` on each input `tools/ace3/dumps/reference/` has a dump of theirs for. ace3's modules were answered, in place of their Celery managers, with the scan output directories in `tools/ace3/dumps/fixtures/scanners/` (`tools/ace3/dumps/run_module.py --scanner-output`), which `tools/ace3/dumps/scanner-fixtures` made by running the scanner images as the managers run them. The test checks the scan each module's first run asks for against what ace3's asked its manager for, then gives its second run the same directory as the scanner pool brings one back. Each module has a job id of its own, so the test puts ace3's in place of ace4's in the paths before comparing. Both results go into the normal form `ace_testkit::reference` describes, and each test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 37a765bf.

| Dumps | Path | Why |
|---|---|---|
| `ace4/web/scripts.html.inline_0` | `/analyzed/tags/js` | A dump of a file another module wrote (`run_module.py --dump-file`) records the file's tags after the run as its input's, so the `js` tag this module gave the script reads, on ace3's side, as one it already had. Both give it: ace3's `observable_after` holds `js`. |

phishkit_analyzer's rows are in `phishkit_differences.md`, beside this file.
