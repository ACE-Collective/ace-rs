# Differences from ace3's reference dumps

`tests/reference.rs` runs the YARA module on `test.zip` with the fixture rules in `tools/ace3/dumps/fixtures/yara/` and the meta tags of each of the three dumps in `tools/ace3/dumps/reference/yara_scanner_v3_4/`, puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 844e3584. The same file also checks the Done condition directly: `ace4_fixture_zip_attachment` matches only when the file is tagged `type=email.attachment`.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/scan_results/*/strings/*/2` | The bytes a pattern matched stay bytes, written `{"base64": ...}` (ace3 #999). ace3 turns them into text, here `"PK\u0003\u0004"`; both hold the same four bytes. |
| `*` | `/details/scan_results/*/context/*/2` | The same matched bytes, in the context entry. |
| `*` | `/details/scan_results/*/match_context/*/data` | The context bytes are bytes too: `{"base64": ...}` where ace3 writes the base64 text itself. The value inside is the same. |
| `*` | `/details/scan_results/*/namespace` | The namespace is the rule directory's name, `ace4_fixture`. ace3's scan result carries the directory's absolute path; its detection details already use the relative name, and those match. |
| `*` | `/details/scan_results/*/target` | The file scanned, by its path inside the alert (`test.zip`). ace3 records the absolute path on the node, which has no meaning once files live in the bucket. |
| `*` | `/details/scan_results/*/ruleset` | Each match records the key of the ruleset it came from (PLAN.md 2.26). ace3 has no ruleset keys. These scans compile the fixture directory, not a ruleset the core built, so the key is null. |
| `*` | `/details/scan_results/*/rule_source` | ace3 attaches each rule's source text and pattern definitions for the analysis template. That belongs with the ruleset the match came from, whose manifest arrives with the ruleset builds of PLAN.md 2.25 and 2.26, rather than being copied into every match. |
| `*` | `/details/scan_results/*/string_patterns` | The same: each pattern's definition from the rule source. |

## Behaviour the dumps don't exercise

These depart from ace3:

- In a YARA pool the rules come from the ruleset the core built (PLAN.md 2.26), and each match records its key and commit; a detection's signature version is the commit, as in ace3. These tests compile `signature_dir` instead, so `commit` and `ruleset` are null and the signature version is `unknown`.
- ace3 asks the yara scanner service and falls back to a local scanner. There is no service here; the module scans in its own process.
- A QA rule's match isn't recorded by the module. When its result lands, the core queues a `yara_qa` task that records the match in `yara.qa_matches` and holds the file in the bucket (PLAN.md 2.27). As in ace3 it never alerts or adds directives.
- `$obsd_` and `$obs_` strings name rows of ace3's database, whose observables ace3 adds to the alert. In ace4 the `$obsd_` rows are entries of 7.6's `observable_detection` list, and the ruleset will carry each one's observable (`crates/ace-core/src/reads.md`), which 7.6 builds. `$obs_` strings name ace3's legacy `observables` rows, which ace4 doesn't have, so they won't be served.
- Rules tagged `asm` get no disassembly of their match context; ace3 uses distorm3.
- A scan that fails for a reason other than its timeout fails the task. ace3 logs it, optionally copies the file aside, and moves on with no analysis. A timeout is skipped with no analysis, as in ace3.
- When the input redirects to another observable, `sandbox` goes in the result's `redirected` additions, which the core applies to that observable.
