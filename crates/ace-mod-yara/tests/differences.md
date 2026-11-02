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
| `*` | `/details/scan_results/*/rule_source` | ace3 attaches each rule's source text and pattern definitions for the analysis template. That belongs with the ruleset the match came from, whose manifest arrives with the ruleset builds of PLAN.md 2.25 and 2.26, rather than being copied into every match. |
| `*` | `/details/scan_results/*/string_patterns` | The same: each pattern's definition from the rule source. |

## Behaviour the dumps don't exercise

These depart from ace3:

- The rules come from `signature_dir`, compiled when the module starts, until the YARA pool loads rulesets from the bucket (PLAN.md 2.26). So `commit` is always null and a detection's signature version is `unknown`.
- ace3 asks the yara scanner service and falls back to a local scanner. There is no service here; the module scans in its own process.
- A QA rule's match isn't recorded in the QA store (PLAN.md 2.27); it is logged, and as in ace3 it never alerts or adds directives.
- `$obsd_` and `$obs_` strings name rows of ace3's database, whose observables ace3 adds to the alert. That needs the core's read API (PLAN.md 7.2).
- Rules tagged `asm` get no disassembly of their match context; ace3 uses distorm3.
- A scan that fails for a reason other than its timeout fails the task. ace3 logs it, optionally copies the file aside, and moves on with no analysis. A timeout is skipped with no analysis, as in ace3.
- When the input redirects to another observable, `sandbox` goes in the result's `redirected` additions, which the core applies to that observable.
