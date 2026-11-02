# YARA scanner comparison

PLAN.md step 1.11 runs ace3's YARA scanner and ace4's port side by side. Both compile every rule file in ace3's signatures checkout, both scan the local sample set, and the comparison checks libmagic's mime types against `file`. It found no difference anywhere. The match half is thin on the sample set, though. Only 3 of the 288 loaded rules match anything in it.

## What was compared

| | ace3 | ace4 |
|---|---|---|
| Scanner | yara-python 4.5.4 under yara_scanner_v2 3.0.0, through `tools/ace3/yara/child.py`: ace3's SVS replay child (`saq/svs/yara/child.py`, checkout at 844e3584) with pattern offsets added | `ace yara replay` (PLAN.md 1.10), a release build of `ace-yara` on yara-x 1.22.1 |
| Where it ran | ace3's dev container `ace-dev-1`, on ace3's Python, without the Landlock sandbox `replay.py` adds | a one-off `dev` container of ace4's stack (`ACE4_STACK=ace4-yara`) |
| Mime types | `file -b --mime-type`, file 5.46 | libmagic 5.46 through `ace_yara::mime` |

Both read the same rule files and the same unit files at the same absolute paths. The signatures checkout is at commit `0ca119e9f49a01643d25b8598d3111efb7fc1d2b`, with nothing under `yara/` differing from it: `ace yara build` records a commit only then, and it recorded this one. Both images have the same magic database, sha256 `23e4e113bd1e43940d079f9f8a9a105ce7b99321c917623808701eac99cb81af`.

`tools/ace3/yara/compare-replay WORKROOT` runs everything below and writes every difference it finds to `WORKROOT/differences.json`:

```sh
ACE4_STACK=ace4-yara ACE4_ACE3_CHECKOUT=/path/to/ace3 tools/ace3/yara/compare-replay /tmp/yara-compare
```

It writes three working directories with `tools/ace3/yara/make-workdir` and runs both children on each:

- **every-rule-file.** All 97 rule files in the checkout, one namespace per directory that holds any (`yara/site`, `yara/svs_marker`, `analyst_rules_a`, `analyst_rules_b`, `vti`), and no units. ace3's yara service loads only the 87 under `yara/`.
- **samples.** The 87 files ace3's yara service loads, in its namespaces `site`, `svs_marker` and the empty `observable_export`, and one unit per distinct (sha256, path inside the alert, meta tags) in `samples/manifest.json`, as ace3's `corpus.py` makes units. That is 52 units from 53 samples, because `sample_rfc822.in` and `splunk_logging.email.rfc822` are the same bytes with the same path and tags. 35 units carry `type=email.attachment` and 17 carry no tags, as the manifest gives them.
- **rule-sources.** A supplementary set, not part of the plan's sample set. The same 87 files, with each rule file scanned as a unit twice: once with all 12 tags the rules' `meta_tags` directives name, once with none. A rule's strings are in its own source, so this set exercises far more rules than the samples do.

The compile half compares, file by file, whether each scanner left the file out, and for each file both include, the rules it defines (name, private, global, tags) and each rule's meta. The match half compares, unit by unit, every rule that matched before the meta filter: its namespace and name, every string occurrence's offset, identifier and length, whether the filter kept it, and the scan errors. A unit's path is where it was written in the working directory, such as `/tmp/ace4-yara-work/samples/u/7/files/email.rfc822`, in both, as in ace3's replay.

The comparison ran three times on 2026-11-02, with the same counts each time. The counts are deterministic, so the repeats only show the setup is stable. A mutation check confirmed that the diff catches what it should: adding 1 to one offset, removing one kept match and moving one match to the dropped list each showed up as one difference of the expected kind.

## Differences by kind

| Kind | every-rule-file | samples | rule-sources |
|---|---|---|---|
| File left out by ace3 only | 0 | 0 | 0 |
| File left out by ace4 only | 0 | 0 | 0 |
| Different rules in a file | 0 | 0 | 0 |
| Different meta for a rule | 0 | 0 | 0 |
| Ruleset loads in one scanner only | 0 | 0 | 0 |
| Rule matched by ace3 only | | 0 | 0 |
| Rule matched by ace4 only | | 0 | 0 |
| Same rule, different string occurrences | | 0 | 0 |
| Kept by the filter in one scanner only | | 0 | 0 |
| Different scan errors | | 0 | 0 |
| Mime type differs from ace3's `file` | | 0 of 53 samples | |

## Compile half

All 97 rule files in the checkout:

- Both scanners leave out one file, `vti/signature_name_8.yar`, for the same reason. It uses `vt.net.url.new_url`, a field of VirusTotal's `vt` module that only VT Livehunt's URL rulesets have. yara-python says `invalid field name "net"`, and yara-x says `vt.net is not supported in rulesets matching against files`. ace3's yara service doesn't load `vti/`.
- The other 96 files compile alone in both, with 301 rules between them, and every file defines the same rules with the same meta in both.
- The 96 don't compile together in either scanner, because `analyst_rules_a/signature_name_7.yar` and `signature_name_9.yar` both define `signature_name_6`, and this job puts them in one namespace. Both report it the same way. ace3's service never loads that directory, so this says nothing about production.

The 87 files ace3's yara service loads all compile in both, alone and together, with the same 288 rules: 287 in `site` and 1 in `svs_marker`.

yara-x warns where libyara doesn't: 149 warnings on the 87 files, in 9 files, against libyara's 5. Warnings don't leave anything out. By kind: 88 `potentially_slow_loop` (for example `for any i in (1..#comment)`), 42 `text_as_hex`, 14 `unintended_pattern_in_set` (a pattern such as `$a1` also caught by a set such as `$a*`), 4 `duplicate_pattern_value`, and 1 `deprecated_field` (`pe.number_of_signatures` in `site/signature_name_4.yar`; yara-x suggests `pe.signatures.len()`).

## Match half: the sample set

52 units against the 288 loaded rules, scanned with a 10-second timeout per scan (ace3's `service_yara.default_timeout`).

- 3 rules matched before the filter, once each, with 9 string occurrences between them. Both scanners found the same occurrences.
- The filter dropped all 3 in both, because each rule's `meta_tags` names a tag the unit doesn't carry: `signature_name_1` (wants `type=intel.article`) on `too_many_files.jar`, `signature_name_10` (wants `type=email.combined`) on `sample_pdf_with_qr_code.pdf`, and `signature_name_2` (wants `type=email.attachment` and a file name ending `.eml`) on the untagged `encrypted_zip_password_in_body.email.rfc822`.
- So no match survives the filter on this set, and no scan errors or timeouts occurred.

That is the coverage the plan's sample set gives: 52 units, 3 of 288 rules with a match, 0 rules with a kept match. It can't show much about how the two engines match.

## Match half, supplementary: the rule files as samples

174 units (87 files, each with all 12 tags and with none) against the same 288 rules:

- 91 rules matched before the filter, 316 times in all, with 2,606 string occurrences. Both scanners found every one of them at the same offset, with the same identifier and length.
- The filter kept 133 of the 316 in both, from 76 rules, and dropped the other 183 in both.
- No scan errors or timeouts.

These units are rule source text, not mail or documents, and a rule only matches here when its own strings satisfy its condition. Rules that need binary structure (`uint16(0) == 0x5A4D`, `pe.*`) or many strings together mostly don't match their own source. So this set covers string and regex matching, offsets and the filter well, and modules and file-format conditions hardly at all.

## Mime types

ace4's libmagic (`ace yara scan --json` with no rules) and ace3's `file -b --mime-type` agree on all 53 samples. 12 types occur: `application/java-archive`, `application/msword`, `application/pdf`, `application/vnd.oasis.opendocument.text`, the OOXML spreadsheet and word types, `application/vnd.rar`, `application/x-7z-compressed`, `application/x-ace-compressed`, `application/zip`, `message/rfc822` and `text/rtf`. Step 1.7's test adds text formats such as HTML, SVG, iCalendar and JSON, checked against `file` in ace4's image.

## Timing

One run each, so these are not a benchmark. The compile figures for ace4 include yara-x's code generation for its WebAssembly runtime, which libyara doesn't do.

| Namespace `site`, 287 rules | ace3 | ace4 |
|---|---|---|
| Compile the namespace alone | 0.03 s | 0.42 s |
| Scan the 52 sample units | 0.04 s | 0.05 s |
| Scan the 174 rule-source units | 0.42 s | 0.24 s |

## What this doesn't cover

- **The SVS corpus.** It lives in production. The plan's sample set matched 3 rules, so most rules were compared only on their own source text, and none on mail or documents they would alert on.
- **Paths inside the alert.** Units are scanned at their path in the working directory, as ace3's replay scans them. In ace4's pipeline the path will be the file's path inside the alert, as `ace yara scan --path` already takes it. The filter's path handling is covered by step 1.2's table instead.
- **The Landlock sandbox.** ace3's child ran without it here. It doesn't change what the child computes.
- **Includes.** No rule file in the checkout uses `include`, so neither scanner's include handling was exercised.
