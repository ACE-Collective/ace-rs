"""Runs ace-yara's meta filter table through yara_scanner_v2's own filter_scan_results.

PLAN.md 1.2 ports the filter, and crates/ace-yara/tests/filter.rs checks the port against
the table in crates/ace-yara/tests/fixtures/filter_cases.json. This script checks the same
table against ace3's library, so the expected values are ace3's behaviour and not a reading
of it. It runs on ace3's Python in ace3's dev container and reads the table on stdin:

    tools/ace3/yara/in-ace3 tools/ace3/yara/filter_cases.py \
        < crates/ace-yara/tests/fixtures/filter_cases.json

Each case becomes a stand-in for a yara-python match with the case's meta. The library runs
`file -b --mime-type` for a mime_type directive, so Popen is replaced with one that answers
the case's mime type. Prints each case whose outcome differs from the table, and exits 1 if
any does.
"""

import io
import json
import sys

import yara_scanner

RULE = "table_rule"


class FakeMatch:
    """The attributes of a yara.Match that filter_scan_results reads."""

    def __init__(self, meta):
        self.rule = RULE
        self.meta = meta
        self.namespace = "table"
        self.tags = []
        self.strings = []


class FakePopen:
    mime_type = ""

    def __init__(self, argv, **kwargs):
        assert argv[:3] == ["file", "-b", "--mime-type"], argv
        self.stdout = io.BytesIO(FakePopen.mime_type.encode())


def main() -> int:
    table = json.load(sys.stdin)
    yara_scanner.Popen = FakePopen

    differences = 0
    for case in table["cases"]:
        FakePopen.mime_type = case.get("mime_type", "")
        scanner = yara_scanner.YaraScanner()
        scanner.blacklist = [RULE] if case.get("blacklisted") else []
        kept = scanner.filter_scan_results(
            case["path"], None, [FakeMatch(case["meta"])], meta_tags=case.get("meta_tags") or None)
        if kept != case["keep"]:
            differences += 1
            print(f"DIFFERS: {case['name']}: yara_scanner_v2 kept={kept}, the table says {case['keep']}")

    print(f"{len(table['cases'])} cases, {differences} differ from yara_scanner_v2 {yara_scanner.__version__}")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
