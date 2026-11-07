"""ace3's OLEVBA_Analyzer_v1_2 (saq/modules/file_analysis/olevba.py), on the same oletools.

The result's Rust type is crates/ace-results' OlevbaAnalysis, and its manifest crates/ace-mod-python's
Olevba. The deadline is the manifest's: oletools can hang on a crafted file.
"""

import logging

from oletools.olevba import VBA_Parser, filter_vba

from ace4_python.file_checks import is_office_ext, is_ole_file, is_rtf_file, is_zip_file
from ace4_python.sdk import text_or_bytes

MODULE = "olevba_v1_2"
MAX_SIZE = 4 * 1024 * 1024
DEFAULT_THRESHOLDS = {"autoexec": 1, "suspicious": 1}
SANDBOX = "sandbox"


def why_not(ctx, file):
    """Why ace3's checks would leave this file alone, if they would. A file with no result."""
    if is_rtf_file(ctx.input):
        return "an RTF file"
    if file["path"].lower().endswith(".msi"):
        return "an MSI file"
    if not (is_office_ext(file["path"]) or is_ole_file(ctx.input) or is_zip_file(ctx.input)):
        return "not an Office, OLE or zip file"
    if file["size"] > MAX_SIZE:
        return "larger than 4 MB"
    if "html" in file["mime_type"] or file["mime_type"] == "text/plain":
        return f"its mime type is {file['mime_type']}"
    return None


def keyword_summary(scan_results):
    """As ace3 counts them. It looks up the kind before lowercasing it, so it starts each count
    again and every count is 1. The summary and the thresholds read these, so the port keeps it."""
    summary = {}
    for kind, _keyword, _description in scan_results:
        if kind not in summary:
            summary[kind.lower()] = 0
        summary[kind.lower()] += 1
    return summary


def meets_thresholds(summary, thresholds):
    return all(summary.get(kind, -1) >= count for kind, count in thresholds.items())


def summarize(details):
    if not details["type"] or not details["macros"]:
        return None
    counts = ", ".join(f"{kind}={count}" for kind, count in details["keyword_summary"].items())
    return (
        f"OLEVBA Analysis: ({len(details['macros'])} macro files) ({details['type']}) | {counts}"
    )


def analyze(ctx):
    file = ctx.observable["file"]
    reason = why_not(ctx, file)
    if reason:
        return ctx.skip(reason)

    settings = ctx.settings or {}
    merge = settings.get("merge_macros", False)
    thresholds = settings.get("thresholds", DEFAULT_THRESHOLDS)
    details = {"type": None, "macros": [], "keyword_summary": {}}
    files = []
    analyzed = {}

    def add_macro_file(name, code):
        """ace3's _add_macro_file: its record, whose sha256 names what's in it."""
        files.append(
            ctx.write_file(
                f"{file['path']}.olevba/{name}",
                code.encode("utf-8"),
                tags=["macro"],
                directives=[SANDBOX],
                yara_meta=["type=script.macro.vba"],
                redirection={"type": "file", "value": ctx.value},
                exclude_modules=[MODULE],
            )
        )
        return files[-1]["sha256"]

    def macro(file_name, stream_path, vba_filename, code):
        # oletools names an OLE file by the path it opened, which here is the task's
        named = lambda name: file["path"] if name == ctx.input else name  # noqa: E731
        return {
            "file_name": text_or_bytes(named(file_name)),
            "stream_path": text_or_bytes(stream_path),
            "vba_filename": text_or_bytes(named(vba_filename)),
            "vba_code": code,
        }

    parser = None
    try:
        parser = VBA_Parser(ctx.input, relaxed=True)
        details["type"] = parser.type
        if parser.detect_vba_macros():
            # deobfuscate=True hung on 0.55.1, ace3 says
            scan_results = parser.analyze_macros(show_decoded_strings=True, deobfuscate=False)
            index = 0
            merged = []
            for file_name, stream_path, vba_filename, vba_code in parser.extract_all_macros():
                if isinstance(vba_code, bytes):
                    vba_code = vba_code.decode("utf8", errors="ignore")
                vba_code = filter_vba(vba_code)
                if not vba_code.strip():
                    continue
                if stream_path == "VBA P-code":
                    # pcodedmp starts by naming the path it read, which is this task's, so the
                    # macro's file would have a new sha256 each run
                    vba_code = vba_code.replace(ctx.input, file["path"])
                entry = macro(file_name, stream_path, vba_filename, vba_code)
                if merge:
                    merged.append(entry)
                else:
                    entry["local_path"] = add_macro_file(f"macro_{index}.bas", vba_code)
                    details["macros"].append(entry)
                index += 1
            if merged:
                sha256 = add_macro_file("macros.bas", "".join(m["vba_code"] for m in merged))
                details["macros"] += [{**m, "local_path": sha256} for m in merged]
            if scan_results:
                details["keyword_summary"] = keyword_summary(scan_results)
                if meets_thresholds(details["keyword_summary"], thresholds):
                    analyzed = {"tags": ["olevba"], "directives": [SANDBOX]}
    except Exception as error:
        logging.warning("olevba execution error on %s: %s", file["path"], error)
        analyzed = (
            {"tags": ["olevba_failed"], "directives": [SANDBOX]}
            if is_office_ext(file["path"])
            else {}
        )
    finally:
        if parser:
            try:
                parser.close()
            except Exception:
                logging.exception("unable to close olevba parser")

    return ctx.done(details, summary=summarize(details), analyzed=analyzed, files=files)
