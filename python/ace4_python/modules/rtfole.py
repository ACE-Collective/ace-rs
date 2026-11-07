"""ace3's RTFOLEObjectAnalyzer (saq/modules/file_analysis/rtf.py), on the same oletools.

ace3 runs the rtfobj command and keeps what it prints, its exit code and the files it writes. A
worker can't start a process, so this calls what that command calls: its `main` prints a banner and
runs `process_file`, with logging on stdout. The report is the result here too, so it has to be the
same text. rtfobj's table writes to the sys.stdout it saw at import, so stdout is caught at its
descriptor, which is also what a pipe would have caught.

The result's Rust type is crates/ace-results' RtfOleObjectAnalysis, and its manifest
crates/ace-mod-python's RtfOle. The manifest's deadline stands in for ace3's run_tool timeout.
"""

import logging
import os
import sys
import tempfile
import traceback

from oletools import oleobj, rtfobj

from ace4_python.file_checks import is_rtf_file

MAX_SUMMARY_ITEMS = 20
LOG_FORMAT = "%(levelname)-8s %(message)s"


def print_banner():
    """What rtfobj's main prints first."""
    python_version = "%d.%d.%d" % sys.version_info[0:3]
    print(
        f"rtfobj {rtfobj.__version__} on Python {python_version} - "
        "http://decalage.info/python/oletools"
    )
    print("THIS IS WORK IN PROGRESS - Check updates regularly!")
    print("Please report any issue at https://github.com/decalage2/oletools/issues")
    print("")


def run_rtfobj(input_path, name, output_dir, stdout_path):
    """`rtfobj -d output_dir -s all`, on the file at input_path that's called name. Returns its
    stderr and exit code, and leaves its stdout at stdout_path. As from the command, an exception
    is a traceback and exit code 1, and what was written before it stays."""
    sys.stdout.flush()
    saved_stdout = os.dup(1)
    with open(stdout_path, "wb") as capture:
        os.dup2(capture.fileno(), 1)
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(handler)
    levels = [(log, log.level) for log in (rtfobj.log, oleobj.log)]
    for log, _ in levels:
        log.setLevel(logging.NOTSET)
    try:
        print_banner()
        with open(input_path, "rb") as fp:
            data = fp.read()
        rtfobj.process_file(None, name, data, output_dir=output_dir, save_object="all")
        return "", 0
    except Exception:
        return traceback.format_exc(), 1
    finally:
        for log, level in levels:
            log.setLevel(level)
        root.removeHandler(handler)
        sys.stdout.flush()
        os.dup2(saved_stdout, 1)
        os.close(saved_stdout)


def summarize(extracted_files):
    if not extracted_files:
        return None
    names = ", ".join(extracted_files[:MAX_SUMMARY_ITEMS])
    if len(extracted_files) > MAX_SUMMARY_ITEMS:
        names += f" + {len(extracted_files) - MAX_SUMMARY_ITEMS} more"
    return f"RTF OLE Object Analysis: extracted {names}"


def analyze(ctx):
    file = ctx.observable["file"]
    if file["size"] == 0:
        return ctx.skip("an empty file")
    if not is_rtf_file(ctx.input):
        return ctx.skip("not an RTF file")

    # under the task's outputs, the one place a worker can write; only write_file's are uploaded
    work = tempfile.mkdtemp()
    output_dir = os.path.join(work, "objects")
    os.mkdir(output_dir)
    stdout_path = os.path.join(work, "stdout")
    stderr, return_code = run_rtfobj(ctx.input, file["path"], output_dir, stdout_path)

    # the alert's path where the command's output names the directory it wrote to. Text mode reads
    # newlines as ace3's universal_newlines does
    alert_dir = f"{file['path']}.rtfobj"
    with open(stdout_path, encoding="utf-8", errors="replace") as fp:
        stdout = fp.read().replace(output_dir, alert_dir)
    stderr = stderr.replace(output_dir, alert_dir)

    source = {"type": "file", "value": ctx.value}
    extracted_files = []
    files = []
    # ace3 walks the directory in the filesystem's order, and rtfobj never makes a subdirectory
    for name in sorted(os.listdir(output_dir)):
        with open(os.path.join(output_dir, name), "rb") as fp:
            data = fp.read()
        path = f"{alert_dir}/{name}"
        extracted_files.append(path)
        files.append(
            ctx.write_file(
                path,
                data,
                tags=["extracted_rtf"],
                yara_meta=["type=document.rtf.object"],
                redirection=source,
                relationships=[{"type": "extracted_from", "target": source}],
            )
        )

    details = {
        "stdout": stdout,
        "stderr": stderr,
        "return_code": return_code,
        "extracted_files": extracted_files,
    }
    return ctx.done(details, summary=summarize(extracted_files), files=files)
