"""pdf-parser.py with the arguments ace3's PDFAnalyzer gives it (ace3's pdf.py, run_pdfparser). It's a
command there, and here too, so this catches what the command does: its stdout, which ace3 keeps as a
file, and its exit code. stderr only says whether there was any: ace3 logs that it was, and a traceback
names this script's path."""

import os
import subprocess
import sys

PARSER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor", "pdf-parser.py")


def has_content(output):
    """It dumps any file as comments, so an object is what says it read a PDF."""
    return b"obj " in output["stdout"]


def run(path):
    done = subprocess.run(
        [sys.executable, "-I", "-B", PARSER, "-f", "-w", "-v", "-c", "--debug", path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    return {"stdout": done.stdout, "exit": done.returncode, "stderr": bool(done.stderr)}
