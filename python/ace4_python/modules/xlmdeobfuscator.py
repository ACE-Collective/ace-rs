"""ace3's XLMMacroDeobfuscatorAnalyzer (saq/modules/file_analysis/xlm.py), on the same library.

ace3 runs the xlmdeobfuscator command twice. `-f` emulates the macro from its Auto_Open, which is what
shows a URL a macro only builds when it runs, and `-x` lists the cells with no emulation, which still
works when emulation can't: the tags and the cell count come from that one. A worker can't start a
process, so this calls the command's own `main` each time and reads what it prints, at file descriptor
1 because the library binds sys.stdout at import, which is also what a pipe would have caught. What
differs from the command's stdout is on purpose: the file is named by its path in the alert, and the
last line, `time elapsed`, is left out. Either would give the file a new sha256 each run.

The command isn't given -n, so it asks stdin where to start, and what a cell holds, when it can't tell.
ace3's stdin is at its end, so each question ends in `EOF when reading a line`, and the macro's text has
that error in it. A worker's descriptor 0 isn't a stdin, so sys.stdin is put at its end here.

ace3 gives each pass 30 s: past that it drops what the pass printed, tags the file and goes on, so a
macro that spins in emulation still has its cells listed. A timer does that here. It can't stop C code,
such as a regular expression that never ends, and there the manifest's deadline fails the task with
its stack in the row, losing both passes.

The result's Rust type is crates/ace-results' XlmDeobfuscatorAnalysis, and its manifest
crates/ace-mod-python's XlmDeobfuscator.
"""

import io
import os
import re
import shutil
import signal
import sys
import tempfile
from urllib.parse import urlsplit

import yara_x
from XLMMacroDeobfuscator import deobfuscator

# ace3's etc/xlmdeobfuscator.yar. Rules tagged xlm4 say a file has Excel 4.0 macros
RULES = yara_x.compile(
    open(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "xlmdeobfuscator.yar"),
        encoding="utf-8",
    ).read()
)
DEFAULT_SETTINGS = {
    "timeout": 30,
    "maximum_size_mb": 10,
    "yara_rule_names": ["Content_Types_Macrosheet", "XLM_Macrosheet_NonBin", "Possible_XLM_in_XLSB"],
}
# ace3's built-in XLM_MACRO_URL signature
SIGNATURE_UUID = "3e719b5d-8063-4cd7-a72b-3d1cc8ead39c"
DETECTION = "A url was found in an Excel 4.0 macro."
ENCRYPTED_TEXT = b"Failed to decrypt the file\nUse --password switch to provide the correct password"

BROWSER_IGNORED_CHARS = str.maketrans("", "", "\t\r\n")

RE_CELL = re.compile(rb"\nCELL:")
RE_ERROR = re.compile(rb"\nError ")
RE_PARAMS = re.compile(r"^CELL:.*\(([^\)]*)\)$")
RE_URL = re.compile(r'https?://[^"]+', re.IGNORECASE)
RE_ELAPSED = re.compile(rb"time elapsed: [0-9.e+-]+\n\Z")


class PassTimeout(BaseException):
    """A pass ran out of time. The library catches Exception, and a bare `except:` here and there, so
    this isn't one, and the timer goes on firing until it gets out."""


def run_command(args, output_path, timeout):
    """`xlmdeobfuscator <args>` with stdin at its end and stdout in output_path. Returns False if it
    ran out of time."""
    armed = True

    def on_alarm(_signal, _frame):
        if armed:
            raise PassTimeout()

    sys.stdout.flush()
    saved_stdout = os.dup(1)
    with open(output_path, "wb") as capture:
        os.dup2(capture.fileno(), 1)
    saved_argv, saved_stdin = sys.argv, sys.stdin
    sys.argv, sys.stdin = ["xlmdeobfuscator", *args], io.StringIO("")
    saved_handler = signal.signal(signal.SIGALRM, on_alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout, 1)
        deobfuscator.main()
        return True
    except PassTimeout:
        return False
    except SystemExit:
        return True
    finally:
        armed = False
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, saved_handler)
        sys.argv, sys.stdin = saved_argv, saved_stdin
        sys.stdout.flush()
        os.dup2(saved_stdout, 1)
        os.close(saved_stdout)


def clean_output(stdout, library_path, alert_path):
    """The command's stdout as ace3 keeps it, with the banner cut off, and as the port names things."""
    if b"\nFile:" in stdout:
        stdout = stdout[stdout.index(b"\nFile:") :]
    stdout = stdout.replace(os.fsencode(library_path), os.fsencode(alert_path))
    return RE_ELAPSED.sub(b"", stdout)


def urls_in(stdout):
    """The URLs passed as parameters in the macro's cells: ace3's _extract_urls."""
    urls = []
    for line in stdout.decode(errors="replace").split("\n"):
        if line.startswith("CELL:"):
            match = RE_PARAMS.match(line)
            if match:
                urls += RE_URL.findall(match.group(1))
    return urls


def names_a_host(url):
    """ace3's URLObservable refuses a URL with no host, which is text an attacker wrote, and keeps one
    urlsplit can't read. This module is the first port to add URLs, and the core doesn't check them."""
    try:
        scheme = urlsplit(url).scheme
        if scheme not in ("http", "https", "ftp"):
            return True
        rest = url.partition(":")[2].translate(BROWSER_IGNORED_CHARS).replace("\\", "/").lstrip("/")
        return any(c.isalnum() for c in urlsplit(f"{scheme}://{rest}").hostname or "")
    except ValueError:
        return True


def has_macros(ctx, rules_below, rule_names):
    """Whether ace3 would analyze this file: its own rules, or the YARA module's in it or below it."""
    if rules_below.intersection(rule_names):
        return True
    with open(ctx.input, "rb") as fp:
        results = RULES.scan(fp.read())
    return any("xlm4" in rule.tags for rule in results.matching_rules)


def analyze(ctx):
    file = ctx.observable["file"]
    settings = {**DEFAULT_SETTINGS, **(ctx.settings or {})}
    if file["size"] > settings["maximum_size_mb"] * 1024 * 1024:
        return ctx.skip(f"larger than {settings['maximum_size_mb']} MB")
    if not has_macros(ctx, set(ctx.yara_rules_below), settings["yara_rule_names"]):
        return ctx.skip("no Excel 4.0 macros")

    # under the task's outputs, the one place a worker can write. The library reads the file's name
    # when a macro asks for it (GET.DOCUMENT), so it has the name ace3's has
    work = tempfile.mkdtemp()
    library_path = os.path.join(work, os.path.basename(file["path"]))
    shutil.copyfile(ctx.input, library_path)
    output_path = os.path.join(work, "stdout")
    output_dir = f"{file['path']}.xlmdeobfuscator"

    tags, files, urls = [], [], []
    cell_count = 0

    def run_pass(args, failed_tag):
        """What the pass printed, or None when it printed nothing or ran out of time."""
        finished = run_command([*args, "-f", library_path], output_path, settings["timeout"])
        if not finished:
            tags.append(failed_tag)
            return None
        with open(output_path, "rb") as fp:
            return clean_output(fp.read(), library_path, file["path"]) or None

    def add_output(name, stdout):
        files.append(
            ctx.write_file(
                f"{output_dir}/{name}",
                stdout,
                directives=["extract_urls", "crawl_extracted_urls"],
                yara_meta=["type=script.macro.xlm"],
            )
        )
        urls.extend(urls_in(stdout))

    def end():
        analyzed = {"tags": tags}
        if urls:
            # one, however many URLs: ace3 keeps one detection point per description
            analyzed["detections"] = [{"description": DETECTION, "signature_uuid": SIGNATURE_UUID}]
        return ctx.done(
            {"cell_count": cell_count},
            summary=f"XLMMacroDeobfuscator Analysis - analyzed {cell_count} cells",
            analyzed=analyzed,
            observables=[
                {"type": "url", "value": url, "directives": ["crawl"]}
                for url in dict.fromkeys(urls)
                if names_a_host(url)
            ],
            files=files,
        )

    stdout = run_pass([], "xlmdeobfuscator_failed")
    if stdout and ENCRYPTED_TEXT in stdout:
        return end()
    if stdout:
        add_output("xlmdeobfuscator.stdout", stdout)

    stdout = run_pass(["-x"], "xlmdeobfuscatorextractcells_failed")
    if stdout and ENCRYPTED_TEXT in stdout:
        return end()
    if stdout:
        add_output("xlmdeobfuscatorextractcells.stdout", stdout)
        cell_count = len(RE_CELL.findall(stdout))
        tags.append("xlm4" if cell_count else "xlm4:no_cells")
        if RE_ERROR.search(stdout):
            tags.append("xlm4:error")

    return end()
