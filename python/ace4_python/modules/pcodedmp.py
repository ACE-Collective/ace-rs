"""ace3's PCodeAnalyzer (saq/modules/file_analysis/vbs.py), on the same pcodedmp.

ace3 runs the command through bin/pcodedmp_wrapper, which keeps a module's disassembly and drops the
rest. A worker can't start a process, so this calls processFile, which writes to the file it's given,
and does the wrapper's `sed -ne '/^Module streams:/,$ p' | egrep '^[[:space:]]'`. What that keeps doesn't
name the file it read, so unlike olevba's p-code there's no task path here to replace.

The wrapper stops pcodedmp at 30 s and ace3 keeps nothing, with no result and only a log line. Here the
manifest's 30 s deadline fails the task, with its stack in the row.

The result's Rust type is crates/ace-results' PCodeAnalysis, and its manifest crates/ace-mod-python's
PCode.
"""

import argparse
import io
import re

from pcodedmp.pcodedmp import processFile

from ace4_python.file_checks import is_office_file

# what [[:space:]] is in the C.UTF-8 locale ace3 runs egrep under
RE_INDENTED = re.compile("[ \t\n\v\f\r  -  -    　]")
ARGS = argparse.Namespace(disasmOnly=False, verbose=False, norecurse=False)


def disassembly(text):
    """The wrapper's filter. A newline is the only thing that ends a line, whatever a string in the
    macro holds."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    for index, line in enumerate(lines):
        if line.startswith("Module streams:"):
            return "".join(f"{kept}\n" for kept in lines[index:] if RE_INDENTED.match(kept))
    return ""


def analyze(ctx):
    file = ctx.observable["file"]
    if not is_office_file(file["path"], ctx.input):
        return ctx.skip("not an Office file")

    output = io.StringIO()
    processFile(ctx.input, ARGS, output_file=output)
    code = disassembly(output.getvalue()).encode("utf-8", "surrogateescape")
    if not code:
        return ctx.skip("no p-code")

    line_count = code.count(b"\n")
    return ctx.done(
        {"line_count": line_count},
        summary=f"PCode Analysis: decoded {line_count} lines",
        files=[
            ctx.write_file(
                f"{file['path']}.pcode.bas",
                code,
                yara_meta=["type=script.vbscript"],
                redirection={"type": "file", "value": ctx.value},
            )
        ],
    )
