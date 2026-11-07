"""pcodedmp, as python/ace4_python/modules/pcodedmp.py calls it, whole: what the module's filter keeps
is the port's business, and what it drops shows where the two part. processFile reports an error on
sys.stderr and returns, so that's in the output too."""

import argparse
import io

from pcodedmp.pcodedmp import processFile

import side

ARGS = argparse.Namespace(disasmOnly=False, verbose=False, norecurse=False)


def has_content(output):
    """More than its first line, which names the file whatever it is."""
    return output["text"].count("\n") > 1


def run(path):
    output = io.StringIO()
    with side.captured_stderr() as errors:
        processFile(path, ARGS, output_file=output)
    return {"text": output.getvalue(), "errors": errors.getvalue()}
