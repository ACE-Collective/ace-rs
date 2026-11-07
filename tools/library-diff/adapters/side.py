"""A Python side of tools/library-diff/run: `python -I -B side.py <adapter.py> <file>`.

An adapter is a module with `run(path)`, which calls its library on one file and returns what the
library gave, for a Rust port to give the same, and may have `has_content(output)`, for whether the
library read anything from the file. A library can answer every file and find nothing in any, so a run
needs some file with content. This prints one JSON object on stdout and exits 0:

    {"output": <what run returned>, "content": <what has_content said, when false>}
    {"error": {"type": "ValueError", "message": "..."}}   when run raised, SystemExit included

Bytes stay bytes: in JSON they're {"base64": "..."}, as ace_results::Bytes writes them, and so is a
string that isn't valid Unicode, the form of ace_results::TextOrBytes. A port's side writes the same.

Libraries print, some of them when imported, so the protocol keeps stdout to itself and points
descriptor 1 at stderr first, as the Python pool's worker did.
"""

import base64
import contextlib
import importlib.util
import io
import json
import math
import os
import sys


def canon(value):
    """What a library returned as JSON, losing nothing."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"base64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return canon(value.encode("utf-8", "surrogateescape" if escaped(value) else "surrogatepass"))
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        if all(isinstance(key, str) and canon(key) == key for key in value):
            return {key: canon(item) for key, item in value.items()}
        return [[canon(key), canon(item)] for key, item in value.items()]
    if isinstance(value, (list, tuple)):
        return [canon(item) for item in value]
    raise TypeError(f"an adapter returned a {type(value).__name__}: {value!r}")


def escaped(text):
    """Whether every surrogate in text is one surrogateescape made from a byte."""
    return all(not 0xD800 <= ord(c) <= 0xDFFF or 0xDC80 <= ord(c) <= 0xDCFF for c in text)


def error_data(error):
    """An exception as something to compare."""
    if isinstance(error, SystemExit):
        return {"type": "SystemExit", "message": str(error.code)}
    return {"type": type(error).__name__, "message": str(error)}


@contextlib.contextmanager
def captured_fd1(path="/tmp/library-diff-stdout"):
    """Catches descriptor 1 while the body runs, because a library may have bound sys.stdout when
    imported. Yields a list that holds the bytes when the body ends, raised or not."""
    captured = []
    sys.stdout.flush()
    saved = os.dup(1)
    with open(path, "wb") as capture:
        os.dup2(capture.fileno(), 1)
    try:
        yield captured
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)
        with open(path, "rb") as fp:
            captured.append(fp.read())
        os.remove(path)


@contextlib.contextmanager
def captured_stderr():
    """Catches sys.stderr, which pcodedmp reports errors on."""
    caught = io.StringIO()
    with contextlib.redirect_stderr(caught):
        yield caught


def load(adapter):
    """The adapter, by path, so that one named after its library doesn't hide that library."""
    spec = importlib.util.spec_from_file_location("library_diff_adapter", adapter)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(adapter, path):
    replies = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    # adapters import this module by name
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    try:
        module = load(adapter)
        output = module.run(path)
        reply = {"output": canon(output)}
        if hasattr(module, "has_content") and not module.has_content(output):
            reply["content"] = False
    except BaseException as error:  # a library's exception, whatever it is, is data
        reply = {"error": canon(error_data(error))}
    replies.write(json.dumps(reply, allow_nan=False, ensure_ascii=True).encode("ascii"))
    replies.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
