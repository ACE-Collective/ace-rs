"""What a module gets and returns: the Python side of the lease API's task and TaskEnd.

A module is a file with `analyze(ctx)`, which returns ctx.done(...), ctx.skip(...) or ctx.delay(...),
and raises ModuleError or anything else to fail its task. The supervisor reads what it returns as a
TaskEnd, and the core checks a result against the JSON Schema of the module's Rust analysis type
(crates/ace-mod-python), so nothing here validates it. A result that fails ends its task as failed
at once, with each failing field's path in the row, and nothing from it lands.

`ace schema export <dir>` writes the schemas. To try a result before it reaches a pool, write
`ctx.done(...)["result"]` to a file with json.dump and run `ace schema check <file>`, which is the
core's own check, so this image needs no JSON Schema library.
"""

import base64
import hashlib
import os
import tempfile


class ModuleError(Exception):
    """The module failed, for a reason its message says in full."""


def text_or_bytes(value):
    """A value that's usually text, as crates/ace-results' TextOrBytes writes it. JSON can't carry
    bytes, and a str holding a lone surrogate, which a library's decoding of a hostile file can
    leave, is JSON the core can't read. Either would lose the whole result, so these stay bytes."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            try:
                value = value.encode("utf-8", "surrogateescape")
            except UnicodeEncodeError:
                value = value.encode("utf-8", "surrogatepass")
    return {"base64": base64.b64encode(bytes(value)).decode("ascii")}


def failed(error):
    return {"outcome": "failed", "error": error}


class Context:
    """One task as a module sees it."""

    def __init__(self, request, tasks_in_process):
        task = request["task"]
        self.task_id = task["id"]
        self.root = task["root"]
        self.attempts = task["attempts"]
        self.observable = task["observable"]
        self.value = self.observable["value"]
        self.delayed = task.get("delayed")
        self.settings = request.get("settings")
        # the input's bytes, for a file task
        self.input = request.get("input")
        # the YARA rules that matched the file or anything under it, for a module that runs last
        # (Module::RUNS_LAST)
        self.yara_rules_below = task.get("yara_rules_below") or []
        self.tasks_in_process = tasks_in_process
        self._outputs = request["outputs"]
        # the one place a worker can write, for libraries that use tempfile; its directory goes with
        # the task, and only what write_file stored in it is uploaded
        tempfile.tempdir = self._outputs
        self._analysis_type = request["analysis_type"]
        self._schema_version = request["schema_version"]

    def done(self, details, **envelope):
        """The module's result. `envelope` holds any other ResultEnvelope field by name, such as
        summary, tags, detections, observables and files."""
        result = {
            "analysis_type": self._analysis_type,
            "schema_version": self._schema_version,
            "details": details,
            **envelope,
        }
        return {"outcome": "done", "result": result}

    def skip(self, reason):
        return {"outcome": "skipped", "reason": reason}

    def delay(self, after_seconds, state=None):
        return {"outcome": "delay", "after_seconds": after_seconds, "state": state}

    def write_file(self, path, data, **fields):
        """Stores bytes the module produced and returns the record for done(files=[...]). `path` is
        the file's path in the alert; the supervisor refuses an absolute path or a `..` part, which
        fails the task (#829). `fields` holds any other NewFile field by name, such as yara_meta,
        tags, directives, exclude_modules and redirection."""
        sha256 = hashlib.sha256(data).hexdigest()
        with open(os.path.join(self._outputs, sha256), "wb") as stored:
            stored.write(data)
        return {"path": path, "sha256": sha256, "size": len(data), **fields}
