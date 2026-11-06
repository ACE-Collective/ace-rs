"""What a module gets and returns: the Python side of the lease API's task and TaskEnd.

A module is a file with `analyze(ctx)`, which returns ctx.done(...), ctx.skip(...) or ctx.delay(...),
and raises ModuleError or anything else to fail its task. The supervisor reads what it returns as a
TaskEnd, and the core checks a result against the JSON Schema of the module's Rust analysis type
(crates/ace-mod-python, `ace schema export`), so nothing here validates it.
"""

import hashlib
import os


class ModuleError(Exception):
    """The module failed, for a reason its message says in full."""


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
        self.tasks_in_process = tasks_in_process
        self._outputs = request["outputs"]
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

    def write_file(self, path, data, yara_meta=(), tags=()):
        """Stores bytes the module produced and returns the record for done(files=[...]). `path` is
        the file's path in the alert; the supervisor refuses an absolute path or a `..` part, which
        fails the task (#829)."""
        sha256 = hashlib.sha256(data).hexdigest()
        with open(os.path.join(self._outputs, sha256), "wb") as stored:
            stored.write(data)
        record = {"path": path, "sha256": sha256, "size": len(data)}
        if yara_meta:
            record["yara_meta"] = list(yara_meta)
        if tags:
            record["tags"] = list(tags)
        return record
