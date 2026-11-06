"""A Python pool's worker (PLAN.md 4.1): runs tasks one after another until EOF on stdin.

The supervisor (crates/ace-pool/src/python.rs) starts it with the names of the modules to import,
contained and with an empty environment. It holds no token and can't reach the lease API, the
network or the bucket. The supervisor does all of that, and keeps a task's lease and deadline.

On stdin it reads one JSON request a line, and on stdout it writes `{"ready": true}` once, then one
TaskEnd (crates/ace-sdk/src/wire.rs) a line. Modules and their libraries sometimes print, so the
protocol keeps those two descriptors to itself and points 0 and 1 at stderr, which the supervisor
logs. A setup failure exits 10, as a parser's task process does.
"""

import importlib
import json
import os
import sys
import traceback

# python -I leaves this directory off sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ace4_python.registry import MODULES  # noqa: E402
from ace4_python.sdk import Context, ModuleError, failed  # noqa: E402

EXIT_SETUP = 10
MAX_ERROR = 4000


def load(names):
    """Imports only the modules named, each exposing analyze(ctx)."""
    return {name: importlib.import_module(MODULES[name]) for name in names}


def run_one(request, modules, tasks_in_process):
    """Runs one request and returns its TaskEnd. Whatever the module raises fails the task, not the
    worker, even SystemExit, which some of these libraries' code paths raise."""
    try:
        ctx = Context(request, tasks_in_process)
        return modules[request["module"]].analyze(ctx)
    except ModuleError as error:
        return failed(str(error))
    except BaseException:
        return failed(traceback.format_exc()[-MAX_ERROR:])


def main(names):
    requests = os.fdopen(os.dup(0), "rb")
    replies = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 0)
    os.dup2(2, 1)
    # what a module prints goes to the log as it prints it
    sys.stdout.reconfigure(line_buffering=True)
    try:
        modules = load(names)
    except BaseException:
        traceback.print_exc()
        return EXIT_SETUP
    replies.write(b'{"ready": true}\n')
    replies.flush()
    tasks_in_process = 0
    for line in requests:
        tasks_in_process += 1
        end = run_one(json.loads(line), modules, tasks_in_process)
        replies.write(json.dumps(end).encode() + b"\n")
        replies.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
