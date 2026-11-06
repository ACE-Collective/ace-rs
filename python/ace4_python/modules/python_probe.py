"""A module for testing the pool itself (crates/ace-mod-python's PythonProbe). It reports the
process it ran in and does what the first part of its fqdn says, so a test picks an action by
naming an observable. A test's overlay turns it on; no site should.

  hold-<N>     keep N MB of written memory for the rest of the process
  print        write to stdout, which mustn't reach the protocol
  raise        raise an exception
  fail         raise ModuleError
  crash        exit the process at once
  hang         run forever
  fork         fork, which containment answers by killing the process
  thread       start a thread, likewise
  connect-<P>  connect to TCP port P on this machine, and report what happened
  read         try to read a file outside the worker's paths, and report what happened
  file         write a file, whose path in the alert is probe.txt
  libraries    import every library the pool's image exists for, and report their versions
  anything else: only the report
"""

import importlib
import importlib.metadata
import os
import socket
import sys
import threading

from ace4_python.sdk import ModuleError

# the distributions, and the module each imports as
LIBRARIES = {
    "oletools": "oletools.olevba",
    "msoffcrypto-tool": "msoffcrypto",
    "pcodedmp": "pcodedmp.pcodedmp",
    "XLMMacroDeobfuscator": "XLMMacroDeobfuscator.deobfuscator",
    "xlrd2": "xlrd2",
    "pyxlsb2": "pyxlsb2",
}

_held = []


def _attempt(call):
    try:
        return f"allowed: {call()}"
    except OSError as error:
        return f"refused: {type(error).__name__}: {error}"


def _libraries():
    versions = []
    for distribution, module in LIBRARIES.items():
        importlib.import_module(module)
        versions.append(f"{distribution} {importlib.metadata.version(distribution)}")
    return ", ".join(versions)


def _act(action, argument, ctx):
    """Returns the action's note and the result's files."""
    if action == "hold":
        _held.append(b"\x01" * (int(argument) * 1024 * 1024))
        return f"holding {argument} MB", []
    if action == "print":
        print("a module that prints")
        os.write(1, b"and one that writes to the descriptor\n")
        return "printed", []
    if action == "raise":
        raise ValueError(f"the probe raised on {ctx.value}")
    if action == "fail":
        raise ModuleError(f"the probe failed on {ctx.value}")
    if action == "crash":
        os._exit(7)
    if action == "hang":
        while True:
            pass
    if action == "fork":
        os.fork()
        return "forked", []
    if action == "thread":
        threading.Thread(target=lambda: None).start()
        return "started a thread", []
    if action == "connect":
        return _attempt(lambda: socket.create_connection(("127.0.0.1", int(argument)), 5)), []
    if action == "read":
        return _attempt(lambda: open("/etc/passwd", encoding="utf-8").read(10)), []
    if action == "file":
        return "wrote a file", [ctx.write_file("probe.txt", b"from the probe\n")]
    if action == "libraries":
        return _libraries(), []
    return None, []


def analyze(ctx):
    action, _, argument = ctx.value.split(".", 1)[0].partition("-")
    note, files = _act(action, argument, ctx)
    details = {
        "pid": os.getpid(),
        "uid": os.getuid(),
        "tasks_in_process": ctx.tasks_in_process,
        "python": sys.version.split()[0],
        "environment": sorted(os.environ),
        "note": note,
    }
    return ctx.done(details, summary=f"ran in {details['pid']}", files=files)
