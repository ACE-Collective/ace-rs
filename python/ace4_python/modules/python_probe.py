"""A module for testing the pool itself (crates/ace-mod-python's PythonProbe). It reports the
process it ran in and does what the first part of its fqdn says, so a test picks an action by
naming an observable. A test's overlay turns it on; no site should.

  hold-<N>     keep N MB of written memory for the rest of the process
  print        write to stdout, which mustn't reach the protocol
  raise        raise an exception
  fail         raise ModuleError
  crash        exit the process at once
  hang         run forever in pure Python
  hang-sleep   hang in a C call that has let go of the GIL, time.sleep
  hang-select  hang in a C call that has let go of the GIL, select.select
  hang-regex   hang in a C call that holds the GIL, a regular expression that backtracks
  hang-stopped stop this process with SIGSTOP, so py-spy can't pause it
  hang-closed  refuse to be read, with PR_SET_DUMPABLE, and hang
  hang-hostile hang in a function whose name holds a NUL and an escape sequence
  tool         try to use py-spy, which a worker mustn't reach, and report what happened
  ptrace-<P>   try to read process P's memory, and report what happened
  fork         fork, which containment answers by killing the process
  thread       start a thread, likewise
  connect-<P>  connect to TCP port P on this machine, and report what happened
  read         try to read a file outside the worker's paths, and report what happened
  temp         write a temporary file, as libraries do, and report what happened
  file         write a file, whose path in the alert is probe.txt
  files-<N>    write N different files
  libraries    import every library the pool's image exists for, and report their versions
  wrong        return a result whose pid isn't a number, adding an observable and a file
  unknown      return a result with a field its type doesn't have
  envelope     return a result whose summary isn't a string
  bytes        return a result holding bytes, which JSON can't carry
  forge        reply with the end only a supervisor may send
  anything else: only the report
"""

import ctypes
import importlib
import importlib.metadata
import importlib.util
import os
import re
import select
import signal
import socket
import sys
import tempfile
import threading
import time

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

# where the image installs py-spy, as PythonConfig says
PY_SPY = "/opt/ace4/tools/bin/py-spy"
# longer than any deadline
FOREVER = 100000

_held = []


def _hang_in_python():
    while True:
        pass


def _hang_in_sleep():
    time.sleep(FOREVER)


def _hang_in_select():
    select.select([], [], [], FOREVER)


def _hang_in_regex():
    re.match(r"(a+)+b", "a" * 64)


def _hang_stopped():
    os.kill(os.getpid(), signal.SIGSTOP)


def _hang_closed():
    PR_SET_DUMPABLE = 4
    ctypes.CDLL(None).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    time.sleep(FOREVER)


def _hang_hostile():
    name = "_hang_hostile\0\x1b]0;owned\x07"
    code = _hang_in_sleep.__code__.replace(co_qualname=name, co_name=name)
    type(_hang_in_sleep)(code, globals())()


HANGS = {
    None: _hang_in_python,
    "sleep": _hang_in_sleep,
    "select": _hang_in_select,
    "regex": _hang_in_regex,
    "stopped": _hang_stopped,
    "closed": _hang_closed,
    "hostile": _hang_hostile,
}


def _reach_the_tool():
    """What a worker gets from py-spy: nothing, if containment holds."""

    def run():
        # on success this process becomes py-spy, and the reply never comes
        os.execv(PY_SPY, ["py-spy", "--version"])

    def read():
        with open(PY_SPY, "rb") as tool:
            return f"{len(tool.read(4))} bytes"

    found = importlib.util.find_spec("py_spy")
    return f"import: {found}; read: {_attempt(read)}; run: {_attempt(run)}"


def _read_process(pid):
    """Tries everything py-spy does to process `pid`."""
    PTRACE_ATTACH, PTRACE_DETACH = 16, 17

    class Iovec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_readv.restype = ctypes.c_ssize_t

    def answer(result):
        return "allowed" if result >= 0 else f"refused: {os.strerror(ctypes.get_errno())}"

    buffer = ctypes.create_string_buffer(8)
    here = Iovec(ctypes.addressof(buffer), 8)
    # an address no one's memory need hold, because the permission check comes before the read
    there = Iovec(0x400000, 8)
    read = libc.process_vm_readv(pid, ctypes.byref(here), 1, ctypes.byref(there), 1, 0)
    reading = answer(0 if read < 0 and ctypes.get_errno() == 14 else read)
    attach = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
    attaching = answer(attach)
    if attach == 0:
        libc.ptrace(PTRACE_DETACH, pid, 0, 0)
    memory = _attempt(lambda: open(f"/proc/{pid}/mem", "rb").close())
    return f"ptrace: {attaching}; process_vm_readv: {reading}; /proc mem: {memory}"


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
        HANGS[argument or None]()
        return "hung, and it came back", []
    if action == "tool":
        return _reach_the_tool(), []
    if action == "ptrace":
        return _read_process(int(argument)), []
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
    if action == "temp":
        return _attempt(lambda: tempfile.TemporaryFile().write(b"x")), []
    if action == "file":
        return "wrote a file", [ctx.write_file("probe.txt", b"from the probe\n")]
    if action == "files":
        return "wrote files", [
            ctx.write_file(f"probe_{n}.txt", b"file %d\n" % n) for n in range(int(argument))
        ]
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
    if action == "wrong":
        # a result the core must refuse, with things in it that must not land
        rejected = ctx.write_file("rejected.txt", b"from a rejected result\n")
        observables = [{"type": "fqdn", "value": "rejected.example.com"}]
        return ctx.done({**details, "pid": "not a pid"}, observables=observables, files=[rejected])
    if action == "unknown":
        return ctx.done({**details, "extra": 1})
    if action == "envelope":
        return ctx.done(details, summary=3)
    if action == "forge":
        return {"outcome": "hung", "error": "forged", "stacks": "a stack the worker wrote"}
    if action == "bytes":
        return ctx.done({**details, "note": b"bytes"})
    return ctx.done(details, summary=f"ran in {details['pid']}", files=files)
