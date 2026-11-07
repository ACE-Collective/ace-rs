"""XLMMacroDeobfuscator, as crates/ace-mod-xlm calls its port: the command's main twice, emulating with
-f and listing cells with -x, with stdin at its end and 30 s for each pass. A pass that runs out has
`timed_out`, as the module drops it and goes on. Its banner and its last line, `time elapsed`, are cut as
the module cuts them. The file keeps its own path. When lark can't parse a formula it lists what it
expected from a set, whose order changes each run, so that list is sorted here, as the port writes it."""

import io
import re
import signal
import sys

from XLMMacroDeobfuscator import deobfuscator

import side

TIMEOUT = 30
RE_ELAPSED = re.compile(rb"time elapsed: [0-9.e+-]+\n\Z")
RE_EXPECTED = re.compile(rb"Expected one of: \n((?:\t\* [^\n]*\n)+)")


class PassTimeout(BaseException):
    """Not an Exception, because the library catches those, and the timer goes on firing because it
    has a bare `except:` here and there."""


def one_pass(args, path):
    armed = True

    def on_alarm(_signal, _frame):
        if armed:
            raise PassTimeout()

    result = {"timed_out": False}
    saved_argv, saved_stdin = sys.argv, sys.stdin
    sys.argv, sys.stdin = ["xlmdeobfuscator", *args, "-f", path], io.StringIO("")
    saved_handler = signal.signal(signal.SIGALRM, on_alarm)
    with side.captured_fd1() as stdout:
        try:
            signal.setitimer(signal.ITIMER_REAL, TIMEOUT, 1)
            deobfuscator.main()
        except PassTimeout:
            result["timed_out"] = True
        except SystemExit:
            pass
        except Exception as error:
            result["raised"] = side.error_data(error)
        finally:
            armed = False
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, saved_handler)
            sys.argv, sys.stdin = saved_argv, saved_stdin
    # dropped when it timed out, since where it stopped depends on the machine
    if not result["timed_out"]:
        text = stdout[0]
        if b"\nFile:" in text:
            text = text[text.index(b"\nFile:") :]
        text = RE_EXPECTED.sub(
            lambda m: b"Expected one of: \n" + b"".join(sorted(m.group(1).splitlines(True))), RE_ELAPSED.sub(b"", text)
        )
        result["stdout"] = text
    return result


def has_content(output):
    return any(b"CELL:" in one.get("stdout", b"") for one in output.values())


def run(path):
    return {"emulation": one_pass([], path), "cells": one_pass(["-x"], path)}
