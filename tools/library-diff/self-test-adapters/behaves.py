"""What self-test runs in place of a library: one behaviour per sample."""

import os
import signal
import time


def run(path):
    name = os.path.basename(path)
    if name == "garbage.doc":
        raise ValueError(f"not a document: {path}")
    if name == "text_named.doc":
        time.sleep(600)
    if name == "html_named.doc":
        os.kill(os.getpid(), signal.SIGSEGV)
    if name == "source.doc":
        return {"random": os.urandom(8)}
    if name == "surrogate_name.doc":
        return {"bytes": b"\xff\xfe\x00", "broken_text": "caf\udce9", "wide": "caf\xe9"}
    return {"size": os.path.getsize(path), "tuple": (1, "two")}
