"""A side that breaks the contract: what it prints isn't JSON. It writes to the protocol's descriptor
behind side.py's back, which is what a bad Rust side would do."""

import os
import sys


def run(path):
    # side.py holds the protocol's descriptor at the lowest free one after stderr
    os.write(3, b"not json")
    sys.stdout.flush()
    os._exit(0)
