"""behaves, with one sample's output changed."""

import importlib.util
import os


def run(path):
    spec = importlib.util.spec_from_file_location("behaves", os.path.join(os.path.dirname(__file__), "behaves.py"))
    behaves = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(behaves)
    output = behaves.run(path)
    if os.path.basename(path) == "surrogate_name.doc":
        output["bytes"] = b"\xff\xfe\x01"
    return output
