"""The real pcodedmp adapter, with its text changed on the one file that has real p-code."""

import side


def run(path):
    output = side.load("/library-diff/adapters/pcodedmp.py").run(path)
    output["text"] = output["text"].replace("FuncDefn", "FuncDefN", 1)
    return output
