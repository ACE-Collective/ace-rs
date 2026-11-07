"""oletools' rtfobj, as python/ace4_python/modules/rtfole.py calls it: the report it prints, with its
logging, and the files it writes."""

import logging
import os
import sys

from oletools import oleobj, rtfobj

import side

OBJECTS = "/tmp/rtfobj-objects"


def has_content(output):
    return bool(output["files"])


def run(path):
    output = {}
    os.mkdir(OBJECTS)
    with open(path, "rb") as fp:
        data = fp.read()
    with side.captured_fd1() as stdout:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
        logging.getLogger().addHandler(handler)
        for log in (rtfobj.log, oleobj.log):
            log.setLevel(logging.NOTSET)
        try:
            rtfobj.process_file(None, path, data, output_dir=OBJECTS, save_object="all")
        except Exception as error:
            # the command prints a traceback and keeps what it wrote before it
            output["raised"] = side.error_data(error)
    output["stdout"] = stdout[0]
    output["files"] = {}
    for name in sorted(os.listdir(OBJECTS)):
        with open(os.path.join(OBJECTS, name), "rb") as fp:
            output["files"][name] = fp.read()
    return output
