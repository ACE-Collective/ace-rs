"""Tests of the Python pool's modules, on the image's libraries and the real samples. The dev image's
Python has only the standard library, so cargo test can't run them; tests/e2e/run runs this in the
pool's image:

    python3 -I -B /opt/ace4/python/tests/run.py /samples

A module's tests are a TestCase here. The comparison with ace3 is what proves a module's output; these
hold what it doesn't reach, and name the branch when one breaks.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ace4_python.modules import olevba_v1_2  # noqa: E402
from ace4_python.sdk import Context, text_or_bytes  # noqa: E402

SAMPLES = sys.argv[1] if len(sys.argv) > 1 else "/samples"
DOC_WITH_MACROS = "ace3/office/receipt_687790.doc"
STOMPED = "ace3/office/word2013_macro_stripped.doc"
with open(os.path.join(SAMPLES, DOC_WITH_MACROS), "rb") as _fp:
    DOC_BYTES = _fp.read()
DOC_SHA256 = hashlib.sha256(DOC_BYTES).hexdigest()


def run(module, sample=None, data=None, name=None, mime="application/msword", settings=None):
    """Runs a module's analyze on a file in a directory like a task's, and returns its end and that
    directory's outputs, as a contained worker would see them."""
    work = tempfile.mkdtemp()
    os.mkdir(os.path.join(work, "outputs"))
    path = os.path.join(work, "input")
    if sample:
        with open(os.path.join(SAMPLES, sample), "rb") as fp:
            data = fp.read()
    with open(path, "wb") as fp:
        fp.write(data)
    name = name or os.path.basename(sample)
    request = {
        "task": {
            "id": 1,
            "root": "00000000-0000-0000-0000-000000000000",
            "attempts": 1,
            "observable": {
                "type": "file",
                "value": hashlib.sha256(data).hexdigest(),
                "file": {"path": name, "size": len(data), "mime_type": mime},
            },
        },
        "settings": settings,
        "input": path,
        "outputs": os.path.join(work, "outputs"),
        "analysis_type": "olevba_analysis",
        "schema_version": 1,
    }
    end = module.analyze(Context(request, 1))
    # what the worker does with an end, so what JSON can't carry fails here
    json.dumps(end, allow_nan=False).encode("utf-8")
    return end, os.path.join(work, "outputs")


class Olevba(unittest.TestCase):
    def test_macros_become_files_with_ace3s_names_tags_and_directives(self):
        end, outputs = run(olevba_v1_2, sample=DOC_WITH_MACROS)
        result = end["result"]
        details = result["details"]
        self.assertEqual(details["type"], "OLE")
        self.assertEqual(len(details["macros"]), 5)
        self.assertEqual(result["analyzed"], {"tags": ["olevba"], "directives": ["sandbox"]})
        self.assertTrue(result["summary"].startswith("OLEVBA Analysis: (5 macro files) (OLE) | "))
        for index, (macro, file) in enumerate(zip(details["macros"], result["files"])):
            self.assertEqual(file["path"], f"receipt_687790.doc.olevba/macro_{index}.bas")
            self.assertEqual(file["tags"], ["macro"])
            self.assertEqual(file["directives"], ["sandbox"])
            self.assertEqual(file["yara_meta"], ["type=script.macro.vba"])
            self.assertEqual(file["exclude_modules"], ["olevba_v1_2"])
            self.assertEqual(file["redirection"], {"type": "file", "value": DOC_SHA256})
            self.assertEqual(macro["local_path"], file["sha256"])
            self.assertEqual(macro["file_name"], "receipt_687790.doc")
            with open(os.path.join(outputs, file["sha256"]), "rb") as stored:
                self.assertEqual(stored.read().decode("utf-8"), macro["vba_code"])

    def test_every_count_is_one_as_in_ace3(self):
        kinds = [("AutoExec", "a", ""), ("AutoExec", "b", ""), ("IOC", "c", "")]
        self.assertEqual(olevba_v1_2.keyword_summary(kinds), {"autoexec": 1, "ioc": 1})

    def test_a_stomped_document_has_no_task_path_in_its_p_code(self):
        end, _ = run(olevba_v1_2, sample=STOMPED)
        code = next(
            m["vba_code"] for m in end["result"]["details"]["macros"]
            if m["stream_path"] == "VBA P-code"
        )
        self.assertTrue(code.startswith("' Processing file: word2013_macro_stripped.doc\n"), code[:80])

    def test_merged_macros_share_one_file(self):
        end, _ = run(olevba_v1_2, sample=DOC_WITH_MACROS, settings={"merge_macros": True})
        result = end["result"]
        self.assertEqual([f["path"] for f in result["files"]], ["receipt_687790.doc.olevba/macros.bas"])
        self.assertEqual({m["local_path"] for m in result["details"]["macros"]},
                         {result["files"][0]["sha256"]})

    def test_a_threshold_not_met_leaves_no_tag(self):
        end, _ = run(olevba_v1_2, sample=DOC_WITH_MACROS, settings={"thresholds": {"dridex string": 1}})
        self.assertEqual(end["result"]["analyzed"], {})
        self.assertEqual(len(end["result"]["details"]["macros"]), 5)

    def test_what_ace3_checks_before_it_opens_a_file(self):
        ole = DOC_BYTES
        for why, kwargs in {
            "RTF": {"data": b"{\\rtf1 x}", "name": "a.doc"},
            "MSI": {"data": ole, "name": "A.MSI"},
            "not an Office": {"data": b"just text", "name": "a.txt"},
            "4 MB": {"data": ole + b"\0" * (4 * 1024 * 1024), "name": "a.doc"},
            "text/html": {"data": b"<html>", "name": "a.doc", "mime": "text/html"},
            "text/plain": {"data": b"text", "name": "a.doc", "mime": "text/plain"},
        }.items():
            end, _ = run(olevba_v1_2, **kwargs)
            self.assertEqual(end["outcome"], "skipped", why)

    def test_a_file_oletools_cant_open_fails_only_under_an_office_extension(self):
        junk = bytes(range(256)) * 8
        end, _ = run(olevba_v1_2, data=junk, name="a.doc")
        self.assertEqual(end["result"]["analyzed"], {"tags": ["olevba_failed"], "directives": ["sandbox"]})
        self.assertIsNone(end["result"]["details"]["type"])
        zipped = run(olevba_v1_2, sample="ace3/archive/test.jar")[0]
        self.assertEqual(zipped["result"]["analyzed"], {})

    def test_a_hostile_name_stays_bytes_and_the_result_lands(self):
        end, _ = run(olevba_v1_2, sample="ace4/office/surrogate_name.doc")
        macro = end["result"]["details"]["macros"][0]
        self.assertEqual(macro["file_name"], {"base64": "7aCALm1zbw=="})
        self.assertEqual(macro["stream_path"], "VBA/ThisDocument")

    def test_text_or_bytes(self):
        self.assertEqual(text_or_bytes("é"), "é")
        self.assertEqual(text_or_bytes(b"\xff"), {"base64": "/w=="})
        # what a surrogateescape decoding of the byte 0xff leaves
        self.assertEqual(text_or_bytes("\udcff"), {"base64": "/w=="})
        self.assertEqual(text_or_bytes("\ud800"), {"base64": "7aCA"})

    def test_a_result_doesnt_say_where_its_task_ran(self):
        # a run's path in a result would make every tree of a macro document differ
        end, _ = run(olevba_v1_2, sample=DOC_WITH_MACROS)
        self.assertNotIn(tempfile.gettempdir(), json.dumps(end))


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1], verbosity=1)
