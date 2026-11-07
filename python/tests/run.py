"""Tests of the Python pool's modules, on the image's libraries and the real samples. The dev image's
Python has only the standard library, so cargo test can't run them; tests/e2e/run runs this in the
pool's image:

    python3 -I -B /opt/ace4/python/tests/run.py /samples

A module's tests are a TestCase here. The comparison with ace3 is what proves a module's output; these
hold what it doesn't reach, and name the branch when one breaks.
"""

import hashlib
import json
import logging
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ace4_python.modules import olevba_v1_2, rtfole  # noqa: E402
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


class RtfOle(unittest.TestCase):
    def run_rtf(self, name):
        return run(rtfole, sample=f"ace4/rtf/{name}", mime="text/rtf")

    def test_objects_become_files_with_ace3s_names_tags_and_links(self):
        end, outputs = self.run_rtf("objects.rtf")
        result = end["result"]
        details = result["details"]
        self.assertEqual(details["return_code"], 0)
        self.assertEqual(details["stderr"], "")
        names = [file["path"] for file in result["files"]]
        self.assertEqual(names, details["extracted_files"])
        self.assertEqual(names, sorted(names))
        for name in ("payload.exe", "._._evil.exe", "caf\u00e9.txt", "inner.zip", "inner.rtf"):
            self.assertIn(f"objects.rtf.rtfobj/objects.rtf_{name}", names)
        with open(os.path.join(SAMPLES, "ace4/rtf/objects.rtf"), "rb") as fp:
            source = {"type": "file", "value": hashlib.sha256(fp.read()).hexdigest()}
        for file in result["files"]:
            self.assertEqual(file["tags"], ["extracted_rtf"])
            self.assertEqual(file["yara_meta"], ["type=document.rtf.object"])
            self.assertEqual(file["redirection"], source)
            self.assertEqual(file["relationships"], [{"type": "extracted_from", "target": source}])
            with open(os.path.join(outputs, file["sha256"]), "rb") as stored:
                self.assertEqual(hashlib.sha256(stored.read()).hexdigest(), file["sha256"])

    def test_the_report_is_the_commands_and_names_no_task_path(self):
        end, outputs = self.run_rtf("objects.rtf")
        stdout = end["result"]["details"]["stdout"]
        self.assertTrue(stdout.startswith("rtfobj 0.60.1 on Python "), stdout[:80])
        self.assertIn("File: 'objects.rtf' - size: ", stdout)
        # the table is written to the sys.stdout rtfobj saw at import
        self.assertIn("id |index     |OLE Object", stdout)
        self.assertIn("EXECUTABLE FILE", stdout)
        self.assertIn("URL extracted: http://example.com/a.hta", stdout)
        self.assertIn("  saving to file objects.rtf.rtfobj/objects.rtf_payload.exe\n", stdout)
        self.assertNotIn(os.path.dirname(outputs), stdout)

    def test_running_it_leaves_the_worker_as_it_was(self):
        stdout_was = os.fstat(1)
        handlers_were = list(logging.getLogger().handlers)
        self.run_rtf("no_objects.rtf")
        self.assertEqual(os.fstat(1).st_ino, stdout_was.st_ino)
        self.assertEqual(logging.getLogger().handlers, handlers_were)
        self.assertGreater(rtfole.rtfobj.log.level, logging.CRITICAL)
        self.assertGreater(rtfole.oleobj.log.level, logging.CRITICAL)

    def test_an_exception_is_an_exit_code_and_what_was_saved_stays(self):
        details = self.run_rtf("bin_at_end.rtf")[0]["result"]["details"]
        self.assertEqual(details["return_code"], 1)
        self.assertIn("TypeError: ord() expected a character", details["stderr"])
        self.assertEqual(details["extracted_files"], [])

        end, outputs = self.run_rtf("long_name.rtf")
        details = end["result"]["details"]
        self.assertEqual(details["return_code"], 1)
        self.assertIn("File name too long: 'long_name.rtf.rtfobj/long_name.rtf_", details["stderr"])
        self.assertEqual(details["extracted_files"], ["long_name.rtf.rtfobj/long_name.rtf_saved.txt"])
        self.assertNotIn(os.path.dirname(outputs), details["stderr"])

    def test_a_name_with_glob_characters_is_read(self):
        details = self.run_rtf("bracket[1].rtf")[0]["result"]["details"]
        self.assertEqual(details["extracted_files"], ["bracket[1].rtf.rtfobj/bracket_1_.rtf_payload.exe"])

    def test_what_ace3_checks_before_it_reads_a_file(self):
        self.assertEqual(run(rtfole, data=b"", name="a.rtf")[0]["outcome"], "skipped")
        self.assertEqual(self.run_rtf("text_named.rtf")[0]["outcome"], "skipped")
        end = self.run_rtf("backslash_start.rtf")[0]
        self.assertEqual(end["outcome"], "done")
        self.assertEqual(len(end["result"]["files"]), 1)
        end = self.run_rtf("no_objects.rtf")[0]
        self.assertEqual(end["result"]["details"]["extracted_files"], [])
        self.assertIsNone(end["result"]["summary"])

    def test_the_summary_lists_twenty(self):
        self.assertEqual(rtfole.summarize(["a", "b"]), "RTF OLE Object Analysis: extracted a, b")
        names = [str(n) for n in range(22)]
        self.assertEqual(
            rtfole.summarize(names),
            "RTF OLE Object Analysis: extracted " + ", ".join(names[:20]) + " + 2 more",
        )


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1], verbosity=1)
