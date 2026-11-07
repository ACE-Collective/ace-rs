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
import signal
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ace4_python.file_checks import file_description, is_office_file  # noqa: E402
from ace4_python.modules import pcodedmp, xlmdeobfuscator  # noqa: E402
from ace4_python.sdk import Context, text_or_bytes  # noqa: E402

SAMPLES = sys.argv[1] if len(sys.argv) > 1 else "/samples"
DOC_WITH_MACROS = "ace3/office/receipt_687790.doc"
STOMPED = "ace3/office/word2013_macro_stripped.doc"
with open(os.path.join(SAMPLES, DOC_WITH_MACROS), "rb") as _fp:
    DOC_BYTES = _fp.read()
DOC_SHA256 = hashlib.sha256(DOC_BYTES).hexdigest()


def run(
    module,
    sample=None,
    data=None,
    name=None,
    mime="application/msword",
    settings=None,
    yara_rules_below=None,
):
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
    if yara_rules_below:
        request["task"]["yara_rules_below"] = yara_rules_below
    end = module.analyze(Context(request, 1))
    # what the worker does with an end, so what JSON can't carry fails here
    json.dumps(end, allow_nan=False).encode("utf-8")
    return end, os.path.join(work, "outputs")


class TextOrBytes(unittest.TestCase):
    def test_text_or_bytes(self):
        self.assertEqual(text_or_bytes("é"), "é")
        self.assertEqual(text_or_bytes(b"\xff"), {"base64": "/w=="})
        # what a surrogateescape decoding of the byte 0xff leaves
        self.assertEqual(text_or_bytes("\udcff"), {"base64": "/w=="})
        self.assertEqual(text_or_bytes("\ud800"), {"base64": "7aCA"})


def stored(outputs, file):
    with open(os.path.join(outputs, file["sha256"]), "rb") as fp:
        return fp.read()


class XlmDeobfuscator(unittest.TestCase):
    def outputs(self, end, outputs):
        return {f["path"]: stored(outputs, f) for f in end["result"]["files"]}

    def test_a_macro_that_builds_its_url_is_emulated_and_its_cells_listed(self):
        name = "xlm_obfuscated.xlsm"
        end, outputs = run(xlmdeobfuscator, sample=f"ace4/office/{name}")
        result = end["result"]
        self.assertEqual(result["details"], {"cell_count": 13})
        self.assertEqual(result["summary"], "XLMMacroDeobfuscator Analysis - analyzed 13 cells")
        self.assertEqual(result["analyzed"]["tags"], ["xlm4"])
        self.assertEqual(
            result["analyzed"]["detections"],
            [{"description": xlmdeobfuscator.DETECTION, "signature_uuid": xlmdeobfuscator.SIGNATURE_UUID}],
        )
        files = self.outputs(end, outputs)
        emulated = files[f"{name}.xlmdeobfuscator/xlmdeobfuscator.stdout"]
        extracted = files[f"{name}.xlmdeobfuscator/xlmdeobfuscatorextractcells.stdout"]
        self.assertTrue(emulated.startswith(f"\nFile: {name}\n".encode()), emulated[:60])
        self.assertTrue(extracted.startswith(f"\nFile: {name}\n".encode()), extracted[:60])
        self.assertIn(b"http://xlm-built.example.com/stage2.exe", emulated)
        self.assertNotIn(b"http://xlm-built.example.com/stage2.exe", extracted)
        self.assertIn("é日本".encode(), emulated)
        for data in (emulated, extracted):
            self.assertNotIn(b"time elapsed", data)
        for file in result["files"]:
            self.assertEqual(file["directives"], ["extract_urls", "crawl_extracted_urls"])
            self.assertEqual(file["yara_meta"], ["type=script.macro.xlm"])
        self.assertEqual(
            sorted((o["value"], o["directives"]) for o in result["observables"]),
            [
                ("HTTP://Upper.example.com/a b", ["crawl"]),
                ("http://xlm-built.example.com/stage2.exe", ["crawl"]),
                ("https://xlm-plain.example.com/a?b=1", ["crawl"]),
            ],
        )

    def test_each_format_is_read(self):
        for name, cells, url in [
            ("xlm_biff8.xls", 5, "http://xlm-biff8.example.com/stage2.exe"),
            ("xlm_xlsb.xlsb", 3, "http://xlm-xlsb.example.com/stage2.exe"),
        ]:
            end, _ = run(xlmdeobfuscator, sample=f"ace4/office/{name}")
            self.assertEqual(end["result"]["details"], {"cell_count": cells}, name)
            self.assertIn(url, [o["value"] for o in end["result"]["observables"]])

    def test_a_question_for_stdin_ends_in_its_eof_and_stdin_is_left_alone(self):
        before = sys.stdin
        end, outputs = run(xlmdeobfuscator, sample="ace4/office/xlm_no_entry.xlsm")
        self.assertIs(sys.stdin, before)
        emulated = self.outputs(end, outputs)["xlm_no_entry.xlsm.xlmdeobfuscator/xlmdeobfuscator.stdout"]
        self.assertIn(b"There is no entry point", emulated)
        self.assertIn(b"EOF when reading a line", emulated)

        end, outputs = run(xlmdeobfuscator, sample="ace4/office/xlm_unknown_cell.xlsm")
        emulated = self.outputs(end, outputs)["xlm_unknown_cell.xlsm.xlmdeobfuscator/xlmdeobfuscator.stdout"]
        self.assertIn(b"Process Interruption:", emulated)
        self.assertIn(b"EOF when reading a line", emulated)

    def test_what_comes_of_no_cells_and_a_workbook_that_wont_load(self):
        end, _ = run(xlmdeobfuscator, sample="ace4/office/xlm_no_cells.xlsm")
        self.assertEqual(end["result"]["analyzed"]["tags"], ["xlm4:no_cells"])
        end, _ = run(xlmdeobfuscator, sample="ace4/office/xlm_broken.xlsm")
        self.assertEqual(end["result"]["analyzed"]["tags"], ["xlm4:no_cells", "xlm4:error"])

    def test_a_pass_out_of_time_is_tagged_and_the_next_still_runs(self):
        end, _ = run(xlmdeobfuscator, sample="ace4/office/xlm_loop.xlsm", settings={"timeout": 1})
        result = end["result"]
        self.assertEqual(result["analyzed"]["tags"], ["xlmdeobfuscator_failed", "xlm4"])
        self.assertEqual(
            [f["path"] for f in result["files"]],
            ["xlm_loop.xlsm.xlmdeobfuscator/xlmdeobfuscatorextractcells.stdout"],
        )
        self.assertEqual(result["details"], {"cell_count": 5})
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_only_a_file_with_macros_and_under_the_limit_is_read(self):
        doc = dict(data=b"plain text", name="book.xlsb")
        self.assertEqual(run(xlmdeobfuscator, **doc)[0]["outcome"], "skipped")
        self.assertEqual(
            run(xlmdeobfuscator, **doc, yara_rules_below=["Some_Other_Rule"])[0]["outcome"], "skipped"
        )
        end, _ = run(xlmdeobfuscator, **doc, yara_rules_below=["XLM_Macrosheet_NonBin"])
        self.assertEqual(end["outcome"], "done")
        self.assertEqual(end["result"]["details"], {"cell_count": 0})
        end, _ = run(xlmdeobfuscator, **doc, yara_rules_below=["Mine"], settings={"yara_rule_names": ["Mine"]})
        self.assertEqual(end["outcome"], "done")
        end, _ = run(
            xlmdeobfuscator, sample="ace4/office/xlm_obfuscated.xlsm", settings={"maximum_size_mb": 0}
        )
        self.assertEqual(end["outcome"], "skipped")

    def test_a_url_with_no_host_is_no_observable_but_still_a_detection(self):
        self.assertTrue(xlmdeobfuscator.names_a_host("https://example.com/a"))
        self.assertTrue(xlmdeobfuscator.names_a_host("HTTP://Upper.example.com/a b"))
        self.assertTrue(xlmdeobfuscator.names_a_host("http://[x/"))
        self.assertTrue(xlmdeobfuscator.names_a_host("https:\\\\evil.example.com"))
        self.assertFalse(xlmdeobfuscator.names_a_host("http://%"))
        self.assertFalse(xlmdeobfuscator.names_a_host("https://.."))
        end, _ = run(xlmdeobfuscator, sample="ace4/office/xlm_obfuscated.xlsm")
        self.assertNotIn("http://%", [o["value"] for o in end["result"]["observables"]])

    def test_stdout_is_given_back(self):
        before = os.fstat(1)
        run(xlmdeobfuscator, sample="ace4/office/xlm_biff8.xls")
        after = os.fstat(1)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))


class PCode(unittest.TestCase):
    def test_a_macro_document_has_its_disassembly(self):
        end, outputs = run(pcodedmp, sample=DOC_WITH_MACROS)
        result = end["result"]
        file = result["files"][0]
        self.assertEqual(file["path"], "receipt_687790.doc.pcode.bas")
        self.assertEqual(file["yara_meta"], ["type=script.vbscript"])
        self.assertEqual(file["redirection"], {"type": "file", "value": DOC_SHA256})
        data = stored(outputs, file)
        self.assertGreater(result["details"]["line_count"], 0)
        self.assertEqual(data.count(b"\n"), result["details"]["line_count"])
        self.assertEqual(result["summary"], f"PCode Analysis: decoded {result['details']['line_count']} lines")
        self.assertTrue(data.startswith(b"\t"), data[:20])
        self.assertNotIn(b"Processing file", data)
        self.assertNotIn(b"/outputs", data)

    def test_the_wrappers_filter(self):
        text = "Processing file: a\n\tbefore\nModule streams:\na - 1 bytes\nLine #0:\n\tLitStr 0x0001 \"x\"\n y\u2003\n\xa0no\n\u2003yes\nlast"
        self.assertEqual(pcodedmp.disassembly(text), "\tLitStr 0x0001 \"x\"\n y\u2003\n\u2003yes\n")
        self.assertEqual(pcodedmp.disassembly("\tno streams\n"), "")

    def test_a_document_with_no_macros_or_no_office_file_has_no_result(self):
        self.assertEqual(run(pcodedmp, sample="ace3/office/doc.docx")[0]["outcome"], "skipped")
        end, _ = run(pcodedmp, data=b"plain text", name="note.txt")
        self.assertEqual(end, {"outcome": "skipped", "reason": "not an Office file"})

    def test_a_document_is_known_by_libmagic_without_its_extension(self):
        with open(os.path.join(SAMPLES, "ace3/office/doc.docx"), "rb") as sample, tempfile.NamedTemporaryFile() as fp:
            fp.write(sample.read())
            fp.flush()
            self.assertTrue(is_office_file("attachment.bin", fp.name), file_description(fp.name))
        # "Microsoft Office Word" isn't the "microsoft word" ace3 looks for
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(DOC_BYTES)
            fp.flush()
            self.assertFalse(is_office_file("attachment.bin", fp.name), file_description(fp.name))
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(b"plain text\n")
            fp.flush()
            self.assertEqual(file_description(fp.name), "ASCII text")
            self.assertFalse(is_office_file("attachment.bin", fp.name))
            self.assertTrue(is_office_file("a/b.docm", fp.name))


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1], verbosity=1)
