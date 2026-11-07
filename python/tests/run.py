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
import signal
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ace4_python.modules import msoffice_encryption_analyzer as msoffice  # noqa: E402
from ace4_python.file_checks import file_description, is_office_file  # noqa: E402
from ace4_python.modules import olevba_v1_2, pcodedmp, rtfole, xlmdeobfuscator  # noqa: E402
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
    email_body=None,
    carried_by_email=False,
    yara_rules_below=None,
):
    """Runs a module's analyze on a file in a directory like a task's, and returns its end and that
    directory's outputs, as a contained worker would see them. email_body is the bytes of the body of
    the email that carried it."""
    work = tempfile.mkdtemp()
    os.mkdir(os.path.join(work, "outputs"))
    path = os.path.join(work, "input")
    if sample:
        with open(os.path.join(SAMPLES, sample), "rb") as fp:
            data = fp.read()
    with open(path, "wb") as fp:
        fp.write(data)
    name = name or os.path.basename(sample)
    body_path = None
    if email_body is not None:
        body_path = os.path.join(work, "email_body")
        with open(body_path, "wb") as fp:
            fp.write(email_body)
        carried_by_email = True
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
        "email_body": body_path,
        "outputs": os.path.join(work, "outputs"),
        "analysis_type": "olevba_analysis",
        "schema_version": 1,
    }
    if carried_by_email:
        request["task"]["carrying_email"] = {"body": None}
    if yara_rules_below:
        request["task"]["yara_rules_below"] = yara_rules_below
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


class MsofficeEncryption(unittest.TestCase):
    NO_EMAIL = "ace4/office/encrypted_no_email.docx"

    def details(self, sample, **kwargs):
        return run(msoffice, sample=sample, **kwargs)[0]["result"]["details"]

    def test_a_password_in_the_body_decrypts_the_file_and_it_goes_on_with_ace3s_names(self):
        sample = "ace4/office/encrypted_velvet.docx"
        end, outputs = run(msoffice, sample=sample, name="a.docx", email_body=b"nothing useful\n")
        result = end["result"]
        self.assertEqual(result["summary"], "MSOffice Encryption Analysis: password VelvetSweatshop")
        self.assertEqual(result["analyzed"], {"tags": ["encrypted_msoffice"]})
        file = result["files"][0]
        self.assertEqual(file["path"], "a.docx.decrypted")
        self.assertEqual(file["tags"], ["decrypted_msoffice"])
        self.assertEqual(file["yara_meta"], ["type=document.office"])
        self.assertEqual(
            file["detections"][0]["signature_uuid"], "ef715326-081e-4ece-97ba-02817b5a28cd"
        )
        with open(os.path.join(outputs, file["sha256"]), "rb") as stored:
            self.assertEqual(stored.read(2), b"PK")

    def test_a_password_the_body_doesnt_hold_is_a_result_with_no_file(self):
        end = run(msoffice, sample=self.NO_EMAIL, email_body=b"The password is wrong\n")[0]
        result = end["result"]
        self.assertEqual(result["details"]["error"], "could not crack password")
        self.assertIsNone(result["details"]["password"])
        self.assertEqual(result["files"], [])
        self.assertEqual(result["details"]["email_body"], "The password is wrong\n\n")

    def test_what_the_email_gives_it(self):
        details = self.details(self.NO_EMAIL)
        self.assertFalse(details["email"])
        self.assertIsNone(details["email_body"])
        self.assertEqual(details["word_list"], msoffice.DEFAULT_PASSWORDS)
        details = self.details(self.NO_EMAIL, carried_by_email=True)
        self.assertTrue(details["email"])
        self.assertIsNone(details["email_body"])

    def test_the_word_list_is_ace3s_set(self):
        words = msoffice.generate_wordlist("ab cdef\nghij", 4, 5, 1024, 5000)
        self.assertEqual(words, ["cdef", "ghij"])
        # a limit stops on the same words whatever the order, and the byte limit cuts the text
        self.assertEqual(msoffice.generate_wordlist("abcdefgh", 4, 5, 1024, 2), ["abcd", "bcde"])
        self.assertEqual(msoffice.generate_wordlist("abcdefgh", 4, 5, 4, 5000), ["abcd"])
        self.assertEqual(msoffice.generate_wordlist("", 4, 5, 1024, 5000), [])

    def test_a_file_it_cant_read_or_that_isnt_encrypted_is_skipped(self):
        for sample in ("ace3/office/doc.docx", "ace3/office/doc.doc", "ace4/office/encrypted_extensible.docx"):
            self.assertEqual(run(msoffice, sample=sample)[0]["outcome"], "skipped", sample)
        self.assertEqual(run(msoffice, data=b"plain text", name="a")[0]["outcome"], "skipped")
        self.assertEqual(run(msoffice, data=b"", name="empty")[0]["outcome"], "skipped")

    def test_john_has_no_format_for_xor_so_nothing_is_tried(self):
        for sample, verifier in (
            ("ace4/office/encrypted_xor.doc", "Password Verifier : b'78563412'"),
            ("ace4/office/encrypted_xor.xls", "key : b'cdab', hash : b'3412'"),
        ):
            details = self.details(sample, name="x", email_body=b"The password is whatever\n")
            self.assertEqual(
                details["error"], f"office2john.py failed: x : XOR obfuscation detected, {verifier}\n"
            )
            self.assertEqual(details["word_list"], [])

    def test_a_spin_count_past_the_time_stops_with_the_result_ace3_gets(self):
        real_office_file = msoffice.msoffcrypto.OfficeFile
        real_time = msoffice.TIME_TO_CRACK

        def huge_spin(fp):
            office = real_office_file(fp)
            office.info["spinValue"] = 2**31 - 1
            return office

        msoffice.msoffcrypto.OfficeFile = huge_spin
        msoffice.TIME_TO_CRACK = 0.2
        try:
            details = self.details(self.NO_EMAIL, email_body=b"The password is Secr3tPw\n")
        finally:
            msoffice.msoffcrypto.OfficeFile = real_office_file
            msoffice.TIME_TO_CRACK = real_time
        self.assertEqual(details["error"], "could not crack password")
        self.assertIn("Secr3tPw", details["word_list"])


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
