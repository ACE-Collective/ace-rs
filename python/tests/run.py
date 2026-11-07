"""Tests of the Python pool's SDK. The dev image's Python has only the standard library, so cargo test
can't run them; tests/e2e/run runs this in the pool's image:

    python3 -I -B /opt/ace4/python/tests/run.py /samples

No module is left on the pool but the probe since PLAN.md 4.12, whose tests are tests/e2e/run's.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ace4_python.sdk import text_or_bytes  # noqa: E402

class TextOrBytes(unittest.TestCase):
    def test_text_or_bytes(self):
        self.assertEqual(text_or_bytes("é"), "é")
        self.assertEqual(text_or_bytes(b"\xff"), {"base64": "/w=="})
        # what a surrogateescape decoding of the byte 0xff leaves
        self.assertEqual(text_or_bytes("\udcff"), {"base64": "/w=="})
        self.assertEqual(text_or_bytes("\ud800"), {"base64": "7aCA"})


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1], verbosity=1)
