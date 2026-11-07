"""What ace3's modules ask about a file before they read it: the parts of
saq/modules/file_analysis/is_file_type.py that the Python pool's modules use, at ace3's values.

file_type isn't ported (PLAN.md 7.5) and these aren't file_type: a task's file already has what
file_type's mime_type would say (`ctx.observable["file"]["mime_type"]`), from the core's libmagic,
the version ace3's `file` is. An extension here is the file's path in the alert, which ends the same
as ace3's path on its node.
"""

import os
import zipfile

KNOWN_OFFICE_EXTENSIONS = frozenset(
    "." + ext
    for ext in """
    doc docb dochtml docm docx docxml dot dothtml dotm dotx odt rtf wbk wiz
    csv dqy iqy odc ods slk xla xlam xlk xll xlm xls xlsb xlshtml xlsm xlsx xlt xlthtml xltm xltx xlw
    odp pot pothtml potm potx ppa ppam pps ppsm ppsx ppt ppthtml pptm pptx pptxml pwz sldm sldx thmx
    """.split()
)


def is_office_ext(path):
    return os.path.splitext(path)[1] in KNOWN_OFFICE_EXTENSIONS


def is_ole_file(path):
    with open(path, "rb") as fp:
        return fp.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def is_rtf_file(path):
    with open(path, "rb") as fp:
        data = fp.read(4)
    return data[:3] == b"\\rt" or data == b"{\\rt"


def is_zip_file(path):
    try:
        with zipfile.ZipFile(path, "r") as zfile:
            return bool(zfile.namelist())
    except Exception:
        return False
