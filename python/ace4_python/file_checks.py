"""What ace3's modules ask about a file before they read it: the parts of
saq/modules/file_analysis/is_file_type.py that the Python pool's modules use, at ace3's values.

file_type isn't ported (PLAN.md 7.5) and these aren't file_type: a task's file already has what
file_type's mime_type would say (`ctx.observable["file"]["mime_type"]`), from the core's libmagic,
the version ace3's `file` is. An extension here is the file's path in the alert, which ends the same
as ace3's path on its node.

A task doesn't carry `file -b`'s description, which is_office_file reads, so file_description asks the
image's libmagic, the library the pool's binary links, with the database it was built to read. A
hostile file meets libmagic here inside the worker's containment, which is better than in the core.
"""

import ctypes
import os
import zipfile

MAGIC_SYMLINK = 0x2
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


_magic = None


def file_description(path):
    """What `file -b -L` says about the file."""
    global _magic
    if _magic is None:
        library = ctypes.CDLL("libmagic.so.1")
        library.magic_open.restype = ctypes.c_void_p
        library.magic_open.argtypes = [ctypes.c_int]
        library.magic_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        library.magic_file.restype = ctypes.c_char_p
        library.magic_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        cookie = library.magic_open(MAGIC_SYMLINK)
        if not cookie or library.magic_load(cookie, None) != 0:
            raise RuntimeError("libmagic's database didn't load")
        _magic = (library, cookie)
    library, cookie = _magic
    return (library.magic_file(cookie, os.fsencode(path)) or b"").decode("utf-8", "replace")


def is_office_file(alert_path, path):
    """is_office_file: by the extension, or by what libmagic calls the file."""
    if is_office_ext(os.path.basename(alert_path)):
        return True
    description = file_description(path).lower()
    return any(
        name in description
        for name in (
            "microsoft powerpoint", "microsoft excel", "microsoft word", "microsoft ooxml", "opendocument",
        )
    )
