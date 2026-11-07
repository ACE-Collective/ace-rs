"""msoffcrypto, as python/ace4_python/modules/msoffice_encryption_analyzer.py calls it: what it says
of the file and, for each password, whether it opens it and what it decrypts to.

The passwords are ace3's two defaults and those of tools/samples/make-encrypted-office and ace3's
info_3805.xls, so a port is compared on the right ones and the wrong ones.
"""

import io

import msoffcrypto
from msoffcrypto import exceptions

import side

PASSWORDS = [
    "VelvetSweatshop",
    "/01Hannes Ruescher/01",
    "709384",
    "Secr3tPw",
    "St4ndard",
    "H7mlPass",
    "NotInTheBody99",
    "InnerPw1",
]


def attempt(path, password):
    """A fresh OfficeFile for each, since load_key keeps state on it."""
    attempt = {"password": password, "opens": False}
    with open(path, "rb") as fp:
        office_file = msoffcrypto.OfficeFile(fp)
        try:
            if office_file.format == "ooxml":
                office_file.load_key(password=password, verify_password=True)
            else:
                office_file.load_key(password=password)
        except exceptions.InvalidKeyError:
            return attempt
        except Exception as error:
            attempt["raised"] = side.error_data(error)
            return attempt
        attempt["opens"] = True
        out = io.BytesIO()
        try:
            office_file.decrypt(out)
            attempt["decrypted"] = out.getvalue()
        except Exception as error:
            attempt["raised"] = side.error_data(error)
    return attempt


def has_content(output):
    return output["encrypted"]


def run(path):
    with open(path, "rb") as fp:
        office_file = msoffcrypto.OfficeFile(fp)
        output = {
            "format": office_file.format,
            "type": getattr(office_file, "type", None),
            "encrypted": office_file.is_encrypted(),
        }
    if output["encrypted"]:
        output["attempts"] = [attempt(path, password) for password in PASSWORDS]
    return output
