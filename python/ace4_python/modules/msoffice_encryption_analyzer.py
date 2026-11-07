"""ace3's MSOfficeEncryptionAnalyzer (saq/modules/email/encryption/msoffice.py), on the same
msoffcrypto, with ace3's generate_wordlist and wordlist_from_email (saq/cracking.py).

ace3 extracts a hash with office2john.py and cracks it with John the Ripper. A worker can't start a
process, so this tries the same passwords with msoffcrypto itself. PLAN.md 7.3 decides John's future.
Three things follow from that:

- It's slower. John does about 513 Office 2013 passwords a second on ten threads, and this about 30 on
  one. So it runs under a longer deadline, and stops itself before that as John is stopped in ace3,
  whatever a file's spin count asks for. See crates/ace-mod-python's MsofficeEncryption.
- John has no format for XOR obfuscation, so office2john.py's complaint about it is kept as the error.
  doc97's load_key verifies nothing for XOR, so a password can't be tried on one anyway.
- ace3 reads John's answer up to a ':', so a password with one is cut short and the file isn't decrypted
  there. Here it is. No sample has one.

The carrying email comes from the core, in the task: `ctx.carried_by_email` and `ctx.email_body`.
"""

import binascii
import contextlib
import io
import re
import signal
import struct
import traceback

import msoffcrypto
from html2text import html2text
from msoffcrypto import exceptions
from msoffcrypto.method.ecma376_agile import ECMA376Agile

DISPLAY_NAME = "MSOffice Encryption Analysis"
# ace3's built-in EMAIL_ENCRYPTED_DECRYPTED signature
SIGNATURE_UUID = "ef715326-081e-4ece-97ba-02817b5a28cd"
# Stops trying passwords here, in seconds from when it starts on the email. The rest of the manifest's
# 240 s is for decrypting a file whose password came late: 1.4 s for 64 MB. A full list takes 169 s.
TIME_TO_CRACK = 225
# see https://isc.sans.edu/diary/rss/23774 and https://twitter.com/BouncyHat/status/1308897932389896192
DEFAULT_PASSWORDS = ["VelvetSweatshop", "/01Hannes Ruescher/01"]

WHITESPACE = re.compile(r"\s")


class OutOfTime(BaseException):
    """TIME_TO_CRACK has passed. Not an Exception, so nothing in a library can catch it."""


def raise_out_of_time(signum, frame):
    raise OutOfTime()


def generate_wordlist(text, range_low, range_high, byte_limit, list_limit):
    """ace3's generate_wordlist, which returns the same set. Its order is that of the words' first
    appearance rather than a set's, which changes from run to run."""
    data = text[:byte_limit]
    words = {}
    for size in range(range_low, range_high + 1):
        for start in range(0, len(data) - size + 1):
            word = data[start : start + size]
            if not word or WHITESPACE.search(word):
                continue
            words[word] = True
            if len(words) >= list_limit:
                return list(words)
    return list(words)


def read_body(path, settings):
    """ace3's wordlist_from_email, past its finding the email. Its text mode is UTF-8 on its nodes."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        body = html2text(fp.read())[: settings["byte_limit"]]
    words = generate_wordlist(
        body,
        settings["range_low"],
        settings["range_high"],
        settings["byte_limit"],
        settings["list_limit"],
    )
    return body, words


def xor_complaint(office_file, path):
    """What office2john.py writes for a file John has no format for, naming it by `path`. None for
    any other file. msoffcrypto's Excel 95 XOR never gets here: it fails is_encrypted."""
    if office_file.format == "doc97":
        fib = office_file.info.fib.base
        if fib.fObfuscation == 1:
            return (
                f"{path} : XOR obfuscation detected, Password Verifier : "
                f"{binascii.hexlify(struct.pack('<I', fib.IKey))}\n"
            )
    elif office_file.format == "xls97":
        workbook = office_file.data.workbook
        workbook.seek(0)
        while True:
            header = workbook.read(4)
            if len(header) < 4:
                return None
            kind, length = struct.unpack("<HH", header)
            data = workbook.read(length)
            if kind == 0x2F:
                if data[:2] != b"\x00\x00":
                    return None
                return (
                    f"{path} : XOR obfuscation detected, key : {binascii.hexlify(data[2:4])}, "
                    f"hash : {binascii.hexlify(data[4:6])}\n"
                )
    return None


def opens(office_file, password):
    """Whether the password opens the file, with its key loaded if it does. For Office 2010 and later,
    load_key would derive the spin count's hash twice to be sure, so it's checked once and loaded on a
    match. A verifier that isn't the password's raises InvalidKeyError."""
    if office_file.format != "ooxml":
        try:
            office_file.load_key(password=password)
        except exceptions.InvalidKeyError:
            return False
        return True
    if office_file.type == "agile":
        info = office_file.info
        if not ECMA376Agile.verify_password(
            password,
            info["passwordSalt"],
            info["passwordHashAlgorithm"],
            info["encryptedVerifierHashInput"],
            info["encryptedVerifierHashValue"],
            info["spinValue"],
            info["passwordKeyBits"],
        ):
            return False
        office_file.load_key(password=password)
        return True
    try:
        office_file.load_key(password=password, verify_password=True)
    except exceptions.InvalidKeyError:
        return False
    return True


@contextlib.contextmanager
def time_limit(seconds):
    """Raises OutOfTime in the body after `seconds`. A worker runs a task on its main thread, and
    hashing a password is Python between short C calls, so any spin count stops here."""
    signal.signal(signal.SIGALRM, raise_out_of_time)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def crack(office_file, passwords):
    """The password that opens the file, or None when none does. A password that breaks msoffcrypto's
    reading of the file stops it, as John refusing the hash would."""
    try:
        for password in passwords:
            if opens(office_file, password):
                return password
    except Exception:
        return None
    return None


def summarize(details):
    if details["error"]:
        return f"{DISPLAY_NAME}: {details['error']}"
    if details["password"]:
        return f"{DISPLAY_NAME}: password {details['password']}"
    if not details["email"]:
        return f"{DISPLAY_NAME}: no associated email detected"
    if not details["email_body"]:
        return f"{DISPLAY_NAME}: email body cannot be determined"
    if not details["word_list"]:
        return f"{DISPLAY_NAME}: word list could not be created from email"
    return f"{DISPLAY_NAME}: password not available"


def decrypt(ctx, office_file, file, details):
    """Fills in the details and returns the decrypted file's record, or None."""
    complaint = xor_complaint(office_file, file["path"])
    if complaint:
        details["error"] = f"office2john.py failed: {complaint}"
        return None

    details["word_list"] = list(DEFAULT_PASSWORDS)
    if ctx.carried_by_email:
        details["email"] = True
    try:
        with time_limit(TIME_TO_CRACK):
            words = []
            if ctx.email_body:
                details["email_body"], words = read_body(ctx.email_body, settings_of(ctx))
            # sorted in the result because ace3's order is a set's. They're tried in the body's order
            details["word_list"].extend(sorted(words))
            details["password"] = crack(office_file, DEFAULT_PASSWORDS + words)
    except OutOfTime:
        pass
    if not details["password"]:
        details["error"] = "could not crack password"
        return None

    output = io.BytesIO()
    office_file.decrypt(output)
    data = output.getvalue()
    return ctx.write_file(
        f"{file['path']}.decrypted",
        data,
        tags=["decrypted_msoffice"],
        yara_meta=["type=document.office"],
        detections=[
            {
                "description": "Was able to decrypt based on contents of email.",
                "signature_uuid": SIGNATURE_UUID,
            }
        ],
    )


def settings_of(ctx):
    defaults = {"range_low": 4, "range_high": 11, "byte_limit": 1024, "list_limit": 5000}
    return {**defaults, **(ctx.settings or {})}


def analyze(ctx):
    file = ctx.observable["file"]
    with open(ctx.input, "rb") as fp:
        try:
            office_file = msoffcrypto.OfficeFile(fp)
        except Exception:
            return ctx.skip("msoffcrypto can't read it")
        try:
            if not office_file.is_encrypted():
                return ctx.skip("not encrypted")
        except Exception:
            # ace3's "Unsupported encryption method" makes a result, but only is_encrypted's own
            # exceptions get here, and msoffcrypto 6.0.0 raises no such thing from it
            return ctx.skip("msoffcrypto can't tell if it's encrypted")

        details = {
            "email": False,
            "email_body": None,
            "word_list": [],
            "password": None,
            "error": None,
            "encryption_info": None,
        }
        files = []
        try:
            decrypted = decrypt(ctx, office_file, file, details)
            if decrypted:
                files.append(decrypted)
        except Exception:
            # As ace3: it logs this, and the result has what it had. This is a file that broke
            # msoffcrypto or the memory limit: one past about 256 MB can't be decrypted in 1 GB of
            # address space, so it has its password and no file. The supervisor logs stderr
            traceback.print_exc()
    return ctx.done(
        details,
        summary=summarize(details),
        analyzed={"tags": ["encrypted_msoffice"]},
        files=files,
    )
