"""pikepdf, as ace3's PDFAnalyzer calls it (ace3/saq/modules/file_analysis/pdf.py): what it reads of an
encrypted file, the annotation URIs, the form fields and the JavaScript. Each has its own try there, so
each has its own `raised` here. `links` is what ace3's PDFLinkTextAnalyzer reads in the same file
(`read_links`, with its default `max_links`): each link annotation's URL, page, box, whether its page
is rotated, its page's media box and its /Contents, under one try, as there. Strings come as text and as their bytes, because str() is what ace3
keeps and the bytes are what a port on libqpdf reads first. A PDF that needs a password raises at
open, which is the whole output's `error`.

It keeps the fields and scripts ace3's filters would drop, such as a name under 64 characters, since a
port has to read them to drop them.
"""

import io
import struct

import pikepdf

import side


def value_of(value):
    """A PDF object as data."""
    if isinstance(value, pikepdf.Stream):
        return {"stream": value.read_bytes()}
    if isinstance(value, pikepdf.Name):
        return {"name": str(value)}
    if isinstance(value, pikepdf.String):
        return {"text": str(value), "bytes": bytes(value)}
    return {"other": str(value)}


def encryption_of(pdf):
    encryption = pdf.encryption
    return {
        "filter": str(pdf.trailer.Encrypt.get("/Filter", "")),
        "V": encryption.V,
        "R": encryption.R,
        "P": encryption.P,
        "bits": encryption.bits,
        "method": "rc4" if encryption.V < 4 else encryption.stream_method.name,
        "owner_password_empty": pdf.owner_password_matched,
        "permissions": dict(pdf.allow._asdict()),
    }


def decrypted_copy(pdf):
    out = io.BytesIO()
    pdf.save(
        out,
        stream_decode_level=pikepdf.StreamDecodeLevel.none,
        compress_streams=False,
        deterministic_id=True,
    )
    return out.getvalue()


def annotation_uris(pdf):
    uris = []
    for page in pdf.pages:
        for annot in page.get("/Annots") or []:
            action = annot.get("/A")
            uri = action.get("/URI") if action else None
            if uri:
                uris.append(value_of(uri))
    return uris


def form_fields(pdf):
    fields = []
    acroform = pdf.Root.get("/AcroForm")
    if acroform:
        for field in acroform.get("/Fields", []):
            value = field.get("/V")
            fields.append(
                {
                    "name": value_of(field.get("/T", "unknown")),
                    "value": None if value is None else value_of(value),
                }
            )
    return fields


def javascript(pdf):
    scripts = []
    names = pdf.Root.get("/Names")
    tree = names.get("/JavaScript") if names else None
    if tree:
        array = tree.get("/Names", [])
        for i in range(0, len(array) - 1, 2):
            js = array[i + 1].get("/JS")
            scripts.append(
                {"name": value_of(array[i]), "js": None if js is None else value_of(js)}
            )
    return scripts


MAX_LINKS = 200
LINK_TEXT_MAX_LEN = 200


def bits(value):
    """A float as its 64 bits, which say an infinity, a NaN and a negative zero as they are."""
    return struct.pack(">d", value).hex()


def annotation_rect(annot):
    try:
        rect = [float(value) for value in annot.get("/Rect")]
    except (TypeError, ValueError):
        return None
    return rect if len(rect) == 4 else None


def links(pdf):
    found, seen, truncated = [], set(), False
    for number, page in enumerate(pdf.pages, start=1):
        for annot in page.get("/Annots") or []:
            action = annot.get("/A")
            uri = action.get("/URI") if action else None
            if not uri:
                continue
            uri = str(uri)
            rect = annotation_rect(annot)
            key = (uri, number, tuple(rect) if rect else None)
            if key in seen:
                continue
            if len(found) >= MAX_LINKS:
                truncated = True
                continue
            seen.add(key)
            contents = annot.get("/Contents")
            found.append(
                {
                    "url": uri,
                    "page": number,
                    "rect": [bits(value) for value in rect] if rect else None,
                    "rotated": bool(int(page.get("/Rotate", 0)) % 360),
                    "mediabox": [bits(float(value)) for value in page.mediabox],
                    "contents": None if contents is None else (str(contents).strip()[:LINK_TEXT_MAX_LEN] or None),
                }
            )
    return {"links": found, "truncated": truncated}


def run(path):
    output = {}
    with pikepdf.open(path) as pdf:
        output["pages"] = len(pdf.pages)
        output["is_encrypted"] = pdf.is_encrypted
        parts = [
            ("annotation_uris", annotation_uris),
            ("form_fields", form_fields),
            ("javascript", javascript),
            ("links", links),
        ]
        if pdf.is_encrypted:
            parts = [("encryption", encryption_of), ("decrypted", decrypted_copy), *parts]
        for name, read in parts:
            try:
                output[name] = read(pdf)
            except Exception as error:
                output[name] = {"raised": side.error_data(error)}
    return output
