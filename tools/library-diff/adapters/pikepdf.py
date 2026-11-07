"""pikepdf, as ace3's PDFAnalyzer calls it (ace3/saq/modules/file_analysis/pdf.py): what it reads of an
encrypted file, the annotation URIs, the form fields and the JavaScript. Each has its own try there, so
each has its own `raised` here. Strings come as text and as their bytes, because str() is what ace3
keeps and the bytes are what a port on libqpdf reads first. A PDF that needs a password raises at
open, which is the whole output's `error`.

It keeps the fields and scripts ace3's filters would drop, such as a name under 64 characters, since a
port has to read them to drop them.
"""

import io

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


def run(path):
    output = {}
    with pikepdf.open(path) as pdf:
        output["pages"] = len(pdf.pages)
        output["is_encrypted"] = pdf.is_encrypted
        parts = [
            ("annotation_uris", annotation_uris),
            ("form_fields", form_fields),
            ("javascript", javascript),
        ]
        if pdf.is_encrypted:
            parts = [("encryption", encryption_of), ("decrypted", decrypted_copy), *parts]
        for name, read in parts:
            try:
                output[name] = read(pdf)
            except Exception as error:
                output[name] = {"raised": side.error_data(error)}
    return output
