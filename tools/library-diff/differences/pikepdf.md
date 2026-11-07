# Differences between pikepdf and its port

`tools/library-diff/run pikepdf --right rust:ace-mod-pdf/pikepdf` diffs pikepdf 10.17.0 with `crates/ace-mod-pdf` on libqpdf. Both are libqpdf 12.4.2. The rows follow `tools/ace3/trees/differences.md` and `docs/acceptance.md`.

## Explained

| Samples | Path | Why | When |
|---|---|---|---|
| `ace3/pdf/ComplaintApril_424256637.pdf` | `/output/decrypted/base64` | `pdf.save` runs `update_xmp_pdfversion` when `fix_metadata_version` is on, as ace3 leaves it, and that opens the XMP with lxml and writes it back pretty-printed and without its padding, as a new stream with no filter, even with nothing to change. The port leaves the stream as it was: rewriting metadata isn't what a decrypted copy is for, and matching it would mean porting lxml's parser and serializer, its recovery and pikepdf's `_normalize_descriptions`. Checked: pikepdf with `fix_metadata_version=False` writes the port's bytes exactly. The file holds the same XMP properties either way, and `.pdfparser` shows them decoded. |  |
| `ace4/pdf/encrypted_with_xmp.pdf` | `/output/decrypted/base64` | The same, on a sample whose XMP has padding and is on one line. Checked the same way. |  |
| `ace4/pdf/field_unfilterable.pdf` | `/output/form_fields/raised/message` | pikepdf's message gives `QPDF::getLastOffset()`, which libqpdf's C API doesn't expose, so the port's leaves out `, offset N`. The type and the rest of the text are the same. ace3 only logs this. |  |
| `ace4/pdf/js_unfilterable.pdf` | `/output/javascript/raised/message` | The same. |  |
