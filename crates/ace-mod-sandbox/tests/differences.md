# Differences from ace3's reference dumps

`tests/reference.rs` runs `pdftotext`, `exif`, `qrcode` and `ocr` on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<file>` here, and gives `exif` the file_type result of its dump. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `exif/*` | `/analyzed/tags/*` | file_type's tags. The dumps ran file_type as the module's dependency, and the form doesn't say which module added a tag. This test gives the module file_type's result but doesn't run file_type. |
| `exif/*` | `/analyzed/yara_meta/*` | file_type's `yara_meta` types, the same way. |
| `exif/*` | `/details/exifdata/SourceFile` | The path ExifTool was given. ace3 gives it the file where the alert keeps it, which the dumps write as `<root>/files/<name>`; ace4's runner copies the file into the tool's working directory under its own name and gives it that. `File:FileName` is the same on both sides. |
| `exif/*` | `/details/exifdata/File:Directory` | The directory of that path: `<root>/files` and `.`. |
| `exif/*` | `/details/exifdata/File:FileModifyDate` | The copy's own times, which ExifTool reads from the filesystem: when run_module.py copied the file into ace3's root and when ace4's runner staged it. |
| `exif/*` | `/details/exifdata/File:FileAccessDate` | The same. |
| `exif/*` | `/details/exifdata/File:FileInodeChangeDate` | The same. |
| `exif/*` | `/details/output_dir` | ace3 names the directory by its path on its node, `<root>/files/<file>.exif`; ace4 by its path in the alert, as the hidden_mime port names its parts. |
| `exif/*` | `/observables/file:*.exif~1exiftool.out/sha256` | The pretty-printed metadata holds the five values above, so its bytes differ. Checked on `ace3/office/doc.docx`: ace3's `exiftool.out` (run_module.py's `--sidecars`), with ace4's five values put in, pformats to ace4's sha256. |
| `exif/*` | `/observables/file:*.exif~1exiftool.out/size` | The same file's size. |
