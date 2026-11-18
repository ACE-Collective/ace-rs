# Differences from ace3's reference dumps

`tests/reference.rs` runs `pdftotext`, `pdf_link_text`, `exif`, `qrcode` and `ocr` on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<file>` here, and gives `exif` the file_type result of its dump. `pdf_link_text` is `ace-mod-pdf`'s, which has no test binary of its own; its 169 dumps are every PDF sample and, for the samples made for it, the same file again with its four bounds low (`.bounds`) and wide (`.wide`), made with ace3 at commit fe6da632, with no difference. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything.

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
| `java_class_decompiler/*` | `/details/decompiled_files/*` | ace3 names the source file by its path on its node, `<root>/files/<file>-0-decompiled.java`; ace4 by its path in the alert, which is what ace3's ends with, as the hidden_mime port names its parts. |
| `autoit/*` | `/details/output_dir` | ace3 names the directory by its path on its node, `<root>/files/<file>.autoit`; ace4 by its path in the alert, the same way. |
| `de4dot/*` | `/details/stdout` | de4dot prints the paths it read and wrote, made absolute: ace3's are the file where the alert keeps it, `<root>/files/<path>`, and its sandbox's working directory, `<work>/data/var/tool_sandbox/cmd-<random>/deobfuscated`, a new name each run; ace4's are the task's copy of the file and its runner's working directory. Checked on both dumps: with each side's paths taken out, the lines are the same. |
| `dmg_analyzer/*` | `/details/image_file` | ace3 names the image by its path on its node, `<root>/files/<file>.img`; ace4 by its path in the alert, which is what ace3's ends with, as the hidden_mime port names its parts. |
| `dmg_analyzer/*` | `/details/stderr` | dmg2img prints the path it was given: ace3's is the file where the alert keeps it, `<root>/files/<file>`, and ace4's the task's copy of it, here the checkout's sample. Checked on all ten dumps: with ace4's path replaced by ace3's, dmg2img's stderr in the dev image is ace3's byte for byte, its progress backspaces included. |

## Behaviour the dumps don't compare

When pdftotext doesn't finish or exits non-zero, both systems mark `pdf_link_text`'s result failed with the same reason, such as `pdftotext exited with status 99: Command Line Error: Wrong page range given ..., without the text under the links` on `link_text_page_count.pdf`, and keep the links without their text. The dumps compare both.

`pdf_link_text` departs from ace3 in these, which the normal form doesn't hold:

- ace3 doesn't cache a failed result, and caches the others for 30 days by the PDF, the settings and pdftotext's version. ace4 has no analysis result cache (PLAN.md 6.7).
- A node that can't start the sandbox makes ace3 keep the links without text, as a failure; in ace4 a tool that can't start fails the task, as for every module that runs one.
- ace3 has a result for each path of a PDF; ace4 analyzes a file once.
