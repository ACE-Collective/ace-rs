# Differences from ace3's reference dumps

`tests/reference.rs` runs each module on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<dump>` here. A dump named `<fixture>.<body>` is of the file attached to an email whose body run_module.py made: the test gives the module the body ace3's email module wrote, from the dump, as the carrying email's. The files are `tools/ace3/dumps/fixtures/encrypted`, which `tools/samples/make-encrypted-files` writes, and the samples the modules take. ace3's candidates come out of a set, in an order that changes from run to run, and the port sorts them, so the test sorts ace3's `word_list` too. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit fe6da632.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `*_encryption_analyzer/*.*.*` | `/analyzed/directives/extract_urls` | The email module's directive on an attachment, which the dumps of a file attached to an email ran before this one. The form doesn't say which module added a directive. |
| `*_encryption_analyzer/*.*.*` | `/analyzed/directives/render` | The same. |
| `*_encryption_analyzer/*.*.*` | `/analyzed/yara_meta/type=email.attachment` | The email module's `yara_meta` type on an attachment, the same way. |
| `*_encryption_analyzer/*.*.*` | `/analyzed/tags/zip` | file_type's tag on a zip, which those dumps ran too, so the email module had its dependency. |
| `*_encryption_analyzer/*.*.*` | `/analyzed/tags/pdf` | file_type's tag on a PDF, the same way. |
| `*_encryption_analyzer/*.*.*` | `/analyzed/yara_meta/type=document.pdf` | file_type's `yara_meta` type on a PDF, the same way. |
| `pdf_encryption_analyzer/*.*.*` | `/observables/*/tags/pdf` | file_type's tag on the decrypted copy, which it analyzed in the same run. |

## Behaviour the dumps don't exercise

These depart from ace3, or follow it where no fixture reaches:

- John's check is followed, not repeated. For ZipCrypto it also wants two check bytes when every entry is PKZIP 1.0's, and a sound start of each entry's deflate stream, where the zip crate checks one byte; both only turn away wrong candidates, which the smallest entry's CRC turns away anyway. The RAR4 file is the one rar2john's rule picks from the headers (`rar::rar4_best`).
- zip2john's and rar2john's hashes hold an entry's data in hex, and ace3 stops a tool past 64 MiB of output; the port estimates the hash's length, within a few hundred bytes, and says `<tool> did not finish` past the limit (`docs/measurements/encrypted.md`). zip2john, rar2john and pdf2john.pl failing is kept as `<tool> failed: ...` with ace4's reason, not the tool's stderr: a zip whose encrypted entries are all under 4 bytes or compressed other than by deflate, a RAR with no encrypted file, or a PDF whose `/Encrypt` pdf2john.pl doesn't take (`pdf::Hash::of`). pdf2john.pl reads a PDF with ExifTool's parser, which may fail on a file libqpdf repairs, or the other way round.
- A candidate's bytes are its UTF-8. John reads its wordlist as raw bytes and, for RAR's UTF-16 key, takes them as ISO-8859-1, where libunrar decodes UTF-8, so a password outside ASCII can crack a RAR here that John wouldn't. John cuts a PDF candidate at 32 bytes, as the port does.
- pikepdf's `save()` rewrites a PDF's XMP `pdf:PDFVersion` (`fix_metadata_version`) when the file has XMP metadata; the port's copy doesn't, as `pdf_analyzer`'s doesn't (`tools/ace3/trees/differences.md`, `encrypted_with_xmp.pdf`). The copy's second `/ID` is the content's, where pikepdf's is the clock's.
- The candidates stop when what's left of the task is what extracting or decrypting needs, and the result is then ace3's when John is stopped: no password. ace3's John has the module's 60 s and ten threads; each module here has one thread and the limits `docs/measurements/encrypted.md` measured.
- A RAR's files are read whole into memory, as the archive module reads them, under the task's 2 GiB. unrar's write error (exit 5), where ace3 keeps what was written, is the file store's limit here, which fails the task as it does the archive module's. A split RAR's other volumes aren't there: a task has one file.
- ace3 writes `<file>.hash`, `<file>.wordlist` and `<file>.hash.pot` beside the file and never adds them; nothing here writes them.
