# Differences from ace3's reference dumps

`tests/reference.rs` runs each module on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<dump>` here, with the dump's directives, meta tags, file_type's result where the module depends on it, and the file it was extracted from with that file's tags and, for `extracted_ole_analyzer`, the module that added it. The files are `tools/ace3/dumps/fixtures/office`, which `tools/samples/make-office-containers` writes, and the samples the modules take. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 37a765bf.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `officeparser3/*` | `/analyzed/tags/microsoft_office` | file_type's tag. The dumps ran file_type as the module's dependency, and the form doesn't say which module added a tag. The test gives the module file_type's result but doesn't run it; its own dumps (`crates/ace-mod-files`) match. |
| `officeparser3/*` | `/analyzed/tags/ole` | file_type's tag, the same way. |
| `officeparser3/*` | `/analyzed/tags/zip` | file_type's tag, the same way: Python's `zipfile` opens these compound files, which have a zip's end record inside. |
| `officeparser3/*` | `/observables/*/tags/zip` | file_type's tag on a stream the module wrote: the dumps' file_type ran on each file the module added, which this test doesn't. |
| `officeparser3/*` | `/observables/*/yara_meta/type=image` | file_type's `yara_meta` type on a stream the module wrote, an image, the same way. |
| `hidden_mime/*` | `/observables/*/tags/executable` | file_type's tag on a part the module wrote, a PE header in base64, the same way. |
| `hidden_mime/*` | `/observables/*/yara_meta/type=executable` | file_type's `yara_meta` type on that part, the same way. |
| `extracted_ole_analyzer/*` | `/analyzed/tags/executable` | file_type's tag on `PAYLOAD.EXE`, which starts `MZ`; the test gives the module file_type's result and doesn't run it. |
| `extracted_ole_analyzer/*` | `/analyzed/yara_meta/type=executable` | file_type's `yara_meta` type on the same file. |
| `extracted_ole_analyzer/*` | `/analyzed/tags/lnk` | file_type's tag on `shortcut.dat`, the same way. |
| `active_mime/*` | `/details/extracted_file` | ace3 names the payload by its path on its node, `<root>/files/<file>.activemime`, which has no meaning once files live in the bucket. ace4 writes the path in the alert, which is what ace3's ends with: checked on each of the 5, the rest of each path is the same, and the files themselves, by path, sha256 and size, match. |
| `active_mime/*` | `/summary` | The same path, in the summary. |
| `hidden_mime/*` | `/details/extracted_files/*` | ace3 names each part by its path on its node, `<root>/files/<file>.mime/extracted-<n>`, as `active_mime` does. Checked on all 15: the rest of each path is the same, and the files match. |
| `hidden_mime/*` | `/summary` | The same paths, in the summary. |
| `xml_plain_text_analyzer/plain/cp1252.xml` | `/details/xml_plain_text` | The document declares windows-1252. lxml's libxml2 has iconv and decodes it; the vendored libxml2 has no iconv and refuses an encoding it doesn't decode itself, so the parse raises and there is no `.noxml` file. UTF-8, UTF-16 and the ISO-8859 family, which libxml2 decodes itself, match (`latin1.xml` here, and `crates/ace-lxml`'s target cases). |
| `xml_plain_text_analyzer/plain/cp1252.xml` | `/error` | The same parse, which raises here and not in ace3: the result is marked failed with libxml2's reason, `unable to parse XML: Unsupported encoding: windows-1252, line 1, column 44 (cp1252.xml, line 1)`, where ace3's analysis has no error. |
| `xml_plain_text_analyzer/plain/cp1252.xml` | `/observables/file:*` | The `.noxml` file ace3 wrote, the same way. |

## Behaviour the dumps don't exercise

These depart from ace3:

- Each module writes at most 499 files, and `office_xml_rel` adds at most 500 URLs: ace3's root takes at most 500 of each (`maximum_observable_count`) and holds the file itself, which ace4's core doesn't count. The officeparser3 dumps of `ole_deep_directory.doc` show ace3 stopping at 499.
- officeparser3 is quadratic in ace3, where a chain's loop check searches a list and a macro is built a byte at a time; a file ace3's 90 seconds stop finishes here. The port stops as if killed only where officeparser3 would never end, on a chain its checks follow in a circle (`stream_cycle.doc`, `ole_fat_loop.doc`), past 256 MiB of streams read, counting each chain once, and raises `MemoryError` past 64 Mi FAT entries (`docs/measurements/office-containers.md`).
- A name officeparser3 would write outside its directory, through `..`, is written nowhere here, where ace3 writes it beside the document; ace3 then looks for its last part in the directory, as here (`native_names.doc`'s `../up.txt`). An absolute name raises here, where ace3 writes it if it may. A name an alert path can't hold, such as `..\x`, which Linux takes, isn't added.
- `active_mime` stops inflating at 256 MiB and leaves no result, where ace3 inflates until Python runs out of memory.
- `extracted_ole_analyzer` runs once the rest of its root has finished, reading on the lease the modules that added its file, and `xml_plain_text_analyzer` reads the tags of the file its file was extracted from as they are when it's leased. ace3 runs them a pass after the modules that wrote the file. With more than one `extracted_from` relationship ace3 takes the first one added; ace4 has them in its order of their targets.
- `xml_binary_analyzer` numbers a name against its own input and outputs, where ace3 checks the whole alert's directory.
