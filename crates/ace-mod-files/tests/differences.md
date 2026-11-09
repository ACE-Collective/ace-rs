# Differences from ace3's reference dumps

`tests/reference.rs` runs `file_type`, `file_hash_analyzer` and `binary_file_analyzer` on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<file>` here, and gives `file_hash_analyzer` the file_type result of its dump. The files are `tools/ace3/dumps/fixtures/files`, hand-made. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `file_hash_analyzer/*` | `/analyzed/tags/*` | file_type's tags. The dumps ran file_type as the module's dependency, and the form doesn't say which module added a tag. This test gives the module file_type's result but doesn't run file_type, whose own dumps (`file_type/*`) match. |
| `file_hash_analyzer/*` | `/analyzed/yara_meta/*` | file_type's `yara_meta` types, the same way. |
| `x509_analyzer/*` | `/analyzed/tags/x509` | file_type's tag, the same way. |
| `x509_analyzer/*` | `/analyzed/yara_meta/type=certificate.x509` | file_type's `yara_meta` type, the same way. |
| `x509_analyzer/ace4/x509/cert.*` | `/details/serial_number` | A serial of 160 bits. ace3 writes it as a JSON number, which serde_json reads as a float here; ace4 writes its digits as text, since its JSON numbers are 64 bits. Checked: ace3's dump holds `537340134452770599315352164468300597304041358695`, the text ace4 writes. |
| `x509_analyzer/*` | `/observables/file:*.metadata` | A bug in ace3 that the port doesn't keep. ace3's `write_metadata_to_file` returns the metadata file's path relative to the root's directory, and `add_file_observable` looks for it relative to the process's working directory (`LocalFileManager.store_file`), so it logs `FileNotFoundError` and adds nothing, and the `metadata.x509` file YARA rules are written for never reaches YARA. ace4 adds it. |
