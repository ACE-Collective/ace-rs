# Differences from ace3's reference dumps

`tests/reference.rs` runs each module on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<dump>` here, with the dump's directives, meta tags and, for `extracted_rtf_analyzer`, file_type's result, and rtfole as the module that added a file the dump tagged `extracted_rtf`. The files are `tools/ace3/dumps/fixtures/scripts`, which `tools/samples/make-scripts` writes, and the samples the modules take. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `microsoft_script_encoding_analysis/mse/xxxxxxxx*` | `/error` | The file's name is 250 bytes, so the output's name is past the 255 a file system holds and `open` raises out of ace3's module. ace3's engine marks the analysis failed with the exception, which names the file by its path on its node, written `<root>/files/<name>.decrypted.vbs` in the dump; the port's names it by its path in the alert. With `<root>/files/` taken off ace3's the two are the same text: `OSError: [Errno 36] File name too long: '<name>.decrypted.vbs'` (the form leaves ace3's crash report id out). |
| `microsoft_script_encoding_analysis/mse/xxxxxxxx*` | `/summary` | The same error, in the summary, `Microsoft Script Encoding Analysis: failed: <error>`. |
| `nowhitespace_analyzer/rtf/rrrrrrrr*` | `/error` | The same, for a name of 253 bytes and `<name>.nowhitespace`: ace3's path on its node, and the port's in the alert. |
| `microsoft_script_encoding_analysis/mse/twice.vbe` | `/observables/file:twice.vbe.decrypted.vbs/tags/microsoft_script_encoding` | The fixture is encoded twice, so what the module writes starts with `#@~^` too, and in the dump ace3 ran the module again on that output, which tagged it. The test runs the module once, on the dump's file; run on the output, the port tags it the same way (`mse::tests`' `twice_encoded_output_is_decoded_again`). |
| `microsoft_script_encoding_analysis/mse/twice.vbe` | `/observables/file:twice.vbe.decrypted.vbs/directives/sandbox` | The directive the same second run gave the output. |
| `extracted_rtf_analyzer/*` | `/analyzed/tags/executable` | file_type's tag on a PE or DOS executable. The dumps ran file_type as the module's dependency, and the form doesn't say which module added a tag. The test gives the module file_type's result but doesn't run it; its own dumps (`crates/ace-mod-files`) match. |
| `extracted_rtf_analyzer/*` | `/analyzed/yara_meta/type=executable` | file_type's `yara_meta` type on the same files. |
| `extracted_rtf_analyzer/*` | `/analyzed/tags/lnk` | file_type's tag on `shortcut.bin`, the same way. |

## Behaviour the dumps don't exercise

These depart from ace3:

- `extracted_rtf_analyzer` reads which modules' results added its file, as they are when it's leased, and looks for rtfole, where ace3 reads the `extracted_rtf` tag rtfole gives the file it adds. Only rtfole gives that tag in ace3, but an analyst's tag, which 7.6 brings, would also make ace3's module run.
- ace3 writes the decoder's stderr to `<file>.decrypted.stderr` and never adds it; nothing here writes it. The Perl's messages are `mse::DecodeError::message`.
- The decoder runs in the task, in time linear in the file, where ace3 stops the Perl at what's left of the module's 60 seconds less a margin and keeps nothing it wrote (`docs/measurements/scripts.md`).
