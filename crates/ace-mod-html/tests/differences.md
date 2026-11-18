# Differences from ace3's reference dumps

`tests/reference.rs` runs each module on each file `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<dump>` here, with the dump's directives, meta tags and relationships. The files are `tools/ace3/dumps/fixtures/html`, hand-made, and the samples the modules take. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The DOM snapshots ace3 writes beside the scripts are compared too, under `/sidecars/<path>`. The dumps were made with ace3 at commit fe6da632.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `html_js_extraction/*` | `/analyzed/yara_meta/*` | file_type's `yara_meta` types. The dumps ran file_type as the module's dependency, and the form doesn't say which module added a type. This test gives the module file_type's result and the types it left on the file, but doesn't run it; its own dumps (`crates/ace-mod-files`) match. |
| `html_js_extraction/*` | `/analyzed/tags/email` | file_type's tag, the same way. |

## Behaviour the dumps don't exercise

These depart from ace3:

- Each module writes at most 500 files, and `html_js_extraction` adds at most 500 URLs, because ace3's root takes at most 500 file and 500 URL observables (`maximum_observable_count`) and ace4's core has no such limit. Past that ace3 keeps writing files to its node that no observable holds; these stop. `html_js_extraction` also stops at 500 URI paths, where ace3 has no limit (`docs/measurements/html.md`).
- The DOM snapshots ride in the results' `dom_snapshots`, each with the files whose `.dom.json` it is, rather than in files beside the scripts, since ace4 keeps no file outside the tree. Past 16 MiB of them in one result a document's snapshot isn't kept and its sidecars aren't listed in `dom_snapshot_files`, where ace3 writes them all.
- `mhtml` waits for `file_type`. ace3 runs a pass's modules in the order of a set of names, which Python's hash seed decides, so whether the parts copy file_type's `yara_meta` types changes from one ace3 process to the next; here they always do.
- `har_extraction` writes a `status` past 64 bits as its nearest float, and a NaN or infinite one as null; ace3 writes Python's JSON, which has both. A URL's lone surrogates are U+FFFD here.
- What Python raises out of ace3's `har_extraction` and `html_data_url_extraction`, such as `urlsplit`'s `ValueError` or an `open()` of a name past 255 bytes, leaves ace3's analysis as far as it got, and here the result holds that much. ace3's engine marks that analysis failed with the exception, as `<type>: <message>` and its crash report's id, and the result here is marked the same way, without the id, which the form leaves out of ace3's too: `ValueError: Invalid IPv6 URL` on `bad_url.har` and `bad_join.har`, which show it. No dump has a name past 255 bytes; for one the port writes ace3's `OSError: [Errno 36] File name too long: '<path>'` with the file's path in the alert, where ace3's is its path on its node.
- A `RecursionError` from Python's JSON decoder names the C stack it used, which differs between runs; `ace-pycompat` raises it at a fixed depth with one message.
