# Differences from ace3's reference dumps

`tests/reference.rs` runs `url_extraction` on each file `tools/ace3/dumps/reference/url_extraction/` has a dump for, and `ioc_extraction` on each of `reference/ioc_extraction/` (named `ioc/<file>` here), with the dump's directives and meta tags and ace3's file_type result as the module's dependency. The files are `tools/ace3/dumps/fixtures/urls` and `fixtures/iocs`, hand-made, and the HTML samples. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. urlfinderlib returns a set, so where both sides hold the same URLs, ace3's lists take ace4's order before the diff, and the test checks ace4's order is the module's ranking (the URLs of the domains with the fewest URLs first, images last). The dumps were made with ace3 at commit f72f8946, with `PYTHONHASHSEED=0`.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/analyzed/yara_meta/type=document.html` | ace3's file_type module, which the dumps ran as the module's dependency, marks an HTML file. In ace4 that's `file_type`'s own result (`crates/ace-mod-files`), which this test doesn't run; the trees compare it. |
| `script.js*` | `/analyzed/yara_meta/type=script.javascript` | file_type marks a JavaScript file, by its extension and node's syntax check. |
| `email.eml` | `/analyzed/tags/email` | file_type tags an email. |
| `email.eml` | `/analyzed/yara_meta/type=email` | And marks it. |
| `table.csv` | `/analyzed/tags/microsoft_office` | file_type tags a `.csv` as an Office file, by its extension. |
| `script.js` | `/details/urls/*` | In this dump the file came with no meta tag, and file_type marked it `type=script.javascript` before url_extraction ran, so ace3 read it as plain text and kept `https://js-file.example.com/a\u002Fb` as written. This test runs url_extraction alone, with no `file_type` to add the tag, so ace4's url_extraction lets libmagic choose, which finds HTML in it, and that path decodes the escape. The dump `script.js.type=script.javascript`, with the tag given, matches. |
| `script.js` | `/details/urls_grouped_by_domain/example.com/*` | The same URL in the domain's list. |
| `script.js` | `/observables/url:https:~1~1js-file.example.com~1a*u002Fb` | And its observable. |
| `ioc/report.txt` | `/observables/cve:*` | ace3 makes a `DefaultObservable` of any type its configuration names, and `cve` isn't one of ace3's observable types. ace4's types are fixed when the binary is built (ace3 #1030), so the CVEs stay in the details and make no observable. |
| `ioc/*` | `/observables/file:*.refanged.txt/display_type` | ace3 labels the re-fanged text "Re-fanged Text". A file record in ace4 has no display type; the alert view names a file by its path. |
