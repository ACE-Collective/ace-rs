# Module inventory

PLAN.md 7.1. The 92 `analysis_module_*` sections of `ace3/etc/saq.default.yaml` at ace3 `fe6da632`, with what each module does, where it runs in ace4 and which step ports it. 90 of them were there at `141a60a2`, the commit PLAN.md was written against, and at `f72f8946`, which this inventory followed until 2026-11-16; ace3's `b4badb2c` added the 91st, `pdf_link_text`, which it followed to `37a765bf` until 2026-11-17, and `d7436a48` the 92nd, `apex_domain_analyzer`. Each entry comes from the module's code, not just its config: the class, the helpers it calls and the base classes they inherit. It's the plan for the rest of phase 7, so when a step ports a module, change its row.

`tools/ace3/modules/check` reads the sections at the head of ace3's checkout and fails if this file misses one, names one that's gone, or disagrees with ace3 about a module's class, groups or modes. It also checks that every module has a pool and a step from the lists below, that the ported modules are the ones `crates/ace` registers, that every reader of ACE's data has what serves it (7.2), and that every module starting a process has a decision for each program (7.3). tests/e2e/run runs it.

Versions are those of ace3's image: Python packages from `installer/requirements-pinned.txt` and the Dockerfile's git installs, Debian trixie's packages from `dpkg-query` in ace3's dev container. "Writes" names the files a module adds to the alert, with `{file}` for the analyzed file's path; YARA rules match on those names and on the `yara_meta` types, which reach the scanner as its `meta_tags`.

## Pools

| Pool | Means |
|---|---|
| parser | a contained task process with one thread, no network and no database: it parses attacker bytes or values |
| lookup | the async network pool: DNS, HTTP APIs, and ACE's own data through the internal API (7.2), parsing nothing hostile |
| core | work over the whole tree that edits other nodes or the root's mode, which only the core's orchestrator can do |
| sandbox | a parser pool whose image carries external programs, which its supervisor runs at a task's request in ACE's sandbox runner (*External tools*, 7.3) |
| scanner | 7.7's scanner pool, the one process with the Docker socket, which starts a scanner image per scan, and parses nothing it wrote; the module itself runs on the parser pool, which asks for the scan, waits for it as a delayed task, and reads what came back contained |

## What a module takes

PLAN.md decisions 23 and 25. A module that declares what it takes (`Module::takes`, `ace_sdk::takes`) has its first checks as rules over facts the core holds, and the core queues no task they decline; the pool checks them again before the module runs, and the module's own code no longer does. Since decision 25 the facts include the file's type, what the type step found in its bytes (libmagic's description and mime type, file_type's checks, and the first-byte tests of the modules below that declare on them: a packet capture, OneNote's header, a Java class, `<?xml`, EPS, an encoded script and a HAR; `TypeFacts`), and its role: a rule such as "the file's type says PDF" is the module's own check of the bytes, moved. A rule on a file's type holds when that type is unknown, because the type step failed, so a failure never keeps a module off a file. A check that needs a real parse of the bytes, the whole root or an observable's value stays in the module. The rules, each the module's own check moved:

| Module | Rules, in order |
|---|---|
| `active_mime`, `dhash`, `html_data_url_extraction` | not an empty file |
| `qrcode` | not an empty file, and an image Pillow opens (`is_image`, migration 0073) or a PDF (`is_pdf_file`), as ace3's 2026-06-25 consult gate |
| `archive` | the path doesn't contain `email.rfc822`; the type isn't a packet capture (ace3's `is_pcap_file`); the type's mime type, lowered, doesn't start with an `excluded_mime_types` entry, lowered; the type isn't an OLE file |
| `binary_file_analyzer` | not empty; the type is an RTF file, or EPS (`C5D0D3C6` or `%!PS-Adobe-` at the start) with `.doc` in the path (the module keeps its stricter `{\rt`, which the type's RTF fact, `\rt` or `{\rt`, contains) |
| `de4dot`, `ilspy` | the type is a PE file whose description, lowered, has `.net assembly` |
| `cve_2021_30657_analyzer` | the path ends in `.img`, lowered; `dmg_analyzer` added it and it redirects |
| `dmg_analyzer` | the name ends in `.dmg`, lowered |
| `email_analyzer` | the path doesn't end in `.headers`; file_type has a result with a description; that description has `RFC 822 mail` or `message/rfc822`, or its mime type has `message/rfc822`, or file_type calls it an email, or the file has `original_email` |
| `email_conversation_attachment_analyzer` | file_type has a result that calls it an Office document (whether the root has an email stays in the module) |
| `encrypted_archive_analyzer` | the path ends in `.gz.e` |
| `exif` | the path doesn't end in `.pdfparser` or `.gs.pdf`; at most `file_size_limit` bytes, when it is set; an Office extension on the name, or file_type's description, lowered, names an Office format or OpenDocument, or the type is an OLE file or ace3's `is_pdf_file` |
| `extracted_ole_analyzer` | file_type has a result; `officeparser3` added it |
| `extracted_rtf_analyzer` | `rtfole` added it; file_type has a result |
| `file_hash_analyzer` | not empty; file_type has a result; no `ignore_pattern` matches the path on ace3's node, and no `ignore_mime_type` file_type's mime type |
| `har_extraction` | not empty; the type has ace3's HAR header (`^\s*\{\s*"log"\s*:` in the first 4096 bytes) |
| `hidden_mime` | not empty; no `original_email` and not named `email.rfc822`; file_type doesn't call it `message/rfc822` or an email; the type isn't a packet capture |
| `html_js_extraction` | not empty; named as HTML or MHTML (lowered), or else not tagged `type=script.javascript` and file_type's mime type is an HTML one |
| `java_class_decompiler` | not empty; the type is a Java class file (`CAFEBABE` at the start) |
| `javascript_deobfuscation` | tagged `type=script.javascript` or named `.js` (whether file_type gave the tag reads the bytes, and stays) |
| `lnk_parser` | the type is a Windows shortcut |
| `mhtml` | the name ends in `.mhtml` or `.mht`, lowered |
| `microsoft_script_encoding_analysis` | not empty; the type starts with `#@~^` |
| `nowhitespace_analyzer` | the path doesn't end in `.nowhitespace`; not empty; the type is an RTF file |
| `office_xml_rel` | named `document.xml.rels` |
| `onenote_extraction` | not empty; the name ends in `.one`, lowered, or the type has OneNote's header GUID in its first 16 bytes |
| `officeparser3` | file_type has a result; the type is an OLE file; neither a path ending in `.msi`, lowered, nor file_type's description, lowered, with `windows installer` |
| `olevba_v1_2` | the type isn't an RTF file; the path doesn't end in `.msi`, lowered; an Office extension, or the type is an OLE or a zip file; at most 4 MB; the type's mime type has no `html` and isn't `text/plain` |
| `pcap_analyzer`, `pcap_dns`, `pcap_files`, `pcap_http`, `pcap_tls`, `pcap_tls_decryption` | the type is a packet capture: ace3's `is_pcap_file`, a pcap magic number or a pcapng section header with its byte-order magic |
| `pcodedmp` | an Office extension, or file_type's description, lowered, names an Office format |
| `pdf_analyzer` | the path doesn't end in `.pdfparser` or `.ocr`; the type has `%PDF-` in the first kilobyte |
| `pdf_encryption_analyzer`, `pdf_link_text`, `pdftotext` | the type is ace3's `is_pdf_file`: `%PDF-` in the first kilobyte, and the path doesn't end in `.pdfparser` |
| `phishkit_analyzer` | a file has `render` or `type=email.attachment`, the root is in correlation mode, the file isn't empty, and its extension, lowered, or its type's mime type (file_type's) is one the settings render (a URL's checks stay) |
| `rtfole` | not an empty file; the type is an RTF file |
| `site_tagger` | the observable's type is one the settings' rows are for |
| `upx` | the type is a PE file |
| `vbscript_analyzer` | not empty; the path ends in `.vbs`, ASCII letters in either case |
| `x509_analyzer` | file_type has a result that calls it a certificate |
| `xml_binary_analyzer` | the type has `<?xml` in its first kilobyte (`Word.Document` there stays in the module) |
| `xml_plain_text_analyzer` | the name doesn't end in `.noxml`; at most `maximum_size` bytes; the type has `<?xml` in its first kilobyte; extracted from something (the source's `microsoft_office` tag stays) |

## Counts

| Pool | Modules | Ported |
|---|---|---|
| parser | 54 | 54 |
| lookup | 16 | 16 |
| core | 4 | 3 |
| sandbox | 16 | 16 |
| scanner | 2 | 2 |
| all | 92 | 91 |

| Step | Modules |
|---|---|
| done | 91 |
| owner | 1 |

No ace3 module goes to 7.8 or 7.9: 7.8's integrations are a site's (below), and remediation and file collection are services, not modules. "done" is the ten modules phases 1 to 4 ported, those 7.4, 7.5, 7.6, 7.7 and 7.10 have ported since, `pdf_link_text`, ported when the inventory followed ace3 to `37a765bf`, and `apex_domain_analyzer`, ported when it followed ace3 to `fe6da632` (their entries). "owner" is a module no step names.

## 7.5's batches

In order. Batches 10 to 13 run programs in the sandbox runner, which batch 10 builds (*External tools*).

1. **URLs and indicators in text**: done. `url_extraction` and `ioc_extraction`, in `ace-mod-urls`, on `ace-urlfinder`, a port of urlfinderlib 0.27.1 whose `Url` and child URLs other modules can use too, with `ace-pycompat` (Python's urllib.parse, html, base64, json, csv and unicodedata, and the idna, validators and tld packages) and `ace-lxml` (libxml2 2.14.6 as lxml 6.1.3 bundles it, with lxml's tree and BeautifulSoup's `get_text()` over it). `url_extraction` waits for `file_type`, ported in batch 2.
2. **File identity**: done. `file_type`, `file_hash_analyzer`, `lnk_parser`, `binary_file_analyzer`, `x509_analyzer` and `dhash`, in `ace-mod-files`. file_type first: many later modules read its result, its tags and its `yara_meta` types. `ssdeep` moved to batch 10: fuzzyhash doesn't give ssdeep's scores (`docs/measurements/ssdeep.md`); batch 10 ported ssdeep's comparison.
3. **Observable values**: done. `command_line_analyzer`, `file_location_analysis`, `file_path_analysis`, `network_identifier`, `parse_url`, `idna_analyzer`, `email_address_fqdn_analyzer`, `protected_url_analyzer`, in `ace-mod-values`, on `ace-urlfinder` and `ace-pycompat`. Strings in, observables out; no files but command lines' payloads. `protected_url_analyzer`'s 1drv.ms links go to `protected_url_one_drive` on the lookup pool (its entry has the decision).
4. **HTML**: done. `html_data_url_extraction`, `har_extraction`, `html_js_extraction`, `mhtml`, in `ace-mod-html`, on `ace-lxml`'s BeautifulSoup tree, `ace-mod-oletools`' port of Python's feed parser and `ace-pycompat`. HTML, MHTML and HAR files, with the DOM snapshots 7.7's js-deobfuscator reads, which ride in the results' `dom_snapshots` rather than in files beside the scripts.
5. **Office containers**: done. `onenote_extraction`, `officeparser3`, `office_xml_rel`, `xml_binary_analyzer`, `xml_plain_text_analyzer`, `extracted_ole_analyzer`, `hidden_mime`, `active_mime`, in `ace-mod-office`. OneNote, compound files, Office XML, hidden MIME and ActiveMime. XML is parsed by `ace_lxml::target`, lxml's target parser over the vendored libxml2, which matches lxml on 472 inputs; MIME by `ace-mod-oletools`' feed parser; compound files by a port of officeparser3's own reader, not olefile's, since what officeparser3 writes for a damaged file follows from how it reads one. `extracted_ole_analyzer` reads on the lease which modules added its file, and runs last; `xml_plain_text_analyzer` reads the tags of the file its file came from, and the archive module now waits for file_type, as ace3's does, so those tags are there.
6. **RTF and scripts**: done. `microsoft_script_encoding_analysis`, `extracted_rtf_analyzer`, `vbscript_analyzer`, `nowhitespace_analyzer`, in `ace-mod-scripts`. Checks and transforms of RTF and script files. The Perl decoder ace3 runs for encoded scripts is ported and matches it byte for byte on 50,000 inputs (`docs/measurements/scripts.md`); `extracted_rtf_analyzer` reads on the lease which modules added its file, and looks for rtfole, whose `extracted_rtf` tag is what ace3 reads.
7. **Encrypted files**: done. `zip_encryption_analyzer`, `rar_encryption_analyzer`, `pdf_encryption_analyzer`, in `ace-mod-encrypted`. No John (7.3): the email's candidates, cut from every body part by `ace_mod_msoffice::words_from_parts` (4.11's, made ace3's again at `1998ca56`), are tried in the task with the zip crate, libunrar and libqpdf, keeping what John's check accepts, which for a PDF is the user password only. The dumps cover each encryption method, a wrong, missing and full list, and no email or no body, with 0 differences but other modules' tags; a decrypted PDF matches pikepdf's copy byte for byte but for the `/ID` pikepdf takes from the clock (`docs/measurements/encrypted.md`).
8. **Email tree**: done. `lure_url_analyzer` and `mailbox_email_analyzer` in `ace-mod-emailtree`, `email_conversation_attachment_analyzer` and `email_conversation_link_analyzer` in `ace-mod-brocess`, beside the frequency module whose `new_sender` tag they read. Each walks the root's tree, which the core sends on the lease (`Module::READS_TREE`, `ace_sdk::tree`), with the files it reads (`Module::READS_TREE_FILES`), the lure module's HTML bodies; a result adds to other observables in the root (`ResultEnvelope::others`) only what its module declares (`Module::ADDS_TO_OTHERS`), the lure's `crawl` and the mailbox's `tracked`, and the mailbox module's changes its root's description and details (`ResultEnvelope::root`, `Module::SETS_ROOT`). The lure module runs last, as ace3's final analysis; the attachment module looks for a macro only as far as ace3 does when it runs, so its answer doesn't depend on which task lands first; the link module, which does nothing without a pattern in ace3, is off until a site gives it a section.
9. **Email archive**: done. `email_archiver`, `encrypted_archive_analyzer`, `url_email_pivot_analyzer`, `message_id_analyzer_v2`, in `ace-mod-emailarchive`, lookup modules on 7.2's reads (`crates/ace-core/src/reads.md`): `archived-email`, `decrypted-archive` and `archived-url-count`, and the `email-archive` write. The archive is `ace_core::email_archive`: each email gzipped and encrypted in the core with ACE's key (`ACE4_ENCRYPTION_KEY`, AES-256-GCM in ace3's layout, which only `ace serve` holds), an object of the bucket's `email_archive` pool held by its rows, and migration 0041's weekly-partitioned tables, which the scheduler's `email_archive_partitions` keeps (6.7's `daily/partitions`, its archive half). A read that opens an email puts it in the task's root, and the result adds it with no upload, which the core allows only for a module that declares such a read (`ace_sdk::reads::FILE_READS`). Brings ace3's `email` router (5.6), `GET /api/email/v1/archive`, under `email:read`, each read audited. The email logger's log entry now names the archive path.
10. **PDF and image text**: done. `ocr`, `qrcode`, `exif` and `pdftotext` in `ace-mod-sandbox`, on the sandbox pool, and `ssdeep` in `ace-mod-files`, on the parser pool. Builds the sandbox runner (`ace_pool::tools`, *The sandbox runner* below) and the sandbox pool's image (*Image*), and adds Ghostscript's rewrite to `pdf_analyzer` and ACE archives to `archive`, which move to the sandbox pool. OpenCV is 5.0.0, ace3's, built with the wheel's defaults and linked statically; tesseract's output matches ace3's on every dump. ssdeep is fuzzyhash's hash with ssdeep 2.14.1's comparison, which matches ssdeep's `-m` on all 420 measured files. The comparison keys Ghostscript's rewrite and ExifTool's metadata, whose bytes change every run on both systems, by their paths (`ace compare`'s `VOLATILE_FILES`), so what runs on them is compared.
11. **Executables**: done. `java_class_decompiler`, `upx`, `autoit`, `de4dot`, `ilspy`, in `ace-mod-sandbox`, on the sandbox runner as it was built, under the filter that lets threads through: CFR on OpenJDK 21, upx, unautoit, and de4dotEx and ilspycmd on .NET 10, each at ace3's version, the .NET tools and unautoit byte for byte (*Image*). Every tool ran contained, with its threads, to the same output as plain (`docs/measurements/sandbox-runner.md`); the runner needed no change to its filter or Landlock, only fixed arguments in a tool's spec and the dlopen'd modules of a tool's data allowed to need a library the image lacks (*The sandbox runner*). Crafted files and what stops each are in `docs/measurements/executables.md`.
12. **macOS images**: done. `dmg_analyzer` and `cve_2021_30657_analyzer`, in `ace-mod-sandbox`: dmg2img 1.6.7 and 7-Zip 25.01, ace3's, on the sandbox runner as it was built, with no change to its filter or Landlock; 7z is the program `/usr/bin/7z` execs, reading the `7z.so` and the RAR codec (7zip-rar's, as ace3 has) it loads. ace3 has no DMG sample, so `tools/samples/make-macos-images` makes ten on Linux (HFS+ by mkfs.hfsplus and libdmg-hfsplus, UDIF by libdmg-hfsplus and by hand), and the CVE module lists the image again rather than read the DMG's result. Crafted images and what stops each are in `docs/measurements/macos-images.md`.
13. **Packet captures**: done. `pcap_analyzer`, `pcap_dns`, `pcap_tls`, `pcap_http`, `pcap_files`, `pcap_tls_decryption` and `tls_keylog`, in `ace-mod-pcap`: tshark 4.4.19 and capinfos, ace3's, on the sandbox runner as it was built, with no change to its filter or Landlock. pcap_analyzer and the decryption are on the sandbox pool; the four categories, which ace3 configures as instances of one class, and tls_keylog, which ace4 never has to run tshark for, are on the parser pool. tshark reads a file only (`-n -r`): asked to capture or list interfaces it runs dumpcap or an extcap helper, and the runner kills it. Its spec gives it a home and a personal configuration directory that don't exist, so it loads no Lua or preferences a working directory could hold (`ace_pool`'s containment tests). pcap_analyzer stores the objects and certificates it carves for the root without adding them (`ResultEnvelope::stored`), and pcap_files and pcap_tls add them with no upload, which the core takes from a module that declares `Module::ADDS_STORED_FILES` when the root holds the file, with the bucket's size. The categories work out their share of each type's 50 observables from the same index, in the order ace3's trees run them, rather than read each other's results. The decryption reads the key logs tls_keylog tagged (`TreeFiles::tagged`), and their key lines reach tshark through the task's scratch directory and nowhere else. ace3's late key log, which an analyst adds to an analyzed alert, has no case in ace4 (the crate's docs). The dumps (`make-dumps pcap_analyzer pcap_dns pcap_tls pcap_http pcap_files pcap_tls_decryption tls_keylog`) match with no row; ace3's fixtures and `tools/samples/make-pcaps`' captures are the samples, and crafted captures are in `docs/measurements/pcap.md`.

7.4 ports, in this workspace, all done: `fqdn_analyzer`, `nrd_analyzer`, `snort_signature_analysis_v1`, `user_analyzer`, `email_conversation_frequency_analyzer`, `email_thread_analyzer`, `email_logger`, `clicker_detection_splunk`. The brocess modules (`email_logger` writes what `email_conversation_frequency_analyzer` and `email_thread_analyzer` read) go together, after 7.2's endpoints.

## Failed analyses

A module fails in one of two ways, and ace4 keeps them apart.

**A result that says it failed.** The module ran to its end and produced a result, but something it needed failed: a tool exited with an error, a lookup couldn't answer, a file didn't parse. It marks the result with the reason (`ResultEnvelope::error`, set with `with_error`), as ace3's module sets `Analysis.error` (ace3 `2b9fcd2c`, `41d44392`, `eb0d0d42`). ace3 moved each module's own key for the reason (`error`, `query_error`, `lookup_error`) out of its details into that, and so did ace4.

- The task ends `done`. What the result held before the failure is kept as a partial result: its details, its summary, the observables and files it added.
- The reason is `analysis.results.error` (migration 0065), outside the details, so nothing has to know the analysis type to read it. A reason is required: the result's schema refuses a blank one, as ace3 raises on one.
- The alert tree shows an `error` badge on the result, with the reason beside it when the result has no summary, and the result's page shows the reason above its details. The API's observables carry it as `results[].error`.
- The normal form holds it as the result's `error`, on a result that failed and on no other, so the comparison with ace3 checks it (`ace_core::normal`, `tools/ace3/dumps/run_module.py`'s `tree_form`). A reference dump holds it the same way.
- A module that depends on the result reads it with `TaskContext::dependency_error`, and one that walks the tree with `TreeResult::error`, as ace3's modules check `analysis.error` before they trust another's analysis. The pcap category modules and `pcap_tls_decryption` do, for `pcap_analyzer`.

**A task that failed.** The module didn't run to its end: it crashed, was killed at its deadline (PLAN.md 2.19), returned a `ModuleError`, or wrote a result the core refused. There is no result. The task's row is `failed` with its error and its inputs' hashes, `/api/crashes` lists it, and `ace task replay` runs it again (2.20). ace3 keeps these in `root.analysis_failures`. The alert tree lists each under its observable with the same badge, and the API's observables as `failed_modules`. The AI investigation API's observables leave `failed_modules` out: its database role holds nothing on the task queue (migration 0064).

Where the two systems draw the line differently:

- ace3's engine marks an analysis failed when its module raises after creating it, with the exception as `<type>: <message>` and ` (crash_id <id>)`, its crash report's id. An ace4 module that returns an error has no result, so that is a failed task. Where a port keeps a partial result at a point ace3's module raises, it marks the result with ace3's `<type>: <message>`. The id is new each run, so both normal forms leave it out of ace3's error and summary. The ports that do this are `har_extraction` (`ValueError: Invalid IPv6 URL` from `urlsplit`), `onenote_extraction` (construct's `StreamError: Error in path (parsing) -> FileDataStoreObject -> <field>` and how much the stream was short), and four for a name past 255 bytes, `OSError: [Errno 36] File name too long: '<path>'`: `microsoft_script_encoding_analysis`, `nowhitespace_analyzer`, `har_extraction` and `html_data_url_extraction`. ace3's path there is the file's on its node and the port's is its path in the alert. `clicker_detection_splunk` raises a `TypeError` in ace3 on a multivalue user field, which the port doesn't reproduce. Other ports stop quietly at a name past 255 bytes where ace3's module would raise: no sample or dump reaches those, and they weren't gone through.
- A delay asked for past its timeout: ace3 closes the analysis with `timed out waiting for delayed analysis to complete`. ace4's task fails with `DelayTimedOut`.
- ace3 says `<tool> did not finish` when its sandbox stops a tool on a timeout or a limit, and goes on. A module that runs a tool in ace4's sandbox runner says the same, and adds why the runner stopped it. A module whose tool is a library inside the task (libmagic, the ports of officeparser, pdf-parser, rtfobj, John's `*2john`, 7z and unrar) has no such stop: past the task's deadline it is a failed task.
- ace3 never caches a failed analysis, and runs a module again on one when the module allows it (`allow_reanalysis_on_failure`, once per work item since `907e3b3e`). ace4 has no result cache (PLAN.md 6.7) and never claims a finished task again; a retry isn't built.

What each module says. ace3's column is every place its code sets `Analysis.error` at `fe6da632`; `<e>` is an exception's text, and `<how T exited>` is ace3's `tool_failure_reason`: `T exited with status N` or `T was killed by signal N`, then `: ` and the last line T wrote to stderr.

| Module | Crate | ace3's reason | ace4 |
|---|---|---|---|
| `rdap_analyzer` | `ace-mod-rdap` | `rdap: <RDAP's error>; whois: <WHOIS's error>` | `rdap: <RDAP's error>`: WHOIS isn't ported |
| `nrd_analyzer` | `ace-mod-nrd` | the creation-date lookup's error | the same lookup's, RDAP's alone |
| `fqdn_analyzer` | `ace-mod-dns` | `A lookup failed: <e>`, `MX lookup failed: <e>`, `wildcard probe failed: <e>`, joined by `; ` | the same, for a resolver that answered with a failure; one that can't be reached fails the task as unavailable |
| a Splunk instance, such as `proxy_domain_splunk` | `ace-mod-splunk` | `timed out`, or `<e>` | the same; splunkd down fails the task as unavailable |
| `clicker_detection_splunk` | `ace-mod-splunk` | each failed search's `<name>: <error>`, joined by `; ` | the same |
| `msoffice_encryption_analyzer` | `ace-mod-msoffice` | `office2john.py failed: <stderr>`, `decryption failed: <e>`, `<e>` for msoffcrypto's `Unsupported encryption method`, `office2john.py did not finish` | the first two; msoffcrypto 6.0.0 raises no such thing where ace3 looks for it, and office2john is a library here |
| `zip_encryption_analyzer` | `ace-mod-encrypted` | `zip2john failed: <stderr>`, `unable to build the password wordlist: <e>`, `<how 7z exited>` above status 1, `unable to crack the password: <e>` where John raised, and two for a tool that didn't finish | the first three: 7z is a library here, so its line is written for it, `7z exited with status 2: ERROR: Wrong password : <member>` for the last member the password doesn't open, and the library's words in 7z's place for any other member that doesn't extract |
| `rar_encryption_analyzer` | `ace-mod-encrypted` | `rar2john failed: <stderr>`, `unable to build the password wordlist: <e>`, `<how unrar exited>`, `unrar could not write every file`, `unable to crack the password: <e>` where John raised, and two for a tool that didn't finish | the first two, and `unrar could not extract the archive` where libunrar fails |
| `pdf_encryption_analyzer` | `ace-mod-encrypted` | `pdf2john.pl failed: <stderr>`, `decryption failed: <e>`, `pdf2john.pl did not finish` | the first two |
| `exif` | `ace-mod-sandbox` | `exiftool did not finish`, ExifTool's own error or `<how exiftool exited>`, `unreadable exiftool output: <e>` | the same |
| `javascript_deobfuscation` | `ace-mod-scanners` | `js deobfuscator call failed: <e>`, the report's error, `<how js deobfuscator exited>` when it reported none | the same |
| `phishkit_analyzer` | `ace-mod-scanners` | `phishkit scan failed for <observable> job ID <id>: <e>`, the same with `timed out`, `failed to scan URL <url>: <e>`, `no job id: the scan was never dispatched` | the first; the scanner pool always has the scan it was asked for |
| `pcap_analyzer` | `ace-mod-pcap` | why the capture wasn't dissected | the same |
| `pcap_tls_decryption` | `ace-mod-pcap` | tshark's failure, or that there isn't time left | the same |
| `autoit` | `ace-mod-sandbox` | `unautoit list timed out`, `unautoit extract-all timed out`, `<e>` | the two, or `unautoit <step> was stopped: <why>` for another stop |
| `upx` | `ace-mod-sandbox` | `upx -d did not finish`, `<e>` | the first, and why the runner stopped it |
| `de4dot` | `ace-mod-sandbox` | `de4dot did not finish`, `<how de4dot exited>, without writing a deobfuscated file` | the same |
| `ilspy` | `ace-mod-sandbox` | `ilspy did not finish`, `<how ilspy exited>, without writing IL` | the same |
| `java_class_decompiler` | `ace-mod-sandbox` | `cfr did not finish`, `<how cfr exited>`, `cfr could not decompile the class file`, `class file <path> does not exist` | the first three |
| `dmg_analyzer` | `ace-mod-sandbox` | `dmg2img did not finish`, `<how dmg2img exited>, without writing an image`, `7z l did not finish, so the image's files are not listed`, `<how 7z l exited>, so the image's file list may be incomplete` | the same |
| `cve_2021_30657_analyzer` | `ace-mod-sandbox` | `7z did not finish extracting <member>, so it and the files after it were not checked`, `<how 7z exited>, without extracting <member>`, `file did not finish on <member>, ...` | the first two, the first naming the first member of a run of several; and its own, when a member's path is too long for a program's arguments or it has added its 500 files |
| `pdftotext` | `ace-mod-sandbox` | `pdftotext did not finish` | the same |
| `pdf_link_text` | `ace-mod-pdf` | `<how pdftotext exited or that it didn't finish>, without the text under the links` | the same |
| `har_extraction` | `ace-mod-html` | `<n> bytes exceeds max_file_size <m>`, `not valid JSON: <e>`, `no log.entries list` | the same |
| `html_js_extraction` | `ace-mod-html` | `failed to extract JavaScript: <e>` | the same |
| `lnk_parser` | `ace-mod-files` | LnkParse3's exception | the port's, with Python's text |
| `olevba_v1_2` | `ace-mod-oletools` | `olevba failed: <e>`, unless olevba couldn't open a file not named as an Office document | the same |
| `rtfole` | `ace-mod-oletools` | `<how rtfobj exited>`, `rtfobj did not finish`, `unable to run rtfobj: <e>` | the first: rtfobj is a library here |
| `xml_plain_text_analyzer`, `xml_binary_analyzer` | `ace-mod-office` | `unable to parse XML: <e>` | the same, with lxml's wording of libxml2's error |
| `office_xml_rel` | `ace-mod-office` | `unable to parse <file name>: <e>` | the same |
| `file_type` | `ace-mod-files` | `file did not finish` | never: libmagic runs in the task |
| `officeparser3` | `ace-mod-office` | `officeparser timed out after <n> seconds` | the same, with ace3's 90, where the port stops because officeparser3 would never end |
| `pdf_analyzer` | `ace-mod-pdf` | `pdfparser did not finish, so its dump of the objects is incomplete` | never: the port runs in the task |
| `microsoft_script_encoding_analysis` | `ace-mod-scripts` | `the decoder did not finish` | never: the decoder runs in the task |
| `archive` | `ace-mod-archive` | `the extractor did not finish`, `the listing was larger than <n> bytes, so the file count is not known`, `unable to create <directory>: <e>` | never: the extractors are libraries, with no listing to cut and no directory to make |
| `yara_scanner_v3_4` | `ace-mod-yara` | `yara scan failed: <e>`, when the scan raised after the analysis was made | never: a scan that fails fails the task |
| `snort_signature_analysis_v1` | `ace-mod-snort` | `unable to look up the signature: <e>` | never: a read the core can't answer fails the task as unavailable |
| `email_conversation_frequency_analyzer` | `ace-mod-brocess` | `unable to query brocess for the conversation count: <e>` | never: one read answers both counts, and fails the task as unavailable |
| `message_id_analyzer_v2` | `ace-mod-emailarchive` | `<e>`, when adding the file fails after the analysis exists | never: a result adds its file or doesn't land |

ace3's `saq/modules/shodan.py` and `saq/modules/test.py` set it too. Neither has a section in `saq.default.yaml`, so neither is in this inventory.

## What 7.2 serves

Modules that read or write ACE's own data in ace3, or hold its encryption key, and what serves each in ace4, where workers hold neither. The reads, their scope, their bounds and how they refuse are a contract in `crates/ace-core/src/reads.md`, beside the lease API; each module's port step builds what its module calls. None is built in 7.2: the one ported module here then, `yara_scanner_v3_4`, gets its data on the ruleset, and that waits for 7.6, which brings the list it reads. 7.4 built the first, `snort-signature`, then `smtp-counts`, `email-thread-domains` with the first writes, `email_logger`'s, `email-thread`, and `newly-registered`, which serves `nrd_analyzer` though ace3's module reads no database of ACE's (below). 7.6 built `observable-tags`, over migration 0042's `analysis.observable_tags`, and `observable_detection` reads its list on the lease; the `ruleset` half of `yara_scanner_v3_4`, ace3's export of the detections as YARA rules, isn't built yet (PLAN.md 7.6).

`tools/ace3/modules/check` finds these in ace3's code at the commit it checks. From each section's class it follows the class's methods, its bases, the functions they name in ace3's own packages and, through an interface, the methods of the package's classes, until it finds `get_db(`, `get_db_connection(`, `private_transaction(`, `run_private_transaction(` or a Redis connection, or a use of `saq.crypto`. It doesn't follow ace3's framework (`saq.analysis`, `saq.configuration`, `saq.engine` and the module base classes), whose own reads are the engine's. Some reads aren't in the module's own file: they're in helpers such as `saq/brocess.py`, `saq/modules/email/conversation.py`, `saq/email_archive/` and `saq/svs/`. At ace3 `37a765bf` it finds the 14 below. The check fails when this table misses one or lists one it doesn't find, or when a row names nothing to serve it or a read `reads.md` doesn't have.

Served by is one or more of: a read of `reads.md`; `lease`, on the leased task (`Module::LISTS` here); `ruleset`, on the YARA ruleset; `end`, a write that lands with the task's end; and `core`, only for a module on the core's pool, which runs in the core.

Not here: `rdap_analyzer` and `nrd_analyzer` use ace3's analysis result cache, which is the engine's, not the module's, and is the core's in ace4 too (PLAN.md decision 26, `ace_core::cache`); `nrd_analyzer`'s domain list is a SQLite file on the node in ace3, which its `nrd-refresh` keeps, and in ace4 migration 0039's `nrd.domains`, which `ace serve`'s `nrd_refresh` task keeps and the `newly-registered` read serves (7.4); the Redis of `javascript_deobfuscation` and `phishkit_analyzer` is Celery's, which 7.7 replaces. A module's secrets, which ace3 can keep encrypted in its database, are the pool's environment in ace4 (2.24). `saq/modules/remediation.py` queries the database through `saq.remediation`, but no section names its module, so it has no row here: `AutomatedRemediationAnalyzer`, ace3's `automated_remediation`, disabled in ace3 and placed nowhere by 7.1, which the owner decided on 2026-11-13 not to port for now (PLAN.md 7.9).

| Module | Reads and writes in ace3 | Why | Served by |
|---|---|---|---|
| `email_archiver` | email_archive: archive (W, INSERT IGNORE; R archive_id); email_archive: archive_index (W, field message_id and url hashes); email_archive: email_history (W, message_id/recipient); email_archive: archive_server (R/W at initialize_email_archive/register, not in this module) | to keep every email it archives findable by Message-ID and URL later | `end` |
| `encrypted_archive_analyzer` | ACE's encryption key: saq.crypto.decrypt of the file, then gunzip. No database | to open an archived email file (`.gz.e`) in the alert | `decrypted-archive` |
| `snort_signature_analysis_v1` | Redis: Redis 'default' config (get_config().redis host/port/user/password), DB 1 (REDIS_DB_SNORT): GET '<sid>:<rev>' per observable. The index (keys '<sid>:<rev>' = rule line, 'suricata_rules_lastmtime', lock 'suricata_rules_lock' with 30s ex/nx) is built by 'ace signatures build-db' (saq/cli/commands/signatures.py:202-230) from data/snort/snort.rules, not by the module. A new redis.Redis connection is created per call (snort.py:110-120). | to show the rule text of a sid and rev an IDS alert names | `snort-signature` |
| `email_conversation_frequency_analyzer` | brocess: smtplog (R, SUM(numconnections) by source, and by source+destination) | to tag a new sender or a frequent conversation by how often the pair was seen | `smtp-counts` |
| `email_thread_analyzer` | brocess: email_thread_message (R: anchor by message_id_hash, messages by thread_id_hash, same-subject threads by normalized_subject_hash); brocess: email_thread_domain (R: participants by thread_id_hash, subject-linked domains) | to show the conversation a Message-ID belongs to, and judge look-alike domains in it | `email-thread` |
| `url_email_pivot_analyzer` | email_archive (primary plus every database_email_archive_* section): archive_index (R, COUNT(DISTINCT archive_id) WHERE field='url' AND hash=UNHEX(SHA2(url,256))) | to count the archived emails that held a URL | `archived-url-count` |
| `email_logger` | brocess: smtplog (W, INSERT ... ON DUPLICATE KEY UPDATE numconnections+1 per envelope recipient); brocess: email_thread_message (W record_thread; R COUNT by thread for telemetry); brocess: email_thread_domain (W record_thread; R established domains by thread or same-subject) | to record each email's sender, recipients and thread for the modules above, and to emit look-alike telemetry against earlier messages | `email-thread-domains`, `end` |
| `yara_scanner_v3_4` | ace: observable_detections (ObservableDetection) by id from $obsd_<id> strings, R; ace: observables (Observable) by id from legacy $obs_<id> strings, R | to add the observable an exported detection rule matched | `ruleset` |
| `message_id_analyzer_v2` | email_archive (primary section): archive JOIN archive_server JOIN archive_index (R, by message_id hash) - called twice (email_is_archived then iter_archived_email) | to pull an archived email into the alert by its Message-ID | `archived-email` |
| `user_defined_tagging` | ace: observables, observable_tag_mapping, tags R (one SELECT per observable, tag.py:107-120) | to add the tags mapped to an observable's value | `observable-tags` |
| `alert_added_to_event` | ace: event_mapping joined to alerts, R | to switch the root to event mode when it's in an event | `core` |
| `svs_yara_sample_capture` | ace: alerts R (disposition), svs_attributions + svs_runs R (unreviewed_run_condition); ace: svs_yara_captures R/W (insert pending, update stored/missing; private transactions); ace: svs_sample_deletions R (is_deleted, checked before and after); ace: cas_objects, cas_holds, cas_purges R/W (CAS index via pool.put/hold/stat/release) | to capture the files YARA matched on a dispositioned alert as SVS samples | `svs-capture-state`, `end` |
| `svs_alert_tagger` | ace: alerts R (insert_date); ace: svs_runs, svs_maintenance_windows R (attribution_open gate, cached svs.attribution.gate_cache_seconds); ace: svs_runs, svs_test_hosts, svs_maintenance_windows, svs_attributions R (evaluate: resolve_markers, runs_overlapping, maintenance_windows_overlapping, _existing) | to tag an alert SVS attributes to a test run or maintenance window | `core` |
| `observable_detection` | Redis: Redis 'local' config (redis_local), DB 4 (REDIS_DB_FOR_DETECTION_A): GET '<type>:<value>' per observable; populated by 'ace observables export' (saq/observables/export/redis_cache.py). One connection per module instance, health_check_interval 30. | to flag an observable an analyst set for detection | `lease` |

## External tools

PLAN.md 7.3. Every module that starts a process in ace3, each program it starts, and what ace4 does instead. A program goes one of four ways:

- **crate**: the module's own task process does the work with a library, and no program runs.
- **runner**: ACE's sandbox runner, below, runs the program as its own contained process, which may start threads but not processes.
- **children**: the sandbox runner runs the program and lets it start processes. No module's program needs this; it is there for 6.6.
- **scanner**: 7.7's scanner pool, which starts an image per file. **none**: the process goes away with nothing in its place.

`tools/ace3/modules/check` finds the modules that start a process in ace3's code, as it finds 7.2's readers: from each section's class through its methods, bases and helpers, to `run_tool`, `run_sandboxed_tool`, `run_sandboxed`, `subprocess`, `Popen`, `os.system` and the like, or `pytesseract`. At ace3 `37a765bf` it finds 31. The modules table below has those and three the scan can't see: two scanners, whose programs ACE's own code doesn't start, and `svs_yara_sample_capture`, whose `git` is behind an interface. The check fails when the scan finds a module the table doesn't have, when a row has no decision, when a row's decisions aren't those of the tools table's rows that name it, or when a decision doesn't fit the module's pool: **runner** needs the sandbox pool (or a module already ported, whose tool comes with batch 10) and **scanner** the scanner pool.

### Evidence

Each program ran in a throwaway container of ace3's own image (`ace3:latest`, Debian trixie, aarch64), with no network, on samples from ace3's tests and a DMG made with `hdiutil`, under `strace -f -qq -e trace=clone,clone3,fork,vfork,execve`. A thread is a `clone` with `CLONE_THREAD`; a process is a `clone` without it, a `fork` or a `vfork`. No program started a process. The ones with threads were run again under a seccomp filter that kills a new process and lets a thread through (`clone` with `CLONE_THREAD` allowed, `clone` without it killed, `clone3` failing with ENOSYS so glibc falls back to `clone`), and the rest under one that kills every `clone`, as the parser's does. A control that forks (`sh -c '/bin/true; echo after'`) died of SIGSYS under the first. Each run under a filter was compared with one without it, stdout and the files written: all were the same but for what names a time or a path (exiftool's `File:FileAccessDate`, and the document ID, dates and `%%Invocation` path in Ghostscript's PDF). `tools/ace3/strace/run` runs it all again: `pass1.sh` counts every tool's threads and processes, `pass2.sh` tries larger inputs and the filters (`filter.py`), `pass3.sh` compares outputs with thread limits and on the page that holds a QR code, and `pass4.sh` covers the programs whose modules go to crates.

### The sandbox runner

ace3's runner (`ace3/saq/sandbox/`) runs a program under `launcher.py`, `prlimit` and `setpriv`: Landlock rules for files, TCP ports and (from ABI 6) signals, rlimits on address space, file size, open files and CPU, an environment of `PATH`, `LANG`, `HOME` and `TMPDIR` only, and a launcher outside the program's Landlock domain that is a child subreaper, caps live descendants (64), and kills every descendant when the program exits, times out or writes more than 64 MiB. It never runs a program where Landlock is missing. ace4's runner, built in 7.5's batch 10, keeps all of that, from ace4's containment rather than `setpriv`. `crates/ace-pool/src/tools.rs` has the code and the protocol; `docs/measurements/sandbox-runner.md` the tests.

- **Who runs it.** A module names its tools in `Module::TOOLS` and runs one with `TaskContext::run_tool` (`ace_sdk::tools`). The pool's image maps each name to an absolute program (`ace_sdk::tools::SANDBOX_TOOLS`), resolved when the pool starts with the libraries its program and interpreter need by `DT_NEEDED`, the dynamic loader and the data it reads (`ace_pool::tools::ToolTable`); the pool won't start with a module whose tool it lacks. A library the program or its interpreter needs must be in the image; one that a module in its data needs, such as the JVM's own libraries, which it loads by dlopen, may be missing, and is left out, since dlopen fails for that module the same way outside the runner (batch 11). A spec may give the program fixed arguments before the request's (`ToolSpec::args`): the `cfr` tool is `java` with ace3's JVM options and CFR's jar. A contained task process can't exec, so the supervisor gives it one end of a Unix socket as descriptor 3 before it contains itself, and serves its requests in order: a frame of JSON naming the tool, its arguments, the task's files it reads and copies into its working directory, the files to keep and the variables to set. The supervisor refuses a tool the module doesn't declare, a path that isn't a plain path inside the task's directory, a variable the tool's spec doesn't allow, and a run past the task's 64 (`MAX_RUNS`); a task can't name a program. It makes an empty working directory owned by the task's user, which is the tool's current directory, `HOME` and `TMPDIR`, and execs the pool's binary in its `tool` mode as that user, never forking (#982). The answer is the exit status or signal, or why the run was stopped, with stdout and stderr (64 MiB each, as ace3) and what the run kept, as files in the task's `results` directory, which the task process may read; it writes the files it hands a tool in its `scratch` directory. A kept file is a plain file with one link, as ace3's `_keep_tool_output` takes it, made readable, whose path a system call takes: 7z can make a deeper tree, a folder at a time, than ace3 or the runner can open (batch 12). Each run's timeout is the module's, cut to the task's time left less ace3's 5-second margin. ace3's flows of several runs (qrcode's page count, renders, scans and inverted scans; unace's listing then extraction) stay as they are.
- **How a tool is contained.** The `tool` process reads what to run on stdin, opens every path it may touch (the task's with `openat2` beneath the task's directory and no symlink followed, since a task can write some of it), and contains itself while it is one thread (`containment::contain_tool`): `RLIMIT_AS` (4 GiB, ace3's `tool_sandbox.memory_limit`), `RLIMIT_CPU` (the timeout times the cores, as ace3, since it counts every thread), `RLIMIT_FSIZE` (1 GiB, ace3's), `RLIMIT_NOFILE` (1,024) and `RLIMIT_CORE` 0, `no_new_privs`, Landlock ABI 4 or later: reading only the tool's program, interpreter, loader, libraries and data and the task files the request names, writing only its working directory (and `/dev/null`), executing only the program, its interpreter and the loader, no TCP, and the signal and abstract socket scopes. Then the tool filter, then the exec. Landlock and seccomp are applied before the exec, so every thread the tool starts inherits them. The PID the supervisor holds is the tool's, and killing it ends every thread, so the deadline and the output cap need no launcher.
- **The tool filter.** `clone` with both `CLONE_THREAD` and `CLONE_VM` (a thread) is allowed, any other `clone` kills the tool, and `fork`, `vfork` and `io_uring_setup` kill it; `clone3` fails with ENOSYS, since seccomp can't read its flags, and glibc falls back to `clone`. `socket` fails with EACCES for every family but `AF_UNIX`, so a tool has no UDP either, which Landlock doesn't cover. `execve` and `execveat` go to the supervisor through the filter's listener (`SECCOMP_RET_USER_NOTIF`): it lets the first through, the `tool` process's own exec of the program, and kills the tool at any other. The supervisor reports a new process (SIGSYS) and a second program as the run stopped, where ace3 would have let it run.
- **With children.** Not built: no module's program starts a process, and 6.6's scripts became command types (decision 16). It would be ace3's launcher, forking once while one thread, outside the program's Landlock domain.
- **Failures.** As ace3 tells them apart: a tool that can't start (missing, not executable, or containment failed) is the node's fault and fails the task; a timeout, too much output, SIGXFSZ, a new process or a second program is the file's, and the run comes back stopped, which the module records as ace3 records a tool that didn't finish. Landlock below ABI 4 fails containment, so a node without it runs no tool, as ace3 runs none.
- **Where it goes.** The runner is in `ace-pool` (`tools`, beside `containment` and the supervisor); `ace-sdk` has the API, the image's tools and `LocalRunner`, which runs them as plain processes for module tests and `ace task replay`. Modules that run tools are on the `sandbox` pool, `ace-sandbox`: a parser pool with the same supervisor and task processes, whose image adds the tools below, so the `parsers` image stays as it is. A parser pool without tools never starts the `tool` mode.
- **For 6.6.** The owner picked 6.6's second option (PLAN.md decision 16): a hunt's scripts are built-in script command types (`ace_hunt::correlate::scripts`), nothing a hunt names is executed, and the hunter's image has no Python.

### Image

The sandbox image's packages, by Debian's installed size: the JRE 199 MB, Wireshark's libraries 134 MB, the .NET 10 runtime 86 MB with de4dotEx (90 MB as ace3 publishes it, self-contained) and ilspycmd 22 MB, Perl 60 MB with ExifTool 28 MB, Ghostscript 24 MB, ImageMagick and zbar 14 MB, tesseract with its data and Leptonica 24 MB, unautoit 11 MB, 7-Zip 7 MB, poppler 6 MB, upx 3 MB, dmg2img and unace under 1 MB: about 710 MB before OpenCV. ace3's one image carries all of that and also the .NET SDK (436 MB, where the runtime is enough), John's build (310 MB) and Node.js (237 MB), which ace4 doesn't need. The JVM and .NET together are about 400 MB for three modules (`java_class_decompiler`, `de4dot`, `ilspy`); the owner kept them in the sandbox image (PLAN.md decision 18), since each module's output (decompiled Java, deobfuscated assemblies, IL) has no other source. The licences don't stop anything: every GPL or AGPL program here (Ghostscript, poppler, unautoit, de4dot, upx, dmg2img, tshark) runs as a separate program, as ace3 runs it, and none is linked into ace4's Apache-2.0 binaries. That is also why Ghostscript, poppler and libautoit aren't crates.

Batch 10's image (`docker/ace4/Dockerfile`'s `sandbox` target, on `debian:13.7-slim`) pins ace3's versions, from `dpkg-query` in ace3's dev container: tesseract-ocr 5.5.0-1+b1 with tesseract-ocr-eng and tesseract-ocr-osd 1:4.1.0-2 (ace3's language data), libtesseract5 5.5.0-1+b1, libleptonica6 1.84.1-4; zbar-tools and libzbar0t64 0.23.93-8, ImageMagick 8:7.1.1.43+dfsg1-1+deb13u14 with its extra coders; libimage-exiftool-perl 13.25+dfsg-1 with libarchive-zip-perl 1.68-1, which ExifTool reads OOXML and OpenDocument with, on Perl 5.40.1-6+deb13u1; poppler-utils and libpoppler147 25.03.0-5+deb13u4, poppler-data 0.4.12-1; ghostscript, libgs10 and libgs10-common 10.05.1~dfsg-1+deb13u3, fonts-urw-base35 20200910-8; unace-nonfree 2.5-10, from non-free; hunspell-en-us 1:2020.12.07-4, the dictionary ace3's enchant uses. OpenCV 5.0.0 is ace3's opencv-python 5.0.0.93's release, built in a stage of its own and linked into the binaries, so the image carries no OpenCV library. ssdeep is a crate. Batch 11 adds, at ace3's versions: openjdk-21-jre-headless 21.0.13+9-1~deb13u2 (ace3's default-jre also pulls openjdk-21-jre's GUI libraries, which CFR doesn't load) with CFR 0.151's jar, the release's, sha256 `316e9015...e837`, at `/usr/local/share/java/cfr-0.151.jar`; upx-ucl 4.2.4-1.1; dotnet-runtime-10.0, dotnet-hostfxr-10.0, dotnet-host and dotnet-runtime-deps-10.0 10.0.14-1 from Microsoft's Debian 13 repository, where ace3 installs the SDK; ilspycmd 11.0.0.9375 as a .NET tool in `/opt/dotnet` and de4dotEx 3.10.0 (commit `5ffdf0f0`) published self-contained to `/opt/de4dotEx`, both made in the `dotnet-tools` stage on dotnet-sdk-10.0 10.0.403-1 with its packs pinned at 10.0.14-1, as ace3's are, so all 283 files are ace3's byte for byte; and unautoit, built from `vendor/unautoit` with Go 1.27.3 as ace3's Dockerfile builds it, the same binary as ace3's (sha256 `571da970...0c77` on arm64), with its licences in `/usr/local/share/doc/unautoit`. ace4-sandbox:latest was 687 MB before batch 11 and is 1.28 GB after (`docker images`, 1,278,887,026 bytes), 591 MB more. Batch 12 adds, at ace3's versions, in a layer of their own: dmg2img 1.6.7+git20201227.a3e4134-0.1, 7zip 25.01+dfsg-1~deb13u2 and 7zip-rar 25.00+ds-1+deb13u1 (non-free), whose `Codecs/Rar.so` ace3's 7z loads too, so an image that is a RAR archive lists and extracts as in ace3. Batch 13 adds, at ace3's version, in a layer of its own with wireshark-common's debconf question answered as ace3's Dockerfile answers it (dumpcap not setuid): tshark, wireshark-common, libwireshark18, libwiretap15, libwsutil16 and libwireshark-data 4.4.19-0+deb13u1, from Debian's security archive, with capinfos and the plugins Debian ships, none of them Lua. ace4-sandbox:latest is 1.49 GB after it (1,486,151,498 bytes), which includes the batch's own code.

### Tools

| Tool | Modules | Threads and children | Options | Decision | Image and licence |
|---|---|---|---|---|---|
| tshark 4.4.19, capinfos | `pcap_analyzer`, `pcap_tls_decryption` | tshark: 3 threads (statistics and JSON runs), no process; capinfos: none. Under the runner (batch 13) the field run with a key log and its object export gave the same JSON and objects as plain, and strace showed no exec but tshark's own, no fork or process `clone`, and no socket but its `AF_UNIX` lookups of nscd. Asked to capture or list interfaces, it runs dumpcap or an extcap helper, which the runner stops (`containment.rs`' `tshark_is_stopped_when_it_would_capture`). | none: the plan keeps tshark in the sandbox runner | **runner**, as the plan says. It starts no process, so it runs without children. Its spec gives it `HOME` and `WIRESHARK_CONFIG_DIR` that don't exist, so it reads no personal preferences or plugins, Lua among them (`tshark_reads_no_lua_or_configuration_from_a_home`), and a 256 MiB file size, ace3's `pcap.sandbox`. | tshark, libwireshark18, libwiretap15, libwsutil16, wireshark-common and libwireshark-data 4.4.19-0+deb13u1, 134 MB; GPL-2 |
| tshark, for a late key log | `tls_keylog` | not run | ace3 runs it only for a key log that arrives after a capture's decryption finished, which an analyst adding a file to an analyzed alert causes; ace4 has no such case (`ace-mod-pcap`'s docs) | **none** | none |
| exiftool 13.25 (Perl) | `exif` | none, on a PDF and a DOCX; the same JSON under the parser's filter | kamadak-exif 0.6.2 (BSD-2, kept up) and nom-exif 3.8.0 read EXIF in images and media; little_exif 0.6.23 is for writing. None reads a PDF's Info and XMP, OLE property sets or OOXML document properties under ExifTool's `Group:Tag` names, which the module stores whole and summarizes. | **runner** | libimage-exiftool-perl 28 MB and Perl 5.40, 60 MB; GPL-1+ or Artistic |
| java (OpenJDK 21) with CFR 0.151 | `java_class_decompiler` | 29 threads with ace3's options, 13 with one CPU, the serial GC and one compiler thread; no process. The parser's filter kills it; the tool filter gives the same source. | no Rust decompiler of Java classes | **runner** | openjdk-21-jre-headless 199 MB, cfr.jar 2 MB; GPL-2 with the Classpath exception, CFR MIT. Kept by decision 18 (Image). |
| upx 4.2.4 | `upx` | none, for `-t` and `-d`; the same output under the parser's filter | no crate unpacks UPX; goblin and object read a PE but not UPX's compressed sections | **runner** | upx-ucl 3 MB; GPL-2+ with UPX's exception |
| unautoit (Go) | `autoit` | 4 or 5 threads (Go's runtime), no process; the same listing under the tool filter | porting its vendored libautoit, 5,315 lines of GPL-3 Go, would put GPL-3 code in ace4's binaries | **runner**, where ace3 runs it unsandboxed | a static Go binary, 11 MB, built from ace3's `third_party/unautoit` as ace3's Dockerfile builds it; GPL-3 |
| de4dotEx 3.10.0 (.NET 10) | `de4dot` | 8 threads detecting, 9 cleaning, no process. The parser's filter kills it; under the tool filter both runs work and the clean writes `deobfuscated`. | no Rust .NET deobfuscator | **runner**. De4dot's dynamic string decrypters can call the sample's methods; one that starts a process now kills the tool. | 90 MB self-contained as ace3 publishes it, of which de4dot's own assemblies are 4 MB, so about that on the shared runtime; GPL-3. Kept by decision 18 (Image); it also reads OpenSSL's two libraries, to hash a reference's public key. |
| ilspycmd 11.0.0.9375 (.NET 10) | `ilspy` | 19 threads, no process; under the tool filter it wrote the sample's IL (2.7 MB) | no crate gives ILSpy's IL | **runner** | dotnet-runtime-10.0 86 MB (ace3 installs the 436 MB SDK), ilspycmd 22 MB; MIT |
| tesseract 5.5.0 | `ocr` | none with `OMP_THREAD_LIMIT=1`, ace3's `omp_thread_limit`; 4 OpenMP threads without it on a large screenshot, with the same text | libtesseract in the task through `tesseract` 0.15.2 (last release April 2025) or `tesseract-rs` 0.4.0 (young): the same engine, but pytesseract runs the program on a PNG, so the program matches ace3 with no binding to keep up | **runner**, with `OMP_THREAD_LIMIT=1` | tesseract-ocr, its English and OSD data, libtesseract5 and Leptonica, 24 MB; Apache-2.0 |
| OpenCV (cv2 5.0 in Python) | `ocr`, `qrcode` | ace3's QR script: 19 threads without `OPENBLAS_NUM_THREADS=1` (numpy's OpenBLAS), none with it and `cv2.setNumThreads(1)` | the `opencv` crate 0.102.0 (MIT, kept up) binds the same library. `imageproc` 0.27 has no non-local-means denoising, and rxing 0.9.4 and rqrr 0.11 find QR codes differently from cv2's `QRCodeDetector`. | **crate**: `opencv` in the task, with `setNumThreads(1)` before containment. ace3 has opencv-python 5.0.0.93 and trixie has OpenCV 4.10, so batch 10 builds 5.0 or shows 4.10 gives the same text and codes. | libopencv's core, imgproc, imgcodecs, photo and objdetect, in the sandbox image only; Apache-2.0 |
| Ghostscript 10.05.1 | `pdf_analyzer`, `qrcode` | none, for `pdfwrite` and `pngalpha`; under the parser's filter the same pages, and the same PDF but for its ID, dates and invocation line | pdfium-render 0.9.5 needs a PDFium library and renders differently; mupdf 0.8.0 is AGPL; qpdf rewrites a PDF but doesn't interpret it, which is what `.gs.pdf` is for (AES-encrypted PDFs' URLs). 4.9 left this open. | **runner** | libgs10 and its common files, 24 MB; AGPL-3 |
| pdfinfo, pdftotext (poppler 25.03.0) | `qrcode`, `pdftotext`, `pdf_link_text` | none; `pdftotext -bbox`, which `pdf_link_text` runs, started no thread and no process either (strace in ace3's image on `ace4/pdf/link_text.pdf`, 2026-11-16) | pdf-extract 0.12.1 (MIT) lays text out differently from pdftotext, and YARA rules match its text; poppler-rs 0.26.0 binds poppler-glib, GPL. libqpdf could count pages but differs from pdfinfo on a damaged file. | **runner** | poppler-utils and libpoppler147, 6 MB; GPL-2 or 3 |
| zbarimg 0.23.93 | `qrcode` | 6 threads (ImageMagick's OpenMP), none with `MAGICK_THREAD_LIMIT=1` and `OMP_THREAD_LIMIT=1`; the same URL plain, under the tool filter, and limited under the parser's | zbar-rust 0.1.1 (LGPL-2.1, little used) binds libzbar; rxing and rqrr are other decoders | **runner** | zbar-tools and libzbar 0.5 MB, ImageMagick 7's libraries 14 MB; LGPL-2.1, ImageMagick's licence |
| dmg2img 1.6.7 | `dmg_analyzer` | none | dmgwiz 1.1.1 (MIT, about 7,000 downloads) extracts partitions, not dmg2img's whole image, which the module adds as a file for YARA | **runner** | 0.2 MB; GPL-2 |
| 7z 25.01, on a DMG's image | `dmg_analyzer`, `cve_2021_30657_analyzer` | none, listing and extracting a member of an HFS+ image, and extracting a 64 MB LZMA2 archive under the parser's filter | hfsplus 0.4.0 (MIT, young) reads HFS+; the module keeps 7z's listing lines as they are and parses its columns | **runner** | 7zip 7 MB; LGPL-2.1; with 7zip-rar's RAR codec, 0.2 MB, under the unRAR licence (non-free), which forbids making a RAR compressor from it, nothing ACE does |
| unace 2.5 | `archive` | none, listing and extracting | no crate reads ACE archives | **runner**, added to `archive` in batch 10 | unace-nonfree 0.2 MB; the Public UnAce Licence, which forbids using it to make an ACE compressor, nothing ACE does |
| 7z, unrar, unzip, `bin/unjar` | `archive`, `zip_encryption_analyzer`, `rar_encryption_analyzer` | not run | zip, sevenz-rust2 and unrar (1.29) | **crate** | none |
| John the Ripper 1.9.0-jumbo-1, zip2john, rar2john, pdf2john.pl, office2john.py | `msoffice_encryption_analyzer`, `zip_encryption_analyzer`, `rar_encryption_analyzer`, `pdf_encryption_analyzer` | john: 10 threads (OpenMP; it links libgomp), no process; zip2john and pdf2john.pl: none | ace3 runs John only with `--wordlist`, the email body's candidates (up to `list_limit`, 5,000), and no rules, so trying each word with the format's own library gives the same password | **crate**: the wordlist tried in the task, as 4.11 does for Office, with zip, unrar and libqpdf (batch 7, `ace-mod-encrypted`), each candidate checked as John's format checks it | none; saves John's 310 MB build |
| file (libmagic 5.46) | `archive`, `file_type`, `de4dot`, `ilspy`, `cve_2021_30657_analyzer` | none | libmagic in the task: `ace-mod-files`' own cookies, from the database's bytes, for the type step's description and mime type, and `ace_yara::mime` from the same bytes in the YARA module for a file whose type step failed; the core runs none (PLAN.md decision 25) | **crate** | none |
| node `--check`, grep | `file_type`, `extracted_ole_analyzer` | node: 7 threads, no process | oxc_parser 0.157.0 (MIT, kept up) checks syntax; batch 2 measured it against node 24 on 850 cases, with no disagreement once the proposals V8 13.6 lacks are refused (`docs/measurements/javascript-check.md`) | **crate** | none; saves Node.js, 237 MB |
| ssdeep 2.14.1 | `ssdeep` | none | fuzzyhash 0.2.2 (MIT, pure Rust, last release 2023) gives ssdeep's hashes but not its `-m` scores, batch 2 found; batch 10 kept its hash and wrote ssdeep 2.14.1's comparison, `fuzzy_compare` (`ace_mod_files::ssdeep`), which gives ssdeep's scores on all 420 files (`docs/measurements/ssdeep.md`); ssdeep 0.7.0 binds libfuzzy and is GPL-3, ffuzzy 0.3 is GPL-2+ | **crate**: fuzzyhash, with the comparison ported, in the parser pool | none |
| pdf-parser.py, xlmdeobfuscator, pcodedmp, rtfobj, officeparser3 | `pdf_analyzer`, `xlmdeobfuscator`, `pcodedmp`, `rtfole`, `officeparser3` | Python, gone | ported in 4.9, 4.10 and 4.12; officeparser3 in batch 5, as a port of its own compound file reader in `ace-mod-office` | **crate** | none |
| jscript.decode.pl | `microsoft_script_encoding_analysis` | none | about 80 lines of Perl, ported in batch 6 (`ace_mod_scripts::mse::decode`), matching the Perl byte for byte (`docs/measurements/scripts.md`) | **crate** | none |
| git | `yara_scanner_v3_4`, `observable_modifier`, `svs_yara_sample_capture` | not run | the ruleset records its commit (2.26) | **none** | none |
| version probes (`probe_binary_version`) | `ocr`, `qrcode`, `pdf_link_text` | the tool with its version arguments, no input, once | they key ace3's analysis result cache, which is the core's in ace4 (decision 26) | **none**: no module runs them; the pool runs each cacheable module's tools with `ToolSpec::version_args` once when it starts, as a plain child process with an empty environment and no input, outside the sandbox runner, and sends the versions with each result (`ace_pool::cache`) | none |
| docker, through the scanner managers | `javascript_deobfuscation`, `phishkit_analyzer` | not ACE's | 7.7: the scanner pool, `ace_pool::scanners`, over Docker's API | **scanner** | `ace4-js-deobfuscator` and `ace4-phishkit`, built from ace3's sources by `docker/scanners/build` |

### Modules that start a process

| Module | Pool | Tools in ace3 | Decision |
|---|---|---|---|
| `pcap_analyzer` | sandbox | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); runs: `capinfos -M -S input` (30 s timeout), `tshark -n -r input -q -z io,stat,0 -z endpoints,eth -z endpoints,ip -z endpoints,ipv6 -z conv,tcp -z conv,udp`, then `tshark -n -r input -T json -Y 'frame.number <= max_field_packets && (dns \|\| tls.handshake \|\| http.request \|\| http.response \|\| http2.headers \|\| dhcp \|\| nbns)' -e <38 fields> --export-objects http\|smb\|ftp-data\|tftp\|imf,objects/<proto>` (pcap.tshark_timeout 120 s each) | tshark, capinfos: **runner** |
| `pcap_tls_decryption` | sandbox | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); one run: `tshark -n -r input -T json -Y ... -e ... --export-objects ... -o tls.keylog_file:keylog` (no statistics/capinfos pass) | tshark: **runner** |
| `tls_keylog` | parser | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError) -- only for late key logs: one tshark run per pcap with a completed PcapTlsDecryptionAnalysis that this key log has new session keys (or RSA keys) for | tshark: **none** |
| `javascript_deobfuscation` | scanner | none started by ACE itself; the js-deobfuscator manager container (docker:dind image, Alpine python3 venv with celery[redis] + pyyaml, unpinned) runs `docker run --rm --network none -v <stack>_js-deobfuscator:/js-deobfuscator ${ACE3_JS_DEOBFUSCATOR_IMAGE_URL:-js-deobfuscator} node /opt/app/harness.js <input> <output>/deobfuscated.js` via subprocess.Popen on the host docker socket, killed after scanner_timeout (30 s); scanner image: node:26-alpine with webcrack 2.15.1 (npm, --ignore-scripts, isolated-vm not built); harness.js uses node:vm (webcrack sandbox 10 s timeout, dynamic run 5 s per script) | **scanner** (7.7) |
| `ssdeep` | parser | ssdeep 2.14.1 via run_tool (plain subprocess.run, unsandboxed): `ssdeep -m <ssdeep_hashes> <file>` | ssdeep: **crate** (fuzzyhash's hashes, ssdeep 2.14.1's comparison) |
| `archive` | sandbox | 7z (7zip 25.01, with 7zip-rar 25.00) via run_sandboxed_tool: `7z -y -pinfected l` and `7z -y -pinfected -o<dir> x` (and `7z -y -o<dir> x` for MSI); unrar 7.1.8 via run_sandboxed_tool: `unrar la` and `unrar e -y -o+ -idq -kb`; unzip via run_sandboxed_tool: `unzip -l -P infected` and `unzip -qq ... -x xl/activeX/* ... -d <dir>`; unace-nonfree 2.5 via run_sandboxed_tool on a copy in a temp staging dir: `unace l` and `unace x -y -o`; bin/unjar (python3 script using custom_zipfile.extractall) via run_sandboxed_tool for jar files; file via Popen `file -b -L` (unsandboxed, no timeout) in is_msi_file, called up to twice | 7z, unrar, unzip, unjar: **crate** (1.29); unace: **runner**; file: **crate** |
| `java_class_decompiler` | sandbox | java (default-jre, OpenJDK 21) running /usr/local/bin/cfr.jar (cfr 0.151) via run_sandboxed_tool: `java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar cfr.jar <class>` | java with CFR: **runner** |
| `officeparser3` | parser | officeparser3 (unixfreak0037/officeparser3, pip-installed from git master; config officeparser_path /venv/bin/officeparser3) via subprocess.Popen directly, NOT sandboxed, timeout config 90s | **crate**: a port of officeparser3 in `ace-mod-office` |
| `xlmdeobfuscator` | parser | xlmdeobfuscator CLI (DissectMalware/XLMMacroDeobfuscator master, with xlrd2 and pyxlsb2 master) resolved from PATH via subprocess.Popen, NOT sandboxed: `xlmdeobfuscator -f <file>` and `xlmdeobfuscator -x -f <file>`, timeout config 30s each | **crate** (4.12) |
| `pcodedmp` | parser | bin/pcodedmp_wrapper (bash) via subprocess.Popen, NOT sandboxed: `timeout --foreground --signal=KILL 30 /venv/bin/pcodedmp <file> \| sed -ne '/^Module streams:/,$ p' \| egrep '^[[:space:]]'`; pcodedmp 1.2.6 (pip, uses oletools/olefile) | **crate** (4.12) |
| `msoffice_encryption_analyzer` | parser | bin/office2john.py (vendored, bundles an old olefile 0.42) via run_sandboxed_tool with the venv python3 -I (sandbox_python()); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>` | office2john.py and John: **crate**, the wordlist tried in the task (4.11) |
| `extracted_ole_analyzer` | parser | node (nodejs 24.22) `node --check <file or hard link {file}-<uuid>.js>` via subprocess.Popen from is_javascript_file(), NOT sandboxed, no timeout; grep -Eq <JS keyword regex> <file> via Popen, no timeout | node and grep: **crate** (oxc_parser) |
| `file_type` | parser | file (libmagic 5.46) via run_tool (plain subprocess.run, unsandboxed), twice: `file -b -L` and `file -b --mime-type -L`; node 24.22 via Popen `node --check <file or hard link>.js` (unsandboxed, no timeout) in is_javascript_file, only when mime is a JS type or extension is .js/.mjs/.cjs/.jse; grep via Popen `grep -Eq <js keyword regex>` (unsandboxed) after node --check succeeds | file: **crate** (libmagic); node and grep: **crate** (oxc_parser) |
| `pdf_analyzer` | sandbox | python3 bin/pdf-parser.py (Didier Stevens pdf-parser 0.7.12, vendored) via run_tool (plain subprocess.run, unsandboxed), timeout 10 s, run on the file and again on the decrypted copy; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pdfwrite -o output.pdf -f <file>`, timeout 10 s | pdf-parser.py: **crate** (4.9); gs: **runner** |
| `upx` | sandbox | upx (upx-ucl 4.2.4) via run_sandboxed_tool: `upx -t <file>` then `upx -d -ounpacked.exe <file>` | upx: **runner** |
| `autoit` | sandbox | unautoit (vendored Go build from third_party/unautoit) via run_tool (plain subprocess.run, UNSANDBOXED): `unautoit list <file>` and `unautoit extract-all --output-dir {file}.autoit <file>` | unautoit: **runner** |
| `de4dot` | sandbox | de4dotEx 3.10.0 (/opt/de4dotEx/de4dot, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET_GCHeapHardLimit=1 GB, memory limit 12 GB, timeout 10 s: `de4dot -d <file>` then `de4dot <file> -o deobfuscated`; file via Popen `file -b -L` (unsandboxed, no timeout) in is_dotnet | de4dot: **runner**; file: **crate** |
| `ilspy` | sandbox | ilspycmd 11.0.0.9375 (/opt/dotnet/ilspycmd, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET env heap limits, memory limit 12 GB, timeout 10 s: `ilspycmd -il --disable-updatecheck -o . <file>`; file via Popen `file -b -L` (unsandboxed) in is_dotnet | ilspycmd: **runner**; file: **crate** |
| `ocr` | sandbox | tesseract (tesseract-ocr 5.5.0) via pytesseract.image_to_string, which starts it with subprocess UNSANDBOXED and no timeout, twice per image (`--oem 1 --psm 3`); tesseract --version via probe_binary_version (subprocess.run, cached per binary mtime) for the cache key | tesseract: **runner**; OpenCV: **crate** (`opencv`); the version probe: **none** |
| `qrcode` | sandbox | pdfinfo (poppler-utils 25.03.0) via run_sandboxed_tool for the page count; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pngalpha -o <pattern> -r144 -dFirstPage -dLastPage`, up to 2 runs plus a full-render fallback; zbarimg (zbar-tools 0.23.93) via run_sandboxed_tool: `zbarimg -q --raw --nodbus`, per page and per inverted page; venv python3 -I bin/qr_decode_opencv.py via run_sandboxed_tool (OPENBLAS_NUM_THREADS=1), when zbarimg finds no URL; zbarimg/gs/pdfinfo version probes via probe_binary_version (subprocess.run, cached) for the cache key | pdfinfo, gs, zbarimg: **runner**; the OpenCV script: **crate** (`opencv`); the version probes: **none**, the pool's once at its start (`ace_pool::cache`, decision 26) |
| `dmg_analyzer` | sandbox | dmg2img 1.6.7 via run_sandboxed_tool: `dmg2img <file> image.img`; 7z 25.01 via run_sandboxed_tool: `7z l <image>` | dmg2img, 7z: **runner** |
| `cve_2021_30657_analyzer` | sandbox | 7z 25.01 via run_sandboxed_tool: `7z x -o<temp> <img> <member>` once per Contents/MacOS member; file via run_tool (plain subprocess.run, unsandboxed): `file -b --mime-type -L <extracted>` | 7z: **runner**; file: **crate** |
| `exif` | sandbox | exiftool (libimage-exiftool-perl 13.25) via run_sandboxed_tool: `exiftool -j -G -n <file>`, timeout 30 s | exiftool: **runner** |
| `pdftotext` | sandbox | pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext <file> output.txt`, timeout 5 s | pdftotext: **runner** |
| `pdf_link_text` | sandbox | pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext -bbox -f <first> -l <last> <file> -`, timeout 10 s, once per PDF, over the pages with links among the first `link_text_pages`; `pdftotext -v` via probe_binary_version (subprocess.run, cached) for the cache key | pdftotext: **runner**; the version probe: **none** |
| `yara_scanner_v3_4` | parser | git via subprocess.run `git -C <dir> rev-parse HEAD` (saq/git.py get_commit_hash) when initializing the local scanner, through get_validated_git_repo_dirs | git: **none**; the ruleset records its commit (2.26) |
| `microsoft_script_encoding_analysis` | parser | perl script bin/jscript.decode.pl (vendored, ~80 lines) via run_tool() = subprocess.run, NOT sandboxed; timeout = time_left() minus margin | jscript.decode.pl: **crate**, the decoder ported |
| `observable_modifier` | core | git rev-parse HEAD via subprocess.run (saq/git.py:53-70), only when the optional git_dir setting is configured (not set in saq.default.yaml), on each rules reload | git: **none**; its rules come from the overlay, with no commit |
| `rtfole` | parser | `python /venv/bin/rtfobj -d {file}.rtfobj -s all <file>` (oletools 0.60.2 rtfobj) via run_tool() = subprocess.run, NOT sandboxed; 'python' resolved from PATH; timeout = time_left() minus margin | **crate** (4.10) |
| `zip_encryption_analyzer` | parser | zip2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; 7z 25.01 `7z x -y -p<password> -o<abs dir> <file>` via run_sandboxed_tool, timeout extract_timeout=5s, write_dirs=[{file}.decrypted] | zip2john and John: **crate**, the wordlist tried in the task with zip; 7z: **crate** |
| `rar_encryption_analyzer` | parser | rar2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; unrar 7.1.8 `unrar x -y -kb -p<password> <file> <abs dir>/` via run_sandboxed_tool, read_files=archive_volumes(), write_dirs=[{file}.decrypted], timeout = time_left() | rar2john and John: **crate**, the wordlist tried in the task with unrar; unrar: **crate** |
| `pdf_encryption_analyzer` | parser | perl <john_bin_path>/pdf2john.pl <file> via run_sandboxed_tool, read_dirs=[john run dir] (uses john's bundled ExifTool perl lib); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; hash written as 'pdf:<$pdf$...>' with login='pdf' | pdf2john.pl and John: **crate**, the wordlist tried in the task with libqpdf |
| `svs_yara_sample_capture` | lookup | git via subprocess.run (rev-parse --show-toplevel, remote URL, rev-parse HEAD) through saq.signatures.git_context.GitContext.resolve when the yara rule inventory is (re)built for _rule_content_hash (saq/svs/capture.py:210-217, saq/signatures/loaders/yara.py:332, saq/git.py:53-110) | git: **none**; the ruleset records its commit (2.26) |
| `phishkit_analyzer` | scanner | none started by ACE; the phishkit manager container (docker:dind, Alpine, python venv with unpinned celery[redis], pydantic, pyyaml, python-magic) runs two Celery workers (worker_launcher.py: scan queue 'celery' and control queue 'phishkit_control' solo pool) and per scan `docker run --rm --init --name phishkit-scan-<job> --label phishkit.* --memory/--memory-swap --cpus --stop-timeout 5 -v <stack>_phishkit:/phishkit ${ACE3_PHISHKIT_IMAGE_URL:-phishkit} /opt/venv/bin/python /opt/app/scanner.py <url \| --file path> --output-dir ... [--proxy ...] [--config ...]` via Popen, with a retry without proxy on proxy errors; also docker inspect/ps/stop/kill/rm (reaper thread kills orphans older than reaper_max_age_seconds); scanner image: ubuntu 22.04 + google-chrome-stable (current at build) + chromedriver, Xvfb, ffmpeg; python seleniumbase, pyautogui, selenium-recaptcha-solver (git), pillow, opencv-python, pyyaml (all unpinned) | **scanner** (7.7) |

## Modules

In the config's order. ace4 is the crate a ported module is in.

| Module | Class | ace4 | Pool | Step | Groups | Modes |
|---|---|---|---|---|---|---|
| `html_data_url_extraction` | `HTMLDataURLAnalyzer` | `ace-mod-html` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `har_extraction` | `HARExtractor` | `ace-mod-html` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_analyzer` | `PcapAnalyzer` | `ace-mod-pcap` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_dns` | `PcapCategoryAnalyzer` | `ace-mod-pcap` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_tls` | `PcapCategoryAnalyzer` | `ace-mod-pcap` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_http` | `PcapCategoryAnalyzer` | `ace-mod-pcap` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_files` | `PcapCategoryAnalyzer` | `ace-mod-pcap` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcap_tls_decryption` | `PcapTlsDecryptor` | `ace-mod-pcap` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `tls_keylog` | `TlsKeylogAnalyzer` | `ace-mod-pcap` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `html_js_extraction` | `HTMLJavaScriptExtractor` | `ace-mod-html` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `onenote_extraction` | `OneNoteFileAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `javascript_deobfuscation` | `JavaScriptDeobfuscationAnalyzer` | `ace-mod-scanners` | scanner | done | file | analysis, binary, cli, correlation, email, file |
| `command_line_analyzer` | `CommandLineAnalyzer` | `ace-mod-values` | parser | done | common | analysis, binary, cli, correlation, email, file |
| `mailbox_email_analyzer` | `MailboxEmailAnalyzer` | `ace-mod-emailtree` | parser | done | email | analysis, cli, correlation, email |
| `email_analyzer` | `EmailAnalyzer` | `ace-mod-email` | parser | done | email | analysis, cli, correlation, email |
| `lure_url_analyzer` | `LureURLAnalyzer` | `ace-mod-emailtree` | parser | done | correlation | analysis, cli, correlation |
| `email_archiver` | `EmailArchiveAction` | `ace-mod-emailarchive` | lookup | done | - | email |
| `encrypted_archive_analyzer` | `EncryptedArchiveAnalyzer` | `ace-mod-emailarchive` | lookup | done | email | analysis, cli, correlation, email |
| `file_location_analysis` | `FileLocationAnalyzer` | `ace-mod-values` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `file_path_analysis` | `FilePathAnalyzer` | `ace-mod-values` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `network_identifier` | `NetworkIdentifier` | `ace-mod-values` | parser | done | correlation | analysis, cli, correlation |
| `parse_url` | `ParseURLAnalyzer` | `ace-mod-values` | parser | done | correlation | analysis, cli, correlation |
| `fqdn_analyzer` | `FQDNAnalyzer` | `ace-mod-dns` | lookup | done | correlation | analysis, cli, correlation |
| `apex_domain_analyzer` | `ApexDomainAnalyzer` | `ace-mod-values` | parser | done | correlation | analysis, cli, correlation |
| `idna_analyzer` | `IDNAAnalyzer` | `ace-mod-values` | parser | done | correlation | analysis, cli, correlation |
| `rdap_analyzer` | `RdapAnalyzer` | `ace-mod-rdap` | lookup | done | correlation | analysis, cli, correlation |
| `nrd_analyzer` | `NRDAnalyzer` | `ace-mod-nrd` | lookup | done | common | analysis, binary, cli, correlation, email, file |
| `snort_signature_analysis_v1` | `SnortSignatureAnalyzer_v1` | `ace-mod-snort` | lookup | done | correlation | analysis, cli, correlation, suricata_ids |
| `user_analyzer` | `UserAnalyzer` | `ace-mod-user` | lookup | done | correlation | analysis, cli, correlation |
| `email_address_fqdn_analyzer` | `EmailAddressFQDNAnalyzer` | `ace-mod-values` | parser | done | common | analysis, binary, cli, correlation, email, file |
| `email_conversation_frequency_analyzer` | `EmailConversationFrequencyAnalyzer` | `ace-mod-brocess` | lookup | done | email | analysis, cli, correlation, email |
| `email_conversation_attachment_analyzer` | `EmailConversationAttachmentAnalyzer` | `ace-mod-brocess` | parser | done | email | analysis, cli, correlation, email |
| `email_conversation_link_analyzer` | `EmailConversationLinkAnalyzer` | `ace-mod-brocess` | parser | done | email | analysis, cli, correlation, email |
| `email_thread_analyzer` | `EmailThreadAnalyzer` | `ace-mod-brocess` | lookup | done | correlation | analysis, cli, correlation |
| `url_email_pivot_analyzer` | `URLEmailPivotAnalyzer` | `ace-mod-emailarchive` | lookup | done | correlation | analysis, cli, correlation |
| `email_logger` | `EmailLoggingAnalyzer` | `ace-mod-brocess` | lookup | done | - | email |
| `file_hash_analyzer` | `FileHashAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `ssdeep` | `SsdeepAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `archive` | `ArchiveAnalyzer` | `ace-mod-archive` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `java_class_decompiler` | `JavaClassDecompilerAnalysisModule` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `olevba_v1_2` | `OLEVBA_Analyzer_v1_2` | `ace-mod-oletools` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `officeparser3` | `OfficeParserAnalyzer3` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `xlmdeobfuscator` | `XLMMacroDeobfuscatorAnalyzer` | `ace-mod-xlm` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `mhtml` | `MHTMLAnalysisModule` | `ace-mod-html` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pcodedmp` | `PCodeAnalyzer` | `ace-mod-xlm` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `office_xml_rel` | `OfficeXMLRelationshipExternalURLAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `msoffice_encryption_analyzer` | `MSOfficeEncryptionAnalyzer` | `ace-mod-msoffice` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `xml_binary_analyzer` | `XMLBinaryDataAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `xml_plain_text_analyzer` | `XMLPlainTextAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `extracted_ole_analyzer` | `ExtractedOLEAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `file_type` | `FileTypeAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pdf_analyzer` | `PDFAnalyzer` | `ace-mod-pdf` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `pdf_link_text` | `PDFLinkTextAnalyzer` | `ace-mod-pdf` | sandbox | done | correlation | analysis, cli, correlation |
| `upx` | `UPXAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `autoit` | `AutoItAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `lnk_parser` | `LnkParseAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `de4dot` | `De4dotAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `ilspy` | `IlspyAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `ocr` | `OCRAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `qrcode` | `QRCodeAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `hidden_mime` | `HiddenMIMEAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `active_mime` | `ActiveMimeAnalyzer` | `ace-mod-office` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `dmg_analyzer` | `DMGAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `cve_2021_30657_analyzer` | `CVE_2021_30657_Analyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `exif` | `ExifAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `pdftotext` | `PDFTextAnalyzer` | `ace-mod-sandbox` | sandbox | done | file | analysis, binary, cli, correlation, email, file |
| `yara_scanner_v3_4` | `YaraScanner_v3_4` | `ace-mod-yara` | parser | done | file, yara | analysis, binary, cli, correlation, email, file, yara |
| `binary_file_analyzer` | `BinaryFileAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `microsoft_script_encoding_analysis` | `MicrosoftScriptEncodingAnalyzer` | `ace-mod-scripts` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `url_extraction` | `URLExtractionAnalyzer` | `ace-mod-urls` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `ioc_extraction` | `IOCExtractionAnalyzer` | `ace-mod-urls` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `observable_modifier` | `ObservableModifierAnalyzer` | `ace-core` | core | done | common | analysis, binary, cli, correlation, email, file |
| `x509_analyzer` | `X509Analyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `protected_url_analyzer` | `ProtectedURLAnalyzer` | `ace-mod-values` | parser | done | common | analysis, binary, cli, correlation, email, file |
| `rtfole` | `RTFOLEObjectAnalyzer` | `ace-mod-oletools` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `extracted_rtf_analyzer` | `ExtractedRTFAnalyzer` | `ace-mod-scripts` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `message_id_analyzer_v2` | `MessageIDAnalyzerV2` | `ace-mod-emailarchive` | lookup | done | correlation | analysis, cli, correlation |
| `vbscript_analyzer` | `VBScriptAnalyzer` | `ace-mod-scripts` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `nowhitespace_analyzer` | `NoWhiteSpaceAnalyzer` | `ace-mod-scripts` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `user_defined_tagging` | `UserDefinedTaggingAnalyzer` | `ace-mod-tag` | lookup | done | common | analysis, binary, cli, correlation, email, file |
| `configuration_defined_tagging` | `ConfigurationDefinedTaggingAnalyzer` | `ace-core` | core | done | common | analysis, binary, cli, correlation, email, file |
| `site_tagger` | `SiteTagAnalyzer` | `ace-mod-tag` | parser | done | common, file | analysis, binary, cli, correlation, email, file |
| `zip_encryption_analyzer` | `ZipEncryptionAnalyzer` | `ace-mod-encrypted` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `rar_encryption_analyzer` | `RarEncryptionAnalyzer` | `ace-mod-encrypted` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `pdf_encryption_analyzer` | `PDFEncryptionAnalyzer` | `ace-mod-encrypted` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `alert_added_to_event` | `AlertAddedToEventAnalyzer` | not yet | core | owner | - | dispositioned |
| `svs_yara_sample_capture` | `YaraSampleCapture` | `ace-mod-svs` | lookup | done | - | dispositioned |
| `svs_alert_tagger` | `SVSAlertTagger` | `ace-core` | core | done | - | correlation |
| `dhash` | `DHashImageAnalyzer` | `ace-mod-files` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `observable_detection` | `ObservableDetectionAnalyzer` | `ace-mod-tag` | lookup | done | common | analysis, binary, cli, correlation, email, file |
| `phishkit_analyzer` | `PhishkitAnalyzer` | `ace-mod-scanners` | scanner | done | correlation, file | analysis, binary, cli, correlation, email, file |
| `clicker_detection_splunk` | `SplunkClickerDetectionAnalyzer` | `ace-mod-splunk` | lookup | done | correlation | analysis, cli, correlation |

## Entries

### html_data_url_extraction

- **Section**: `analysis_module_html_data_url_extraction`, class `HTMLDataURLAnalyzer` in `saq/modules/file_analysis/html.py`, enabled by default.
- **ace4**: ported in `ace-mod-html`. ace3's `etc/mime.types` (public domain) is `mime_types.tsv`. It writes at most 500 files and stops there, as ace3's root takes at most 500 file observables (`maximum_observable_count`), which ace4's core doesn't have (`docs/measurements/html.md`).
- **Pool**: parser. Regex and base64 over an attacker's file.
- **Step**: done.
- **Does**: Scans any non-empty file (no file-type gate) with a regex for base64 data: URLs (data:<mime>;base64,...), decodes each and adds it as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: {file}_embed_{n}.{ext} (ext from etc/mime.types for the declared mime type, default 'bin').
- **yara_meta**: type=document.html.embedded.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/mime.types (map_mimetype_to_file_ext reads the whole file for every extracted item, saq/util/filesystem.py:134).
- **Tags and detections**: No tags or detections. Extracted files: volatile, extracted_from the source, exclude_analysis(self) and exclude_analysis(OCRAnalyzer) (QR scanning still runs).
- **Notes**: mmaps min(max_bytes 100 MiB, size) of the file (html.py:211). No cap on the number of data URLs extracted, nor on the decoded size, nor dedup. Runs on every file type, not only HTML. Counter `count` increments even if add_file_observable returns None, so names stay unique.

### har_extraction

- **Section**: `analysis_module_har_extraction`, class `HARExtractor` in `saq/modules/file_analysis/har.py`, enabled by default.
- **ace4**: ported in `ace-mod-html`. It parses with `ace-pycompat`'s `json.loads` and `urllib.parse`. The DOM snapshots are in the result's `dom_snapshots`, each with the scripts whose `.dom.json` it is, since ace4 keeps no file outside the tree. Where Python raises out of ace3's module, such as `urlsplit` on a broken IPv6 host, the result is what ace3's analysis held at that point. Its header test is its declaration, from the file's type (*What a module takes*).
- **Pool**: parser. JSON and HTML parsing of an attacker's file.
- **Step**: done.
- **Does**: Detects an HTTP archive (.har JSON with a leading "log" key) by content, extracts the HTML/SVG page and JavaScript response bodies as file observables linked to the URL they were downloaded from, and writes a DOM-snapshot sidecar beside each script a page loads.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: beautifulsoup4 4.15.0 with lxml 6.1.3 (parse_document for page script tags and build_dom_snapshot, imported from html_js_extraction); pydantic 2.14.1 (config).
- **Tools**: none.
- **Writes**: {file}.extracted/<NNN entry index>_<sanitized last path segment><.html|.svg|.js>; {file}.extracted/<NNN>_<name>.js.dom.json (DOM snapshot of the first page that loads that script; not an observable).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: No tags or detections. Adds file observables (volatile, extracted_from the .har, exclude_analysis(self)) and url observables (http/https) with downloaded_from relationship file -> url.
- **Notes**: Caps: max_file_size 50 MiB (whole file json.load-ed), max_extracted_files 50 (pages first, then scripts), dedup by body sha256, data: URLs skipped. Base64 bodies decoded. Records truncated when content.size > body length. The .dom.json sidecar format is shared with html_js_extraction and consumed by javascript_deobfuscation (har.py:331).

### pcap_analyzer

- **Section**: `analysis_module_pcap_analyzer`, class `PcapAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `analyzer` module: capinfos and the two tshark runs in the sandbox runner, the index built as ace3 builds it, the hosts added, and the objects and certificates it carves stored for the root (`ResultEnvelope::stored`), for pcap_files and pcap_tls to add, as ace3 writes them beside the capture. tshark reads the task's copy of the capture where it is, rather than a copy in its working directory, which ace3 makes so tshark can't write the evidence: Landlock lets it read the task's files only. Its JSON is parsed by serde_json, and by `ace-pycompat`'s `json.loads` when that refuses it, for Python's error. A node that can't run the tools fails the task, as every sandbox module's does, where ace3 records `PcapNodeError` on the analysis. Observables aren't volatile, which ace4 doesn't have. Its 10 dumps match. Its `is_pcap_file` test is its declaration, from the file's type, as is each pcap module's (*What a module takes*).
- **Pool**: sandbox. Runs tshark and capinfos, which stay in ACE's sandbox runner. tshark starts threads and no process, so it runs there without children (*External tools*).
- **Step**: done.
- **Does**: Dissects a pcap/pcapng file (detected by magic, not extension) with sandboxed capinfos and two tshark runs, stores the capture index (capture metadata, endpoints, flows, DNS/TLS/HTTP/hostnames, carved objects, certificates, embedded pcapng decryption secrets) and adds the host observables (IP, MAC, hostname).
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: cryptography 50.0.2 (x509 DER cert parsing via saq/x509.py); pydantic 2.14.1 (config).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); runs: `capinfos -M -S input` (30 s timeout), `tshark -n -r input -q -z io,stat,0 -z endpoints,eth -z endpoints,ip -z endpoints,ipv6 -z conv,tcp -z conv,udp`, then `tshark -n -r input -T json -Y 'frame.number <= max_field_packets && (dns || tls.handshake || http.request || http.response || http2.headers || dhcp || nbns)' -e <38 fields> --export-objects http|smb|ftp-data|tftp|imf,objects/<proto>` (pcap.tshark_timeout 120 s each).
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel. tshark itself starts threads (2 or 3 under strace, short-lived) and no process; capinfos none (batch 13).
- **Writes**: {pcap}.pcap_objects/<protocol>/<exported object name> (tshark --export-objects, moved out of the workdir; _NNN suffix on collision); {pcap}.pcap_objects/certificates/<sha256>.der (handshake certificates); DATA_DIR/var/pcap_sandbox/<tmp>/input (temporary copy, deleted).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config section `pcap` (shared by all pcap modules).
- **Tags and detections**: tags the pcap pcap_embedded_<kind>_keys (tls, ssh, wireguard, zigbee_nwk, zigbee_aps, opc_ua, unknown) when a pcapng carries Decryption Secrets Blocks; no detection points. Adds ip/mac_address/hostname observables (volatile) under the PCAP Analysis node; the carved files and certificates are written here but added as observables by pcap_files / pcap_tls.
- **Notes**: Sandbox config is pcap.sandbox (a plain SandboxConfig, max_output_bytes 64 MiB default), work dir DATA_DIR/var/pcap_sandbox (sweep_stale_workdirs on every dissect); the capture is copied (never hard-linked) into the workdir as 'input' (pcap.py:849). Checks the run fits: needed = 30 + 2*(tshark_timeout+30) s vs self.time_left() (module maximum_analysis_time 360 and the alert's cumulative 900 s), records an error instead of starting (pcap.py:1266). Caps: max_file_size 1 GiB, max_field_packets 50,000 (a display filter, so object export still covers the whole capture), max_table_rows 500, max_extracted_files 100 (objects + certs), max_observables_per_type 50 counted across all pcap nodes of one capture (add_pcap_observables, pcap.py:1074). read_embedded_secrets parses pcapng block headers in Python, at most 1,000,000 blocks, TLS secrets up to max_keylog_size; only client randoms with keys are stored, never the secrets (pcap.py:1299). On engine stop (SandboxCancelled) it calls cancel_analysis() and returns INCOMPLETE so dependants stay unresolved (pcap.py:1277). PcapNodeError (no Landlock, tool missing) goes to log_loop_exception; PcapError is recorded on the analysis. Files carved only if a regular file with st_nlink==1 and the dirs are not symlinks (pcap.py:740-778). Excluded fqdn suffixes .arpa/.local. Docs: docs/PCAP_ANALYSIS.md.

### pcap_dns

- **Section**: `analysis_module_pcap_dns` (instance `dns`), class `PcapCategoryAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `category` module makes one module of each instance, each reading pcap_analyzer's result on the capture (`Module::DEPENDS_ON`). A capture's 50 observables of a type are shared by its results in ace3's order, which ace3 takes from a set (in its trees: http, files, dns, tls); each category works it out from the same index (`ace_mod_pcap::budget`), so the shares are the same on every run, and the `categories` setting names the categories a site runs, as one it turns off gives the others its share in ace3. Its dumps match.
- **Pool**: parser. Turns pcap_analyzer's index into observables; no process.
- **Step**: done.
- **Does**: Turns the 'dns' part of the PcapAnalysis index of a pcap file into observables under its own 'PCAP DNS' node; does no dissection itself.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (wait_for_analysis(_file, PcapAnalysis), pcap.py:1376; completes with nothing if PcapAnalysis errored or is missing).
- **Libraries**: pydantic 2.14.1 (PcapCategoryConfig: category Literal).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config section `pcap` (excluded_fqdn_suffixes, max_observables_per_type).
- **Tags and detections**: No tags. Adds fqdn (display types DNS Query Name / DNS CNAME Target / DNS Zone (SOA/NS) / DNS Record Name) and ip observables for answers (volatile, timed at first answer, display 'DNS Answer IP'); non-interesting IPs (multicast, loopback, link-local, reserved, unspecified) dropped.
- **Notes**: One class, four config instances (instance: dns|tls|http|files, `category` setting). Gated on is_pcap_file magic. Rows copied into details are the index's (<= max_table_rows 500). Observable budget shared per capture: add_pcap_observables counts every PcapAnalysis/PcapCategoryAnalysis/PcapTlsDecryptionAnalysis node of the pcap and reserves room for the files node's payload files when this is not the files instance (pcap.py:1390). Sets display_type only when no other module set one. No node when the category has neither rows nor observables.

### pcap_tls

- **Section**: `analysis_module_pcap_tls` (instance `tls`), class `PcapCategoryAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `category` module, as pcap_dns. pcap_tls and pcap_files add the files pcap_analyzer stored with no upload (`Module::ADDS_STORED_FILES`); the core gives each the bucket's size, which the index doesn't hold for a certificate. Its dumps match.
- **Pool**: parser. As pcap_dns.
- **Step**: done.
- **Does**: Turns the 'tls' part of the PcapAnalysis index of a pcap file into observables under its own 'PCAP TLS' node plus the carved handshake certificates; does no dissection itself.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (wait_for_analysis(_file, PcapAnalysis), pcap.py:1376; completes with nothing if PcapAnalysis errored or is missing).
- **Libraries**: pydantic 2.14.1 (PcapCategoryConfig: category Literal).
- **Tools**: none.
- **Writes**: none written; adds as observables the {pcap}.pcap_objects/certificates/<sha256>.der files pcap_analyzer wrote.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config section `pcap` (excluded_fqdn_suffixes, max_observables_per_type).
- **Tags and detections**: No tags. Adds fqdn for SNI (display 'TLS SNI' unless DNS saw it), ja4 observables (display 'JA4 client fingerprint (TLS ClientHello), seen to ...'), and file observables for certificates pcap_analyzer carved, with directive no_crawl and relationship extracted_from the pcap.
- **Notes**: One class, four config instances (instance: dns|tls|http|files, `category` setting). Gated on is_pcap_file magic. Rows copied into details are the index's (<= max_table_rows 500). Observable budget shared per capture: add_pcap_observables counts every PcapAnalysis/PcapCategoryAnalysis/PcapTlsDecryptionAnalysis node of the pcap and reserves room for the files node's payload files when this is not the files instance (pcap.py:1390). Sets display_type only when no other module set one. No node when the category has neither rows nor observables.

### pcap_http

- **Section**: `analysis_module_pcap_http` (instance `http`), class `PcapCategoryAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `category` module, as pcap_dns. Its dumps match.
- **Pool**: parser. As pcap_dns.
- **Step**: done.
- **Does**: Turns the 'http' part of the PcapAnalysis index of a pcap file into observables under its own 'PCAP HTTP' node; does no dissection itself.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (wait_for_analysis(_file, PcapAnalysis), pcap.py:1376; completes with nothing if PcapAnalysis errored or is missing).
- **Libraries**: pydantic 2.14.1 (PcapCategoryConfig: category Literal).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config section `pcap` (excluded_fqdn_suffixes, max_observables_per_type).
- **Tags and detections**: No tags. Adds url (http/https only), fqdn/ip for the Host header, and user_agent observables.
- **Notes**: One class, four config instances (instance: dns|tls|http|files, `category` setting). Gated on is_pcap_file magic. Rows copied into details are the index's (<= max_table_rows 500). Observable budget shared per capture: add_pcap_observables counts every PcapAnalysis/PcapCategoryAnalysis/PcapTlsDecryptionAnalysis node of the pcap and reserves room for the files node's payload files when this is not the files instance (pcap.py:1390). Sets display_type only when no other module set one. No node when the category has neither rows nor observables.

### pcap_files

- **Section**: `analysis_module_pcap_files` (instance `files`), class `PcapCategoryAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `category` module, as pcap_dns. pcap_tls and pcap_files add the files pcap_analyzer stored with no upload (`Module::ADDS_STORED_FILES`); the core gives each the bucket's size, which the index doesn't hold for a certificate. Its dumps match.
- **Pool**: parser. As pcap_dns.
- **Step**: done.
- **Does**: Turns the 'files' part of the PcapAnalysis index of a pcap file into observables under its own 'PCAP Files' node; does no dissection itself.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (wait_for_analysis(_file, PcapAnalysis), pcap.py:1376; completes with nothing if PcapAnalysis errored or is missing).
- **Libraries**: pydantic 2.14.1 (PcapCategoryConfig: category Literal).
- **Tools**: none.
- **Writes**: none written; adds as observables the {pcap}.pcap_objects/<protocol>/<name> files pcap_analyzer wrote.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config section `pcap` (excluded_fqdn_suffixes, max_observables_per_type).
- **Tags and detections**: No tags. Adds file observables for the objects tshark exported (extracted_from the pcap; downloaded_from a url observable when exactly one HTTP request's last path segment matches the file name, _link_http_objects pcap.py:815).
- **Notes**: One class, four config instances (instance: dns|tls|http|files, `category` setting). Gated on is_pcap_file magic. Rows copied into details are the index's (<= max_table_rows 500). Observable budget shared per capture: add_pcap_observables counts every PcapAnalysis/PcapCategoryAnalysis/PcapTlsDecryptionAnalysis node of the pcap and reserves room for the files node's payload files when this is not the files instance (pcap.py:1390). Sets display_type only when no other module set one. No node when the category has neither rows nor observables.

### pcap_tls_decryption

- **Section**: `analysis_module_pcap_tls_decryption`, class `PcapTlsDecryptor` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `decryption` module runs last (`Module::RUNS_LAST`), as ace3's final analysis, and reads the files tls_keylog tagged `tls_keylog` (`TreeFiles::tagged`), which ace3 finds by the same sniff of every file in the alert, so the pool downloads only those. Their key lines go to a file in the task's scratch directory, which tshark reads in the runner and which is removed after; no log line or result holds one. Its 9 dumps match. Its `is_pcap_file` test is its declaration, from the file's type (*What a module takes*).
- **Pool**: sandbox. Runs tshark with key logs, in the sandbox runner.
- **Step**: done.
- **Does**: In final analysis, finds every TLS key log (SSLKEYLOGFILE format, by content) among the alert's file observables and re-runs tshark on a pcap with those keys, adding the DNS/TLS/HTTP/file observables the decrypted traffic shows beyond the plaintext index.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (reads PcapAnalysis via get_and_load_analysis in execute_final_analysis, no wait_for; needs index.tls non-empty); scans all file observables in the root for key logs (find_keylog_observables).
- **Libraries**: cryptography 50.0.2 (certificate names via saq/x509.py).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); one run: `tshark -n -r input -T json -Y ... -e ... --export-objects ... -o tls.keylog_file:keylog` (no statistics/capinfos pass).
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel. tshark itself starts threads (2 or 3 under strace, short-lived) and no process; capinfos none (batch 13).
- **Writes**: {pcap}.pcap_decrypted/<protocol>/<exported object name>; {pcap}.pcap_decrypted/certificates/<sha256>.der; DATA_DIR/var/pcap_sandbox/<tmp>/keylog (the merged key log lines, i.e. the TLS secrets, written into the temporary sandbox workdir; deleted with it).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none configured; it handles TLS session secrets from key-log files in the alert (stored only as label counts and sha256 in details).
- **Network**: none.
- **Reads outside the alert**: config section `pcap`.
- **Tags and detections**: No tags or detections. Adds observables not already in the plaintext index (non-host categories), files with extracted_from/downloaded_from and certificates with no_crawl.
- **Notes**: execute_analysis returns INCOMPLETE for any pcap so the work happens in execute_final_analysis, once every key log is in the tree (pcap.py:1544-1550). Skips (records error) if tshark_timeout+30 s does not fit in time_left() (maximum_analysis_time 180). Runs tshark only when some session has new keys not already covered by pcapng embedded secrets, or an RSA key line is present (pcap.py:1491). Idempotent: known_sha256 from the plaintext index and earlier decryptions are not carved again; merge_index keeps old rows (pcap.py:663). On SandboxCancelled it deletes its analysis and returns INCOMPLETE. Key log sniff: first 4 KiB ASCII, up to 5 lines must match NSS labels; max_keylog_size 10 MiB. tls_keylog may later re-run apply_keylogs on this module's analysis (late key log).

### tls_keylog

- **Section**: `analysis_module_tls_keylog`, class `TlsKeylogAnalyzer` in `saq/modules/file_analysis/pcap.py`, enabled by default.
- **ace4**: ported in `ace-mod-pcap`. Its `keylog` module: the sniff, the labels and the tag. ace3's late application, a tshark run on a capture whose decryption finished before the key log arrived, is left out: in ace3 an analyst adding a key log to an analyzed alert causes it, and ace4 has no way to add a file to one; its decryption runs once everything else in the alert has, this module among them, and finds every key log. A module that runs last adding a key log is the one case left, which no ported module does with a key log. `applied_to` and `skipped` stay empty. Its 4 dumps match.
- **Pool**: parser. It runs no program in ace4 (above).
- **Step**: done.
- **Does**: Recognizes a file as a TLS key log (NSS SSLKEYLOGFILE lines) by content, records label counts and session count, tags it, and when the key log arrives after a pcap's TLS decryption already completed, decrypts that pcap again with it via sandboxed tshark.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: reads other observables' PcapTlsDecryptionAnalysis (must be completed) and PcapAnalysis via get_and_load_analysis; no wait_for.
- **Libraries**: cryptography 50.0.2 (only on the late-apply path, via certificate parsing).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError) -- only for late key logs: one tshark run per pcap with a completed PcapTlsDecryptionAnalysis that this key log has new session keys (or RSA keys) for.
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel. tshark itself starts threads (2 or 3 under strace, short-lived) and no process; capinfos none (batch 13).
- **Writes**: {pcap}.pcap_decrypted/<protocol>/<name> and {pcap}.pcap_decrypted/certificates/<sha256>.der (late apply, added to the pcap's existing PCAP TLS Decryption analysis); DATA_DIR/var/pcap_sandbox/<tmp>/keylog (temporary).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none configured; reads TLS secrets from the key-log file itself (never stored: only label counts and number of client randoms).
- **Network**: none.
- **Reads outside the alert**: config section `pcap`.
- **Tags and detections**: Tags the file tls_keylog. No detections. Modifies another observable's PcapTlsDecryptionAnalysis (set_details_modified) and adds observables under it.
- **Notes**: Mutates analysis of a different observable (the pcap's PcapTlsDecryptionAnalysis), which an ace4 port must model as a cross-observable write (pcap.py:1634-1667). maximum_analysis_time 600; pcaps that no longer fit (tshark_timeout+30 > time_left) are listed in details.skipped. On SandboxCancelled deletes its own analysis and returns INCOMPLETE so it re-applies. max_keylog_size 10 MiB.

### html_js_extraction

- **Section**: `analysis_module_html_js_extraction`, class `HTMLJavaScriptExtractor` in `saq/modules/file_analysis/html_js_extraction.py`, enabled by default.
- **ace4**: ported in `ace-mod-html`. It parses with `ace_lxml::soup`, BeautifulSoup 4.15's tree over lxml's target parser, checked against bs4 on 750 inputs. The DOM snapshots are in the result's `dom_snapshots` with the files whose `.dom.json` each is, up to 16 MiB of them a result, since ace4 keeps no file outside the tree; 7.7's deobfuscator reads them from there. It writes at most 500 scripts and adds at most 500 URLs and 500 URI paths, as ace3's root takes at most 500 files and URLs (`maximum_observable_count`); ace3 has no limit on URI paths (`docs/measurements/html.md`).
- **Pool**: parser. HTML parsing of an attacker's file.
- **Step**: done.
- **Does**: Extracts inline <script> bodies and inline event-handler code from HTML, SVG and MHTML files into .js file observables (with a DOM-snapshot sidecar for the JS deobfuscator) and adds url/uri_path observables for external script sources.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; file_type (config dependency; reads FileTypeAnalysis.mime_type for files without an HTML extension, accepted: text/html, application/xhtml+xml, image/svg+xml, message/rfc822); reads the file's downloaded_from relationship (set by phishkit_analyzer / har_extraction) to put the page URL into the DOM snapshot.
- **Libraries**: beautifulsoup4 4.15.0 (lxml parser); lxml 6.1.3; urlfinderlib 0.27.1 (URL(...).is_url to choose url vs uri_path); pydantic 2.14.1 (config).
- **Tools**: none.
- **Writes**: {dir of file}/{basename without ext}_js_inline_{i}_{sha256[:8]}.js; {dir}/{basename}_js_event_{onattr}_{i}_{sha256[:8]}.js; <each script>.js.dom.json (DOM snapshot sidecar, not an observable); {file}.dom.json (document snapshot, when external script URLs were found).
- **yara_meta**: type=script.javascript (on each extracted script); reads: type=script.javascript (skip a non-.html/.svg/.mht file already known to be JS).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: No tags or detections. Extracted .js files: volatile, extracted_from the source, exclude_analysis(self), source directives copied then preview directive removed. External script URLs get directive crawl when the source has crawl_extracted_urls.
- **Notes**: Skips JSON documents sniffed as text/html (is_json_document, to avoid HAR files) (html_js_extraction.py:374). MHTML: only text/html and application/xhtml+xml parts. min_script_size 10, max_event_handler_size 8192, dedup by sha256 across the file. DOM snapshot caps: 2000 elements, 16 KiB per attribute, 4 KiB text, dom_snapshot_max_bytes 512 KiB. No overall file size cap: the whole file is read and parsed. build_dom_snapshot/parse_document/get_script_source/write_dom_snapshot are imported by har_extraction.

### onenote_extraction

- **Section**: `analysis_module_onenote_extraction`, class `OneNoteFileAnalyzer` in `saq/modules/file_analysis/one_note.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. The FileDataStoreObject is read as construct reads it, and an object that runs past the bytes read ends the search there with what was found before, as the exception does in ace3. It writes at most 499 files, as ace3's root holds 500 with the file itself (`docs/measurements/office-containers.md`). Its test, a `.one` name or OneNote's header GUID, is its declaration: the name over the path, the header from the file's type (*What a module takes*).
- **Pool**: parser. Binary parsing of an attacker's file.
- **Step**: done.
- **Does**: For a OneNote file (.one extension or the OneNote header GUID), finds every FileDataStoreObject by its GUID and writes each embedded file payload out as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: construct 2.10.70 (saq/onenote.py FileDataStoreObject struct).
- **Tools**: none.
- **Writes**: {file}.extracted-{sha256(payload)[:6]}.
- **yara_meta**: type=document.onenote.embedded.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the source onenote (before parsing). Extracted files extracted_from the source; not volatile. No detections.
- **Notes**: Reads up to max_bytes (100 MiB) into memory; regex search for GUID e716e3bd65261145a4c48d4d0b7a9eac; FileDataStoreObject.parse is not wrapped in try/except, so a truncated object (cbLength beyond the data) raises out of execute_analysis (one_note.py:90). Two payloads sharing the first 6 hex chars of sha256 overwrite each other's file. is_onenote_file trusts the .one extension alone (is_file_type.py:348).

### javascript_deobfuscation

- **Section**: `analysis_module_javascript_deobfuscation`, class `JavaScriptDeobfuscationAnalyzer` in `saq/modules/file_analysis/js.py`, enabled by default.
- **ace4**: ported in `ace-mod-scanners`. The module runs on the parser pool and reads its root's tree for the DOM snapshot of the document the script runs in, which `html_js_extraction` and `har_extraction` keep in their results' `dom_snapshots` (`Module::READS_TREE_DETAILS`), or for a script fetched from a URL, that URL's `extracted_from` document's. Its first run asks for a js-deobfuscator scan of the script, with the snapshot beside it as `<script>.dom.json`, and its task waits for the scan as a delayed task, up to `celery_timeout`; the scanner pool runs `ace4-js-deobfuscator`, ace3's image built from ace3's sources (`docker/scanners/build`), with `--network none` as ace3's manager does, and its next run reads the output, contained, and makes the manager's `report.json` from stdout as the manager does. It waits for `file_type` and leaves out the `script.javascript` tag file_type's own test gives, since ace3 runs it before file_type in its configuration's order and never sees that tag; in ace4, without the wait, which landed first would be a race. Matches ace3's dumps on 9 inputs (`crates/ace-mod-scanners/tests/differences.md`); the trace's bytes differ from run to run in both, by the job id in its `// source:` line, so the comparison keys it by its path (`ace compare`'s `VOLATILE_PREFIXES`). No volatile observables, as elsewhere in ace4.
- **Pool**: scanner. Runs attacker JavaScript in node in a no-network container that a Celery manager starts through the Docker socket; 7.7's scanner pool replaces the manager.
- **Step**: done.
- **Does**: Sends a JavaScript file (.js extension or yara meta type=script.javascript) to the js-deobfuscator Celery service, which runs it in a throwaway no-network Node container (webcrack static pass plus a node:vm sandbox that traces writes to stubbed browser/Acrobat globals), and adds the reconstructed trace and any Blob payloads as file observables marked for URL extraction.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: html_js_extraction / har_extraction (sidecar .dom.json and type=script.javascript yara meta; not a wait_for). In ace4 the sidecars are those results' `dom_snapshots`, each listing the files whose `.dom.json` it is (7.5 batch 4).
- **Libraries**: celery[redis] 5.6.3 (client side: imports js_deobfuscator.js_deobfuscator and calls deobfuscate.delay(...).get(timeout=celery_timeout)); redis 6.4.0 (Celery result backend); pydantic 2.14.1.
- **Tools**: none started by ACE itself; the js-deobfuscator manager container (docker:dind image, Alpine python3 venv with celery[redis] + pyyaml, unpinned) runs `docker run --rm --network none -v <stack>_js-deobfuscator:/js-deobfuscator ${ACE3_JS_DEOBFUSCATOR_IMAGE_URL:-js-deobfuscator} node /opt/app/harness.js <input> <output>/deobfuscated.js` via subprocess.Popen on the host docker socket, killed after scanner_timeout (30 s); scanner image: node:26-alpine with webcrack 2.15.1 (npm, --ignore-scripts, isolated-vm not built); harness.js uses node:vm (webcrack sandbox 10 s timeout, dynamic run 5 s per script).
- **Threads and children**: Not in ACE's process: the remote manager starts a docker CLI process that starts a sibling Node container per scan (Node has its own worker threads).
- **Writes**: {dir}/deobfuscated-{file name} (moved from the result dir); {dir}/{file name}.{blob file name} (Blob payloads named by MIME-derived extension: .html/.svg/.js); /js-deobfuscator/input/<uuid>/<file name> and <file name>.dom.json on the shared docker volume (input copy; aged out by the maintain_files task); a temp dir from create_temporary_directory() that receives copies of the result files (std.out, std.err, exit.code, report.json, deobfuscated.js, blobs); not removed by this module (js.py:279).
- **yara_meta**: reads: type=script.javascript (as directive yara_meta:type=script.javascript); type=script.javascript (on the source when exit 0 and the source parsed or failed only at runtime; and on deobfuscated-*).
- **ACE's data**: Redis: Celery result backend redis://ace3:<password>@redis:6379/8, key prefix js_deobfuscator; password read from /auth/passwords/redis when the js_deobfuscator module is imported.
- **Secrets**: RabbitMQ password (/auth/passwords/rabbitmq, user ace3); Redis password (/auth/passwords/redis).
- **Network**: Celery over RabbitMQ (pyamqp://ace3@rabbitmq//, queue/exchange js_deobfuscator) and Redis db 8; hardcoded hostnames, deliberately NOT ACE's rabbitmq config (saq/js_deobfuscator.py docstring, issue #1100). The scanner container has --network none..
- **Reads outside the alert**: the DOM snapshot sidecar {file}.dom.json or, for a script fetched from a URL, the extracting document's {document}.dom.json found via the url's extracted_from relationship (js.py:220).
- **Tags and detections**: Tags the source js. No detections. Output files get extracted_from the source and directive extract_urls; deobfuscated-* also exclude_analysis(self).
- **Notes**: Blocking: waits up to celery_timeout 60 s in the analysis worker (no delayed analysis), scanner_timeout 30 s passed to the task. ACE side needs the shared volume mounted at /js-deobfuscator (SHARED_INPUT_DIR). Manager (js_deobfuscator/js_deobfuscator.py): Celery app 'js_deobfuscator', tasks ping, deobfuscate(file_path, timeout) -> output dir /js-deobfuscator/output/<uuid> with std.out/std.err/exit.code/report.json (harness's JSON stdout), maintain_files(max_file_age_days) deleting input/output job dirs (called from saq/cli/commands/js_deobfuscator.py). Needs /var/run/docker.sock, i.e. root-equivalent on the host. Skips files already prefixed deobfuscated-. Emits an observable only when exit 0, output non-empty and event_count>0 or an error. No cache (comment js.py and html_js_extraction.py:733 note the sidecar would need to be in a cache key).

### command_line_analyzer

- **Section**: `analysis_module_command_line_analyzer`, class `CommandLineAnalyzer` in `saq/modules/command_line.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. shlex's non-POSIX split, ntpath's basename and ace3's path and base64 helpers are ported in `py.rs`; the paths a shorter one starts with are dropped by sorting rather than comparing every pair, the same result in `n log n`. A command line `executed_on` a host gives `file_location` observables, so a leased task now carries its observable's relationships (`TaskObservable::relationships`). A payload's file is named by its path in the alert, and numbered `_000` and on only against this result's own files. Only the first 500 payloads get files, as ace3's root takes at most 500 file observables (`maximum_observable_count`), which ace4's core doesn't have (`docs/measurements/observable-values.md`).
- **Pool**: parser. Tokenizes an attacker's string and writes decoded payloads.
- **Step**: done.
- **Does**: Tokenises a command_line observable to extract Windows file paths (as file_path, plus file_location when the command has an executed_on host) and base64 payloads (decoded to files), with PowerShell -EncodedCommand awareness.
- **Input**: command_line.
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: command_line_base64_payload.bin (via root.create_output_file, one per payload; uniquified by create_output_file).
- **yara_meta**: type=payload.base64.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: tag base64 on each payload file observable; file_location observables inherit the collect_file directive when the command line has it
- **Notes**: base64_minimum_length 128 (decoded bytes) except the token right after a PowerShell -e/-enc/-ec/-EncodedCommand flag (also en/em dash variants) when the program is powershell/pwsh (command_line.py:146-182). A second regex pass finds base64 inside tokens (RE_BASE64_RUN). Paths: is_nt_path on tokens plus find_nt_paths_in_text, then prefix-substring paths dropped. shlex posix=False; unbalanced quotes skip the token pass only.

### mailbox_email_analyzer

- **Section**: `analysis_module_mailbox_email_analyzer`, class `MailboxEmailAnalyzer` in `saq/modules/email/mailbox.py`, enabled by default.
- **ace4**: ported in `ace-mod-emailtree`. It reads the root's alert type in the tree on the lease (`Module::READS_TREE`), the email's analysis as its dependency, and the Message-IDs that analysis added in the tree. The root's new description and the email's details merged into its own go in the result (`ResultEnvelope::root`), which the core takes only from a module that declares it (`Module::SETS_ROOT`) and lands with it: the description in the root's row, the details merged into the `details` of its origin, where a submitter inside ACE keeps them. `tracked` goes to each Message-ID through `ResultEnvelope::others`. A root's alert type is its origin's `alert_type`; nothing in ace4 submits a `mailbox` root until 6.1, so the module skips every root today. `crates/ace-mod-emailtree/tests/differences.md` has the rest.
- **Pool**: parser. Edits the tree only: no file, network or database. The result carries the root's description and details and the Message-IDs' directive, which the core lands.
- **Step**: done.
- **Does**: For roots of alert_type 'mailbox' only, on the file with the original_email directive, sets the root description to 'ACE Mailbox Scanner Detection - <subject>', merges EmailAnalysis details into the root details, and marks the email's message_id observables tracked.
- **Input**: file (required directive original_email).
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: config: email_analyzer; reads EmailAnalysis via get_and_load_analysis (config dependency email_analyzer, no wait_for_analysis).
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: No tags or detections; adds DIRECTIVE_TRACKED to F_MESSAGE_ID observables under EmailAnalysis.
- **Notes**: Side effects on the RootAnalysis itself (description and details.update(email_analysis.details), mailbox.py:49-66, marked 'XXX HACK'); ace4 needs a way for a module to set root description/details. wide_diff: true in config tells the delta recorder the module touches observables outside the analyzed one (module_execution_delta.py:331). Since 8617ba8e it no longer returns early for a whitelisted root.

### email_analyzer

- **Section**: `analysis_module_email_analyzer`, class `EmailAnalyzer` in `saq/modules/email/rfc822.py`, enabled by default.
- **ace4**: ported in `ace-mod-email`.
- **Pool**: parser. Parses an attacker's MIME in the task's own process on mail-parser (1.x, 4.x).
- **Step**: done.
- **Does**: Parses a file observable that FileTypeAnalysis says is an RFC 822 email (or has the original_email directive) with Python's email package, picks the target message (Office 365 journal unwrapping by X-MS-Exchange-Parent-Message-Id and the journal 'meta block'), applies the outbound filter (`scan_inbound_only`, which since 8617ba8e skips only the email analysis), and adds address/subject/message-id/delivery/IP/first-hop/DKIM/tenant/user-agent observables plus every MIME part as an extracted file.
- **Input**: file.
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: config: file_type; reads FileTypeAnalysis via get_and_load_analysis (no wait; config dependency file_type); reads root observables tagged smtp_mail_from / smtp_rcpt_to (added by the SMTP collector) as envelope from/to.
- **Libraries**: python stdlib email/mimetypes; python-dateutil 3.0.0 (Received date parse); pytz 2026.5; pydantic 2.14.1 (config). saq/whitelist.py, and with it iptools on this path, went in 8617ba8e.
- **Tools**: none.
- **Writes**: {file}.unknown_<maintype>_<subtype>_<NNN><ext> (unnamed MIME parts; ext from mimetypes.guess_extension of the declared type); <attachment filename from the sender, RFC2047-decoded, CR/LF stripped, cleaned/uniquified by create_output_file>; {file}.email.rfc822 (attached message/rfc822 that is not the journal target); {file}.headers (shortened basename; all headers, one per line); {file}.combined (headers + every 'unknown_' body part concatenated, for yara); OUTSIDE ALERT: $DATA_DIR/review/rfc822/<uuid4> copy when BytesParser fails (rfc822.py:1085); OUTSIDE ALERT: $DATA_DIR/review/rfc822/<basename>.<YYYYmmddHHMMSS> copy when a MIME part fails to extract (rfc822.py:1688).
- **yara_meta**: type=email.attachment (every extracted part); type=email.headers; type=email.combined; reads: type=email.headers, type=email.combined (EmailAnalysis.attachments, rfc822.py:909).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: config global_settings.local_domains and local_email_domains (first-hop resolution, is_local_email_domain).
- **Tags and detections**: Tags the email file outbound_email, outbound_email_exception, email_parse_incomplete, authentication_failed (compauth or dmarc = fail), anonymous_direct_send, spoofed_internal. No detection points. (Before 8617ba8e it also whitelisted the file on a brotex smtp_from/smtp_to hit or an outbound O365 email under scan_inbound_only.) Adds directives extract_urls + preview (declared text/plain) or render on parts; copies remediate from a matching message_id observable to each email_delivery; excludes MessageIDAnalyzerV2 on its own message_id and excludes itself on .headers/.combined. Appends ' - <subject>' to root description when the file has rename_analysis.
- **Notes**: Large module (rfc822.py 1846 lines). provider_headers config (EmailProviderHeaders, M365 defaults) drives first-hop IP, tenant id, compauth, direct-send, directionality headers. Builds a log_entry dict (consumed by email_logger and conversation.py) including a misspelled key 'refereneces' (rfc822.py:1729); conversation.py reads References from headers to work around it. Skips files ending in .headers. The outbound check under scan_inbound_only happens before analysis is created, so such an email gets its outbound_email tag and no EmailAnalysis. Per-part extraction errors are caught and recorded in details.extraction_errors. Delivery observables are created for every local recipient in env_rcpt_to+To+Cc+Bcc. No caps on number of parts beyond the root's per-type observable limit (add_file_observable may return None).

### lure_url_analyzer

- **Section**: `analysis_module_lure_url_analyzer`, class `LureURLAnalyzer` in `saq/modules/email/lure.py`, enabled by default.
- **ace4**: ported in `ace-mod-emailtree`. It runs last (`Module::RUNS_LAST`), as ace3's `execute_final_analysis`, once, where ace3 reruns it on each final pass; walks the email's subtree in the tree on the lease (`Module::READS_TREE`); reads the email's bodies, HTML and plain text, up to 5 MiB each, which the core sends as the tree's files (`Module::READS_TREE_FILES`), the HTML on `ace-lxml`'s BeautifulSoup tree; and reads `pdf_link_text`'s details in the tree (`Module::READS_TREE_DETAILS`) for the text under a PDF's links. It follows ace3 `b4badb2c` and `40ee8208`: a link's place in the thread (a signature block, an earlier message the email quotes), the newest message's reference to its attachment, and a PDF's link text and only link. URLs are spelt by `ace-urlfinder` and domains by `ace_sdk::nrd::registrable_domain`, tldextract's bundled snapshot. `crawl` on the primary goes through `ResultEnvelope::others`. The settings are `etc/lure_url.yaml`'s keys, in the site's overlay, with its values as defaults; ace3 reloads the file when analysts edit it. Each candidate has no `observable_uuid`, since ace4's observables have none, and the GUI draws the result as an analysis view rather than ace3's section of the alert page. `crates/ace-mod-emailtree/tests/differences.md` has the rest.
- **Pool**: parser. Scores URLs already in the tree and parses the email's HTML bodies; no network or database. The core hands it the tree and the bodies when it runs last.
- **Step**: done.
- **Does**: For a file with EmailAnalysis, waits until final analysis and then scores every http(s) URL found in the email's body parts, attachments, QR codes, PDF link annotations and unwrapped protected URLs, by where it is (a clickable link, a button, a signature block, a quoted message, an attachment the message refers to) and what its text says, picks the primary lure URL and adds the crawl directive to it.
- **Input**: file (only those with EmailAnalysis).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: config: email_analyzer; reads EmailAnalysis, ProtectedURLAnalysis (url protected unwrapping), QRCodeAnalysis, PDFLinkTextAnalysis (the text under a PDF's links), PhishkitAnalysis (skipped), and whatever analyses hang URLs off the email's parts (url_extraction, pdf annotations) by walking the tree in final analysis, no wait_for_analysis; config dependency email_analyzer.
- **Libraries**: beautifulsoup4 4.15.0 + lxml 6.1.3 (parse_document from html_js_extraction, body anchors); urlfinderlib 0.27.1 (URL normalization); tldextract 5.4.0 (default extractor; may fetch the public suffix list from publicsuffix.org over HTTPS on first use and cache it under ~/.cache/python-tldextract, falling back to its bundled snapshot; ace3 does not configure it) via saq.nrd.util.registrable_domain; idna 3.20 (saq.nrd.util normalization); PyYAML 6.0.3 (settings file); pydantic 2.14.1.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: reads: type=email.headers, type=email.combined (to skip non-parts); reads: type=document.pdf.annotation_uris (marks URLs under it as clickable PDF links).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none directly; tldextract may fetch the public suffix list on first use (unsure whether the image pre-caches it).
- **Reads outside the alert**: etc/lure_url.yaml (config_path, analyst-editable, watched with FileWatcher for live reload; a bad edit keeps the previous settings).
- **Tags and detections**: No tags or detection points. Adds DIRECTIVE_CRAWL to the primary lure URL (settings.crawl_primary). Uses existing detection points on URLs as a scoring signal.
- **Notes**: execute_analysis returns INCOMPLETE; all work is in execute_final_analysis, which always returns INCOMPLETE and sets analysis.completed=False so it reruns on every final pass (lure.py:620-666) - the engine must stop when a pass adds nothing. Bodies over 5 MiB are not parsed (MAX_BODY_BYTES). Keeps max_candidates (default 5). Inner (attached) emails are excluded and get their own LureURLAnalysis. In module_group correlation, so only alerts run it. build_lure_urls() is a GUI helper for the alert page.

### email_archiver

- **Section**: `analysis_module_email_archiver`, class `EmailArchiveAction` in `saq/modules/email/archive.py`, disabled by default.
- **ace4**: ported in `ace-mod-emailarchive`. It depends on the email module, whose result comes with the task, reads its file's tags in the tree on the lease (`Module::READS_TREE`), and hands the email's Message-ID and normalized envelope recipients to the core as the `email-archive` write (`reads.md`). The core reads the file from the bucket, gzips it and encrypts it with ACE's key, puts it in the `email_archive` pool held by its row until its week is dropped, and writes migration 0041's rows in the end's transaction, setting the result's `archive_id`; when the root's analysis completes it indexes the URLs below the email, as ace3's post-analysis does (`ace_core::email_archive::index_urls`). The archive path names the email by its hash, without ace3's data directory or hostname. Off by default and in the `email` mode, as in ace3. `crates/ace-mod-emailarchive/tests/differences.md` has the rest.
- **Pool**: lookup. Writes ACE's email archive, which in ace4 is the bucket and Postgres; the write lands with the task's end (7.2, `reads.md`). It parses nothing.
- **Step**: done.
- **Does**: For an email file with the archive directive and an EmailAnalysis carrying a message-id and envelope recipients, gzips and AES-GCM encrypts the email into the email archive, records it in the email_archive database, and in post-analysis indexes every URL under the email.
- **Input**: file (required directive archive).
- **Groups and modes**: groups none; modes email.
- **Depends on**: config: email_analyzer; reads EmailAnalysis via get_and_load_analysis (config dependency email_analyzer); post-analysis walks the tree for all F_URL under the email (recurse_tree) after every other module has run.
- **Libraries**: cryptography 50.0.2 (AES-256-GCM via saq.crypto); PyMySQL 1.2.0; python stdlib gzip; boto3/botocore only when email_archive.target is s3 (not pinned; 1.43.125 in ace3's dev container).
- **Tools**: none.
- **Writes**: OUTSIDE ALERT: $DATA_DIR/archive/email/<hostname>/<sha256[0:2]>/<sha256>.gz.e (encrypted gzip of the email; temp .gz removed); OUTSIDE ALERT: $DATA_DIR/review/rfc822/<uuid4>.rfc822 when message-id or envelope recipients are missing (archive.py:194); S3 object <sha256> in bucket email_archive.s3_bucket with metadata message_id (target s3).
- **yara_meta**: none.
- **ACE's data**: email_archive: archive (W, INSERT IGNORE; R archive_id); email_archive: archive_index (W, field message_id and url hashes); email_archive: email_history (W, message_id/recipient); email_archive: archive_server (R/W at initialize_email_archive/register, not in this module).
- **Secrets**: SAQ encryption key (encryption must be initialized; raises otherwise); S3 credentials when target is s3.
- **Network**: MySQL email_archive database; S3 endpoint when target is s3.
- **Reads outside the alert**: none.
- **Tags and detections**: None.
- **Notes**: Disabled by default and only in mode 'email'. Side effects outside ACE's alert: permanent archive file and DB rows. expiration_days is declared in config but never read anywhere in saq/ (archive.py:100). Uses lock_local on the target path; skips if file already exists (dedup by sha256). insert_date truncated to seconds because it is part of the unique key (local.py). The analysis is created only after the archive succeeds so post-analysis never indexes under a missing archive_id. Skips files tagged decrypted_email.

### encrypted_archive_analyzer

- **Section**: `analysis_module_encrypted_archive_analyzer`, class `EncryptedArchiveAnalyzer` in `saq/modules/email/archive.py`, enabled by default.
- **ace4**: ported in `ace-mod-emailarchive`. For a file whose path ends `.gz.e` (a lookup gets the file's path, `Observable::path`, not its bytes) it asks the core for the `decrypted-archive` read, which decrypts ace3's v0 or v1 layout with ACE's key and gunzips up to 64 MiB, and puts the email in the root; the result adds it with no upload. A file that doesn't open gets no result, as in ace3. ace3's leftover `.rfc822.gz` isn't written.
- **Pool**: lookup. Opens an archived email with ACE's encryption key. In ace4 that's the `decrypted-archive` read (7.2): the core decrypts, and no worker holds the key.
- **Step**: done.
- **Does**: For a file named *.gz.e (an ACE email archive file), decrypts it with the ACE encryption key, gunzips it, and adds the resulting .rfc822 email as a file observable.
- **Input**: file (name ending .gz.e).
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: none.
- **Libraries**: cryptography 50.0.2 (AES-256-GCM via saq.crypto.decrypt); python stdlib gzip.
- **Tools**: none.
- **Writes**: {file minus .gz.e}.rfc822.gz (decrypted gzip, left on disk); {file minus .gz.e}.rfc822 (added as file observable).
- **yara_meta**: type=email (on the decrypted email).
- **ACE's data**: none.
- **Secrets**: SAQ encryption key (returns early unless encryption_initialized).
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the decrypted email decrypted_email.
- **Notes**: verify_environment calls verify_program_exists('zcat'), which runs `which zcat` via Popen at startup (base_module.py:157), but zcat is never executed - decompression uses Python gzip. No size cap on the gunzip (decompression bomb risk) - archive.py:75. The intermediate .rfc822.gz is written into the alert dir and not removed.

### file_location_analysis

- **Section**: `analysis_module_file_location_analysis`, class `FileLocationAnalyzer` in `saq/modules/file_path.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`.
- **Pool**: parser. Splits a string.
- **Step**: done.
- **Does**: Splits a file_location observable ('host@path') into a hostname observable and a file_path observable.
- **Input**: file_location.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none
- **Notes**: Relies on FileLocationObservable having already parsed hostname/full_path (rejects values lacking either).

### file_path_analysis

- **Section**: `analysis_module_file_path_analysis`, class `FilePathAnalyzer` in `saq/modules/file_path.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`.
- **Pool**: parser. Regex over a string.
- **Step**: done.
- **Does**: From a file_path observable containing a path separator, adds the file name as a file_name observable and, for C:\Users\<name>\ paths, the user name as a user observable.
- **Input**: file_path.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none
- **Notes**: No analysis when the value has no '/' or '\' (file_path.py:71-73). USER_REGEX matches any drive letter, case-insensitive, at the start only.

### network_identifier

- **Section**: `analysis_module_network_identifier`, class `NetworkIdentifier` in `saq/modules/asset/network_identifier.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. iptools 0.7.0's `IpRange` is ported in `iptools.rs`. The CSV's rows are the overlay's `networks` setting, `cidr` and `name`, read once when the pool starts as ace3 reads its file; ace3's shipped file has only its header, so the default is none. A range iptools can't read stops the module from starting, as it stops ace3's.
- **Pool**: parser. CIDR matching of a value against a site file; no network or database. The CSV became overlay settings, not a 5.14 list, whose entries match values rather than ranges.
- **Step**: done.
- **Does**: Matches an ip/ipv4 observable against the CIDR ranges in a local CSV and, when it falls in any, records the network names and adds an asset observable for the same IP.
- **Input**: ip; ipv4.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
- **Libraries**: iptools 0.7.0 (IpRange).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: data/etc/local_networks.csv (csv_file; header must be Indicator,Indicator_Type, rows are CIDR,name; loaded once in __init__, no reload).
- **Tags and detections**: none; adds an asset observable (same value) when the IP is in at least one listed network
- **Notes**: Linear scan over every network per observable (network_identifier.py:94). CSV header is asserted (lines 80-81), so a bad header crashes module load. The file is read once at construction; edits need a worker restart. verify_environment checks the path exists.

### parse_url

- **Section**: `analysis_module_parse_url`, class `ParseURLAnalyzer` in `saq/modules/url/parser.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. It reads the URL with `ace-urlfinder`'s `Url`. Its decoded query parameters are only in the summary, as in ace3, whose module sets them on the analysis object rather than its details.
- **Pool**: parser. Parses an attacker's string in memory.
- **Step**: done.
- **Does**: Splits a url observable into scheme/netloc/path/query/params/fragment and adds the host as an fqdn (or ip) observable and the path as a uri_path observable.
- **Input**: url.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
- **Libraries**: urlfinderlib 0.27.1 (url.URL).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: tag ip_in_url on an added ip observable, domain_in_url on an added fqdn observable
- **Notes**: parse_url() (parser.py:97-113) treats a scheme-less value as host-first ('yahoo.com:8080/login') by retrying with a '//' prefix when the netloc is an IPv4 or a valid TLD. FQDN added only when urlfinderlib says is_netloc_valid_tld (uses its own TLD list). Query params are url-decoded into details.params. Exceptions are re-raised after a warning (line 157).

### fqdn_analyzer

- **Section**: `analysis_module_fqdn_analyzer`, class `FQDNAnalyzer` in `saq/modules/dns.py`, enabled by default.
- **ace4**: ported in `ace-mod-dns`. On hickory-proto (7.4), asking as dnspython's stub resolver does. A resolver that doesn't answer fails the task as unavailable, where ace3 records `dns_error`; `crates/ace-mod-dns/tests/differences.md` has the rest.
- **Pool**: lookup. DNS queries, the plan's hickory-dns example.
- **Step**: done.
- **Does**: Resolves an fqdn observable's A records (and for a registrable apex, its MX and a wildcard probe) and adds the first resolved address as an ip observable; every outcome (ok/nxdomain/no_answer/dns_error) produces an analysis.
- **Input**: fqdn.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
- **Libraries**: dnspython 2.9.0 (dns.resolver); tldextract 5.4.0 (registrable apex check).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: system DNS resolver (/etc/resolv.conf via dns.resolver.Resolver()); up to 3 queries per apex FQDN: A, MX, and A for ace-wildcard-probe-nonexistent.<fqdn>. tldextract may also fetch the Public Suffix List over HTTPS (publicsuffix.org) on first use if its cache is empty (no custom TLDExtract is configured anywhere in saq/), else falls back to its bundled snapshot..
- **Reads outside the alert**: tldextract PSL cache (~/.cache/python-tldextract or TLDEXTRACT_CACHE).
- **Tags and detections**: none; adds one ip observable (first sorted A record)
- **Notes**: Timeout 5s per query, lifetime 5s (dns.py:48,171-175). Only the first address becomes an observable (line 214-217); all are in details. MX and wildcard probe only when the name is its own eTLD+1 (line 177-179, 224). Probe label is constant for cacheability, but no cache_ttl is configured for this module. A CNAME chain is recorded as aliaslist.

### apex_domain_analyzer

- **Section**: `analysis_module_apex_domain_analyzer`, class `ApexDomainAnalyzer` in `saq/modules/apex_domain.py`, enabled by default. ace3 added it in `d7436a48`.
- **ace4**: ported in `ace-mod-values`. Ported when the inventory followed ace3 to `fe6da632`. The apex is `ace_sdk::domains::apex_domain_of`, on the public suffix list tldextract 5.4.0 ships, the reduction the RDAP module already used.
- **Pool**: parser. Reduces a name in memory.
- **Step**: done.
- **Does**: Adds the registrable domain (eTLD+1) of a subdomain fqdn as an fqdn observable of its own, with the subdomain's time, so an analyst can pivot to every alert with that domain. A name that is its own apex, or has no public suffix, gets no analysis.
- **Input**: fqdn.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none. `rdap_analyzer` depends on it in ace3 and skips a subdomain it gave an apex observable (`7265bb53`, `e871441c`); in ace4 RDAP computes the same apex itself (its entry).
- **Libraries**: tldextract 5.4.0 (`saq.domain_similarity.registrable_domain`, imported when the module first runs).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none in ace4. ace3's tldextract may fetch the public suffix list from publicsuffix.org when its cache is empty.
- **Reads outside the alert**: none in ace4; tldextract's cache in ace3.
- **Tags and detections**: none; the apex observable gets display_type 'Apex Domain'.
- **Notes**: Details hold `apex_domain`; the summary is `Apex Domain: <apex>`. The name is stripped, lowered and its trailing dots dropped before it is reduced (apex_domain.py:21-33).

### idna_analyzer

- **Section**: `analysis_module_idna_analyzer`, class `IDNAAnalyzer` in `saq/modules/url/idna.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. It reads the name with `ace-urlfinder`'s `Url`, whose IDNA spellings are urlfinderlib's: the idna package's IDNA 2008, then Python's IDNA 2003 codec where that refuses (`ace-pycompat`).
- **Pool**: parser. Converts a name in memory.
- **Step**: done.
- **Does**: Converts an fqdn observable between its IDNA (punycode) and Unicode forms and adds whichever differs from the original as a new fqdn observable.
- **Input**: fqdn.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
- **Libraries**: urlfinderlib 0.27.1 (url.URL netloc_idna / netloc_unicode).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none; new fqdn observables get display_type 'IDNA Domain' or 'Unicode Domain' and exclude_analysis(idna_analyzer) to stop ping-pong
- **Notes**: No analysis is created when both forms are equal or when an xn-- label is invalid punycode (UnicodeError caught, idna.py:79-84). Which IDNA codec urlfinderlib uses internally (stdlib 'idna' 2003 codec vs idna package 3.20) is unsure; a port should check IDNA2003 vs IDNA2008 differences.

### rdap_analyzer

- **Section**: `analysis_module_rdap_analyzer`, class `RdapAnalyzer` in `saq/modules/rdap.py`, enabled by default.
- **ace4**: ported in `ace-mod-rdap`. Its results are kept in the analysis cache for 7 days, ace3's `cache_ttl` (PLAN.md decision 26); a lookup that failed is marked failed and isn't kept.
- **Pool**: lookup. RDAP over HTTPS (1.x).
- **Step**: done.
- **Does**: Looks up registration data for an fqdn (reduced to its eTLD+1) or a globally routable ip via RDAP, falling back to legacy WHOIS, recording registrar, dates/ages, nameservers, emails, network CIDR/country and raw responses.
- **Input**: fqdn; ip (and subtypes, e.g. email_first_hop_ip; custom_requirement skips non-global IPs, and since `7265bb53` a subdomain fqdn that `apex_domain_analyzer` gave an apex observable, which RDAP looks up instead).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: `apex_domain_analyzer` in ace3. In ace4 none: the module computes the apex from the value as the apex module does and skips a subdomain that has one, since a dependency in ace4 waits for a result and the apex module stores none for a name that is its own apex (`ace-mod-rdap`'s docs). The two differ only for an fqdn the apex module doesn't run on.
- **Libraries**: whoisit 4.1.0 (RDAP bootstrap + domain/ip queries); python-whois 0.9.6 (whois.whois fallback); tldextract 5.4.0 (eTLD+1 reduction).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: analysis_result_cache DB: analysis_result_cache table R/W via the engine's analysis cache (cache_ttl 604800 = 7 days), not by module code.
- **Secrets**: none.
- **Network**: IANA RDAP bootstrap (data.iana.org, via whoisit.bootstrap, once per process), then the registry/RIR RDAP server for the TLD or IP (HTTPS); WHOIS fallback over TCP 43 to whois servers (python-whois NICClient socket, default command=False so no whois binary); tldextract may fetch the PSL from publicsuffix.org on first use..
- **Reads outside the alert**: tldextract PSL cache.
- **Tags and detections**: none
- **Notes**: Config version: 2 is part of the cache key (bumped when ip subtypes were looked up as domains, rdap.py:545-548). Authoritative RDAP 'not found' stops without a WHOIS attempt (line 607-609). Emails capped at 20 (line 94). Heavy imports are lazy (line 60). The module also exports lookup_domain_creation_date() used by nrd_analyzer, with a per-process memo of up to 4096 successes (line 183-268). No HTTP proxy is configured for whoisit; it uses whatever its HTTP client picks up from the environment (unsure which: requests vs httpx).

### nrd_analyzer

- **Section**: `analysis_module_nrd_analyzer`, class `NRDAnalyzer` in `saq/modules/nrd.py`, enabled by default.
- **ace4**: ported in `ace-mod-nrd`. The list is migration 0039's `nrd.domains`, one for every node, which `ace serve`'s `nrd_refresh` scheduled task rebuilds in one transaction from the overlay's `nrd.url_lists` as ace3's `nrd-refresh` does (`ace_app::nrd`, acting as `scheduler:nrd_refresh` with `nrd:refresh` alone), and the module reads through the core's `newly-registered` read, which answers only for the task's own observable. A hit is verified by RDAP through `ace_mod_rdap::CreationDates`; ace3's WHOIS fallback isn't ported. `crates/ace-mod-nrd/tests/differences.md` has the rest. Its results are kept in the analysis cache for 24 hours, ace3's `cache_ttl` (decision 26), keyed on the `newly-registered` read's answer for the name where ace3 keys on its database file's mtime and size (`ace_sdk::cache::KEYED_READS`).
- **Pool**: lookup. RDAP on a hit, and the core's `newly-registered` read of the list.
- **Step**: done.
- **Does**: Checks whether an fqdn or url's host (or a parent down to its eTLD+1) is in the local newly-registered-domains SQLite database and, on a hit, verifies the registration age via RDAP/WHOIS before tagging it suspect:nrd.
- **Input**: fqdn; url.
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: idna 3.20 (punycode normalisation); tldextract 5.4.0; whoisit 4.1.0 + python-whois 0.9.6 (via saq.modules.rdap.lookup_domain_creation_date, only on DB hits); sqlite3 (stdlib).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: local SQLite file data/external/nrd/nrd_index.db (nrd.database_path), table nrd, R (read-only URI connection, reopened when mtime changes); analysis_result_cache DB via the engine (cache_ttl 86400, extended_version = db file mtime_ns-size).
- **Secrets**: none.
- **Network**: none for misses; on a DB hit with max_registration_age_days set (default 90): IANA RDAP bootstrap, registry RDAP server, WHOIS TCP 43 fallback; tldextract PSL fetch possible on first use..
- **Reads outside the alert**: data/external/nrd/nrd_index.db (refreshed by saq/nrd/refresh.py, atomically swapped).
- **Tags and detections**: tag suspect:nrd on the observable; deliberately no detection point (an observable_modifier rule promotes it)
- **Notes**: Hits for domains registered more than max_registration_age_days ago are dropped silently (no analysis, nrd.py:196-203) because feeds include updated domains. Lookup failure fails open: the hit is kept and the analysis is marked failed with why (`Analysis.error`, `lookup_error` in its details until ace3 `41d44392`; in ace4 the result's error). Missing DB file = no hits (fresh deploy). The DB is node-local, so each ace4 node needs its own copy or a shared store.

### snort_signature_analysis_v1

- **Section**: `analysis_module_snort_signature_analysis_v1`, class `SnortSignatureAnalyzer_v1` in `saq/modules/snort.py`, enabled by default.
- **ace4**: ported in `ace-mod-snort`. Its `snort-signature` read is the first built (7.4): the core indexes the rules file in `ACE4_SNORT_RULES`. ace3's summary detail on the root isn't ported, since ace4's roots have none yet; `crates/ace-mod-snort/tests/differences.md` has the rest.
- **Pool**: lookup. A Redis read today; in ace4 the `snort-signature` read (7.2) of the rules `ace signatures build-db` indexes.
- **Step**: done.
- **Does**: For a snort_signature observable ('gid:sid:rev'), fetches the full Suricata/Snort rule text indexed in Redis by sid:rev and adds it as a summary detail on the root.
- **Input**: snort_signature.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation, suricata_ids.
- **Depends on**: none.
- **Libraries**: redis 6.4.0.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: Redis: Redis 'default' config (get_config().redis host/port/user/password), DB 1 (REDIS_DB_SNORT): GET '<sid>:<rev>' per observable. The index (keys '<sid>:<rev>' = rule line, 'suricata_rules_lastmtime', lock 'suricata_rules_lock' with 30s ex/nx) is built by 'ace signatures build-db' (saq/cli/commands/signatures.py:202-230) from data/snort/snort.rules, not by the module. A new redis.Redis connection is created per call (snort.py:110-120)..
- **Secrets**: Redis username/password (redis config).
- **Network**: Redis server.
- **Reads outside the alert**: data/snort/snort.rules (signature_path) only via the build-db CLI; the module itself does not read it (the staleness check is commented out, snort.py:84-85).
- **Tags and detections**: none; adds a root summary detail 'Suricata Signature <sid> rev <rev>'
- **Notes**: Creates an analysis even when sid/rev are missing (then default text 'unknown signature (rules not updating?)'). verify_environment is a no-op. Observable parsing: saq/observables/ids.py splits value on ':' into 3 parts.

### user_analyzer

- **Section**: `analysis_module_user_analyzer`, class `UserAnalyzer` in `saq/modules/user.py`, disabled by default.
- **ace4**: ported in `ace-mod-user`. On the ldap3 crate, with each value formatted by the server's schema as ace3's ldap3 formats it (`format.rs`). ace3 binds in plaintext on 389; ace4 uses LDAPS or StartTLS with verified certificates, and plain LDAP only with `allow_plaintext`, which logs a warning when the module starts. The bind password is the `ldap_bind_password` secret (2.24). Off unless the overlay has a section for it (`Module::ENABLED_BY_DEFAULT`). `crates/ace-mod-user/tests/differences.md` has the rest.
- **Pool**: lookup. LDAP searches with a bind password. Disabled by default.
- **Step**: done.
- **Does**: Looks up a user (by cn) or a local-domain email_address (by proxyAddresses) in LDAP/AD, stores the attributes, adds the counterpart user/email observable, fetches the manager, and tags executives.
- **Input**: email_address (local email domains only); user.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
- **Libraries**: ldap3 2.9.1.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: LDAP bind user/password (ldap.ldap_bind_user / ldap_bind_password).
- **Network**: LDAP server (ldap.ldap_server:ldap_port, SIMPLE bind, paged subtree search, RESTARTABLE strategy); up to 2 searches per observable (user + manager).
- **Reads outside the alert**: none.
- **Tags and detections**: tag executive on the observable when the user, their manager or manager's manager equals ldap.top_user; new observables get directive skip_user_analysis plus a copy of the source's directives
- **Notes**: Disabled by default. Module-global LDAP connection shared per process (saq/ldap.py:8-23). Filter values are escaped (escape_filter_chars). generate_summary indexes details['ldap'] directly. 'privileged' is always False. Deriving manager_cn uses a regex on the manager DN.

### email_address_fqdn_analyzer

- **Section**: `analysis_module_email_address_fqdn_analyzer`, class `EmailAddressFQDNAnalyzer` in `saq/modules/email/address.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. ace4 has no volatile flag for the fqdn.
- **Pool**: parser. Splits a string; no I/O.
- **Step**: done.
- **Does**: Splits the domain off an email_address observable (any subtype) and adds it as a volatile fqdn observable.
- **Input**: email_address (and subtypes via the type hierarchy).
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None; adds F_FQDN with volatile=True.
- **Notes**: get_email_domain is value.split('@',1)[1] with no normalization (saq/email.py:40).

### email_conversation_frequency_analyzer

- **Section**: `analysis_module_email_conversation_frequency_analyzer`, class `EmailConversationFrequencyAnalyzer` in `saq/modules/email/fa.py`, enabled by default.
- **ace4**: ported in `ace-mod-brocess`. Through the `smtp-counts` read (7.4), of migration 0037's `brocess.smtplog`, which stays empty until `email_logger` is ported. A core that can't answer fails the task as unavailable, where ace3 goes into a cooldown; `crates/ace-mod-brocess/tests/differences.md` has the rest.
- **Pool**: lookup. Reads brocess's smtplog, which becomes the `smtp-counts` read (7.2).
- **Step**: done.
- **Does**: For an email_conversation observable (sender|recipient), counts in brocess how often the sender has emailed us and how often it emailed this recipient, tagging new_sender or frequent_conversation.
- **Input**: email_conversation.
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: none.
- **Libraries**: PyMySQL 1.2.0.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: brocess: smtplog (R, SUM(numconnections) by source, and by source+destination).
- **Secrets**: brocess DB credentials.
- **Network**: MySQL brocess database.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the conversation new_sender (source count 0) or frequent_conversation (count >= conversation_count_threshold, default 5). No detections.
- **Notes**: Any query exception puts the module in cooldown for cooldown_period (60s) and returns without analysis (fa.py:102-105); cooldown is per-process module state. smtplog is written by email_logger, so results depend on email_logger history.

### email_conversation_attachment_analyzer

- **Section**: `analysis_module_email_conversation_attachment_analyzer`, class `EmailConversationAttachmentAnalyzer` in `saq/modules/email/fa.py`, enabled by default.
- **ace4**: ported in `ace-mod-brocess`. It reads the tree on the lease (`Module::READS_TREE`) and delays while olevba or officeparser3 has a task on the document, or the frequency module on a conversation, as ace3 waits for them. ace3 looks for `macro` anywhere below the document, but when its own modules have run and nothing they found has been analyzed; ace4 looks at the document, its results and what they added, which is what ace3 sees then, whatever order ace4's tasks run in. `crates/ace-mod-brocess/tests/differences.md` has the rest.
- **Pool**: parser. Reads the tree only (tags and other modules' results), on the lease.
- **Step**: done.
- **Does**: For an office-document file in a root that has EmailAnalysis, if anything under it is tagged macro and some email_conversation is tagged new_sender, adds the sandbox directive and a detection point.
- **Input**: file.
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: config: file_type, olevba_v1_2, officeparser3; wait_for_analysis(file, FileTypeAnalysis); wait_for_analysis(each email_conversation, EmailConversationFrequencyAnalysis); reads the 'macro' tag set by olevba_v1_2/officeparser3 (config dependencies) anywhere in the file's subtree; checks root has any EmailAnalysis.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Detection point 'An email from a new sender contained a macro.' (signature EMAIL_MACRO_NEW_SENDER); adds DIRECTIVE_SANDBOX to the file.
- **Notes**: Waits on the frequency analyzer's result, so it inherits that module's brocess lookups indirectly. Analysis object is empty; it is created only when the detection fires.

### email_conversation_link_analyzer

- **Section**: `analysis_module_email_conversation_link_analyzer`, class `EmailConversationLinkAnalyzer` in `saq/modules/email/fa.py`, enabled by default.
- **ace4**: ported in `ace-mod-brocess`. Its patterns are its settings' `url_pattern_*` keys, as ace3's, Python `re` on fancy-regex (`ace_mod_urls::pyre`). ace3's default config has none, so it does nothing; ace4's module is off until a site gives it a section (`Module::ENABLED_BY_DEFAULT`), so it isn't queued for every URL to do nothing. It finds the email as ace3's `search_down` does, in the tree on the lease (`Module::READS_TREE`), and delays while the email module has a task on a file on the way or the frequency module on one of the email's conversations. `crates/ace-mod-brocess/tests/differences.md` has the rest.
- **Pool**: parser. Regex and the tree only, on the lease.
- **Step**: done.
- **Does**: For a URL matching one of the configured url_pattern_* regexes, finds the email it came from and adds a detection point if any of that email's conversations is tagged new_sender.
- **Input**: url.
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: wait_for_analysis(file, EmailAnalysis) while searching down from the URL; wait_for_analysis(email_conversation, EmailConversationFrequencyAnalysis).
- **Libraries**: python stdlib re.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Detection point 'Suspect URL sent from new sender.' on the URL (signature EMAIL_SUSPECT_URL_NEW_SENDER).
- **Notes**: Patterns come from extra config keys url_pattern_* (model_config extra='allow'); etc/saq.default.yaml defines none, so by default nothing matches and the module is a no-op. Patterns are compiled with Python re (fa.py:216); a Rust port changes regex dialect.

### email_thread_analyzer

- **Section**: `analysis_module_email_thread_analyzer`, class `EmailThreadAnalyzer` in `saq/modules/email/thread.py`, enabled by default.
- **ace4**: ported in `ace-mod-brocess`. Through the `email-thread` read (7.4), with the GUI view `email_thread.html`, which also draws the findings ace3 adds as a summary detail, since ace4's results have none. It runs last, and delays while the read says a module that records threads has a task in the root that hasn't finished, so it sees an alert's own email, which ace3 records before its correlation pass. The pairs never reported are a setting rather than ace3's watched `etc/email_thread_analysis.yaml`, and a core that can't answer fails the task as unavailable where ace3 cools down; `crates/ace-mod-brocess/tests/differences.md` has the rest.
- **Pool**: lookup. Reads brocess's thread store through the `email-thread` read (7.2); the similarity work is cheap and runs in the same task.
- **Step**: done.
- **Does**: For a message_id, loads the recorded conversation from the brocess thread store and builds a display-only timeline with look-a-like domain pairs, inline markdown findings and missing-parent message ids.
- **Input**: message_id.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: data written by email_logger with thread_recording_enabled (no in-engine wait).
- **Libraries**: PyMySQL 1.2.0; jellyfish 1.3.0 (Damerau-Levenshtein, Jaro-Winkler); confusable-homoglyphs 3.3.1; idna 3.20; tldextract 5.4.0 (default extractor; may fetch the public suffix list from publicsuffix.org over HTTPS on first use and cache it under ~/.cache/python-tldextract, falling back to its bundled snapshot; ace3 does not configure it); PyYAML 6.0.3 (settings); pydantic 2.14.1.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: brocess: email_thread_message (R: anchor by message_id_hash, messages by thread_id_hash, same-subject threads by normalized_subject_hash); brocess: email_thread_domain (R: participants by thread_id_hash, subject-linked domains).
- **Secrets**: brocess DB credentials.
- **Network**: MySQL brocess database; tldextract may fetch the public suffix list on first use.
- **Reads outside the alert**: etc/email_thread_analysis.yaml (config_path, analyst-editable ignored_domain_pairs, watched for live reload).
- **Tags and detections**: None by design (thread.py:9-10); adds an Analysis summary detail (markdown) when look-a-likes exist. No observables.
- **Notes**: Caps max_messages 50 and max_threads 50 (fetches max_messages+1 to detect truncation; never drops the anchor). Any query exception -> cooldown 60s (thread.py:286-289). Up to 4-5 brocess queries per message id. Has a custom presenter template analysis/email_thread.html. In correlation group only.

### url_email_pivot_analyzer

- **Section**: `analysis_module_url_email_pivot_analyzer`, class `URLEmailPivotAnalyzer` in `saq/modules/email/correlation.py`, enabled by default.
- **ace4**: ported in `ace-mod-emailarchive`. It counts on the `archived-url-count` read, over ace4's one archive.
- **Pool**: lookup. Reads the email archive's URL index through the `archived-url-count` read (7.2).
- **Step**: done.
- **Does**: For a URL, counts how many archived emails contain it by looking up its SHA-256 in archive_index across every configured email archive database.
- **Input**: url.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: data indexed by email_archiver post-analysis.
- **Libraries**: PyMySQL 1.2.0.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: email_archive (primary plus every database_email_archive_* section): archive_index (R, COUNT(DISTINCT archive_id) WHERE field='url' AND hash=UNHEX(SHA2(url,256))).
- **Secrets**: email_archive DB credentials (each section).
- **Network**: MySQL email_archive database(s).
- **Reads outside the alert**: none.
- **Tags and detections**: None.
- **Notes**: Only records a count: the emails list is never populated (correlation.py:73, 105-109 commented out) and the result_limit (35) branch does the same thing as the other branch (correlation.py:98-104). No exception handling: a DB error fails the module.

### email_logger

- **Section**: `analysis_module_email_logger`, class `EmailLoggingAnalyzer` in `saq/modules/email/logging.py`, enabled by default.
- **ace4**: ported in `ace-mod-brocess`. A module on the `original_email` file that runs last and depends on the email module, whose result comes with the task, with the URLs below it (`Module::REQUIRED_DIRECTIVES`, `RUNS_LAST`, `DEPENDS_ON`, `READS_BELOW`). Its `smtp-log` and `email-thread` writes land with its task's end (`Module::WRITES`, 7.2), which stores no result, as ace3 creates no analysis; it reads `email-thread-domains` for the look-alike telemetry, and sends fluent-bit's forward protocol itself. No URLs come from `url_extraction` and `archive_path` is null until 7.5 ports those modules; `crates/ace-mod-brocess/tests/differences.md` has the rest.
- **Pool**: lookup. Writes brocess (through the internal API) and sends records to fluent-bit; parses nothing new.
- **Step**: done.
- **Does**: In post-analysis, for each file with the original_email directive and an EmailAnalysis, exports the email's log entry (plus every extracted URL and archive path) to brocess smtplog and fluent-bit, records the message in the brocess thread store, and emits look-a-like domain telemetry.
- **Input**: none (valid_observable_types None; works in execute_post_analysis over files with directive original_email).
- **Groups and modes**: groups none; modes email.
- **Depends on**: reads EmailAnalysis.log_entry, EmailArchiveResults.archive_path and URLExtractionAnalysis details (load_details of the full url list) in post-analysis.
- **Libraries**: fluent-logger 0.11.1 (fluent.sender.FluentSender; msgpack is its transitive dependency, version not pinned); PyMySQL 1.2.0; jellyfish 1.3.0; confusable-homoglyphs 3.3.1; idna 3.20; tldextract 5.4.0 (default extractor; may fetch the public suffix list from publicsuffix.org over HTTPS on first use and cache it under ~/.cache/python-tldextract, falling back to its bundled snapshot; ace3 does not configure it).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: brocess: smtplog (W, INSERT ... ON DUPLICATE KEY UPDATE numconnections+1 per envelope recipient); brocess: email_thread_message (W record_thread; R COUNT by thread for telemetry); brocess: email_thread_domain (W record_thread; R established domains by thread or same-subject).
- **Secrets**: brocess DB credentials.
- **Network**: fluent-bit forward protocol TCP to fluent_bit_hostname:fluent_bit_port (default fluent-bit:24224), tags phishfinder-main/-urls/-headers/-lookalike; MySQL brocess; tldextract PSL fetch possible.
- **Reads outside the alert**: none.
- **Tags and detections**: None.
- **Notes**: Side effects outside ACE: brocess smtplog counts (feed email_conversation_frequency_analyzer), thread store rows (feed email_thread_analyzer), and fluent-bit/Splunk events; reprocessing an email increments smtplog again (no dedup, logging.py:340-342) while thread rows are idempotent. Telemetry is computed against prior messages BEFORE record_thread (ordering matters). FluentSender objects are created once in __init__ per module instance. Only in mode 'email'. Each exporter's exceptions are logged and swallowed.

### file_hash_analyzer

- **Section**: `analysis_module_file_hash_analyzer`, class `FileHashAnalyzer` in `saq/modules/file_analysis/hash.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. ace3's `ignore_pattern_*` and `ignore_mime_type_*` keys are two maps; a path pattern is matched on the alert path under a directory, as ace3's node path ends with it, so the two patterns that don't start with `*` never match, as in ace3. The misspelled `ignore_pattenr_*` keys, which ace3 never reads, are gone.
- **Pool**: parser. Hashing in the task's process.
- **Step**: done.
- **Does**: Computes md5/sha1/sha256 of a file and adds md5 and sha256 observables linked to it, unless the file path or its mime type matches a configured ignore pattern.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; FileTypeAnalysis (reads mime_type via get_and_load_analysis; returns without analysis if absent; config dependency file_type).
- **Libraries**: hashlib stdlib.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None; adds md5 and sha256 observables with R_IS_HASH_OF relationships and links.
- **Notes**: Config uses extra='allow' so any ignore_pattern_* key is an fnmatch on the full local path and any ignore_mime_type_* key an fnmatch on the mime type (hash.py:104-116); note the misspelled keys ignore_pattenr_eml / ignore_pattenr_eml_extra in the default config are NOT matched (they don't start with ignore_pattern_). Skips empty files. Hashing is done by FileObservable.compute_hashes (observables/file.py:208), which caches on the observable.

### ssdeep

- **Section**: `analysis_module_ssdeep`, class `SsdeepAnalyzer` in `saq/modules/file_analysis/ssdeep.py`, disabled by default.
- **ace4**: ported in `ace-mod-files`. The `fuzzyhash` crate's hash, which is ssdeep's on every file measured, with ssdeep 2.14.1's comparison (`ace_mod_files::ssdeep::compare`), which gives ssdeep's `-m` scores on all 420 files of `docs/measurements/ssdeep.md`, where fuzzyhash's own comparison didn't. The list of known hashes is read when the module is built, from its `ssdeep_hashes` setting.
- **Pool**: parser. fuzzyhash in the task's process, no tool. Disabled by default.
- **Step**: done (7.5 batch 10).
- **Does**: Runs `ssdeep -m` to match a file (1 KB to maximum_size) against a list of known fuzzy hashes and tags/sandboxes it when a match scores at or above the threshold.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: ssdeep 2.14.1 via run_tool (plain subprocess.run, unsandboxed): `ssdeep -m <ssdeep_hashes> <file>`.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/ssdeep_hashes (config ssdeep_hashes, relative to SAQ_HOME).
- **Tags and detections**: Tags the file 'ssdeep' and adds DIRECTIVE_SANDBOX on a match >= ssdeep_match_threshold (90). No detection point.
- **Notes**: Disabled by default (enabled: false). Skips files < 1024 bytes and > maximum_size (2048000). Parses output with regex at ssdeep.py:115.

### archive

- **Section**: `analysis_module_archive`, class `ArchiveAnalyzer` in `saq/modules/file_analysis/archive.py`, enabled by default.
- **ace4**: ported in `ace-mod-archive`. It waits for file_type, as ace3's config has it, since 7.5 batch 5, whose `xml_plain_text_analyzer` reads the tags file_type puts on the archive. Its packet capture test is its declaration, from the file's type (*What a module takes*).
- **Pool**: sandbox. zip, sevenz-rust2 and unrar in the task's process (1.29); ACE archives through unace in the sandbox runner, on a copy staged in the tool's working directory as ace3 stages it (7.5 batch 10).
- **Step**: done.
- **Does**: Lists and extracts archive files (rar, jar, xlsx-style zip, ACE, MSI, and anything else 7z opens, password 'infected') into {file}.extracted/ and adds each member as a file observable, flagging single-file archives holding executables, scripts, lnk, jnlp or OneNote files.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; FileTypeAnalysis (mime_type, file_type, is_jar_file; returns if absent; config dependency file_type).
- **Libraries**: zipfile stdlib (jar member count); bin/custom_zipfile.py (vendored zipfile, used by bin/unjar).
- **Tools**: 7z (7zip 25.01, with 7zip-rar 25.00) via run_sandboxed_tool: `7z -y -pinfected l` and `7z -y -pinfected -o<dir> x` (and `7z -y -o<dir> x` for MSI); unrar 7.1.8 via run_sandboxed_tool: `unrar la` and `unrar e -y -o+ -idq -kb`; unzip via run_sandboxed_tool: `unzip -l -P infected` and `unzip -qq ... -x xl/activeX/* ... -d <dir>`; unace-nonfree 2.5 via run_sandboxed_tool on a copy in a temp staging dir: `unace l` and `unace x -y -o`; bin/unjar (python3 script using custom_zipfile.extractall) via run_sandboxed_tool for jar files; file via Popen `file -b -L` (unsandboxed, no timeout) in is_msi_file, called up to twice.
- **Threads and children**: 7z runs one thread per core (base_module.py:475 comment). bin/unjar starts a Python interpreter.
- **Writes**: {file}.extracted/<member path> (each member added as a volatile file observable); <temp_dir>/unace-*/<archive and volumes> (temporary copies for unace, removed).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none (uses the hard-coded archive password 'infected').
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: For a one-member archive: tag single_file_zip on the analysis and DIRECTIVE_SANDBOX on the member; tags exe_in_zip/script_in_zip/lnk_in_zip/jnlp_in_zip/one_in_zip and a detection point (signature ARCHIVE_SINGLE_DANGEROUS_FILE) on the member by extension. Members of office documents get redirection to the archive; .xps/.rels/.xml members get DIRECTIVE_EXTRACT_URLS.
- **Notes**: Skips files whose path contains 'email.rfc822', pcap files, excluded mime types (default application/x-shockwave-flash, application/x-mach-binary) and OLE files that are not MSI. max_file_count 6 (not applied to office documents), max_jar_file_count 30; extra members beyond the limit are DELETED from disk after extraction (archive.py:591-594), ordered so lnk/iso/exe/script/office members are kept first (order_archive_file_list). A listing cut by tool_sandbox.max_output_bytes treats the count as over the limit (archive.py:476-478). Multi-volume archives: sibling volumes are made readable (archive_volumes). java_class_decompile_limit is configured but never used (archive.py:200,223). timeout 5 s per tool. Normalises extracted permissions (0o775/0o664, skipping symlinks). verify_environment checks 7z, unrar, unace, unzip and java.

### java_class_decompiler

- **Section**: `analysis_module_java_class_decompiler`, class `JavaClassDecompilerAnalysisModule` in `saq/modules/file_analysis/java.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. CFR 0.151 on OpenJDK 21.0.13 in the sandbox runner, as the image's `cfr` tool: `java` with ace3's JVM options and CFR's jar as fixed arguments (`ToolSpec::args`), reading the JDK's directory and `/etc/java-21-openjdk`, where its configuration links, as ace3's `jvm_conf_dirs` makes readable. A JVM that can't start (`JVM_STARTUP_ERRORS`) fails the task as the node's fault, where ace3 logs it and records an empty analysis. A run the runner stops, a run that exits non-zero and a file CFR can't decompile mark the result failed, as java.py raises `AnalysisError` for each: `cfr did not finish` and here why the runner stopped it, `cfr exited with status <n>: <its last line>`, and `cfr could not decompile the class file`. Its `CAFEBABE` test is its declaration, from the file's type (*What a module takes*).
- **Pool**: sandbox. Runs CFR on a JVM in the sandbox runner; no Rust decompiler. The JVM is in the image by decision 18 (*External tools*).
- **Step**: done (7.5 batch 11).
- **Does**: Decompiles a Java .class file (CAFEBABE magic) with CFR and adds the Java source as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: java (default-jre, OpenJDK 21) running /usr/local/bin/cfr.jar (cfr 0.151) via run_sandboxed_tool: `java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar cfr.jar <class>`.
- **Threads and children**: The JVM started 29 threads on the sample, 13 with one CPU, and no process (strace, 7.3).
- **Writes**: {file}-{N}-decompiled.java (next to the class file, N makes it unique).
- **yara_meta**: type=script.java.decompiled.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: the JVM conf directory (/etc/java-<ver>-openjdk via jvm_conf_dirs) made readable in the sandbox.
- **Tags and detections**: Tags the decompiled file 'decompiled'. No detections.
- **Notes**: timeout 30 s. CFR's leading /* ... */ banner comments are stripped in Python (strip_banner). JVM_STARTUP_ERRORS make a JVM that cannot start under the sandbox's memory limit report as a node failure (java.py:23). Non-zero exit or empty output means no file.

### olevba_v1_2

- **Section**: `analysis_module_olevba_v1_2`, class `OLEVBA_Analyzer_v1_2` in `saq/modules/file_analysis/olevba.py`, enabled by default.
- **ace4**: ported in `ace-mod-oletools`.
- **Pool**: parser. Ports of olevba and olefile in the task's process (4.10).
- **Step**: done.
- **Does**: Parses an Office/OLE/zip file (not RTF, not .msi, <=4MB, not html or text/plain per file_type) in-process with oletools VBA_Parser, writes each extracted VBA macro to a .bas file and tags the document when olevba keyword counts meet the configured thresholds.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; reads FileTypeAnalysis via get_and_load_analysis (mime_type) and returns without analysis if absent (config dependency file_type).
- **Libraries**: oletools 0.60.2 (olevba VBA_Parser, filter_vba); olefile 0.47 (via oletools); XLMMacroDeobfuscator git master (loaded by oletools.olevba for XLM detection, per comment olevba.py:162).
- **Tools**: none.
- **Writes**: {file}.olevba/macro_{N}.bas (one per non-empty macro); {file}.olevba/macros.bas when merge_macros.
- **yara_meta**: type=script.macro.vba (on each extracted macro file).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: macro tag + sandbox directive on each macro file (redirection to source, excluded from olevba itself); 'olevba' tag + sandbox directive on the document when all threshold_* met; 'olevba_failed' + sandbox on exception if office extension. No detection points.
- **Notes**: Config 'timeout' is unused: no process and no timeout around VBA_Parser (olevba.py:86, 169). deobfuscate=False because True hung in 0.55.1 (olevba.py:179). Threshold bug: keyword_summary is keyed by _type.lower() but membership is tested with the original-case _type (olevba.py:230-231), so a mixed-case type like 'AutoExec' is reset to 0 on every hit and each count ends at 1. threshold_* fields are dynamic (extra='allow'); every threshold must be met. Macro files added volatile=True.

### officeparser3

- **Section**: `analysis_module_officeparser3`, class `OfficeParserAnalyzer3` in `saq/modules/file_analysis/officeparser3.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. It is a port of officeparser3 at `af70dd43` that runs in the task, with its output directory in memory, rather than one onto `ace-mod-oletools`' olefile port, which this entry named: officeparser3 reads the compound file itself, and what it writes for a damaged one, where it raises, exits or loops for ever, decides the manifest; olefile reads such files differently. A FAT that goes in a circle makes officeparser3's checks loop until ace3's 90 seconds; the port knows the loop when it comes back to a sector and ends as ace3 does, `officeparser_failed` and `sandbox` and an empty manifest. The port is fast where officeparser3 is quadratic, so a file only slow in ace3 finishes here; it stops as if killed past 256 MiB written and raises `MemoryError` past 64 Mi FAT entries (`docs/measurements/office-containers.md`).
- **Pool**: parser. Runs officeparser3, a Python CLI, unsandboxed today; a port of it runs in the task's process (batch 5), so no process is needed.
- **Step**: done.
- **Does**: Runs the officeparser3 CLI on an OLE compound document (magic D0CF11E0, not .msi or 'windows installer') to extract streams, OLE streams, macros and unknown sectors, then adds every non-empty file named in its manifest.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; reads FileTypeAnalysis (file_type string for 'windows installer'); returns if absent.
- **Libraries**: none.
- **Tools**: officeparser3 (unixfreak0037/officeparser3, pip-installed from git master; config officeparser_path /venv/bin/officeparser3) via subprocess.Popen directly, NOT sandboxed, timeout config 90s.
- **Threads and children**: a Python interpreter process; no children known
- **Writes**: {file}.officeparser/<every file officeparser writes, incl. manifest, stream_N_N.dat, macros>; {file}.officeparser/macros.bas when merge_macros.
- **yara_meta**: type=script.macro (on extracted .bas/.frm/.cls files).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: 'officeparser_failed' tag + sandbox directive on timeout; extracted files get R_EXTRACTED_FROM, extract_urls directive, redirection to source; macro files get 'macro' tag + sandbox directive. Empty macros (only Attribute VB_ lines) skipped.
- **Notes**: Runs outside the Landlock sandbox via Popen (officeparser3.py:140-161), with p.kill() + communicate() on timeout (officeparser3.py:165-173). Output still processed after timeout if a manifest exists. Extracted files volatile=True. extracted_ole_analyzer keys off OfficeParserAnalysis3 outputs.

### xlmdeobfuscator

- **Section**: `analysis_module_xlmdeobfuscator`, class `XLMMacroDeobfuscatorAnalyzer` in `saq/modules/file_analysis/xlm.py`, enabled by default.
- **ace4**: ported in `ace-mod-xlm`.
- **Pool**: parser. A port of XLMMacroDeobfuscator in the task's process (4.12).
- **Step**: done.
- **Does**: In final analysis, runs XLMMacroDeobfuscator twice (emulate, then -x extract cells) on a file (<=10MB) that matches etc/xlmdeobfuscator.yar's xlm4-tagged rules or whose subtree has a yara_scanner_v3_4 match on a configured rule name, keeps its output and adds URLs found in cell parameters.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: yara_scanner_v3_4; execute_analysis returns INCOMPLETE; work happens in execute_final_analysis so extracted files have been yara-scanned; recurse_tree over the file's subtree reading YaraScanResults_v3_4.scan_results rule names (config dependency yara_scanner_v3_4).
- **Libraries**: yara-python 4.5.4 (compiles etc/xlmdeobfuscator.yar at module init).
- **Tools**: xlmdeobfuscator CLI (DissectMalware/XLMMacroDeobfuscator master, with xlrd2 and pyxlsb2 master) resolved from PATH via subprocess.Popen, NOT sandboxed: `xlmdeobfuscator -f <file>` and `xlmdeobfuscator -x -f <file>`, timeout config 30s each.
- **Threads and children**: a Python interpreter per run; no children known
- **Writes**: {file}.xlmdeobfuscator/xlmdeobfuscator.stdout; {file}.xlmdeobfuscator/xlmdeobfuscatorextractcells.stdout; {file}.xlmdeobfuscator/<name>.stderr (not added as observables).
- **yara_meta**: type=script.macro.xlm (on both stdout files).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/xlmdeobfuscator.yar (15 rules).
- **Tags and detections**: from the -x run: 'xlm4' tag if CELL: lines else 'xlm4:no_cells', plus 'xlm4:error'; '<tag>_failed' (xlmdeobfuscator_failed / xlmdeobfuscatorextractcells_failed) on timeout; detection point XLM_MACRO_URL per URL in a CELL's parameters; URL observables get crawl directive; stdout files get extract_urls + crawl_extracted_urls directives.
- **Notes**: Encrypted workbooks detected by output text ('Failed to decrypt the file') and abandon analysis (xlm.py:209). Banner cut at '\nFile:'. Unsandboxed Popen with kill on timeout (xlm.py:189-198). Output files volatile=True.

### mhtml

- **Section**: `analysis_module_mhtml`, class `MHTMLAnalysisModule` in `saq/modules/file_analysis/html.py`, enabled by default.
- **ace4**: ported in `ace-mod-html`. It parses with `ace-mod-oletools`' port of Python's feed parser with the stock `headerRE`, rather than mail-parser, which this entry named: the port already gives Python's parts, its quirks and the depth where it raises `RecursionError` (past 974 nested multiparts, as in ace3). It writes at most 500 parts, as ace3's root takes at most 500 file observables (`docs/measurements/html.md`). It waits for `file_type`, which ace3's doesn't: ace3's order of a pass's modules comes from a set of names and Python's hash seed, so whether the parts copy file_type's `yara_meta` types differs between ace3 processes, and ace4's would differ with the pool's order of tasks. A page Blink saves starts `From: <Saved by Blink>`, so file_type calls it an email and the email module writes its parts too, with the same bytes as `mhtml`'s. ace3 analyzes each path; ace4 analyzes the bytes once, under the path the core's rule chooses, the first in byte order of those nearest the root, here `mhtml`'s (PLAN.md decision 15), so the tree is the same on every run. The sample `ace4/web/page.mht` is Blink's, as the dumps' is.
- **Pool**: parser. MIME parsing of an attacker's file.
- **Step**: done.
- **Does**: Parses a .mhtml/.mht file (by extension only) as MIME with the stdlib email parser and writes every non-multipart part out as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none in ace3; ace4's waits for file_type (see ace4).
- **Libraries**: none.
- **Tools**: none.
- **Writes**: {file}.extracted/file_{n} (n counts every non-multipart part).
- **yara_meta**: type=document.mhtml.part.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: No tags or detections. Extracted parts are volatile and get the source's directives copied (copy_directives_to). No extracted_from relationship is added.
- **Notes**: Skips leading lines until one matches ^[A-Za-z0-9-_]+: (html.py:85). No size cap and no part-count cap; the whole file is fed to BytesFeedParser. Part names are not preserved (TODO in code, html.py:119). Calls get_payload(decode=True) twice per part.

### pcodedmp

- **Section**: `analysis_module_pcodedmp`, class `PCodeAnalyzer` in `saq/modules/file_analysis/vbs.py`, enabled by default.
- **ace4**: ported in `ace-mod-xlm`.
- **Pool**: parser. A port of pcodedmp in the task's process (4.12).
- **Step**: done.
- **Does**: Runs pcodedmp through bin/pcodedmp_wrapper on an Office file (extension or file_type) to disassemble VBA p-code and adds the indented module-stream lines as a .pcode.bas file.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; is_office_file() reads FileTypeAnalysis (config dependency file_type).
- **Libraries**: none.
- **Tools**: bin/pcodedmp_wrapper (bash) via subprocess.Popen, NOT sandboxed: `timeout --foreground --signal=KILL 30 /venv/bin/pcodedmp <file> | sed -ne '/^Module streams:/,$ p' | egrep '^[[:space:]]'`; pcodedmp 1.2.6 (pip, uses oletools/olefile).
- **Threads and children**: bash spawns timeout, pcodedmp (Python), sed and egrep as a pipeline in the worker's process group
- **Writes**: {file}.pcode.bas (added as observable); {file}.pcode.err (kept if non-empty, not added).
- **yara_meta**: type=script.vbscript (on {file}.pcode.bas).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none; output file redirected to the source file.
- **Notes**: Timeout hard-coded PCODEDMP_TIMEOUT=30 + 5s wait margin (vbs.py:19-23), no config. Exit 137/SIGKILL deletes partial output (vbs.py:269-274). Output volatile=True.

### office_xml_rel

- **Section**: `analysis_module_office_xml_rel`, class `OfficeXMLRelationshipExternalURLAnalyzer` in `saq/modules/file_analysis/msoffice.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. It parses with `ace_lxml::target`, lxml's target parser over the vendored libxml2, which reads a gzip file as lxml's does and refuses external entities as lxml 6's `resolve_entities='internal'` does; it matches lxml on 472 inputs. It adds at most 500 URLs, ace3's root limit.
- **Pool**: parser. XML parsing of an extracted part.
- **Step**: done.
- **Does**: Parses a file named document.xml.rels with lxml and adds the Target of every Relationship whose Type ends /oleObject and TargetMode is External as a URL.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: lxml 6.1.3 (etree.XMLParser target parser).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: detection point OFFICE_EXTERNAL_OLEOBJECT per external oleObject (even when the target is not a valid URL); URL observables get force_download directive.
- **Notes**: Matches on exact basename 'document.xml.rels' only (msoffice.py:104). Parse errors are logged and whatever was collected is still used.

### msoffice_encryption_analyzer

- **Section**: `analysis_module_msoffice_encryption_analyzer`, class `MSOfficeEncryptionAnalyzer` in `saq/modules/email/encryption/msoffice.py`, enabled by default.
- **ace4**: ported in `ace-mod-msoffice`.
- **Pool**: parser. Tries the wordlist in the task's process instead of office2john and John (4.11).
- **Step**: done.
- **Does**: Detects an encrypted Office file with msoffcrypto, extracts its hash with office2john.py, cracks it with John the Ripper using fixed defaults plus words from the carrying email, and adds the decrypted document.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body file (no wait_for_analysis).
- **Libraries**: msoffcrypto-tool 6.0.0 (is_encrypted, load_key, decrypt in-process); html2text 2025.4.15 (email body to text, saq/cracking.py).
- **Tools**: bin/office2john.py (vendored, bundles an old olefile 0.42) via run_sandboxed_tool with the venv python3 -I (sandbox_python()); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`.
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this)
- **Writes**: {file}.hash; {file}.wordlist; {file}.hash.pot; {file}.decrypted (added as observable).
- **yara_meta**: type=document.office (on the decrypted file).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: bin/office2john.py; /opt/tools/john-1.9.0-jumbo-1/run (john_bin_path).
- **Tags and detections**: 'encrypted_msoffice' tag on the source (also when msoffcrypto says 'Unsupported encryption method'); decrypted file tagged 'decrypted_msoffice' with detection point EMAIL_ENCRYPTED_DECRYPTED.
- **Notes**: Always tries 'VelvetSweatshop' and '/01Hannes Ruescher/01' first (msoffice.py:114). wordlist harvested from the carrying email (saq/cracking.py wordlist_from_email, since 1998ca56 and ea898311): search_down() to the nearest EmailAnalysis with .email, then every body part (EmailAnalysis.body_parts), an HTML part through html2text, each stripped and cut to byte_limit and kept once, joined by a blank line; then every whitespace-separated word, as written and without its punctuation, then every substring of each word, shortest first, of length range_low..range_high, until list_limit. A password not found is no error since 1998ca56: the summary says "password not available". Decryption runs in-process on the attacker file after a password is found (msoffice.py:137-141). crack_password finds the line by the attachment's basename and takes field 2 (cracking.py:126-127).

### xml_binary_analyzer

- **Section**: `analysis_module_xml_binary_analyzer`, class `XMLBinaryDataAnalyzer` in `saq/modules/file_analysis/xml.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. Part names are cleaned and numbered as ace3's `create_output_file` does, a task seeing only its own input and outputs. It writes at most 499 files, as ace3's root holds 500 with the file itself. Its `<?xml` test is its declaration, from the file's type; the `Word.Document` test stays in the module (*What a module takes*).
- **Pool**: parser. XML and base64 of an attacker's file.
- **Step**: done.
- **Does**: For an XML file whose first 1KB has '<?xml' and 'Word.Document' (Word 2003 flat XML package), base64-decodes every pkg:part's pkg:binaryData into its own file.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: lxml 6.1.3 (target parser).
- **Tools**: none.
- **Writes**: {file_path}.xml/<clean_file_name(part name)> via root.create_output_file.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none; extracted files added volatile=True.
- **Notes**: Part names are cleaned with clean_file_name before joining (xml.py:154). No size cap on the input or decoded parts.

### xml_plain_text_analyzer

- **Section**: `analysis_module_xml_plain_text_analyzer`, class `XMLPlainTextAnalyzer` in `saq/modules/file_analysis/xml.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. It reads the tags of the file it was extracted from on the lease (`Module::READS_RELATED_TAGS`). The archive module, which extracts Office parts, waits for file_type as ace3's config has it, so file_type has tagged that file by then, as in ace3, which runs this a pass later. Its `<?xml` test is its declaration, from the file's type (*What a module takes*).
- **Pool**: parser. XML text extraction.
- **Step**: done.
- **Does**: For an XML file (<=131072 bytes) extracted from a document tagged microsoft_office, writes the text content and any attribute whose name contains 'instr' (e.g. field instructions) to a .noxml file.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: needs an R_EXTRACTED_FROM relationship to a source that has the 'microsoft_office' tag (set by file_type, file_type.py:288).
- **Libraries**: lxml 6.1.3 (target parser).
- **Tools**: none.
- **Writes**: {file}.noxml (deleted and rewritten each run).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none.
- **Notes**: Reopens the output file in append mode on every start/end tag (xml.py:26, 30), hence the size cap. Skips names ending .noxml. Output volatile=True.

### extracted_ole_analyzer

- **Section**: `analysis_module_extracted_ole_analyzer`, class `ExtractedOLEAnalyzer` in `saq/modules/file_analysis/ole.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. Its declaration reads on the lease which modules' results added its file (`takes::Condition::AddedBy`, in the lease's gate) and it runs once the rest of the root has finished, so officeparser3's result has landed even where another module added the same bytes first. `node --check` and grep are file_type's port of them.
- **Pool**: parser. String checks, and `node --check` as a JavaScript syntax test, unsandboxed today, which a Rust JavaScript parser replaces (the same check as file_type's).
- **Step**: done.
- **Does**: For a file that is an output of OfficeParserAnalysis3, flags it as a suspect OLE attachment by file type (file command output), extension, or because node --check accepts it as JavaScript.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; FileTypeAnalysis via get_and_load_analysis (config dependency file_type); root.iterate_all_references(_file) must include an OfficeParserAnalysis3 (no wait).
- **Libraries**: none.
- **Tools**: node (nodejs 24.22) `node --check <file or hard link {file}-<uuid>.js>` via subprocess.Popen from is_javascript_file(), NOT sandboxed, no timeout; grep -Eq <JS keyword regex> <file> via Popen, no timeout.
- **Threads and children**: node starts V8 worker threads
- **Writes**: {file}-<uuid4>.js temporary hard link, removed after node --check.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: detection point OLE_EXTRACTED_SUSPECT_FILE (suspect type, ext, or javascript); 'suspect_ole_attachment' tag.
- **Notes**: node and grep run unsandboxed with no timeout (is_file_type.py:165-185). JS check runs only if type and ext checks did not match. Creates an analysis for every officeparser output, suspect or not.

### file_type

- **Section**: `analysis_module_file_type`, class `FileTypeAnalyzer` in `saq/modules/file_analysis/file_type.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. It is the type step (PLAN.md decision 25, docs/decisions/0003): the core queues it first on every new file, alone, and keeps what it finds, the file's type (`TypeFacts`: libmagic's description and mime type and the checks that read only the bytes), once per sha256, not as a result in the tree. ace3's `file_type_analysis` result, its tags and its `yara_meta` types are built from the type and the file's analysis path where ace3's module would have run (`ace_core::type_step`), so the comparison checks them as before; the GUI and the API show a file's type and role instead of a result. libmagic runs in the task on the database ace3's `file` reads, loaded from its bytes before containment (`libmagic.rs`), and matches `file -b -L` and `file -b --mime-type -L` on every file of every sample's tree. `node --check` is oxc_parser 0.157.0, as CommonJS then as an ES module, with oxc's early errors and V8 13.6's missing proposals refused: it agrees with node 24 on 850 cases (`docs/measurements/javascript-check.md`, which also has nesting and the stack); the type step asks it only where the mime type or the name says JavaScript, as ace3 does. ace3's mime stamp on the observable is the file's type, and its image preview size the GUI's business. The modules that depend on it read ace3's result built from the type, and the declarations read the type itself.
- **Pool**: parser. Magic bytes, libmagic and a JavaScript parse in the task's process.
- **Step**: done.
- **Does**: Runs `file` twice on a file to record its human-readable type and mime type, checks magic bytes for office/OLE/RTF/PDF/PE/zip/x509/lnk/jar/email, then tags the file and stamps yara_meta type directives.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: Pillow 13.0.0 (Image.open for scaled preview dimensions, FileObservable.compute_scaled_dimensions); cryptography 50.0.2 + pyasn1 0.6.5 (is_x509 via saq/x509.py load_cert/is_der_bytes); zipfile stdlib (is_zip_file, is_jar_file).
- **Tools**: file (libmagic 5.46) via run_tool (plain subprocess.run, unsandboxed), twice: `file -b -L` and `file -b --mime-type -L`; node 24.22 via Popen `node --check <file or hard link>.js` (unsandboxed, no timeout) in is_javascript_file, only when mime is a JS type or extension is .js/.mjs/.cjs/.jse; grep via Popen `grep -Eq <js keyword regex>` (unsandboxed) after node --check succeeds.
- **Threads and children**: node starts V8 worker threads; file and grep do not.
- **Writes**: {file}-<uuid4>.js (temporary hard link next to the file for node --check, unlinked afterwards; is_file_type.py is_javascript_file).
- **yara_meta**: type=image (mime starts with image/); type=document.pdf; type=document.rtf; type=executable; type=archive.jar; type=certificate.x509; type=email; type=document.html (mime text/html or application/xhtml+xml); type=script.javascript (node --check passes and grep finds a JS keyword).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags microsoft_office, ole, rtf, pdf, executable, zip, lnk, x509, jar, email. No detection points.
- **Notes**: The yara_meta mapping table is YARA_META_TYPE_BY_DETAIL (file_type.py:14-21): is_pdf_file->document.pdf, is_rtf_file->document.rtf, is_pe_file->executable, is_jar_file->archive.jar, is_x509->certificate.x509, is_email_file->email. Outside the table it also sets type=image (line 317), type=document.html (line 324) and type=script.javascript (line 331). Sets FileObservable.mime_type and computes scaled image dimensions so the GUI does not fork `file` per render (lines 250-261). is_pe_file only checks for 'MZ'. is_email_file needs from, subject and message-id headers in 7-bit ASCII, or mime message/rfc822. is_jar_file is only checked when is_zip_file is true. Runs node on attacker content outside the sandbox with no timeout (is_file_type.py Popen). The details keys (is_ole_file, is_office_document, is_zip_file, mime...) are read by archive, file_hash_analyzer, url_extraction, x509_analyzer, exif (via is_office_file).

### pdf_analyzer

- **Section**: `analysis_module_pdf_analyzer`, class `PDFAnalyzer` in `saq/modules/file_analysis/pdf.py`, enabled by default.
- **ace4**: ported in `ace-mod-pdf`.
- **Pool**: sandbox. libqpdf and a port of pdf-parser.py in the task's process (4.9); Ghostscript's rewrite, `<file>.gs.pdf`, in the sandbox runner (7.5 batch 10).
- **Step**: done.
- **Does**: For a PDF, dumps its objects with stream filters decoded via pdf-parser.py, re-renders it with ghostscript, and with pikepdf extracts annotation URIs, base64 AcroForm field values and /Names JavaScript, and saves a decrypted copy of PDFs that open with an empty password.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: pikepdf 10.17.0.
- **Tools**: python3 bin/pdf-parser.py (Didier Stevens pdf-parser 0.7.12, vendored) via run_tool (plain subprocess.run, unsandboxed), timeout 10 s, run on the file and again on the decrypted copy; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pdfwrite -o output.pdf -f <file>`, timeout 10 s.
- **Threads and children**: pdf-parser starts a Python interpreter; gs single process.
- **Writes**: {file}.pdfparser; {file}.gs.pdf; {file}.annotation_uris.txt; {file}.field_<name>_decoded.bin; {file}.js_<name>.js; {file_name}.decrypted.pdf (via root.create_output_file); {file_name}.decrypted.pdf.pdfparser (via root.create_output_file).
- **yara_meta**: type=document.pdf.object (pdfparser output); type=document.pdf.rendered (gs output); type=document.pdf.annotation_uris; type=document.pdf.form_field; type=script.javascript (extracted /JS); type=document.pdf (decrypted copy).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: bin/pdf-parser.py (config pdfparser_path).
- **Tags and detections**: Tags the source 'encrypted_pdf_empty_password' and the copy 'decrypted_pdf'. All outputs get DIRECTIVE_EXTRACT_URLS (except the decrypted copy), redirection to the source PDF and R_EXTRACTED_FROM. No detections.
- **Notes**: Detects PDFs by '%PDF-' in the first 1024 bytes; skips *.pdfparser and *.ocr. pdfparser output is written even if the tool is stopped (pdf.py:243). pdf-parser.py is run OUTSIDE the sandbox on attacker files (pdf.py:245). The gs, uri, form-field and js outputs exclude pdf_analyzer itself. Decrypted copy is saved with stream_decode_level none and deterministic_id so its sha256 is stable (pdf.py:283-293), and excludes pdf_analyzer, pdftotext, exif and qrcode. PDFs needing a user password are left to PDFEncryptionAnalyzer.

### pdf_link_text

- **Section**: `analysis_module_pdf_link_text`, class `PDFLinkTextAnalyzer` in `saq/modules/file_analysis/pdf.py`, enabled by default. Added by ace3 `b4badb2c`, with `40ee8208`'s fixes.
- **ace4**: ported in `ace-mod-pdf`. libqpdf reads the link annotations in the task (`crate::objects`, as the PDF module's annotation URIs: each link's URL, page, `/Rect`, `/Contents`, its page's `/Rotate` and media box, as pikepdf hands them over; `tools/library-diff/adapters/pikepdf.py` and its Rust side read the same, for `tools/library-diff/run pikepdf`), and `pdftotext -bbox` runs in the sandbox runner. Its bounds are ace3's settings, with ace3's defaults: `max_links`, `link_text_pages`, `max_page_words`, `max_link_band_words`. `pdftotext_path` is the pool's image's and `cache_ttl` is of ace3's analysis result cache, which ace4 doesn't have (6.7). When pdftotext doesn't finish or exits non-zero, the result is marked failed with ace3's reason (`<how pdftotext exited>, without the text under the links`) and the links are kept without their text, as ace3's are. `crates/ace-mod-sandbox/tests/differences.md` has the rest, and `docs/measurements/pdf-link-text.md` crafted files against its limits. Its results are kept in the analysis cache for 30 days, ace3's `cache_ttl` (decision 26), keyed on pdftotext's version; one marked failed isn't kept.
- **Pool**: sandbox. libqpdf in the task's process, and pdftotext in the sandbox runner.
- **Step**: done (ported with the inventory's move to ace3 `37a765bf`, 2026-11-16).
- **Does**: For a PDF with link annotations, records each link's URL and page with the text the PDF shows under it (the words of `pdftotext -bbox` whose centre is inside the link's `/Rect`) and the text of the line it is on, which the lure module reads as the link's text.
- **Input**: file (a PDF, by `%PDF-` in its first 1024 bytes, not `*.pdfparser`; checked in `custom_requirement`, before the cache lookup).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none. `pdf_analyzer` excludes it from a PDF's decrypted copy.
- **Libraries**: pikepdf 10.17.0 (libqpdf 12.4.2).
- **Tools**: pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext -bbox -f <first> -l <last> <file> -`, timeout 10 s; `pdftotext -v` via probe_binary_version for the cache key.
- **Threads and children**: none: `pdftotext -bbox` started no thread and no process (strace, 2026-11-16).
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none.
- **Notes**: Each (URL, page, box) once, at most `max_links` (200) per PDF. Only links with a four-number `/Rect`, on a page that isn't rotated, among the first `link_text_pages` (3) are placed; the rest keep the annotation's `/Contents`. A page of more than `max_page_words` (20,000) words isn't placed, and a link whose lines hold more than `max_link_band_words` (500) words gets no text. No analysis when the PDF has no link, or when pikepdf can't open it or reading a link raises (a `/Rotate` that isn't a number). The summary counts the links and those with text or a line. Results are cached for 30 days in ace3, keyed on the PDF, the settings and pdftotext's version; a failed one isn't cached.

### upx

- **Section**: `analysis_module_upx`, class `UPXAnalyzer` in `saq/modules/file_analysis/upx.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. upx 4.2.4 in the sandbox runner, each run given the task's time left, as ace3's run with no timeout of its own is. A `upx -d` the runner stops marks the result failed with ace3's `upx -d did not finish` and why the runner stopped it.
- **Pool**: sandbox. Runs upx in the sandbox runner; no crate unpacks UPX.
- **Step**: done (7.5 batch 11).
- **Does**: Tests a PE file with `upx -t` and, if it is UPX packed, unpacks it with `upx -d` and adds the unpacked executable as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: upx (upx-ucl 4.2.4) via run_sandboxed_tool: `upx -t <file>` then `upx -d -ounpacked.exe <file>`.
- **Threads and children**: none: upx started no thread and no process (strace, 7.3).
- **Writes**: {file}.upx.exe.
- **yara_meta**: type=executable.unpacked.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the unpacked file 'upx'; copies the source file's directives to it. No detections.
- **Notes**: PE check is 'MZ' magic only. No explicit timeout (uses the analysis time left). Analysis is created once upx -t passes, with error recorded if upx -d does not finish.

### autoit

- **Section**: `analysis_module_autoit`, class `AutoItAnalyzer` in `saq/modules/file_analysis/autoit.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. unautoit, built from `vendor/unautoit` (ace3's `third_party/unautoit`) to the same binary as ace3's, in the sandbox runner where ace3 runs it as a plain process. ace3 keeps `run_tool`'s bytes as the listing's stdout and stderr, which its JSON encoder writes decoded as `unicode_escape` (a Windows path's `\U` becomes U+FFFD, its `\a` a bell); the port decodes them so, with `ace_pycompat::escape`. A run the runner stops for a limit other than its timeout records why, beside ace3's `timed out`.
- **Pool**: sandbox. Runs unautoit in the sandbox runner, where ace3 runs it unsandboxed. A port of its libautoit would be GPL-3 code in ace4.
- **Step**: done (7.5 batch 11).
- **Does**: For a compiled AutoIt executable (PE or .au3 containing AU3!EA05/EA06), lists and extracts its embedded resources with unautoit and adds each decompiled .au3 script as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: unautoit (vendored Go build from third_party/unautoit) via run_tool (plain subprocess.run, UNSANDBOXED): `unautoit list <file>` and `unautoit extract-all --output-dir {file}.autoit <file>`.
- **Threads and children**: Go's runtime started 4 or 5 threads, and no process (strace, 7.3).
- **Writes**: {file}.autoit/<name>.au3 (and any other resources unautoit extracts, only .au3 are added).
- **yara_meta**: type=script.autoit.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the source and each script 'autoit'. No detections.
- **Notes**: custom_requirement streams the file in 8 MB chunks for the AutoIt marker (is_file_type.py is_autoit). os.makedirs(output_path) at autoit.py:129 is not exist_ok, so a re-run on the same file raises into the except and then os.listdir still runs. No explicit timeout (time left). Extracted scripts exclude autoit.

### lnk_parser

- **Section**: `analysis_module_lnk_parser`, class `LnkParseAnalyzer` in `saq/modules/file_analysis/lnk_parser.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. It runs on `ace-lnkparse`, a port of LnkParse3 1.6.0 that matches it on 134 hand-made shortcuts and 6,000 mutations of them, values, both JSON forms and exception text.
- **Pool**: parser. Parses an attacker's shortcut in the task's process.
- **Step**: done.
- **Does**: Parses a Windows shortcut (.lnk magic) with LnkParse3, stores its JSON in details and writes it to a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: LnkParse3 1.6.0.
- **Tools**: none.
- **Writes**: {file}.lnkparser.json.
- **yara_meta**: type=metadata.lnk.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the file 'lnk'. No detections.
- **Notes**: verify_environment requires a 'lnkparse' program on PATH, but the code only uses the library (lnk_parser.py:141). Summary shows target path, arguments, icon location, working directory.

### de4dot

- **Section**: `analysis_module_de4dot`, class `De4dotAnalyzer` in `saq/modules/file_analysis/dotnet.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. de4dotEx 3.10.0, self-contained on .NET 10.0.14, in the sandbox runner, with ace3's heap limit and region range and its 12 GB address-space limit in the tool's spec, and its own `/proc/<pid>` and ICU readable. `file -b -L`'s answer is libmagic's in the task, over the same database. A runtime that can't start (`DOTNET_STARTUP_ERRORS`) fails the task as the node's fault. A cleaning run the runner stops marks the result failed with ace3's `de4dot did not finish` and why the runner stopped it, and one that ends without writing the file with `<how de4dot exited>, without writing a deobfuscated file`.
- **Pool**: sandbox. Runs de4dot on .NET in the sandbox runner. .NET is in the image by decision 18 (*External tools*).
- **Step**: done (7.5 batch 11).
- **Does**: For a .NET assembly, checks for a known obfuscator with `de4dot -d` and, if one is detected, deobfuscates it and adds the cleaned assembly as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: de4dotEx 3.10.0 (/opt/de4dotEx/de4dot, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET_GCHeapHardLimit=1 GB, memory limit 12 GB, timeout 10 s: `de4dot -d <file>` then `de4dot <file> -o deobfuscated`; file via Popen `file -b -L` (unsandboxed, no timeout) in is_dotnet.
- **Threads and children**: .NET started 8 or 9 threads and no process (strace, 7.3); de4dot's dynamic string decrypters can execute the sample's own methods (dotnet.py:110), and one that starts a process kills the tool in ace4.
- **Writes**: {file}.deobfuscated.
- **yara_meta**: type=executable.dotnet.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None. Output gets redirection to the source and excludes de4dot, file_hash_analyzer and file_type.
- **Notes**: is_dotnet = 'MZ' plus `file` output containing '.net assembly'. Detection test is 'Detected' in stdout. deobfuscated=True and add_file_observable are done even if the second run did not finish (dotnet.py:146-147).

### ilspy

- **Section**: `analysis_module_ilspy`, class `IlspyAnalyzer` in `saq/modules/file_analysis/dotnet.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. ilspycmd 11.0.0.9375 on the .NET 10.0.14 runtime in the sandbox runner, given the file under its own name in its working directory, so its IL is named as ace3's, with the same limits as de4dot's. The IL is `<name>_ilspy.il` at the top of the alert; ace3 counts up from `_ilspy_0` past names its root already holds, and ace4 analyzes a file once (decision 15). A run the runner stops marks the result failed with ace3's `ilspy did not finish` and why the runner stopped it, and one that ends without writing IL with `<how ilspy exited>, without writing IL`; the summary is then ace3's `Ilspy Analysis: failed: <reason>`.
- **Pool**: sandbox. Runs ilspycmd on .NET in the sandbox runner; no crate gives ILSpy's output.
- **Step**: done (7.5 batch 11).
- **Does**: Disassembles a .NET assembly to IL with ilspycmd and adds the .il file as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: ilspycmd 11.0.0.9375 (/opt/dotnet/ilspycmd, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET env heap limits, memory limit 12 GB, timeout 10 s: `ilspycmd -il --disable-updatecheck -o . <file>`; file via Popen `file -b -L` (unsandboxed) in is_dotnet.
- **Threads and children**: .NET started 19 threads and no process (strace, 7.3).
- **Writes**: {file_name}_ilspy.il or {file_name}_ilspy_<n>.il (via root.create_file_path).
- **yara_meta**: type=script.dotnet.decompiled.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none (ilspycmd's update check over the network is disabled with --disable-updatecheck, and the sandbox has no network).
- **Reads outside the alert**: none.
- **Tags and detections**: None. Output gets redirection and excludes ilspy, file_hash_analyzer, file_type.
- **Notes**: Uses -o so ilspycmd writes a buffered file (stdout writes were too slow on macOS bind mounts, dotnet.py:241). Records exit_code and stderr.

### ocr

- **Section**: `analysis_module_ocr`, class `OCRAnalyzer` in `saq/modules/file_analysis/ocr.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. Pillow's reading of the image and OpenCV's preprocessing in the task, with OpenCV 5.0.0 built as opencv-python 5.0.0.93 builds it, statically linked; tesseract in the sandbox runner with `OMP_THREAD_LIMIT` from `omp_thread_limit`; the en_US Hunspell dictionary through `spellbook`, with Hunspell's default word breaks, where ace3 asks enchant. Its results are kept in the analysis cache for 30 days, ace3's `cache_ttl` (decision 26), a clean read's among them, keyed on tesseract's version as ace3's are, and also on the en_US dictionary's bytes and OpenCV's version; the file it adds is named after the new root's path on a hit.
- **Pool**: sandbox. OpenCV in the task, tesseract in the sandbox runner.
- **Step**: done (7.5 batch 10).
- **Does**: For an image file carrying the ocr directive, preprocesses it with OpenCV and runs two tesseract passes (grayscale and denoised), writing the extracted text to a file observable for URL extraction and yara.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: opencv-python 5.0.0.93 (cv2); numpy 2.5.4; pytesseract 0.3.13; Pillow 13.0.0 (is_image); pyenchant 3.3.0 (enchant en_US dictionary, in saq/ocr.py remove_line_wrapping).
- **Tools**: tesseract (tesseract-ocr 5.5.0) via pytesseract.image_to_string, which starts it with subprocess UNSANDBOXED and no timeout, twice per image (`--oem 1 --psm 3`); tesseract --version via probe_binary_version (subprocess.run, cached per binary mtime) for the cache key.
- **Threads and children**: tesseract started no thread with OMP_THREAD_LIMIT=1 (config omp_thread_limit 1) and 4 OpenMP threads without it, with the same text, and no process (strace, 7.3); OpenCV starts none with `setNumThreads(1)`.
- **Writes**: {file}.ocr/{basename}.ocr; pytesseract temp image/output files in the system temp dir (removed by pytesseract).
- **yara_meta**: type=document.text.ocr.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: enchant en_US dictionary (system).
- **Tags and detections**: None. Output gets DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL and redirection to the image.
- **Notes**: required_directives [ocr]; valid_analysis_modes/valid_alert_types restrict it when non-empty (both [] by default). file_size_limit 100 MB. cache_ttl 2592000 (30 days), cache key includes tesseract version (extended_version). Records an empty analysis for a clean negative result so it caches, but nothing if a pass raised (ocr.py:230-234). Sets os.environ OMP_THREAD_LIMIT process-wide (ocr.py:161). saq.ocr imported lazily (~18 MB).

### qrcode

- **Section**: `analysis_module_qrcode`, class `QRCodeAnalyzer` in `saq/modules/file_analysis/qrcode.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. pdfinfo, Ghostscript and zbarimg in the sandbox runner; OpenCV's `QRCodeDetector` in the task where ace3 runs `bin/qr_decode_opencv.py`; the inverted image written by the task. `qrcode.filter` is the analyst-edited list `qrcode_filter` (5.14). Its results are kept in the analysis cache for 30 days, ace3's `cache_ttl` (decision 26), a clean scan's among them, keyed on pdfinfo's, gs's and zbarimg's versions, OpenCV's and the `qrcode_filter` list's entries; the file it adds is named after the new root's path on a hit. It takes only images and PDFs by the file's type, as ace3's 2026-06-25 consult gate.
- **Pool**: sandbox. pdfinfo, Ghostscript and zbarimg in the sandbox runner; OpenCV's QR decoder in the task.
- **Step**: done (7.5 batch 10).
- **Does**: Scans an image, or the first and last pages of a PDF rendered with ghostscript, for QR codes with zbarimg (falling back to an OpenCV script and an inverted image) and writes the decoded URLs to a file observable for crawling.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: Pillow 13.0.0 (is_image, ImageOps.invert); opencv-python 5.0.0.93 and numpy 2.5.4 (in bin/qr_decode_opencv.py, run as a sandboxed subprocess).
- **Tools**: pdfinfo (poppler-utils 25.03.0) via run_sandboxed_tool for the page count; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pngalpha -o <pattern> -r144 -dFirstPage -dLastPage`, up to 2 runs plus a full-render fallback; zbarimg (zbar-tools 0.23.93) via run_sandboxed_tool: `zbarimg -q --raw --nodbus`, per page and per inverted page; venv python3 -I bin/qr_decode_opencv.py via run_sandboxed_tool (OPENBLAS_NUM_THREADS=1), when zbarimg finds no URL; zbarimg/gs/pdfinfo version probes via probe_binary_version (subprocess.run, cached) for the cache key.
- **Threads and children**: The OpenCV script runs a Python interpreter; OpenBLAS limited to 1 thread and cv2.setNumThreads(1), with which it started none (19 without the OpenBLAS limit). zbarimg started 6 threads (ImageMagick's OpenMP), none with MAGICK_THREAD_LIMIT=1 and OMP_THREAD_LIMIT=1; Ghostscript and pdfinfo none. No process (strace, 7.3).
- **Writes**: {file}.qrcode; temp dir qrcode-pages-*/page-N.png, first-N.png, last-N.png (removed); temp inverted PNG via tempfile.NamedTemporaryFile (removed).
- **yara_meta**: type=document.text.qrcode.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: <analyst_data_dir>/qrcode.filter (config filter_path; one regex per line of URLs to drop); bin/qr_decode_opencv.py.
- **Tags and detections**: Tags the output 'qr-code' and 'qr-code-inverted' when read from the inverted image; adds DIRECTIVE_EXTRACT_URLS and DIRECTIVE_CRAWL_EXTRACTED_URLS; excludes file_hash_analyzer. No detections.
- **Notes**: custom_requirement: non-empty image (PIL opens it) or PDF. pdf_first_pages 3, pdf_last_pages 3, timeout 30 s per tool (60 s for OpenCV). cache_ttl 30 days, cache key includes zbarimg/gs/pdfinfo/opencv versions and the filter file's sha256. Records an empty analysis for a clean negative, nothing if any scan failed. Lines with neither '.' nor '/' are dropped as not URLs.

### hidden_mime

- **Section**: `analysis_module_hidden_mime`, class `HiddenMIMEAnalyzer` in `saq/modules/file_analysis/mime.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. It parses with `ace-mod-oletools`' port of Python's feed parser, raising `RecursionError` past 971 nested multiparts, as ace3 does. It writes at most 499 files. Its packet capture test is its declaration, from the file's type (*What a module takes*).
- **Pool**: parser. MIME parsing of an attacker's file.
- **Step**: done.
- **Does**: Searches a non-email, non-pcap file for a 'content-type: ... boundary=' header and parses the MIME body from there with the stdlib email parser, writing each decoded part.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; FileTypeAnalysis via get_and_load_analysis (mime_type, is_email_file); runs if absent.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: {file}.mime/extracted-{N}.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none; R_EXTRACTED_FROM on parts.
- **Notes**: saq/mime_extractor.py:17-77; mmaps the whole file, regex over it, no size cap. Skips original_email directive, email.rfc822, message/rfc822, is_email_file, pcap magic.

### active_mime

- **Section**: `analysis_module_active_mime`, class `ActiveMimeAnalyzer` in `saq/modules/file_analysis/mime.py`, enabled by default.
- **ace4**: ported in `ace-mod-office`. It inflates with `ace-mod-oletools`' port of `zlib.decompress`, up to 256 MiB, past which ace3 would run out of memory; past that there is no result.
- **Pool**: parser. A header walk and zlib.
- **Step**: done.
- **Does**: For a file starting 'ActiveMime', walks its header fields and zlib-decompresses the payload into a .activemime file.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: {file}.activemime.
- **yara_meta**: type=document.activemime.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: 'activemime' tag on the extracted file; R_EXTRACTED_FROM.
- **Notes**: saq/mime_extractor.py:94-155. Reads whole file into memory and inflates with no output size limit (zlib bomb risk).

### dmg_analyzer

- **Section**: `analysis_module_dmg_analyzer`, class `DMGAnalyzer` in `saq/modules/file_analysis/dmg.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. dmg2img 1.6.7 and 7-Zip 25.01 in the sandbox runner, each run given the task's time left, as ace3 gives them no timeout of their own; 7z is `/usr/lib/7zip/7z`, which ace3's `/usr/bin/7z` script execs, reading `7z.so` beside it and 7zip-rar's `Codecs/Rar.so`, as ace3's 7z loads them. The image is added under the DMG's alert path with `.img` for `.dmg`, and `image_file` names it so. The result is marked failed with ace3's reasons: `dmg2img did not finish` or `7z l did not finish, so the image's files are not listed`, each with why the runner stopped it, `<how dmg2img exited>, without writing an image`, and `<how 7z l exited>, so the image's file list may be incomplete` when 7z exits above 1.
- **Pool**: sandbox. Runs dmg2img and 7z in the sandbox runner; the DMG and HFS+ crates are young, and the module keeps 7z's listing as it is.
- **Step**: done (7.5 batch 12).
- **Does**: For a file named *.dmg, converts it to a raw .img with dmg2img, adds that image as a file observable, and records the 7z listing of its files.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: dmg2img 1.6.7 via run_sandboxed_tool: `dmg2img <file> image.img`; 7z 25.01 via run_sandboxed_tool: `7z l <image>`.
- **Threads and children**: dmg2img and 7z started no thread and no process on an HFS+ DMG (strace, 7.3).
- **Writes**: {file without .dmg}.img.
- **yara_meta**: type=archive.dmg.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the .img 'macos' and 'dmg' (which cve_2021_30657_analyzer requires); redirection to the dmg. No detections.
- **Notes**: Matches on the .dmg extension only. No explicit timeout (time left). The file listing parse uses column 20 for the 'D' attribute (dmg.py:140).

### cve_2021_30657_analyzer

- **Section**: `analysis_module_cve_2021_30657_analyzer`, class `CVE_2021_30657_Analyzer` in `saq/modules/file_analysis/cve.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. 7-Zip 25.01 in the sandbox runner; `file -b --mime-type -L` is libmagic in the task over the same database (`ace_mod_files::libmagic`). A module reads no other observable's result, so it lists the image again with dmg_analyzer's `7z l`, on the same bytes, rather than read the DMG analysis's `file_list`; and it runs on an image dmg_analyzer added (`Module::READS_ADDED_BY`) that redirects, which is what ace3's checks of the `macos` and `dmg` tags and of the redirection's DMG analysis select, since only dmg_analyzer adds them. Each member is extracted with a run of its own, as ace3 does, while the task's 64 runs (`MAX_RUNS`) allow; with more members, the runs share them out in order, so none goes unchecked (66 in `samples/ace4/macos/many_members.dmg` take 33 runs, with ace3's result). A script is added under its name, as ace3's copy in `cve_2021_30657/` is. A run the runner stops, members whose paths are too long to be a run's arguments, or its 500th script (`MAX_FILES`; ace3's root holds 500 files) ends the checks, and why is the result's error; a member 7z didn't extract is ace3's `<how 7z exited>, without extracting <member>`, and a stopped run its `7z did not finish extracting <member>, so it and the files after it were not checked`, naming the first member of the run.
- **Pool**: sandbox. Runs 7z on dmg_analyzer's HFS+ image in the sandbox runner; `file` becomes libmagic in the task.
- **Step**: done (7.5 batch 12).
- **Does**: For a .img produced by dmg_analyzer, extracts each file under */Contents/MacOS/ with 7z and raises a detection when its mime type is a script (CVE-2021-30657 Gatekeeper bypass).
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: DMGAnalysis on the file's redirection (the .dmg), read via _file.redirection.get_and_load_analysis; requires tags macos and dmg set by dmg_analyzer.
- **Libraries**: none.
- **Tools**: 7z 25.01 via run_sandboxed_tool: `7z x -o<temp> <img> <member>` once per Contents/MacOS member; file via run_tool (plain subprocess.run, unsandboxed): `file -b --mime-type -L <extracted>`.
- **Threads and children**: 7z started no thread and no process extracting a member (strace, 7.3).
- **Writes**: <storage_dir>/cve_2021_30657/<basename> (copy of each script found); temp dir under get_temp_dir() (removed).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Detection point 'Possible CVE-2021-30657 attack' (signature CVE_2021_30657_DMG_SCRIPT) and tag CVE-2021-30657 on each script file.
- **Notes**: No config dependency on dmg_analyzer is declared, only the code dependency through redirection and tags; if dmg_analyzer has not run on the redirection target it returns without analysis. Copies scripts into the root storage dir (cve.py:122-127).

### exif

- **Section**: `analysis_module_exif`, class `ExifAnalyzer` in `saq/modules/file_analysis/exif.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. exiftool in the sandbox runner, on a copy under the file's own name; its metadata pretty-printed by a port of Python's `pprint`.
- **Pool**: sandbox. exiftool in the sandbox runner.
- **Step**: done (7.5 batch 10).
- **Does**: Runs exiftool on office documents, OLE files and PDFs, stores the metadata in details and writes it pretty-printed to a file observable for yara.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: FileTypeAnalysis read indirectly by is_office_file (falls back to extension when absent; wait_for_analysis commented out, exif.py:169).
- **Libraries**: json, pprint stdlib.
- **Tools**: exiftool (libimage-exiftool-perl 13.25) via run_sandboxed_tool: `exiftool -j -G -n <file>`, timeout 30 s.
- **Threads and children**: none: Perl started no thread and no process (strace, 7.3).
- **Writes**: {file}.exif/exiftool.out.
- **yara_meta**: type=metadata.exif.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None. Output excludes file_hash_analyzer and file_type.
- **Notes**: Skips *.pdfparser and *.gs.pdf. file_size_limit 80 MB (base_module enforces it). Records an error string when exiftool fails or times out. pprint falls back to repr on RecursionError (exif.py:212-217).

### pdftotext

- **Section**: `analysis_module_pdftotext`, class `PDFTextAnalyzer` in `saq/modules/file_analysis/pdf.py`, enabled by default.
- **ace4**: ported in `ace-mod-sandbox`. poppler's pdftotext in the sandbox runner.
- **Pool**: sandbox. pdftotext in the sandbox runner.
- **Step**: done (7.5 batch 10).
- **Does**: Converts a PDF to plain text with poppler's pdftotext and adds the text file as a file observable for yara scanning.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext <file> output.txt`, timeout 5 s.
- **Threads and children**: none: pdftotext started no thread and no process (strace, 7.3).
- **Writes**: {file}.txt when the name ends in .pdf, else {file}.pdf.txt.
- **yara_meta**: type=document.pdf.text.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None. Output gets redirection to the PDF, R_EXTRACTED_FROM, and excludes the archive analyzer.
- **Notes**: Uses is_pdf_file ('%PDF-' in first 1024 bytes, not *.pdfparser). Stores stdout/stderr in details.

### yara_scanner_v3_4

- **Section**: `analysis_module_yara_scanner_v3_4`, class `YaraScanner_v3_4` in `saq/modules/file_analysis/yara.py`, enabled by default.
- **ace4**: ported in `ace-mod-yara`.
- **Pool**: parser. yara-x through `ace-yara` in the task's process (1.x, 2.26). Its database reads of $obsd_ strings come on the ruleset: the core's build exports the `observable_detection` list as rules of the namespace `observable_export` with an index of each exported detection's type and value, and the module adds the observable a matched `$obsd_<id>` names, tagged with the rule (7.16, `ace_yara::export`, `reads.md`); $obs_ strings aren't served.
- **Step**: done.
- **Does**: Scans a file with ACE's yara rules through the yara scanner service over a Unix socket (falling back to an in-process scanner), adds rule/string/signature_id observables and detection points, resolves $obsd_/$obs_ strings to database observables, and applies rule modifiers and tags.
- **Input**: file.
- **Groups and modes**: groups file, yara; modes analysis, binary, cli, correlation, email, file, yara.
- **Depends on**: indirect: relies on yara_meta directives set by earlier modules (file_type, pdf_analyzer, ...) to scope type= rules.
- **Libraries**: yara-python 4.5.4; yara_scanner (yara_scanner_v2 v3.0.0, git) for the local fallback; distorm3 3.5.2 (disassembly for rules tagged asm); markupsafe (presenter).
- **Tools**: git via subprocess.run `git -C <dir> rev-parse HEAD` (saq/git.py get_commit_hash) when initializing the local scanner, through get_validated_git_repo_dirs.
- **Writes**: <signature_dir>/marker rule file (install_marker_rule, local fallback only); <data_dir>/<scan_failure_dir>/<basename>[_timestamp] copy of a file that failed to scan, when save_scan_failures (false by default).
- **yara_meta**: reads: all yara_meta directives on the file (_file.yara_meta_tags) and passes them as meta_tags to the scanner.
- **ACE's data**: ace: observable_detections (ObservableDetection) by id from $obsd_<id> strings, R; ace: observables (Observable) by id from legacy $obs_<id> strings, R.
- **Secrets**: none.
- **Network**: Unix socket to the yara scanner service (<data_dir>/<socket_dir>/<SOCKET_NAME>); the service stores QA matches in the yara_qa CAS pool when save_qa_scan_results..
- **Reads outside the alert**: yara rule files under service_yara_scanner.signature_dir (local fallback compiles them; auto_reload checks for changes).
- **Tags and detections**: A detection point on the file per matching rule that `detection_blocker()` (saq/signatures/yara_meta.py, 91211a66) lets through: enabled, no no_alert/qa modifier, no `whitelisted` tag (signature uuid from rule meta or YARA_RULE_MATCH fallback, version = rule repo commit, queue from rule meta). Adds the rule's tags to the file (`whitelisted` is an ordinary tag since 8617ba8e), adds DIRECTIVE_SANDBOX (to the redirection target if any) when alertable, and directives from 'directive=X' modifiers. Adds yara_rule, yara_string, signature_id, indicator (SIP_ rules) and DB-resolved observables tagged with the rule name.
- **Notes**: Skips empty files and files with DIRECTIVE_NO_SCAN. Local scanner kept local_scanner_lifetime (5) minutes after the service returns. Drops matches from rules with enabled=false meta. context_bytes 64: records hex dump and base64 context for each string match (re-reads the file). always_visible when the file has a yara detection. Detection details include namespace made relative to signature_dir (yara.py:72-98).

### binary_file_analyzer

- **Section**: `analysis_module_binary_file_analyzer`, class `BinaryFileAnalyzer` in `saq/modules/file_analysis/binary.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. `.doc` is looked for in the alert path, where ace3 looks in its node path. Its RTF or EPS test is its declaration, from the file's type, with the stricter `{\rt` left in the module (*What a module takes*).
- **Pool**: parser. Reads bytes.
- **Step**: done.
- **Does**: For RTF files (and EPS files with '.doc' in the path), flags the file for sandboxing if it contains a null byte anywhere but the last byte.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: Tags the file 'unexpected_binary_data' and adds DIRECTIVE_SANDBOX. No detection point.
- **Notes**: Creates an (empty) analysis for every supported file. RTF check here is only '{\rt' (stricter than is_rtf_file).

### microsoft_script_encoding_analysis

- **Section**: `analysis_module_microsoft_script_encoding_analysis`, class `MicrosoftScriptEncodingAnalyzer` in `saq/modules/file_analysis/mse.py`, enabled by default.
- **ace4**: ported in `ace-mod-scripts`. The Perl decoder is `mse::decode`, which matches `bin/jscript.decode.pl` byte for byte, dying where it dies with its message, on every fixture and sample and on 50,000 generated inputs, run in ace3's container against the Perl (`tools/samples/compare-mse-decoder`, `docs/measurements/scripts.md`). It runs in the task, linear in the file, where the Perl holds about 90 bytes per byte of the file and was killed for memory on 90 MB files, leaving part of its output for ace3 to add. The `.decrypted.stderr` file ace3 writes and never adds isn't written. `crates/ace-mod-scripts/tests/differences.md` has the rest. Its `#@~^` test is its declaration, from the file's type (*What a module takes*).
- **Pool**: parser. Runs a vendored 80-line Perl decoder, unsandboxed today; the table-driven decoding ports to Rust.
- **Step**: done.
- **Does**: For a file starting #@~^ (VBScript/JScript.Encode), tags it and decodes it with bin/jscript.decode.pl.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: perl script bin/jscript.decode.pl (vendored, ~80 lines) via run_tool() = subprocess.run, NOT sandboxed; timeout = time_left() minus margin.
- **Writes**: {file}.decrypted (or {file}.decrypted.vbs for .vbe, {file}.decrypted.js for .jse); {file}.decrypted.stderr (never added, never removed).
- **yara_meta**: type=script.encoded (on the decoded file).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: bin/jscript.decode.pl.
- **Tags and detections**: 'microsoft_script_encoding' tag + sandbox directive on the source; decoded file redirected to source.
- **Notes**: Output volatile=True; partial output removed if the tool is stopped (mse.py:104-107).

### url_extraction

- **Section**: `analysis_module_url_extraction`, class `URLExtractionAnalyzer` in `saq/modules/file_analysis/url_extraction.py`, enabled by default.
- **ace4**: ported in `ace-mod-urls`. urlfinderlib is `ace-urlfinder`'s port, which matches urlfinderlib on every sample and on hand-made and generated HTML, text, JSON, CSV, XML, iCalendar and PDF-like blobs in each of its modes. Its sets are sorted, so where ace3's order of URLs follows its hash seed, ace4's is the same each run. It depends on `file_type`, whose `yara_meta` types it reads; there's no dependency on the YARA module, whose skipped tasks store no result; an HTML file `downloaded_from` a URL has its relative URLs made absolute against it, as in ace3, since batch 4's `har_extraction` adds that relationship; observables aren't volatile, which ace4 doesn't have. `crates/ace-mod-urls/tests/differences.md` and `docs/measurements/url-extraction.md` have the rest.
- **Pool**: parser. Parses an attacker's file for URLs in the task's process.
- **Step**: done.
- **Does**: For files with the extract_urls directive, extracts URLs with urlfinderlib, filters excluded domains, orders them by interest and adds up to max_extracted_urls as URL observables.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type, yara_scanner_v3_4; FileTypeAnalysis (mime_type; returns if absent; config dependencies file_type and yara_scanner_v3_4).
- **Libraries**: urlfinderlib 0.27.1 (find_urls, find_urls_in_text; uses lxml, beautifulsoup and python-magic/libmagic internally); tld 0.13.2 (get_tld); validators 0.36.0 (OCR URLs); python-magic 0.4.27 (via urlfinderlib when mimetype is empty).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: reads: type=script.javascript (forces urlfinderlib mimetype text/plain); reads: type=document.text.ocr (uses find_urls_in_text and requires validators.url).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: tld's bundled public suffix list.
- **Tags and detections**: None. Adds volatile URL observables; adds DIRECTIVE_CRAWL to them when the file has DIRECTIVE_CRAWL_EXTRACTED_URLS. Uses DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL to treat bare domains as URLs.
- **Notes**: required_directives [extract_urls]. max_file_size is in MB (10). maximum_analysis_time 15 s ('XXX this can hang hard', url_extraction.py:217). HTML files downloaded from a URL (R_DOWNLOADED_FROM) resolve relative URLs against it. All URLs are kept in details (urls, urls_grouped_by_domain) even past the observable cap of 12. Default excluded domains: XML schema hosts.

### ioc_extraction

- **Section**: `analysis_module_ioc_extraction`, class `IOCExtractionAnalyzer` in `saq/modules/file_analysis/ioc_extraction.py`, enabled by default.
- **ace4**: ported in `ace-mod-urls`. Its YAML is the module's overlay settings, defaulting to ace3's `etc/ioc_extraction.yaml`, with `refang_patterns` a list of `{replacement, patterns}`; ace3 reloads the file when it changes. Patterns are Python `re` on fancy-regex with Python's `\w`, `\b`, `\s` and `$` (`crate::pyre`). The visible text is BeautifulSoup's `get_text()` on libxml2 (`ace_lxml::soup`). A type ace4 doesn't know, such as the default `cve`, stays in the details and makes no observable.
- **Pool**: parser. Text and regexes in the task's process; its settings file becomes a 5.14 list or overlay settings (5.14 says so).
- **Step**: done.
- **Does**: For files with the extract_iocs directive, takes the visible text (via BeautifulSoup), re-fangs it with configured regexes, and extracts URLs and configured regex IOC patterns as observables with configured directives, tags and display types.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: beautifulsoup4 4.15.0 with lxml 6.1.3; urlfinderlib 0.27.1 (find_urls); PyYAML 6.0.3; pydantic 2.14.1.
- **Tools**: none.
- **Writes**: {file_path}.refanged.txt (when re-fanging changed the text; written to a temp file then moved).
- **yara_meta**: type=document.text.refanged.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/ioc_extraction.yaml (config extraction_config_path, relative to SAQ_HOME; analyst-editable refang_patterns, patterns, urls; reloaded on change via watch_file).
- **Tags and detections**: Tags/directives/display_type on extracted observables come from the YAML. No detections.
- **Notes**: max_file_size 10 MB. Field default extraction_config_path is etc/default_ioc_extraction.yaml, which does not exist; the default config sets etc/ioc_extraction.yaml. Re-fang loop repeats until no substitution happens, which can loop forever on a pattern whose replacement matches itself (ioc_extraction.py:266-274). Ignored IOCs are listed in details with the pattern that excluded them. Python re patterns from analyst YAML.

### observable_modifier

- **Section**: `analysis_module_observable_modifier`, class `ObservableModifierAnalyzer` in `saq/modules/util/observable_modifier.py`, enabled by default.
- **ace4**: ported in `ace-core`. One of the core's hooks (`crates/ace-core/src/hooks.rs`, `hooks/rules.rs`): `pre` rules run where a result lands or a submission starts, before eligibility queues anything for what it touched, and `post` rules in the core's hooks task at the end of a pass, rerun while they match. The rules are the overlay's `hooks.observable_modifier.rules` in ace3's schema, checked when the core starts, and name modules by ace4's keys. A match is the observable's `observable_modifier_analysis` result with ace3's `matched_rules` and summary, a `signature_id` observable per rule, and its actions on the observable: `limit_modules`, `display_value` and `ignored` are migration 0044's, an `ignore` scoped to parents marks the parents' additions `ignored`, and `reset_analysis` queues again a task that ended with no result. Bounded: 1000 rules, 1024 patterns on the `regex` crate within size limits, the tree read to 20,000 observables and results, and a step budget per evaluation. The alert view has ace3's Observable Modifier Rules card and leaves an ignored observable out of the tree. What differs from ace3 is in the hooks' docs: rules reload with the core, not live, a rule ace3 would log and skip stops startup, `str()` of a details value is written as Python writes it, and the git commit isn't the detections' signature version.
- **Pool**: core. Evaluates rules over the whole tree and edits other nodes (wide_diff: removes observables, limits and resets analysis), which only the core's orchestrator can do; it parses no attacker bytes.
- **Step**: done.
- **Does**: Evaluates analyst-written YAML rules (observable type/value/tags/directives/yara_meta, alert type/queue/tags, and tree conditions over ancestors/descendants/siblings/parent/global analysis details) against every observable and applies actions: add directives/tags/detection points, exclude/limit/reset analysis, set display type/value, or ignore (remove from parent analyses).
- **Input**: all (valid_observable_types None; rule observable_types are subtype-aware).
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: Implicit: post-phase rules run in execute_final_analysis after the tree is otherwise done; tree_conditions wait on whatever analysis_type they name (including analyses produced in later analysis modes; the analysis is left completed=False to stay re-runnable).
- **Libraries**: PyYAML 6.0.3 (safe_load).
- **Tools**: git rev-parse HEAD via subprocess.run (saq/git.py:53-70), only when the optional git_dir setting is configured (not set in saq.default.yaml), on each rules reload.
- **Writes**: none.
- **yara_meta**: reads: has_yara_meta_tags rule condition checks directives yara_meta:<tag> (DIRECTIVE_YARA_META_PREFIX) (observable_modifier.py:458-461).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/observable_modifier_rules.yaml (rules_config_path; analyst-edited, mtime-polled via watch_file and reloaded live); external analysis details files of other analyses in the tree (details_match tree conditions load them from disk, cached per root).
- **Tags and detections**: rule-defined tags, directives and detection points (signature_uuid = rule uuid, signature_family observable_modifier, signature_version = git commit or unknown); adds a signature_id observable per matched rule uuid; ignore sets DIRECTIVE_EXCLUDE_ALL (pre phase) and observable.ignored / removes the observable from parent analyses' _observables
- **Notes**: wide_diff: true (it edits other analyses' observable lists and other observables), which forbids cache_ttl (saq/modules/config.py:42-48). Two phases: 'pre' rules in execute_analysis (returns INCOMPLETE), 'post' rules in execute_final_analysis (also INCOMPLETE). Matches persisted in the analysis (and copied to data.json as matched_rules) so they survive worker hand-off; rule uuids already matched are skipped. execute_post_analysis logs per-rule cost metrics consumed by a Splunk rex (rule_name must stay last, line 1089-1090). Rules without uuid are refused. Immutable-rule negative memo per root. config priority default 1 (runs early).

### x509_analyzer

- **Section**: `analysis_module_x509_analyzer`, class `X509Analyzer` in `saq/modules/x509.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. It runs on `ace-x509`, which uses cryptography's own Rust structures and asn1 crate, so it accepts what cryptography does, and ports pyasn1's DER check and cryptography's printing of names and extensions: it matches ace3's `saq/x509.py` on 4,303 cases but three nested past 100 levels, which it refuses. A serial past 64 bits is decimal text; a file under a URL observable can't be told apart, so only `no_crawl` stops the URLs.
- **Pool**: parser. Parses a certificate in the task's process.
- **Step**: done.
- **Does**: For a file FileTypeAnalysis marks as an x509 certificate, parses it and adds the common name and SAN names as fqdn (and crawlable http/https URL) observables, SAN IPs, and the certificate's sha256, and writes the metadata to a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; FileTypeAnalysis.is_x509 (returns if absent or false; config dependency file_type).
- **Libraries**: cryptography 50.0.2 (x509); pyasn1 0.6.5 (DER check).
- **Tools**: none.
- **Writes**: <storage_dir>/{file sha256}.metadata (JSON of details).
- **yara_meta**: type=metadata.x509.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: None. Adds DIRECTIVE_CRAWL on http/https URLs from CN and SANs unless a parent is a URL observable or the file has DIRECTIVE_NO_CRAWL.
- **Notes**: Wildcards are stripped from CN/SAN names. With DIRECTIVE_NO_CRAWL only the first 10 SAN names become fqdn observables (MAX_NO_CRAWL_SAN_FQDNS). The metadata file name uses the file observable's value (its sha256).

### protected_url_analyzer

- **Section**: `analysis_module_protected_url_analyzer`, class `ProtectedURLAnalyzer` in `saq/modules/url/protected.py`, enabled by default.
- **ace4**: ported in `ace-mod-values`. Proofpoint's URLs come from `ace-urlfinder`, the first in sorted order where ace3 pops one from a set. A 1drv.ms link goes to `protected_url_one_drive` (below).
- **Pool**: parser. Unwraps URLs in memory. Its one network case, following a 1drv.ms link's redirects, is left out of the parser. **Decided in 7.5 batch 3: a lookup instance**, `protected_url_one_drive` in `ace-mod-values` on the lookup pool, in ace3's `common` group (`App::module_in_group`), writing ProtectedURLAnalysis's fields as `protected_url_one_drive_analysis`. A crawl directive was the other choice, and it would change what ace4 does: 7.7's phishkit would load every OneDrive link in a browser, where ace3 asks for the link and turns the address it ends at into a download link, and until 7.7 nothing would follow it at all. The lookup does what ace3 does, with bounds ace3 doesn't have: it asks only 1drv.ms and its subdomains, where ace3's `endswith('1drv.ms')` also takes a host such as `evil1drv.ms`; it follows a redirect only to `redirect_hosts`, Microsoft's by default (1drv.ms, live.com, onedrive.com, sharepoint.com), at most 30 as requests does, each request within 8 s; it reads no body. A link it can't follow there is recorded as ace3 records one whose fetch failed: unprotected, the link itself. So the worker never contacts a host outside Microsoft's on an attacker's word. The parser module skips a 1drv.ms link, so its result is under the lookup's name, not ace3's.
- **Step**: done.
- **Does**: Unwraps a url observable protected or rewritten by a known service (Egnyte, FireEye, Outlook SafeLinks, Dropbox, SharePoint, Google Drive, URLDefense, Proofpoint, Cisco, Sophos, Barracuda cudasvc, OneDrive 1drv.ms) and adds the extracted url observable.
- **Input**: url.
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: urlfinderlib 0.27.1 (find_urls, Proofpoint only); requests 2.34.2 (1drv.ms only).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: only for 1drv.ms URLs: requests.get(url, allow_redirects=True, timeout=8) straight to the attacker-supplied URL and wherever it redirects (saq/util/url.py:220-243), with no explicit proxy (requests honours HTTP(S)_PROXY env vars). Otherwise none..
- **Reads outside the alert**: none.
- **Tags and detections**: tag protected_url on the original url; extracted url gets relationship extracted_from and a copy of the original's directives
- **Notes**: Docstring says most of the logic moved to URLObservable.sanitize_protected_urls (protected.py:55); this module still calls saq.util.url.extract_protected_url. Analysis is created before extraction, so every url gets one (possibly empty). Following a 1drv.ms link from the worker contacts attacker infrastructure directly from ACE, which a porter should route through the crawl egress.

### rtfole

- **Section**: `analysis_module_rtfole`, class `RTFOLEObjectAnalyzer` in `saq/modules/file_analysis/rtf.py`, enabled by default.
- **ace4**: ported in `ace-mod-oletools`.
- **Pool**: parser. A port of rtfobj in the task's process (4.10).
- **Step**: done.
- **Does**: Runs oletools' rtfobj on an RTF file to save every embedded object into a directory and adds each saved file.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: `python /venv/bin/rtfobj -d {file}.rtfobj -s all <file>` (oletools 0.60.2 rtfobj) via run_tool() = subprocess.run, NOT sandboxed; 'python' resolved from PATH; timeout = time_left() minus margin.
- **Threads and children**: a Python interpreter; no children known
- **Writes**: {file}.rtfobj/<rtfobj output names>.
- **yara_meta**: type=document.rtf.object (on each extracted file).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: extracted files tagged 'extracted_rtf', redirected to source, R_EXTRACTED_FROM. Config suspect_ext / suspect_mime_type are declared but unused here.
- **Notes**: Skips the file if {file}.rtfobj already exists (rtf.py:121). Stores stdout, stderr and return code in details. Outputs volatile=True. A stopped run returns before adding anything (rtf.py:135-137).

### extracted_rtf_analyzer

- **Section**: `analysis_module_extracted_rtf_analyzer`, class `ExtractedRTFAnalyzer` in `saq/modules/file_analysis/rtf.py`, enabled by default.
- **ace4**: ported in `ace-mod-scripts`. ace3 reads the `extracted_rtf` tag rtfole gives the files it writes; ace4's declaration reads on the lease which modules' results added the file (`takes::Condition::AddedBy`, in the lease's gate) and looks for rtfole. Its file is first leased once nothing nearer the root is pending (decision 15), so rtfole's result has landed. It depends on `file_type`, whose description and mime type it reads.
- **Pool**: parser. String checks on earlier results.
- **Step**: done.
- **Does**: For a file tagged extracted_rtf, flags it when its extension, mime type or file type matches the configured suspect lists.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; reads the 'extracted_rtf' tag set by rtfole; FileTypeAnalysis via get_and_load_analysis (config dependency file_type).
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: detection point RTF_EXTRACTED_SUSPECT_FILE + sandbox directive per matching ext / mime / file type (can add several).
- **Notes**: Always creates an (empty-details) analysis for extracted_rtf files.

### message_id_analyzer_v2

- **Section**: `analysis_module_message_id_analyzer_v2`, class `MessageIDAnalyzerV2` in `saq/modules/email/message_id.py`, enabled by default.
- **ace4**: ported in `ace-mod-emailarchive`. It pulls the email through the `archived-email` read, which finds the newest archive with the normalized Message-ID, opens it in the core and puts it in the root; the result adds it with no upload. ace3's `search_down` for the email that added the Message-ID is whether the email module's result added it (`Module::READS_ADDED_BY`).
- **Pool**: lookup. Fetches an archived email through the `archived-email` read (7.2), which decrypts it in the core; the email it adds is parsed by email_analyzer.
- **Step**: done.
- **Does**: For a message_id not already backed by an EmailAnalysis in the tree, looks it up in the email archive, decrypts and gunzips the archived email, and adds it as a file observable.
- **Input**: message_id.
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: search_down for an EmailAnalysis whose message_id equals the observable (skips if found); EmailAnalyzer excludes this module on the message_id it extracts.
- **Libraries**: PyMySQL 1.2.0; cryptography 50.0.2 (AES-256-GCM via saq.crypto.decrypt); python stdlib gzip/tempfile; boto3/botocore when email_archive.target is s3 (not pinned; 1.43.125 in ace3's dev container).
- **Tools**: none.
- **Writes**: <sha256(message_id)>.rfc822 (root file dir via create_file_path; removed if 0 bytes); OUTSIDE ALERT: decrypted gzip in a NamedTemporaryFile in the system temp dir during iteration (local.py iter_decrypt_email); OUTSIDE ALERT (s3 target): downloads $DATA_DIR/archive/email/<host>/<xx>/<sha256>.gz.e from S3 as a cache if missing.
- **yara_meta**: type=email (on the extracted email).
- **ACE's data**: email_archive (primary section): archive JOIN archive_server JOIN archive_index (R, by message_id hash) - called twice (email_is_archived then iter_archived_email).
- **Secrets**: SAQ encryption key; email_archive DB credentials; S3 credentials when target is s3.
- **Network**: MySQL email_archive database; S3 when target is s3.
- **Reads outside the alert**: $DATA_DIR/archive/email/<hostname>/<xx>/<sha256>.gz.e (archive store).
- **Tags and detections**: Tags the extracted email decrypted_email (literal string, message_id.py:101).
- **Notes**: In local target mode the archive path is built with the LOCAL hostname (local.py get_archive_path_by_hash), not the hostname returned by the query, and archive_email_is_local is never checked, so emails archived by another node fail to open and are logged as an exception. Exception path never sets analysis.error because the analysis is only created after a successful write. No size cap on the decompressed email.

### vbscript_analyzer

- **Section**: `analysis_module_vbscript_analyzer`, class `VBScriptAnalyzer` in `saq/modules/file_analysis/vbs.py`, enabled by default.
- **ace4**: ported in `ace-mod-scripts`. A byte scan with ace3's rules: Python's `str.isspace` of each byte, comment lines skipped without ending a run, and the same-length check against `large_hex_string_quantity`, as ace3 has it. Its percentage is formatted as Python formats a float.
- **Pool**: parser. A byte scan of an attacker's file.
- **Step**: done.
- **Does**: Scans a .vbs file for runs of ASCII hex characters (ignoring comment lines and whitespace) and flags large, repeated or file-dominating hex strings.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: detection point VBS_HEX_ENCODED_CONTENT for many same-length hex strings or hex >= hex_string_percentage_limit of the file; 'large_hex_string' tag when longest run > large_hex_string_size; sandbox directive in each case.
- **Notes**: Only files whose name ends .vbs (vbs.py:119). Quirk: the 'same length' check compares the length against large_hex_string_quantity (50), not large_hex_string_size (vbs.py:170). Runs of >=5 hex chars counted. mmap of whole file.

### nowhitespace_analyzer

- **Section**: `analysis_module_nowhitespace_analyzer`, class `NoWhiteSpaceAnalyzer` in `saq/modules/file_analysis/rtf.py`, enabled by default.
- **ace4**: ported in `ace-mod-scripts`. The copy streams into the bucket, as ace3 reads 1 MiB chunks; a name too long for `<file>.nowhitespace` leaves a result with no file and a count of 0, as ace3's failed `open` does.
- **Pool**: parser. A byte transform.
- **Step**: done.
- **Does**: For an RTF file, writes a copy with all ASCII whitespace removed and adds it for further scanning.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: {file}.nowhitespace.
- **yara_meta**: type=document.rtf.stripped.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: none.
- **Tags and detections**: none; output redirected to source.
- **Notes**: Streams 1MB chunks; skips files already ending .nowhitespace. Output volatile=True.

### user_defined_tagging

- **Section**: `analysis_module_user_defined_tagging`, class `UserDefinedTaggingAnalyzer` in `saq/modules/tag.py`, enabled by default.
- **ace4**: ported in `ace-mod-tag`. Through the core's `observable-tags` read (7.2), of migration 0042's `analysis.observable_tags`, keyed by type and value. Nothing in ace3 writes its `observable_tag_mapping` but its tests, so nothing in ace4 writes the table either: a site fills it, and tests/e2e/run does with SQL. `crates/ace-mod-tag/tests/differences.md` has the rest.
- **Pool**: lookup. One `observable-tags` read (7.2) per observable.
- **Step**: done.
- **Does**: For every observable, reads the tags analysts attached to that (type, sha256 of value) in ACE's database and adds them to the observable.
- **Input**: all (valid_observable_types None).
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: PyMySQL 1.2.0 (via get_db_connection pool).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: ace: observables, observable_tag_mapping, tags R (one SELECT per observable, tag.py:107-120).
- **Secrets**: ACE database credentials.
- **Network**: ACE MySQL database.
- **Reads outside the alert**: none.
- **Tags and detections**: adds the DB-mapped tags to the observable
- **Notes**: Creates an analysis for every observable, even with no tags. Errors are logged and re-raised (tag.py:127-129). High call volume (every observable in every mode): batch per root in ace4.

### configuration_defined_tagging

- **Section**: `analysis_module_configuration_defined_tagging`, class `ConfigurationDefinedTaggingAnalyzer` in `saq/modules/tag.py`, disabled by default.
- **ace4**: ported in `ace-core`. One of the core's hooks (`crates/ace-core/src/hooks.rs`, the owner's decision of 2026-11-10): it runs at the end of a pass in the core's hooks task, once the observable modifier's post rules match nothing more, and adds its detections on the root, `analysis.detections` with no observable (migration 0044). ace3's `tags:` section is the overlay's `hooks.configuration_defined_tagging.tags`, and the section's presence turns it on, as ace3 ships it disabled. A tag gets one root detection per root, ever, where ace3's dedup is the detection's equality. A detection in a detectable mode makes the root an alert, as ace3's does after the pass; the alert view lists them above the tree. tools/ace3/trees/make-trees enables it over ace3's own tags, which tests/e2e/site/overlay.yaml copies.
- **Pool**: core. Post-analysis over the whole tree, turning configured tag levels into detection points: core work. Disabled by default.
- **Step**: done.
- **Does**: In post-analysis, walks every node of the root and adds one root detection point per tag whose value in the config 'tags' section is alert, critical or warning.
- **Input**: all (execute_analysis is a no-op; work is in execute_post_analysis).
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: saq config 'tags' section (tag name -> level), read once at construction.
- **Tags and detections**: root detection point 'tag <tag> is configured to be alertable' (signature ALERTABLE_TAG 14564014-a223-440a-914f-03a1f322e1bf), once per tag
- **Notes**: Disabled by default. Never creates an analysis object. execute_post_analysis runs at the end of every pass; `BaseNode.add_detection_point` drops a detection equal to one the root has.

### site_tagger

- **Section**: `analysis_module_site_tagger`, class `SiteTagAnalyzer` in `saq/modules/tag.py`, enabled by default.
- **ace4**: ported in `ace-mod-tag`. The CSV's text is the module's `csv` setting in the site's overlay, read when the pool starts, where ace3 watches `data/etc/site_tags.csv`; the rows are read with `ace-pycompat`'s csv reader and globs translated with its `fnmatch`. Off until the overlay gives it a section: ace3 enables it but doesn't ship the file it needs. A regex is the `regex` crate's, so a row using what only Python's `re` has is skipped, as ace3 skips a row it can't load. `crates/ace-mod-tag/tests/differences.md` has the rest. Cacheable, keyed on its settings, its rows among them, but kept only when the overlay gives it a `cache_ttl`, since ace3's default config gives it none (decision 26).
- **Pool**: parser. Matches values against the site's rows; no network or database. Its CSV is overlay settings, as 5.14 allows.
- **Step**: done.
- **Does**: Tags any observable whose value matches a row of the site tags CSV (match by exact, glob, regex, CIDR or subdomain, optionally case-insensitive, per observable type).
- **Input**: all (valid_observable_types None; only types listed in the CSV do work).
- **Groups and modes**: groups common, file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: data/etc/site_tags.csv (csv_file; analyst-edited; columns o_types|...,match_type,ignore_case,value,tags|...; mtime-polled via watch_file and reloaded live).
- **Tags and detections**: adds the CSV row's tags to the observable
- **Notes**: extended_version mixes the CSV mtime_ns-size into the analysis cache key (tag.py:261-278), though no cache_ttl is set by default. Exclusions disabled (load_exclusions/is_excluded overridden, tag.py:235-239). A bad row is logged and skipped. Analysis created only on a match.

### zip_encryption_analyzer

- **Section**: `analysis_module_zip_encryption_analyzer`, class `ZipEncryptionAnalyzer` in `saq/modules/email/encryption/zip.py`, enabled by default.
- **ace4**: ported in `ace-mod-encrypted`. No zip2john, John or 7z: the email's candidates, from `ace_mod_msoffice::words_from_parts`, are tried with the zip crate as John checks them, an AES entry by its verifier and HMAC, each one a hash of its own whose last cracked password ace3 keeps, and ZipCrypto by the check bytes of up to eight of the smallest entries and the smallest one's CRC. The password is what ace3 reads from John's `--show` line, up to its first `:`. The extraction is `ace-mod-archive`'s 7z, which writes an empty file for an entry the password doesn't open. `john_bin_path` and `extract_timeout` aren't settings. `crates/ace-mod-encrypted/tests/differences.md` has the rest.
- **Pool**: parser. ace3 runs zip2john, John and 7z. As 4.11 did for Office, the task tries the email's wordlist itself, with the zip crate's ZipCrypto and AES, as `ace-mod-archive` already reads zips. 7.3 drops John: ace3 runs it only with this wordlist.
- **Step**: done.
- **Does**: For a zip with any encrypted entry, extracts its hash with zip2john, cracks it with John the Ripper using words from the carrying email, and extracts the archive with 7z using the cracked password.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body file (no wait_for_analysis).
- **Libraries**: html2text 2025.4.15 (via cracking.wordlist_from_email since 1998ca56; zip.py had its own copy of the old logic before).
- **Tools**: zip2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; 7z 25.01 `7z x -y -p<password> -o<abs dir> <file>` via run_sandboxed_tool, timeout extract_timeout=5s, write_dirs=[{file}.decrypted].
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this); 7z uses multiple threads
- **Writes**: {file}.hash; {file}.wordlist; {file}.hash.pot; {file}.decrypted/<members> (added as observables).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: /opt/tools/john-1.9.0-jumbo-1/run (john_bin_path).
- **Tags and detections**: 'encrypted_zip' tag on source; each extracted member gets detection point EMAIL_ENCRYPTED_DECRYPTED and extract_urls directive.
- **Notes**: Encryption check via stdlib zipfile flag_bits & 1. No default passwords; without an email body nothing is cracked. The wordlist is cracking.wordlist_from_email's since 1998ca56, which made an email with no body part an email (`email` true) where zip.py's own copy didn't, and a password not found no error. Password passed on 7z's command line. Members extracted before a 7z stop are still added (zip.py:249-255). Loop variable shadows _file (zip.py:261). Decrypted members not volatile.

### rar_encryption_analyzer

- **Section**: `analysis_module_rar_encryption_analyzer`, class `RarEncryptionAnalyzer` in `saq/modules/email/encryption/rar.py`, enabled by default.
- **ace4**: ported in `ace-mod-encrypted`. No rar2john, John or unrar: the body's candidates are tried with libunrar (the unrar crate, single-threaded), on what rar2john hashes: the headers when they're encrypted, RAR5's first encrypted file by its check value, or the RAR4 file rar2john's rule picks, decrypted, unpacked and its CRC checked. A RAR4 file or zip entry too large for the hash ace3 reads from rar2john or zip2john, 64 MiB, is ace3's `did not finish`. `unrar x` is libunrar's extraction, adding nothing unless every file extracts; when one doesn't the result is marked failed, where ace3's reason is `unrar exited with status <n>: <unrar's last line>`. A split archive's other volumes aren't there, as a task has one file. `john_bin_path` isn't a setting.
- **Pool**: parser. ace3 runs rar2john, John and unrar. The unrar crate `ace-mod-archive` uses takes a password, so the task tries the wordlist itself, as 4.11 did. 7.3 drops John: ace3 runs it only with this wordlist.
- **Step**: done.
- **Does**: For a RAR that rarfile says needs a password, extracts its hash with rar2john, cracks it with John the Ripper using words from the carrying email, and extracts it with unrar using the cracked password.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body parts (no wait_for_analysis).
- **Libraries**: rarfile 4.5 (RarFile.needs_password header check only); html2text 2025.4.15 (via cracking.wordlist_from_email since 1998ca56; rar.py had its own copy of the old logic before).
- **Tools**: rar2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; unrar 7.1.8 `unrar x -y -kb -p<password> <file> <abs dir>/` via run_sandboxed_tool, read_files=archive_volumes(), write_dirs=[{file}.decrypted], timeout = time_left().
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this); unrar may use threads
- **Writes**: {file}.hash; {file}.wordlist; {file}.hash.pot; {file}.decrypted/<members> (added as observables).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: /opt/tools/john-1.9.0-jumbo-1/run (john_bin_path); sibling volume files of a split archive (archive_volumes, saq/modules/file_analysis/archive.py:108).
- **Tags and detections**: 'encrypted_rar' tag on source; each extracted member gets detection point EMAIL_ENCRYPTED_DECRYPTED and extract_urls directive.
- **Notes**: Near copy of zip.py (diff is check, tools, messages). Its wordlist is cracking.wordlist_from_email's since 1998ca56, as zip.py's is. unrar used directly because rarfile would run unrar outside the sandbox (rar.py:239-241). UNRAR_WRITE_ERROR (5) keeps partial output; other non-zero exits return without adding files. No explicit extract timeout. Unsure whether rarfile.needs_password ever calls an external tool; this path only parses headers.

### pdf_encryption_analyzer

- **Section**: `analysis_module_pdf_encryption_analyzer`, class `PDFEncryptionAnalyzer` in `saq/modules/email/encryption/pdf.py`, enabled by default.
- **ace4**: ported in `ace-mod-encrypted`. No pdf2john.pl or John: libqpdf reads the trailer and `/Encrypt` when the empty password fails, and each candidate is checked as John's PDF format checks it, as the user password only, for revisions 2 to 6. A body with only the owner password, which pikepdf would open the file with, cracks nothing, as in ace3. The copy is libqpdf's write with pikepdf's `save()` defaults, byte for byte pikepdf's but for the second `/ID`, which ace3 takes from the clock and the port from the content. `john_bin_path` isn't a setting.
- **Pool**: parser. ace3 runs pdf2john.pl and John. libqpdf, which `ace-mod-pdf` links, opens a PDF with a password, so the task tries the wordlist itself, as 4.11 did. 7.3 drops John: ace3 runs it only with this wordlist.
- **Step**: done.
- **Does**: For a PDF that pikepdf cannot open without a user password, builds a wordlist from the carrying email, extracts the hash with pdf2john.pl, cracks it with John the Ripper and saves a decrypted copy.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body file (no wait_for_analysis).
- **Libraries**: pikepdf 10.17.0 (qpdf; open, PasswordError, save); html2text 2025.4.15 (via cracking.wordlist_from_email).
- **Tools**: perl <john_bin_path>/pdf2john.pl <file> via run_sandboxed_tool, read_dirs=[john run dir] (uses john's bundled ExifTool perl lib); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; hash written as 'pdf:<$pdf$...>' with login='pdf'.
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this)
- **Writes**: {file_name}.decrypted via root.create_output_file (added as observable); pdf.hash, wordlist, pdf.hash.pot in a TemporaryDirectory under get_temp_dir() (removed).
- **yara_meta**: type=document.pdf (on the decrypted file).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: /opt/tools/john-1.9.0-jumbo-1/run (pdf2john.pl and its lib).
- **Tags and detections**: 'encrypted_pdf' tag on source; decrypted file tagged 'decrypted_pdf' with detection point EMAIL_ENCRYPTED_DECRYPTED.
- **Notes**: Owner-password-only PDFs open without a password and are skipped (pdf.py:69-73). No default passwords; empty wordlist ends analysis before pdf2john. pdf2john path prefix replaced by 'pdf:' so ':' in names cannot break john (pdf.py:111-113). On any exception sets analysis.error and re-raises (pdf.py:134-138).

### alert_added_to_event

- **Section**: `analysis_module_alert_added_to_event`, class `AlertAddedToEventAnalyzer` in `saq/modules/event.py`, disabled by default.
- **ace4**: not yet. Left out by the owner's decision of 2026-11-19: it is disabled in ace3 and marked for removal there.
- **Pool**: core. Moves a dispositioned alert to the event mode when it's in an event: a database read and a mode change, which is the core's. Disabled by default and marked `TODO trash this` in ace3 (`saq/modules/event.py:8`), and no step names it: the owner decides whether it ports.
- **Step**: owner.
- **Does**: In post-analysis of a dispositioned alert, switches the root's analysis mode to 'event' when the alert is mapped to an event in the database.
- **Input**: none (post-analysis only; execute_analysis is a no-op).
- **Groups and modes**: groups none; modes dispositioned.
- **Depends on**: none.
- **Libraries**: SQLAlchemy 2.1.6.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: ace: event_mapping joined to alerts, R.
- **Secrets**: ACE database credentials.
- **Network**: ACE MySQL database.
- **Reads outside the alert**: none.
- **Tags and detections**: none; sets root.analysis_mode = event
- **Notes**: Disabled by default and marked '# TODO trash this' (event.py:8). Runs in dispositioned mode only. Likely not worth porting.

### svs_yara_sample_capture

- **Section**: `analysis_module_svs_yara_sample_capture`, class `YaraSampleCapture` in `saq/modules/svs.py`, enabled by default.
- **ace4**: ported in `ace-mod-svs`. PLAN.md 7.10 batch 2 ported it: a lookup module on each file of a dispositioned root, which the core queues again on each disposition, as ace3 reruns it on each dispositioned pass (`Orchestrator::stop_for_disposition`, for a dispositioned module that stores no result). It reads the alert's disposition and class, its unreviewed test run, the file's paths and detections, its deletion and its captures with `svs-capture-state` (7.2), finds a candidate per YARA detection with a rule uuid of 1 to 36 characters, with its scan result from the YARA result that comes with the task (`Module::DEPENDS_ON`) as the match record, and hands them to the core as its `svs-capture` write, which lands with its end and stores no result. The core copies the file from the root's files into the bucket's `svs_samples` pool, held by the capture, and writes migration 0048's row with the match record in it (`ace_core::svs::samples`). What differs from ace3: the record is the row's, as 2.27's QA matches keep theirs, where ace3 puts it in its CAS pool; the bucket is shared, so there's no node; the version recorded is yara-x's; the rule's content hash is left NULL for batch 3, since the ruleset records none per rule; and the same bytes under two names are one observable here, so one candidate and one vote per rule. ace3's module creates no analysis and changes nothing in the tree, so there are no reference dumps to compare: its output is its database rows and CAS objects, which `run_module.py`'s single-module run has no alert row, SVS tables or CAS pool for. Its cases are `test_capture.py`'s, ported in `ace-mod-svs` and `ace-service`'s `tests/service.rs`, and its read and write have the lease API's tests (`reads.md`).
- **Pool**: lookup. Database and bucket writes at disposition; its git calls are for the rule inventory, which ace4's ruleset already records.
- **Step**: done.
- **Does**: In post-analysis of an alert dispositioned tp or fp (and not attributed to an unreviewed SVS test run), stores every file a uuid'd YARA rule matched, plus its match record, in the svs_samples CAS pool and records it in svs_yara_captures.
- **Input**: none (post-analysis over the root's YARA detection points on file observables).
- **Groups and modes**: groups none; modes dispositioned.
- **Depends on**: needs the YARA scanner's detection details (rule_uuid, sha256, namespace) and its YaraScanResults_v3_4 analysis (scan_results) on file observables.
- **Libraries**: SQLAlchemy 2.1.6; yara-python 4.5.4 and yara_scanner v3.0.0 (only __version__ recorded); plyara 2.2.8 (yara rule inventory parse, for rule content hash); zstandard 0.25.0 (unsure: only if the CAS pool compresses).
- **Tools**: git via subprocess.run (rev-parse --show-toplevel, remote URL, rev-parse HEAD) through saq.signatures.git_context.GitContext.resolve when the yara rule inventory is (re)built for _rule_content_hash (saq/svs/capture.py:210-217, saq/signatures/loaders/yara.py:332, saq/git.py:53-110).
- **Writes**: CAS pool svs_samples: the matched file (by sha256) and the serialized match record (by its digest), under <DATA_DIR>/<local_root>/svs_samples for the default local backend.
- **yara_meta**: reads: the file observable's yara_meta_tags (stored in the capture row for replay).
- **ACE's data**: ace: alerts R (disposition), svs_attributions + svs_runs R (unreviewed_run_condition); ace: svs_yara_captures R/W (insert pending, update stored/missing; private transactions); ace: svs_sample_deletions R (is_deleted, checked before and after); ace: cas_objects, cas_holds, cas_purges R/W (CAS index via pool.put/hold/stat/release).
- **Secrets**: ACE database credentials; SAQ system encryption key (svs_samples pool is encryption: system in saq.default.yaml:205-210).
- **Network**: ACE MySQL database; CAS backend (local filesystem by default; a multi-node site configures a shared backend).
- **Reads outside the alert**: YARA rule source under service_yara.signature_dir (every .yar/.yara, parsed by plyara, cached per process for svs.samples.inventory_refresh_seconds); the alert's matched files (full_path) to put into the pool.
- **Tags and detections**: none
- **Notes**: Runs in dispositioned mode; idempotent per (alert, sha256, rule_uuid); 'missing' rows retried on the next dispositioned pass. A file deleted from SVS after capture began is abandoned and purged (capture.py:242-247). Side effect outside the alert: writes into a shared CAS pool that outlives alert archival. Rules without uuid or with uuid longer than SIGNATURE_UUID_MAX_LENGTH are skipped. Default local backend is node-local, so multi-node needs a shared backend (saq.default.yaml ~201-206). The svs_samples pool is encrypted (encryption: system), retention: held, shared: false by default.

### svs_alert_tagger

- **Section**: `analysis_module_svs_alert_tagger`, class `SVSAlertTagger` in `saq/modules/svs.py`, enabled by default.
- **ace4**: ported in `ace-core`. One of the core's hooks (`crates/ace-core/src/hooks.rs`, the owner's decision of 2026-11-14, ace3 #842): at the end of a pass in a mode that lists it, once the observable modifier's post rules match nothing and `configuration_defined_tagging` has added its detections, the hooks task judges the root's SVS context once (`crates/ace-core/src/svs/attribution.rs`'s `judge`) and writes everything that follows from that one judgment in its transaction: the tags below on the root (`analysis.roots.tags`), a root detection per marker that doesn't agree with its run, and also what ace3's `svs_marker` alert router writes by judging the alert again, twice: the attributions of the alert's detections to test runs (`svs.attributions`, each change in its run's event log, its result marked stale, a reviewed run flagged changed) and the alert's maintenance record (`svs.maintenance_alerts`). Nothing judges an alert again: batch 7's router and everything else read these rows. Markers in module output are read from the results' details at the end of the pass, where ace3's executor saves them on the root as each module returns; the marker rule (`crates/ace-core/src/svs/marker_rule.rs`) is a namespace the ruleset builder adds to every ruleset. The gate is one query in the hook's transaction, with no cache, so with no run registered or in its window the hook costs that query. Bounded: only rows holding marker-shaped text are read, at most 1,000 of each kind, 200 markers from module output, 256 markers judged, 256 hosts an event, 500 runs and 500 windows on those hosts, and a root with more than 10,000 detections isn't judged. A marker that doesn't agree stays one: its own detection carries the marker, as ace3's does. Before the core queues the hooks task on this hook's account alone (a mode with no other hook), it asks the same gate (`queue::check_completion`, the owner's decision of 2026-11-14, 7.10 batch 7b): a pass with no run registered or inside its attribution window, and no maintenance window open lately, queues no hooks task and ends. A lock orders the gate's reads against the two writes that open it (a registration and a maintenance window), so a run registered while a pass ends is either seen by that pass or registered after it ended.
- **Pool**: core. It edits the root (its tags and detections) and writes SVS's tables, so it runs beside the tree as a hook, with no read to serve: 7.2's planned `svs-attribution` read is dropped.
- **Step**: done.
- **Does**: In correlation-mode post-analysis, evaluates SVS test-run attribution for the alert (markers in the tree, hosts, event time vs registered runs and maintenance windows) and tags it svs_test, svs:marker_mismatch (with detection points) or svs:maintenance.
- **Input**: none (post-analysis over the root).
- **Groups and modes**: groups none; modes correlation.
- **Depends on**: runs before the svs_marker alert router's POST_ANALYSIS stage in the same pass and must judge the same way (svs.py:80-85).
- **Libraries**: SQLAlchemy 2.1.6.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: ace: alerts R (insert_date); ace: svs_runs, svs_maintenance_windows R (attribution_open gate, cached svs.attribution.gate_cache_seconds); ace: svs_runs, svs_test_hosts, svs_maintenance_windows, svs_attributions R (evaluate: resolve_markers, runs_overlapping, maintenance_windows_overlapping, _existing).
- **Secrets**: ACE database credentials.
- **Network**: ACE MySQL database.
- **Reads outside the alert**: none.
- **Tags and detections**: root tags svs_test (removed when no longer fully attributed), svs:marker_mismatch (never removed) plus one detection point per mismatched marker (signature SVS_MARKER_MISMATCH 9b90e9be-67e7-402c-b4f6-e7be758ee260), svs:maintenance (removed when no longer in a window)
- **Notes**: Writes nothing to the DB (evaluate is read-only, attribution.py:737-741); the router writes svs_attributions. Gate short-circuits when no run is open. Marker discovery walks every string in the tree (tree_sightings).

### dhash

- **Section**: `analysis_module_dhash`, class `DHashImageAnalyzer` in `saq/modules/dhash.py`, enabled by default.
- **ace4**: ported in `ace-mod-files`. It runs on `ace-dhash`, which opens, decodes, converts and resizes images as Pillow 13 does, ported, with libjpeg-turbo's decoder: it matches Pillow on 1,684 of 1,709 cases; the rest are decoders not ported (AVIF, JPEG 2000, EPS, DDS, BLP, ICNS, TIFF with JPEG or G4), which the module skips where ace3 hashes, and five corrupt lossy WebP and JPEG files. The reference images are read and hashed once when the module starts, from its `source_dir` setting, since a contained task can't read the directory, and are scored in name order where ace3 takes `os.listdir`'s.
- **Pool**: parser. Decodes an image in the task's process; the reference images are read before containment.
- **Step**: done.
- **Does**: For an image with the dhash directive, computes a 16x16 difference hash and compares it with each .png in the analyst data repo's dhash directory, raising a detection when similarity reaches that image's .score threshold.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: Pillow 13.0.0.
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: <analyst_data_dir>/dhash/*.png and *.png.score (analyst-maintained reference images and thresholds).
- **Tags and detections**: Detection point 'matches <image> N% (threshold T%)' (signature DHASH_IMAGE_MATCH) on the file per reference image over threshold.
- **Notes**: required_directives [dhash]. Re-hashes every reference image on every call (no cache). Transparent images are composited on white before hashing. Scores for every reference image are recorded in details.

### observable_detection

- **Section**: `analysis_module_observable_detection`, class `ObservableDetectionAnalyzer` in `saq/modules/observable_detection.py`, enabled by default.
- **ace4**: ported in `ace-mod-tag`. The observables enabled for detection are 5.14's `observable_detection` list, typed by observable type, which the core adds to each task as it is when the task is leased (`Module::LISTS`), where ace3 reads a Redis copy of its `observable_detections` table that `ace observables export` rewrites every minute. An entry matches the observable's own type and its value exactly, as ace3's `<type>:<value>` key does, and an expired one matches nothing. Analysts edit it through ace3's `detection` router, `/api/observables/v1/detections` (`ace-service`'s `detection`, under `detection:read` and `detection:write`), and its admin page, `/admin/detection`. ace3's export of the same detections as YARA rules, whose `$obsd_` strings the YARA module resolves, isn't built (PLAN.md 7.6). `crates/ace-mod-tag/tests/differences.md` has the rest.
- **Pool**: lookup. Reads the `observable_detection` list (5.14), which comes on the lease; it connects to nothing.
- **Step**: done.
- **Does**: For every observable, checks whether '<type>:<value>' is flagged for detection in the Redis cache maintained by 'ace observables export' and, if so, adds a detection point and a detect_<type> tag.
- **Input**: all (valid_observable_types None).
- **Groups and modes**: groups common; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: redis 6.4.0 (via saq.redis_client.get_redis_connection).
- **Tools**: none.
- **Writes**: none.
- **yara_meta**: none.
- **ACE's data**: Redis: Redis 'local' config (redis_local), DB 4 (REDIS_DB_FOR_DETECTION_A): GET '<type>:<value>' per observable; populated by 'ace observables export' (saq/observables/export/redis_cache.py). One connection per module instance, health_check_interval 30..
- **Secrets**: Redis (redis_local) username/password.
- **Network**: local Redis server.
- **Reads outside the alert**: none.
- **Tags and detections**: detection point 'Observable <type>:<value> is enabled for detection' (signature OBSERVABLE_FLAGGED 97a0bcb8-1bde-4cf0-8fa2-72d6343c6458) and tag detect_<type>
- **Notes**: Runs on every observable in every mode; creates an analysis for each. The flag source of truth is the ACE DB (observables with for_detection), exported to Redis by a separate job.

### phishkit_analyzer

- **Section**: `analysis_module_phishkit_analyzer`, class `PhishkitAnalyzer` in `saq/modules/phishkit.py`, enabled by default.
- **ace4**: ported in `ace-mod-scanners`. The module runs on the parser pool; a URL needs `crawl` (`Module::REQUIRED_DIRECTIVES_BY_KIND`), so the core queues it when another module adds one, as ace3's `custom_requirement` lets it run then; a file renders only in correlation mode, which its declaration reads from the lease's gate. Its results are kept in the analysis cache for ace3's 6 hours, keyed on the observable, its settings and the image id of its scan's container (`Cache::scanners`), with its files under `phishkit/<job id>/` (`CachePaths::Under`); it doesn't depend on file_type, whose mime type its declaration reads from the file's type, so a crawl URL is no longer held back waiting for a file_type result a URL never gets. Its first run asks for a phishkit scan, `scanner.py <url>` or `--file <path>` with the extension the file's type has (the manager's `_correct_file_extension`), and its task waits for it as a delayed task, up to `max(scanner_timeout, 60) * 2 + 30` seconds, as ace3's `delay_analysis`; the scanner pool runs `ace4-phishkit`, ace3's image built from ace3's sources, with the manager's `--init`, `--stop-timeout 5`, 2 GiB of memory and swap and 2 CPUs, on Docker's default network or `ACE4_PHISHKIT_NETWORK`'s, and stops it with SIGTERM at the deadline so it flushes what it has, as the manager does. Its next run reads the output, contained: the files, `requests.json`, the bodies corpus and `metrics.json`, and makes the manager's `proxy.json`. Matches ace3's dumps on 8 inputs, from a real file scan and URL scans made from it (`crates/ace-mod-scanners/tests/phishkit_differences.md`). Not carried over: proxies (ace3's named proxy configuration, its credentials, and the manager's retry without the proxy, which parses `requests.json` and so would be this module's next run), fluent-bit's metrics events, the analysis cache, and the manager's per-scan copy of `etc/phishkit_config.yaml`: the scanner reads the copy its image was built with, and `deny_crawl_url_patterns` is the module's setting. Its trees aren't compared: make-trees doesn't enable it, since it would load the samples' URLs on the internet, and tests/e2e/site/overlay.yaml keeps ace4's from loading any; tests/e2e/run renders a page through it instead (PLAN.md 7.7). Not cacheable in ace4 as it is, though ace3 keeps its results 6 hours (decision 26): its lease carries its tree and file_type's result, which the analysis cache's refusal rule refuses, and its key would need the scanner image's id, which the scanner pool doesn't report (docs/decisions/0004, *As built*).
- **Pool**: scanner. Drives Chrome against attacker URLs in a container a Celery manager starts; 7.7's scanner pool replaces the manager, with a delayed task while it runs.
- **Step**: done.
- **Does**: Sends a URL with the crawl directive (or, in correlation mode, an HTML/PDF file with the render directive or an email attachment) to the phishkit Celery service, which loads it in headless Chrome (SeleniumBase UC mode) in a throwaway container, then adds the screenshots, rendered DOM, captured requests/bodies and downloads as file observables and the requested and captured URLs as url observables.
- **Input**: url; file.
- **Groups and modes**: groups correlation, file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: config: file_type; file_type (config dependency; FileTypeAnalysis.mime_type for valid_mime_types text/html, application/pdf); a url needs directive crawl and a file needs directive render (from other modules) via custom_requirement.
- **Libraries**: celery[redis] 5.6.3 (imports phishkit.phishkit; scan_url/scan_file .delay, AsyncResult.ready/get); redis 6.4.0 (result backend); fluent-logger 0.11.1 (fluent.sender.FluentSender metrics); urlfinderlib 0.27.1 (find_urls over captured bodies, URL normalization); PyYAML 6.0.3 (deny_crawl_url_patterns from the phishkit YAML); pydantic 2.14.1.
- **Tools**: none started by ACE; the phishkit manager container (docker:dind, Alpine, python venv with unpinned celery[redis], pydantic, pyyaml, python-magic) runs two Celery workers (worker_launcher.py: scan queue 'celery' and control queue 'phishkit_control' solo pool) and per scan `docker run --rm --init --name phishkit-scan-<job> --label phishkit.* --memory/--memory-swap --cpus --stop-timeout 5 -v <stack>_phishkit:/phishkit ${ACE3_PHISHKIT_IMAGE_URL:-phishkit} /opt/venv/bin/python /opt/app/scanner.py <url | --file path> --output-dir ... [--proxy ...] [--config ...]` via Popen, with a retry without proxy on proxy errors; also docker inspect/ps/stop/kill/rm (reaper thread kills orphans older than reaper_max_age_seconds); scanner image: ubuntu 22.04 + google-chrome-stable (current at build) + chromedriver, Xvfb, ffmpeg; python seleniumbase, pyautogui, selenium-recaptcha-solver (git), pillow, opencv-python, pyyaml (all unpinned).
- **Threads and children**: Not in ACE's process: the manager starts docker CLI processes; each scan container runs Chrome (many child processes), chromedriver and Xvfb.
- **Writes**: phishkit/<job_id>/<relative path> in the alert storage for every result file except exit.code/std.out/std.err/metrics.json/proxy.json (e.g. screenshot.png, pre_bypass_screenshot*.png, dom.html, requests.json, response_bodies.txt, script.js, downloads); a temp dir (create_temporary_directory) as analysis.output_dir receiving copies of the result files; not removed by this module; /phishkit/input/<uuid>/<file name> on the shared volume for file scans (aged out by the manager's maintain_files).
- **yara_meta**: type=document.html.phishkit (on every output file); reads: type=email.attachment (lets a file without the render directive through).
- **ACE's data**: Redis: Celery result backend redis://ace3:<password>@redis:6379/7 built in phishkit/phishkit.py; AsyncResult.ready() polled every 3 s.
- **Secrets**: RabbitMQ credentials (ACE config `rabbitmq` username/password applied to the app's broker_url on each call); Redis password (/auth/passwords/redis, read by phishkit/phishkit.py at import); proxy credentials of the named proxy config (resolve_secret) passed to the scanner as --proxy user:pass@host:port; redacted from stdout/stderr/proxy.json.
- **Network**: Celery/RabbitMQ (ACE rabbitmq config) and Redis db 7; fluent-bit forward input fluent-bit:24224 (tag phishkit-metrics: scan_dispatched, scan_outcome, cache_served, per-domain stats); the scanner container browses the internet directly or via the configured HTTP/SOCKS proxy (no --network none); recaptcha solver traffic: unsure.
- **Reads outside the alert**: etc/phishkit_config.yaml (config_path; analyst-editable, watched with watch_file to reload deny_crawl_url_patterns; content sha256 in extended_version; the manager reads it from /opt/ace/<config_path> and copies it to the shared volume per scan).
- **Tags and detections**: No tags or detections. Adds url observables with display types 'Phishkit Request URL' (MARKER URL lines and requests.json requests), 'Phishkit Captured URL' (find_urls over each captured body) and 'Phishkit Document URL'; dom.html gets downloaded_from the final document URL; script.js gets directive extract_urls. Output files: exclude_analysis(self) and PDFAnalyzer; screenshots exclude OCRAnalyzer when the top-level response was JS/CSS/JSON/text; response_bodies.txt excludes HTMLJavaScriptExtractor.
- **Notes**: Delayed analysis: dispatch returns delay_analysis(5 s, timeout (max(scanner_timeout,60))*2+30 s), continue_analysis polls every 3 s with ready() before get(timeout=1) (phishkit.py:612-628). Analysis cache opt-in: cache_ttl 21600 (6 h), extended_version = phishkit YAML sha256 + scanner image id from the scanner_image_id control task (cached 600 s success / 60 s failure in-process, 5 s probe timeout, saq/phishkit.py:67); partial/timeout results cached on purpose; on_cache_hit emits cache_served to fluent-bit. File scans only in correlation analysis mode. deny_crawl_url_patterns are substring matches on the lowercased URL. Exit code 143 or metrics.interrupted => 'partial scan'. Manager (phishkit/phishkit.py, 835 lines): tasks ping, scanner_image_id, scan_url, scan_file (fixes file extension via libmagic), maintain_files; resource limits/reaper/proxy_fallback from the YAML; containers labelled with ACE_STACK so the reaper only kills its own. The client uses ACE's rabbitmq config but the manager hardcodes pyamqp://ace3@rabbitmq// (phishkit.py:627). Needs /var/run/docker.sock in the manager (host-root equivalent).

### clicker_detection_splunk

- **Section**: `analysis_module_clicker_detection_splunk` (instance `clicker_detection_splunk`), class `SplunkClickerDetectionAnalyzer` in `saq/modules/clicker_detection.py`, disabled by default.
- **ace4**: ported in `ace-mod-splunk`. It's `clicker.rs` there, a module of its own, on the Splunk module's client and delay loop (1.28), reading ace3's `clicker_detection.yaml` from `config_path`. A URL matches itself alone: urlfinderlib's child URLs come with 7.5's `url_extraction`. Its searches' time ranges are around the observable's time, else the root's event time, which its task carries (`Module::READS_EVENT_TIME`, decision 27), else its first run's clock, as ace3's. Off unless the overlay has a section for it. tests/e2e/site/overlay.yaml's Splunk instance, which had this name, is `proxy_domain_splunk`, joining the correlation group with `groups`. `crates/ace-mod-splunk/tests/clicker_differences.md` has the rest.
- **Pool**: lookup. Splunk searches with delayed analysis. Splunk's client stays in this workspace (7.8).
- **Step**: done.
- **Does**: For url/fqdn observables carrying the clicker_detection directive, runs each analyst-configured Splunk search (with every urlfinderlib child-URL permutation of the value) to find users who clicked/visited it, records ClickerEvents, and on a configured hit adds a detection point and/or schedules a crawl.
- **Input**: url; fqdn (config valid_observable_types; required_directives clicker_detection).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: on a url hit with crawl_clicked_url it adds the crawl directive and clears a skipped PhishkitAnalysis sentinel so phishkit runs (analyzer.py:359-379).
- **Libraries**: splunk-sdk 3.0.1 (splunklib.client/binding/results); requests 2.34.2 (exceptions only); urlfinderlib 0.27.1 (child URL permutations); PyYAML 6.0.3 (clicker config); pytz 2026.5 (timezone for timespec).
- **Tools**: none.
- **Writes**: optional Splunk performance CSVs <DATA_DIR>/<performance_logging_directory>/splunk_sid_lookup_%d%m%Y.csv and splunk_performance_%d%m%Y.csv when that splunk setting is set (saq/splunk.py:770-805).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: Splunk API credentials (username/password or token via resolve_secret, splunk config api_name 'default'); proxy credentials if splunk.proxy is set.
- **Network**: Splunk REST API (async search jobs: create, poll, fetch, delete), optionally via the configured HTTP CONNECT proxy.
- **Reads outside the alert**: etc/clicker_detection.yaml (config_path, analyst-edited, source key 'splunk'; mtime-polled via watch_file and reloaded live).
- **Tags and detections**: detection point 'URL clicker identified via <search> (<users>)' (signature URL_CLICKER a764126b-443d-4991-a554-72d86125382d) when on_hit.add_detection_point; directive crawl on url observables; observables extracted per search's observable_mapping; fqdn hits add clicked url observables (not crawled)
- **Notes**: Disabled by default. Uses delayed analysis: each search is an async Splunk job; delay_analysis with async_delay until query_timeout, then records 'timed out' as the analysis's error (`Analysis.error`, `query_error` until ace3 `41d44392`) so silence is not read as 'no clicks'. The plan of searches is snapshotted in details (clicker_plan/clicker_index) to survive resumes. custom_requirement makes it a no-op when the config has no enabled search for the source+type. Inherits BaseAPIAnalyzer (saq/modules/api_analysis.py) correlation_delay and max_result_count defaults from api_defaults.

## site_ace

PLAN.md 7.1 gives a site's modules the same inventory in a site's Rust workspace (2.32), which isn't on this machine (`~/Development/site/site_port`), so that half is blocked. ace3's checkout holds the site_ace Python repository under `integrations/site_ace` (at `59064f6`). It could be read here, but its inventory stays out of this repository: it describes a site's own systems, and the plan puts it in the site's workspace. It's left for 7.8, which ports those integrations there.

What's there, by count: 34 `analysis_module_*` sections ace3's config doesn't have. 20 are in the integrations' own config files (9 in `ace_endpoint_vendor`, 4 in `ace_mail_api`, 4 in `ace_vt`, 2 in `ace_example_sandbox`, 1 in `ace_wiz`; `ace_rapid7` and `ace_intel_feed` have none) and 14 in a site's own: 5 of its own Python modules, 2 on `ace_endpoint_vendor`'s LogScale classes and 7 instances of ace3's `SplunkAPIAnalyzer`, which would run on `ace-mod-splunk` as overlay instances. So 27 are code to port and 7 are Splunk queries. site_ace also overrides the settings of 11 of ace3's sections, keeping their classes, which this inventory's entries cover.

