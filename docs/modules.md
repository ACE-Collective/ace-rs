# Module inventory

PLAN.md 7.1. The 90 `analysis_module_*` sections of `ace3/etc/saq.default.yaml` at ace3 `f72f8946`, with what each module does, where it runs in ace4 and which step ports it. The same 90 sections were there at `141a60a2`, the commit PLAN.md was written against. Each entry comes from the module's code, not just its config: the class, the helpers it calls and the base classes they inherit. It's the plan for the rest of phase 7, so when a step ports a module, change its row.

`tools/ace3/modules/check` reads the sections at the head of ace3's checkout and fails if this file misses one, names one that's gone, or disagrees with ace3 about a module's class, groups or modes. It also checks that every module has a pool and a step from the lists below, and that the ported modules are the ones `crates/ace` registers. tests/e2e/run runs it.

Versions are those of ace3's image: Python packages from `installer/requirements-pinned.txt` and the Dockerfile's git installs, Debian trixie's packages from `dpkg-query` in ace3's dev container. "Writes" names the files a module adds to the alert, with `{file}` for the analyzed file's path; YARA rules match on those names and on the `yara_meta` types, which reach the scanner as its `meta_tags`.

## Pools

| Pool | Means |
|---|---|
| parser | a contained task process with one thread, no network and no database: it parses attacker bytes or values |
| lookup | the async network pool: DNS, HTTP APIs, and ACE's own data through the internal API (7.2), parsing nothing hostile |
| core | work over the whole tree that edits other nodes or the root's mode, which only the core's orchestrator can do |
| sandbox | an external tool in ACE's sandbox runner (`ace3/saq/sandbox/`), which 7.3 brings; tshark is already placed there |
| scanner | 7.7's pool that starts a scanner image per file and reads back what it wrote |
| 7.3 | starts an external program, and 7.3 decides between a crate, the tool as its own contained task process, and the sandbox runner |

## Counts

| Pool | Modules | Ported |
|---|---|---|
| parser | 54 | 9 |
| lookup | 17 | 1 |
| core | 3 | 0 |
| sandbox | 3 | 0 |
| scanner | 2 | 0 |
| 7.3 | 11 | 0 |
| all | 90 | 10 |

| Step | Modules |
|---|---|
| done | 10 |
| 7.4 | 8 |
| 7.5 | 62 |
| 7.6 | 5 |
| 7.7 | 2 |
| 7.10 | 2 |
| owner | 1 |

No ace3 module goes to 7.8 or 7.9: 7.8's integrations are a site's (below), and remediation and file collection are services, not modules. "done" is the ten modules phases 1 to 4 ported. "owner" is a module no step names.

## 7.5's batches

In order. Batches 10 to 13 wait for 7.3's decisions about their tools.

1. **URLs and indicators in text**: `url_extraction`, `ioc_extraction`. Starts with `url_extraction`, as 7.5 says, which hits its 15-second cap on multi-line blobs. Until file_type is ported it reads the mime type the core gives every input file.
2. **File identity**: `file_type`, `file_hash_analyzer`, `ssdeep`, `lnk_parser`, `binary_file_analyzer`, `x509_analyzer`, `dhash`. file_type first: many later modules read its result, its tags and its `yara_meta` types.
3. **Observable values**: `command_line_analyzer`, `file_location_analysis`, `file_path_analysis`, `network_identifier`, `parse_url`, `idna_analyzer`, `email_address_fqdn_analyzer`, `protected_url_analyzer`. Strings in, observables out; no files.
4. **HTML**: `html_data_url_extraction`, `har_extraction`, `html_js_extraction`, `mhtml`. HTML, MHTML and HAR files, with the DOM snapshots 7.7's js-deobfuscator reads.
5. **Office containers**: `onenote_extraction`, `officeparser3`, `office_xml_rel`, `xml_binary_analyzer`, `xml_plain_text_analyzer`, `extracted_ole_analyzer`, `hidden_mime`, `active_mime`. OLE streams, Office XML, OneNote and MIME blobs, on `ace-mod-oletools`' olefile port.
6. **RTF and scripts**: `microsoft_script_encoding_analysis`, `extracted_rtf_analyzer`, `vbscript_analyzer`, `nowhitespace_analyzer`. Checks and transforms of RTF and script files.
7. **Encrypted files**: `zip_encryption_analyzer`, `rar_encryption_analyzer`, `pdf_encryption_analyzer`. After 7.3 records John's decision: the email's wordlist tried in the task, as 4.11 did for Office.
8. **Email tree**: `mailbox_email_analyzer`, `lure_url_analyzer`, `email_conversation_attachment_analyzer`, `email_conversation_link_analyzer`. Modules that read the email's analysis; the two conversation modules after 7.4's frequency analyzer.
9. **Email archive**: `email_archiver`, `encrypted_archive_analyzer`, `url_email_pivot_analyzer`, `message_id_analyzer_v2`. Brings ace3's `email` router (5.6) and the `daily/partitions` task's archive half (6.7). Lookup modules, on 7.2's endpoints.
10. **PDF and image text**: `ocr`, `qrcode`, `exif`, `pdftotext`. After 7.3, the tools that turn PDFs and images into text YARA scans.
11. **Executables**: `java_class_decompiler`, `upx`, `autoit`, `de4dot`, `ilspy`. After 7.3: unpackers and decompilers.
12. **macOS images**: `dmg_analyzer`, `cve_2021_30657_analyzer`. After 7.3.
13. **Packet captures**: `pcap_analyzer`, `pcap_dns`, `pcap_tls`, `pcap_http`, `pcap_files`, `pcap_tls_decryption`, `tls_keylog`. On ACE's sandbox runner with tshark (7.3).

7.4 ports, in this workspace: `fqdn_analyzer`, `nrd_analyzer`, `snort_signature_analysis_v1`, `user_analyzer`, `email_conversation_frequency_analyzer`, `email_thread_analyzer`, `email_logger`, `clicker_detection_splunk`. The brocess modules (`email_logger` writes what `email_conversation_frequency_analyzer` and `email_thread_analyzer` read) go together, after 7.2's endpoints.

## What 7.2 serves

Modules that read or write ACE's own data (`get_db(`, `get_db_connection(` and Redis), which in ace4 go through the internal API. Some reads aren't `get_db(` calls in the module's own file: they're in helpers such as `saq/modules/email/conversation.py` and `saq/email_archive/`.

Not here: `rdap_analyzer` and `nrd_analyzer` use ace3's analysis result cache, which is the engine's, not the module's, and which ace4 doesn't have (6.7); `nrd_analyzer`'s domain list is a SQLite file on the node, which 6.7's `nrd-refresh` keeps; the Redis of `javascript_deobfuscation` and `phishkit_analyzer` is Celery's, which 7.7 replaces.

| Module | Reads and writes |
|---|---|
| `email_archiver` | email_archive: archive (W, INSERT IGNORE; R archive_id); email_archive: archive_index (W, field message_id and url hashes); email_archive: email_history (W, message_id/recipient); email_archive: archive_server (R/W at initialize_email_archive/register, not in this module) |
| `snort_signature_analysis_v1` | Redis: Redis 'default' config (get_config().redis host/port/user/password), DB 1 (REDIS_DB_SNORT): GET '<sid>:<rev>' per observable. The index (keys '<sid>:<rev>' = rule line, 'suricata_rules_lastmtime', lock 'suricata_rules_lock' with 30s ex/nx) is built by 'ace signatures build-db' (saq/cli/commands/signatures.py:202-230) from data/snort/snort.rules, not by the module. A new redis.Redis connection is created per call (snort.py:110-120). |
| `email_conversation_frequency_analyzer` | brocess: smtplog (R, SUM(numconnections) by source, and by source+destination) |
| `email_thread_analyzer` | brocess: email_thread_message (R: anchor by message_id_hash, messages by thread_id_hash, same-subject threads by normalized_subject_hash); brocess: email_thread_domain (R: participants by thread_id_hash, subject-linked domains) |
| `url_email_pivot_analyzer` | email_archive (primary plus every database_email_archive_* section): archive_index (R, COUNT(DISTINCT archive_id) WHERE field='url' AND hash=UNHEX(SHA2(url,256))) |
| `email_logger` | brocess: smtplog (W, INSERT ... ON DUPLICATE KEY UPDATE numconnections+1 per envelope recipient); brocess: email_thread_message (W record_thread; R COUNT by thread for telemetry); brocess: email_thread_domain (W record_thread; R established domains by thread or same-subject) |
| `yara_scanner_v3_4` | ace: observable_detections (ObservableDetection) by id from $obsd_<id> strings, R; ace: observables (Observable) by id from legacy $obs_<id> strings, R |
| `message_id_analyzer_v2` | email_archive (primary section): archive JOIN archive_server JOIN archive_index (R, by message_id hash) - called twice (email_is_archived then iter_archived_email) |
| `user_defined_tagging` | ace: observables, observable_tag_mapping, tags R (one SELECT per observable, tag.py:107-120) |
| `alert_added_to_event` | ace: event_mapping joined to alerts, R |
| `svs_yara_sample_capture` | ace: alerts R (disposition), svs_attributions + svs_runs R (unreviewed_run_condition); ace: svs_yara_captures R/W (insert pending, update stored/missing; private transactions); ace: svs_sample_deletions R (is_deleted, checked before and after); ace: cas_objects, cas_holds, cas_purges R/W (CAS index via pool.put/hold/stat/release) |
| `svs_alert_tagger` | ace: alerts R (insert_date); ace: svs_runs, svs_maintenance_windows R (attribution_open gate, cached svs.attribution.gate_cache_seconds); ace: svs_runs, svs_test_hosts, svs_maintenance_windows, svs_attributions R (evaluate: resolve_markers, runs_overlapping, maintenance_windows_overlapping, _existing) |
| `observable_detection` | Redis: Redis 'local' config (redis_local), DB 4 (REDIS_DB_FOR_DETECTION_A): GET '<type>:<value>' per observable; populated by 'ace observables export' (saq/observables/export/redis_cache.py). One connection per module instance, health_check_interval 30. |

## What 7.3 decides

Every module that starts a process in ace3, and what it starts. Pool `parser` here means the process goes away in the port; `sandbox`, `scanner` and `7.3` mean it stays a process.

| Module | Pool | Tools in ace3 | In ace4 |
|---|---|---|---|
| `pcap_analyzer` | sandbox | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); runs: `capinfos -M -S input` (30 s timeout), `tshark -n -r input -q -z io,stat,0 -z endpoints,eth -z endpoints,ip -z endpoints,ipv6 -z conv,tcp -z conv,udp`, then `tshark -n -r input -T json -Y 'frame.number <= max_field_packets && (dns \|\| tls.handshake \|\| http.request \|\| http.response \|\| http2.headers \|\| dhcp \|\| nbns)' -e <38 fields> --export-objects http\|smb\|ftp-data\|tftp\|imf,objects/<proto>` (pcap.tshark_timeout 120 s each) | stays a process, in the sandbox runner |
| `pcap_tls_decryption` | sandbox | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); one run: `tshark -n -r input -T json -Y ... -e ... --export-objects ... -o tls.keylog_file:keylog` (no statistics/capinfos pass) | stays a process, in the sandbox runner |
| `tls_keylog` | sandbox | tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError) -- only for late key logs: one tshark run per pcap with a completed PcapTlsDecryptionAnalysis that this key log has new session keys (or RSA keys) for | stays a process, in the sandbox runner |
| `javascript_deobfuscation` | scanner | none started by ACE itself; the js-deobfuscator manager container (docker:dind image, Alpine python3 venv with celery[redis] + pyyaml, unpinned) runs `docker run --rm --network none -v <stack>_js-deobfuscator:/js-deobfuscator ${ACE3_JS_DEOBFUSCATOR_IMAGE_URL:-js-deobfuscator} node /opt/app/harness.js <input> <output>/deobfuscated.js` via subprocess.Popen on the host docker socket, killed after scanner_timeout (30 s); scanner image: node:26-alpine with webcrack 2.15.1 (npm, --ignore-scripts, isolated-vm not built); harness.js uses node:vm (webcrack sandbox 10 s timeout, dynamic run 5 s per script) | stays a process, in 7.7's scanner pool |
| `ssdeep` | parser | ssdeep 2.14.1 via run_tool (plain subprocess.run, unsandboxed): `ssdeep -m <ssdeep_hashes> <file>` | a fuzzy-hash crate |
| `archive` | parser | 7z (7zip 25.01, with 7zip-rar 25.00) via run_sandboxed_tool: `7z -y -pinfected l` and `7z -y -pinfected -o<dir> x` (and `7z -y -o<dir> x` for MSI); unrar 7.1.8 via run_sandboxed_tool: `unrar la` and `unrar e -y -o+ -idq -kb`; unzip via run_sandboxed_tool: `unzip -l -P infected` and `unzip -qq ... -x xl/activeX/* ... -d <dir>`; unace-nonfree 2.5 via run_sandboxed_tool on a copy in a temp staging dir: `unace l` and `unace x -y -o`; bin/unjar (python3 script using custom_zipfile.extractall) via run_sandboxed_tool for jar files; file via Popen `file -b -L` (unsandboxed, no timeout) in is_msi_file, called up to twice | ported onto crates (1.29); ACE archives (unace) left for 7.3 |
| `java_class_decompiler` | 7.3 | java (default-jre, OpenJDK 21) running /usr/local/bin/cfr.jar (cfr 0.151) via run_sandboxed_tool: `java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar cfr.jar <class>` | 7.3 decides |
| `officeparser3` | parser | officeparser3 (unixfreak0037/officeparser3, pip-installed from git master; config officeparser_path /venv/bin/officeparser3) via subprocess.Popen directly, NOT sandboxed, timeout config 90s | `ace-mod-oletools`' olefile port |
| `xlmdeobfuscator` | parser | xlmdeobfuscator CLI (DissectMalware/XLMMacroDeobfuscator master, with xlrd2 and pyxlsb2 master) resolved from PATH via subprocess.Popen, NOT sandboxed: `xlmdeobfuscator -f <file>` and `xlmdeobfuscator -x -f <file>`, timeout config 30s each | ported (4.12) |
| `pcodedmp` | parser | bin/pcodedmp_wrapper (bash) via subprocess.Popen, NOT sandboxed: `timeout --foreground --signal=KILL 30 /venv/bin/pcodedmp <file> \| sed -ne '/^Module streams:/,$ p' \| egrep '^[[:space:]]'`; pcodedmp 1.2.6 (pip, uses oletools/olefile) | ported (4.12) |
| `msoffice_encryption_analyzer` | parser | bin/office2john.py (vendored, bundles an old olefile 0.42) via run_sandboxed_tool with the venv python3 -I (sandbox_python()); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>` | ported: the wordlist tried in the task (4.11); 7.3 records John |
| `extracted_ole_analyzer` | parser | node (nodejs 24.22) `node --check <file or hard link {file}-<uuid>.js>` via subprocess.Popen from is_javascript_file(), NOT sandboxed, no timeout; grep -Eq <JS keyword regex> <file> via Popen, no timeout | a Rust JavaScript parser |
| `file_type` | parser | file (libmagic 5.46) via run_tool (plain subprocess.run, unsandboxed), twice: `file -b -L` and `file -b --mime-type -L`; node 24.22 via Popen `node --check <file or hard link>.js` (unsandboxed, no timeout) in is_javascript_file, only when mime is a JS type or extension is .js/.mjs/.cjs/.jse; grep via Popen `grep -Eq <js keyword regex>` (unsandboxed) after node --check succeeds | libmagic through `ace_yara::mime`, and a Rust JavaScript parser |
| `pdf_analyzer` | parser | python3 bin/pdf-parser.py (Didier Stevens pdf-parser 0.7.12, vendored) via run_tool (plain subprocess.run, unsandboxed), timeout 10 s, run on the file and again on the decrypted copy; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pdfwrite -o output.pdf -f <file>`, timeout 10 s | pdf-parser.py ported (4.9); Ghostscript left for 7.3 |
| `upx` | 7.3 | upx (upx-ucl 4.2.4) via run_sandboxed_tool: `upx -t <file>` then `upx -d -ounpacked.exe <file>` | 7.3 decides |
| `autoit` | 7.3 | unautoit (vendored Go build from third_party/unautoit) via run_tool (plain subprocess.run, UNSANDBOXED): `unautoit list <file>` and `unautoit extract-all --output-dir {file}.autoit <file>` | 7.3 decides |
| `de4dot` | 7.3 | de4dotEx 3.10.0 (/opt/de4dotEx/de4dot, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET_GCHeapHardLimit=1 GB, memory limit 12 GB, timeout 10 s: `de4dot -d <file>` then `de4dot <file> -o deobfuscated`; file via Popen `file -b -L` (unsandboxed, no timeout) in is_dotnet | 7.3 decides |
| `ilspy` | 7.3 | ilspycmd 11.0.0.9375 (/opt/dotnet/ilspycmd, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET env heap limits, memory limit 12 GB, timeout 10 s: `ilspycmd -il --disable-updatecheck -o . <file>`; file via Popen `file -b -L` (unsandboxed) in is_dotnet | 7.3 decides |
| `ocr` | 7.3 | tesseract (tesseract-ocr 5.5.0) via pytesseract.image_to_string, which starts it with subprocess UNSANDBOXED and no timeout, twice per image (`--oem 1 --psm 3`); tesseract --version via probe_binary_version (subprocess.run, cached per binary mtime) for the cache key | 7.3 decides |
| `qrcode` | 7.3 | pdfinfo (poppler-utils 25.03.0) via run_sandboxed_tool for the page count; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pngalpha -o <pattern> -r144 -dFirstPage -dLastPage`, up to 2 runs plus a full-render fallback; zbarimg (zbar-tools 0.23.93) via run_sandboxed_tool: `zbarimg -q --raw --nodbus`, per page and per inverted page; venv python3 -I bin/qr_decode_opencv.py via run_sandboxed_tool (OPENBLAS_NUM_THREADS=1), when zbarimg finds no URL; zbarimg/gs/pdfinfo version probes via probe_binary_version (subprocess.run, cached) for the cache key | 7.3 decides |
| `dmg_analyzer` | 7.3 | dmg2img 1.6.7 via run_sandboxed_tool: `dmg2img <file> image.img`; 7z 25.01 via run_sandboxed_tool: `7z l <image>` | 7.3 decides |
| `cve_2021_30657_analyzer` | 7.3 | 7z 25.01 via run_sandboxed_tool: `7z x -o<temp> <img> <member>` once per Contents/MacOS member; file via run_tool (plain subprocess.run, unsandboxed): `file -b --mime-type -L <extracted>` | 7.3 decides |
| `exif` | 7.3 | exiftool (libimage-exiftool-perl 13.25) via run_sandboxed_tool: `exiftool -j -G -n <file>`, timeout 30 s | 7.3 decides |
| `pdftotext` | 7.3 | pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext <file> output.txt`, timeout 5 s | 7.3 decides |
| `yara_scanner_v3_4` | parser | git via subprocess.run `git -C <dir> rev-parse HEAD` (saq/git.py get_commit_hash) when initializing the local scanner, through get_validated_git_repo_dirs | ported; ace4's ruleset records its commit (2.26) |
| `microsoft_script_encoding_analysis` | parser | perl script bin/jscript.decode.pl (vendored, ~80 lines) via run_tool() = subprocess.run, NOT sandboxed; timeout = time_left() minus margin | the decoder ported to Rust |
| `observable_modifier` | core | git rev-parse HEAD via subprocess.run (saq/git.py:53-70), only when the optional git_dir setting is configured (not set in saq.default.yaml), on each rules reload | none: its rules come from 5.14's lists or the overlay, not a git checkout |
| `rtfole` | parser | `python /venv/bin/rtfobj -d {file}.rtfobj -s all <file>` (oletools 0.60.2 rtfobj) via run_tool() = subprocess.run, NOT sandboxed; 'python' resolved from PATH; timeout = time_left() minus margin | ported (4.10) |
| `zip_encryption_analyzer` | parser | zip2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; 7z 25.01 `7z x -y -p<password> -o<abs dir> <file>` via run_sandboxed_tool, timeout extract_timeout=5s, write_dirs=[{file}.decrypted] | the wordlist tried in the task with the zip crate; 7.3 records John |
| `rar_encryption_analyzer` | parser | rar2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; unrar 7.1.8 `unrar x -y -kb -p<password> <file> <abs dir>/` via run_sandboxed_tool, read_files=archive_volumes(), write_dirs=[{file}.decrypted], timeout = time_left() | the wordlist tried in the task with the unrar crate; 7.3 records John |
| `pdf_encryption_analyzer` | parser | perl <john_bin_path>/pdf2john.pl <file> via run_sandboxed_tool, read_dirs=[john run dir] (uses john's bundled ExifTool perl lib); john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; hash written as 'pdf:<$pdf$...>' with login='pdf' | the wordlist tried in the task with libqpdf; 7.3 records John |
| `svs_yara_sample_capture` | lookup | git via subprocess.run (rev-parse --show-toplevel, remote URL, rev-parse HEAD) through saq.signatures.git_context.GitContext.resolve when the yara rule inventory is (re)built for _rule_content_hash (saq/svs/capture.py:210-217, saq/signatures/loaders/yara.py:332, saq/git.py:53-110) | none: ace4's ruleset records its commit (2.26) |
| `phishkit_analyzer` | scanner | none started by ACE; the phishkit manager container (docker:dind, Alpine, python venv with unpinned celery[redis], pydantic, pyyaml, python-magic) runs two Celery workers (worker_launcher.py: scan queue 'celery' and control queue 'phishkit_control' solo pool) and per scan `docker run --rm --init --name phishkit-scan-<job> --label phishkit.* --memory/--memory-swap --cpus --stop-timeout 5 -v <stack>_phishkit:/phishkit ${ACE3_PHISHKIT_IMAGE_URL:-phishkit} /opt/venv/bin/python /opt/app/scanner.py <url \| --file path> --output-dir ... [--proxy ...] [--config ...]` via Popen, with a retry without proxy on proxy errors; also docker inspect/ps/stop/kill/rm (reaper thread kills orphans older than reaper_max_age_seconds); scanner image: ubuntu 22.04 + google-chrome-stable (current at build) + chromedriver, Xvfb, ffmpeg; python seleniumbase, pyautogui, selenium-recaptcha-solver (git), pillow, opencv-python, pyyaml (all unpinned) | stays a process, in 7.7's scanner pool |

## Modules

In the config's order. ace4 is the crate a ported module is in.

| Module | Class | ace4 | Pool | Step | Groups | Modes |
|---|---|---|---|---|---|---|
| `html_data_url_extraction` | `HTMLDataURLAnalyzer` | not yet | parser | 7.5 batch 4 | file | analysis, binary, cli, correlation, email, file |
| `har_extraction` | `HARExtractor` | not yet | parser | 7.5 batch 4 | file | analysis, binary, cli, correlation, email, file |
| `pcap_analyzer` | `PcapAnalyzer` | not yet | sandbox | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `pcap_dns` | `PcapCategoryAnalyzer` | not yet | parser | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `pcap_tls` | `PcapCategoryAnalyzer` | not yet | parser | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `pcap_http` | `PcapCategoryAnalyzer` | not yet | parser | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `pcap_files` | `PcapCategoryAnalyzer` | not yet | parser | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `pcap_tls_decryption` | `PcapTlsDecryptor` | not yet | sandbox | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `tls_keylog` | `TlsKeylogAnalyzer` | not yet | sandbox | 7.5 batch 13 | file | analysis, binary, cli, correlation, email, file |
| `html_js_extraction` | `HTMLJavaScriptExtractor` | not yet | parser | 7.5 batch 4 | file | analysis, binary, cli, correlation, email, file |
| `onenote_extraction` | `OneNoteFileAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `javascript_deobfuscation` | `JavaScriptDeobfuscationAnalyzer` | not yet | scanner | 7.7 | file | analysis, binary, cli, correlation, email, file |
| `command_line_analyzer` | `CommandLineAnalyzer` | not yet | parser | 7.5 batch 3 | common | analysis, binary, cli, correlation, email, file |
| `mailbox_email_analyzer` | `MailboxEmailAnalyzer` | not yet | parser | 7.5 batch 8 | email | analysis, cli, correlation, email |
| `email_analyzer` | `EmailAnalyzer` | `ace-mod-email` | parser | done | email | analysis, cli, correlation, email |
| `lure_url_analyzer` | `LureURLAnalyzer` | not yet | parser | 7.5 batch 8 | correlation | analysis, cli, correlation |
| `email_archiver` | `EmailArchiveAction` | not yet | lookup | 7.5 batch 9 | - | email |
| `encrypted_archive_analyzer` | `EncryptedArchiveAnalyzer` | not yet | lookup | 7.5 batch 9 | email | analysis, cli, correlation, email |
| `file_location_analysis` | `FileLocationAnalyzer` | not yet | parser | 7.5 batch 3 | file | analysis, binary, cli, correlation, email, file |
| `file_path_analysis` | `FilePathAnalyzer` | not yet | parser | 7.5 batch 3 | file | analysis, binary, cli, correlation, email, file |
| `network_identifier` | `NetworkIdentifier` | not yet | parser | 7.5 batch 3 | correlation | analysis, cli, correlation |
| `parse_url` | `ParseURLAnalyzer` | not yet | parser | 7.5 batch 3 | correlation | analysis, cli, correlation |
| `fqdn_analyzer` | `FQDNAnalyzer` | not yet | lookup | 7.4 | correlation | analysis, cli, correlation |
| `idna_analyzer` | `IDNAAnalyzer` | not yet | parser | 7.5 batch 3 | correlation | analysis, cli, correlation |
| `rdap_analyzer` | `RdapAnalyzer` | `ace-mod-rdap` | lookup | done | correlation | analysis, cli, correlation |
| `nrd_analyzer` | `NRDAnalyzer` | not yet | lookup | 7.4 | common | analysis, binary, cli, correlation, email, file |
| `snort_signature_analysis_v1` | `SnortSignatureAnalyzer_v1` | not yet | lookup | 7.4 | correlation | analysis, cli, correlation, suricata_ids |
| `user_analyzer` | `UserAnalyzer` | not yet | lookup | 7.4 | correlation | analysis, cli, correlation |
| `email_address_fqdn_analyzer` | `EmailAddressFQDNAnalyzer` | not yet | parser | 7.5 batch 3 | common | analysis, binary, cli, correlation, email, file |
| `email_conversation_frequency_analyzer` | `EmailConversationFrequencyAnalyzer` | not yet | lookup | 7.4 | email | analysis, cli, correlation, email |
| `email_conversation_attachment_analyzer` | `EmailConversationAttachmentAnalyzer` | not yet | parser | 7.5 batch 8 | email | analysis, cli, correlation, email |
| `email_conversation_link_analyzer` | `EmailConversationLinkAnalyzer` | not yet | parser | 7.5 batch 8 | email | analysis, cli, correlation, email |
| `email_thread_analyzer` | `EmailThreadAnalyzer` | not yet | lookup | 7.4 | correlation | analysis, cli, correlation |
| `url_email_pivot_analyzer` | `URLEmailPivotAnalyzer` | not yet | lookup | 7.5 batch 9 | correlation | analysis, cli, correlation |
| `email_logger` | `EmailLoggingAnalyzer` | not yet | lookup | 7.4 | - | email |
| `file_hash_analyzer` | `FileHashAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `ssdeep` | `SsdeepAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `archive` | `ArchiveAnalyzer` | `ace-mod-archive` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `java_class_decompiler` | `JavaClassDecompilerAnalysisModule` | not yet | 7.3 | 7.5 batch 11 | file | analysis, binary, cli, correlation, email, file |
| `olevba_v1_2` | `OLEVBA_Analyzer_v1_2` | `ace-mod-oletools` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `officeparser3` | `OfficeParserAnalyzer3` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `xlmdeobfuscator` | `XLMMacroDeobfuscatorAnalyzer` | `ace-mod-xlm` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `mhtml` | `MHTMLAnalysisModule` | not yet | parser | 7.5 batch 4 | file | analysis, binary, cli, correlation, email, file |
| `pcodedmp` | `PCodeAnalyzer` | `ace-mod-xlm` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `office_xml_rel` | `OfficeXMLRelationshipExternalURLAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `msoffice_encryption_analyzer` | `MSOfficeEncryptionAnalyzer` | `ace-mod-msoffice` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `xml_binary_analyzer` | `XMLBinaryDataAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `xml_plain_text_analyzer` | `XMLPlainTextAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `extracted_ole_analyzer` | `ExtractedOLEAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `file_type` | `FileTypeAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `pdf_analyzer` | `PDFAnalyzer` | `ace-mod-pdf` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `upx` | `UPXAnalyzer` | not yet | 7.3 | 7.5 batch 11 | file | analysis, binary, cli, correlation, email, file |
| `autoit` | `AutoItAnalyzer` | not yet | 7.3 | 7.5 batch 11 | file | analysis, binary, cli, correlation, email, file |
| `lnk_parser` | `LnkParseAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `de4dot` | `De4dotAnalyzer` | not yet | 7.3 | 7.5 batch 11 | file | analysis, binary, cli, correlation, email, file |
| `ilspy` | `IlspyAnalyzer` | not yet | 7.3 | 7.5 batch 11 | file | analysis, binary, cli, correlation, email, file |
| `ocr` | `OCRAnalyzer` | not yet | 7.3 | 7.5 batch 10 | file | analysis, binary, cli, correlation, email, file |
| `qrcode` | `QRCodeAnalyzer` | not yet | 7.3 | 7.5 batch 10 | file | analysis, binary, cli, correlation, email, file |
| `hidden_mime` | `HiddenMIMEAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `active_mime` | `ActiveMimeAnalyzer` | not yet | parser | 7.5 batch 5 | file | analysis, binary, cli, correlation, email, file |
| `dmg_analyzer` | `DMGAnalyzer` | not yet | 7.3 | 7.5 batch 12 | file | analysis, binary, cli, correlation, email, file |
| `cve_2021_30657_analyzer` | `CVE_2021_30657_Analyzer` | not yet | 7.3 | 7.5 batch 12 | file | analysis, binary, cli, correlation, email, file |
| `exif` | `ExifAnalyzer` | not yet | 7.3 | 7.5 batch 10 | file | analysis, binary, cli, correlation, email, file |
| `pdftotext` | `PDFTextAnalyzer` | not yet | 7.3 | 7.5 batch 10 | file | analysis, binary, cli, correlation, email, file |
| `yara_scanner_v3_4` | `YaraScanner_v3_4` | `ace-mod-yara` | parser | done | file, yara | analysis, binary, cli, correlation, email, file, yara |
| `binary_file_analyzer` | `BinaryFileAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `microsoft_script_encoding_analysis` | `MicrosoftScriptEncodingAnalyzer` | not yet | parser | 7.5 batch 6 | file | analysis, binary, cli, correlation, email, file |
| `url_extraction` | `URLExtractionAnalyzer` | not yet | parser | 7.5 batch 1 | file | analysis, binary, cli, correlation, email, file |
| `ioc_extraction` | `IOCExtractionAnalyzer` | not yet | parser | 7.5 batch 1 | file | analysis, binary, cli, correlation, email, file |
| `observable_modifier` | `ObservableModifierAnalyzer` | not yet | core | 7.6 | common | analysis, binary, cli, correlation, email, file |
| `x509_analyzer` | `X509Analyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `protected_url_analyzer` | `ProtectedURLAnalyzer` | not yet | parser | 7.5 batch 3 | common | analysis, binary, cli, correlation, email, file |
| `rtfole` | `RTFOLEObjectAnalyzer` | `ace-mod-oletools` | parser | done | file | analysis, binary, cli, correlation, email, file |
| `extracted_rtf_analyzer` | `ExtractedRTFAnalyzer` | not yet | parser | 7.5 batch 6 | file | analysis, binary, cli, correlation, email, file |
| `message_id_analyzer_v2` | `MessageIDAnalyzerV2` | not yet | lookup | 7.5 batch 9 | correlation | analysis, cli, correlation |
| `vbscript_analyzer` | `VBScriptAnalyzer` | not yet | parser | 7.5 batch 6 | file | analysis, binary, cli, correlation, email, file |
| `nowhitespace_analyzer` | `NoWhiteSpaceAnalyzer` | not yet | parser | 7.5 batch 6 | file | analysis, binary, cli, correlation, email, file |
| `user_defined_tagging` | `UserDefinedTaggingAnalyzer` | not yet | lookup | 7.6 | common | analysis, binary, cli, correlation, email, file |
| `configuration_defined_tagging` | `ConfigurationDefinedTaggingAnalyzer` | not yet | core | 7.6 | common | analysis, binary, cli, correlation, email, file |
| `site_tagger` | `SiteTagAnalyzer` | not yet | parser | 7.6 | common, file | analysis, binary, cli, correlation, email, file |
| `zip_encryption_analyzer` | `ZipEncryptionAnalyzer` | not yet | parser | 7.5 batch 7 | file | analysis, binary, cli, correlation, email, file |
| `rar_encryption_analyzer` | `RarEncryptionAnalyzer` | not yet | parser | 7.5 batch 7 | file | analysis, binary, cli, correlation, email, file |
| `pdf_encryption_analyzer` | `PDFEncryptionAnalyzer` | not yet | parser | 7.5 batch 7 | file | analysis, binary, cli, correlation, email, file |
| `alert_added_to_event` | `AlertAddedToEventAnalyzer` | not yet | core | owner | - | dispositioned |
| `svs_yara_sample_capture` | `YaraSampleCapture` | not yet | lookup | 7.10 | - | dispositioned |
| `svs_alert_tagger` | `SVSAlertTagger` | not yet | lookup | 7.10 | - | correlation |
| `dhash` | `DHashImageAnalyzer` | not yet | parser | 7.5 batch 2 | file | analysis, binary, cli, correlation, email, file |
| `observable_detection` | `ObservableDetectionAnalyzer` | not yet | lookup | 7.6 | common | analysis, binary, cli, correlation, email, file |
| `phishkit_analyzer` | `PhishkitAnalyzer` | not yet | scanner | 7.7 | correlation, file | analysis, binary, cli, correlation, email, file |
| `clicker_detection_splunk` | `SplunkClickerDetectionAnalyzer` | not yet | lookup | 7.4 | correlation | analysis, cli, correlation |

## Entries

### html_data_url_extraction

- **Section**: `analysis_module_html_data_url_extraction`, class `HTMLDataURLAnalyzer` in `saq/modules/file_analysis/html.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. Regex and base64 over an attacker's file.
- **Step**: 7.5 batch 4 (HTML).
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
- **ace4**: not yet.
- **Pool**: parser. JSON and HTML parsing of an attacker's file.
- **Step**: 7.5 batch 4 (HTML).
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
- **ace4**: not yet.
- **Pool**: sandbox. Runs tshark and capinfos, which stay in ACE's sandbox runner (7.3 says so).
- **Step**: 7.5 batch 13 (Packet captures).
- **Does**: Dissects a pcap/pcapng file (detected by magic, not extension) with sandboxed capinfos and two tshark runs, stores the capture index (capture metadata, endpoints, flows, DNS/TLS/HTTP/hostnames, carved objects, certificates, embedded pcapng decryption secrets) and adds the host observables (IP, MAC, hostname).
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: cryptography 50.0.2 (x509 DER cert parsing via saq/x509.py); pydantic 2.14.1 (config).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); runs: `capinfos -M -S input` (30 s timeout), `tshark -n -r input -q -z io,stat,0 -z endpoints,eth -z endpoints,ip -z endpoints,ipv6 -z conv,tcp -z conv,udp`, then `tshark -n -r input -T json -Y 'frame.number <= max_field_packets && (dns || tls.handshake || http.request || http.response || http2.headers || dhcp || nbns)' -e <38 fields> --export-objects http|smb|ftp-data|tftp|imf,objects/<proto>` (pcap.tshark_timeout 120 s each).
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel; whether tshark itself starts threads: unsure
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
- **ace4**: not yet.
- **Pool**: parser. Turns pcap_analyzer's index into observables; no process. Could become part of pcap_analyzer's result in ace4.
- **Step**: 7.5 batch 13 (Packet captures).
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
- **ace4**: not yet.
- **Pool**: parser. As pcap_dns.
- **Step**: 7.5 batch 13 (Packet captures).
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
- **ace4**: not yet.
- **Pool**: parser. As pcap_dns.
- **Step**: 7.5 batch 13 (Packet captures).
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
- **ace4**: not yet.
- **Pool**: parser. As pcap_dns.
- **Step**: 7.5 batch 13 (Packet captures).
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
- **ace4**: not yet.
- **Pool**: sandbox. Runs tshark with key logs, in the sandbox runner.
- **Step**: 7.5 batch 13 (Packet captures).
- **Does**: In final analysis, finds every TLS key log (SSLKEYLOGFILE format, by content) among the alert's file observables and re-runs tshark on a pcap with those keys, adding the DNS/TLS/HTTP/file observables the decrypted traffic shows beyond the plaintext index.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: pcap_analyzer (reads PcapAnalysis via get_and_load_analysis in execute_final_analysis, no wait_for; needs index.tls non-empty); scans all file observables in the root for key logs (find_keylog_observables).
- **Libraries**: cryptography 50.0.2 (certificate names via saq/x509.py).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError); one run: `tshark -n -r input -T json -Y ... -e ... --export-objects ... -o tls.keylog_file:keylog` (no statistics/capinfos pass).
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel; whether tshark itself starts threads: unsure
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
- **ace4**: not yet.
- **Pool**: sandbox. Recognizing a key log is parser work, but a late key log runs tshark again, so it goes with tshark; 7.5 may split it.
- **Step**: 7.5 batch 13 (Packet captures).
- **Does**: Recognizes a file as a TLS key log (NSS SSLKEYLOGFILE lines) by content, records label counts and session count, tags it, and when the key log arrives after a pcap's TLS decryption already completed, decrypts that pcap again with it via sandboxed tshark.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: reads other observables' PcapTlsDecryptionAnalysis (must be completed) and PcapAnalysis via get_and_load_analysis; no wait_for.
- **Libraries**: cryptography 50.0.2 (only on the late-apply path, via certificate parsing).
- **Tools**: tshark 4.4.19 (and capinfos 4.4.19 from the same dir) via saq.sandbox.runner.run_sandboxed + build_sandbox_argv directly (NOT AnalysisModule.run_sandboxed_tool): argv is `python3 -I -S saq/sandbox/launcher.py --max-processes=64 --deadline=... -- /usr/bin/prlimit --as --fsize --nofile --cpu --core=0 -- setpriv --no-new-privs --landlock-access fs ... -- tshark -n -r input ...`; env is only PATH/LANG/HOME; refuses to run when landlock_available() is false (PcapNodeError) -- only for late key logs: one tshark run per pcap with a completed PcapTlsDecryptionAnalysis that this key log has new session keys (or RSA keys) for.
- **Threads and children**: each run is a chain of processes: the sandbox launcher (a Python interpreter) -> prlimit -> setpriv -> tshark/capinfos; the launcher caps the tree at sandbox.max_processes (64) and kills the session on deadline/cancel; whether tshark itself starts threads: unsure
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
- **ace4**: not yet.
- **Pool**: parser. HTML parsing of an attacker's file.
- **Step**: 7.5 batch 4 (HTML).
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
- **ace4**: not yet.
- **Pool**: parser. Binary parsing of an attacker's file.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: scanner. Runs attacker JavaScript in node in a no-network container that a Celery manager starts through the Docker socket; 7.7's scanner pool replaces the manager.
- **Step**: 7.7.
- **Does**: Sends a JavaScript file (.js extension or yara meta type=script.javascript) to the js-deobfuscator Celery service, which runs it in a throwaway no-network Node container (webcrack static pass plus a node:vm sandbox that traces writes to stubbed browser/Acrobat globals), and adds the reconstructed trace and any Blob payloads as file observables marked for URL extraction.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: html_js_extraction / har_extraction (sidecar .dom.json and type=script.javascript yara meta; not a wait_for).
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
- **ace4**: not yet.
- **Pool**: parser. Tokenizes an attacker's string and writes decoded payloads.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: parser. Edits the tree only: no file, network or database. The SDK needs a way for a module to set the root's description and details.
- **Step**: 7.5 batch 8 (Email tree).
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
- **Notes**: Side effects on the RootAnalysis itself (description and details.update(email_analysis.details), mailbox.py:49-66, marked 'XXX HACK'); ace4 needs a way for a module to set root description/details. wide_diff: true in config tells the delta recorder the module touches observables outside the analyzed one (module_execution_delta.py:331). Returns early when root.whitelisted.

### email_analyzer

- **Section**: `analysis_module_email_analyzer`, class `EmailAnalyzer` in `saq/modules/email/rfc822.py`, enabled by default.
- **ace4**: ported in `ace-mod-email`.
- **Pool**: parser. Parses an attacker's MIME in the task's own process on mail-parser (1.x, 4.x).
- **Step**: done.
- **Does**: Parses a file observable that FileTypeAnalysis says is an RFC 822 email (or has the original_email directive) with Python's email package, picks the target message (Office 365 journal unwrapping by X-MS-Exchange-Parent-Message-Id and the journal 'meta block'), applies the brotex whitelist and outbound filter, and adds address/subject/message-id/delivery/IP/first-hop/DKIM/tenant/user-agent observables plus every MIME part as an extracted file.
- **Input**: file.
- **Groups and modes**: groups email; modes analysis, cli, correlation, email.
- **Depends on**: config: file_type; reads FileTypeAnalysis via get_and_load_analysis (no wait; config dependency file_type); reads root observables tagged smtp_mail_from / smtp_rcpt_to (added by the SMTP collector) as envelope from/to.
- **Libraries**: python stdlib email/mimetypes; python-dateutil 3.0.0 (Received date parse); pytz 2026.5; pydantic 2.14.1 (config); iptools 0.7.0 (imported by saq/whitelist.py; IpRangeList used only for http ip whitelist types, not on this path).
- **Tools**: none.
- **Writes**: {file}.unknown_<maintype>_<subtype>_<NNN><ext> (unnamed MIME parts; ext from mimetypes.guess_extension of the declared type); <attachment filename from the sender, RFC2047-decoded, CR/LF stripped, cleaned/uniquified by create_output_file>; {file}.email.rfc822 (attached message/rfc822 that is not the journal target); {file}.headers (shortened basename; all headers, one per line); {file}.combined (headers + every 'unknown_' body part concatenated, for yara); OUTSIDE ALERT: $DATA_DIR/review/rfc822/<uuid4> copy when BytesParser fails (rfc822.py:1085); OUTSIDE ALERT: $DATA_DIR/review/rfc822/<basename>.<YYYYmmddHHMMSS> copy when a MIME part fails to extract (rfc822.py:1688).
- **yara_meta**: type=email.attachment (every extracted part); type=email.headers; type=email.combined; reads: type=email.headers, type=email.combined (EmailAnalysis.attachments, rfc822.py:909).
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: etc/brotex.whitelist (whitelist_path; BrotexWhitelist reloads on mtime change; verify_environment requires it to exist); config global_settings.local_domains and local_email_domains (first-hop resolution, is_local_email_domain).
- **Tags and detections**: Tags the email file outbound_email, outbound_email_exception, email_parse_incomplete, authentication_failed (compauth or dmarc = fail), anonymous_direct_send, spoofed_internal; whitelists the file (smtp_from/smtp_to whitelist hit, or outbound O365 when scan_inbound_only). No detection points. Adds directives extract_urls + preview (declared text/plain) or render on parts; copies remediate from a matching message_id observable to each email_delivery; excludes MessageIDAnalyzerV2 on its own message_id and excludes itself on .headers/.combined. Appends ' - <subject>' to root description when the file has rename_analysis.
- **Notes**: Large module (rfc822.py 1846 lines). provider_headers config (EmailProviderHeaders, M365 defaults) drives first-hop IP, tenant id, compauth, direct-send, directionality headers. Builds a log_entry dict (consumed by email_logger and conversation.py) including a misspelled key 'refereneces' (rfc822.py:1729); conversation.py reads References from headers to work around it. Skips files ending in .headers. Whitelist check happens before analysis is created, so a whitelisted email gets no EmailAnalysis. Per-part extraction errors are caught and recorded in details.extraction_errors. Delivery observables are created for every local recipient in env_rcpt_to+To+Cc+Bcc. No caps on number of parts beyond the root's per-type observable limit (add_file_observable may return None).

### lure_url_analyzer

- **Section**: `analysis_module_lure_url_analyzer`, class `LureURLAnalyzer` in `saq/modules/email/lure.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. Scores URLs already in the tree and parses bodies with an HTML parser; no network or database. The core has to hand it the email's URLs at final analysis.
- **Step**: 7.5 batch 8 (Email tree).
- **Does**: For a file with EmailAnalysis, waits until final analysis and then scores every http(s) URL found in the email's body parts, attachments, QR codes, PDF link annotations and unwrapped protected URLs, picks the primary lure URL and adds the crawl directive to it.
- **Input**: file (only those with EmailAnalysis).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: config: email_analyzer; reads EmailAnalysis, ProtectedURLAnalysis (url protected unwrapping), QRCodeAnalysis, PhishkitAnalysis (skipped), and whatever analyses hang URLs off the email's parts (url_extraction, pdf annotations) by walking the tree in final analysis, no wait_for_analysis; config dependency email_analyzer.
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
- **ace4**: not yet.
- **Pool**: lookup. Writes ACE's email archive, which in ace4 is the bucket and Postgres behind the internal API (7.2); it parses nothing.
- **Step**: 7.5 batch 9 (Email archive).
- **Does**: For a non-whitelisted email file with the archive directive and an EmailAnalysis carrying a message-id and envelope recipients, gzips and AES-GCM encrypts the email into the email archive, records it in the email_archive database, and in post-analysis indexes every URL under the email.
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
- **ace4**: not yet.
- **Pool**: lookup. Opens an archived email with ACE's encryption key. In ace4 the archive is ACE's own store, so this becomes a read through the internal API and no worker holds the key.
- **Step**: 7.5 batch 9 (Email archive).
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
- **ace4**: not yet.
- **Pool**: parser. Splits a string.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: parser. Regex over a string.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: parser. CIDR matching of a value against a site file; no network or database. The CSV becomes a 5.14 list or overlay settings.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: parser. Parses an attacker's string in memory.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: lookup. DNS queries, the plan's hickory-dns example.
- **Step**: 7.4.
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

### idna_analyzer

- **Section**: `analysis_module_idna_analyzer`, class `IDNAAnalyzer` in `saq/modules/url/idna.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. Converts a name in memory.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: ported in `ace-mod-rdap`.
- **Pool**: lookup. RDAP over HTTPS (1.x).
- **Step**: done.
- **Does**: Looks up registration data for an fqdn (reduced to its eTLD+1) or a globally routable ip via RDAP, falling back to legacy WHOIS, recording registrar, dates/ages, nameservers, emails, network CIDR/country and raw responses.
- **Input**: fqdn; ip (and subtypes, e.g. email_first_hop_ip; custom_requirement skips non-global IPs).
- **Groups and modes**: groups correlation; modes analysis, cli, correlation.
- **Depends on**: none.
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
- **ace4**: not yet.
- **Pool**: lookup. RDAP and WHOIS on a hit, and a local database file the nrd-refresh task keeps (6.7).
- **Step**: 7.4.
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
- **Notes**: Hits for domains registered more than max_registration_age_days ago are dropped silently (no analysis, nrd.py:196-203) because feeds include updated domains. Lookup failure fails open: hit kept and lookup_error recorded. Missing DB file = no hits (fresh deploy). The DB is node-local, so each ace4 node needs its own copy or a shared store.

### snort_signature_analysis_v1

- **Section**: `analysis_module_snort_signature_analysis_v1`, class `SnortSignatureAnalyzer_v1` in `saq/modules/snort.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: lookup. A Redis read today; in ace4 an internal API read (7.2) of the rules `ace signatures build-db` indexes.
- **Step**: 7.4.
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
- **ace4**: not yet.
- **Pool**: lookup. LDAP searches with a bind password. Disabled by default.
- **Step**: 7.4.
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
- **ace4**: not yet.
- **Pool**: parser. Splits a string; no I/O.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: lookup. Reads brocess's smtplog, which becomes an internal API read (7.2).
- **Step**: 7.4.
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
- **ace4**: not yet.
- **Pool**: parser. Reads the tree only (tags and other modules' results). Needs 7.4's frequency analyzer first.
- **Step**: 7.5 batch 8 (Email tree).
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
- **ace4**: not yet.
- **Pool**: parser. Regex and the tree only. Needs 7.4's frequency analyzer first. With no url_pattern_* setting, the default, it does nothing.
- **Step**: 7.5 batch 8 (Email tree).
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
- **ace4**: not yet.
- **Pool**: lookup. Reads brocess's thread store through the internal API (7.2); the similarity work is cheap and runs in the same task.
- **Step**: 7.4.
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
- **ace4**: not yet.
- **Pool**: lookup. Reads the email archive's URL index through the internal API (7.2).
- **Step**: 7.5 batch 9 (Email archive).
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
- **ace4**: not yet.
- **Pool**: lookup. Writes brocess (through the internal API) and sends records to fluent-bit; parses nothing new.
- **Step**: 7.4.
- **Does**: In post-analysis, for each file with the original_email directive and a non-whitelisted EmailAnalysis, exports the email's log entry (plus every extracted URL and archive path) to brocess smtplog and fluent-bit, records the message in the brocess thread store, and emits look-a-like domain telemetry.
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
- **ace4**: not yet.
- **Pool**: parser. Hashing in the task's process.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: not yet.
- **Pool**: parser. Runs the ssdeep binary today; a fuzzy-hash crate computes and compares the same hashes. Disabled by default.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: ported in `ace-mod-archive`.
- **Pool**: parser. zip, sevenz-rust2 and unrar in the task's process (1.29). ACE archives, which ace3 opens with unace, are left for 7.3.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs CFR on a JVM, which starts many threads; no Rust decompiler.
- **Step**: 7.5 batch 11 (Executables).
- **Does**: Decompiles a Java .class file (CAFEBABE magic) with CFR and adds the Java source as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: java (default-jre, OpenJDK 21) running /usr/local/bin/cfr.jar (cfr 0.151) via run_sandboxed_tool: `java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar cfr.jar <class>`.
- **Threads and children**: The JVM starts many threads (GC, JIT compiler threads per core).
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
- **ace4**: not yet.
- **Pool**: parser. Runs officeparser3, a Python CLI, unsandboxed today; what it does (dump an OLE file's streams and macros) is `ace-mod-oletools`'s olefile port, so no process is needed.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: parser. MIME parsing of an attacker's file; mail-parser covers it.
- **Step**: 7.5 batch 4 (HTML).
- **Does**: Parses a .mhtml/.mht file (by extension only) as MIME with the stdlib email parser and writes every non-multipart part out as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
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
- **ace4**: not yet.
- **Pool**: parser. XML parsing of an extracted part.
- **Step**: 7.5 batch 5 (Office containers).
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
- **Notes**: Always tries 'VelvetSweatshop' and '/01Hannes Ruescher/01' first (msoffice.py:114). wordlist harvested from the carrying email's body: search_down() to the nearest EmailAnalysis with .email, read its body file, html2text, cut to byte_limit, then every non-whitespace substring of length range_low..range_high until list_limit (saq/cracking.py:20-81). Decryption runs in-process on the attacker file after a password is found (msoffice.py:137-141). crack_password finds the line by the attachment's basename and takes field 2 (cracking.py:126-127).

### xml_binary_analyzer

- **Section**: `analysis_module_xml_binary_analyzer`, class `XMLBinaryDataAnalyzer` in `saq/modules/file_analysis/xml.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. XML and base64 of an attacker's file.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: parser. XML text extraction.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: parser. String checks, and `node --check` as a JavaScript syntax test, unsandboxed today, which a Rust JavaScript parser replaces (the same check as file_type's).
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: parser. Magic bytes and headers. Its `file` runs become the magic crate, as the core already uses for an input's mime type, and `node --check` a Rust JavaScript parser.
- **Step**: 7.5 batch 2 (File identity).
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
- **Pool**: parser. libqpdf and a port of pdf-parser.py in the task's process (4.9). Its Ghostscript rewrite is left for 7.3.
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

### upx

- **Section**: `analysis_module_upx`, class `UPXAnalyzer` in `saq/modules/file_analysis/upx.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: 7.3. Runs upx; no crate unpacks UPX.
- **Step**: 7.5 batch 11 (Executables).
- **Does**: Tests a PE file with `upx -t` and, if it is UPX packed, unpacks it with `upx -d` and adds the unpacked executable as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: upx (upx-ucl 4.2.4) via run_sandboxed_tool: `upx -t <file>` then `upx -d -ounpacked.exe <file>`.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs unautoit (Go, unsandboxed today), whose runtime starts threads; or port its vendored libautoit.
- **Step**: 7.5 batch 11 (Executables).
- **Does**: For a compiled AutoIt executable (PE or .au3 containing AU3!EA05/EA06), lists and extracts its embedded resources with unautoit and adds each decompiled .au3 script as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: unautoit (vendored Go build from third_party/unautoit) via run_tool (plain subprocess.run, UNSANDBOXED): `unautoit list <file>` and `unautoit extract-all --output-dir {file}.autoit <file>`.
- **Threads and children**: Go runtime starts its own OS threads.
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
- **ace4**: not yet.
- **Pool**: parser. Parses an attacker's shortcut with a library; a crate replaces LnkParse3.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs de4dot on .NET, which starts threads and can run the sample's own methods.
- **Step**: 7.5 batch 11 (Executables).
- **Does**: For a .NET assembly, checks for a known obfuscator with `de4dot -d` and, if one is detected, deobfuscates it and adds the cleaned assembly as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: de4dotEx 3.10.0 (/opt/de4dotEx/de4dot, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET_GCHeapHardLimit=1 GB, memory limit 12 GB, timeout 10 s: `de4dot -d <file>` then `de4dot <file> -o deobfuscated`; file via Popen `file -b -L` (unsandboxed, no timeout) in is_dotnet.
- **Threads and children**: .NET CoreCLR runtime starts GC/JIT/finalizer threads; de4dot's dynamic string decrypters can execute the sample's own methods (dotnet.py:110).
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs ilspycmd on .NET; no crate gives ILSpy's output.
- **Step**: 7.5 batch 11 (Executables).
- **Does**: Disassembles a .NET assembly to IL with ilspycmd and adds the .il file as a file observable.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: ilspycmd 11.0.0.9375 (/opt/dotnet/ilspycmd, .NET 10) via run_sandboxed_tool with /proc/self readable, DOTNET env heap limits, memory limit 12 GB, timeout 10 s: `ilspycmd -il --disable-updatecheck -o . <file>`; file via Popen `file -b -L` (unsandboxed) in is_dotnet.
- **Threads and children**: .NET CoreCLR runtime threads.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs tesseract (unsandboxed today, through pytesseract) after OpenCV; libtesseract in the task's process is the alternative.
- **Step**: 7.5 batch 10 (PDF and image text).
- **Does**: For an image file carrying the ocr directive, preprocesses it with OpenCV and runs two tesseract passes (grayscale and denoised), writing the extracted text to a file observable for URL extraction and yara.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: opencv-python 5.0.0.93 (cv2); numpy 2.5.4; pytesseract 0.3.13; Pillow 13.0.0 (is_image); pyenchant 3.3.0 (enchant en_US dictionary, in saq/ocr.py remove_line_wrapping).
- **Tools**: tesseract (tesseract-ocr 5.5.0) via pytesseract.image_to_string, which starts it with subprocess UNSANDBOXED and no timeout, twice per image (`--oem 1 --psm 3`); tesseract --version via probe_binary_version (subprocess.run, cached per binary mtime) for the cache key.
- **Threads and children**: tesseract uses OpenMP threads (limited by OMP_THREAD_LIMIT, config omp_thread_limit 1); OpenCV may start its own threads.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs Ghostscript, pdfinfo, zbarimg and an OpenCV script. A QR crate could decode in the task; rendering PDF pages still needs a tool.
- **Step**: 7.5 batch 10 (PDF and image text).
- **Does**: Scans an image, or the first and last pages of a PDF rendered with ghostscript, for QR codes with zbarimg (falling back to an OpenCV script and an inverted image) and writes the decoded URLs to a file observable for crawling.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: Pillow 13.0.0 (is_image, ImageOps.invert); opencv-python 5.0.0.93 and numpy 2.5.4 (in bin/qr_decode_opencv.py, run as a sandboxed subprocess).
- **Tools**: pdfinfo (poppler-utils 25.03.0) via run_sandboxed_tool for the page count; gs (ghostscript 10.05.1) via run_sandboxed_tool: `gs -sDEVICE=pngalpha -o <pattern> -r144 -dFirstPage -dLastPage`, up to 2 runs plus a full-render fallback; zbarimg (zbar-tools 0.23.93) via run_sandboxed_tool: `zbarimg -q --raw --nodbus`, per page and per inverted page; venv python3 -I bin/qr_decode_opencv.py via run_sandboxed_tool (OPENBLAS_NUM_THREADS=1), when zbarimg finds no URL; zbarimg/gs/pdfinfo version probes via probe_binary_version (subprocess.run, cached) for the cache key.
- **Threads and children**: The OpenCV script runs a Python interpreter; OpenBLAS limited to 1 thread and cv2.setNumThreads(1).
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
- **ace4**: not yet.
- **Pool**: parser. MIME parsing of an attacker's file.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: parser. A header walk and zlib.
- **Step**: 7.5 batch 5 (Office containers).
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs dmg2img and 7z; no maintained crate reads DMG and HFS+.
- **Step**: 7.5 batch 12 (macOS images).
- **Does**: For a file named *.dmg, converts it to a raw .img with dmg2img, adds that image as a file observable, and records the 7z listing of its files.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: dmg2img 1.6.7 via run_sandboxed_tool: `dmg2img <file> image.img`; 7z 25.01 via run_sandboxed_tool: `7z l <image>`.
- **Threads and children**: 7z may start threads.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs 7z on dmg_analyzer's HFS+ image, and `file`.
- **Step**: 7.5 batch 12 (macOS images).
- **Does**: For a .img produced by dmg_analyzer, extracts each file under */Contents/MacOS/ with 7z and raises a detection when its mime type is a script (CVE-2021-30657 Gatekeeper bypass).
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: DMGAnalysis on the file's redirection (the .dmg), read via _file.redirection.get_and_load_analysis; requires tags macos and dmg set by dmg_analyzer.
- **Libraries**: none.
- **Tools**: 7z 25.01 via run_sandboxed_tool: `7z x -o<temp> <img> <member>` once per Contents/MacOS member; file via run_tool (plain subprocess.run, unsandboxed): `file -b --mime-type -L <extracted>`.
- **Threads and children**: 7z may start threads.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs exiftool, whose tag names YARA rules match; no crate gives them for Office and PDF files.
- **Step**: 7.5 batch 10 (PDF and image text).
- **Does**: Runs exiftool on office documents, OLE files and PDFs, stores the metadata in details and writes it pretty-printed to a file observable for yara.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: FileTypeAnalysis read indirectly by is_office_file (falls back to extension when absent; wait_for_analysis commented out, exif.py:169).
- **Libraries**: json, pprint stdlib.
- **Tools**: exiftool (libimage-exiftool-perl 13.25) via run_sandboxed_tool: `exiftool -j -G -n <file>`, timeout 30 s.
- **Threads and children**: Perl interpreter, single process.
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
- **ace4**: not yet.
- **Pool**: 7.3. Runs poppler's pdftotext; a crate's text layout would differ from what YARA rules match today.
- **Step**: 7.5 batch 10 (PDF and image text).
- **Does**: Converts a PDF to plain text with poppler's pdftotext and adds the text file as a file observable for yara scanning.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: none.
- **Libraries**: none.
- **Tools**: pdftotext (poppler-utils 25.03.0, /usr/bin/pdftotext) via run_sandboxed_tool: `pdftotext <file> output.txt`, timeout 5 s.
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
- **Pool**: parser. yara-x through `ace-yara` in the task's process (1.x, 2.26). Its database reads of $obsd_ and $obs_ strings wait for 7.2 (`crates/ace-mod-yara/src/lib.rs:309`).
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
- **Tags and detections**: A detection point on the file per matching rule without no_alert/qa modifiers (signature uuid from rule meta or YARA_RULE_MATCH fallback, version = rule repo commit, queue from rule meta). Adds the rule's tags to the file, whitelists the file on tag 'whitelisted', adds DIRECTIVE_SANDBOX (to the redirection target if any) when alertable, and directives from 'directive=X' modifiers. Adds yara_rule, yara_string, signature_id, indicator (SIP_ rules) and DB-resolved observables tagged with the rule name.
- **Notes**: Skips empty files and files with DIRECTIVE_NO_SCAN. Local scanner kept local_scanner_lifetime (5) minutes after the service returns. Drops matches from rules with enabled=false meta. context_bytes 64: records hex dump and base64 context for each string match (re-reads the file). always_visible when the file has a yara detection. Detection details include namespace made relative to signature_dir (yara.py:72-98).

### binary_file_analyzer

- **Section**: `analysis_module_binary_file_analyzer`, class `BinaryFileAnalyzer` in `saq/modules/file_analysis/binary.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. Reads bytes.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: not yet.
- **Pool**: parser. Runs a vendored 80-line Perl decoder, unsandboxed today; the table-driven decoding ports to Rust.
- **Step**: 7.5 batch 6 (RTF and scripts).
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
- **ace4**: not yet.
- **Pool**: parser. Parses an attacker's file for URLs in the task's process.
- **Step**: 7.5 batch 1 (URLs and indicators in text).
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
- **ace4**: not yet.
- **Pool**: parser. Text and regexes in the task's process; its settings file becomes a 5.14 list or overlay settings (5.14 says so).
- **Step**: 7.5 batch 1 (URLs and indicators in text).
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
- **ace4**: not yet.
- **Pool**: core. Evaluates rules over the whole tree and edits other nodes (wide_diff: removes observables, limits and resets analysis), which only the core's orchestrator can do; it parses no attacker bytes.
- **Step**: 7.6.
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
- **ace4**: not yet.
- **Pool**: parser. Parses a certificate.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: not yet.
- **Pool**: parser. Unwraps URLs in memory. Its one network case, following a 1drv.ms redirect to the attacker's host, is left out of the parser: it becomes a crawl directive or a lookup instance, which 7.5 decides with 7.7's phishkit.
- **Step**: 7.5 batch 3 (Observable values).
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
- **ace4**: not yet.
- **Pool**: parser. String checks on earlier results.
- **Step**: 7.5 batch 6 (RTF and scripts).
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
- **ace4**: not yet.
- **Pool**: lookup. Fetches an archived email through the internal API (7.2); the email it adds is parsed by email_analyzer.
- **Step**: 7.5 batch 9 (Email archive).
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
- **ace4**: not yet.
- **Pool**: parser. A byte scan of an attacker's file.
- **Step**: 7.5 batch 6 (RTF and scripts).
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
- **ace4**: not yet.
- **Pool**: parser. A byte transform.
- **Step**: 7.5 batch 6 (RTF and scripts).
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
- **ace4**: not yet.
- **Pool**: lookup. One read of ACE's tag tables per observable, through the internal API (7.2); batch it per root.
- **Step**: 7.6.
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
- **ace4**: not yet.
- **Pool**: core. Post-analysis over the whole tree, turning configured tag levels into detection points: core work. Disabled by default.
- **Step**: 7.6.
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
- **Notes**: Disabled by default. Never creates an analysis object. execute_post_analysis runs at the end of every pass; detection points are presumably deduped by description (unsure).

### site_tagger

- **Section**: `analysis_module_site_tagger`, class `SiteTagAnalyzer` in `saq/modules/tag.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. Matches values against a site file; no network or database. Its CSV becomes a 5.14 list (5.14 says so).
- **Step**: 7.6.
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
- **ace4**: not yet.
- **Pool**: parser. ace3 runs zip2john, John and 7z. As 4.11 did for Office, the task tries the email's wordlist itself, with the zip crate's ZipCrypto and AES, as `ace-mod-archive` already reads zips. 7.3 records John's decision.
- **Step**: 7.5 batch 7 (Encrypted files).
- **Does**: For a zip with any encrypted entry, extracts its hash with zip2john, cracks it with John the Ripper using words from the carrying email, and extracts the archive with 7z using the cracked password.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body file (no wait_for_analysis).
- **Libraries**: html2text 2025.4.15 (inline in zip.py, not via wordlist_from_email).
- **Tools**: zip2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; 7z 25.01 `7z x -y -p<password> -o<abs dir> <file>` via run_sandboxed_tool, timeout extract_timeout=5s, write_dirs=[{file}.decrypted].
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this); 7z uses multiple threads
- **Writes**: {file}.hash; {file}.wordlist; {file}.hash.pot; {file}.decrypted/<members> (added as observables).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: /opt/tools/john-1.9.0-jumbo-1/run (john_bin_path).
- **Tags and detections**: 'encrypted_zip' tag on source; each extracted member gets detection point EMAIL_ENCRYPTED_DECRYPTED and extract_urls directive.
- **Notes**: Encryption check via stdlib zipfile flag_bits & 1. No default passwords; without an email body nothing is cracked. Wordlist logic duplicates cracking.wordlist_from_email (zip.py:195-214). Password passed on 7z's command line. Members extracted before a 7z stop are still added (zip.py:249-255). Loop variable shadows _file (zip.py:261). Decrypted members not volatile.

### rar_encryption_analyzer

- **Section**: `analysis_module_rar_encryption_analyzer`, class `RarEncryptionAnalyzer` in `saq/modules/email/encryption/rar.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. ace3 runs rar2john, John and unrar. The unrar crate `ace-mod-archive` uses takes a password, so the task tries the wordlist itself, as 4.11 did. 7.3 records John's decision.
- **Step**: 7.5 batch 7 (Encrypted files).
- **Does**: For a RAR that rarfile says needs a password, extracts its hash with rar2john, cracks it with John the Ripper using words from the carrying email, and extracts it with unrar using the cracked password.
- **Input**: file.
- **Groups and modes**: groups file; modes analysis, binary, cli, correlation, email, file.
- **Depends on**: search_down() to the carrying EmailAnalysis and its body file (no wait_for_analysis).
- **Libraries**: rarfile 4.5 (RarFile.needs_password header check only); html2text 2025.4.15 (inline in rar.py).
- **Tools**: rar2john (john run dir) via run_sandboxed_tool; john 1.9.0-jumbo-1 (openwall git master, built with plain ./configure, so OpenMP is enabled if detected) via saq/cracking.py crack_password(): two run_sandboxed_tool calls, `john --session=john --pot=john.pot --wordlist=<abs> <hash>` (pot moved out as {hash}.pot) then `john --pot=<pot> --show <hash>`; unrar 7.1.8 `unrar x -y -kb -p<password> <file> <abs dir>/` via run_sandboxed_tool, read_files=archive_volumes(), write_dirs=[{file}.decrypted], timeout = time_left().
- **Threads and children**: john runs one OpenMP thread per core (base_module.py:476 comment; RLIMIT_CPU is scaled by cpu_count for this); unrar may use threads
- **Writes**: {file}.hash; {file}.wordlist; {file}.hash.pot; {file}.decrypted/<members> (added as observables).
- **yara_meta**: none.
- **ACE's data**: none.
- **Secrets**: none.
- **Network**: none.
- **Reads outside the alert**: /opt/tools/john-1.9.0-jumbo-1/run (john_bin_path); sibling volume files of a split archive (archive_volumes, saq/modules/file_analysis/archive.py:108).
- **Tags and detections**: 'encrypted_rar' tag on source; each extracted member gets detection point EMAIL_ENCRYPTED_DECRYPTED and extract_urls directive.
- **Notes**: Near copy of zip.py (diff is check, tools, messages). unrar used directly because rarfile would run unrar outside the sandbox (rar.py:239-241). UNRAR_WRITE_ERROR (5) keeps partial output; other non-zero exits return without adding files. No explicit extract timeout. Unsure whether rarfile.needs_password ever calls an external tool; this path only parses headers.

### pdf_encryption_analyzer

- **Section**: `analysis_module_pdf_encryption_analyzer`, class `PDFEncryptionAnalyzer` in `saq/modules/email/encryption/pdf.py`, enabled by default.
- **ace4**: not yet.
- **Pool**: parser. ace3 runs pdf2john.pl and John. libqpdf, which `ace-mod-pdf` links, opens a PDF with a password, so the task tries the wordlist itself, as 4.11 did. 7.3 records John's decision.
- **Step**: 7.5 batch 7 (Encrypted files).
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
- **ace4**: not yet.
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
- **ace4**: not yet.
- **Pool**: lookup. Database and bucket writes at disposition; its git calls are for the rule inventory, which ace4's ruleset already records.
- **Step**: 7.10.
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
- **ace4**: not yet.
- **Pool**: lookup. Reads SVS run state through the internal API (7.2).
- **Step**: 7.10.
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
- **ace4**: not yet.
- **Pool**: parser. Decodes an image and compares hashes; the reference images come from the analyst data repository.
- **Step**: 7.5 batch 2 (File identity).
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
- **ace4**: not yet.
- **Pool**: lookup. One read per observable of the observables flagged for detection, a Redis cache today and a 5.14 list in ace4 (5.14 says so).
- **Step**: 7.6.
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
- **ace4**: not yet.
- **Pool**: scanner. Drives Chrome against attacker URLs in a container a Celery manager starts; 7.7's scanner pool replaces the manager, with a delayed task while it runs.
- **Step**: 7.7.
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
- **ace4**: not yet.
- **Pool**: lookup. Splunk searches with delayed analysis. ace4's Splunk module (`ace-mod-splunk`, 1.28) is ace3's `SplunkAPIAnalyzer`, which tests/e2e/site/overlay.yaml runs as an instance under this name; this class, with its clicker_detection.yaml searches, isn't ported. Splunk's client stays in this workspace (7.8).
- **Step**: 7.4.
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
- **Notes**: Disabled by default. Uses delayed analysis: each search is an async Splunk job; delay_analysis with async_delay until query_timeout, then records 'timed out' in query_error so silence is not read as 'no clicks'. The plan of searches is snapshotted in details (clicker_plan/clicker_index) to survive resumes. custom_requirement makes it a no-op when the config has no enabled search for the source+type. Inherits BaseAPIAnalyzer (saq/modules/api_analysis.py) correlation_delay and max_result_count defaults from api_defaults.

## site_ace

PLAN.md 7.1 gives a site's modules the same inventory in a site's Rust workspace (2.32), which isn't on this machine (`~/Development/site/site_port`), so that half is blocked. ace3's checkout holds the site_ace Python repository under `integrations/site_ace` (at `59064f6`). It could be read here, but its inventory stays out of this repository: it describes a site's own systems, and the plan puts it in the site's workspace. It's left for 7.8, which ports those integrations there.

What's there, by count: 34 `analysis_module_*` sections ace3's config doesn't have. 20 are in the integrations' own config files (9 in `ace_endpoint_vendor`, 4 in `ace_mail_api`, 4 in `ace_vt`, 2 in `ace_example_sandbox`, 1 in `ace_wiz`; `ace_rapid7` and `ace_intel_feed` have none) and 14 in a site's own: 5 of its own Python modules, 2 on `ace_endpoint_vendor`'s LogScale classes and 7 instances of ace3's `SplunkAPIAnalyzer`, which would run on `ace-mod-splunk` as overlay instances. So 27 are code to port and 7 are Splunk queries. site_ace also overrides the settings of 11 of ace3's sections, keeping their classes, which this inventory's entries cover.

