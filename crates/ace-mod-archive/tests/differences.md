# Differences from ace3's reference dumps

`tests/reference.rs` runs the archive module on each sample that `tools/ace3/dumps/reference/archive/` has a dump for, with the mime type ace3's file_type module found, puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 844e3584. A second test runs the module with no file limit and checks every file ace3 extracted against ace4's by path, size and sha256.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `ace3/archive/dhl_report.ace` | `/` | ACE archives aren't read: ace3 runs `unace`, and no Rust crate reads the format. The module skips the file, so there is no result. |
| `*` | `/analyzed/tags/zip` | ace3's file_type module tags a zip file `zip`. The dumps ran it as the archive module's dependency; ace4 has no file_type module yet. |
| `*` | `/analyzed/tags/jar` | file_type's tag for a JAR. |
| `*` | `/analyzed/yara_meta/type=archive.jar` | file_type's `yara_meta` tag for a JAR. |
| `*` | `/observables/*/tags/*` | file_type's tags on the extracted files (`zip`, `jar`, `executable`). The archive module tags no file. |
| `*` | `/observables/*/yara_meta/*` | file_type's `yara_meta` tags on the extracted files (`type=archive.jar`, `type=executable`, `type=script.javascript`). The archive module sets none. |
| `local/archive/zip-slip.zip` | `/details/extracted_files/*` | The two files come out in archive order, `x` (stored as `../x`) then `readme.txt`. ace3 lists its extraction directory with `os.walk`, whose order is the filesystem's: on the tmpfs the dumps ran on that is newest first, so `readme.txt` came first. On ext4 it is the order of the names' hashes. The files, names and tags match. |
| `local/archive/zip-slip.zip` | `/summary` | The summary lists the files in the same order. |
| `ace3/archive/malicious.jar` | `/observables/*` | More files than the limit (68 entries, 30 extracted). Both pick the riskiest kinds first, but within a kind ace3 takes them in its filesystem's order (above) and ace4 in archive order, so they pick different files of the same kind. The no-limit test shows every file ace3 extracted comes out of ace4 with the same bytes. |
| `ace3/archive/malicious.jar` | `/details/extracted_files/*` | The same choice of files. |
| `ace3/archive/malicious.jar` | `/summary` | The same choice of files, in the summary. |
| `ace3/archive/too_many_files.jar` | `/observables/*` | More files than the limit (1,037 entries, 30 extracted); the same choice of files as `malicious.jar`. |
| `ace3/archive/too_many_files.jar` | `/details/extracted_files/*` | The same choice of files. |
| `ace3/archive/too_many_files.jar` | `/summary` | The same choice of files, in the summary. |
| `ace3/archive/over.7z` | `/observables/*` | More files than the limit (11, 6 extracted); the same choice of files as `malicious.jar`. ace3 took `hello_world_9.txt` down to `_4`, the last ones 7z wrote; ace4 takes the first six. |
| `ace3/archive/over.7z` | `/details/extracted_files/*` | The same choice of files. |
| `ace3/archive/over.7z` | `/summary` | The same choice of files, in the summary. |
| `ace3/archive/test.jar` | `/observables/*` | More files than the limit (42 entries, 30 extracted); the same choice of files as `malicious.jar`. |
| `ace3/archive/test.jar` | `/details/extracted_files/*` | The same choice of files. |
| `ace3/archive/test.jar` | `/summary` | The same choice of files, in the summary. |
| `ace3/archive/test.jar` | `/observables/*/size` | 30 of this JAR's 42 entries have a CRC that doesn't match their bytes, a trick that a JVM ignores. Python's `zipfile`, which ace3 extracts JARs with, raises when it reaches the end of such an entry and loses the last chunk it read, so ace3 wrote these classes empty. ace4 writes each entry's bytes whole and logs the mismatch. |
| `ace3/archive/test.jar` | `/observables/*/sha256` | The same entries. |

## Behaviour the dumps don't exercise

These follow ace3 on purpose, so they aren't differences, but they're easy to get wrong:

- A zip member the password `infected` doesn't open, ZipCrypto or AES, is written as an empty file, and counts, tags and flags as a member. ace3's `7z -pinfected` leaves that empty file (checked with 7-Zip 25.01, ace3's), and ace3 lists what's in the directory. So a single encrypted `evil.exe` is still a detection. A 7z archive's member gets no file, in 7z and here: it's counted and not extracted.

These depart from ace3:

- Formats: zip (and JAR and the Office formats built on it), 7z, RAR and gzip are read. ace3's `7z` also opens cab, tar, ISO, MSI, bzip2, xz, arj, lzh and others, and `unace` ACE archives; those are skipped until a port needs them.
- A RAR's members are tried with the password `infected` too. ace3 passes `unrar` no password, so it extracts nothing from an encrypted RAR.
- An entry that fails to extract, other than a password's, is logged and the others are still extracted. ace3's JAR extraction stops at the first entry that fails, and its other tools carry on.
- When two entries extract to the same path, the later one wins, as 7z's `-y` and unrar's `-o+` overwrite. Each extracted file is its own result file, even when two have the same bytes.
- unrar is built with `RAR_SMP` and may start threads for a RAR 5 archive, and sevenz-rust2's LZMA2 decoder is set to one thread. The single-threaded containment of PLAN.md 2.18 will need unrar built without `RAR_SMP`.
