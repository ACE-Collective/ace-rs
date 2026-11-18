# Batch 7's encrypted attachment modules: crafted files

PLAN.md 7.5 batch 7. `zip_encryption_analyzer`, `rar_encryption_analyzer` and `pdf_encryption_analyzer` try the carrying email's candidate passwords in the task, where ace3 gives them to John the Ripper (7.3). A contained parser task is one thread with no exec, so each module is bounded for hostile input and what crafted input costs it is measured against its limits.

## The bounds

- **How many candidates.** At most `list_limit`, 5,000, cut from at most `byte_limit`, 1,024 characters of each body part, by `ace_mod_msoffice::words_from_parts`, 4.11's made ace3's again at its `1998ca56`. A part of 1,024 characters with no whitespace fills the list.
- **What one costs.** The format's key derivation, which the file fixes or caps, and for some formats data:
  - zip AES: PBKDF2-SHA1, 1,000 rounds, per AES entry; the entry's data only for a candidate whose 2-byte verifier matches. Entries are tried from the last, which decides ace3's answer, so a shared password costs one entry's work.
  - ZipCrypto: no derivation; the smallest of up to 8 entries is decrypted and inflated only for a candidate past its check byte, about 1 in 256. zip2john writes that entry's data into its hash, and ace3 stops a tool past 64 MiB of output, so past about 32 MiB the result is ace3's `zip2john did not finish`, with nothing tried.
  - RAR4: libunrar's derivation, 2^18 SHA-1 rounds, and the file rar2john picks decrypted, unpacked and its CRC checked; the same 64 MiB limit on rar2john's hash makes a file over about 32 MiB `rar2john did not finish`.
  - RAR5: libunrar's PBKDF2-HMAC-SHA256, 2^lg2count rounds, which the archive sets: 15 as RAR writes it, and up to 23 here, since rar2john refuses 24.
  - PDF: MD5 and RC4 for revisions 2 to 4, one SHA-256 for 5, and for 6 the hardened hash, 64 or more rounds of AES and SHA-2 on under 3 KB.
- **How long in all.** Each module stops trying 10 s before its timeout, leaving that for extracting or decrypting, and its result is then ace3's when John is stopped: no password. zip and PDF have 120 s, RAR 300 s; each has 2,048 MB.

## Crafted files

`tools/samples/make-encrypted-hostile <dir>` writes the files, in Debian containers with 7-Zip, Info-ZIP, qpdf and RARLAB's rar 6.24. In the dev container:

    ACE4_ENCRYPTED_HOSTILE=<dir> cargo test -p ace-pool --features test-pools --test supervisor \
        measure_encrypted -- --ignored --nocapture

attaches each file to an email whose body is 1,200 letters with no whitespace, so 5,000 candidates and none of them the password, and submits it to the real supervisor, which runs each module as `ace4-task` under Landlock and seccomp with its limits. 3 runs each, each in a new root. The time runs from the root's submission until the root is idle, so it includes the email module, the upload, the lease and the task process's start. It's a dev build, with the hashes, ciphers and libunrar optimized (`Cargo.toml`) and the rest not. Measured on 2026-11-09 on the dev container (Rancher Desktop, 10 CPUs, 24 GB), with ace3's and budge's stacks up.

ace3's column is one run of its module on the same file and body in ace3's dev container (`run_module.py --carrying-email`), from the process's start, about 3 s of which is ace3's engine starting. Its John has ten threads.

| File | Size | ace4, median (range), s | ace4's result | ace3, s | ace3's result |
|---|---|---|---|---|---|
| `pdf_aes_256.pdf`, revision 6 | 3 KB | 4.3 (4.1-4.4) | could not crack | 2.9 | the same |
| `rar4.rar`, files encrypted | 145 B | 38.5 (38.0-38.7) | could not crack | 8.8 | the same |
| `rar5.rar`, files encrypted | 188 B | 125.7 (124.4-127.3) | could not crack | 6.3 | the same |
| `rar5_headers.rar`, `-hp` | 286 B | 123.0 (122.7-123.4) | could not crack | 6.2 | the same |
| `rar5_headers_kdf_2^23.rar`, its KDF count raised to 2^23 | 286 B | 295.7 (295.3-296.6), stopped at the deadline | could not crack | 297.0 | the same |
| `rar4_64mb.rar`, one 64 MB stored file | 64 MB | 4.5 (4.5-4.6) | rar2john did not finish | 4.2 | the same |
| `zip_aes_200_entries.zip`, 200 AES entries | 49 KB | 112.6 (112.6-112.8), stopped at the deadline | unable to crack | 16.9 | the same |
| `zip_zipcrypto_64mb.zip`, one 64 MB stored entry | 64 MB | 4.4 (4.4-4.4) | zip2john did not finish | 4.9 | the same |

Every task ended `done` with ace3's result, and the supervisor kept running. These runs were made before ace3's `1998ca56`: "could not crack" and "unable to crack" were the result's error then, and are "password not available" in its summary, with no error, since. The candidates of a 1,200-letter body are 5,000 substrings either way, so the times stand. The two 64 MB files were measured again after the port learned ace3's output limit: before it, they took 294.6 s (RAR4, stopped at the deadline) and 40.1 s (ZipCrypto), and gave `could not crack`, where ace3 says the tool didn't finish. During the remeasurement the dev stack's bucket was killed for memory, at its 1 GiB, while compacting after the 64 MB uploads; it was started again and the runs repeated.

What it means:

- A RAR5 candidate costs about 25 ms of one thread in libunrar, so a full list takes about 125 s, inside the RAR module's 300 s; ace3's John takes 6 s with ten threads and SIMD. A RAR4 candidate costs about 7.5 ms. libunrar's SHA-256 is portable C; checking RAR5's check value with the `sha2` crate would be faster, and is left for now.
- A crafted RAR5 KDF count makes each candidate cost up to 256 times as much; the module stops at its deadline, as ace3's John is stopped.
- 200 AES entries and no password cost 200 derivations a candidate, and the module stops at its deadline, where ace3's John finishes the list. Both find nothing; with the password in the list, ace4 cracks the last entry alone, and the rest share it.
- In the PDF, the time is the email module and the task's start as much as the 5,000 hardened hashes.

The fixtures' dumps (`tools/ace3/dumps/reference/{zip,rar,pdf}_encryption_analyzer`) cover a full list: `zip/zipcrypto.zip.full_early` cracks with the password among the first 5,000 windows, and `full_late` doesn't, with the password past them, on both sides.
