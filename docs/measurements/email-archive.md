# Batch 9's email archive: crafted archives

PLAN.md 7.5 batch 9. The four modules are lookups and parse nothing an attacker wrote; what does is the core, which opens an archived email for two reads: `decrypted-archive`, for a `.gz.e` file anyone can put in an alert, and `archived-email`, for an email the archive kept. (Since ace4 followed ace3 to `85c8e9e5`, only `archived-email` and its module are left: `decrypted-archive` went with `encrypted_archive_analyzer`, and the core reads only the v1 layout it writes. The bounds below still hold for it.) ace3 streams both and sets no limit, so a small `.gz.e` that gunzips without end fills its disk (`archive.py:75`). The core (`ace_core::email_archive`) opens in memory, in a blocking thread, and bounds it:

- a sealed object larger than 64 MiB and a sixteenth isn't read;
- the AES-256-GCM tag is checked before anything is gunzipped, so a file the key didn't seal, or one with a byte changed, costs one decryption and no gunzip;
- the gunzip stops at 64 MiB (`MAX_EMAIL_BYTES`) and the read answers with an error, which the module logs, as ace3's logs an exception;
- the archiver's write seals at most a 64 MiB email; a larger one fails its task, saying why.

Measured on 2026-11-10 in the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs, 24 GB), with ace3's and budge's stacks up. A dev build, unoptimized, where AES and deflate are much slower than in a release build:

    cargo test -p ace-core --lib measure_open -- --ignored --nocapture

opens each input with `email_archive::open`, the function both reads call, 5 runs each. The times are the decryption and the gunzip alone: they leave out reading the object from the bucket and putting the email back.

| Input | Sealed size | Outcome | Median, seconds | Range, seconds |
|---|---|---|---|---|
| a 64 MiB email of bytes that don't compress | 67,129,109 | opens | 4.86 | 4.85 to 4.90 |
| the same with one byte changed | 67,129,109 | the tag fails; nothing is gunzipped | 0.95 | 0.92 to 0.96 |
| a 64 MiB email and one byte more | 67,129,110 | stops at 64 MiB | 4.80 | 4.75 to 4.80 |
| 1 GiB of zeros, gzipped and sealed | 1,043,708 | stops at 64 MiB | 0.44 | 0.43 to 0.46 |

The bomb's cost is the 64 MiB it writes before it stops, not its gigabyte. Each open holds at most the sealed object, its plaintext and 64 MiB of email at once, about 200 MiB at the bound, in `ace serve`; a lookup task waits on it within its own deadline, 300 seconds by default. `a_sealed_gzip_bomb_stops_at_the_bound` keeps the stop as a test.
