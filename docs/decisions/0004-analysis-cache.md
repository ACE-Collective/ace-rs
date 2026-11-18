# 0004: A cache of module results across alerts

Status: proposed on 2026-11-18. The owner decided that day that ace4 needs a version of ace3's analysis result cache; this is the design for the owner to review before any code. It replaces PLAN.md 6.7's "ace4 has no analysis cache".

## Why

The same thing turns up in many alerts: the same image in a hundred phishing emails, the same domain in a week of hunts. ace3 runs a module once on it and reuses the result in later alerts for a time the module's config sets (`cache_ttl`). The owner's figure: hundreds of hours of compute a day saved in production, from OCR and QR code alone. For a site's lookups it also spares vendor quotas.

ace4 has nothing like it. Decision 15's "one analysis per file" holds inside one root only: the next alert with the same file runs every module on it again.

## What ace3 does (`ace3/docs/ANALYSIS_CACHING.md`, at `fe6da632`)

- **Opt-in per module**, with a time to live: `rdap_analyzer` 7 days, `nrd_analyzer` 24 hours, `site_tagger` 30 days, `ocr` 7 days, `qrcode` 7 days, `phishkit_analyzer` 6 hours, `pdf_link_text` 30 days. A global switch stops all writes.
- **The key** is a sha256 over the observable's type and value, the module's name and version, a hash of its config (less operational fields), and an *extended version*: what else the output depends on, such as tesseract's version for OCR or the content hash of a list file for `site_tagger`.
- **What is stored** is the module's *delta*: the analysis it made, the observables it added (files by content, in a blob store), and what it added to the observable it analyzed. Most of ace3's design is about finding that delta, because an ace3 module edits the tree in place and nothing records which module did what.
- **Never cached:** a failed analysis (`Analysis.error`), a module that hasn't finished (a delay), a result that removes anything or touches observables other than its own and its new ones, a delta over 1 MiB.
- **A hit** replays the delta into the new root as if the module had run, and is recorded as a hit. Expired rows are dropped by daily partitions.
- **Not cached on purpose:** YARA, whose output depends on the file's name and `yara_meta`, which the content key doesn't see.

## The design for ace4

**What makes it simpler here.** An ace4 module doesn't edit the tree. It returns one result envelope, and the core applies it: its details, summary, tags, detections and the observables and files it adds, each addition recorded against the result (`analysis.result_additions`). The envelope *is* the delta. Files are already stored once by content in the bucket. So ace4 caches the envelope and the sha256s of its files, and a hit applies that envelope through the same path as a task's end.

**A module opts in** with `Module::CACHE`: whether it may be cached, and what its extended version is (a function of its settings and its tools' versions, as decision 23's declarations are built from its settings). The time to live is a setting in the overlay, per module, so a site sets it as ace3's config does, and the global switch is a setting too.

**Only a module whose output depends on nothing but its key may opt in.** A module's lease says what else it reads: dependencies' results (`DEPENDS_ON`), the tree (`READS_TREE`, `READS_ADDED_BY`), the carrying email, its path or `yara_meta`. A pool refuses to start with a cacheable module that reads any of them, unless what it reads is part of its key. This is the rule ace3 enforces with a contract lint, made a check the binary can't skip.

**The key** is a sha256 over: the cache's format version; the observable's type and value (a file's value is its sha256); the module's name, version and instance; a hash of its settings, less the time to live; and its extended version. Under docs/decisions/0003 a file's type facts follow from its sha256, so they need no place in the key; its role does not, so a module whose output depends on the role must put it in its key or not opt in.

**Where the cache is checked: in the core, before a task is queued.** When eligibility would queue a cacheable module's task, the core looks the key up first. A hit writes the cached envelope as that module's result on the observable, records it as a hit, and queues no task: no lease, no pool, no process. A miss queues the task as now, and its end writes the cache when its result may be cached. One indexed lookup per would-be task of an opted-in module, and none for any other module.

**Never cached:** a result with `error` set (decision 19); a task that failed, timed out or was cancelled; a delayed task until its final run, and then the final envelope only; a result that adds to anything but its own observable and the observables it creates; an envelope larger than a limit (ace3's 1 MiB, compressed).

**Storage: Postgres and the bucket, nothing new.** A table in its own schema, `cache.results`: the key, the module, the observable's type and value, the envelope as `jsonb` (Postgres compresses large values itself), the files' sha256s, `created_at` and `expires_at`. The newest unexpired row for a key wins, as in ace3. Each row holds its files in the bucket, as a root does today, so the bucket's collector doesn't remove a file a cache row still names. Expired rows go by daily partitions, dropped by a scheduled task (7.12's scheduler), with the retention longer than the longest time to live.

**What a person sees.** A result from the cache is the module's result, shown and returned as any other, with a mark saying it came from the cache and when the original ran (ace3's `from_cache_hit` and `cached_at`). The metrics event's module records (decision 24) count hits and misses per module, as ace3's do.

## The comparison with ace3

`tests/e2e/run`'s comparison runs with the cache off, so every sample is analyzed live and the comparison checks the modules, not the cache. A new check in the same run turns the cache on and runs a set of samples twice: the second run must take its cached modules' results from the cache, run none of their tasks, and give the same normal form as the first. That is the proof a hit is equivalent to a run.

## Expected effect

On the laptop's comparison it saves nothing, by design. In production it saves what ace3's saves, for the same modules: the owner's figure for OCR and QR code is hundreds of hours a day. With ace4's other costs gone (decisions 21 to 23) a cached module costs one indexed lookup and one result write where it cost a contained process and its tool. The step measures a hit's cost and a run's on the 14 large samples, run twice with the cache on.

## In what order

1. The cache itself (opt-in, key, the core's check, storage, the bucket holds, expiry, the mark, metrics), with ace3's seven opt-ins, and the two-run check in `tests/e2e/run`.
2. a site's five cacheable modules opt in as they are ported (the site port's `docs/modules.md`, question 9).

Not now: ace3's designed-but-unbuilt *single flight* (two alerts with the same new file at the same moment both run the module; the second could wait for the first).

## What the owner decides

1. Whether the cache is checked before a task is queued (no task on a hit), as proposed, or at the lease.
2. Whether the comparison runs with the cache off plus the two-run check, as proposed.
3. Whether ace3's seven opt-ins and their times to live are ace4's defaults.
4. Whether the time to live lives in the overlay per module, as proposed.
