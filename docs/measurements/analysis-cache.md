# The analysis cache: what a hit costs against a run

PLAN.md decision 26, docs/decisions/0004. Measured on 2026-11-18 on the laptop (Docker with 10 CPUs), on a
stack `tests/e2e/run --compare --keep` left up, with the code of this change.

## Command

    tools/lease/measure --cache --runs 6

`--cache` starts the core on a copy of the e2e site whose overlay turns the cache on, and makes the
runs in pairs: the cache is emptied (`cache.results`, `cache.probes`) before each pair's first run, which
is cold, and the second runs warm on what the first kept. Each run is `ace compare` over the 14 large
samples (`DEFAULT_SAMPLES`), 8 at once. Six runs: three cold, three warm.

## The runs

| | cold (3) | warm (3) |
|---|---|---|
| `ace compare`'s seconds, median (range) | 68.5 (67.5 to 71.2) | 68.8 (68.0 to 74.3) |
| tasks | 15,118 (15,015 to 15,174) | 15,017 (14,999 to 15,055) |
| CPU seconds, every service | 235.6 (233.7 to 239.2) | 239.4 (233.4 to 240.1) |
| results from the cache, of 6,309 | 7 (7 to 7) | 23 (23 to 23) |

A cold run takes 7 results from the cache because the samples share images: a result one sample kept is
a hit in another in the same run. The warm runs take 23: about 100 fewer tasks, and no difference in
time or CPU that the spread doesn't cover (the first warm run, 74.3 s, was the slowest of all six). On
the laptop's comparison the cache saves nothing to speak of, as the decision record expected: these
samples are made of the modules that don't opt in, and each sample is new to the stack.

## A hit against a run

From the same stack, after the six runs (rows of roots created in the last 15 minutes, which may hold the
tail of the comparison before them):

| module | its tasks that ran and kept a result: n, median run time, range | lookups: hits, misses, keeps | a lookup, mean ms (max) |
|---|---|---|---|
| `qrcode` | 292, 177.7 ms, 40.4 ms to 3,993 ms | 36, 54, 42 | 0.593 (5.99) |
| `pdf_link_text` | 80, 71.5 ms, 24.8 to 139.2 ms | 0, 12, 0 | 0.187 (0.48) |
| `rdap_analyzer` | 278, 29.7 ms, 4.8 to 90.3 ms | 54, 936, 12 | 0.159 (2.06) |
| `nrd_analyzer` | 9, 42.6 ms, 15.9 to 69.1 ms | 0, 1,242, 0 | 0.225 (2.41) |
| `site_tagger` | 23, 16.8 ms, 10.1 to 58.8 ms | not on in this stack | |

A task's run time is decision 24's: from its claim to its end, a pool slot's time, with the lease's
decision, the task process, the file's download and the result's upload; a lookup's time is the core's,
from making the key to its hit or miss (`cache.activity`, the module event's `cache_lookup_ms_*`). So a
hit costs under a millisecond of the core's time and the result's own writes, which a run also makes,
where a qrcode run held a sandbox slot a median 178 ms and at most 4 s. The 18 rows the stack kept
hold 6,506 bytes of envelope.

## What else the numbers could be measuring

- Misses that can't become hits: most of `rdap_analyzer`'s misses are names the e2e responder has no
  recording for, whose results have an error and so aren't kept; `nrd_analyzer`'s are names not on the
  list, which the module skips, so nothing is kept; `pdf_link_text`'s misses are on Ghostscript's rewrites,
  new bytes each run.
- A lookup at a task's lease isn't timed (none happened here: no kept result waited for its path).
- A lookup's time includes making its key, the list read for qrcode's `qrcode_filter` and the
  `newly-registered` answer for `nrd_analyzer`; the result's writes on a hit aren't in it.
- The task run times are of the runs that kept a result, cold and warm runs and possibly the end of the
  comparison together, one run each; tasks that skipped (no image, not listed) are left out.
- The kept stack holds the comparison's roots and every earlier run's, so later runs read a larger
  database; the order was cold, warm, cold, warm, cold, warm, so that drift falls on both.
