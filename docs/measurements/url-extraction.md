# URL and IOC extraction against their deadlines

PLAN.md 7.5 says `url_extraction` is done when a multi-line blob that times out in ace3 finishes in under 15 seconds in ace-rs. Both modules parse attacker text in one contained thread, so this also records what crafted text costs them against their limits: `url_extraction` has ace3's 15 s (deadline and CPU) and 2 GiB, `ioc_extraction` ace3's global 60 s and 2 GiB.

Measured on 2026-11-09 on the dev container of `docs/measurements/build-loop.md` (Rancher Desktop, 10 CPUs), with ace3's and budge's stacks up and idle.

## The blob

`tools/ace3/dumps/fixtures/urls/chat_log.txt`, 335,130 bytes, which `tools/samples/make-url-hostile --chat-log` writes: a support chat of 3,500 lines, each with ten `:(` and one URL, and only the last line with a `)`. Every `(` pairs with that one `)`, so urlfinderlib's text finder makes 35,000 tokens that each run to the end of the text, and the work grows as the square of its length. It holds 6 URLs.

**ace3**, in `ace-dev-1`, ace3's own code:

- `url_extraction` as ace3 runs it (`tools/ace3/dumps/run_module.py --module url_extraction --enable file_type --directive extract_urls`), 3 runs: each one logged `analysis module AnalysisModuleAdapter(URLExtractionAnalyzer) has exceeded it's maximum analysis time of 15 seconds` and `analysis module crash recorded`, with no analysis. 17.0, 17.0 and 17.3 s from `docker exec` to its end.
- urlfinderlib's `find_urls` on the bytes, which is the module's work, 5 runs in one process: median 17.35 s, range 17.27 to 18.74 s.
- With the cap raised to 600 s for one run (`fixtures/urls/uncapped.yaml`), the module finishes with the 6 URLs: the reference dump `url_extraction/chat_log.txt.uncapped`.

**ace-rs**: `ACE_RS_URL_HOSTILE=<dir with chat_log.txt> ACE_RS_URL_RUNS=7 cargo test -p ace-pool --features test-pools --test supervisor measure_url_extraction -- --ignored --nocapture` submits the file with `extract_urls` to the real supervisor, which runs `url_extraction` as `ace-rs-task` under Landlock and seccomp with the module's limits. Each run appends a line, so each is a new file. The time runs from the root's submission to the task's end, so it includes the upload, the lease and the task process's start.

- 7 runs: median 3.21 s, range 3.16 to 3.29 s. Each found the 6 URLs of ace3's dump, and `crates/ace-mod-urls/tests/reference.rs` checks the result against that dump field by field.
- This is a dev build, in which the dev profile builds `ace-urlfinder`, `ace-pycompat`, `ace-mod-urls`, memchr, rustc-hash, fancy-regex and regex-automata at `opt-level = 3` (the root `Cargo.toml`); the rest of the task process is unoptimized. A release build of the port's binary (`urlfinderlib`, uncontained) took 2.95 s once.

So ace-rs finishes in about a fifth of ace3's cap, where ace3 doesn't finish. Getting there took three changes that keep the output: `urlsplit_head` for the start of a split where only the scheme and netloc matter, `fix_possible_value` copying a token only when a step changes it, and `is_netloc_valid_tld` reusing the URL's split. Before them the port took 48 s, because each of a token's ten `urlsplit`s copied 300 KB.

## Crafted text

`tools/samples/make-url-hostile <dir>` and `--iocs <dir>` write the sets; each file is at most the modules' 10 MB. 3 runs each, as above.

`url_extraction`:

| File | Size | Runs | End | Seconds | URLs |
|---|---:|---|---|---|---:|
| `chat_log.txt`, the blob | 335 KB | 3 | done | 3.14 to 3.35 | 6 |
| `chat_log_x2.txt`, twice the lines | 670 KB | 3 | done | 12.18 to 12.20 | 6 |
| `chat_log_10mb.txt`, 100,000 lines | 9.6 MB | 3 | failed: SIGXCPU at 15 s | 15.02 to 15.04 | 0 |
| `redirects_10mb.txt`: 70,000 URLs, each with a URL in its query and a base64 email | 9.1 MB | 3 | done | 14.32 to 14.52 | 210,000 |
| `links_10mb.html`: 100,000 links | 4.8 MB | 3 | done | 3.13 to 3.19 | 100,000 |
| `invalid_tlds_10mb.txt`: 700,000 tokens that aren't URLs | 8.3 MB | 3 | done | 1.14 to 1.15 | 0 |
| `brackets_10mb.txt`: `(` ten million times | 10 MB | 3 | done | 0.16 to 0.73 | 0 |
| `quotes_10mb.txt` | 9.8 MB | 3 | done | 0.26 to 0.31 | 0 |

`ioc_extraction`:

| File | Size | Runs | End | Seconds |
|---|---:|---|---|---|
| `colons_10mb.txt`: `1:` five million times | 10 MB | 3 | done | 6.69 to 6.97 |
| `hex_10mb.txt`: 63-character hex runs | 10 MB | 3 | done | 2.93 to 3.02 |
| `refang_10mb.txt`: `hxxp`, `[.]`, `dot` and `[@]` to re-fang | 10 MB | 3 | done | 6.06 to 6.16 |
| `html_10mb.html`: 200,000 IPs and defanged URLs in markup | 9.4 MB | 3 | done | 4.90 to 4.91 |
| `dots_10mb.txt`: `a dot ` 1.7 million times | 10 MB | 3 | failed: fancy-regex's backtracking stack | 2.64 to 3.02 |

ace3's IOC work on the same files (BeautifulSoup, the re-fanging loop, `find_urls` and the patterns, as `execute_analysis` runs them, timed in `ace-dev-1`, one run each): colons 2.05 s, hex 1.12 s, refang 2.54 s, html 3.57 s, dots 1.52 s.

What this shows:

- **Nothing passes a deadline it shouldn't.** The one `url_extraction` file that does is the blob's shape at 10 MB, whose work is 800 times the blob's; ace3 needs far more than its cap for the blob alone. The task fails with a row and the supervisor keeps leasing, as ace3's killed module leaves no analysis.
- **The heaviest real shape is many URLs with children**: 210,000 URLs in 14.4 s. That comes close to the deadline, but it's a 9 MB file of nothing but redirect URLs, and ace3's `find_urls` takes 25.0 s on it (one run in `ace-dev-1`; 9.7 s on `links_10mb.html`).
- **`ioc_extraction` is slower than ace3 on large text**, 2 to 4 times, though inside its 60 s. Python's `re` is a tuned backtracker, and fancy-regex runs a pattern with a lookbehind through its own machine. Rust's `\b` and `\w` are used where the text has no character they class otherwise than Python's (`crate::pyre`); Python's own classes, written as lookarounds, ran the same files in 37 to 55 s. fancy-regex's limit on backtracking steps, which counts a whole search, is lifted, so the deadline bounds a pattern; its limit of a million backtracking frames stays, and a run of 3.4 million characters the email pattern's `[a-zA-Z0-9._%+-]*` takes one by one passes it. That task fails where ace3 finishes in 1.5 s; such a file needs the `extract_iocs` directive, which no ace3 module sets (only analyst rules and an integration do).
