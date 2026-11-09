# Batch 3's modules against crafted values

PLAN.md 7.5: a contained parser task is one thread with no exec, so each module is bounded for hostile input, and what crafted input costs it is measured against its limits. Batch 3's modules read an observable's value, not a file, and each has the default 300 s, 1 GiB and 300 CPU seconds. ace3 gives them no limit of their own. `email_address_fqdn_analyzer` and `file_location_analysis` split a value once at its first `@` and aren't measured.

Measured on 2026-11-09 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs), with ace3's and budge's stacks up.

## Command

In the dev container, for each module:

    ACE4_VALUES_MODULE=<module> cargo test -p ace-pool --features test-pools --test supervisor \
        measure_observable_values -- --ignored --nocapture

builds each of the module's values in the test, puts it in a new root and queues the module's task, which the real supervisor runs as `ace4-task` under Landlock and seccomp with the module's limits. The module is alone in the catalog, so what it adds queues nothing else. 3 runs each, the value changed by trailing spaces each run. The time runs from the task's queueing to its end with its result landed, so it includes the lease, the task process's start, the uploads and the core writing the result's observables. It's a dev build, with `ace-mod-urls` at `opt-level = 3` and the rest of the task unoptimized.

## Results

| Value | Bytes | Module | End | Seconds, 3 runs |
|---|---|---|---|---|
| `paths_1mb`: `C:\a\b ` repeated | 1,048,572 | command_line_analyzer | done | 0.99 to 1.10 |
| `prefixes_1mb`: 65,536 paths `C:\0` to `C:\ffff`, many the start of others | 519,920 | command_line_analyzer | done | 13.82 to 14.30 |
| `quoted_paths_1mb`: quoted and escaped drive and UNC paths | 1,143,888 | command_line_analyzer | done | 0.84 to 0.88 |
| `unc_open_1mb`: `"\\` and half a million quotes, no closing backslash | 1,048,579 | command_line_analyzer | done | 0.52 to 0.53 |
| `base64_1mb`: `powershell -enc` and 1 MB of base64 | 1,048,592 | command_line_analyzer | done | 0.37 to 0.41 |
| `base64_words_1mb`: `pwsh -e QUJD` repeated, 80,659 payloads | 1,048,567 | command_line_analyzer | done | 4.43 to 4.78 |
| `separators_1mb`: a user path, then a million backslashes | 1,048,585 | file_path_analysis | done | 0.26 to 0.37 |
| `url_1mb`: a query of 262,144 parameters | 1,048,597 | parse_url | done | 0.39 to 0.50 |
| `host_first_1mb`: a 1 MB host with no scheme | 1,048,582 | parse_url | done | 0.31, 0.31, 0.31 |
| `label_100k`: one label of 100,000 `é` | 200,004 | idna_analyzer | done | 0.26 to 0.32 |
| `labels_1mb`: 262,144 labels `éa` | 1,048,579 | idna_analyzer | done | 0.85 to 0.87 |
| `proofpoint_1mb`: a Proofpoint URL wrapping 37,449 URLs | 1,011,166 | protected_url_analyzer | done | 0.65 to 0.80 |
| `dropbox_1mb`: a Dropbox URL with 262,144 parameters | 1,048,604 | protected_url_analyzer | done | 0.69 to 0.74 |
| `urldefense_1mb`: a URLDefense v3 URL of `_a` repeated | 1,048,604 | protected_url_analyzer | done | 0.21 to 0.22 |
| `networks_2000`: an address against 2,000 networks | 10 | network_identifier | done | 0.16 to 0.27 |

Every task ended `done`, well inside its deadline. What each value does:

- `prefixes_1mb` makes 65,536 `file_path` observables. ace3 drops a path another starts with by comparing every pair, which is 4 billion comparisons here; the port sorts, and the time is the core writing the observables.
- `base64_words_1mb` first ran past 420 s and was still uploading when the test gave up: each `QUJD` after PowerShell's `-e` is a payload, and the module wrote 80,659 files in 30 s, which the supervisor then uploaded one by one. ace3 would write them all too, but its root takes at most 500 file observables (`maximum_observable_count`), which ace4's core doesn't have. So the module writes the first 500 payloads' files and lists the rest in its details, and the task takes under 5 s.
- `unc_open_1mb` and `quoted_paths_1mb` exercise `find_nt_paths_in_text`'s four patterns, each a scan to the next quote from each start, so the text is read a few times over.
- `label_100k` is too long a label for the idna package and for Python's IDNA 2003 codec, so its IDNA spelling is empty, as urlfinderlib gives it, and the result has no observable. `labels_1mb` has 262,144 short labels, each encoded, and its 2.6 MB IDNA spelling isn't a domain ace3's fqdn check takes, so it isn't added either. Neither is a name ace3 would hold as an fqdn, since that check refuses both.
- `proofpoint_1mb` runs urlfinderlib's text finder over the URL. The other two never reach it.
- The network identifier reads its 2,000 networks once, when the pool starts, and checks the address against each.
- `protected_url_one_drive` is a lookup and isn't contained: it sends at most 31 requests, each within 8 s, only to Microsoft's hosts, and reads no body (`docs/modules.md`).
