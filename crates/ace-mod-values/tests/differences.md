# Differences from ace3's reference dumps

`tests/reference.rs` runs each module on each observable `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<dump>` here, with the dump's directives and relationships. The observables are `tools/ace3/dumps/make-dumps`' `VALUE_RUNS`, hand-written. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
| `command_line_analyzer/*` | `/details/base64_payloads/*/file_path` | ace3 names each payload's file by its path on its node, `<root>/files/<name>`, which has no meaning once files live in the bucket. ace-rs writes the path in the alert, which is what ace3's ends with: checked on every payload here, the rest of each path is the same, and the files themselves, by path, sha256 and size, match. |

## Behaviour the dumps don't exercise

These depart from ace3:

- `command_line_analyzer` numbers a payload's file name, `_000` and on, only against the files of its own result. ace3's `create_output_file` numbers it against every file in the alert, so a second command line in one alert writes `command_line_base64_payload_000.bin` there and `command_line_base64_payload.bin` here, with other bytes.
- `command_line_analyzer` writes the first 500 payloads' files. ace3 writes them all, but its root takes at most 500 file observables (`maximum_observable_count`), which ace-rs's core doesn't have; the rest are in the details only, with the name their file would have had. A command line of 80,000 encoded words otherwise made a task upload 80,000 files for minutes (`docs/measurements/observable-values.md`).
- `command_line_analyzer` drops a path that a longer one starts with by sorting the paths, where ace3 compares every pair. The result is the same, and a command line of many paths costs `n log n` rather than `n²`.
- `network_identifier` reads its networks from the overlay's `networks` setting rather than ace3's CSV file. iptools' patterns use Python's `\d`, which takes any Unicode digit; the port reads ASCII digits only, so a range written with other digits stops the module from starting where ace3 would read it.
- `protected_url_analyzer` takes Proofpoint's URL as the first in sorted order where urlfinderlib finds more than one; ace3 pops one from a set, in an order that changes with each process's hash seed.
- A 1drv.ms link is followed by `protected_url_one_drive` on the lookup pool, not by `protected_url_analyzer`, so its result is under that name (`docs/modules.md`). It asks only 1drv.ms and its subdomains, where ace3 asks any host ending in `1drv.ms`, and follows a redirect only to its `redirect_hosts`, Microsoft's by default, where ace3 follows any; a link it doesn't follow is recorded as ace3 records one it couldn't fetch. It reads the status and the `Location` of each answer and no body. The dumps' three links are compared with the lookup's result from the same recording ace3 was answered from.
- `idna_analyzer` leaves out a spelling ace3's fqdn check refuses, where ace3 fails on it, having stored its analysis. The only cases found are names that check refuses too, such as a label past 63 characters, so ace3 never holds one as an fqdn; ace-rs's core can be given one.
- ace3 adds `email_address_fqdn_analyzer`'s fqdn as volatile. ace-rs has no volatile flag, which in ace3 only the GUI's pruning and the analysis cache read.
