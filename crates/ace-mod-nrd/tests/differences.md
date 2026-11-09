# Differences from ace3's reference dumps

`tests/reference.rs` runs the newly registered domains module on each fqdn and URL `tools/ace3/dumps/reference/nrd_analyzer/` has a dump for. ace3 read the SQLite list its own `refresh()` built from `tools/ace3/dumps/fixtures/nrd/lists` (`tools/ace3/dumps/nrd_reference.py`, whose record is `reference/nrd/reference.json`). The test answers the module's `newly-registered` read with what the core answers from the same domains; the core's read is tested through the lease API in ace-pool's `lease_api` test, and its normalization against every value of `fixtures/nrd/lookups.json` in `ace_sdk::nrd`'s tests. RDAP is replayed from the RDAP module's recording of IANA's bootstrap files and example.com, and from `fixtures/nrd/rdap`'s hand-written registrations. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

| Dumps | Path | Why |
|---|---|---|
| `fqdn_ace4-norecord.com` | `/details/lookup_error` | The registry's answer has no registration event, so ace3 asks WHOIS, which fails in a replay: its error is `rdap: rdap result has no registration date; whois: no WHOIS in a replay`. The WHOIS fallback isn't ported, so ace4's is `rdap: rdap result has no registration date`. Both keep the hit unverified. |
| `fqdn_ace4-norecord.com` | `/summary` | The same error in the summary. |

## Behaviour the dumps don't exercise

These depart from ace3:

- The list is in Postgres, one for every node, rebuilt in one transaction by `ace serve`'s `nrd_refresh` task (`ace_app::nrd`), which the module reads through the core's `newly-registered` read. ace3 opens a SQLite file on its node, which the node's cron job swaps in whole. A read the core can't answer (503) fails the task as unavailable, so it runs again later; ace3's failed SQLite query is a miss.
- ace3 caches the module's results for a day in its analysis result cache, keyed by the list file's modification time and size. ace4 has no such cache (PLAN.md 6.7), so every task reads the list. The RDAP lookup's successes are remembered for the pool's process, at most 4096, as ace3's `_creation_date_memo` is.
- When RDAP can't answer, ace3 asks WHOIS through python-whois. That isn't ported: the error is RDAP's alone, `rdap: <error>`, and the hit is kept unverified, as ace3 keeps it when both fail. An RDAP server that can't be reached, or answers 429, 502, 503 or 504, fails the task as unavailable (PLAN.md 1.20), where ace3 records the error and tries WHOIS.
- A name is encoded as Python's `idna` package encodes it (IDNA 2008), with RFC 5892's derived property computed from Unicode's general category and NFKC rather than from `idna`'s generated tables, and a label that needs a joiner or context rule (CONTEXTJ, CONTEXTO) or the bidi rule refused rather than checked (`ace_sdk::nrd::idna_encode`). So a label with a zero-width joiner, a Greek keraia or Arabic-Indic digits isn't looked up, where ace3 may look it up. Every case of `fixtures/nrd/lookups.json` and every line of the fixture lists normalizes as ace3's did.
- The public suffix list is the snapshot tldextract 5.4.0 ships, as for the RDAP module; ace3's tldextract may fetch the live list.
