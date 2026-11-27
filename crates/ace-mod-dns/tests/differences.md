# Differences from ace3's reference dumps

`tests/reference.rs` runs the DNS module on each name `tools/ace3/dumps/reference/fqdn_analyzer/` has a dump for, with the answers ace3 got from `tools/ace3/dumps/fake_dns.py` replayed on 127.0.0.1 (`ace_testkit::dns`). It checks that the module asks the same queries in the same order, puts both results into the normal form `ace_testkit::reference` describes, and fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit c55f15a2, against the zone in `tools/ace3/dumps/fixtures/dns/zone.json`.

| Dumps | Path | Why |
|---|---|---|

## Behaviour the dumps don't exercise

These depart from ace3:

- A resolver that doesn't answer within the timeout, or can't be reached, fails the task as unavailable, so it runs again later (PLAN.md 1.20). ace3 records `dns_error`. A resolver that answers with a failure, such as SERVFAIL, is `dns_error` in both, as `fqdn_broken.example.com` shows.
- The MX lookup or the wildcard probe meeting a resolver that can't be reached fails the task the same way. ace3 logs it and leaves `mx` or `wildcard_dns` null.
- A name with non-ASCII characters is asked for in its IDNA form by hickory-proto's UTS 46 conversion. dnspython converts with the `idna` package's IDNA 2008, so a name the two read differently, such as one with `ß`, is asked for differently.
- The public suffix list is the snapshot tldextract 5.4.0 ships (2025-04-07), as for the RDAP module.
