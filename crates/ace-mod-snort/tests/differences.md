# Differences from ace3's reference dumps

`tests/reference.rs` runs the snort signature module on each `snort_sig` value `tools/ace3/dumps/reference/snort_signature_analysis_v1/` has a dump for. ace3 read an index of `tools/ace3/dumps/fixtures/snort/snort.rules` that its own `_build_signature_db` built (`tools/ace3/dumps/run_module.py --snort-rules`). The test answers the module's `snort-signature` read with the line of that file the core's index gives; the core's index itself is tested against the same rules in `ace-core` (`reads::tests`) and through the lease API in ace-pool's `lease_api` test. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit 85c8e9e5.

| Dumps | Path | Why |
|---|---|---|

## Behaviour the dumps don't exercise

These depart from ace3:

- ace3 adds the rule to the root's summary details (`Suricata Signature <sid> rev <rev>`). ace4's roots have no summary details yet, so the rule is in the result only. The dumps don't hold the root's summary details.
- ace3 reads the index `ace signatures build-db` last built, which goes stale when the rules file changes until it's built again. The core indexes the file again whenever its size or modification time changes (`ACE4_SNORT_RULES`).
- ace3 makes a Redis connection per call and logs a failed one, answering "unknown signature". A core that can't answer (503) fails the task as unavailable, so it runs again later.
