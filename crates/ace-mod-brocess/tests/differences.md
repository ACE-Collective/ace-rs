# Differences from ace3's reference dumps

`tests/reference.rs` runs the conversation frequency module on each `email_conversation` value `tools/ace3/dumps/reference/email_conversation_frequency_analyzer/` has a dump for. ace3 counted from the smtplog rows in `tools/ace3/dumps/fixtures/brocess/smtplog.json` in place of brocess (`tools/ace3/dumps/run_module.py --brocess`, which sums them as ace3's SQL does). The test answers the module's `smtp-counts` read with the counts the core's query gives for those rows; ace-pool's `lease_api` test runs that query on the same rows in Postgres and checks it against the same dumps. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything. The dumps were made with ace3 at commit f72f8946.

| Dumps | Path | Why |
|---|---|---|

## Behaviour the dumps don't exercise

These depart from ace3:

- When brocess can't be queried, ace3 logs it, puts the module in a cooldown of `cooldown_period` (60 s) during which it analyzes nothing, and stores no result, or for a known sender a result without `dest_count`. A core that can't answer (503) fails the task as unavailable here, so it runs again later. There is no cooldown.
- ace3 asks for the conversation's count only when the sender's isn't 0. The `smtp-counts` read answers both at once; the module ignores the second for a new sender, as ace3 never has it.
