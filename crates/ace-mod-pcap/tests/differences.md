# Differences from ace3's reference dumps

`src/reference.rs` runs `pcap_analyzer`, `pcap_dns`, `pcap_tls`, `pcap_http`, `pcap_files`, `pcap_tls_decryption` and `tls_keylog` on each capture or key log `tools/ace3/dumps/reference/<module>/` has a dump for, named `<module>/<file>` here. Both results go into the normal form `ace_testkit::reference` describes, and the test fails on any difference this table doesn't list, or on a row that no longer matches anything.

In the Dumps column, `*` matches any text in a dump's name. In the Path column, a `*` segment matches one segment of the JSON pointer, `**` any number, and a `*` inside a segment any text; `/` alone is the whole result.

| Dumps | Path | Why |
|---|---|---|
